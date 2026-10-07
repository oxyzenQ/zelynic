// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The zelynic ECN-first debt core (NIGHT-private-research-4, schema
// v19): the pure arithmetic behind mark-instead-of-drop policing,
// extracted the math.rs/drr.rs way — zero aya/eBPF dependencies so
// the SAME file compiles into the kernel object (ebpf/src/bin/
// limiter.rs wires it with #[path]) AND into the userspace test tree
// (src/ebpf/limiter/mod.rs wires it the same way), where
// test/ebpf/limiter/ecn_tests.rs pins it rootlessly.
//
// THE DESIGN, stated honestly. A drop-based policer teaches TCP the
// hard way: every dropped packet is a lost window, a retransmit
// timer, and a latency spike the application feels. An ECN-first
// policer tells the same sender the same news — "the budget is
// exhausted" — in the signal the kernel already carries: the CE
// codepoint in the IP header (set through bpf_skb_ecn_set_ce, the
// helper the kernel exposes to cgroup_skb since long before the
// 5.13 verified floor; it handles IPv4 AND IPv6, the header
// checksums, and the cloned-not-writable refusal itself). A
// CE-reactive sender (TCP with ECN negotiated, QUIC with ECT) reads
// the mark and converges WITHOUT a single lost packet: goodput under
// the cap rises and retransmit jitter falls, which is the entire
// point. A non-ECT packet (the RFC 3168 majority) is refused by the
// helper and drops exactly as before — the legacy verdict, untouched.
//
// THE BUDGET LAW — the part that makes this honest instead of
// wishful. Marked packets are DELIVERED, so they must come out of
// the policy's budget or the promise "the aggregate stays exactly
// the policy" dies. The accounting: every delivered marked packet
// charges a DEBT (debt_charge below, capped at one GSO super-packet,
// the same 64 KiB admit floor the DRR lane heals starved flows
// with), and every DELIVERED packet on the lane PAYS that debt from
// the bucket's own tokens afterwards, out of the stream's leftover
// (debt_pay below — the conservation move; the call-site law in its
// docs is load-bearing). The invariant chain, closed under every
// adversarial shape the battery throws at it:
//
//   delivered = lane_consumed + marked
//   marked    <= debt_charged = debt_paid + debt_outstanding
//   debt_paid <= tokens_deducted (each pay removes tokens)
//   lane_consumed + tokens_deducted <= refill_credits
//   =>  delivered <= refill_credits + debt_outstanding
//   =>  delivered <= rate*t + burst + 64 KiB
//
// A CE-IGNORING flow (the cheat shape: set ECT, never react) gets
// exactly the same bound as a non-ECT flow — the marking lane cannot
// be farmed for a single byte beyond the one-time 64 KiB slack,
// because the debt pay eats out of the same stream the flow's own
// deliveries feed. A CE-reactive flow spends that slack during its
// convergence transients, and the converged periods' leftover
// re-arms it — it never sees a drop it did not also ignore a mark
// for. There is no time-based decay anywhere: time decay would hand
// a second independent rate stream to the CE-ignoring shape (the 2R
// hole), and the token-stream pay is the only form whose bound does
// not depend on the sender's goodwill.
//
// The debt lives in its own LRU map (the leaf-bucket posture), keyed
// by the generation-prefixed BUDGET key — the pool's root for the
// DRR lane, the group id for the group lane (the repair-6
// discipline: a fresh budget never inherits the predecessor's debt,
// stale entries age out through the LRU). The per-socket lane
// carries the same law with its own shape (schema v21, the
// convergence closure): the debt word lives INSIDE the socket's
// bucket — per-connection state in the per-connection bucket,
// belt-zeroed by the generation stamp a policy mutation bumps —
// because the u64 cookie the lane keys by cannot carry the
// generation prefix the map family's keying rides. The scope note
// that once deferred this lane ("a server's N connections each
// halving their windows on per-connection marks is an
// aggregate-collapse shape that needs its own convergence analysis
// before it ships") is closed by the rootless fleet sims in
// test/ebpf/limiter/ecn_tests.rs: per-connection budgets are
// independent, so each connection converges on its own stream and
// the aggregate rides N x per-connection — no collapse term exists,
// the marking fleet beats the drop fleet, and a CE-ignoring hammer
// stays bounded by its own budget law while its neighbors converge
// untouched.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once (the math.rs
// contract, verbatim). The functions take RAW POINTERS to the two
// words they arbitrate (the bucket's tokens field, the debt map
// word) — the drr.rs law: pure cores never reference each other's
// types, because the two trees wire them under different module
// names; the wiring side (limiter.rs) hands the field pointers the
// same way it hands math.rs its bucket references.
//
// Kernel requirement: nothing new — the CAS sequences lower to the
// same BPF_ATOMIC ISA the 5.13 floor already carries (math.rs's
// note), and the helper call itself lives in the wiring half.

use core::sync::atomic::{AtomicU64, Ordering};

/// The ECN debt ceiling: one GSO super-packet of outstanding marked
/// bytes (the drr.rs GSO_ADMIT_FLOOR law — the same 64 KiB the starved
/// flow's fat GRO admit rides). The value is the slack term in the
/// budget law above: the one-time convergence room a CE-reactive
/// sender spends before its window settles under the cap. Bigger
/// buys nothing honest (a CE-ignoring flow would farm it) and
/// smaller starves the heal (the marked GSO admit that lets TCP's
/// window recover). Pinned against drr.rs's floor in the test tree.
pub const ECN_DEBT_CAP: u64 = 65_536;

// The access discipline is math.rs's, applied to bare words: BPF
// has RMW atomics but no atomic load/store, so reads ride volatile
// and only genuine RMW (compare_exchange) rides core's AtomicU64 —
// the same lowering reasoning, one word instead of one struct field.

/// READ_ONCE for one arbitrated word (a debt word or a tokens field).
#[inline(always)]
fn word_read(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // (a map value, a bucket field, or a test-tree local).
    unsafe { p.read_volatile() }
}

/// Compare-and-swap one arbitrated word, true when this caller's
/// view won.
#[inline(always)]
fn word_cas(p: *mut u64, from: u64, to: u64) -> bool {
    // SAFETY: same 8-aligned contract as word_read.
    unsafe { AtomicU64::from_ptr(p) }
        .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Charge one delivered marked packet's bytes onto the debt word,
/// the note_share discipline (two written-out attempts, never a
/// loop): true when this packet's `pkt_len` found room under the
/// cap and the charge landed. The caller charges ONLY after the
/// kernel helper actually set CE — a refused mark (non-ECT, cloned
/// not writable, header not linear) never touches the debt, so the
/// word only ever counts bytes the network actually delivered.
///
/// The two attempts absorb the same contention class the DRR
/// share-note absorbs (concurrent chargers on one word): each
/// attempt re-reads, so a lost race retries against the survivor's
/// value once. A twice-lost charge returns false and the packet
/// DROPS — already CE-marked, harmlessly: a marked packet that is
/// then dropped signals nothing the receiver will read, and the
/// safe-verdict discipline (never over-allow) holds. The transient
/// over-cap window between the read and the CAS is bounded by one
/// pkt_len per contending CPU, erring the same safe direction.
#[inline(always)]
pub fn debt_charge(debt: *mut u64, pkt_len: u32) -> bool {
    let want = u64::from(pkt_len);
    macro_rules! charge_attempt {
        () => {
            let observed = word_read(debt);
            if observed.saturating_add(want) <= ECN_DEBT_CAP
                && word_cas(debt, observed, observed + want)
            {
                return true;
            }
        };
    }
    charge_attempt!();
    charge_attempt!();
    false
}

/// Pay the debt from the bucket's own token stream — the
/// conservation move. Each pay removes `pay` tokens from the bucket
/// (`tokens` points at the bucket's tokens field) and forgives the
/// same `pay` bytes of debt: the marked bytes of past packets are
/// retroactively bought with real budget, which is what closes the
/// budget law's chain. Order matters and is fixed: the TOKEN
/// deduction lands first, the debt word second — a lost debt CAS
/// after a won token CAS over-pays the budget (bytes counted as
/// debt that were never marked), the SAFE direction, exactly one
/// pay wide; the reverse order could under-pay (tokens kept, debt
/// forgiven), the never direction.
///
/// THE CALL-SITE LAW (the starvation close, found by the rootless
/// simulation before any kernel ever saw this code): the pay runs
/// ONLY on the lane's ALLOW path, from the stream's LEFTOVER after
/// the lane delivered a packet. A pay that ran on every packet —
/// drop path included — drains the accumulated token stock toward
/// the debt, and a CE-IGNORING hammer pins the debt at its cap:
/// every refill credit diverts to the pay, no lane ever affords a
/// packet again, and the flow starves BELOW the policy (the exact
/// inversion of the promise — the mixed-cgroup shape starves its
/// reactive siblings through the shared pool too). The allow-path
/// placement makes the pay self-limiting: it only ever takes tokens
/// the stream just showed it can spare, so the diversion can never
/// outrun the deliveries that feed it. The resulting semantics, per
/// sender shape: a CE-reactive sender marks during its convergence
/// transients and the converged periods' leftover re-arms the
/// marking budget; a CE-ignoring sender sees the debt saturate once
/// and the lane settle into EXACT drop-lane parity (every credit
/// consumed, nothing diverted) — never worse than the legacy
/// policer, never a second rate stream.
///
/// A lost token CAS (a concurrent consumer spent first) skips the
/// pay entirely — the next allow pays from whatever the refill
/// landed. Idle lanes (no deliveries) do not pay; their debt ages
/// out through the LRU instead, un-bought and un-delivered, the
/// same safe-direction loss every LRU lane in this object
/// documents.
#[inline(always)]
pub fn debt_pay(tokens: *mut u64, debt: *mut u64) {
    let outstanding = word_read(debt);
    if outstanding == 0 {
        return;
    }
    macro_rules! pay_attempt {
        () => {
            let available = word_read(tokens);
            let pay = if available < outstanding {
                available
            } else {
                outstanding
            };
            if pay == 0 {
                return;
            }
            if word_cas(tokens, available, available - pay) {
                // The budget paid. Now forgive the debt it bought —
                // against a fresh read (a concurrent payer may have
                // already forgiven part of it), never below zero.
                let fresh = word_read(debt);
                let forgive = if fresh < pay { fresh } else { pay };
                let _ = word_cas(debt, fresh, fresh - forgive);
                return;
            }
        };
    }
    pay_attempt!();
    pay_attempt!();
}
