// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The zelynic enforcement math, extracted pure (NIGHT-depthbore-1):
// the token-bucket arithmetic that runs inside the BPF program, with
// zero aya/eBPF dependencies so the SAME file compiles into the
// kernel object (ebpf/src/bin/limiter.rs wires it with #[path]) AND
// into the userspace test tree (src/ebpf/limiter/mod.rs wires it the
// same way), where test/ebpf/limiter/math_tests.rs pins it
// rootlessly. Before the extraction this arithmetic was testable
// only through root-run integration — the sharpest knife in the repo
// had no proof harness. The functions are verbatim moves from the
// limiter program; the NIGHT-depthbore-1 behavioral change (the
// frac_rem sanitization, schema v6) and the NIGHT-boost-38 SMP
// rewrite are marked in place.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once. core::sync::
// atomic and core::ptr are core; the SMP rewrite keeps that contract.
//
// ---------------------------------------------------------------------------
// NIGHT-boost-38: SMP-safe enforcement (schema v7, no layout change).
//
// The v6 and earlier `enforce` mutated the bucket through the plain
// struct reference: load tokens, add refill, subtract the packet,
// store. bpf_map_lookup_elem hands every CPU the SAME map value
// address with no lock, so two CPUs inside the same hook on the same
// bucket (a cgroup with traffic on several CPUs — six parallel curls
// on a 64-core runner is the E2E case) could interleave freely:
//
//   CPU A: load tokens=0        CPU B: load tokens=0        (same
//   CPU A: refill +1MB          stale pre-state)             race
//   CPU A: store tokens=1MB     CPU B: refill +1MB           window
//   CPU A: allow 64KB -> 0xF400 CPU B: store tokens=1MB      (A's
//                              consume clobbered by B's store — the
//                              deducted tokens resurrect)
//
// Two failure shapes, both measured on the E2E runners before this
// fix: resurrected consume (the policer lets a cgroup through at
// 130-146% of its budget under 2-6 concurrent flows — the
// strict-multi and curl-burst reds of 2026-09-24), and double-credit
// (two CPUs crediting the same refill window from the same stale
// last_refill_ns). Single-flow rows (rate ladder 104-108%, sustain
// 97-100%) never showed it — the race needs concurrency. The
// "TCP/GSO lottery" attribution in the supermassive comments was
// this bug wearing a costume: same code, same leg, client ratio
// swinging 97.6%..161.2% across runs — pure scheduling lottery.
//
// The v7 rewrite is lock-free and layout-preserving (the same u64
// fields at the same offsets; pinned v6 maps stay structurally
// valid — the schema bump forces the one-time reload so no v6
// program keeps enforcing with the racy object):
//
//  * Window ownership: the refill is credited by exactly one CPU —
//    the one whose compare_exchange on last_refill_ns wins the
//    window [last, now]. Losers skip crediting (their window is a
//    subset of the winner's; the tail they lose is bounded by one
//    inter-packet gap and errs toward dropping, never over-allow).
//    A window is credited at most once; double-credit is impossible.
//  * Atomic consume: the packet deduction is a compare_exchange
//    from a value that provably covers the packet, so tokens can
//    neither wrap (no transient underflow for a concurrent clamp to
//    misread) nor resurrect (a lost deduction is re-attempted
//    against the fresh value, and losing it drops — never allows).
//  * Atomic stats: every counter moves by fetch_add; lost increments
//    (the ledger undercounting allowed bytes mid-contention) are
//    gone.
//
// Single-threaded behavior is bit-identical to v6 (the math_tests
// pins that predate this rewrite pass unchanged; the SMP invariants
// live in test/ebpf/limiter/math_smp_tests.rs). One documented,
// bounded divergence: under contention the refill winner's frac_rem
// store is not ordered against the NEXT winner's frac_rem load (the
// release edge lives in the last_refill_ns CAS, which precedes the
// store), so a sub-byte fraction may be lost per contended window
// pair — at most one byte of credit per collision, in the safe
// direction, invisible next to the 1.02 GSO epsilon.
//
// Kernel requirement: 64-bit BPF_ATOMIC RMW (fetch_add) and
// BPF_CMPXCHG landed in Linux 5.12; the verified floor (5.13,
// docs/KERNEL_COMPATIBILITY.md) is above it, so the ISA gate moves
// nothing. The code compiles to straight-line CAS sequences — no
// loops, no spin locks, no verifier surprises.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Access primitives for the persistent bucket fields (NIGHT-boost-38).
//
// The BPF ISA has RMW atomics (BPF_ATOMIC fetch-add / cmpxchg, Linux
// 5.12+) but NO dedicated atomic load/store instructions — aligned
// 64-bit LD/ST are single instructions and therefore naturally
// atomic, and the kernel's own pattern for this reality is
// READ_ONCE / WRITE_ONCE: volatile accesses. Rust's AtomicU64::load
// compiles to an LLVM `load atomic` node, which the BPF backend
// cannot select (verified against bpf-linker 0.11.1 / the pinned
// nightly LLVM: "Cannot select: AtomicLoad" at ISel, any -mcpu) —
// so plain reads/writes of the shared fields go through these
// volatile helpers (the kernel's READ_ONCE/WRITE_ONCE semantics:
// not elided, not reordered among themselves, one instruction), and
// only the genuine RMW steps (fetch_add, compare_exchange) ride
// core's AtomicU64, which lowers to the BPF_ATOMIC ISA.
// ---------------------------------------------------------------------------

/// READ_ONCE for one bucket field (see the block comment above).
#[inline(always)]
fn read_once(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // field of a map value (or a test-tree struct).
    unsafe { p.read_volatile() }
}

/// WRITE_ONCE for one bucket field (see the block comment above).
#[inline(always)]
fn write_once(p: *mut u64, v: u64) {
    // SAFETY: same contract as read_once, mut variant.
    unsafe { p.write_volatile(v) }
}

/// The atomic RMW view of one u64 field: fetch_add /
/// compare_exchange only — loads and stores go through read_once /
/// write_once (the block comment above explains why). The returned
/// reference borrows the pointed-to field for the caller's scope,
/// exactly like `AtomicU64::from_ptr` below it.
#[inline(always)]
fn rmw_view<'a>(p: *mut u64) -> &'a AtomicU64 {
    // SAFETY: same 8-aligned-field contract as read_once.
    unsafe { AtomicU64::from_ptr(p) }
}

// ---------------------------------------------------------------------------
// Shared layout contract (kept identical to the userspace mirrors:
// PolicyRaw, BucketRaw, LimiterStatsRaw in src/ebpf/limiter/types.rs).
// The compile-time size pins guarantee the layouts can never drift
// silently; the userspace tests assert the third copy.
// ---------------------------------------------------------------------------

/// The BPF-side policy layout; the userspace mirror is `PolicyRaw`
/// in src/ebpf/limiter/types.rs (layout contract). group_id == 0 means
/// "individual" (use cgroup bucket); group_id != 0 means "shared
/// group" (use the group bucket keyed by group_id).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Policy {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
}

/// The BPF-side token-bucket layout, schema v2 (userspace mirror:
/// `BucketRaw` in src/ebpf/limiter/types.rs — the layout contract).
///
/// `frac_rem` tracks the sub-byte fractional remainder from the
/// refill calculation: `(elapsed_ns * rate_bps) % NS_PER_SEC`.
/// Without this, integer division truncates up to ~1 byte per
/// refill, causing 0.5-1% rate error at common rates.
///
/// NIGHT-boost-38: the fields stay plain `u64` (the pinned layout is
/// the contract); `enforce` takes its atomic views of them through
/// `AtomicU64::from_ptr` at the access site, so no schema migration
/// of the persistent maps is needed for the SMP fix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub frac_rem: u64,
}

/// The BPF-side stats layout (userspace mirror: `LimiterStatsRaw`
/// in src/ebpf/limiter/types.rs — the layout contract). Combined
/// download + upload enforcement stats per cgroup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LimiterStats {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

const _: () = assert!(core::mem::size_of::<Policy>() == 24);
const _: () = assert!(core::mem::size_of::<Bucket>() == 24);
const _: () = assert!(core::mem::size_of::<LimiterStats>() == 32);

/// Refill rate math: nanoseconds per second.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Hard ceiling a stored `burst_bytes` may carry INTO the refill
/// math (NIGHT-improve-10 / security-3). The maps are persistent
/// kernel state that outlives any writer: pins survive process exit,
/// and the pin path is writable by any root process. The userspace
/// `default_burst` clamp (100 MB) is a contract, not a guarantee the
/// kernel side may trust — the enforcement boundary sanitizes for
/// itself. The value is the exact mathematical ceiling under which
/// every product `enforce` can form is provably representable in
/// u64: `2 * burst * NS_PER_SEC` (the fill-detect threshold) and
/// `tokens + 2 * burst` (the worst pre-cap sum) both stay in range.
/// A stored burst above the bound is corruption or drift; it is
/// clamped, never honored. Mirrored in userspace as
/// `MAX_ENFORCABLE_BURST` in src/ebpf/limiter/types.rs (layout
/// contract sibling — both sides pin the value in tests).
pub const MAX_ENFORCABLE_BURST: u64 = u64::MAX / (2 * NS_PER_SEC);

/// Refill tokens and enforce. `pol` is the policy, `bkt` the bucket
/// (individual or group), `stats` an optional stats entry (the
/// program passes None when the stats insert failed and keeps
/// enforcing without bookkeeping).
///
/// NIGHT-boost-38: the body is SMP-safe (see the module docs — the
/// v6 lost-update race and its lock-free fix). The refill arithmetic
/// itself lives in [`refill_credits`]; everything here is atomic
/// orchestration: the security-3 seed clamp, the window-ownership
/// CAS, the token credit and cap, and the CAS consume.
///
/// Fractional remainder tracking keeps the rate precise (see the
/// Bucket docs); the refill multiply is overflow-safe (the
/// NIGHT-cybersecurity-1 fill-detect shape, preserved verbatim in
/// refill_credits).
///
/// Schema v6 (NIGHT-depthbore-1): `frac_rem` is sanitized on read —
/// the third persistent stored field, and the one the v4 clamp
/// family missed. A healthy remainder is always < NS_PER_SEC (the
/// math maintains that invariant itself: the exact branch stores
/// the post-carry remainder, the fill-detect and cap branches store
/// zero), so a value >= NS_PER_SEC is drift or hostile writes.
/// Treating the anomalous remainder as empty completes the clamp
/// family: burst, tokens, and now frac are each clamped to the
/// healthy value the math itself would have stored. Invisible for
/// healthy state, total for hostile state.
#[inline(always)]
pub fn enforce(
    pol: &Policy,
    bkt: &mut Bucket,
    pkt_len: u32,
    now: u64,
    stats: Option<&mut LimiterStats>,
) -> i32 {
    // Field pointers, taken once (the layout pins above guarantee
    // the 8-aligned repr(C) offsets: tokens 0, last_refill_ns 8,
    // frac_rem 16 — and every BPF hash map value the kernel hands
    // out is 8-aligned, so the views are valid for the struct's
    // lifetime). Loads/stores ride read_once/write_once; RMW rides
    // rmw_view (see the access-primitive block above).
    let tokens_ptr = core::ptr::addr_of_mut!(bkt.tokens);
    let last_refill_ptr = core::ptr::addr_of_mut!(bkt.last_refill_ns);
    let frac_rem_ptr = core::ptr::addr_of_mut!(bkt.frac_rem);

    // security-3 trust boundary, v7 one-shot form: clamp a stored
    // token count above the current burst to burst before any
    // consumer sees it. Single-threaded this is the old in-place
    // rewrite (a static hostile value never has a contender); under
    // SMP contention a lost CAS retries on the next packet — the
    // clamp converges across packets instead of looping here (no
    // loop body for the verifier to bound, and an unclamped
    // transient never outlives the contended window).
    let seeded = read_once(tokens_ptr);
    if seeded > pol.burst_bytes {
        let _ = rmw_view(tokens_ptr).compare_exchange(
            seeded,
            pol.burst_bytes,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    // Refill window ownership (NIGHT-boost-38): exactly one CPU
    // credits [last, now]. Single-threaded this is bit-identical to
    // the v6 flow — the unconditional last_refill_ns = now store
    // becomes a CAS that cannot fail, the refill is the same
    // refill_credits arithmetic, the cap is the same burst cap.
    // Under contention the loser skips crediting: its window is a
    // subset of the winner's, so the aggregate credit equals the
    // union of the owned windows — each nanosecond is paid once,
    // never twice.
    let last = read_once(last_refill_ptr);
    let mut elapsed = now.saturating_sub(last);
    // Cap elapsed at 1 second to limit burst after idle.
    if elapsed > NS_PER_SEC {
        elapsed = NS_PER_SEC;
    }
    // The v6 code stored last_refill_ns = now unconditionally. The
    // v7 window rule keeps the forward case identical and closes the
    // stall fountain the unconditional store left open under SMP
    // (found by the math_smp_tests clock-skew hammer: allowed bytes
    // at 80x the true credit):
    //  * now > last — the forward case: the ownership CAS. The
    //    winner credits [last, now]; the loser skips (its window is
    //    a subset of the winner's — each nanosecond paid once).
    //  * now < last with a small excursion (<= 1 s) — a stale
    //    sampler: this CPU sampled ktime, stalled, and other CPUs
    //    already advanced the stamp past it. The interval behind the
    //    stamp is already owned and paid upstream; moving the stamp
    //    back would re-credit it (the fountain). SKIP — no store, no
    //    credit. The credit stays exactly conserved.
    //  * now < last with an absurd excursion (> 1 s) — hostile or
    //    drifted bucket state (a BPF program cannot stall a second
    //    between two instructions): heal the stamp forward-CAS-style
    //    with no credit, the v6 sanitization family's answer to a
    //    corrupted future last_refill_ns.
    if now > last {
        let owns_window = rmw_view(last_refill_ptr)
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if owns_window && elapsed > 0 && pol.rate_bps > 0 {
            let (whole, new_frac) = refill_credits(
                pol.rate_bps,
                pol.burst_bytes,
                elapsed,
                read_once(frac_rem_ptr),
            );
            // Credit the owned window, then enforce the v6 cap
            // shape: tokens + refill above burst collapse to burst
            // and the fraction resets. The post-add clamp is
            // one-shot CAS like the seed clamp — a contended miss
            // retries on the next packet and the transient
            // overshoot is bounded by one refill quantum.
            let before_add = rmw_view(tokens_ptr).fetch_add(whole, Ordering::AcqRel);
            if before_add.saturating_add(whole) > pol.burst_bytes {
                let over = read_once(tokens_ptr);
                if over > pol.burst_bytes {
                    let _ = rmw_view(tokens_ptr).compare_exchange(
                        over,
                        pol.burst_bytes,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
                write_once(frac_rem_ptr, 0);
            } else {
                // The release edge of the ownership CAS precedes
                // this store, not the other way around — a next
                // winner may read a stale fraction (module docs:
                // bounded, sub-byte, safe direction).
                write_once(frac_rem_ptr, new_frac);
            }
        }
    } else if last.saturating_sub(now) > NS_PER_SEC {
        // The absurd excursion: hostile or drifted state (see the
        // window-rule comment above) — heal the stamp, credit
        // nothing (elapsed saturated to zero, matching v6's hostile
        // guard).
        let _ = rmw_view(last_refill_ptr).compare_exchange(
            last,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    // Atomic consume (NIGHT-boost-38): deduct only from a value that
    // provably covers the packet. A fetch_sub-and-revert shape would
    // transiently wrap tokens negative (u64 underflow) and hand a
    // concurrent clamp a huge value to misread; the CAS never lets
    // tokens leave the valid range, and a lost CAS (pure contention)
    // drops this packet — the safe verdict — instead of allowing it.
    let want = u64::from(pkt_len);
    let observed = read_once(tokens_ptr);
    let allowed = observed >= want
        && rmw_view(tokens_ptr)
            .compare_exchange(
                observed,
                observed - want,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
    match stats {
        Some(s) if allowed => {
            book(s, true, pkt_len);
            1
        }
        Some(s) => {
            book(s, false, pkt_len);
            0
        }
        None => {
            if allowed {
                1
            } else {
                0
            }
        }
    }
}

/// Book one verdict into a stats entry with atomic increments
/// (NIGHT-boost-38: the v6 `+=` lost increments whenever two CPUs
/// enforced the same cgroup concurrently — the ledger undercounted
/// allowed bytes mid-contention, the exact noise the E2E
/// "BPF accounting matches client bytes" rows kept swallowing).
/// Layout-preserving: the u64 counters are mutated in place through
/// the RMW view, the same fields at the same offsets.
#[inline(always)]
fn book(stats: &mut LimiterStats, allowed: bool, pkt_len: u32) {
    // Field pointers (8-aligned repr(C) offsets: 0, 8, 16, 24 — the
    // size pin above).
    let packets_allowed_ptr = core::ptr::addr_of_mut!(stats.packets_allowed);
    let packets_dropped_ptr = core::ptr::addr_of_mut!(stats.packets_dropped);
    let bytes_allowed_ptr = core::ptr::addr_of_mut!(stats.bytes_allowed);
    let bytes_dropped_ptr = core::ptr::addr_of_mut!(stats.bytes_dropped);
    if allowed {
        rmw_view(packets_allowed_ptr).fetch_add(1, Ordering::Relaxed);
        rmw_view(bytes_allowed_ptr).fetch_add(u64::from(pkt_len), Ordering::Relaxed);
    } else {
        rmw_view(packets_dropped_ptr).fetch_add(1, Ordering::Relaxed);
        rmw_view(bytes_dropped_ptr).fetch_add(u64::from(pkt_len), Ordering::Relaxed);
    }
}

/// Pure refill arithmetic for one owned window (NIGHT-boost-38
/// extracted the branch from the old monolithic enforce so the
/// overflow-guard and carry contracts pin independently): returns
/// `(whole_bytes, frac_rem)` for an elapsed window, including the
/// 1-second idle cap, the fill-detect overflow guard, and the v6
/// frac sanitization (`frac_rem >= NS_PER_SEC` reads as empty —
/// hostile or drifted state, never trusted into the accumulation).
///
/// Contract: `rate_bps > 0` and `burst_bytes <= MAX_ENFORCABLE_BURST`
/// (the security-3 trust boundary — both are guaranteed by every
/// caller; the guard below protects the division for standalone
/// use).
///
///  * fill-detect: once elapsed is large enough that the true
///    refill reaches 2x burst, the bucket caps at burst anyway —
///    skip the multiply and credit burst directly (the fraction
///    resets, matching the cap branch in enforce).
///  * exact multiply: below that threshold the product is
///    < 2x burst * NS_PER_SEC, safely representable in u64 for any
///    burst the clamp admits — the fill-detect threshold is not an
///    optimization alone, it is the overflow guard: the exact branch
///    only ever runs while `elapsed < fill_ns`, and
///    `fill_ns * rate == 2 * burst * NS_PER_SEC` bounds the product
///    by construction.
#[inline(always)]
pub fn refill_credits(
    rate_bps: u64,
    burst_bytes: u64,
    elapsed_ns: u64,
    frac_rem: u64,
) -> (u64, u64) {
    // v6 sanitize: a healthy remainder is always < NS_PER_SEC.
    let healthy_frac = if frac_rem < NS_PER_SEC { frac_rem } else { 0 };
    // Cap elapsed at 1 second to limit burst after idle.
    let mut elapsed = elapsed_ns;
    if elapsed > NS_PER_SEC {
        elapsed = NS_PER_SEC;
    }
    if rate_bps == 0 || elapsed == 0 {
        return (0, healthy_frac);
    }
    let fill_ns = (2 * burst_bytes * NS_PER_SEC) / rate_bps;
    if elapsed >= fill_ns {
        // Refill >= 2x burst: the cap in enforce makes the exact
        // value irrelevant — burst is the answer (the overflow
        // guard; see the function docs).
        return (burst_bytes, 0);
    }
    let product = elapsed * rate_bps;
    let mut whole = product / NS_PER_SEC;
    let mut new_frac = product % NS_PER_SEC;
    // Accumulate the fractional remainder. If it overflows
    // NS_PER_SEC, carry 1 byte into the integer tokens.
    new_frac += healthy_frac;
    if new_frac >= NS_PER_SEC {
        whole += 1;
        new_frac -= NS_PER_SEC;
    }
    (whole, new_frac)
}
