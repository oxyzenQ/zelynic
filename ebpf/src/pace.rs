// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// night-spark-5 (Egress Socket Pacing — Layer 3 of the quota
// saver): the pure pacing law. Same discipline as math.rs /
// mmspa.rs / drr.rs / ecn.rs / quic.rs / during.rs / recwn.rs:
// pure `core`, zero aya dependencies, wired into the limiter
// object with #[path] (ebpf/src/bin/limiter.rs) AND into the
// userspace test tree the same way, pinned rootlessly by
// test/ebpf/limiter/pace_tests.rs.
//
// THE LAW (the owner's task brief, the verbatim mechanism): when a
// cgroup's UPLOAD policy stands, the sock_ops program pins
// SO_MAX_PACING_RATE to the policy's rate in BYTES per second —
// the kernel's own TCP pacer spaces the outgoing stream at that
// rate, so upload quota is saved BEFORE the link bills the bytes:
// no over-budget burst, no drop, no CE mark, no loss event, and no
// tc qdisc anywhere (the pure-ebpf claim — the pacing qdisc's job
// is done by the stack itself).
//
// Two kernel truths this layer carries (the recwn.rs hunt's
// discipline — the version-dependence is stated, never glossed,
// both verified against the v5.15 tree the floor pins):
//
// 1. SO_MAX_PACING_RATE stores the rate into sk_max_pacing_rate
//    (include/uapi/asm-generic/socket.h option 47 under SOL_SOCKET)
//    and the TCP write path paces at it with NO pacing qdisc
//    attached: the stack's internal pacer (net/ipv4/tcp_output.c's
//    tcp_internal_pacing on the 5.15 floor) hrtimer-limits the
//    transmit path while sk_pacing_status says CPU — the qdisc-less
//    shape this lane rides. A pacing qdisc (fq), when one is
//    attached, simply takes over the same sk_pacing_rate — the law
//    is the socket's, not the qdisc's.
//
// 2. A sock_ops program on the 5.15 floor cannot resolve its own
//    cgroup (bpf_get_current_cgroup_id is absent from
//    sock_ops_func_proto — the recwn lane's verified find), and the
//    dispatch is TCP-only by construction (every tcp_call_bpf call
//    site lives in TCP code). The attribution therefore rides the
//    lane the house already trusts: the EGRESS enforcement hook
//    resolves every packet's socket cgroup (bpf_skb_cgroup_id) and
//    primes a cookie-keyed hint (pace_flow.rs), which the sock_ops
//    program reads back at the connection callbacks. UDP/QUIC
//    sockets never reach this program — QUIC paces itself (RFC
//    9000), and the policer remains UDP's enforcement lane.

/// The pacing field's uapi width: SO_MAX_PACING_RATE carries a u32
/// byte rate (about 4.29 GB/s). A policy beyond it clamps — the
/// field is a ceiling, never a wrap (the recwn sanitize guard's
/// posture: bound the input, keep the arithmetic honest).
pub const PACING_RATE_MAX_BPS: u64 = u32::MAX as u64;

/// The pacing decision — the sock_ops program's whole brain, pure
/// so the rootless pin can SIMULATE the call (the owner's unit-test
/// brief: every sock_ops shape, and the exact rate the wiring would
/// hand bpf_setsockopt). `owned_op` says the callback op is one the
/// program owns (RWND_INIT / ACTIVE_ESTABLISHED / PASSIVE_ESTABLISHED
/// / RTT_CB — the ops the program's match dispatches); `fullsock`
/// mirrors is_fullsock (the passive side's RWND_INIT carries the
/// REQUEST socket, where the helper would refuse with EINVAL
/// anyway); `tcp` mirrors the socket's protocol field (the dispatch
/// is TCP-only by construction — the armor against a future kernel
/// firing these ops at another family); `hint_bps` is the primed
/// upload rate in bytes per second (None — no primed row — is the
/// default-pacing shape, exactly today's behavior for an unpoliced
/// socket). Some(rate) is the value the wiring passes to
/// bpf_setsockopt(SOL_SOCKET, SO_MAX_PACING_RATE); None means no
/// opinion — the socket rides untouched.
#[allow(clippy::fn_params_excessive_bools)]
pub fn pacing_decision(
    owned_op: bool,
    fullsock: bool,
    tcp: bool,
    hint_bps: Option<u64>,
) -> Option<u32> {
    if !owned_op || !fullsock || !tcp {
        return None;
    }
    let rate = hint_bps?;
    if rate == 0 {
        // The BLOCK verdict's own shape: a blocked lane delivers
        // nothing, so no pacing rate can help it — and a zero passed
        // to the option would clear the socket's ceiling, the one
        // direction this lane must never drift.
        return None;
    }
    Some(rate.min(PACING_RATE_MAX_BPS) as u32)
}

// ── night-quota-audit (2026-11-09): the saved-headroom law is
// RETIRED ────────────────────────────────────────────────────────
//
// night-spark-7 booked `bytes_saved_by_edt` here as
// `(rate x dt_capped) - pkt_len`, summed over the lane's life as
// `(rate x time_elapsed) - bytes_uploaded`. The owner's 2026-11-09
// host reading broke the contract the doc claims ("the estimate
// errs LOW, never high"): a brave at 500kb read 744.6 MB booked
// against a 20 MB doc-formula prediction (36.8x), a python3 at
// 300kb read 1.8x — different ratios per cgroup, the signature of
// the formula's own shape, not a scaling bug. The law's only
// NONZERO content is the budget the sender did not use: a saturated
// paced lane books nothing (the budget lands within the packet's
// own length), and an idle-ish lane books `rate x capped-gap` per
// packet — headroom for an upload that was never pending. A pacer
// RESCHEDULES bytes; it does not remove them, and no cap short of
// zero makes the counterfactual honest. The word stays in the
// stats layout (offset 48, the pure-append law) and reads zero
// from schema v29 on; the quota saved total is the two lanes whose
// physics actually withhold bytes (RECWN's window estimate and
// ECN's one-for-one marks), and the pacing lane's wire effect —
// the suppressed burst-retransmission storm — stays what the A/B
// harness measures, never a booked counterfactual. The full record
// lives in docs/QUOTA_SAVER_PHYSICS.md and the arc doc's Layer 4
// section.
