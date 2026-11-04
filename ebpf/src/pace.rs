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

// ── night-spark-7 (the quota telemetry's math — Layer 4 of the
// quota saver): the saved-headroom law, pure like the decision
// above it ──────────────────────────────────────────────────────
//
// THE LAW (the task brief's own formula, per-packet form): the
// egress pacing lane saves the difference between the budget the
// lane's rate accrued over an elapsed gap and the volume actually
// delivered in it —
//     saved = (rate_bytes_per_sec * dt_ns / 1_000_000_000) - pkt_len
// clamped at zero per call, summed over the lane's life it reads
// (rate x active-time) - uploaded: the quota headroom the pacer
// PRESERVED while the lane was delivering. The kernel-side accrual
// runs on the egress policed path only (pace_flow.rs
// pace_saved_book, called from enforce.rs after the stats entry
// materializes), against a per-cgroup stamp, so the column is
// direction-clean: the combined dl+ul ledger never dilutes it.

/// The elapsed-gap cap for the saved-headroom law: one second, the
/// same idle discipline refill_credits pins (math.rs) — a gap longer
/// than a second books at most rate x 1s once (on the first packet
/// after the idle), so an alive-but-silent lane cannot accrue
/// headroom faster than one capped window per return. The cap is
/// the anti-burst law's own number, reused for the same reason:
/// the counter must never reward idleness the bucket itself refuses
/// to credit.
pub const PACING_SAVED_DT_CAP_NS: u64 = 1_000_000_000;

/// The sanitize guard on the rate input for the saved-headroom law:
/// 4 GiB/s, the recwn.rs RECWN_RATE_SANITIZE_CAP posture verbatim.
/// The product (rate x dt) rides a PLAIN 64-bit multiply — the BPF
/// ISA has no widening multiply, so a checked/saturating form would
/// lower to the __multi3 libcall the kernel cannot relocate (the
/// prebuilt-parity gate's own find). Bounding each factor (rate at
/// 2^32, dt at 1e9) bounds the product at 2^32 x 1e9 < 2^62 —
/// overflow-impossible by construction, and invisible for every
/// real policy (a rate above 4 GiB/s is far past the pacing field's
/// own u32 ceiling).
pub const PACING_SAVED_RATE_CAP: u64 = 4_294_967_296;

/// The saved-headroom law (night-spark-7, Layer 4): the bytes the
/// pacing lane preserved over one elapsed gap — the theoretical
/// budget (rate x capped dt) minus the volume actually delivered,
/// clamped at zero so the column stays MONOTONIC (a burst that
/// drains the budget books nothing rather than a negative). The
/// clamping's honest cost, stated: an unpaced drain-and-refill
/// cycle counts the refill's surplus but never the drain's deficit,
/// so bursty unpaced traffic over-books slightly; on the paced lane
/// — the column's own subject — the per-packet budget lands within
/// the packet's length and the law reads exactly the formula. A
/// zero rate (the BLOCK verdict's shape) saves nothing: a blocked
/// lane delivers nothing, so no headroom can be preserved.
#[inline(always)]
pub fn pacing_saved_bytes(rate_bps: u64, dt_ns: u64, pkt_len: u32) -> u64 {
    let rate = if rate_bps > PACING_SAVED_RATE_CAP {
        PACING_SAVED_RATE_CAP
    } else {
        rate_bps
    };
    let dt = if dt_ns > PACING_SAVED_DT_CAP_NS {
        PACING_SAVED_DT_CAP_NS
    } else {
        dt_ns
    };
    let budget = rate * dt / 1_000_000_000;
    budget.saturating_sub(u64::from(pkt_len))
}
