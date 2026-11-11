// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// night-spark-2 (RECWN, Receive Window Control — Layer 1 of the
// quota saver): the pure window law. Same discipline as math.rs /
// mmspa.rs / drr.rs / ecn.rs / quic.rs / during.rs: pure `core`,
// zero aya dependencies, wired into the limiter object with #[path]
// (ebpf/src/bin/limiter.rs) AND into the userspace test tree the
// same way, pinned rootlessly by test/ebpf/limiter/recwn_tests.rs.
//
// THE LAW (the owner's task brief, verbatim arithmetic):
//   target_window = (rate_bytes_per_sec * rtt_us) / 1_000_000
// clamped to [2 x MSS, 1 MiB]. An unknown RTT assumes the
// delivery-cadence estimate (200 ms — the constant's own doc owns
// why the briefed 50 ms grew) — bufferbloat bounded, never
// amplification, and delivery guaranteed at the policy rate.
//
// Two kernel truths this layer carries that the original sketch
// did not (both verified against torvalds/linux v5.15 source, the
// hunt the owner's rules owe the tree):
//
// 1. The RWND_INIT callback's return value is a MULTIPLIER OF MSS,
//    not bytes, and 0 is the "default OS behavior" answer
//    (tcp_rwnd_init_bpf in include/net/tcp.h: rwnd < 0 -> 0;
//    tcp_select_initial_window then applies min(*rcv_wnd,
//    init_rcv_wnd * mss)). Returning 1 — the sketched "allow
//    default" — would clamp EVERY unpoliced socket on the machine
//    to a one-MSS initial window. The program therefore returns 0
//    on every path and lets bpf_setsockopt(SO_RCVBUF) carry the
//    clamp: the buffer is the spine (it bounds both the initial
//    window through tcp_full_space and every later window update
//    through tcp_select_window), it is byte-exact, and it needs no
//    MSS guess.
//
// 2. A sock_ops program on the 5.15 floor cannot resolve its own
//    cgroup: bpf_get_current_cgroup_id is absent from
//    sock_ops_func_proto (verified in net/core/filter.c) — the
//    helper belongs to the cgroup_skb and sk_msg families. The
//    attribution therefore rides the lane the house already trusts:
//    the INGRESS enforcement hook resolves every packet's socket
//    cgroup (bpf_skb_cgroup_id) and primes a cookie-keyed hint
//    (recwn_flow.rs), which the sock_ops program reads back at the
//    connection callbacks. The sender-side clamp lands at
//    establishment for active connecters — the download-quota
//    case, the whole point of Layer 1.
//
// 3. THE MEASURED RETUNE (night-T-3, schema v31): the sock_ops
//    context carries the socket's own smoothed RTT — uapi
//    bpf_sock_ops.srtt_us (microseconds << 3, populated from
//    tcp_sk(sk)->srtt_us whenever is_fullsock holds, v4.16+, so
//    the 5.13 floor carries it; the same ctx-field class the
//    is_fullsock guard rides). The runtime law is therefore
//    window = rate x max(measured srtt, 200 ms), and the 200 ms
//    constant STOPS being an RTT guess: it is the receiver's
//    window-update CADENCE floor — delivery rides that cadence
//    (the delayed-ACK band the legs measured at 145-160 ms with
//    the band topping at 200 ms), so a window below the cadence
//    under-delivers whatever the link's true RTT says (the briefed
//    50 ms shape measured 29-37% of budget). The measured srtt
//    extends the window ABOVE the floor when the link is longer
//    than the band (the satellite class the fixed floor
//    under-admitted at rate x 200 ms — the same window/cadence
//    law predicts ~1/3 of budget there), and the [2 x MSS, 1 MiB]
//    band bounds both directions. Sub-floor srtt — every short
//    link, and every unmeasured socket (srtt_us reads zero before
//    its first sample) — answers the exact v25 derivation, byte
//    for byte: the retune can only extend the pipe, never shrink
//    it (measured_window_bytes owns the law, recwn_flow.rs the
//    wiring).

/// The Layer 1 RTT assumption, microseconds: 200 ms — the
/// delivery-cadence estimate, raised from the briefed 50 ms by the
/// live evidence (night-spark-2's own E2E legs: the 100 kb rung
/// measured 29-37% of budget and the 500 kb rung 34% on ALL THREE
/// CI kernels — 5.13 floor, 5.15 jammy, and the archive's latest —
/// a deterministic under-delivery, not noise). The mechanism the
/// legs measured: with the receive buffer LOCKED small, delivery
/// rides the receiver's window-update CADENCE, not the link RTT —
/// and the cadence on the test links (and any delayed-ACK-bound
/// receiver) runs ~145-160 ms (Linux's delayed-ACK band tops at
/// 200 ms), so a rate x 50 ms window delivered only ~1/3 of budget
/// (window / cadence). The 200 ms estimate covers the cadence band
/// with margin: the sender holds ~one cadence of bytes in flight,
/// the policer stays the binding constraint (drops remain the
/// enforcement signal — the zero-drop reds the legs filed), and
/// delivered matches the limit — the task brief's own success
/// criterion. The trade, stated honestly: on a genuinely 50 ms
/// link the window now admits 4x that link's BDP — more in-flight
/// than the briefed shape would hold; a measured-RTT re-tune (the
/// RTT_CB lane) is the documented Layer-1+ close.
///
/// night-T-3 LANDED that close (schema v31), and in landing it
/// re-framed the constant: 200 ms is no longer the RTT the lane
/// GUESSES — it is the cadence floor the lane MEASURED, the
/// minimum window budget that delivers on any delayed-ACK-bound
/// receiver. The runtime clamp rides rate x max(measured srtt,
/// THIS); the constant keeps the name it started with (the
/// default RTT the derivation assumes below the band) because the
/// status derivation and its userspace twin pin exactly that
/// shape.
pub const RECWN_DEFAULT_RTT_US: u32 = 200_000;

/// The canonical MSS the clamps are phrased against: 1460 bytes
/// (IPv4 over Ethernet, no options). The floor keeps a policed
/// flow's window from stalling the handshake itself; the exact MSS
/// per route is the kernel's own business (the buffer clamp never
/// consults this beyond the floor).
pub const RECWN_MSS_ASSUME_BYTES: u64 = 1460;

/// The window floor: 2 x MSS, the owner's "~3 KB" — a window below
/// two segments invites delayed-ACK stall pathologies on the very
/// connections the lane is trying to help. Clamping UP to this
/// floor is the documented compromise: a 1 kb/s policy computes
/// 50 bytes of window and still advertises two segments' worth.
pub const RECWN_WINDOW_MIN_BYTES: u64 = 2 * RECWN_MSS_ASSUME_BYTES;

/// The window ceiling: 1 MiB, the over-buffering guard. Above this
/// the advertised window stops being a rate-shaped pipe and starts
/// being a queue the sender fills before the policer ever speaks —
/// the bufferbloat the cadence estimate's band exists to prevent.
pub const RECWN_WINDOW_MAX_BYTES: u64 = 1_048_576;

/// The sanitize guard on the rate input: 4 GiB/s. The product
/// (rate x rtt) rides a PLAIN 64-bit multiply — the BPF ISA has no
/// widening multiply, so a checked/saturating u64 multiply would
/// lower to the `__multi3` runtime call the kernel cannot relocate
/// (the prebuilt-parity gate's own find, the first time an undefined
/// GLOBAL symbol ever reached the lane). Clamping each factor to
/// 2^32 bounds the product at 2^64 - 2^32 — overflow-impossible by
/// construction — and the clamp is invisible for every real input:
/// a rate above 4 GiB/s or an RTT above 71 minutes is far past the
/// band the ceiling collapses to anyway. The userspace twin
/// (src/ebpf/display.rs recwn_window_bytes) carries the SAME shape
/// so the pair cannot drift at any input.
pub const RECWN_RATE_SANITIZE_CAP: u64 = 4_294_967_296;

/// The RECWN target window for one policy rate and one RTT
/// estimate, in bytes: the bandwidth-delay product, clamped to the
/// [2 x MSS, 1 MiB] band. Const so the pins can hold exact values
/// and the datapath pays nothing for the arithmetic. A rate of zero
/// (the block verdict) reads as the floor — though the prime lane
/// never carries it there (the block verdict returns before the
/// priming site, and no window shape can help a lane that delivers
/// nothing).
#[inline(always)]
pub const fn target_window_bytes(rate_bps: u64, rtt_us: u32) -> u64 {
    // Sanitize-then-decide, the burst clamp's own posture: each
    // factor bounded before the plain multiply (the 2^32 caps make
    // the product overflow-impossible — see RECWN_RATE_SANITIZE_CAP),
    // then the band clamp brings any sanitized extreme back down.
    let rate = if rate_bps > RECWN_RATE_SANITIZE_CAP {
        RECWN_RATE_SANITIZE_CAP
    } else {
        rate_bps
    };
    let raw = rate * (rtt_us as u64) / 1_000_000;
    if raw < RECWN_WINDOW_MIN_BYTES {
        RECWN_WINDOW_MIN_BYTES
    } else if raw > RECWN_WINDOW_MAX_BYTES {
        RECWN_WINDOW_MAX_BYTES
    } else {
        raw
    }
}

/// The Layer 1 shorthand: the window the lane derives from a policy
/// rate under the 200 ms cadence estimate. The status twin
/// (src/ebpf/display.rs recwn_lane) reimplements this law in the
/// userspace tree — the twin discipline default_burst carries — and
/// test/ebpf/limiter/recwn_tests.rs pins the two against each other
/// so they can never drift.
#[inline(always)]
pub const fn layer1_window(rate_bps: u64) -> u64 {
    target_window_bytes(rate_bps, RECWN_DEFAULT_RTT_US)
}

/// The Layer 1 RUNTIME window for one policy rate and one socket's
/// measured srtt (microseconds — the sock_ops context's srtt_us,
/// shifted right by the 3-bit store the uapi field carries): the
/// measured retune's law (night-T-3, schema v31). The
/// cadence floor is the law's honesty anchor — a measured RTT
/// below it (every short link, every unmeasured socket) answers
/// the exact layer1 derivation byte for byte, and a measured RTT
/// above it (the link longer than the delayed-ACK band) extends
/// the window to the pipe the floor under-admitted. The band
/// clamp and the plain-multiply sanitize cap carry unchanged:
/// rate is bounded at 2^32 and srtt_us at u32, so the raw product
/// stays under 2^64 by construction — the same overflow-impossible
/// posture target_window_bytes owns. Const so the pins can hold
/// exact values and the datapath pays nothing for the arithmetic.
#[inline(always)]
pub const fn measured_window_bytes(rate_bps: u64, measured_rtt_us: u32) -> u64 {
    // The sub-floor branch IS the layer1 shorthand verbatim — the
    // retune's contract that a short link answers the exact v25
    // window — so the call is the contract, not convenience: the
    // law stays one shape per branch and the shorthand stays
    // load-bearing in the datapath.
    if measured_rtt_us > RECWN_DEFAULT_RTT_US {
        target_window_bytes(rate_bps, measured_rtt_us)
    } else {
        layer1_window(rate_bps)
    }
}
