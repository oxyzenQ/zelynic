// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// night-spark-5 (Egress Socket Pacing — Layer 3 of the quota
// saver): the sock_ops wiring, the aya-touching half of the lane —
// the recwn_flow precedent one layer up. The pure pacing law lives
// in ../pace.rs; this file owns the program, the hint map, and the
// kernel helper calls only the kernel side can make.
//
// THE LANE (shaped by the same verified 5.15 kernel truths the
// RECWN lane recorded — see ../recwn.rs's header for the
// source-anchored record):
//
//   * A sock_ops program cannot resolve its own cgroup
//     (bpf_get_current_cgroup_id is absent from sock_ops_func_proto
//     on the 5.15 floor), so the EGRESS enforcement hook — which
//     resolves every packet's socket cgroup exactly, per packet —
//     PRIMES a cookie-keyed hint (pace_socket_hint: socket cookie
//     u64 -> upload rate in bytes per second, LRU 4096, pinned, the
//     recwn_socket_hint posture) on the policed path.
//
//   * The connection callbacks' return values are ignored by the
//     pacing dispatch (only RWND_INIT's return means anything, and
//     it is an MSS multiplier this lane has no opinion about), so
//     the program returns 0 on every path and bpf_setsockopt
//     (SO_MAX_PACING_RATE) carries the whole lane: the stack's
//     internal pacer hrtimer-limits the write path at the pinned
//     rate while no pacing qdisc claims the socket — the kernel's
//     own bytes-per-second clock, no tc anywhere.
//
// THE CONVERGENCE (when the pin actually lands):
//   * ACTIVE connecters — the upload-quota case: the SYN egresses
//     through the policed cgroup and primes the socket's own cookie
//     BEFORE tcp_init_transfer dispatches ACTIVE_ESTABLISHED_CB, so
//     the pacing rate is pinned before the first data-bearing
//     packet. The un-paced exposure is the handshake itself — a few
//     packets, no data (the upload leg's own shape).
//   * Rate changes: the egress re-prime overwrites the hint, and
//     the RTT_CB flag armed at establishment re-applies the pin
//     within one RTT — on flagged (policed) sockets only.
//   * The documented residue: a PASSIVE child's cookie is primed by
//     its first DATA packet, which arrives after
//     PASSIVE_ESTABLISHED_CB has already fired and found nothing —
//     so server-side sockets under an upload-only policing cgroup
//     ride the default pacing for their first window's worth (the
//     recwn lane's own residue, one layer up); connections that
//     outlived their policy's removal keep their last rate until
//     they close (the sweep removes the hint; connection churn
//     heals); and UDP/QUIC sockets never reach this program — QUIC
//     paces itself (RFC 9000), the upload lane's UDP story stays
//     the policer's.

use aya_ebpf::{
    EbpfContext,
    bindings::bpf_sock,
    helpers::{bpf_get_socket_cookie, bpf_setsockopt},
    macros::{map, sock_ops},
    maps::LruHashMap,
    programs::SockOpsContext,
};

use crate::pace::pacing_decision;

/// The socket cookie -> upload pacing rate hint, primed by the
/// egress enforcement hook on the policed path (enforce.rs's pace
/// site) and read back here at the connection callbacks. LRU 4096
/// so dead sockets age out — the recwn_socket_hint posture, one
/// layer over. Pinned (survives process exit, shared with the
/// prime site by object construction) but datapath-internal in
/// SPIRIT: userspace only ever sweeps it whole on policy removals
/// (limiter/pace.rs, the recwn sweep's posture), it never reads a
/// row. A hint miss is today's behavior exactly — the default
/// pacing, untouched.
#[allow(non_upper_case_globals)]
#[map]
pub(crate) static pace_socket_hint: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

// The kernel uapi constants this file rides (include/uapi/linux/bpf.h
// and include/uapi/asm-generic/socket.h — aya-ebpf 0.2.1 does not
// bind the sock_ops callback op ids, and the socket option pair is
// pinned by value with its uapi anchor either way; the recwn twin's
// own constants live one lane over).
const BPF_SOCK_OPS_RWND_INIT_OP: u32 = 2;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP: u32 = 5;
const BPF_SOCK_OPS_RTT_CB_OP: u32 = 12;
const BPF_SOCK_OPS_RTT_CB_FLAG_VALUE: i32 = 8;

/// `setsockopt` levels/options: SOL_SOCKET / SO_MAX_PACING_RATE
/// (asm-generic/socket.h option 47 — the one knob that tells the
/// TCP stack to pace a socket's outgoing stream at a byte rate
/// with no qdisc of its own: the stack's internal pacer
/// hrtimer-limits the write path while sk_pacing_status says CPU).
const SOL_SOCKET_LEVEL: i32 = 1;
const SO_MAX_PACING_RATE_OPT: i32 = 47;

/// IPPROTO_TCP (the recwn twin's armor note verbatim: the sock_ops
/// dispatch is TCP-only by construction — every tcp_call_bpf call
/// site lives in TCP code — so the check is armor against a future
/// kernel firing these ops at another protocol family, not a live
/// filter).
const IPPROTO_TCP: u32 = 6;

/// The pacing program (BPF_PROG_TYPE_SOCK_OPS, section "sockops").
/// Attached once at the cgroup root beside the two enforcement
/// hooks and the RECWN twin; the cookie hint carries the per-cgroup
/// truth the program itself cannot resolve on the 5.15 floor. Every
/// op it does not own answers 0 — the neutral return every other
/// sock_ops callback reads as "no opinion".
#[sock_ops]
fn zelynic_pace(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        BPF_SOCK_OPS_RWND_INIT_OP
        | BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP
        | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP
        | BPF_SOCK_OPS_RTT_CB_OP => pace_apply(&ctx),
        _ => 0,
    }
}

/// One connection callback's worth of pacing: read the socket's
/// primed hint, and when a policy stands, pin SO_MAX_PACING_RATE to
/// the hinted rate. Returns 0 on every path — the neutral answer
/// (the RWND_INIT dispatch reads 0 as "OS default", an MSS
/// multiplier this lane has no opinion about; the established
/// callbacks' returns are ignored by their dispatch sites).
fn pace_apply(ctx: &SockOpsContext) -> u32 {
    // The kernel's own full-socket guard, mirrored before any
    // option write: the RWND_INIT dispatch on the passive side
    // carries the REQUEST socket (is_fullsock 0), where
    // _bpf_setsockopt would refuse with EINVAL anyway — the belt
    // keeps the refusal free. Every other owned op is fullsock by
    // construction (tcp_init_transfer sets it before dispatch).
    // SAFETY: the context pointer is the program's own (the
    // ARG_PTR_TO_CTX contract every helper call below rides too);
    // the field read is a plain u32 load the verifier proves.
    if unsafe { (*ctx.ops).is_fullsock } != 1 {
        return 0;
    }
    // SAFETY: same ctx contract; the union read yields the kernel's
    // sk pointer, null-checked before any deref of it below.
    let sk: *mut bpf_sock = unsafe { (*ctx.ops).__bindgen_anon_2.sk };
    if sk.is_null() {
        return 0;
    }
    // SAFETY: sk is the non-null socket pointer the union carries;
    // the protocol field is a plain u32 load inside bpf_sock.
    if unsafe { (*sk).protocol } != IPPROTO_TCP {
        return 0;
    }
    // The socket's cookie: the same identity the egress prime
    // keyed on. ARG_PTR_TO_CTX — the sock_ops variant of the
    // helper takes the context itself (net/core/filter.c
    // bpf_get_socket_cookie_sock_ops_proto), not the sk.
    // SAFETY: the ctx pointer is the program's own; the return is
    // a plain u64 cookie, no pointer crosses back.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        return 0;
    }
    // The primed rate: a miss is the default pacing, exactly
    // today's behavior — never a fabricated zero (a hint row is
    // only ever written with the policy's own rate).
    // SAFETY: the hint map read shares the contract every map read
    // in this object rides — the kernel holds the map value in
    // stable memory for the invocation, and the shared borrow ends
    // before any write lane below runs.
    let hinted = match unsafe { pace_socket_hint.get(cookie) } {
        Some(r) => *r,
        None => return 0,
    };
    // The decision (the pure law, ../pace.rs): the owned op on a
    // full TCP socket with a primed, nonzero rate paces; every
    // other shape answers None and the socket rides untouched. The
    // guards above already ran, so the wiring hands the law the
    // shapes it observed — the rootless pin simulates the same call
    // with every shape the kernel can produce.
    let rate = match pacing_decision(true, true, true, Some(hinted)) {
        Some(rate) => rate,
        None => return 0,
    };
    // The pin itself. The value passes through the kernel's
    // SO_MAX_PACING_RATE shape: sock_setsockopt stores it into
    // sk_max_pacing_rate and the TCP write path paces at it — the
    // stack's internal pacer (tcp_output.c's tcp_internal_pacing on
    // the 5.15 floor) hrtimer-limits the transmit path while no
    // pacing qdisc claims the socket, the kernel-native clock the
    // no-tc claim stands on. The decision already clamped the uapi
    // field's u32 width.
    // SAFETY: the ctx pointer is the program's own (ARG_PTR_TO_CTX
    // — bpf_sock_ops_setsockopt_proto's contract); optval points at
    // a stack u32 of the exact optlen the helper requires.
    let ret = unsafe {
        bpf_setsockopt(
            ctx.as_ptr(),
            SOL_SOCKET_LEVEL,
            SO_MAX_PACING_RATE_OPT,
            &rate as *const u32 as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as i32,
        )
    };
    if ret != 0 {
        return 0;
    }
    // Arm the per-RTT re-apply on the establishment hits only: a
    // socket whose policy stood at establishment is a policed
    // socket, and its per-RTT re-check is feature cost the
    // unpoliced majority never shares (the recwn twin's own note).
    // The RWND_INIT dispatch never arms: it cannot know whether the
    // hint it just read was primed by this connection's own
    // handshake or aged in from a predecessor; establishment can.
    // The RECWN twin arms the same flag one lane over — the write
    // is idempotent (the same single bit), and these two lanes are
    // the socket's flag word's only writers.
    let op = ctx.op();
    if op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP {
        // SAFETY: the flag write rides the ctx-bound helper
        // (bpf_sock_ops_cb_flags_set); the value is the uapi
        // RTT_CB flag alone.
        let _ = ctx.set_cb_flags(BPF_SOCK_OPS_RTT_CB_FLAG_VALUE);
    }
    0
}

/// The egress prime (called from enforce.rs's policed path, upload
/// direction only): stamp the socket's cookie with the rate the
/// current policy carries, so the next connection callback on this
/// socket paces at it. Steady state is one LRU lookup with no
/// write — the value only moves when the policy's rate does. A full
/// LRU (4096 live cookies) drops the prime: the hint is
/// best-effort by law, a miss answers the default pacing, and the
/// connection still rides the egress policer's own verdicts —
/// enforcement never depended on this lane.
pub(crate) fn pace_prime(cookie: u64, rate_bps: u64) {
    match pace_socket_hint.get_ptr_mut(cookie) {
        Some(ptr) => {
            // SAFETY: the hint map's value pointer lives in stable
            // kernel memory for this invocation; the borrow is the
            // only one this lane takes, and the store is a plain
            // u64 write the verifier proves.
            if unsafe { *ptr } != rate_bps {
                // SAFETY: the same stable-memory value pointer the
                // read above took — the plain u64 store the
                // verifier proves, this invocation's only writer.
                unsafe { *ptr = rate_bps };
            }
        }
        None => {
            let _ = pace_socket_hint.insert(cookie, rate_bps, 0);
        }
    }
}

// night-quota-audit (2026-11-09): the Layer 4 saved-headroom accrual
// (pace_saved_stamp + pace_saved_accrue) is RETIRED with the law it
// served (../pace.rs carries the record): the headroom formula's
// only nonzero content was the budget an idle sender never used —
// the owner's live reading had it erring HIGH by up to 36.8x against
// the documented contract. The pacing lane's hint map and the
// sock_ops pin above are the lane's ENFORCEMENT and stay untouched;
// the retired word reads zero from schema v29 on.
