// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// night-spark-2 (RECWN, Receive Window Control — Layer 1 of the
// quota saver): the sock_ops wiring, the aya-touching half of the
// lane — the socket_flow/quic_flow precedent one feature over. The
// pure window law lives in ../recwn.rs; this file owns the program,
// the hint map, and the kernel helper calls only the kernel side
// can make.
//
// THE LANE (shaped by two verified 5.15 kernel truths — see
// ../recwn.rs's header for the source-anchored record):
//
//   * A sock_ops program cannot resolve its own cgroup
//     (bpf_get_current_cgroup_id is absent from sock_ops_func_proto
//     on the 5.15 floor), so the ingress enforcement hook — which
//     resolves every packet's socket cgroup exactly, per packet —
//     PRIMES a cookie-keyed hint (recwn_socket_hint: socket cookie
//     u64 -> the policy's download rate in bytes per second,
//     night-T-3's schema v31 — the row stopped carrying the window
//     because the window became a per-socket derivation at the
//     callback, rate x max(measured srtt, the 200 ms cadence
//     floor), see ../recwn.rs's measured-retune block; LRU 4096,
//     pinned, the quic_cid_hint posture) on the policed path. The
//     egress twin never primes: RECWN is the download-quota spine.
//
//   * The RWND_INIT callback's return value is an MSS multiplier
//     where 0 means "OS default" (include/net/tcp.h
//     tcp_rwnd_init_bpf + tcp_select_initial_window's
//     min(*rcv_wnd, init_rcv_wnd * mss)), so the program returns 0
//     on every path and bpf_setsockopt(SO_RCVBUF) carries the
//     clamp: the buffer bounds the initial window through
//     tcp_full_space (SO_RCVBUF_LOCK + window_clamp) and every
//     later window update through tcp_select_window — byte-exact,
//     no MSS guess, and impossible to regress the unpoliced
//     majority with.
//
// THE CONVERGENCE (when the clamp actually lands):
//   * ACTIVE connecters — the download-quota case: the SYN-ACK
//     ingresses through the policed cgroup and primes the socket's
//     own cookie BEFORE tcp_init_transfer dispatches
//     ACTIVE_ESTABLISHED_CB, so the clamp is in place before the
//     first data-bearing window update. The unclamped exposure is
//     the initial window itself (~10 MSS), one time, per
//     connection.
//   * Rate changes: the ingress re-prime overwrites the hint, and
//     the RTT_CB flag armed at establishment re-applies the buffer
//     within one RTT — the "dynamic updates" bullet of the owner's
//     brief, on flagged (policed) sockets only.
//   * The measured retune (night-T-3, schema v31): every owned op
//     derives the window from the socket's OWN srtt (the sock_ops
//     context field, v4.16+) with the 200 ms cadence floor beneath
//     it — establishment clamps to the handshake's own RTT where
//     the link runs longer than the band, the armed RTT_CB
//     re-derives per sample, and every short link plus every
//     unmeasured socket answers the exact v25 window, byte for
//     byte (../recwn.rs's measured-retune block owns the record).
//   * The documented residue: a PASSIVE child's cookie is primed by
//     its first DATA packet, which arrives after
//     PASSIVE_ESTABLISHED_CB has already fired and found nothing —
//     so server-side sockets under an upload-only policing cgroup
//     ride the default receive window for their first window's
//     worth (the upload lane is the ECN/EDT layers' business, not
//     Layer 1's); and connections that outlived their policy's
//     removal keep their last window until they close (the sweep
//     removes the hint; connection churn heals). Both are the
//     honest-remainder class the QUIC lane's doc set.

use aya_ebpf::{
    EbpfContext,
    bindings::bpf_sock,
    helpers::{bpf_get_socket_cookie, bpf_setsockopt},
    macros::{map, sock_ops},
    maps::LruHashMap,
    programs::SockOpsContext,
};

use crate::recwn::measured_window_bytes;

/// The socket cookie -> policy download rate hint, primed by the
/// ingress enforcement hook on the policed path (enforce.rs's prime
/// site) and read back here at the connection callbacks. LRU 4096
/// so dead sockets age out — the quic_cid_hint posture, one lane
/// over. Pinned (survives process exit, shared with the prime site
/// by object construction) but datapath-internal in SPIRIT:
/// userspace only ever sweeps it whole on policy removals (the
/// limiter's recwn_hint_invalidate, the MMSPA flush's posture), it
/// never reads a row. The row carries the RATE since night-T-3's
/// schema v31 — the window is a per-socket derivation at the
/// callback (rate x max(measured srtt, the 200 ms cadence floor),
/// ../recwn.rs's measured_window_bytes), so a rate change re-primes
/// and every callback answers the rate's CURRENT law without the
/// row ever going stale mid-window. A hint miss is today's behavior
/// exactly — the default receive window, untouched.
#[allow(non_upper_case_globals)]
#[map]
pub(crate) static recwn_socket_hint: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

// The kernel uapi constants this file rides (include/uapi/linux/bpf.h
// and include/linux/socket.h — aya-ebpf 0.2.1 does not bind the
// sock_ops callback op ids, and the socket option pair is pinned by
// value with its uapi anchor either way).
const BPF_SOCK_OPS_RWND_INIT_OP: u32 = 2;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP: u32 = 5;
const BPF_SOCK_OPS_RTT_CB_OP: u32 = 12;
const BPF_SOCK_OPS_RTT_CB_FLAG_VALUE: i32 = 8;

/// `setsockopt` levels/options: SOL_SOCKET / SO_RCVBUF (the one
/// knob that caps a TCP sender's in-flight bytes before the link
/// bills them — the quota saver's spine).
const SOL_SOCKET_LEVEL: i32 = 1;
const SO_RCVBUF_OPT: i32 = 8;

/// IPPROTO_TCP (the protocol belt the task brief mandates; the
/// sock_ops dispatch is TCP-only by construction — every
/// tcp_call_bpf call site lives in TCP code — so the check is
/// armor against a future kernel firing these ops at another
/// protocol family, not a live filter).
const IPPROTO_TCP: u32 = 6;

/// The RECWN program (BPF_PROG_TYPE_SOCK_OPS, section "sockops").
/// Attached once at the cgroup root beside the two enforcement
/// hooks; the cookie hint carries the per-cgroup truth the program
/// itself cannot resolve on the 5.15 floor. Every op it does not
/// own answers 0 — the neutral return every other sock_ops
/// callback reads as "no opinion".
#[sock_ops]
fn zelynic_recwn(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        BPF_SOCK_OPS_RWND_INIT_OP
        | BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP
        | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP
        | BPF_SOCK_OPS_RTT_CB_OP => recwn_apply(&ctx),
        _ => 0,
    }
}

/// One connection callback's worth of RECWN: read the socket's
/// primed hint, and when a policy stands, clamp the receive buffer
/// to the derived window. Returns 0 on every path — the kernel's
/// "OS default" answer for the RWND_INIT dispatch (the MSS-
/// multiplier semantics documented in ../recwn.rs), and the
/// neutral answer for the established callbacks (their return
/// value is ignored by the dispatch sites).
fn recwn_apply(ctx: &SockOpsContext) -> u32 {
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
    // The socket's cookie: the same identity the ingress prime
    // keyed on. ARG_PTR_TO_CTX — the sock_ops variant of the
    // helper takes the context itself (net/core/filter.c
    // bpf_get_socket_cookie_sock_ops_proto), not the sk.
    // SAFETY: the ctx pointer is the program's own; the return is
    // a plain u64 cookie, no pointer crosses back.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        return 0;
    }
    // The primed RATE: a miss is the default receive window,
    // exactly today's behavior — never a fabricated zero (a hint
    // row is only ever written with the policy's own download
    // rate; the block verdict returns before the prime site). The
    // window derives HERE, per callback, from the rate and this
    // socket's own measured srtt (night-T-3's measured retune,
    // schema v31): the 200 ms cadence floor beneath, the measured
    // RTT extending above, the band clamp on top.
    // SAFETY: the hint map read shares the contract every map read
    // in this object rides — the kernel holds the map value in
    // stable memory for the invocation, and the shared borrow ends
    // before any write lane below runs.
    let rate = match unsafe { recwn_socket_hint.get(cookie) } {
        Some(r) => *r,
        None => return 0,
    };
    if rate == 0 {
        return 0;
    }
    // The socket's own smoothed RTT — uapi bpf_sock_ops.srtt_us
    // (microseconds << 3, populated from tcp_sk(sk)->srtt_us
    // whenever is_fullsock holds — the guard above — v4.16+, so
    // the 5.13 floor carries it). SAFETY: the same fullsock ops
    // pointer the is_fullsock read took; srtt_us is a plain u32
    // load the verifier proves.
    let measured_rtt_us: u32 = unsafe { (*ctx.ops).srtt_us } >> 3;
    let window = measured_window_bytes(rate, measured_rtt_us);
    // The clamp itself. The value passes through the kernel's
    // SO_RCVBUF shape: sock_setsockopt doubles it into sk_rcvbuf
    // (max(val * 2, SOCK_MIN_RCVBUF), capped at rmem_max — the
    // documented ceiling the lane rides), and SOCK_RCVBUF_LOCK
    // lands with it, which is what folds the window_clamp down to
    // the buffer-derived space the initial advertisement and every
    // later window update read. The law's bytes are therefore the
    // PASSED value, matching the task brief's arithmetic exactly.
    let optval: i32 = window.min(i32::MAX as u64) as i32;
    // SAFETY: the ctx pointer is the program's own (ARG_PTR_TO_CTX
    // — bpf_sock_ops_setsockopt_proto's contract); optval points at
    // a stack i32 of the exact optlen the helper requires.
    let ret = unsafe {
        bpf_setsockopt(
            ctx.as_ptr(),
            SOL_SOCKET_LEVEL,
            SO_RCVBUF_OPT,
            &optval as *const i32 as *mut core::ffi::c_void,
            core::mem::size_of::<i32>() as i32,
        )
    };
    if ret != 0 {
        return 0;
    }
    // Arm the per-RTT re-apply on the establishment hits only: a
    // socket whose policy stood at establishment is a policed
    // socket, and its per-RTT re-check is feature cost the
    // unpoliced majority never shares (the flag is per-socket —
    // the RTT_CB dispatch answers it, tcp_bpf_rtt's own gate). The
    // RWND_INIT dispatch never arms: it cannot know whether the
    // hint it just read was primed by this connection's own
    // handshake or aged in from a predecessor; establishment can.
    let op = ctx.op();
    if op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB_OP || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_OP {
        // SAFETY: the flag write rides the ctx-bound helper
        // (bpf_sock_ops_cb_flags_set); the value is the uapi
        // RTT_CB flag alone — this program is the only writer the
        // socket's flag word has.
        let _ = ctx.set_cb_flags(BPF_SOCK_OPS_RTT_CB_FLAG_VALUE);
    }
    0
}

/// The ingress prime (called from enforce.rs's policed path,
/// download direction only): stamp the socket's cookie with the
/// policy's download RATE (night-T-3's schema v31 — the window is
/// a per-socket derivation at the callback, rate x max(measured
/// srtt, the 200 ms cadence floor)), so the next connection
/// callback on this socket clamps to it. Steady state is one LRU
/// lookup with no write — the value only moves when the policy's
/// rate does. A full LRU (4096 live cookies) drops the prime: the
/// hint is best-effort by law, a miss answers the default window,
/// and the connection still rides the ingress policer's own drops
/// — enforcement never depended on this lane.
pub(crate) fn recwn_prime(cookie: u64, rate_bps: u64) {
    match recwn_socket_hint.get_ptr_mut(cookie) {
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
            let _ = recwn_socket_hint.insert(cookie, rate_bps, 0);
        }
    }
}
