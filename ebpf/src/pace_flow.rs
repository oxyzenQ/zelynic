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
//     PRIMES a socket-local hint (pace_socket_hint:
//     BPF_MAP_TYPE_SK_STORAGE, the row hanging off the kernel's own
//     struct sock, value = upload rate in bytes per second plus
//     the MMSPA generation, night-T-4's schema v32 — the recwn
//     twin's migration, one layer up: no hash, no LRU cap, the row
//     dies with the socket, the generation belt replaces the
//     removal sweep; the recwn header carries the full record).
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
//     recwn lane's own residue, one layer up); the post-removal
//     residue the v27 doc carried is GONE with the sweep (the
//     generation belt answers the OS default on the very first
//     callback after a removal); and UDP/QUIC sockets never reach
//     this program — QUIC paces itself (RFC 9000), the upload
//     lane's UDP story stays the policer's.

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_SK_STORAGE_GET_F_CREATE, bpf_sock},
    btf_maps::SkStorage,
    helpers::{bpf_setsockopt, generated::bpf_sk_storage_get},
    macros::{btf_map, sock_ops},
    programs::SockOpsContext,
};

use super::mmspa_resolve::current_generation;

use crate::pace::pacing_decision;

/// The sk-storage hint row (night-T-4, schema v32): the upload
/// RATE plus the MMSPA GENERATION the prime ran under — the same
/// pairing the recwn twin carries (the seq-lock write order: rate
/// first, generation LAST). 16 bytes, repr(C), BTF-flat.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PaceHint {
    pub rate: u64,
    pub generation: u32,
    /// The repr(C) tail padding, carried as a REAL field the
    /// initializer sets: the sk-storage helper's F_CREATE copies the
    /// whole 16-byte value from the stack, and the 5.15 floor's
    /// verifier refuses an indirect stack read over compiler padding
    /// the field stores never initialized ("invalid indirect read
    /// from stack R3 ... size 16" — the jammy floor lane's verdict
    /// line). An explicit zeroed member keeps every byte of the read
    /// initialized; the BTF value type grows the member, the byte
    /// size holds.
    pub pad: u32,
}
const _: () = assert!(core::mem::size_of::<PaceHint>() == 16);

/// The socket-local pacing hint (night-T-4, schema v32): primed by
/// the egress enforcement hook on the policed path (enforce.rs's
/// pace site) and read back here at the connection callbacks.
/// BPF_MAP_TYPE_SK_STORAGE — the row hangs off the kernel's own
/// struct sock: no hash to pay, no LRU cap to evict under, no row
/// to age (the kernel GCs it at sock destruction; the recwn twin's
/// header carries the full migration record). BTF map (the
/// #[btf_map] attribute's .maps section). Datapath-internal in
/// SPIRIT: userspace never reads a row and never sweeps one — the
/// generation belt invalidates, the sockets' own deaths garbage
/// collect. A hint miss is today's behavior exactly — the default
/// pacing, untouched.
#[allow(non_upper_case_globals)]
#[btf_map]
pub(crate) static pace_socket_hint: SkStorage<PaceHint> = SkStorage::new();

/// The map pointer the raw sk_storage helpers take — the recwn
/// twin's hint_map_ptr note verbatim (aya-ebpf 0.2.1 keeps
/// SkStorage::as_ptr crate-private; the pointer is the static's
/// symbol address, relocated to the map by name exactly the same
/// way).
#[inline(always)]
fn pace_map_ptr() -> *mut core::ffi::c_void {
    core::ptr::from_ref(&pace_socket_hint).cast_mut().cast()
}

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
    // The socket-local hint row (night-T-4, schema v32): the
    // storage hangs off the kernel's own struct sock — no cookie
    // fetch, no hash: the sk pointer the fullsock guard already
    // vetted IS the identity. A miss is the default pacing, exactly
    // the pre-migration behavior. SAFETY: sk is the non-null socket
    // pointer the union carries (the same pointer the protocol
    // field read above took); the helper returns either NULL or
    // the kernel's own sk_storage value for this map — stable
    // kernel memory for the invocation, the contract every map
    // read in this object rides.
    let row = unsafe { bpf_sk_storage_get(pace_map_ptr(), sk.cast(), core::ptr::null_mut(), 0) };
    if row.is_null() {
        return 0;
    }
    // The generation belt (the sweep's replacement, night-T-4): a
    // row primed under a retired generation answers nothing. The
    // seq-lock read order: gen first, then the rate the accepted
    // gen pairs with.
    let row_ptr = row.cast::<PaceHint>();
    // SAFETY: plain field loads inside the returned storage value,
    // the addr_of projection the house READ_ONCE discipline pins,
    // valid for the invocation.
    let row_gen = unsafe { core::ptr::addr_of!((*row_ptr).generation).read_volatile() };
    if row_gen != current_generation() {
        return 0;
    }
    // SAFETY: the same storage value, the same invocation window.
    let hinted = unsafe { core::ptr::addr_of!((*row_ptr).rate).read_volatile() };
    if hinted == 0 {
        return 0;
    }
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
/// direction only): stamp the SOCKET-LOCAL hint row (night-T-4,
/// schema v32 — the storage hangs off the kernel's own struct sock)
/// with the upload rate the current policy carries under the live
/// MMSPA generation, so the next connection callback on this socket
/// paces at it. Steady state is one sk_storage lookup with no
/// write. The helper's F_CREATE carries the create-or-get race
/// atomically (the recwn twin's note verbatim). A NULL return
/// (non-fullsock sock, storage alloc failure) drops the prime: the
/// hint is best-effort by law, a miss answers the default pacing,
/// and the connection still rides the egress policer's own
/// verdicts — enforcement never depended on this lane.
pub(crate) fn pace_prime(sk: *mut bpf_sock, rate_bps: u64) {
    let gen_now = current_generation();
    let mut init = PaceHint {
        rate: rate_bps,
        generation: gen_now,
        pad: 0,
    };
    // SAFETY: sk is the caller's vetted socket pointer (the
    // enforce.rs pace site null-checks the __sk_buff.sk union read
    // before this call); the helper either finds the socket's row
    // or creates it from the stack init pair (F_CREATE), and the
    // return is NULL or the row's value pointer — stable kernel
    // memory for this invocation.
    let row = unsafe {
        bpf_sk_storage_get(
            pace_map_ptr(),
            sk.cast(),
            core::ptr::addr_of_mut!(init).cast(),
            BPF_SK_STORAGE_GET_F_CREATE.into(),
        )
    };
    if row.is_null() {
        return;
    }
    // The refresh path: rate FIRST, generation LAST — the seq-lock
    // order the recwn twin's header owns. The two volatile stores
    // are idempotent under the prime race (both CPUs resolve the
    // same policy, both write the same pair).
    let row_ptr = row.cast::<PaceHint>();
    // SAFETY: the row pointer the helper returned — the same
    // stable-memory value contract the read path rides, valid for
    // the invocation.
    let cur_rate = unsafe { core::ptr::addr_of!((*row_ptr).rate).read_volatile() };
    // SAFETY: the same row, the same invocation window.
    let cur_gen = unsafe { core::ptr::addr_of!((*row_ptr).generation).read_volatile() };
    if cur_rate != rate_bps || cur_gen != gen_now {
        // SAFETY: the same row, the rate store first.
        unsafe { core::ptr::addr_of_mut!((*row_ptr).rate).write_volatile(rate_bps) };
        // SAFETY: the same row, the generation store LAST — the
        // pairing order the belt reads.
        unsafe { core::ptr::addr_of_mut!((*row_ptr).generation).write_volatile(gen_now) };
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
