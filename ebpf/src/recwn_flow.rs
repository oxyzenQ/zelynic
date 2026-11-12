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
//     PRIMES a socket-local hint (recwn_socket_hint:
//     BPF_MAP_TYPE_SK_STORAGE, the row hanging off the kernel's own
//     struct sock, value = the policy's download rate in bytes per
//     second plus the MMSPA GENERATION the prime ran under —
//     night-T-4's schema v32; the window itself stayed a per-socket
//     derivation at the callback since night-T-3's schema v31, rate
//     x max(measured srtt, the 200 ms cadence floor), see
//     ../recwn.rs's measured-retune block). The egress twin never
//     primes: RECWN is the download-quota spine.
//
//     THE SK-STORAGE MIGRATION (night-T-4, schema v32): the hint
//     left the cookie-keyed LRU 4096 world for
//     bpf_sk_storage_get — the state hangs off the kernel's own
//     struct sock, so the lookup pays no hash (the storage rides
//     the socket's own local-storage list), the row cannot be
//     evicted under a live connection (no LRU cap, no fake
//     eviction at 4096+ concurrent sockets), and the row DIES WITH
//     THE SOCKET (the kernel GCs the storage at sock destruction —
//     the aging lane the LRU carried is gone with it). The
//     cookie-reuse ambiguity dies too: a row born on a socket can
//     never answer for a predecessor. The kernel floor carries it:
//     cg_skb_func_proto + sock_ops_func_proto both list
//     bpf_sk_storage_get/delete since v5.9 (verified v5.13 and
//     v5.15 net/core/filter.c), arg2 is ARG_PTR_TO_BTF_ID_SOCK_COMMON
//     (the __sk_buff.sk read the prime site takes —
//     PTR_TO_SOCK_COMMON_OR_NULL after the null check), and the
//     helper's own sk_fullsock guard answers NULL on request/
//     timewait sockets — the same miss posture the cookie-0 skip
//     was.
//
//     THE STALENESS BELT (the sweep's replacement): the row carries
//     the MMSPA generation it was primed under, and every callback
//     compares it against the live generation (the same word the
//     socket lane's stale-token belt and the memo cache already
//     ride). A policy removal bumps the generation, the ingress
//     path stops re-priming, and the row's next callback reads a
//     stale gen and answers the OS default — the removal blind
//     spot the v25 sweep swept HEALS ITSELF now, instantly, with
//     zero userspace involvement: the whole-map sweep lanes (the
//     recwn/pace hint flushes, schema v25/v27) retired with this
//     bump. The row write order is the seq-lock discipline: rate
//     first, generation LAST (the volatile-write order the prime
//     keeps), so a reader that sees the live gen sees the rate
//     that belongs to it — a torn read at worst answers the old
//     gen and misses (the safe direction), never the new gen with
//     a rate from a dead policy.
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
//     Layer 1's). The post-removal residue the v25 doc carried is
//     GONE with the sweep: the generation belt answers the OS
//     default on the very first callback after a removal. The
//     remainder is the honest class the QUIC lane's doc set.

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_SK_STORAGE_GET_F_CREATE, bpf_sock},
    btf_maps::SkStorage,
    helpers::{bpf_setsockopt, generated::bpf_sk_storage_get},
    macros::{btf_map, sock_ops},
    programs::SockOpsContext,
};

use super::mmspa_resolve::current_generation;
use crate::recwn::measured_window_bytes;

/// The sk-storage hint row (night-T-4, schema v32; the tail word
/// repurposed by night-verify-final, schema v33): the policy's
/// download RATE plus the MMSPA GENERATION the prime ran under —
/// the pairing the generation belt reads (the header's staleness
/// block) — plus the MEASURED SRTT the RTT callback harvests. 16
/// bytes: the u64 rate, the u32 generation, the u32 srtt — repr(C),
/// BTF-flat, the same posture every map value carries.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RecwnHint {
    pub rate: u64,
    pub generation: u32,
    /// The repr(C) tail word — the padding carried as a REAL field
    /// the initializer sets, ever since the 5.15 floor's verifier
    /// refused an indirect stack read over compiler padding (the
    /// jammy floor lane's "invalid indirect read from stack R3 ...
    /// size 16" verdict line); an explicit member keeps every byte
    /// of the F_CREATE copy initialized, the BTF value type grows
    /// the member, the byte size holds. Since night-verify-final's
    /// schema v33 the word carries the socket's LATEST measured srtt
    /// in microseconds: written by the RTT_CB lane after the
    /// generation belt accepts the row (zero = unmeasured — the
    /// prime initializes it, and a stale pin's pad reads zero, the
    /// honest posture), harvested by the ingress prime site
    /// ([`recwn_prime`]'s return) and ratcheted into the policy's
    /// stats row.
    pub srtt_us: u32,
}
const _: () = assert!(core::mem::size_of::<RecwnHint>() == 16);

/// The socket-local hint (night-T-4, schema v32): primed by the
/// ingress enforcement hook on the policed path (enforce.rs's prime
/// site) and read back here at the connection callbacks.
/// BPF_MAP_TYPE_SK_STORAGE — the row hangs off the kernel's own
/// struct sock: no hash to pay, no LRU cap to evict under, no row
/// to age (the kernel GCs it at sock destruction). BTF map (the
/// #[btf_map] attribute's .maps section — aya-obj parses the BTF
/// def, the loader's LIBBPF_PIN_BY_NAME pins it by name with every
/// other map). Datapath-internal in SPIRIT: userspace never reads
/// a row and never sweeps one — the generation belt invalidates
/// (the header's staleness block), the sockets' own deaths garbage
/// collect. A hint miss is today's behavior exactly — the default
/// receive window, untouched. The window itself derives at the
/// callback from the row's rate since night-T-3's schema v31
/// (rate x max(measured srtt, the 200 ms cadence floor),
/// ../recwn.rs's measured_window_bytes).
#[allow(non_upper_case_globals)]
#[btf_map]
pub(crate) static recwn_socket_hint: SkStorage<RecwnHint> = SkStorage::new();

/// The map pointer the raw sk_storage helpers take: the BTF map
/// static's own address (aya-ebpf 0.2.1 keeps SkStorage::as_ptr
/// crate-private, but the pointer IS the static's symbol address —
/// the same ld_imm64 the typed wrappers' as_ptr materializes, and
/// the loader relocates it to the map by name exactly the same
/// way).
#[inline(always)]
fn hint_map_ptr() -> *mut core::ffi::c_void {
    core::ptr::from_ref(&recwn_socket_hint).cast_mut().cast()
}

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
    // The socket-local hint row (night-T-4, schema v32): the
    // storage hangs off the kernel's own struct sock — no cookie
    // fetch, no hash: the sk pointer the fullsock guard already
    // vetted IS the identity. A miss (no row, or the helper's
    // fullsock guard refusing a request/timewait sock) is the
    // default receive window, exactly the pre-migration behavior.
    // SAFETY: sk is the non-null socket pointer the union carries
    // (the same pointer the protocol field read above took); the
    // helper returns either NULL or the kernel's own sk_storage
    // value for this map — stable kernel memory for the
    // invocation, the contract every map read in this object
    // rides.
    let row = unsafe { bpf_sk_storage_get(hint_map_ptr(), sk.cast(), core::ptr::null_mut(), 0) };
    if row.is_null() {
        return 0;
    }
    // The generation belt (the sweep's replacement, night-T-4): a
    // row primed under a retired generation answers nothing — the
    // policy that primed it is gone and the ingress path will
    // never re-prime it.
    let row_ptr = row.cast::<RecwnHint>();
    // SAFETY: the gen field is a plain u32 load inside the returned
    // storage value (the addr_of projection the house READ_ONCE
    // discipline pins), valid for the invocation.
    let row_gen = unsafe { core::ptr::addr_of!((*row_ptr).generation).read_volatile() };
    if row_gen != current_generation() {
        return 0;
    }
    // The primed RATE: never a fabricated zero (a hint row is only
    // ever written with the policy's own download rate; the block
    // verdict returns before the prime site). The generation was
    // read and accepted FIRST, so this rate belongs to it — the
    // seq-lock write order (rate first, gen last) pairs them.
    // SAFETY: the same storage value, the same invocation window.
    let rate = unsafe { core::ptr::addr_of!((*row_ptr).rate).read_volatile() };
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
    // The measured-srtt harvest (night-verify-final, schema v33):
    // the socket's latest sample rides the row's tail word for the
    // ingress prime site to ratchet into the policy's stats row —
    // the one volatile store the observability lane costs, on a
    // callback the policed socket already pays. Only a live sample
    // writes (zero is the unmeasured sentinel the prime initialized;
    // the harvest never fabricates one).
    if measured_rtt_us > 0 {
        // SAFETY: the same row pointer the gen/rate reads above
        // took, the same stable-storage-value contract, valid for
        // the invocation.
        unsafe { core::ptr::addr_of_mut!((*row_ptr).srtt_us).write_volatile(measured_rtt_us) };
    }
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
/// download direction only): stamp the SOCKET-LOCAL hint row
/// (night-T-4, schema v32 — the storage hangs off the kernel's own
/// struct sock) with the policy's download RATE under the live
/// MMSPA generation, so the next connection callback on this
/// socket derives the window from it (rate x max(measured srtt,
/// the 200 ms cadence floor), night-T-3's law). Steady state is
/// one sk_storage lookup with no write — the pair only moves when
/// the policy's rate or the generation does. The helper's F_CREATE
/// carries the create-or-get race atomically (two CPUs priming one
/// socket: one allocates with the init pair, both walk out with
/// the same row — the LRU NOEXIST dance's job, gone). A NULL
/// return (non-fullsock sock, storage alloc failure) drops the
/// prime: the hint is best-effort by law, a miss answers the
/// default window, and the connection still rides the ingress
/// policer's own drops — enforcement never depended on this lane.
/// The RETURN (night-verify-final, schema v33): the row's measured
/// srtt harvest word — the RTT callback's latest live sample for
/// this socket, zero when the socket is unmeasured or the prime
/// dropped — for the caller's stats-row ratchet; a value the caller
/// never lowers, the binding-policy high-water the status surfaces
/// report.
pub(crate) fn recwn_prime(sk: *mut bpf_sock, rate_bps: u64) -> u32 {
    let gen_now = current_generation();
    let mut init = RecwnHint {
        rate: rate_bps,
        generation: gen_now,
        srtt_us: 0,
    };
    // SAFETY: sk is the caller's vetted socket pointer (the
    // enforce.rs prime site null-checks the __sk_buff.sk union
    // read before this call); the helper either finds the socket's
    // row or creates it from the stack init pair (F_CREATE), and
    // the return is NULL or the row's value pointer — stable
    // kernel memory for this invocation.
    let row = unsafe {
        bpf_sk_storage_get(
            hint_map_ptr(),
            sk.cast(),
            core::ptr::addr_of_mut!(init).cast(),
            BPF_SK_STORAGE_GET_F_CREATE.into(),
        )
    };
    if row.is_null() {
        return 0;
    }
    // The refresh path: a row whose rate or generation moved gets
    // the pair rewritten — rate FIRST, generation LAST (the
    // seq-lock order the header's staleness block owns: a reader
    // that accepts the gen has already seen the rate that belongs
    // to it; a reader mid-write sees the old gen and misses). The
    // two volatile stores are idempotent under the prime race
    // (both CPUs resolve the same policy, both write the same
    // pair).
    let row_ptr = row.cast::<RecwnHint>();
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
    // The harvest read (night-verify-final, schema v33): whatever
    // srtt the RTT lane last left on this row — zero when the socket
    // is unmeasured (a fresh row, no RTT callback yet). The refresh
    // above never touches the word: the samples belong to the
    // socket, not to the policy write. SAFETY: the same row, the
    // same invocation window.
    unsafe { core::ptr::addr_of!((*row_ptr).srtt_us).read_volatile() }
}

/// The read-only srtt peek (night-frontier-2B): the depth
/// histogram's latency half reads the RTT lane's measurement WITHOUT
/// the prime's create/refresh semantics — flags 0 (no F_CREATE), so
/// a socket the lane never owned answers 0 and stays rowless. The
/// word is MICROSECONDS (the RTT callback stored it >> 3 — see the
/// harvest write above). SAFETY: the same vetted socket pointer
/// contract the prime site rides (the __sk_buff.sk union read,
/// null-checked by the caller); the return is the row's own srtt
/// word read volatile, 0 when the row is absent or unmeasured —
/// the honest absence, never a fabricated sample.
pub(crate) fn recwn_peek_srtt(sk: *mut bpf_sock) -> u32 {
    // SAFETY: the same vetted socket pointer contract the prime site
    // rides (the __sk_buff.sk union read, null-checked by the
    // caller); flags 0 means lookup-only — the helper either finds
    // the socket's existing row or answers NULL, never a create.
    let row = unsafe { bpf_sk_storage_get(hint_map_ptr(), sk.cast(), core::ptr::null_mut(), 0) };
    if row.is_null() {
        return 0;
    }
    // SAFETY: the helper returned the row's value pointer — the
    // stable-memory contract the read path rides.
    unsafe { core::ptr::addr_of!((*row.cast::<RecwnHint>()).srtt_us).read_volatile() }
}
