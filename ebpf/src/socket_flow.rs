// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The per-socket datapath wiring (NIGHT-upgrade-charger-core-3b,
// Tier B #7 — per-socket limiting, beyond cgroup): the aya-touching
// half of the lane the owner's list called the hard one, made
// ordinary by the observer's own two-year-old proof — the kernel
// already names the owning socket per packet in both cgroup_skb
// hooks (bpf_get_socket_cookie, NIGHT-boost-26's cookie join: the
// sender on upload, the receiver on download). No tracepoint is
// needed for attribution the hook itself carries; the limiter
// simply spends through a bucket keyed by that cookie instead of
// the socket's cgroup.
//
// Everything here follows the drr_flow.rs precedent one feature
// over (the aya-touching split):
//   * the per-socket bucket maps (socket cookie u64 -> SocketBucket),
//     one per direction, LRU 4096 so dead sockets age out instead of
//     filling the lane — the leaf-bucket posture, and the observer's
//     own per-socket byte map's posture before it;
//   * the spend path: the SAME refill_window + try_consume + book
//     the legacy lanes run, on the socket's own Bucket — each socket
//     holds its own tokens at the policy rate, so a server's N
//     concurrent connections each get the full rate (the documented
//     budget law: the cgroup total is bounded by rate x concurrent
//     sockets, not by rate — that is what per-socket MEANS);
//   * the stale-token belt: the bucket's generation stamp (the
//     AMMSP generation every policy mutation bumps) zeroes a socket
//     bucket's tokens on the first packet after a mutation, so a
//     limit change can never leave a socket spending a dead budget's
//     burst — the DRR leaf belt, one lane over. A dedicated gen
//     field (SocketBucket is 40 bytes, a NEW map with no pinned
//     layout to preserve) instead of the DRR trick of reusing
//     frac_rem, because this lane RUNS the refill math and frac_rem
//     is load-bearing here.
//
//   * the ECN debt word (schema v21, the per-socket convergence
//     closure): the lane's drop verdict became a LAST RESORT the
//     way every budgeted lane's did — mark before drop. The debt
//     lives INSIDE the bucket (no map, no key): a per-connection
//     budget's debt is per-connection state, the belt zeroes it with
//     the tokens on a generation bump (a fresh budget never inherits
//     the predecessor's debt — the repair-6 discipline, structural
//     here), and the LRU ages the whole bucket out together (one
//     posture, not two). The deferred question the marking rode on —
//     "a server's N connections each halving their windows on
//     per-connection marks is an aggregate-collapse shape" — is
//     closed by the rootless fleet sims in test/ebpf/limiter/
//     ecn_tests.rs (the per-socket convergence analysis): per-
//     connection budgets are independent, so each connection
//     converges on its own stream and the fleet rides N x
//     per-connection — no collapse term exists. The budget law, one
//     connection at a time: delivered_i <= rate*t + burst + one
//     64 KiB super-packet (the ecn.rs closed form, unchanged — the
//     aggregate honest bound is N x that, the per-socket lane's own
//     documented "rate x concurrent sockets" shape plus the one-time
//     per-connection ECN slack).
//
// The cookie == 0 degrade: a packet with no socket attribution (the
// helper returns 0 when skb->sk is unset — early ingress before
// demux, some local paths) never rides this lane; try_enforce falls
// through to the DRR cgroup lane, so the packet is still policed at
// the cgroup's shared budget — attribution finer than the hook
// carries is honestly absent, never a silent unlimited pass.

use aya_ebpf::{macros::map, maps::LruHashMap};

// The enforcement arithmetic (the same file the userspace test tree
// compiles — reused from the root's own inclusion, ONE copy per
// crate, the math.rs duplicate-mod discipline).
use super::ammsp_resolve::current_generation;
use super::math::{
    Bucket, LimiterStats, Policy, book, book_rescue, refill_window, tokens_cas, try_consume,
};

// The ECN-first arithmetic (schema v19's pure core, the same #[path]
// file the cgroup lanes' wiring and the rootless test tree build):
// the debt word the mark-before-drop verdict charges and pays.
use super::ecn::{debt_charge, debt_pay};

/// One per-socket bucket: the standard token bucket plus the
/// generation stamp the stale-token belt reads plus the ECN debt
/// word the mark-before-drop verdict arbitrates (schema v21). A NEW
/// map value (schema v15) — not the pinned 24-byte Bucket layout —
/// so the stamp and the debt get their own fields instead of
/// squatting on frac_rem.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketBucket {
    pub core: Bucket,
    pub gen_stamp: u64,
    /// The lane's own ECN debt word (schema v21): outstanding
    /// marked-but-unbought bytes for THIS connection, charged by the
    /// rescue, paid from the socket's own token stream on the allow
    /// path (the ecn.rs call-site law). Belt-zeroed with the tokens
    /// on a generation bump, aged out with the bucket by the LRU.
    pub ecn_debt: u64,
}

const _: () = assert!(core::mem::size_of::<SocketBucket>() == 40);

/// The download per-socket bucket: socket cookie -> tokens the
/// socket may spend. LRU + pinned (the leaf_bucket posture — dead
/// sockets age out, live ones always find room). The static name
/// stays lowercase like every map symbol in the limiter object (the
/// userspace pin contract, one family with the leaf buckets).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static socket_bucket_dl: LruHashMap<u64, SocketBucket> = LruHashMap::pinned(4096, 0);

/// The upload per-socket bucket — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static socket_bucket_ul: LruHashMap<u64, SocketBucket> = LruHashMap::pinned(4096, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (the limiter's own BPF_NOEXIST note carries the race
/// contract — the loser re-looks-up and rides the winner's entry).
const BPF_NOEXIST: u64 = 1;

/// Get or create the socket's bucket: zero tokens, zero stamps
/// (ktime is past boot, so the first refill CAS always owns the
/// window; generation 0 mismatches the live generation on any host
/// that has mutated a policy, and the belt re-stamps on the first
/// packet — a fresh bucket simply takes the zero-token start the
/// legacy lane's first packet takes).
#[inline(always)]
fn get_socket_ptr(map: &LruHashMap<u64, SocketBucket>, cookie: &u64) -> Option<*mut SocketBucket> {
    match map.get_ptr_mut(cookie) {
        Some(ptr) => Some(ptr),
        None => {
            let init = SocketBucket {
                core: Bucket {
                    tokens: 0,
                    last_refill_ns: 0,
                    frac_rem: 0,
                },
                gen_stamp: 0,
                ecn_debt: 0,
            };
            if map.insert(cookie, init, BPF_NOEXIST).is_err() {
                // Lost the init race (the v11 discipline) or the LRU
                // is full under 4096+ concurrent sockets: re-look-up
                // and ride the winner; a re-lookup that still misses
                // hands the caller None, and the caller ALLOWS — the
                // C twin's fail-open bookkeeping contract (never drop
                // on a map miss), the same posture get_flow_ptr's own
                // comment carries one lane over. The drop wording
                // this comment carried was the leaf lane's posture
                // pasted one map family over (night-audit-1's catch):
                // the socket lane has no coarser lane to fall through
                // to, so its miss posture is the documented fail-open
                // one, stated where the caller states it too.
            }
            map.get_ptr_mut(cookie)
        }
    }
}

/// The per-socket flow for one packet (called from try_enforce's
/// per-socket lane, POLICY_FLAG_PER_SOCKET set and a nonzero cookie
/// in hand): belt, refill, consume — the legacy lane's exact
/// arithmetic on a socket-keyed bucket, with the drop verdict
/// rescued ECN-first (schema v21, the per-socket convergence
/// closure): the kernel helper runs FIRST (side-effect-free
/// refusal on non-ECT/cloned/not-linear packets — the legacy drop,
/// untouched), a success charges the bucket's own debt word, and
/// the CE-marked packet is DELIVERED — the caller's ring wrap books
/// it as allowed through this lane's return of 1. `stats` stays
/// keyed at the RESOLVED POLICY ROOT (the ledger rolls up to the
/// target the owner limited, the AMMSP contract), and the ring wrap
/// rides the caller's ring_verdict like every other lane.
#[inline(always)]
pub(super) fn socket_flow(
    pol: &Policy,
    cookie: u64,
    map: &LruHashMap<u64, SocketBucket>,
    now: u64,
    pkt_len: u32,
    stats: Option<&mut LimiterStats>,
    skb: *mut core::ffi::c_void,
) -> i32 {
    let ptr = match get_socket_ptr(map, &cookie) {
        Some(ptr) => ptr,
        // Bookkeeping failure, the C twin's fail-open contract
        // (the pool miss and the leaf miss before it): never drop on
        // a map miss. The honest bound is the observer's own cookie
        // map note — under 4096+ CONCURRENT sockets on one policed
        // cgroup the LRU may age a cold bucket out and a resumed
        // socket restarts at zero tokens; the lane degrades
        // best-effort, documented, never silently re-engineered.
        None => return 1,
    };
    let sb = unsafe { &mut *ptr };

    // The stale-token belt (the DRR leaf belt, one lane over): a
    // stamp mismatching the live AMM generation means the tokens
    // were drawn under a budget a policy mutation has since
    // replaced — zero them before this packet may spend. The CAS
    // form keeps a concurrent consumer correct: its consume
    // re-observes the zero and retries against the fresh state. The
    // debt zero rides the same belt: a fresh budget never inherits
    // the predecessor's debt (the repair-6 discipline, structural
    // here — the word lives in the bucket the belt already owns).
    let generation = u64::from(current_generation());
    if unsafe { core::ptr::addr_of!(sb.gen_stamp).read_volatile() } != generation {
        let stale = unsafe { core::ptr::addr_of!(sb.core.tokens).read_volatile() };
        if stale != 0 {
            let _ = tokens_cas(&mut sb.core, stale, 0);
        }
        let stale_debt = unsafe { core::ptr::addr_of!(sb.ecn_debt).read_volatile() };
        if stale_debt != 0 {
            // Plain volatile write, the gen_stamp's own form: the
            // word has no CAS sequence of its own here, and the
            // write is idempotent under the belt race (two CPUs on
            // one socket both zeroing converge to the same word). A
            // raced stale charge from the dead generation lands at
            // most one cap and pays down through the fresh stream —
            // the budget bound never depends on the belt's timing.
            unsafe { core::ptr::addr_of_mut!(sb.ecn_debt).write_volatile(0) };
        }
        unsafe { core::ptr::addr_of_mut!(sb.gen_stamp).write_volatile(generation) };
    }

    // The legacy lane's exact spend — THROUGH a reference into the
    // map value, never a copy: refill_window and try_consume do
    // their SMP-safe atomic field ops through the reference, and a
    // copy-out/spend/write-back pair would hand two CPUs on one
    // socket the pre-v7 lost-update shape (one CPU's deduction
    // wholesale clobbered by the other's write-back). The addr_of
    // borrow keeps the gen_stamp field above and the core below
    // from aliasing as simultaneous &mut borrows.
    let bkt = unsafe { &mut *core::ptr::addr_of_mut!(sb.core) };
    refill_window(pol, bkt, now);
    let allowed = try_consume(bkt, pkt_len);
    if allowed {
        // The ECN debt pay (the ecn.rs call-site law, the group and
        // DRR lanes' own): on the ALLOW path only, from the stream's
        // leftover AFTER the lane delivered — a pay that ran on every
        // packet would drain the token stock toward the debt and
        // starve the lane below the policy. The calls are safe-code
        // here (addr_of_mut! on reference places, the core's own
        // functions) — no unsafe wrapper, the container lane's
        // -D warnings pins it.
        debt_pay(
            core::ptr::addr_of_mut!(sb.core.tokens),
            core::ptr::addr_of_mut!(sb.ecn_debt),
        );
        return match stats {
            Some(s) => {
                book(s, true, pkt_len);
                1
            }
            None => 1,
        };
    }
    // The drop verdict's rescue, mark before drop: the kernel helper
    // first (its refusal IS the legacy drop — non-ECT traffic never
    // changes behavior), then the debt charge against this
    // connection's own word (a refusal at the cap or a word already
    // at the cap leaves the drop standing — the safe verdict, never
    // an unlimited pass). A rescued packet is DELIVERED: book the
    // drop first, then the rescue's correction pair moves it to the
    // allowed column exactly (the math.rs book_rescue contract).
    if unsafe { super::bpf_skb_ecn_set_ce(skb) } == 0 {
        return match stats {
            Some(s) => {
                book(s, false, pkt_len);
                0
            }
            None => 0,
        };
    }
    let debt_ptr = core::ptr::addr_of_mut!(sb.ecn_debt);
    if !debt_charge(debt_ptr, pkt_len) {
        // The CE codepoint is set but the debt is at its cap: the
        // packet drops anyway — a dropped mark signals nothing the
        // receiver will read, and the cap is the budget law's bite.
        return match stats {
            Some(s) => {
                book(s, false, pkt_len);
                0
            }
            None => 0,
        };
    }
    match stats {
        Some(s) => {
            book(s, false, pkt_len);
            book_rescue(s, pkt_len);
            1
        }
        None => 1,
    }
}
