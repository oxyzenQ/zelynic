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
//     field (SocketBucket is 32 bytes, a NEW map with no pinned
//     layout to preserve) instead of the DRR trick of reusing
//     frac_rem, because this lane RUNS the refill math and frac_rem
//     is load-bearing here.
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
use super::math::{Bucket, LimiterStats, Policy, book, refill_window, tokens_cas, try_consume};

/// One per-socket bucket: the standard token bucket plus the
/// generation stamp the stale-token belt reads. A NEW map value
/// (schema v15) — not the pinned 24-byte Bucket layout — so the
/// stamp gets its own field instead of squatting on frac_rem.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketBucket {
    pub core: Bucket,
    pub gen_stamp: u64,
}

const _: () = assert!(core::mem::size_of::<SocketBucket>() == 32);

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
            };
            if map.insert(cookie, init, BPF_NOEXIST).is_err() {
                // Lost the init race (the v11 discipline) or the LRU
                // is full under 4096+ concurrent sockets: re-look-up
                // and ride the winner; a genuinely full LRU is the
                // honest miss the leaf lane takes — the packet drops
                // (the safe verdict, never an unlimited pass).
            }
            map.get_ptr_mut(cookie)
        }
    }
}

/// The per-socket flow for one packet (called from try_enforce's
/// per-socket lane, POLICY_FLAG_PER_SOCKET set and a nonzero cookie
/// in hand): belt, refill, consume — the legacy lane's exact
/// arithmetic on a socket-keyed bucket. `stats` stays keyed at the
/// RESOLVED POLICY ROOT (the ledger rolls up to the target the
/// owner limited, the AMMSP contract), and the ring wrap rides the
/// caller's ring_verdict like every other lane.
#[inline(always)]
pub(super) fn socket_flow(
    pol: &Policy,
    cookie: u64,
    map: &LruHashMap<u64, SocketBucket>,
    now: u64,
    pkt_len: u32,
    stats: Option<&mut LimiterStats>,
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
    // re-observes the zero and retries against the fresh state.
    let generation = u64::from(current_generation());
    if unsafe { core::ptr::addr_of!(sb.gen_stamp).read_volatile() } != generation {
        let stale = unsafe { core::ptr::addr_of!(sb.core.tokens).read_volatile() };
        if stale != 0 {
            let _ = tokens_cas(&mut sb.core, stale, 0);
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
    match stats {
        Some(s) if allowed => {
            book(s, true, pkt_len);
            1
        }
        Some(s) => {
            book(s, false, pkt_len);
            0
        }
        None if allowed => 1,
        None => 0,
    }
}
