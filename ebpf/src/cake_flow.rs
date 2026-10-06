// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The per-flow datapath wiring (schema v20, CAKE-shaped isolation):
// the aya-touching half of the lane that stops the leaf's sockets
// from sharing one bucket — the maps and the flow draw the pure
// core (ebpf/src/drr.rs's v20 section) and the rootless battery
// (test/ebpf/limiter/cake_isolation_tests.rs) agreed on before any
// kernel saw this file. Everything here follows the drr_flow.rs
// precedent one level down:
//
//   * the per-flow bucket maps (socket cookie u64 -> Bucket), one
//     per direction, LRU 4096 so dead sockets age out instead of
//     filling the lane — the leaf-bucket posture, the socket-bucket
//     lane's own posture one family over. The value is the pinned
//     24-byte Bucket itself: leaf buckets never run refill math, and
//     the flow bucket rides the same trick — last_refill_ns is the
//     DRAW OWNERSHIP stamp, frac_rem is the generation belt's stamp;
//   * the per-leaf flow-share words ((generation << 32) | leaf ->
//     u64, drr.rs's pool-share packing): the learned distinct-flow
//     count, the drawee PEAK, the epoch — the repair-6 discipline
//     full-strength (a mutated budget's successor learns a fresh
//     flow count, never the predecessor's peak throttling it);
//   * the per-flow ledger words (RAW cookie -> u64, drr.rs's ledger
//     packing: carry | epoch): the flow's banked allowance. The raw
//     cookie is a u64 the generation prefix cannot carry without
//     collisions, so a mutated budget's successor inherits at most
//     one quantum of carry, availability-capped by the fresh leaf's
//     own tokens — the bounded residue the repair-6 re-key exists to
//     avoid at the DIVISOR scale, where the damage compounds across
//     epochs (the flow SHARE word carries the generation instead,
//     and the flow BUCKET wears the generation belt on frac_rem).
//
// The draw path mirrors try_draw's, with the four design lessons
// this lane paid for (two filed by the rootless battery BEFORE the
// file existed, two by the live CI battery the day it shipped —
// the source buffer law and the packet floor, both in drr.rs's
// flow_take), all load-bearing:
//
//   * the SPARSE evidence is the flow bucket's own draw stamp (the
//     pre-CAS stamp's epoch), never the ledger word's anchor — a
//     ledger-anchored test leaves a lone ledger-off flow reading
//     sparse forever, and a bulk flow of small packets would draw
//     per packet (a share-word CAS per packet); the stamp
//     self-corrects on every shape (the file's own frequency
//     classifies it);
//   * the OFF lane's take is the learned-share FRACTION of the leaf
//     (leaf/(learned+2)), never the whole leaf: the share word's
//     PEAK decays a step every eight quiet epochs, and for the
//     epochs between a decay and its re-ratchet the allowance reads
//     MAX — a lane-law-only take there drains the leaf whole, once
//     per transient epoch, and the isolation leaks its own
//     divisor's decay (the battery's measured catch: the bulk rode
//     the transient to half again its allowance before the fraction
//     closed it).
//
// The kernel requirement is nothing new — bpf_get_socket_cookie the
// observer's own join already runs in this object (the per-socket
// lane's own attribution), and the CAS sequences lower to the same
// BPF_ATOMIC ISA the 5.13 verified floor already carries.

use aya_ebpf::{macros::map, maps::LruHashMap};

// The pure quantum core and the enforcement arithmetic (reused from
// the root's own inclusion, ONE copy per crate — the math.rs
// duplicate-mod discipline), the generation the repair-6 keys ride,
// and the leaf lane's own note/room/spend helpers (pub(super), the
// same CAS discipline one level down — this file never duplicates
// what a sibling already owns).
use super::ammsp_resolve::current_generation;
use super::drr;
use super::drr_flow::{ledger_room, ledger_spend, note_share};
use super::math::{
    Bucket, Policy, draw_stamp_take, gen_stamp_read, gen_stamp_write, tokens_cas, tokens_fetch_add,
    tokens_read,
};

/// The per-flow download bucket: socket cookie -> the tokens the
/// flow may spend. LRU + pinned (the leaf-bucket posture — dead
/// sockets age out, live ones always find room). The static name
/// stays lowercase like every map symbol in the limiter object (the
/// userspace pin contract, one family with the leaf buckets).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_bucket_dl: LruHashMap<u64, Bucket> = LruHashMap::pinned(4096, 0);

/// The per-flow upload bucket — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_bucket_ul: LruHashMap<u64, Bucket> = LruHashMap::pinned(4096, 0);

/// The flow-share state, download leaves (v20): (generation << 32) |
/// LEAF cgroup id -> the packed pool-share word (drr.rs's packing —
/// `last:u16 | running:u16 | peak:u16 | epoch`), counting the leaf's
/// distinct FLOW askers per 100ms epoch. LRU + pinned like the leaf
/// buckets; datapath-internal (userspace never opens it — the
/// leaf_bucket family's contract), fail-open on a miss (the draw
/// keeps the availability-capped take, never drops).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_share_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The flow-share state, upload leaves — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_share_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The flow-ledger state (v20): RAW socket cookie -> the packed
/// ledger word (drr.rs's packing — `carry:u32 | epoch:u32`), the
/// flow's banked allowance from the leaf's epoch budget split across
/// the flow drawee peak. LRU + pinned like the leaf buckets;
/// datapath-internal (the leaf_bucket family's contract). A cold
/// word reads one quantum of banked room at its first touch (the
/// epoch-0 anchor against a long-lived clock, capped at the
/// stockpile bound — the same documented slack the leaf ledger's
/// cold words carry).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_ledger_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The flow-ledger state, upload — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static flow_ledger_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi; the limiter's own BPF_NOEXIST note carries
/// the race contract — the loser re-looks-up and rides the winner's
/// entry, never clobbers it).
const BPF_NOEXIST: u64 = 1;

/// READ_ONCE for one packed state word (the math.rs access
/// discipline, the ecn.rs precedent for a file that owns its own
/// word views).
#[inline(always)]
fn word_read(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // map value (the same contract math.rs's field views carry).
    unsafe { p.read_volatile() }
}

/// Get or create the flow's bucket: zero tokens, zero draw stamp
/// (ktime is past boot, so the first draw's stamp CAS against 0
/// always wins), zero generation stamp (the belt re-stamps at the
/// first draw under the live generation) — the get_leaf_ptr
/// discipline one level down.
#[inline(always)]
pub(super) fn get_flow_ptr(
    flow_map: &LruHashMap<u64, Bucket>,
    cookie: &u64,
) -> Option<*mut Bucket> {
    match flow_map.get_ptr_mut(cookie) {
        Some(ptr) => Some(ptr),
        None => {
            let init = Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            };
            if flow_map.insert(cookie, init, BPF_NOEXIST).is_err() {
                // Lost the init race (the v11 discipline) or the LRU
                // is full under 4096+ concurrent sockets in one leaf:
                // re-look-up and ride the winner; a genuinely full
                // LRU is the honest miss the caller treats the
                // socket-lane way — the packet allows (a bookkeeping
                // failure never drops), coarser attribution, never a
                // silent unlimited pass.
            }
            flow_map.get_ptr_mut(cookie)
        }
    }
}

/// The flow draw for one empty flow bucket (called from drr_flow's
/// v20 lane, after the leaf-draw cascade): move leaf -> flow under
/// the v20 laws. `pool_share_map` is the direction's POOL share map
/// (read-only here — the leaf's own draws note it; the flow draw
/// reads the leaf's drawee PEAK for the budget cascade);
/// `flow_share_map` / `flow_ledger_map` are the direction's flow
/// state maps. The order is try_draw's, mirrored:
///
///   1. the draw admission + ownership (the flow bucket's stamp CAS
///      — one drawer per flow per timestamp), with the SPARSE test
///      on the PRE-CAS stamp (the design's own catch: the stamp
///      classifies by frequency, the ledger anchor would not);
///   2. the note (the leaf's flow-share word, once per flow per
///      epoch — the evidence is the same pre-CAS stamp);
///   3. the allowance cascade: the leaf's own budget (the pool's
///      refill split across the LEAF drawee peak, read from the pool
///      word) split across the FLOW drawee peak — the flow lane
///      never invents a budget either level did not earn;
///   4. the room (the flow's banked carry, the MAX lane
///      short-circuited — the pure core's precondition);
///   5. the take under flow_take's two-lane law, moved through a
///      sufficiency-verified CAS pair whose lost races DROP (the
///      safe verdict), the credit riding the atomic add that can
///      only under-deliver;
///   6. the failed draw's rollback to the CURRENT EPOCH's start —
///      the retry-every-packet admission for the rest of the epoch
///      (the leaf lane's own discipline).
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub(super) fn try_flow_draw(
    pol: &Policy,
    leaf: &mut Bucket,
    flow: &mut Bucket,
    pool_share_map: &LruHashMap<u64, u64>,
    flow_share_map: &LruHashMap<u64, u64>,
    flow_ledger_map: &LruHashMap<u64, u64>,
    root: &u32,
    leaf_id: &u32,
    cookie: &u64,
    pkt_len: u32,
    now: u64,
) -> bool {
    // 1. The admission + the sparse evidence (the PRE-CAS stamp).
    let stamp = unsafe { core::ptr::addr_of!(flow.last_refill_ns).read_volatile() };
    if !drr::draw_admitted(now, stamp) {
        return false;
    }
    let sparse = drr::flow_is_sparse(stamp, now);
    if !draw_stamp_take(flow, stamp, now) {
        return false;
    }

    // 2. The note: this flow's ask, once per epoch, in the leaf's
    //    flow-share word (the generation-prefixed leaf key).
    let now_epoch = (now / drr::share_epoch_ns()) as u32;
    let generation = u64::from(current_generation());
    let flow_share_key = (generation << 32) | u64::from(*leaf_id);
    let (learned, flow_peak) = note_share(flow_share_map, &flow_share_key, now_epoch, !sparse);

    // 3. The allowance cascade: the leaf's drawee peak from the
    //    pool's own word (read-only — the leaf's draws note it), the
    //    leaf's budget, the flow allowance.
    let pool_share_key = (generation << 32) | u64::from(*root);
    let leaf_peak = pool_share_map
        .get_ptr(&pool_share_key)
        .map(|p| drr::pool_share_peak(word_read(p)))
        .unwrap_or(0);
    let leaf_budget = drr::flow_leaf_budget(pol.rate_bps, leaf_peak);
    // improve-40 (schema v24), the stated residue: the leaf-budget
    // ESTIMATE rides the row's rate, not the guarantee bracket — the
    // leaf's own tokens bound what the flows can ever draw (they
    // spend only what the bracket-bounded draws put in), so the
    // bracket reaches the flows through the leaf bucket's CONTENTS,
    // never through this divisor; an over-estimate here is a looser
    // flow split competing for the same real tokens, the estimate
    // slack the flow laws already absorb (the learned-count class).
    let allowance = drr::flow_allowance(leaf_budget, flow_peak);

    // 4. The room: the flow's banked carry, the MAX lane
    //    short-circuited (the leaf ledger's own wrapper posture).
    let room = ledger_room(
        flow_ledger_map,
        cookie,
        now_epoch,
        allowance,
        drr::quantum(pol.rate_bps),
    );

    // 5. The take, moved leaf -> flow through the sufficiency-
    //    verified CAS pair (two attempts, the draw path's written-
    //    out posture — no loops for the verifier).
    let quantum = drr::quantum(pol.rate_bps);
    macro_rules! draw_attempt {
        () => {{
            let observed = tokens_read(leaf);
            let d = drr::flow_take(sparse, pkt_len, quantum, learned, allowance, room, observed);
            if d > 0 && tokens_cas(leaf, observed, observed - d) {
                // The leaf paid; the credit rides the atomic add —
                // the pair can only under-deliver, never over-deliver.
                let _ = tokens_fetch_add(flow, d);
                if allowance != u64::MAX {
                    ledger_spend(flow_ledger_map, cookie, now_epoch, allowance, quantum, d);
                }
                true
            } else {
                false
            }
        }};
    }
    if draw_attempt!() || draw_attempt!() {
        return true;
    }
    // 6. The failed draw: the stamp rolls to the CURRENT EPOCH's
    //    start (the retry-every-packet admission stays for the rest
    //    of the epoch, the epoch evidence the note consumed
    //    survives for the next packet's check — the leaf lane's own
    //    rollback, safe because the stamp was locked at `now`).
    let epoch_start = now_epoch as u64 * drr::share_epoch_ns();
    let _ = draw_stamp_take(flow, now, epoch_start);
    false
}

/// The stale-quantum belt for one flow bucket (the leaf belt, one
/// level down — the generation stamp's mismatch zeroes tokens drawn
/// under a dead budget before this packet may spend). Split out so
/// drr_flow's lane stays a readable sequence and the belt reads as
/// the law it is; the CAS form keeps a concurrent consumer correct
/// (its consume re-observes the zero and retries against the fresh
/// state).
#[inline(always)]
pub(super) fn flow_belt(flow: &mut Bucket, generation: u64) {
    if gen_stamp_read(flow) != generation {
        let stale = tokens_read(flow);
        if stale != 0 {
            let _ = tokens_cas(flow, stale, 0);
        }
        gen_stamp_write(flow, generation);
    }
}
