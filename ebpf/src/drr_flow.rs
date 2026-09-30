// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The DRR datapath wiring (NIGHT-upgrade-charger-core-1c): the
// aya-touching half of the fair-shared bucket — the two pinned LRU
// leaf-bucket maps and the pool/leaf orchestration
// (ebpf/src/bin/limiter.rs calls into drr_flow from try_enforce's
// individual-bucket lane). Split from the pure core (../drr.rs) at
// the ammsp_resolve precedent: everything decidable about the
// quantum lives there and is pinned rootlessly by
// test/ebpf/limiter/drr_tests.rs; everything here is what only the
// kernel side can touch:
//
//   * the per-leaf bucket maps (leaf cgroup id -> Bucket), one per
//     direction, LRU so dead leaves (transient systemd scopes,
//     churned container cgroups) evict naturally instead of filling
//     the lane — the ammsp_leaf_cache posture, one map family over;
//   * the draw path: refill the POOL through the exact refill_window
//     the legacy lane uses, spend the LEAF through the exact
//     try_consume, and move tokens pool -> leaf only through a
//     sufficiency-verified CAS pair whose lost races DROP (the safe
//     verdict), never over-allow.
//
// The stale-quantum belt (the design's own close): a leaf's quanta
// are stamped with the AMMSP memo generation current at their draw,
// and a mismatching stamp zeroes the leaf's tokens before the
// packet proceeds — the generation-stamp trick (NIGHT-perf-0)
// applied to buckets, so a policy mutation can never leave a leaf
// spending a dead budget's quantum. The bound without the belt would
// be one quantum per live leaf; with it, zero. The stamp lives in
// the Bucket's frac_rem field: leaf buckets never run refill math
// (their tokens come from draws, whole quanta), so the field is free
// — the layout stays the pinned 24-byte v2 shape both trees assert.

use aya_ebpf::{macros::map, maps::LruHashMap};

// The pure quantum core (core-only, the same file the userspace test
// tree compiles) and the enforcement arithmetic it draws from.
// Reused from the root's own inclusion — ONE copy per crate, the
// math.rs duplicate-mod discipline (clippy rightly rejects two).
use super::ammsp_resolve::current_generation;
use super::drr;
use super::math::{
    Bucket, LimiterStats, Policy, book, draw_stamp_take, gen_stamp_read, gen_stamp_write,
    refill_window, tokens_cas, tokens_fetch_add, tokens_read, try_consume,
};

/// The per-leaf download bucket: LEAF cgroup id -> tokens the leaf
/// may spend. LRU + pinned (the ammsp_leaf_cache posture — dead
/// leaves age out, live ones always find room). The static name
/// stays lowercase like every map symbol in the limiter object (the
/// userspace pin contract, one family with the memo map).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static leaf_bucket_dl: LruHashMap<u32, Bucket> = LruHashMap::pinned(4096, 0);

/// The per-leaf upload bucket — the download twin's lane and posture.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static leaf_bucket_ul: LruHashMap<u32, Bucket> = LruHashMap::pinned(4096, 0);

/// The learned-share state, download pool (dinner-28): ROOT cgroup
/// id -> the packed pool-share word (drr.rs's packing —
/// `last:u16 | running:u16 | epoch:u32`). The draw take is the
/// residue law's bound further capped by the quantum's fair split
/// across the learned drawee count — the number of distinct leaves
/// that drew in the last completed 100ms epoch. The CI find this
/// closes: at K > 2 drawers the residue law's takes decay
/// geometrically (50%/25%/12.5%... of the pool per epoch) — the
/// worst leaf measured 3.35x its fair share while the quietest
/// starved below one admit (78 B over 4s); with the learned cap the
/// first-asker position itself stops paying. LRU + pinned like the
/// leaf buckets; datapath-internal (userspace never opens it — the
/// leaf_bucket family's contract), fail-open on a miss (the draw
/// keeps the v13 residue law, never drops).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static drr_pool_state_dl: LruHashMap<u32, u64> = LruHashMap::pinned(4096, 0);

/// The learned-share state, upload pool — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static drr_pool_state_ul: LruHashMap<u32, u64> = LruHashMap::pinned(4096, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi; the limiter's own BPF_NOEXIST note carries
/// the race contract — the loser re-looks-up and rides the winner's
/// entry, never clobbers it).
const BPF_NOEXIST: u64 = 1;

/// Get or create the leaf's bucket: zero tokens, zero draw stamp
/// (ktime is past boot, so the FIRST draw's stamp CAS against 0
/// always wins), zero generation stamp (the belt re-stamps at the
/// first draw under the live generation).
#[inline(always)]
fn get_leaf_ptr(leaf_map: &LruHashMap<u32, Bucket>, leaf: &u32) -> Option<*mut Bucket> {
    match leaf_map.get_ptr_mut(leaf) {
        Some(ptr) => Some(ptr),
        None => {
            let init = Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            };
            if leaf_map.insert(leaf, init, BPF_NOEXIST).is_err() {
                // Lost the init race (the v11 discipline): re-look-up
                // and ride the winner's entry. A full LRU is the same
                // honest miss the memo map takes — the packet drops.
            }
            leaf_map.get_ptr_mut(leaf)
        }
    }
}

/// The DRR flow for one packet (called from try_enforce's
/// individual-bucket lane, group_id == 0): refill the shared pool,
/// spend the leaf, and draw a quantum between them when the leaf
/// runs dry. `pool` is the ROOT-keyed bucket the policy selected
/// (the same map entry the legacy path enforced through); `leaf` is
/// the socket's own cgroup id — the direct-hit path's leaf IS the
/// root, so every packet on this lane takes the same shape, no mixed
/// regime between a target's own sockets and its subtree's.
/// `root` is the policy key (the pool's owner — the learned-share
/// state map is keyed by it); `share_map` is the direction's state
/// map (dinner-28 — the fair-split cap on the draw).
#[inline(always)]
pub(super) fn drr_flow(
    pol: &Policy,
    pool: &mut Bucket,
    leaf_map: &LruHashMap<u32, Bucket>,
    share_map: &LruHashMap<u32, u64>,
    root: &u32,
    leaf: &u32,
    pkt_len: u32,
    now: u64,
    stats: Option<&mut LimiterStats>,
) -> i32 {
    // 1. The POOL: the exact refill the legacy lane runs — the
    // window-ownership credit, the clamp family, the burst cap. The
    // pool never gains tokens except through this credit and never
    // loses them except through the draw below, so the subtree's
    // aggregate stays exactly the policy it had: DRR redistributes
    // the budget, it cannot create one.
    refill_window(pol, pool, now);

    // 2. The LEAF: get-or-create, then the stale-quantum belt.
    let leaf_ptr = match get_leaf_ptr(leaf_map, leaf) {
        Some(ptr) => ptr,
        // Bookkeeping failure, the C twin's fail-open contract:
        // never drop on a map miss.
        None => return 1,
    };
    let bkt = unsafe { &mut *leaf_ptr };

    // The generation stamp: a leaf whose stamp mismatches the live
    // AMMSP generation holds quanta from a dead budget (a policy
    // mutation happened since its draw) — zero them before this
    // packet may spend. The CAS form keeps a concurrent consumer
    // correct: its consume re-observes the zero and retries against
    // the fresh state.
    let generation = current_generation() as u64;
    if gen_stamp_read(bkt) != generation {
        let stale = tokens_read(bkt);
        if stale != 0 {
            let _ = tokens_cas(bkt, stale, 0);
        }
        gen_stamp_write(bkt, generation);
    }

    // 3. Spend what the leaf holds (the legacy consume, verbatim).
    if try_consume(bkt, pkt_len) {
        if let Some(s) = stats {
            book(s, true, pkt_len);
        }
        return 1;
    }

    // 4. The draw: one drawer per leaf per timestamp (the
    // window-ownership trick on the leaf's draw stamp), moving at
    // most one learned-share take from the pool through a
    // sufficiency-verified CAS. The draw stamps the leaf's
    // generation as a side effect — the belt only ever re-fires
    // after a mutation.
    let stamp = unsafe { core::ptr::addr_of!(bkt.last_refill_ns).read_volatile() };
    if try_draw(pol, pool, bkt, share_map, root, stamp, now) && try_consume(bkt, pkt_len) {
        if let Some(s) = stats {
            book(s, true, pkt_len);
        }
        return 1;
    }

    // 5. Nothing drawable: the drop, booked exactly like the legacy
    // lane's (the safe verdict under every race this file carries).
    if let Some(s) = stats {
        book(s, false, pkt_len);
    }
    0
}

/// Draw one quantum from the pool into the leaf, owned by the
/// timestamp CAS on the leaf's draw stamp (the last_refill_ns field
/// — leaf buckets use it only as the draw ownership word, never for
/// refill math). A lost stamp CAS means another CPU's quantum for
/// this leaf is in flight: skip (its credit lands within
/// nanoseconds; a packet dropped in that window is the same bounded
/// contention the try_consume retries absorb).
///
/// dinner-28: the take is the learned-share draw — the residue
/// law's bound further capped by the quantum's fair split across
/// the learned drawee count (the state word in `share_map`, keyed
/// by `root`). The note rides the ATTEMPT, not the success: a
/// starving leaf's draws fail (the pool is empty at its instants),
/// and it is exactly that asker the divisor must learn — the
/// first design counted only succeeders and the learning never
/// bootstrapped (the simulation pin caught it: worst 3.26x fair,
/// barely better than the v13 law). A failed draw rolls the stamp
/// back to the CURRENT EPOCH's start instead of the pre-attempt
/// value: the leaf keeps its retry-every-packet admission for the
/// rest of the epoch (now >= epoch-start always) while its
/// once-per-epoch evidence survives the rollback — a leaf asking
/// on every packet counts once per epoch, never once per packet.
/// A state-map miss fails OPEN onto the v13 residue law — the
/// fairness state never drops a packet.
#[inline(always)]
fn try_draw(
    pol: &Policy,
    pool: &mut Bucket,
    leaf: &mut Bucket,
    share_map: &LruHashMap<u32, u64>,
    root: &u32,
    last_draw: u64,
    now: u64,
) -> bool {
    // The draw admission + lock (the v13 sequence, unchanged).
    if !drr::draw_admitted(now, last_draw) {
        return false;
    }
    if !draw_stamp_take(leaf, last_draw, now) {
        return false;
    }

    // The note rides the attempt: the rollover at epoch boundaries,
    // the distinct-asker count for the running epoch. The leaf's own
    // epoch evidence is `last_draw` (the pre-CAS stamp — the draw
    // that owned this one), so a leaf asking on every packet counts
    // once per epoch. Concurrent notes may lose one increment — the
    // estimate's documented slack.
    let now_epoch = (now / drr::share_epoch_ns()) as u32;
    let leaf_prev_epoch = (last_draw / drr::share_epoch_ns()) as u32;
    let word = share_map.get_ptr(root).map(|p| unsafe { *p }).unwrap_or(0);
    let noted = drr::pool_share_note(word, now_epoch, leaf_prev_epoch == now_epoch);
    let _ = share_map.insert(root, &noted, 0);
    let learned = drr::pool_share_last(noted);

    // Owned the draw: move the take pool -> leaf through the
    // sufficiency-verified CAS, written out (not looped) for the
    // same verifier posture try_consume carries — two attempts,
    // each against its own fresh read. The take is the learned-share
    // cap (dinner-28); the residue law still binds inside it.
    let quantum = drr::quantum(pol.rate_bps);
    macro_rules! draw_attempt {
        () => {{
            let observed = tokens_read(pool);
            let d = drr::fair_draw_size(quantum, observed, learned);
            if d > 0 && tokens_cas(pool, observed, observed - d) {
                // The pool paid; the credit rides the atomic add —
                // the pair can only under-deliver, never over-deliver.
                let _ = tokens_fetch_add(leaf, d);
                true
            } else {
                false
            }
        }};
    }
    if draw_attempt!() || draw_attempt!() {
        return true;
    }
    // The failed draw: the stamp rolls to the CURRENT EPOCH's start
    // (not the pre-attempt value) — the retry-every-packet admission
    // stays for the rest of the epoch, and the epoch evidence the
    // note above consumed survives for the next packet's check. The
    // rollback is safe for the same reason it always was: the stamp
    // was locked at `now`, so the only writer is this one.
    let epoch_start = now_epoch as u64 * drr::share_epoch_ns();
    let _ = draw_stamp_take(leaf, now, epoch_start);
    false
}
