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
use core::sync::atomic::{AtomicU64, Ordering};

// The pure quantum core (core-only, the same file the userspace test
// tree compiles) and the enforcement arithmetic it draws from.
// Reused from the root's own inclusion — ONE copy per crate, the
// math.rs duplicate-mod discipline (clippy rightly rejects two).
use super::ammsp_resolve::current_generation;
use super::cake_flow;
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
pub(super) static drr_pool_state_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The learned-share state, upload pool — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static drr_pool_state_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The epoch-ledger state, download leaves (repair-3, v17): LEAF
/// cgroup id -> the packed ledger word (drr.rs's packing —
/// `drawn:u32 | epoch:u32`). A leaf's TOTAL drawn bytes per 100ms
/// epoch are bounded by the pool's per-epoch refill split across
/// the learned drawee count — the per-take learned cap could not
/// bound a per-epoch share (a fast drawer drained the pool through
/// (K+2)-sized bites on every packet; the battery's worst leaf read
/// 4.7x fair while the quietest measured one admit), so the bound
/// moved to the epoch scale: a blocked leaf stops touching the pool,
/// the refills accumulate, and a starved leaf's rare draws find a
/// rich pool instead of an empty one. LRU + pinned like the leaf
/// buckets; datapath-internal (userspace never opens it — the
/// leaf_bucket family's contract), absent-or-cold fails open onto
/// the v16 law (learned < 2 keeps the ledger off — the lone leaf's
/// whole-budget row depends on it).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static drr_leaf_state_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The epoch-ledger state, upload leaves — the download twin's lane.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static drr_leaf_state_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi; the limiter's own BPF_NOEXIST note carries
/// the race contract — the loser re-looks-up and rides the winner's
/// entry, never clobbers it).
const BPF_NOEXIST: u64 = 1;

// The bare-u64 access primitives (the math.rs discipline, applied to
// the packed state words this lane owns): BPF has RMW atomics but no
// atomic load/store, so reads ride volatile and only genuine RMW
// (compare_exchange) rides core's AtomicU64 — see math.rs's access-
// primitive block for the ISA reasoning. Ordering is Relaxed on both
// sides: these words are fairness SHAPING (an estimate whose slack
// the bounds absorb), never the token-conservation bound — that stays
// the pool CAS in try_draw, exactly as v13/v16 left it.

/// READ_ONCE for one packed state word.
#[inline(always)]
fn word_read(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // map value (the same contract math.rs's field views carry).
    unsafe { p.read_volatile() }
}

/// cmpxchg for one packed state word, true when it landed.
#[inline(always)]
fn word_cas(p: *mut u64, from: u64, to: u64) -> bool {
    // SAFETY: same 8-aligned contract; AtomicU64::from_ptr lowers to
    // the BPF_ATOMIC ISA the 5.13 floor carries (math.rs's note).
    unsafe { AtomicU64::from_ptr(p) }
        .compare_exchange(from, to, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

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
/// map (dinner-28 — the fair-split cap on the draw);
/// `ledger_map` is the direction's epoch-ledger map (repair-3 — the
/// per-epoch cap the per-take cap needed underneath it).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn drr_flow(
    pol: &Policy,
    pool: &mut Bucket,
    leaf_map: &LruHashMap<u32, Bucket>,
    share_map: &LruHashMap<u64, u64>,
    ledger_map: &LruHashMap<u64, u64>,
    flow_map: &LruHashMap<u64, Bucket>,
    flow_share_map: &LruHashMap<u64, u64>,
    flow_ledger_map: &LruHashMap<u64, u64>,
    cookie: u64,
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

    // 3. THE FLOW LANE (schema v20, CAKE-shaped isolation): an
    //    attributed packet spends from its OWN flow bucket inside
    //    the leaf — the leaf becomes a small pool for its sockets
    //    and the monopoly the leaf-level laws closed at the leaf
    //    stays closed one level deeper (the rootless battery's
    //    measured close: 2.9:1 under the shared leaf, 1.1:1 under
    //    the lane). A packet with no attribution (cookie == 0 — the
    //    hook's honest limit, early ingress before demux) falls
    //    through to the leaf lane below: coarser, still policed,
    //    never a silent unlimited pass. A flow-map miss (the full
    //    LRU under 4096+ concurrent sockets in one leaf) allows —
    //    the socket lane's own bookkeeping posture.
    if cookie != 0 {
        if let Some(fp) = cake_flow::get_flow_ptr(flow_map, &cookie) {
            let fbkt = unsafe { &mut *fp };
            // The stale-quantum belt, one level deeper (the leaf
            // bucket's own trick on frac_rem): tokens drawn under a
            // dead budget zero before this packet may spend them.
            cake_flow::flow_belt(fbkt, generation);
            if try_consume(fbkt, pkt_len) {
                if let Some(s) = stats {
                    book(s, true, pkt_len);
                }
                return 1;
            }
            // The cascade: when the leaf cannot cover the packet,
            // the leaf's own draw from the pool runs FIRST (the
            // unchanged v17 machinery — the flow draw rides whatever
            // the leaf then holds).
            if tokens_read(bkt) < u64::from(pkt_len) {
                let leaf_stamp = unsafe { core::ptr::addr_of!(bkt.last_refill_ns).read_volatile() };
                let leaf_share_key = (generation << 32) | u64::from(*root);
                let leaf_ledger_key = (generation << 32) | u64::from(*leaf);
                let _ = try_draw(
                    pol,
                    pool,
                    bkt,
                    share_map,
                    ledger_map,
                    &leaf_share_key,
                    &leaf_ledger_key,
                    leaf_stamp,
                    now,
                );
            }
            if cake_flow::try_flow_draw(
                pol,
                bkt,
                fbkt,
                share_map,
                flow_share_map,
                flow_ledger_map,
                root,
                leaf,
                &cookie,
                pkt_len,
                now,
            ) && try_consume(fbkt, pkt_len)
            {
                if let Some(s) = stats {
                    book(s, true, pkt_len);
                }
                return 1;
            }
            // Nothing drawable: the drop, booked exactly like every
            // lane's (the safe verdict under every race this file
            // carries) — and the caller's ECN rescue still sees it.
            if let Some(s) = stats {
                book(s, false, pkt_len);
            }
            return 0;
        }
        return 1;
    }

    // The unattributed lane (cookie == 0): the leaf spend, verbatim.
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
    // The generation-prefixed state keys (repair-6): every policy
    // mutation bumps the AMMSP generation the belt above already
    // read, and the pool-share and leaf-ledger words ride the bump —
    // a fresh budget starts with a fresh divisor, a fresh carry, a
    // fresh asker count, never the previous budget's peak throttling
    // the successor (the cross-round find: a 24-leaf policy handed
    // its lone successor an allowance of refill/19 for the ~15
    // seconds the decay needed). The old generation's entries age
    // out through the LRU the leaf buckets already trust; the key is
    // (generation << 32) | id, the memo map's own packing shape.
    let share_key = (generation << 32) | *root as u64;
    let ledger_key = (generation << 32) | *leaf as u64;
    if try_draw(
        pol,
        pool,
        bkt,
        share_map,
        ledger_map,
        &share_key,
        &ledger_key,
        stamp,
        now,
    ) && try_consume(bkt, pkt_len)
    {
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
///
/// repair-3, the note's ATOMICITY: the v16 note was a plain read
/// plus a BPF_ANY insert — under the multi-CPU draw storm the
/// concurrent notes clobbered each other's increments (every writer
/// replaced the word from its own stale read), the learned count
/// converged to 1-3, and the cap weakened back to the v13 residue
/// shape. The note now rides a written-out two-attempt CAS on the
/// map value (the draw_attempt! posture — no loops for the
/// verifier); a lost second attempt reads the survivor's word for
/// the divisor (the estimate's documented slack, one increment).
///
/// repair-3, the EPOCH LEDGER: the take is further capped by the
/// leaf's remaining per-epoch allowance (drr::epoch_allowance —
/// the pool's 100ms refill split across the learned count), kept
/// in `ledger_map` keyed by the LEAF. The per-take cap could not
/// bound a per-epoch share: a leaf drawing on every packet drained
/// the pool through (K+2)-sized bites while its starved siblings
/// backed off to retransmit timers (the battery's find — worst
/// 4.7x fair, quietest one admit). The ledger blocks the fast
/// drawer at its fair share, the pool's refills accumulate behind
/// it, and the starved leaf's rare draws find a rich pool. learned
/// < 2 skips the ledger entirely (the lone leaf's whole-budget
/// row); the drawn counter's CAS slack is one take, never a token
/// the pool did not hold.
#[inline(always)]
fn try_draw(
    pol: &Policy,
    pool: &mut Bucket,
    leaf: &mut Bucket,
    share_map: &LruHashMap<u64, u64>,
    ledger_map: &LruHashMap<u64, u64>,
    share_key: &u64,
    ledger_key: &u64,
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
    // once per epoch. The note is a two-attempt CAS (repair-3): the
    // v16 plain-read-plus-BPF_ANY insert lost increments to racing
    // writers until the divisor itself lied.
    let now_epoch = (now / drr::share_epoch_ns()) as u32;
    let leaf_prev_epoch = (last_draw / drr::share_epoch_ns()) as u32;
    let (learned, drawees) = note_share(
        share_map,
        share_key,
        now_epoch,
        leaf_prev_epoch == now_epoch,
    );

    // The epoch ledger's room (repair-4, the carry form): the leaf's
    // banked allowance — earned at the refill split across the drawee
    // PEAK (not the momentary asker count, which IS the silence: the
    // starved stop asking and the survivors' share would inflate),
    // held as a carry capped at one quantum (the stockpile bound: a
    // starved leaf banks several epochs for one fat GRO admit, its
    // TCP heals on the admit, the aggregate floor comes back). The
    // allowance is u64::MAX (a cold pool, a missed lookup, a lone
    // drawer) exactly when the ledger is off — the map is not
    // touched on that path.
    let allowance = drr::epoch_allowance(pol.rate_bps, drawees);
    let cap = drr::quantum(pol.rate_bps);
    let room = ledger_room(ledger_map, ledger_key, now_epoch, allowance, cap);

    // Owned the draw: move the take pool -> leaf through the
    // sufficiency-verified CAS, written out (not looped) for the
    // same verifier posture try_consume carries — two attempts,
    // each against its own fresh read. The take is the two-lane law
    // (repair-7): the ENGAGED lane (drawees >= 2) draws the residue
    // law bounded by the epoch room — the room owns the epoch
    // split, the fraction's old job, and a catch-up drawer banks
    // its GSO admit floor off the unclaimed residue instead of a
    // fraction that never reaches it; the OFF lane (a lone drawer,
    // a cold pool, a miss) keeps the v16 learned-share law verbatim
    // — the fail-open posture, and the lone leaf's whole-budget
    // row rides it.
    let quantum = drr::quantum(pol.rate_bps);
    macro_rules! draw_attempt {
        () => {{
            let observed = tokens_read(pool);
            let d = drr::take_size(quantum, observed, learned, allowance, room);
            if d > 0 && tokens_cas(pool, observed, observed - d) {
                // The pool paid; the credit rides the atomic add —
                // the pair can only under-deliver, never over-deliver.
                let _ = tokens_fetch_add(leaf, d);
                if allowance != u64::MAX {
                    ledger_spend(ledger_map, ledger_key, now_epoch, allowance, cap, d);
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

/// The learned-share note (repair-3's atomic form): get-or-create the
/// pool's state word, then roll it over and count this asker through
/// a written-out two-attempt CAS. Returns the pair the draw reads —
/// (the take law's divisor: the last completed epoch's distinct-asker
/// count; the allowance law's divisor: the decaying drawee PEAK,
/// repair-4). A missing entry starts at 0 (a cold pool keeps the v13
/// law by construction); a full LRU is the same honest miss
/// (fail-open, the leaf-bucket posture); two lost CAS attempts read
/// the survivor's word — the estimate's documented slack.
#[inline(always)]
pub(super) fn note_share(
    share_map: &LruHashMap<u64, u64>,
    share_key: &u64,
    now_epoch: u32,
    drew_this_epoch: bool,
) -> (u16, u16) {
    if share_map.get_ptr(share_key).is_none() {
        let zero = 0u64;
        let _ = share_map.insert(share_key, &zero, BPF_NOEXIST);
        // Lost the init race: the winner's word serves this note too.
    }
    let ptr = match share_map.get_ptr_mut(share_key) {
        Some(ptr) => ptr,
        None => return (0, 0),
    };
    let word = word_read(ptr);
    let noted = drr::pool_share_note(word, now_epoch, drew_this_epoch);
    if word_cas(ptr, word, noted) {
        return (drr::pool_share_last(noted), drr::pool_share_peak(noted));
    }
    // The second attempt against the fresh word (a racing note
    // advanced it — recompute, retry once, the v8 posture).
    let word = word_read(ptr);
    let noted = drr::pool_share_note(word, now_epoch, drew_this_epoch);
    if word_cas(ptr, word, noted) {
        return (drr::pool_share_last(noted), drr::pool_share_peak(noted));
    }
    (drr::pool_share_last(word), drr::pool_share_peak(word))
}

/// The epoch ledger's room (the carry form, repair-4): the leaf's
/// banked allowance — the word's carry plus the epochs elapsed since
/// its anchor, earned at the allowance, capped at the quantum. The
/// ledger-off path (allowance == u64::MAX) never touches the map —
/// the lone-drawer hot lane pays nothing for a bound it does not
/// carry. A missing entry is a fresh leaf's zero carry (nothing
/// banked yet); the get-or-create rides the BPF_NOEXIST contract.
#[inline(always)]
pub(super) fn ledger_room(
    ledger_map: &LruHashMap<u64, u64>,
    ledger_key: &u64,
    now_epoch: u32,
    allowance: u64,
    cap: u64,
) -> u64 {
    if allowance == u64::MAX {
        return u64::MAX;
    }
    if ledger_map.get_ptr(ledger_key).is_none() {
        let zero = 0u64;
        let _ = ledger_map.insert(ledger_key, &zero, BPF_NOEXIST);
        // Lost the init race: the winner's word serves this read too.
    }
    match ledger_map.get_ptr(ledger_key) {
        Some(ptr) => drr::ledger_room(word_read(ptr), now_epoch, allowance, cap),
        None => cap,
    }
}

/// The ledger spend (the carry form): the credit and the spend land
/// together through one CAS — the take re-anchors the word at the
/// now-epoch with the carry reduced. A lost CAS leaves the spend
/// unrecorded (the leaf may re-draw the same bytes once); bounded by
/// the take size, leaf-local, in the safe direction for a bound whose
/// hard edge is the pool's own conservation CAS. Two attempts, the
/// draw path's written-out posture.
#[inline(always)]
pub(super) fn ledger_spend(
    ledger_map: &LruHashMap<u64, u64>,
    ledger_key: &u64,
    now_epoch: u32,
    allowance: u64,
    cap: u64,
    take: u64,
) {
    let ptr = match ledger_map.get_ptr_mut(ledger_key) {
        Some(ptr) => ptr,
        None => return,
    };
    let word = word_read(ptr);
    let noted = drr::ledger_note(word, now_epoch, allowance, cap, take);
    if word_cas(ptr, word, noted) {
        return;
    }
    let word = word_read(ptr);
    let noted = drr::ledger_note(word, now_epoch, allowance, cap, take);
    let _ = word_cas(ptr, word, noted);
}
