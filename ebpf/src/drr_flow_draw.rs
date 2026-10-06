// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: try_draw — the leaf's draw orchestration —
// moved out of drr_flow.rs at the 600-line cap, #[path]-wired as
// a nested module (the parent keeps the maps and the entry).
//
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
use aya_ebpf::maps::LruHashMap;

use super::get_leaf_ptr;
use super::ledger_room;
use super::ledger_spend;
use super::note_share;
use crate::drr;
use crate::drr::epoch_allowance;
use crate::math::Bucket;
use crate::math::Policy;
use crate::math::draw_stamp_take;
use crate::math::tokens_cas;
use crate::math::tokens_fetch_add;
use crate::math::tokens_read;
#[inline(always)]
pub(crate) fn try_draw(
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
    // drawer on a floor-only row) exactly when the ledger is off —
    // the map is not touched on that path.
    //
    // improve-40 (schema v24): the split is the GUARANTEE LAW's —
    // the fair split clamped between the row's floor and ceiling
    // (drr.rs's v24 section), the stockpile the ceiling's own
    // quantum when a ceiling is set. A 0/0 row is the exact v23
    // arithmetic by construction, and a set ceiling engages the
    // ledger even on the lone-drawer lane (a cap that folds when
    // siblings appear is not a cap).
    let allowance = drr::guaranteed_allowance(pol.rate_bps, pol.floor_bps, pol.ceil_bps, drawees);
    let cap = drr::guaranteed_stockpile(pol.rate_bps, pol.ceil_bps);
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
