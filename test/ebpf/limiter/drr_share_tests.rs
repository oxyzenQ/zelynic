// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! dinner-28: the learned-share simulation battery — the K-leaf
//! decay class the live fair-share battery caught on every CI leg,
//! reproduced rootlessly, then closed by the new law.
//!
//! THE FIND (the live numbers, all four legs): the residue law
//! (draw = min(quantum, pool/2)) splits a TWO-asker pool evenly —
//! the v13 pin proved it with the alternating pair — but across K > 2
//! successive drawers the takes decay geometrically: 50% / 25% /
//! 12.5% / ... of the pool per ask-position, and the position is
//! STABLE across epochs on a real hook (the same flow's packets
//! arrive in the same order relative to the refill). At 6 leaves /
//! 1mb / 4s the worst leaf read 2.13 MB (the first position's 500
//! KB/s — 3.35x its 158 KB/s fair share) while the quietest
//! accumulated ~60 KB — one GRO admit short of 64 KiB — and measured
//! 78 B. The pool law held exactly (0.95x of policy) the whole time:
//! the aggregate was always right; only the distribution was broken.
//!
//! THE MODEL, stated honestly (the existing K=2 pin's precedent —
//! the same primitive sequence, the same credit):
//!  * one pool, K leaves; each leaf OFFERS a 64 KiB GRO skb on a
//!    fixed cadence — the starved regime (K x 64 KiB / cadence is
//!    orders above the policy — the demand the CI measured), with a
//!    FIXED cyclic order on ties: the worst case the live battery
//!    caught (the stable order);
//!  * the pool refills continuously (rate x dt, clamped at the
//!    burst cap) — the same credit the kernel's windows produce;
//!  * per event: the DRR primitive sequence the datapath runs — the
//!    spend from the balance, the draw when dry (the stamp guard,
//!    the ownership CAS, the take, the rollback on a failed draw),
//!    and under the new law the learned-share note on the draw's
//!    success.
//!
//! THE PINS: the old law reproduces the decay (worst far over the
//! anti-monopoly bound, quietest starved under one admit — the
//! failure pin, the 95/4 precedent's shape one order deeper); the
//! new law meets the live battery's bounds at K=6 and K=24 — worst
//! within 1.75x fair + one quantum, quietest at fair/4 or better,
//! the aggregate inside 1.45x policy AND above half of it (the
//! 46%-collapse guard) — and the single-active edge keeps the whole
//! budget (the DRR doc's own lo bound).

use super::ebpf_drr::{
    PEAK_DECAY_EPOCHS, draw_size, epoch_allowance, epoch_refill, fair_draw_size, ledger_carry,
    ledger_epoch, ledger_note, ledger_pack, ledger_room, pool_share_last, pool_share_note,
    pool_share_pack, pool_share_peak, pool_share_running, quantum, share_epoch_ns,
};
// The math copy rides drr_tests' parent inclusion (one per test
// binary, the duplicate-mod law) — reached through the grandparent,
// the limiter mod, where math_tests lives.
use super::super::math_tests::ebpf_math::{Bucket, draw_stamp_take, tokens_fetch_add, tokens_read};

/// The sim's GRO super-packet (the hook's view — the admit floor).
const PKT: u64 = 65_536;
/// The offer cadence per leaf: the starved regime (see the module
/// header) — at K=6 this is ~1.9 GB/s of demand against a 1 MB/s
/// policy, the shape the live battery measured.
const OFFER_US: u64 = 200;
/// A past-boot clock base (ktime is ~1e15 on any real machine — a
/// fresh leaf's stamp 0 admits immediately, like the datapath).
const BOOT_NS: u64 = 1_000_000_000_000_000;

/// One simulated leaf: its bucket plus the sim-side epoch evidence
/// the datapath derives from the draw stamp (a successful draw's
/// timestamp is the leaf's epoch marker — the sim carries the same
/// fact as a field so the failed-draw rollback cannot erase it, the
/// exact semantics the datapath's stamp carries).
struct SimLeaf {
    bkt: Bucket,
    noted_epoch: u32,
    got: u64,
}

/// The law under test: a closure from (quantum, pool tokens, learned
/// drawee count) to the take — the old law pins `learned` to 0 (the
/// v13 shape by construction), the new law reads the learned state.
type Law = fn(u64, u64, u16) -> u64;

/// The old law as a Law (learned ignored — the v13 residue law).
fn old_law(q: u64, pool: u64, _learned: u16) -> u64 {
    draw_size(q, pool)
}

/// The new law as a Law (the learned-share draw).
fn new_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// One leaf's offered packet through the DRR primitive sequence (the
/// datapath's own order, the existing K=2 pin's step widened by the
/// note): the spend, the stamp-guarded draw when dry, the take under
/// the law under test, and under the new law the learned-share note
/// riding the draw's success. Returns the bytes admitted (0 on drop).
fn step(leaf: &mut SimLeaf, pool: &mut Bucket, share: &mut u64, law: Law, q: u64, now: u64) -> u64 {
    // The spend: the balance covers the packet.
    if tokens_read(&leaf.bkt) >= PKT {
        let observed = tokens_read(&leaf.bkt);
        leaf.bkt.tokens = observed - PKT;
        leaf.got += PKT;
        return PKT;
    }
    // The draw: the stamp guard (a later clock always admits — the
    // sim is single-threaded, the CAS always wins), the take under
    // the law, the note on success (the new law's state; the old law
    // passes a fixed 0 and the note is a no-op for its verdicts).
    let last_draw = leaf.bkt.last_refill_ns;
    let _ = draw_stamp_take(&mut leaf.bkt, last_draw, now); // ownership
    let now_epoch = (now / share_epoch_ns()) as u32;
    let leaf_drew_this_epoch = leaf.noted_epoch == now_epoch;
    // The note rides the ATTEMPT (the datapath's rev 2 — the sim's
    // first design noted only succeeders and the learning never
    // bootstrapped; the starving asker is exactly the one the
    // divisor must count).
    leaf.noted_epoch = now_epoch;
    let take = law(q, tokens_read(pool), pool_share_last(*share));
    if take > 0 && tokens_read(pool) >= take {
        pool.tokens = tokens_read(pool) - take;
        let _ = tokens_fetch_add(&mut leaf.bkt, take);
        *share = pool_share_note(*share, now_epoch, leaf_drew_this_epoch);
        // The spend retries after the draw (the datapath's step 5).
        if tokens_read(&leaf.bkt) >= PKT {
            let observed = tokens_read(&leaf.bkt);
            leaf.bkt.tokens = observed - PKT;
            leaf.got += PKT;
            return PKT;
        }
        return 0;
    }
    // The failed draw rolls the stamp to the CURRENT EPOCH's start
    // (the datapath's rev 2): the retry-every-packet admission stays
    // for the rest of the epoch while the epoch evidence the note
    // consumed survives — the sim's noted_epoch field carries the
    // same fact (set above, before the attempt's outcome was known).
    let epoch_start = now_epoch as u64 * share_epoch_ns();
    let _ = draw_stamp_take(&mut leaf.bkt, now, epoch_start);
    0
}

/// The contention run: K leaves, one pool at `rate`, `secs` of
/// traffic, the fixed cyclic offer order (leaf 0's packet first at
/// every tie — the stable order the live battery caught). Returns
/// the per-leaf admitted bytes.
fn run(law: Law, rate: u64, k: usize, secs: u64) -> Vec<u64> {
    let q = quantum(rate);
    let burst = (rate.clamp(65_536, 4_194_304)).max(65_536);
    let mut pool = Bucket {
        tokens: 0, // the cushion is paid out by the caller's warm-up
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut leaves: Vec<SimLeaf> = (0..k)
        .map(|_| SimLeaf {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            noted_epoch: 0,
            got: 0,
        })
        .collect();
    let mut share: u64 = 0;
    // The warm-up: pay the fresh pool's cushion out at line rate (the
    // battery's own cushion drain) so the measured window sees steady
    // state — the first burst never carries into the verdicts.
    pool.tokens = 0;

    let total_events = secs * 1_000_000 / OFFER_US;
    let mut last_refill = BOOT_NS;
    for e in 0..total_events {
        let now = BOOT_NS + (e + 1) * OFFER_US * 1_000;
        // The continuous credit: rate x dt, clamped at the burst cap
        // (the same credit the kernel's windows produce).
        let dt = now - last_refill;
        last_refill = now;
        pool.tokens = (pool.tokens + rate.saturating_mul(dt) / 1_000_000_000).min(burst);
        // One round of offers, the fixed cyclic order.
        for leaf in leaves.iter_mut() {
            step(leaf, &mut pool, &mut share, law, q, now);
        }
    }
    leaves.into_iter().map(|l| l.got).collect()
}

/// The bounds the live battery judges (its own numbers): the
/// anti-monopoly bound (worst within 1.75x fair + one quantum), the
/// no-starve bound (quietest at fair/4 or better), the aggregate
/// band (inside 1.45x policy — the pool never creates budget — and
/// above half of it, the 46%-collapse guard).
struct Verdict {
    fair: u64,
    worst: u64,
    quietest: u64,
    total: u64,
}

fn verdict_for(gots: &[u64]) -> Verdict {
    let total: u64 = gots.iter().sum();
    let fair = total / gots.len() as u64;
    Verdict {
        fair,
        worst: *gots.iter().max().unwrap(),
        quietest: *gots.iter().min().unwrap(),
        total,
    }
}

/// The packing round-trip + the note's rollover arithmetic (the pure
/// core's own pins — small, boring, first). The repair-4 packing
/// added the PEAK field (the allowance's divisor source — the
/// ledger battery owns its ratchet/decay pins; this one owns the
/// round-trip and the retirement).
#[test]
fn the_share_word_packs_and_notes() {
    use super::ebpf_drr::{pool_share_epoch, pool_share_pack, pool_share_running};
    let w = pool_share_pack(7, 3, 5, 4);
    assert_eq!(pool_share_epoch(w), 7);
    assert_eq!(pool_share_running(w), 3);
    assert_eq!(pool_share_last(w), 5);
    assert_eq!(pool_share_peak(w), 4);
    // The rollover: a new epoch retires `running` into `last` (9 is
    // off the 8-epoch decay cadence, so the peak only ratchets to
    // running when running passes it).
    let w2 = pool_share_note(w, 9, false);
    assert_eq!(pool_share_last(w2), 3, "the epoch's count retired");
    assert_eq!(pool_share_running(w2), 1, "the first asker counted");
    assert_eq!(pool_share_epoch(w2), 9);
    assert_eq!(
        pool_share_peak(w2),
        4,
        "the peak holds under a smaller count"
    );
    // The same epoch: the count grows, `last` untouched.
    let w3 = pool_share_note(w2, 9, false);
    assert_eq!(pool_share_running(w3), 2);
    assert_eq!(pool_share_last(w3), 3);
    // An asker that already drew this epoch counts once.
    let w4 = pool_share_note(w3, 9, true);
    assert_eq!(pool_share_running(w4), 2, "the repeat asker not counted");
    // The live ratchet: a surge past the peak lifts it mid-epoch.
    let w5 = pool_share_note(w3, 9, false);
    let w6 = pool_share_note(w5, 9, false);
    assert_eq!(pool_share_running(w6), 4);
    assert_eq!(pool_share_peak(w6), 4, "the fourth asker ratchets the peak");
}

/// fair_draw_size's own bounds: the learned cap binds at the micro
/// scale (the pool's instantaneous content — the scale where the
/// residue law owned the geometric decay); learned 0 is the v13 law
/// by construction (a cold pool — and a missed state lookup — keep
/// the exact v13 shape, the fail-open lane).
#[test]
fn the_learned_cap_binds_inside_the_residue_law() {
    // learned 0: the v13 law, exactly (pool/2).
    for &(q, pool) in &[
        (100_000u64, 1_000_000u64),
        (100_000, 10_000),
        (400_000, 3_000_000),
    ] {
        assert_eq!(fair_draw_size(q, pool, 0), draw_size(q, pool));
    }
    // A learned count of 6: the take is at most pool/8 — a flat
    // fraction of the INSTANTANEOUS pool (the micro scale where the
    // decay lived). At a RICH pool the quantum ceiling binds below
    // it (the stockpile cap still owns the ceiling — the share cap
    // is the floor that killed the decay); at the micro scale the
    // share is the binding term.
    assert_eq!(
        fair_draw_size(100_000, 1_000_000, 6),
        100_000,
        "rich pool: the quantum ceiling"
    );
    assert_eq!(fair_draw_size(100_000, 800, 6), 100, "micro scale: 800B/8");
    // A single active leaf (learned 1): pool/3 — smaller takes, the
    // same throughput (the lone leaf re-draws freely).
    assert_eq!(fair_draw_size(100_000, 900, 1), 300);
    // The conservation floor: an empty pool draws nothing, ever.
    assert_eq!(fair_draw_size(100_000, 0, 5), 0);
}

/// THE FAILURE PIN: the old law reproduces the CI decay at K=6 —
/// the worst leaf far over the anti-monopoly bound, the quietest
/// starved under one admit. This pin documents WHY the new law
/// exists; if it ever fails, the decay class came back.
#[test]
fn the_old_law_decays_at_six_leaves() {
    let gots = run(old_law, 1_000_000, 6, 4);
    let v = verdict_for(&gots);
    let q = quantum(1_000_000);
    let bound = v.fair.saturating_mul(175) / 100 + q;
    assert!(
        v.worst > bound,
        "the decay shape: worst {} vs bound {} (fair {} + quantum {}) — if this fails, \
         the first-position monopoly came back",
        v.worst,
        bound,
        v.fair,
        q
    );
    assert!(
        v.quietest < v.fair / 4,
        "the starvation shape: quietest {} under fair/4 {} — if this fails, \
         the starvation came back",
        v.quietest,
        v.fair / 4
    );
}

/// THE CLOSE, K=6 (the CI's equal6 round): the new law meets the
/// live battery's bounds — worst within 1.75x fair + one quantum,
/// quietest at fair/4 or better, the aggregate inside 1.45x policy
/// and above half of it (the 46%-collapse guard).
#[test]
fn the_learned_law_shares_six_leaves_fairly() {
    let gots = run(new_law, 1_000_000, 6, 4);
    let v = verdict_for(&gots);
    let q = quantum(1_000_000);
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "anti-monopoly: worst {} vs bound {} (fair {} + quantum {})",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q,
        v.fair,
        q
    );
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve: quietest {} vs fair/4 {}",
        v.quietest,
        v.fair / 4
    );
    assert!(
        v.total <= 1_000_000 * 4 * 145 / 100,
        "the pool never creates budget: total {} vs the 1.45x band {}",
        v.total,
        1_000_000 * 4 * 145 / 100
    );
    assert!(
        v.total >= 1_000_000 * 4 / 2,
        "the collapse guard: total {} vs half the policy {} (the 46% class)",
        v.total,
        1_000_000 * 4 / 2
    );
}

/// THE CLOSE, K=24 (the CI's many24 round at 4mb — the owner's
/// many-leaf shape, where the old law read its worst ratio).
#[test]
fn the_learned_law_shares_twentyfour_leaves_fairly() {
    let gots = run(new_law, 4_000_000, 24, 4);
    let v = verdict_for(&gots);
    let q = quantum(4_000_000);
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "anti-monopoly at K=24: worst {} vs bound {} (fair {} + quantum {})",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q,
        v.fair,
        q
    );
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve at K=24: quietest {} vs fair/4 {}",
        v.quietest,
        v.fair / 4
    );
    assert!(
        v.total <= 4_000_000 * 4 * 145 / 100,
        "the pool never creates budget at K=24: total {}",
        v.total
    );
    assert!(
        v.total >= 4_000_000 * 4 / 2,
        "the collapse guard at K=24: total {}",
        v.total
    );
}

/// THE SINGLE-ACTIVE EDGE (the battery's own lo bound): one leaf
/// alone must see the whole budget — the DRR doc's own "half-draws
/// pace at the refill rate". The learned count of 1 halves the take
/// but never the throughput: the lone leaf re-draws freely.
#[test]
fn a_lone_leaf_still_sees_the_whole_budget() {
    let gots = run(new_law, 1_000_000, 1, 2);
    let v = verdict_for(&gots);
    assert!(
        v.total >= 1_000_000 * 2 * 8 / 10,
        "the lo bound: the lone leaf delivered {} of the 2s budget {}",
        v.total,
        1_000_000 * 2
    );
    assert!(
        v.total <= 1_000_000 * 2 * 145 / 100,
        "and never over the band: {}",
        v.total
    );
}

/// The allowance family (pure): a lone drawer or a cold pool keeps
/// the ledger OFF; the drawee count splits the epoch's refill; the
/// split never exceeds the refill (the pool never creates budget).
#[test]
fn the_epoch_allowance_family() {
    assert_eq!(
        epoch_allowance(1_000_000, 0),
        u64::MAX,
        "cold pool: fail-open"
    );
    assert_eq!(epoch_allowance(1_000_000, 1), u64::MAX, "lone drawer: off");
    assert_eq!(epoch_allowance(1_000_000, 2), 50_000, "two drawers: half");
    assert_eq!(epoch_allowance(1_000_000, 6), 16_666, "six: the sixth");
    assert_eq!(
        epoch_allowance(1_000_000, 24),
        4_166,
        "the owner's many shape"
    );
    for drawees in 2u16..25 {
        let allowance = epoch_allowance(4_000_000, drawees);
        assert!(
            allowance * drawees as u64 <= epoch_refill(4_000_000),
            "the split never exceeds the refill at drawees {drawees}"
        );
    }
    assert_eq!(epoch_refill(1_000_000), 100_000, "the 100ms refill");
    assert_eq!(epoch_refill(4_000_000), 400_000);
}

/// The ledger word (pure, the carry form): packs, earns elapsed
/// epochs at the allowance, spends down, caps the stockpile at one
/// quantum — the v13 doc's own stockpile sentence, made load-bearing.
#[test]
fn the_ledger_word_banks_carries_and_spends() {
    let w = ledger_pack(7, 12_345);
    assert_eq!(ledger_epoch(w), 7);
    assert_eq!(ledger_carry(w), 12_345);
    // The earning: three elapsed epochs at 50k, capped at the quantum.
    let earned = ledger_room(w, 10, 50_000, 400_000);
    assert_eq!(earned, 12_345 + 150_000, "the carry plus the earned epochs");
    // The cap: one quantum of stockpile, however long the silence.
    let capped = ledger_room(ledger_pack(0, 0), 1_000, 50_000, 100_000);
    assert_eq!(capped, 100_000, "the stockpile caps at one quantum");
    // The spend: the credit and the take land together, re-anchored.
    let spent = ledger_note(w, 10, 50_000, 400_000, 10_000);
    assert_eq!(ledger_epoch(spent), 10, "re-anchored at the spend");
    assert_eq!(ledger_carry(spent), 12_345 + 150_000 - 10_000);
    // A take beyond the room saturates at the room (a caller bug the
    // saturating form forgives once, never over-allowing).
    let big = ledger_note(w, 10, 50_000, 400_000, u64::MAX);
    assert_eq!(ledger_carry(big), 0, "an over-take empties the carry");
    // The epoch-wrap lane: elapsed beyond the ceiling credits a full
    // cap once (the multiply stays PLAIN — saturating_mul lowers to
    // the 128-bit __multi3 libcall the BPF ISA cannot carry, the
    // repair-4 load-death find).
    let wrapped = ledger_room(ledger_pack(1, 1_000), 1 << 30, 50_000, 400_000);
    assert_eq!(wrapped, 400_000, "the wrap credits a full cap, once");
}

/// The share word's PEAK (pure): ratchets on the running count —
/// live mid-epoch and at the retirement — and decays one step on
/// the PEAK_DECAY_EPOCHS cadence, floored at 1.
#[test]
fn the_share_peak_ratchets_and_decays() {
    // The live ratchet: a mid-epoch surge lifts the peak immediately
    // (running 5 growing to 6 passes the peak of 3).
    let w = pool_share_pack(8, 5, 2, 3);
    let surged = pool_share_note(w, 8, false);
    assert_eq!(pool_share_peak(surged), 6, "the sixth asker ratchets live");
    assert_eq!(pool_share_running(surged), 6);
    // The retirement ratchet + the decay cadence: epoch 16 is on the
    // 8-epoch decay period, the peak steps down after ratcheting.
    let retired = pool_share_note(pool_share_pack(15, 9, 9, 9), 16, false);
    assert_eq!(pool_share_last(retired), 9, "the epoch's count retired");
    assert_eq!(pool_share_peak(retired), 8, "ratcheted to 9, decayed one");
    // A non-boundary rollover retires without decaying.
    let plain = pool_share_note(pool_share_pack(15, 9, 9, 9), 17, false);
    assert_eq!(pool_share_peak(plain), 9, "no decay off the cadence");
    // The floor: a decayed peak stops at 1 (the lone-drawer lane).
    let mut word = pool_share_pack(0, 2, 2, 2);
    for epoch in 1..64 {
        word = pool_share_note(word, epoch * PEAK_DECAY_EPOCHS, true);
    }
    assert_eq!(pool_share_peak(word), 1, "the decay floors at one");
}
