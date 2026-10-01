// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! repair-3: the epoch-ledger battery — the kernel-shaped feedback
//! simulation that reproduces the live fair-share battery's CI finds
//! rootlessly, then the law that closes them.
//!
//! THE MODEL, stated honestly (the drr_share_tests precedent, one
//! order deeper — the fixed-cadence sim embedded the fairness it
//! claimed to produce, so the kernel's reality stayed unpinned):
//!  * each leaf's OFFER CADENCE is TCP feedback: an admitted packet
//!    grows the window (cadence toward the 200us base), a starved
//!    flow backs off its retransmit timer exponentially (32x, capped
//!    at 400ms) — the flow that admits offers packets the starved
//!    ones no longer do, which is the asymmetry the live battery
//!    measured and the fixed cadence erased;
//!  * the pool is credited per packet (the window-ownership
//!    timeline: this packet owns [last, now] at the policy rate) —
//!    the micro-credit stream the kernel actually produces, not a
//!    once-per-event lump;
//!  * the admit floor stands (a leaf must hold the whole 64 KiB GRO
//!    super-packet before it can spend one);
//!  * the note rides the attempt, once per leaf per epoch — and the
//!    RACY form can clamp the learned count to the 1-3 band the v16
//!    non-atomic read-modify-write converged to under the multi-CPU
//!    draw storm (every BPF_ANY insert replaced the word from its
//!    own stale read), the second defect the battery caught.
//!
//! THE PINS: the failure side first — the v16 law with a perfect
//! count still breaks the anti-monopoly bound at six equal-demand
//! leaves (the per-take cap cannot bound a per-epoch share: the fast
//! drawer's repeat draws drain the pool through (K+2)-sized bites),
//! and with the racy count the quietest starves below one admit's
//! worth of the fair share (the live battery's exact fingerprint:
//! worst 4.7x fair, quietest 65536 + 78 B over the 4s window). The
//! close side: the epoch ledger (the take further capped by the
//! leaf's remaining per-epoch allowance) meets the battery's bounds
//! at K=6 and K=24, keeps the lone leaf at the whole budget, and
//! holds the aggregate inside the band on the churn shape — the
//! battery's own rows, judged by the battery's own numbers.

use super::ebpf_drr::{
    epoch_allowance, epoch_refill, fair_draw_size, ledger_drawn, ledger_epoch, ledger_note,
    ledger_pack, ledger_roll, pool_share_last, pool_share_note, quantum, share_epoch_ns,
};
// The math copy rides drr_tests' parent inclusion (one per test
// binary, the duplicate-mod law) — reached through the grandparent,
// the limiter mod, where math_tests lives.
use super::super::math_tests::ebpf_math::{draw_stamp_take, tokens_fetch_add, tokens_read, Bucket};

/// The sim's GRO super-packet (the hook's view — the admit floor).
const PKT: u64 = 65_536;
/// The hot-leaf offer cadence: a fully-grown window's packet spacing.
const BASE_NS: u64 = 200_000;
/// The window ceiling the feedback grows toward.
const MAX_CWND: u64 = 64;
/// The retransmit-timer backoff ceiling: 32x the cadence, capped at
/// 400ms — a collapsed connection's offer stream.
const RTO_STEPS: u32 = 5;
const RTO_CAP_NS: u64 = 400_000_000;

/// One simulated leaf: its bucket, its epoch evidence (the sim-side
/// twin of the datapath's stamp-derived check), its TCP feedback
/// state, and its packed epoch-ledger word (the pure core's packing,
/// driven through the same roll/note fns the datapath runs).
struct SimLeaf {
    bkt: Bucket,
    noted_epoch: u32,
    got: u64,
    cwnd: u64,
    streak: u64,
    rto: u32,
    next_offer: u64,
    ledger: u64,
}

impl SimLeaf {
    fn new(first_offer: u64) -> Self {
        SimLeaf {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            noted_epoch: 0,
            got: 0,
            cwnd: 1,
            streak: 0,
            rto: 0,
            next_offer: first_offer,
            ledger: 0,
        }
    }

    /// The offer cadence: the window's feedback, stretched by the
    /// retransmit backoff when starved.
    fn gap(&self) -> u64 {
        let base = BASE_NS * MAX_CWND / self.cwnd;
        let stretched = base << self.rto.min(RTO_STEPS);
        if stretched < RTO_CAP_NS {
            stretched
        } else {
            RTO_CAP_NS
        }
    }

    /// A starved offer: the streak grows, every fourth drop halves
    /// the window and steps the backoff.
    fn drop_tick(&mut self) {
        self.streak += 1;
        if self.streak.is_multiple_of(4) {
            self.cwnd /= 2;
            if self.cwnd == 0 {
                self.cwnd = 1;
            }
            self.rto += 1;
        }
    }

    /// An admitted packet: the window grows, the timers heal.
    fn admit_tick(&mut self) {
        if self.cwnd < MAX_CWND {
            self.cwnd += 1;
        }
        self.streak = 0;
        self.rto = 0;
    }
}

/// The configuration under test: the draw's take law, the note's
/// honesty (the racy cap emulates the v16 word's converged
/// undercount), and whether the epoch ledger caps the room.
struct SimConfig {
    law: fn(u64, u64, u16) -> u64,
    racy_note_cap: Option<u16>,
    ledger: bool,
}

/// The v16 law as a take law (the per-take learned cap).
fn v16_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// The v17 law: the same take law — the ledger caps the room around
/// it, the residue law and the learned cap still binding inside.
fn v17_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// The kernel-shaped run: K leaves, one pool at `rate`, `secs` of
/// feedback-driven offers (the later half staggered in at
/// `stagger_ns` — the churn shape). Returns the per-leaf admitted
/// bytes, judged by the caller against the battery's bounds.
fn run_kernel_shape(cfg: &SimConfig, rate: u64, k: usize, secs: u64, stagger_ns: u64) -> Vec<u64> {
    use std::collections::BinaryHeap;
    let q = quantum(rate);
    let burst = rate.clamp(65_536, 4_194_304).max(65_536);
    let mut pool = Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut pool_stamp: u64 = 0;
    let mut share: u64 = 0;
    let half = k / 2;
    let mut leaves: Vec<SimLeaf> = (0..k)
        .map(|i| {
            let stagger = if i >= half { stagger_ns } else { 0 };
            SimLeaf::new((i as u64 + 1) * BASE_NS + stagger)
        })
        .collect();
    let mut heap: BinaryHeap<std::cmp::Reverse<(u64, usize)>> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| std::cmp::Reverse((l.next_offer, i)))
        .collect();
    let total = secs * 1_000_000_000;
    while let Some(std::cmp::Reverse((now, i))) = heap.pop() {
        if now > total {
            break;
        }
        let leaf = &mut leaves[i];
        // The pool credit: this packet owns [stamp, now] (the exact
        // window-ownership timeline the kernel's refills produce).
        let dt = now - pool_stamp;
        pool_stamp = now;
        let credit = rate.saturating_mul(dt) / 1_000_000_000;
        pool.tokens = (tokens_read(&pool) + credit).min(burst);
        // The spend.
        if tokens_read(&leaf.bkt) >= PKT {
            let observed = tokens_read(&leaf.bkt);
            leaf.bkt.tokens = observed - PKT;
            leaf.got += PKT;
            leaf.admit_tick();
        } else {
            // The draw attempt: the note rides it, once per epoch.
            let now_epoch = (now / share_epoch_ns()) as u32;
            let drew_this_epoch = leaf.noted_epoch == now_epoch;
            leaf.noted_epoch = now_epoch;
            share = pool_share_note(share, now_epoch, drew_this_epoch);
            let mut learned = pool_share_last(share);
            if let Some(cap) = cfg.racy_note_cap {
                learned = learned.min(cap);
            }
            // The take under the law under test.
            let mut take = (cfg.law)(q, tokens_read(&pool), learned);
            // The epoch ledger's room (the v17 cap).
            if cfg.ledger && learned >= 2 {
                let allowance = epoch_allowance(rate, learned);
                let rolled = ledger_roll(leaf.ledger, now_epoch);
                let room = allowance.saturating_sub(ledger_drawn(rolled) as u64);
                take = take.min(room);
            }
            if take > 0 && tokens_read(&pool) >= take {
                pool.tokens = tokens_read(&pool) - take;
                let _ = tokens_fetch_add(&mut leaf.bkt, take);
                if cfg.ledger && learned >= 2 {
                    leaf.ledger = ledger_note(leaf.ledger, now_epoch, take);
                }
                if tokens_read(&leaf.bkt) >= PKT {
                    let observed = tokens_read(&leaf.bkt);
                    leaf.bkt.tokens = observed - PKT;
                    leaf.got += PKT;
                    leaf.admit_tick();
                } else {
                    leaf.drop_tick();
                }
            } else {
                // The failed draw rolls the stamp to the epoch start
                // (the datapath's rev 2): retry-every-packet stands.
                let last_draw = leaf.bkt.last_refill_ns;
                let _ = draw_stamp_take(&mut leaf.bkt, last_draw, now);
                let epoch_start = now_epoch as u64 * share_epoch_ns();
                let _ = draw_stamp_take(&mut leaf.bkt, now, epoch_start);
                leaf.drop_tick();
            }
        }
        leaf.next_offer = now + leaf.gap();
        heap.push(std::cmp::Reverse((leaf.next_offer, i)));
    }
    leaves.into_iter().map(|l| l.got).collect()
}

/// The bounds the live battery judges (its own numbers), as one
/// verdict over the run's per-leaf admits.
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

/// The allowance family (pure): a lone drawer or a cold pool keeps
/// the ledger OFF; a learned count splits the epoch's refill; the
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
    for learned in 2u16..25 {
        let allowance = epoch_allowance(4_000_000, learned);
        assert!(
            allowance * learned as u64 <= epoch_refill(4_000_000),
            "the split never exceeds the refill at learned {learned}"
        );
    }
    assert_eq!(epoch_refill(1_000_000), 100_000, "the 100ms refill");
    assert_eq!(epoch_refill(4_000_000), 400_000);
}

/// The ledger word (pure): packs, rolls at the boundary, saturates
/// the spend, and never lets a spent epoch suppress the next.
#[test]
fn the_ledger_word_packs_rolls_and_notes() {
    let w = ledger_pack(7, 12_345);
    assert_eq!(ledger_epoch(w), 7);
    assert_eq!(ledger_drawn(w), 12_345);
    // The rollover: a past epoch's drawn count zeroes at the boundary.
    assert_eq!(ledger_roll(w, 8), ledger_pack(8, 0));
    assert_eq!(ledger_roll(w, 7), w, "idempotent inside the live epoch");
    // The spend: rolls, then adds, saturating at the u32 ceiling.
    let spent = ledger_note(w, 7, 5_000);
    assert_eq!(ledger_drawn(spent), 17_345);
    let spent_across = ledger_note(w, 8, 5_000);
    assert_eq!(
        ledger_drawn(spent_across),
        5_000,
        "the past epoch's spend never carries"
    );
    let saturated = ledger_note(w, 7, u64::MAX);
    assert_eq!(ledger_drawn(saturated), u32::MAX);
}

/// THE FAILURE PIN, defect one (the feedback alone): the v16 law
/// with a PERFECT note still breaks the anti-monopoly bound at six
/// equal-demand leaves — a per-take cap cannot bound a per-epoch
/// share, because the drawer that admits offers the packets that
/// draw. If this pin fails, the feedback asymmetry left the model.
#[test]
fn the_v16_law_monopolizes_under_feedback_alone() {
    let cfg = SimConfig {
        law: v16_law,
        racy_note_cap: None,
        ledger: false,
    };
    let gots = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0);
    let v = verdict_for(&gots);
    let bound = v.fair.saturating_mul(175) / 100 + quantum(1_000_000);
    assert!(
        v.worst > bound,
        "the monopoly shape: worst {} vs bound {} (fair {}) — if this fails, \
         the frequency feedback no longer concentrates the stream",
        v.worst,
        bound,
        v.fair
    );
}

/// THE FAILURE PIN, defect two (the note race): the v16 law with the
/// racy note's converged count starves the quietest below fair/4 —
/// the live battery's fingerprint (one admit over the whole window,
/// 65536 + 78 B measured on the CI legs this pin reproduces).
#[test]
fn the_v16_law_starves_under_the_note_race() {
    let cfg = SimConfig {
        law: v16_law,
        racy_note_cap: Some(3),
        ledger: false,
    };
    let gots = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0);
    let v = verdict_for(&gots);
    assert!(
        v.quietest < v.fair / 4,
        "the starvation shape: quietest {} vs fair/4 {} — if this fails, \
         the racy note no longer starves the quiet drawer",
        v.quietest,
        v.fair / 4
    );
    let gots = run_kernel_shape(&cfg, 4_000_000, 24, 4, 0);
    let v = verdict_for(&gots);
    assert!(
        v.quietest < v.fair / 4,
        "the starvation shape at K=24: quietest {} vs fair/4 {}",
        v.quietest,
        v.fair / 4
    );
}

/// THE CLOSE, K=6 (the battery's equal6 round): the epoch ledger
/// meets every live bound — worst inside 1.75x fair + one quantum,
/// quietest at fair/4 or better, the aggregate inside the band and
/// above the collapse guard.
#[test]
fn the_epoch_ledger_meets_the_bounds_at_six_leaves() {
    let cfg = SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
    };
    let gots = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0);
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
        "the pool never creates budget: total {}",
        v.total
    );
    assert!(
        v.total >= 1_000_000 * 4 / 2,
        "the collapse guard: total {} vs half the policy {}",
        v.total,
        1_000_000 * 4 / 2
    );
}

/// THE CLOSE, K=24 (the battery's many24 round at 4mb — the owner's
/// many-leaf shape, where the live legs read worst 3.2-5.8 MB).
#[test]
fn the_epoch_ledger_meets_the_bounds_at_twentyfour_leaves() {
    let cfg = SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
    };
    let gots = run_kernel_shape(&cfg, 4_000_000, 24, 4, 0);
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

/// THE LONE-LEAF EDGE (the battery's single round): one leaf alone
/// keeps the whole budget — the ledger is off at learned < 2, and
/// the take law's pool fractions pace a lone drawer exactly as the
/// v16 single-active pin proved they do.
#[test]
fn a_lone_leaf_keeps_the_whole_budget_under_the_ledger() {
    let cfg = SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
    };
    let gots = run_kernel_shape(&cfg, 1_000_000, 1, 2, 0);
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

/// THE CHURN SHAPE (the battery's churn6 round): the later half of
/// the leaves born MID-WINDOW (the stagger), the aggregate judged
/// over the whole span — fresh epochs never leak a spent ledger.
#[test]
fn the_churn_shape_holds_the_band_under_the_ledger() {
    let cfg = SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
    };
    let gots = run_kernel_shape(&cfg, 1_000_000, 6, 6, 2_000_000_000);
    let v = verdict_for(&gots);
    assert!(
        v.total <= 1_000_000 * 6 * 145 / 100,
        "the pool never creates budget on the churn span: total {}",
        v.total
    );
    assert!(
        v.total >= 1_000_000 * 6 / 2,
        "the collapse guard on the churn span: total {}",
        v.total
    );
}
