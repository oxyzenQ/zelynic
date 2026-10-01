// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! repair-3/4/6: the epoch-ledger battery — the kernel-shaped feedback
//! simulation that reproduces the live fair-share battery's CI finds
//! rootlessly, then the law that closes them.
//!
//! THE MODEL, stated honestly (the drr_share_tests precedent, one
//! order deeper — the fixed-cadence sim embedded the fairness it
//! claimed to produce, so the kernel's reality stayed unpinned):
//! each leaf's offer cadence is TCP feedback (an admit grows the
//! window toward the 200us base; a starved flow backs off its
//! retransmit timer exponentially, capped at 400ms), the pool is
//! credited per packet (this packet owns [last, now] — the
//! micro-credit stream the kernel produces), the 64 KiB admit floor
//! stands, and the note rides the attempt once per leaf per epoch —
//! with a RACY form that clamps the learned count to the 1-3 band
//! the v16 non-atomic note converged to (the second defect).
//!
//! THE PINS: the failure side first — the v16 law breaks the
//! anti-monopoly bound at six equal-demand leaves even with a
//! perfect count, and starves the quietest below one admit with the
//! racy one (the live battery's fingerprint: worst 4.7x fair,
//! quietest 65536 + 78 B); the blocking ledger (no carry) still
//! monopolizes (the starved leaf cannot bank toward its admit, its
//! TCP stays collapsed, the aggregate sags); a carried-over
//! pool-share word throttles a lone successor below half (the
//! 8.2%-of-policy handoff find). The close: the carry-formed epoch
//! ledger, split across the drawee peak and re-keyed on every
//! policy mutation, meets the battery's bounds at K=6, K=24, the
//! lone-leaf edge, and the churn shape — the battery's own rows,
//! judged by the battery's own numbers.

use super::ebpf_drr::{
    epoch_allowance, fair_draw_size, ledger_note, ledger_room, pool_share_last, pool_share_note,
    pool_share_peak, quantum, share_epoch_ns,
};
// The math copy rides drr_tests' parent inclusion (the duplicate-mod
// law), reached through the limiter mod where math_tests lives.
use super::super::math_tests::ebpf_math::{draw_stamp_take, tokens_fetch_add, tokens_read, Bucket};

/// The sim's GRO super-packet (the hook's view — the admit floor).
const PKT: u64 = 65_536;
/// The hot-leaf offer cadence (a fully-grown window's spacing).
const BASE_NS: u64 = 200_000;
/// The window ceiling the feedback grows toward.
const MAX_CWND: u64 = 64;
/// The retransmit-timer backoff ceiling: 32x the cadence, capped at
/// 400ms (the calibration that reproduced the CI fingerprint).
const RTO_STEPS: u32 = 5;
const RTO_CAP_NS: u64 = 400_000_000;

/// One simulated leaf: bucket, epoch evidence, TCP feedback state,
/// and its packed epoch-ledger word (the pure core's packing).
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

    /// The offer cadence: the window feedback, stretched by backoff.
    fn gap(&self) -> u64 {
        let base = BASE_NS * MAX_CWND / self.cwnd;
        let stretched = base << self.rto.min(RTO_STEPS);
        if stretched < RTO_CAP_NS {
            stretched
        } else {
            RTO_CAP_NS
        }
    }

    /// A starved offer: streak grows; every fourth drop halves the
    /// window and steps the backoff.
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

/// The configuration under test: the take law, the note's honesty
/// (the racy cap), whether the epoch ledger caps the room, and
/// whether it carries (repair-4) or blocks (the ablation).
struct SimConfig {
    law: fn(u64, u64, u16) -> u64,
    racy_note_cap: Option<u16>,
    ledger: bool,
    carry: bool,
}

/// The v16-law config (ledger off; the racy cap optional).
fn v16_cfg(racy: Option<u16>) -> SimConfig {
    SimConfig {
        law: v16_law,
        racy_note_cap: racy,
        ledger: false,
        carry: true,
    }
}

/// The v17-law config (the ledger on; the carry or the ablation).
fn v17_cfg(carry: bool) -> SimConfig {
    SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
        carry,
    }
}

/// The v16 law as a take law (the per-take learned cap).
fn v16_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// The v17 law: the same take law — the ledger caps the room around it.
fn v17_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// The kernel-shaped run: K leaves, one pool at `rate`, `secs` of
/// feedback-driven offers (the later half staggered in at
/// `stagger_ns`), starting from `initial_share` (the carried-over
/// pool-share word) and returning the per-leaf admits plus the final
/// word.
fn run_kernel_shape(
    cfg: &SimConfig,
    rate: u64,
    k: usize,
    secs: u64,
    stagger_ns: u64,
    initial_share: u64,
) -> (Vec<u64>, u64) {
    use std::collections::BinaryHeap;
    let q = quantum(rate);
    let burst = rate.clamp(65_536, 4_194_304).max(65_536);
    let mut pool = Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut pool_stamp: u64 = 0;
    let mut share: u64 = initial_share;
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
        // The pool credit: this packet owns [stamp, now].
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
            let drawees = pool_share_peak(share);
            // The take under the law under test.
            let mut take = (cfg.law)(q, tokens_read(&pool), learned);
            // The ledger's room: the carry form, or the ablation's
            // blocking form.
            let mut ledgery = false;
            let mut allowance = 0u64;
            if cfg.ledger && drawees >= 2 {
                allowance = epoch_allowance(rate, drawees);
                let room = if cfg.carry {
                    ledger_room(leaf.ledger, now_epoch, allowance, q)
                } else {
                    allowance
                };
                take = take.min(room);
                ledgery = true;
            }
            if take > 0 && tokens_read(&pool) >= take {
                pool.tokens = tokens_read(&pool) - take;
                let _ = tokens_fetch_add(&mut leaf.bkt, take);
                if ledgery {
                    leaf.ledger = ledger_note(leaf.ledger, now_epoch, allowance, q, take);
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
                // The failed draw rolls the stamp to the epoch start.
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
    (leaves.into_iter().map(|l| l.got).collect(), share)
}

/// The bounds the live battery judges, as one verdict over the admits.
struct Verdict {
    fair: u64,
    worst: u64,
    quietest: u64,
    total: u64,
}

fn verdict_for(gots: &[u64]) -> Verdict {
    let total: u64 = gots.iter().sum();
    Verdict {
        fair: total / gots.len() as u64,
        worst: *gots.iter().max().unwrap(),
        quietest: *gots.iter().min().unwrap(),
        total,
    }
}

/// THE FAILURE PIN, defect one (the feedback alone): the v16 law
/// with a perfect note still breaks the anti-monopoly bound — a
/// per-take cap cannot bound a per-epoch share, because the drawer
/// that admits offers the packets that draw.
#[test]
fn the_v16_law_monopolizes_under_feedback_alone() {
    let cfg = v16_cfg(None);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0, 0);
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
    let cfg = v16_cfg(Some(3));
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0, 0);
    let v = verdict_for(&gots);
    assert!(
        v.quietest < v.fair / 4,
        "the starvation shape: quietest {} vs fair/4 {} — if this fails, \
         the racy note no longer starves the quiet drawer",
        v.quietest,
        v.fair / 4
    );
    let (gots, _) = run_kernel_shape(&cfg, 4_000_000, 24, 4, 0, 0);
    let v = verdict_for(&gots);
    assert!(
        v.quietest < v.fair / 4,
        "the starvation shape at K=24: quietest {} vs fair/4 {}",
        v.quietest,
        v.fair / 4
    );
}

/// THE ABLATION PIN (why the carry is load-bearing): the blocking
/// form of the ledger (allowance reset per epoch, no banking) still
/// monopolizes — the starved leaf cannot bank toward the 64 KiB
/// admit, its collapsed TCP starves the pool of askers, and the
/// survivors' inflated takes ride the silence.
#[test]
fn the_blocking_ledger_still_monopolizes() {
    let cfg = v17_cfg(false);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0, 0);
    let v = verdict_for(&gots);
    let bound = v.fair.saturating_mul(175) / 100 + quantum(1_000_000);
    assert!(
        v.worst > bound,
        "the blocking shape: worst {} vs bound {} (fair {}) — the carry is \
         what banks the starved leaf toward its admit",
        v.worst,
        bound,
        v.fair
    );
}

/// THE CLOSE, K=6 (the battery's equal6 round): the carry-formed
/// epoch ledger meets every live bound — worst, quietest, and the
/// aggregate inside the 65%-130% band the battery floors.
#[test]
fn the_epoch_ledger_meets_the_bounds_at_six_leaves() {
    let cfg = v17_cfg(true);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 6, 4, 0, 0);
    let v = verdict_for(&gots);
    let q = quantum(1_000_000);
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "anti-monopoly: worst {} vs bound {}",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q
    );
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve: {} vs {}",
        v.quietest,
        v.fair / 4
    );
    assert!(
        v.total <= 1_000_000 * 4 * 130 / 100,
        "the pool never creates budget: total {}",
        v.total
    );
    assert!(
        v.total >= 1_000_000 * 4 * 65 / 100,
        "the collapse guard: total {} vs the 65% floor {}",
        v.total,
        1_000_000 * 4 * 65 / 100
    );
}

/// THE CLOSE, K=24 (the battery's many24 round at 4mb — the owner's
/// many-leaf shape, where the pre-repair legs read 3.2-5.8 MB).
#[test]
fn the_epoch_ledger_meets_the_bounds_at_twentyfour_leaves() {
    let cfg = v17_cfg(true);
    let (gots, _) = run_kernel_shape(&cfg, 4_000_000, 24, 4, 0, 0);
    let v = verdict_for(&gots);
    let q = quantum(4_000_000);
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "anti-monopoly at K=24: worst {} vs bound {}",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q
    );
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve at K=24: {} vs {}",
        v.quietest,
        v.fair / 4
    );
    assert!(
        v.total <= 4_000_000 * 4 * 130 / 100,
        "the pool never creates budget at K=24: total {}",
        v.total
    );
    assert!(
        v.total >= 4_000_000 * 4 * 65 / 100,
        "the collapse guard at K=24: total {} vs the 65% floor {}",
        v.total,
        4_000_000 * 4 * 65 / 100
    );
}

/// THE LONE-LEAF EDGE (the battery's single round): one leaf alone
/// keeps the whole budget — the ledger is off at drawees < 2, and
/// the take law's pool fractions pace a lone drawer.
#[test]
fn a_lone_leaf_keeps_the_whole_budget_under_the_ledger() {
    let cfg = v17_cfg(true);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 1, 2, 0, 0);
    let v = verdict_for(&gots);
    assert!(
        v.total >= 1_000_000 * 2 * 8 / 10,
        "the lo bound: the lone leaf delivered {} of {}",
        v.total,
        1_000_000 * 2
    );
    assert!(
        v.total <= 1_000_000 * 2 * 145 / 100,
        "over band: {}",
        v.total
    );
}

/// THE CHURN SHAPE (the battery's churn6 round): the later half of
/// the leaves born MID-WINDOW (the stagger), the aggregate judged
/// over the whole span — fresh epochs never leak a spent carry.
#[test]
fn the_churn_shape_holds_the_band_under_the_ledger() {
    let cfg = v17_cfg(true);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 6, 6, 2_000_000_000, 0);
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

/// THE HANDOFF PIN (repair-6): a policy mutation must hand its
/// successor a fresh budget. The battery's rounds re-apply on one
/// root, and the pool-share word used to ride across the applies:
/// many24's peak of 24 left behind, the single round that followed
/// read 8.2% of policy — a lone leaf throttled by a divisor its own
/// demand never asked for (the real-host hazard: a 24-leaf policy
/// that shrinks to one starves the survivor through the decay's
/// tail). The generation-prefixed keys close it; this pin reproduces
/// both sides.
#[test]
fn a_mutated_budget_hands_its_successor_a_fresh_word() {
    let cfg = v17_cfg(true);
    // Round one: 24 leaves at 4mb — the word ratchets its peak high.
    let (_, stale_word) = run_kernel_shape(&cfg, 4_000_000, 24, 2, 0, 0);
    assert!(
        pool_share_peak(stale_word) >= 20,
        "the many-leaf round left its high-water behind: {}",
        pool_share_peak(stale_word)
    );
    // The lone successor reading the carried word: throttled (the
    // pre-fix shape — the battery's single round read 8.2%).
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 1, 2, 0, stale_word);
    let stale_total: u64 = gots.iter().sum();
    assert!(
        stale_total < 1_000_000 * 2 / 2,
        "the stale peak throttles the successor: {stale_total} of {}",
        1_000_000 * 2
    );
    // The same successor with a fresh word (the generation-keyed
    // shape): the whole budget, exactly as the single row demands.
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 1, 2, 0, 0);
    let fresh_total: u64 = gots.iter().sum();
    assert!(
        fresh_total >= 1_000_000 * 2 * 8 / 10,
        "the fresh word keeps the whole budget: {fresh_total} of {}",
        1_000_000 * 2
    );
}
