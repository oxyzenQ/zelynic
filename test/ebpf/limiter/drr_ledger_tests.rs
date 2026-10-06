// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! repair-3/4/6: the epoch-ledger battery — the kernel-shaped feedback
//! simulation that reproduces the live fair-share battery's CI finds
//! rootlessly, then the law that closes them. The ENGINE lives in the
//! drr_sim sibling (split when the improve-40 guarantee bracket needed
//! it and this file rode the 500-LOC owner cap at exactly 500 — the
//! policy_write discipline, one family over); the pins here drive it
//! through the sibling path, unchanged.
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

use super::drr_sim::{run_kernel_shape, v16_cfg, v17_cfg, verdict_for};
use super::ebpf_drr::{pool_share_peak, quantum};

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
