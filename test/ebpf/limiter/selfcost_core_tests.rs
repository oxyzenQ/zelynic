// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z6: rootless pins for the mirror's law file
//! (selfcost_core.rs — the preserved asset beside this file). The
//! hist_tests.rs discipline: the ladder's bounds and exact
//! boundaries, the row's size law, and the record law's four
//! contracts (the buckets ARE the count, the exact sum, the
//! 0-sentinel min, the max ratchet).

// The production arithmetic itself, compiled into this test module:
// the SAME file the BPF object builds. pub(super) so a sibling pin
// module reuses THIS copy (one inclusion of selfcost.rs per test
// binary — the duplicate-mod lint clippy -D warnings rightly rejects
// two).
#[path = "selfcost_core.rs"]
pub(super) mod ebpf_selfcost;

use self::ebpf_selfcost::{
    SELF_COST_BUCKETS, SelfCostRow, SelfCostRowRaw, bucket_bounded_bounds, cost_bucket,
    cost_record, fold_self_cost, format_ns, self_cost_samples,
};

/// The row's layout law: 32 buckets plus the exact-mass word, all
/// u64 — 264 bytes, the shape the schema pin and the userspace twin
/// both hold (the min/max words the first sketch carried are gone —
/// the C77 live leg measured their replace pairs past the verifier's
/// walk budget at the wrapper's position; the bounds ride the
/// buckets).
#[test]
fn row_size_is_pinned() {
    assert_eq!(core::mem::size_of::<SelfCostRow>(), 264);
    assert_eq!(SELF_COST_BUCKETS, 32);
}

/// The ladder is total over the probe shapes the other ladders pin:
/// every power-of-two boundary lands exactly, and the extremes clamp.
#[test]
fn cost_bucket_boundaries_are_exact() {
    assert_eq!(cost_bucket(0), 0);
    assert_eq!(cost_bucket(1), 0);
    for k in 1u64..=31 {
        assert_eq!(cost_bucket(1u64 << k), k as usize, "boundary 2^{k}");
        assert_eq!(
            cost_bucket((1u64 << k) - 1),
            (k - 1) as usize,
            "pre-boundary 2^{k}-1"
        );
    }
    assert_eq!(cost_bucket(u64::MAX), 31, "the clamp is the last bucket");
}

/// The record law, driven on a real row (the test-tree struct, the
/// same single-writer reality the per-CPU slot gives the datapath):
/// N samples of known cost land in the ladder's buckets (the buckets
/// ARE the count), the exact sum books every nanosecond, the min
/// rides its 0-sentinel into the true minimum, and the max ratchets.
#[test]
fn cost_record_keeps_the_four_laws() {
    let mut row = SelfCostRow::default();
    // A fresh row answers zero everywhere: the honest absence.
    assert_eq!(row.buckets.iter().sum::<u64>(), 0);
    assert_eq!(row.sum_ns, 0);

    let samples: [u64; 5] = [100, 3, 4096, 3, 65_537];
    for &ns in &samples {
        cost_record(&mut row, ns);
    }

    // The buckets ARE the count (no second count source).
    let count: u64 = row.buckets.iter().sum();
    assert_eq!(count, samples.len() as u64);
    // Each sample's bucket: log2 of the value.
    for &ns in &samples {
        let b = cost_bucket(ns);
        assert!(row.buckets[b] >= 1, "bucket {b} empty for sample {ns}");
    }
    // The exact sum: every nanosecond booked once.
    let total: u64 = samples.iter().sum();
    assert_eq!(row.sum_ns, total);
}

/// The fold law: buckets and sums add across CPUs, the sample count
/// derives from the folded buckets (no second count source), and the
/// bucket-bounded bounds ride the folded buckets themselves — the
/// smallest sampled cost at least the first nonempty bucket's lower
/// bound, the largest below the last nonempty bucket's ceiling.
#[test]
fn fold_and_bounds_hold_their_laws() {
    let mut a = SelfCostRowRaw::default();
    a.buckets[5] = 3;
    a.buckets[12] = 1;
    a.sum_ns = 900;
    let mut b = SelfCostRowRaw::default();
    b.buckets[5] = 2;
    b.sum_ns = 1_100;
    let folded = fold_self_cost(&[a, b]);
    assert_eq!(folded.buckets[5], 5);
    assert_eq!(folded.buckets[12], 1);
    assert_eq!(folded.sum_ns, 2_000);
    assert_eq!(self_cost_samples(&folded), 6);
    let (lo, hi) = bucket_bounded_bounds(&folded).unwrap();
    assert_eq!(lo, 1 << 5, "the lower bound is the first bucket's floor");
    assert_eq!(
        hi,
        (1 << 13) - 1,
        "the upper bound is the last bucket's ceiling minus one"
    );
    // The honest absence: an empty fold answers None, never a zero
    // dressed as a measurement.
    assert_eq!(bucket_bounded_bounds(&SelfCostRowRaw::default()), None);
}

/// The text surface's nanosecond ladder: ms past a millisecond, us
/// past a microsecond, raw ns below — the three tiers the render
/// labels ride.
#[test]
fn format_ns_ladder_is_honest() {
    assert_eq!(format_ns(42), "42ns");
    assert_eq!(format_ns(1_000), "1.0us");
    assert_eq!(format_ns(1_000_000), "1.0ms");
    assert_eq!(format_ns(12_345_678), "12.3ms");
}

/// The AND-mask law's semantics: cost_bucket already answers
/// 0..=31, so the mask is a verifier-proof formality — the recorded
/// bucket is always the ladder's own answer.
#[test]
fn recorded_bucket_matches_the_ladder() {
    let mut row = SelfCostRow::default();
    // The clamp shape: a cost past 2^31 ns lands in bucket 31.
    cost_record(&mut row, u64::MAX);
    assert_eq!(row.buckets[31], 1, "the clamp sample left the last bucket");
    // The zero shape: a zero-delta sample is still a sample (bucket 0).
    cost_record(&mut row, 0);
    assert!(row.buckets[0] >= 1, "the zero sample vanished");
}
