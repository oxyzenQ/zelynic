// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Rootless pins for the mirror's userspace twin (night-frontier-Z6):
//! the cross-CPU fold law and the mirror's layout — compiled INSIDE
//! the production module (the schema_sync_pin pattern), so the pins
//! ride the same file the render and the JSON projection call.

use super::*;

#[test]
fn mirror_layout_is_the_schema_pin() {
    assert_eq!(SELF_COST_BUCKETS, 32);
    // v36: 256 (the 32 buckets) + 8 (the exact mass — the count
    // rides no word, sum(buckets) IS the count; the min/max words
    // are gone, the bounds ride the buckets).
    assert_eq!(core::mem::size_of::<SelfCostRowRaw>(), 264);
}

/// The fold law's arithmetic: buckets and sums add across CPUs, the
/// max takes the largest per-CPU high-water.
#[test]
fn fold_adds_buckets_sums_and_max() {
    let mut a = SelfCostRowRaw::default();
    a.buckets[5] = 3;
    a.buckets[9] = 1;
    a.sum_ns = 1_000;
    let mut b = SelfCostRowRaw::default();
    b.buckets[5] = 2;
    b.buckets[12] = 4;
    b.sum_ns = 2_500;
    let folded = fold_self_cost(&[a, b]);
    assert_eq!(folded.buckets[5], 5);
    assert_eq!(folded.buckets[9], 1);
    assert_eq!(folded.buckets[12], 4);
    assert_eq!(folded.sum_ns, 3_500);
    assert_eq!(self_cost_samples(&folded), 10);
}

/// The bucket-bounded bounds read: the smallest sampled cost is AT
/// LEAST the first nonempty bucket's lower bound, the largest BELOW
/// the last nonempty bucket's upper bound — the log2 resolution's
/// own shape — and the empty fold answers the honest absence.
#[test]
fn bounds_read_is_bucket_bounded() {
    let mut a = SelfCostRowRaw::default();
    a.buckets[5] = 3;
    a.buckets[12] = 1;
    let folded = fold_self_cost(&[a]);
    let (lo, hi) = bucket_bounded_bounds(&folded).unwrap();
    assert_eq!(lo, 1 << 5, "the lower bound is the first bucket's floor");
    assert_eq!(
        hi,
        (1 << 13) - 1,
        "the upper bound is the last bucket's ceiling minus one"
    );
    // A single-bucket fold: both ends ride that one bucket's band.
    let mut one = SelfCostRowRaw::default();
    one.buckets[10] = 2;
    let (lo, hi) = bucket_bounded_bounds(&fold_self_cost(&[one])).unwrap();
    assert_eq!(lo, 1 << 10);
    assert_eq!(hi, (1 << 11) - 1);
    // The honest absence.
    assert_eq!(bucket_bounded_bounds(&fold_self_cost(&[])), None);
}

/// The empty fold is the honest zero row (the caller renders
/// absence from the sample count, never a fabricated measurement).
#[test]
fn fold_of_no_cpus_is_the_honest_zero() {
    let folded = fold_self_cost(&[]);
    assert_eq!(folded, SelfCostFolded::default());
}

/// The text surface's nanosecond ladder: ms past a millisecond, us
/// past a microsecond, raw ns below — the three tiers the render
/// labels ride.
#[test]
fn format_ns_ladder_is_honest() {
    assert_eq!(format_ns(42), "42ns");
    assert_eq!(format_ns(999), "999ns");
    assert_eq!(format_ns(1_000), "1.0us");
    assert_eq!(format_ns(2_048), "2.0us");
    assert_eq!(format_ns(1_000_000), "1.0ms");
    assert_eq!(format_ns(12_345_678), "12.3ms");
}
