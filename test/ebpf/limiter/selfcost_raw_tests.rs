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
    // v36: 256 (the 32 buckets) + 24 (the exact aggregates — the
    // count rides no word, sum(buckets) IS the count).
    assert_eq!(core::mem::size_of::<SelfCostRowRaw>(), 280);
}

/// The fold law's arithmetic: buckets and sums add across CPUs, the
/// max takes the largest per-CPU high-water.
#[test]
fn fold_adds_buckets_sums_and_max() {
    let mut a = SelfCostRowRaw::default();
    a.buckets[5] = 3;
    a.buckets[9] = 1;
    a.sum_ns = 1_000;
    a.max_ns = 900;
    let mut b = SelfCostRowRaw::default();
    b.buckets[5] = 2;
    b.buckets[12] = 4;
    b.sum_ns = 2_500;
    b.max_ns = 1_800;
    let folded = fold_self_cost(&[a, b]);
    assert_eq!(folded.buckets[5], 5);
    assert_eq!(folded.buckets[9], 1);
    assert_eq!(folded.buckets[12], 4);
    assert_eq!(folded.sum_ns, 3_500);
    assert_eq!(folded.max_ns, 1_800);
    assert_eq!(self_cost_samples(&folded), 10);
}

/// The min fold's sentinel law: a CPU that never sampled carries 0
/// ("no min yet") and must never drag the folded minimum to a zero
/// cost that never happened.
#[test]
fn fold_skips_unsampled_cpus_for_the_min() {
    let a = SelfCostRowRaw {
        min_ns: 4_000,
        ..SelfCostRowRaw::default()
    };
    let b = SelfCostRowRaw::default(); // never sampled: min 0
    let folded = fold_self_cost(&[a, b]);
    assert_eq!(
        folded.min_ns, 4_000,
        "an unsampled CPU fabricated a zero min"
    );
    let c = SelfCostRowRaw {
        min_ns: 2_500,
        ..SelfCostRowRaw::default()
    };
    let folded = fold_self_cost(&[a, b, c]);
    assert_eq!(folded.min_ns, 2_500, "the smallest real min must win");
    // The honest absence: no CPU sampled, the fold answers the
    // sentinel, and the JSON layer renders absence — never a zero.
    let empty = fold_self_cost(&[SelfCostRowRaw::default(), SelfCostRowRaw::default()]);
    assert_eq!(empty.min_ns, 0);
    assert_eq!(self_cost_samples(&empty), 0);
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
