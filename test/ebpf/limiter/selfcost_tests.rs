// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z6: rootless pins for the mirror's pure core
//! (ebpf/src/selfcost.rs — the same file the BPF object builds). The
//! hist_tests.rs discipline: the ladder's bounds and exact
//! boundaries, the row's size law, and the record law's four
//! contracts (the buckets ARE the count, the exact sum, the
//! 0-sentinel min, the max ratchet).

// The production arithmetic itself, compiled into this test module:
// the SAME file the BPF object builds. pub(super) so a sibling pin
// module reuses THIS copy (one inclusion of selfcost.rs per test
// binary — the duplicate-mod lint clippy -D warnings rightly rejects
// two).
#[path = "../../../ebpf/src/selfcost.rs"]
pub(super) mod ebpf_selfcost;

use self::ebpf_selfcost::{SELF_COST_BUCKETS, SelfCostRow, cost_bucket, cost_record};

/// The row's layout law: 32 buckets plus the three exact-aggregate
/// words, all u64 — 280 bytes, the shape the schema pin and the
/// userspace twin both hold.
#[test]
fn row_size_is_pinned() {
    assert_eq!(core::mem::size_of::<SelfCostRow>(), 280);
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
    assert_eq!(row.min_ns, 0);
    assert_eq!(row.max_ns, 0);

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
    // The 0-sentinel min: the true minimum of the sampled set.
    assert_eq!(row.min_ns, 3);
    // The max ratchet: the true maximum.
    assert_eq!(row.max_ns, 65_537);
}

/// The min replace law's sentinel: a real sample always lands on a
/// fresh row (0 = "no min yet"), and the min only goes DOWN — the
/// replace pair never raises it.
#[test]
fn cost_record_min_never_rises() {
    let mut row = SelfCostRow::default();
    cost_record(&mut row, 5_000);
    assert_eq!(row.min_ns, 5_000);
    cost_record(&mut row, 9_000);
    assert_eq!(row.min_ns, 5_000, "the min rose — the replace law broke");
    cost_record(&mut row, 1);
    assert_eq!(row.min_ns, 1);
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
