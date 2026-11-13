// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Rootless pins for the depth histogram's userspace twin
//! (night-frontier-2B): the quantile read's bucket-bounded law and
//! the mirror's layout — compiled INSIDE the production module (the
//! schema_sync_pin pattern), so the pins ride the same file the
//! render and the JSON projection call.

use super::*;

#[test]
fn mirror_layout_is_the_schema_pin() {
    assert_eq!(HIST_BUCKETS, 32);
    assert_eq!(HIST_TAIL, 8);
    // v35: 512 (the two halves) + 48 (the exact aggregates — the
    // count rides no word) + 256 (the eight tail story slots).
    assert_eq!(core::mem::size_of::<HistRowRaw>(), 816);
    assert_eq!(core::mem::size_of::<HistTailRaw>(), 32);
}

#[test]
fn quantile_read_is_the_cumulative_bucket_bound() {
    // One bucket holds everything: every quantile lands on its
    // lower bound (2^10 = 1024 for bucket 10).
    let mut b = [0u64; HIST_BUCKETS];
    b[10] = 7;
    assert_eq!(quantile_permille(&b, 500), Some(1 << 10));
    assert_eq!(quantile_permille(&b, 950), Some(1 << 10));
    assert_eq!(quantile_permille(&b, 990), Some(1 << 10));
}

#[test]
fn quantile_read_walks_the_cumulative_law() {
    // 500 in bucket 9, 500 in bucket 13: p50 crosses inside bucket
    // 9's cumulative, p95/p99 land in bucket 13.
    let mut b = [0u64; HIST_BUCKETS];
    b[9] = 500;
    b[13] = 500;
    assert_eq!(quantile_permille(&b, 500), Some(1 << 9));
    assert_eq!(quantile_permille(&b, 950), Some(1 << 13));
    assert_eq!(quantile_permille(&b, 990), Some(1 << 13));
}

#[test]
fn quantile_read_is_exact_at_the_boundary() {
    // Exactly 950/1000 accumulated at bucket 11: the >= law lands
    // on the bucket that COMPLETED the quantile, never one past it.
    let mut b = [0u64; HIST_BUCKETS];
    b[8] = 900;
    b[11] = 50;
    // cum after 8: 900 (90%) < 950; after 11: 950 (95%) == 950.
    assert_eq!(quantile_permille(&b, 950), Some(1 << 11));
}

#[test]
fn quantile_read_answers_none_on_an_empty_half() {
    let b = [0u64; HIST_BUCKETS];
    assert_eq!(quantile_permille(&b, 500), None);
    assert_eq!(samples(&b), 0);
}

// night-frontier-Z1 (schema v35): the exact mean and the tail story
// read — the figures the bucket bounds approximate but never say.
#[test]
fn mean_is_the_exact_division_or_absent() {
    assert_eq!(mean(0, 0), None);
    assert_eq!(mean(1000, 4), Some(250));
    assert_eq!(
        mean(1001, 4),
        Some(250),
        "the truncating division is the figure the words carry"
    );
}

#[test]
fn tail_read_answers_only_the_live_slots() {
    let mut tail = [HistTailRaw::default(); HIST_TAIL];
    assert!(tail_entries(&tail).is_empty(), "a fresh row keeps no story");
    tail[3] = HistTailRaw {
        ts_ns: 42,
        size: 1500,
        srtt_us: 0,
        cookie: 7,
    };
    let live = tail_entries(&tail);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].size, 1500);
    assert_eq!(live[0].cookie, 7);
    assert_eq!(live[0].srtt_us, 0, "the unmeasured sentinel rides raw");
}
