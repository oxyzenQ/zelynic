// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Rootless pins for the depth histogram's math (night-frontier-2B):
//! the log2 bucket law both halves ride, the sampler cadence's
//! constants, and the row shape — the SAME file the kernel compiles
//! (ebpf/src/hist.rs, the math.rs discipline: one copy, #[path]
//! wired into both trees), so a kernel-side drift breaks these pins
//! before any binary ships.

#[path = "../../../ebpf/src/hist.rs"]
mod hist;

use hist::{HIST_BUCKETS, HIST_SAMPLE_MASK, HIST_SAMPLE_SHIFT, HistRow, size_bucket, srtt_bucket};

#[test]
fn size_bucket_is_ilog2() {
    assert_eq!(size_bucket(0), 0);
    assert_eq!(size_bucket(1), 0);
    assert_eq!(size_bucket(2), 1);
    assert_eq!(size_bucket(3), 1);
    assert_eq!(size_bucket(4), 2);
    assert_eq!(size_bucket(1500), 10); // the classic MTU packet
    assert_eq!(size_bucket(9000), 13); // jumbo
    assert_eq!(size_bucket(65_535), 15); // the full-GSO skb class
    assert_eq!(size_bucket(1 << 31), 31); // the cap's own edge
    assert_eq!(size_bucket(u64::MAX), 31); // 63 & 31 — the mask's own answer
    // The wrap law (the verifier-proof doc): inputs past the u32 skb
    // length ALIAS through the mask (ilog2 & 31) instead of
    // clamping — unreachable for any real skb the kernel hands a
    // cgroup_skb hook, pinned so the aliasing shape stays
    // deliberate rather than accidental.
    assert_eq!(size_bucket(1 << 33), 33 & 31);
    assert_eq!(size_bucket((1 << 63) - 1), 62 & 31);
    assert_eq!(size_bucket(u64::MAX), 63 & 31);
}

#[test]
fn srtt_bucket_is_ilog2_in_micros() {
    assert_eq!(srtt_bucket(0), 0); // the unmeasured sentinel
    assert_eq!(srtt_bucket(1), 0);
    assert_eq!(srtt_bucket(999), 9); // sub-millisecond
    assert_eq!(srtt_bucket(1_023), 9); // the [512, 1024) bucket's edge
    assert_eq!(srtt_bucket(1_024), 10); // 1 ms
    assert_eq!(srtt_bucket(1_000_000), 19); // 1 s
    assert_eq!(srtt_bucket(60_000_000), 25); // 1 min
    assert_eq!(srtt_bucket(u64::MAX), 31);
}

#[test]
fn bucket_law_round_trips_through_the_lower_bound() {
    // Bucket b's range is [2^b, 2^(b+1)): the lower bound lands back
    // in bucket b, and the range's LAST value stays in b (the next
    // bucket owns 2^(b+1) itself). The render's labels and the
    // quantile read both lean on this exact contract.
    for b in 0..HIST_BUCKETS {
        let lower = 1u64 << b;
        assert_eq!(size_bucket(lower), b, "lower bound of bucket {b}");
        if b < HIST_BUCKETS - 1 {
            let last = (1u64 << (b + 1)) - 1;
            assert_eq!(size_bucket(last), b, "last value of bucket {b}");
        }
    }
}

#[test]
fn sampler_constants_pair() {
    assert_eq!(HIST_SAMPLE_MASK, (1u64 << HIST_SAMPLE_SHIFT) - 1);
    assert_eq!(HIST_SAMPLE_SHIFT, 10); // 1-in-1024, the task's shape
}

#[test]
fn row_shape_is_the_schema_pin() {
    // 512 bytes: two 32-bucket u64 halves back to back — the layout
    // the userspace HistRowRaw mirror hand-copies under schema v34.
    assert_eq!(HIST_BUCKETS, 32);
    assert_eq!(core::mem::size_of::<HistRow>(), 512);
    let row = HistRow::default();
    assert!(row.size.iter().all(|&c| c == 0));
    assert!(row.srtt.iter().all(|&c| c == 0));
}
