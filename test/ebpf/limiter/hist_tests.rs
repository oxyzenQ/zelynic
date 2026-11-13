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

use hist::{
    HIST_BUCKETS, HIST_SAMPLE_MASK, HIST_SAMPLE_SHIFT, HIST_TAIL, HistRow, agg_max_word,
    agg_min_word, size_bucket, srtt_bucket, tail_update,
};

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
    assert_eq!(size_bucket(1 << 33), 31); // clamped — past the u32 skb world
    assert_eq!(size_bucket((1 << 63) - 1), 31);
    assert_eq!(size_bucket(u64::MAX), 31);
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
    assert_eq!(srtt_bucket(1 << 40), 31); // clamped — past any real RTT
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
    // 832 bytes (v35): the two 32-bucket u64 halves (512) + the eight
    // exact-aggregate words (64) + the eight tail story slots (256) —
    // the layout the userspace HistRowRaw mirror hand-copies under
    // schema v35.
    assert_eq!(HIST_BUCKETS, 32);
    assert_eq!(HIST_TAIL, 8);
    assert_eq!(core::mem::size_of::<HistRow>(), 832);
    let row = HistRow::default();
    assert!(row.size.iter().all(|&c| c == 0));
    assert!(row.srtt.iter().all(|&c| c == 0));
}

// night-frontier-Z1 (schema v35): the write-side words' laws, driven
// over real rows in userspace memory — the same arithmetic the BPF
// program runs against map memory.
#[test]
fn agg_min_word_is_the_sentinel_aware_cas_min() {
    let mut row = HistRow::default();
    let word = core::ptr::addr_of_mut!(row.size_min);
    // The fresh row's 0-sentinel loses to the first real sample.
    agg_min_word(word, 1500);
    assert_eq!(row.size_min, 1500);
    // A tighter sample replaces; a looser one cannot.
    agg_min_word(word, 64);
    assert_eq!(row.size_min, 64);
    agg_min_word(word, 9000);
    assert_eq!(row.size_min, 64);
    // A true zero-length sample would store 0 — but the record site
    // skips the mass words for it (the doc's own law).
    agg_min_word(word, 0);
    assert_eq!(row.size_min, 0, "0 is the sentinel, 0 is also the min");
}

#[test]
fn agg_max_word_is_the_plain_cas_max() {
    let mut row = HistRow::default();
    let word = core::ptr::addr_of_mut!(row.srtt_max);
    agg_max_word(word, 40_200);
    assert_eq!(row.srtt_max, 40_200);
    agg_max_word(word, 14_600);
    assert_eq!(row.srtt_max, 40_200, "a smaller sample cannot lower max");
    agg_max_word(word, 199_000);
    assert_eq!(row.srtt_max, 199_000);
    agg_max_word(word, 0);
    assert_eq!(row.srtt_max, 199_000);
}

#[test]
fn tail_update_fills_the_weakest_slot_strictly() {
    let mut row = HistRow::default();
    // The first eight samples fill the empty slots (ts 0 always
    // loses to a real sample).
    for i in 0..8u64 {
        tail_update(&mut row, 1000 + i, 19_000 + i, 100 + i, 5_000 + i);
    }
    assert_eq!(row.tail.iter().filter(|t| t.ts_ns != 0).count(), 8);
    // An empty-slot scan picks the smallest size: 1000 (slot 0).
    // A sample not beating the weakest slot (strictly) stays out.
    tail_update(&mut row, 999, 0, 999, 6_000);
    assert!(
        row.tail.iter().all(|t| t.size != 999),
        "999 does not beat the weakest (1000)"
    );
    // A sample beating the weakest replaces THAT slot, fields and all.
    tail_update(&mut row, 50_000, 21_000, 777, 7_000);
    let slot = row
        .tail
        .iter()
        .find(|t| t.size == 50_000)
        .expect("the new worst landed");
    assert_eq!(slot.srtt_us, 21_000);
    assert_eq!(slot.cookie, 777);
    assert_eq!(slot.ts_ns, 7_000);
    // The replaced slot is the old weakest (size 1000) — the tail now
    // holds sizes 1001..1007 plus 50_000.
    let mut sizes: Vec<u64> = row.tail.iter().map(|t| t.size).collect();
    sizes.sort_unstable();
    assert_eq!(sizes[0], 1001, "the weakest (1000) was replaced");
    assert_eq!(sizes[7], 50_000, "the new worst rides");
    // A zero-length skb writes no story (no mass, no slot).
    tail_update(&mut row, 0, 19_000, 123, 8_000);
    assert!(row.tail.iter().all(|t| t.cookie != 123));
}
