// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram's userspace twin (night-frontier-2B, schema
//! v34; the Z1 depth pack rides v35): the HistRowRaw layout mirror
//! (the kernel's hist::HistRow — ebpf/src/hist.rs — hand-copied
//! under the schema pin, the LimiterStatsRaw discipline: a repr(C)
//! all-u64 row whose value contract aya::Pod requires for a BPF map
//! value) and the read-side math the depth surface computes from the
//! row: the bucket-bounded quantiles, the exact aggregates' mean,
//! and the tail story entries. Pure: no aya types beyond the Pod
//! impl, no crate paths — the rootless pins in
//! test/ebpf/limiter/hist_tests.rs compile this exact file beside
//! the kernel core, so a mirror drift breaks the pins before any
//! binary ships.

/// The kernel's HIST_BUCKETS (ebpf/src/hist.rs) — the schema pin
/// keeps the two in lockstep (the row-shape pins assert both).
pub const HIST_BUCKETS: usize = 32;

/// The kernel's sampling cadence (hist::HIST_SAMPLE_SHIFT) — the
/// JSON surface reports it (`sample_shift`) so a script can turn
/// counts into rates (one sample per 2^shift packets per CPU).
pub const HIST_SAMPLE_SHIFT: u32 = 10;

/// The kernel's tail depth (hist::HIST_TAIL) — the worst-by-size
/// story slots the row carries.
pub const HIST_TAIL: usize = 8;

/// One tail story slot, the mirror of the kernel's hist::HistTail:
/// WHEN (ktime ns, boot-relative monotonic), HOW BIG (skb bytes),
/// WHAT RTT (the socket's recwn word — 0 = the unmeasured sentinel),
/// WHICH socket (the bpf cookie — the walk's ConnectionMap resolves
/// it to an endpoint at render time; 0 = unowned, honest).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct HistTailRaw {
    pub ts_ns: u64,
    pub size: u64,
    pub srtt_us: u64,
    pub cookie: u64,
}

/// One cgroup's distribution row, the mirror of ebpf/src/hist.rs's
/// HistRow (v35): the two 32-bucket log2 halves, the eight exact
/// aggregates (count/sum/min/max per half — the min words ride the
/// 0-sentinel "no min yet", the mass words skip zero-length skbs),
/// then the eight tail story slots (ts_ns 0 = the empty sentinel).
/// 512 + 64 + 256 = 832 bytes. The kernel takes cross-CPU atomic
/// adds into the bucket/count/sum words and bounded CAS into the
/// min/max words; the userspace read is one 832-byte map copy — a
/// half can lag the other by an in-flight sample, the sampling
/// resolution's own coarseness.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(align(8))]
pub struct HistRowRaw {
    /// Packet-size distribution, log2 of bytes (bucket b covers
    /// [2^b, 2^(b+1)) bytes).
    pub size: [u64; HIST_BUCKETS],
    /// TCP srtt distribution, log2 of microseconds (the RTT lane's
    /// harvest — sockets the lane never owned stay unrecorded).
    pub srtt: [u64; HIST_BUCKETS],
    pub size_count: u64,
    pub size_sum: u64,
    pub size_min: u64,
    pub size_max: u64,
    pub srtt_count: u64,
    pub srtt_sum: u64,
    pub srtt_min: u64,
    pub srtt_max: u64,
    pub tail: [HistTailRaw; HIST_TAIL],
}

const _: () = assert!(core::mem::size_of::<HistRowRaw>() == 832);
// SAFETY: all-u64 #[repr(C)] arrays — every bit pattern is a valid
// value, the same class the PolicyRaw/RateRingRaw mirrors ride.
unsafe impl aya::Pod for HistRowRaw {}

/// The bucket's lower bound (2^b) — the quantile read reports it and
/// the render labels with it; the true value lives in [2^b, 2^(b+1)),
/// the log2 resolution the surface documents.
pub fn bucket_lower_bound(b: usize) -> u64 {
    1u64 << b
}

/// Total recorded samples across one half.
pub fn samples(buckets: &[u64; HIST_BUCKETS]) -> u64 {
    buckets.iter().sum()
}

/// The exact set's mean (night-frontier-Z1): sum/count — the exact
/// arithmetic mean of the sampled values, the one figure the bucket
/// bounds can never say. None on an empty set: absence, never a
/// zero dressed as a measurement.
pub fn mean(sum: u64, count: u64) -> Option<u64> {
    (count > 0).then(|| sum / count)
}

/// The row's live tail entries (night-frontier-Z1): the story slots
/// with a timestamp, oldest-preserved order the kernel wrote them
/// in (the slots are NOT sorted — the worst-by-size REPLACEMENT
/// policy overwrites the weakest slot; the read renders what the
/// kernel kept). Empty slots (ts 0) stay out — the honest absence.
pub fn tail_entries(tail: &[HistTailRaw; HIST_TAIL]) -> Vec<&HistTailRaw> {
    tail.iter().filter(|t| t.ts_ns != 0).collect()
}

/// The smallest bucket whose cumulative count reaches
/// `permille`/1000 of the total, reported as the bucket's LOWER
/// bound — the value lives in [2^b, 2^(b+1)), the honest bucket-
/// bounded read (never an interpolated fiction the resolution
/// cannot back). None on an empty half: no samples yet, the caller
/// renders absence, never zero-as-fact. u128 accumulation — a
/// machine-lifetime of u64 counts cannot overflow the product.
pub fn quantile_permille(buckets: &[u64; HIST_BUCKETS], permille: u64) -> Option<u64> {
    let total = samples(buckets);
    if total == 0 {
        return None;
    }
    let mut cum: u128 = 0;
    for (b, &count) in buckets.iter().enumerate() {
        cum += u128::from(count);
        if cum * 1000 >= u128::from(total) * u128::from(permille) {
            return Some(bucket_lower_bound(b));
        }
    }
    None
}

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/hist_raw_tests.rs"]
mod raw_pins;
