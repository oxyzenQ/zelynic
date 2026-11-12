// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram's userspace twin (night-frontier-2B, schema
//! v34): the HistRowRaw layout mirror (the kernel's hist::HistRow —
//! ebpf/src/hist.rs — hand-copied under the schema pin, the
//! LimiterStatsRaw discipline: a repr(C) all-u64 row whose value
//! contract aya::Pod requires for a BPF map value) and the quantile
//! math the depth surface computes from the buckets. Pure: no aya
//! types beyond the Pod impl, no crate paths — the rootless pins in
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

/// One cgroup's distribution row, the mirror of ebpf/src/hist.rs's
/// HistRow: two 32-bucket log2 halves back to back, 512 bytes. The
/// kernel takes cross-CPU atomic adds into these words (the
/// share-word discipline); the userspace read is one 512-byte map
/// copy — a half can lag the other by an in-flight sample, the
/// sampling resolution's own coarseness.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(align(8))]
pub struct HistRowRaw {
    /// Packet-size distribution, log2 of bytes (bucket b covers
    /// [2^b, 2^(b+1)) bytes).
    pub size: [u64; HIST_BUCKETS],
    /// TCP srtt distribution, log2 of microseconds (the RTT lane's
    /// harvest — sockets the lane never owned stay unrecorded).
    pub srtt: [u64; HIST_BUCKETS],
}

const _: () = assert!(core::mem::size_of::<HistRowRaw>() == 512);
// SAFETY: all-u64 #[repr(C)] arrays — every bit pattern is a valid
// value, the same class the PolicyRaw/RateRingRaw mirrors ride.
unsafe impl aya::Pod for HistRowRaw {}

/// The bucket's lower bound (2^b) — the quantile read reports it and
/// the render labels with it; the true value lives in
/// [2^b, 2^(b+1)), the log2 resolution the surface documents.
pub fn bucket_lower_bound(b: usize) -> u64 {
    1u64 << b
}

/// Total recorded samples across one half.
pub fn samples(buckets: &[u64; HIST_BUCKETS]) -> u64 {
    buckets.iter().sum()
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
