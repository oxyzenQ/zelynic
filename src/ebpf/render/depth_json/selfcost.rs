// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The self-cost block's JSON projection (night-frontier-Z6, schema
//! v36): the struct and the builder the document's `self_cost` key
//! carries — the limiter's own per-packet verdict cost, measured in
//! the datapath it polices. The sibling-split lineage, one file per
//! contract (the 600-line LOC law the split serves).

use crate::ebpf::limiter::hist::{mean, quantile_permille};
use crate::ebpf::limiter::selfcost::{SELF_COST_SAMPLE_SHIFT, SelfCostFolded, self_cost_samples};

/// The mirror's stats as JSON (night-frontier-Z6, schema v36): the
/// sampling cadence (the depth histogram's own shift — one tick
/// decision, two consumers), the 32 log2 bucket counts folded
/// machine-wide (bucket b covers [2^b, 2^(b+1)) nanoseconds of
/// verdict-path wall time), the bucket-bounded quantiles (the LOWER
/// bound of the first bucket whose cumulative count reaches the
/// quantile — null while no sample), and the exact aggregates the
/// kernel's own words carry (sum/min/max/mean — the bounds
/// approximate, these ARE; `count` derives from the buckets, the one
/// source). Additive under the stable v11 contract (scripts
/// predating the field ignore it); null while no packet has sampled —
/// the honest absence, never a zero dressed as a measurement.
#[derive(Debug, Clone)]
pub struct SelfCostJson {
    pub sample_shift: u32,
    pub count: u64,
    pub buckets: Vec<u64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub p99: Option<u64>,
    pub sum_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: Option<u64>,
}

/// The folded per-CPU row as JSON (None stays null — the honest
/// absence; the caller only builds a folded value when the buckets
/// hold samples, and the field law keeps the null the pre-v36 pin
/// and the idle machine both answer).
pub(super) fn self_cost_json(folded: &SelfCostFolded) -> SelfCostJson {
    let count = self_cost_samples(folded);
    SelfCostJson {
        sample_shift: SELF_COST_SAMPLE_SHIFT,
        count,
        buckets: folded.buckets.to_vec(),
        p50: quantile_permille(&folded.buckets, 500),
        p95: quantile_permille(&folded.buckets, 950),
        p99: quantile_permille(&folded.buckets, 990),
        sum_ns: folded.sum_ns,
        min_ns: folded.min_ns,
        max_ns: folded.max_ns,
        mean_ns: mean(folded.sum_ns, count),
    }
}
