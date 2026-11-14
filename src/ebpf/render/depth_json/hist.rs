// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram block's JSON projection (night-frontier-2B;
//! the Z1 depth pack, schema v35): the structs and the builders the
//! `histogram` target key carries. Split whole from depth_json/mod.rs
//! at night-frontier-Z2 (the sibling-split lineage — one file per
//! contract; the 600-line LOC law the split serves, a pure move: the
//! structs, the docs, and the builders ride verbatim, the wire shape
//! byte-identical).

use std::collections::HashMap;

use crate::ebpf::connections::CgroupConnections;
use crate::ebpf::limiter::hist::{HIST_SAMPLE_SHIFT, HistRowRaw, mean, quantile_permille, samples};
use crate::ebpf::render::hist_section::HistSection;

use super::hist_tail;

/// One half's stats as JSON (night-frontier-2B; Z1, schema v35):
/// the 32 log2 bucket counts (bucket b covers [2^b, 2^(b+1)) of the
/// half's unit) and the bucket-bounded quantiles (the LOWER bound of
/// the first bucket whose cumulative count reaches the quantile —
/// null while the half holds no samples), then the Z1 exact
/// aggregates: sum/min/max are the kernel's own words (the bounds
/// approximate, these ARE — the sampled set's exact mass; `count`
/// derives from the buckets, the one source), mean the sum's honest
/// division.
#[derive(Debug, Clone)]
pub struct HistStatsJson {
    pub samples: u64,
    pub buckets: Vec<u64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub p99: Option<u64>,
    pub count: u64,
    pub sum: u64,
    pub min: u64,
    pub max: u64,
    pub mean: Option<u64>,
}

/// One direction's histogram row as JSON: the size half plus the
/// srtt half, each independently null (the srtt half of a cgroup the
/// RTT lane never owned is absence, not zero), plus the Z1 tail
/// story list (empty while the kernel kept no worst-by-size slot).
#[derive(Debug, Clone)]
pub struct HistHalfJson {
    pub size: Option<HistStatsJson>,
    pub srtt: Option<HistStatsJson>,
    pub tail: Vec<TailJson>,
}

/// One tail story slot as JSON (night-frontier-Z1, schema v35):
/// when, how big, what RTT (None = unmeasured), which socket (the
/// raw bpf cookie) and the endpoint label the walk's census
/// resolves (None = a cookie the walk missed — the raw cookie
/// stays the honest remainder).
#[derive(Debug, Clone)]
pub struct TailJson {
    pub ts_ns: u64,
    pub size: u64,
    pub srtt_us: Option<u64>,
    pub cookie: u64,
    pub endpoint: Option<String>,
}

/// The depth histogram block as JSON (night-frontier-2B; None
/// stays null — the honest absence, the additive rule above).
#[derive(Debug, Clone)]
pub struct HistJson {
    /// The kernel's sampling cadence: one sample per 2^shift packets
    /// per CPU — the divisor a script multiplies bucket counts by
    /// to estimate rates.
    pub sample_shift: u32,
    pub download: Option<HistHalfJson>,
    pub upload: Option<HistHalfJson>,
}

fn hist_stats_json(buckets: &[u64; 32], sum: u64, min: u64, max: u64) -> HistStatsJson {
    // The count is DERIVED — sum(buckets) IS the count (the Z1
    // probe's structural lesson: no second count source).
    let count = samples(buckets);
    HistStatsJson {
        samples: count,
        buckets: buckets.to_vec(),
        p50: quantile_permille(buckets, 500),
        p95: quantile_permille(buckets, 950),
        p99: quantile_permille(buckets, 990),
        count,
        sum,
        min,
        max,
        mean: mean(sum, count),
    }
}

fn hist_half_json(row: &Option<HistRowRaw>, labels: &HashMap<u64, String>) -> Option<HistHalfJson> {
    row.as_ref().map(|r| HistHalfJson {
        size: (samples(&r.size) > 0)
            .then(|| hist_stats_json(&r.size, r.size_sum, r.size_min, r.size_max)),
        srtt: (samples(&r.srtt) > 0)
            .then(|| hist_stats_json(&r.srtt, r.srtt_sum, r.srtt_min, r.srtt_max)),
        tail: hist_tail::tail_json(&r.tail, labels),
    })
}

/// The depth histogram block as JSON (None stays null — the honest
/// absence). The tail labels ride the walk's own census (the Z1
/// cookie-to-endpoint map, no second walk).
pub(super) fn histogram_json(
    section: &Option<HistSection>,
    conns: Option<&CgroupConnections>,
) -> Option<HistJson> {
    section.as_ref().map(|h| {
        let labels = hist_tail::tail_labels(conns);
        HistJson {
            sample_shift: HIST_SAMPLE_SHIFT,
            download: hist_half_json(&h.download, &labels),
            upload: hist_half_json(&h.upload, &labels),
        }
    })
}
