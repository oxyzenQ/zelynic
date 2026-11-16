// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth report's histogram section (night-frontier-2B, schema
//! v34) — split from report.rs at the 600-line law (the depth_json
//! sibling-split lineage): the section's struct, its one-line read,
//! and the render push live here; report.rs composes them.

use crate::ebpf::limiter::hist::{
    HIST_BUCKETS, HistRowRaw, mean, quantile_permille, samples, tail_entries,
};
use crate::ebpf::limiter::selfcost::{SelfCostFolded, format_ns, self_cost_samples};
use crate::ebpf::limiter::{format_bytes, format_count};

use super::format_srtt_lower_bound;
use super::report::kv;

/// One depth report's histogram rows (night-frontier-2B): the raw
/// 32-bucket log2 halves as the kernel recorded them; the render
/// and the JSON projection derive the quantiles from the buckets
/// (the bucket-bounded read — a value in [2^b, 2^(b+1))).
#[derive(Debug, Clone)]
pub struct HistSection {
    pub download: Option<HistRowRaw>,
    pub upload: Option<HistRowRaw>,
}

/// The histogram half's one-line read (night-frontier-2B; the Z1
/// depth pack, schema v35): the sample count, the exact mean the
/// kernel's sum/count words carry (the one figure the bucket bounds
/// can never say), the worst tail entry's size when the kernel kept
/// a story slot, and the bucket-bounded p50/p95/p99 for both metric
/// halves. Bytes ride format_bytes, srtt microseconds ride
/// format_srtt_lower_bound (the sub-second-honest ladder — the ≥
/// prefix stays a true lower bound at every tier, the "0s" lie
/// healed). The srtt half renders only when the RTT lane's sockets
/// recorded — a half with zero samples is the honest absence, never
/// a "0" dressed as a measurement. The quantile is the bucket's
/// LOWER bound: the true value lives in [2^b, 2^(b+1)), the log2
/// resolution the JSON documents and the render's ≥ prefix admits.
pub(crate) fn hist_half_sentence(label: &str, row: &HistRowRaw) -> String {
    let fmt_q =
        |buckets: &[u64; HIST_BUCKETS], p: u64, unit: fn(u64) -> String| -> Option<String> {
            quantile_permille(buckets, p).map(|v| format!("p{} ≥{}", p / 10, unit(v)))
        };
    let mut bits: Vec<String> = Vec::new();
    // The Z1 exact mean (the sampled set's own arithmetic mean) and
    // the worst story slot's mass — the two figures the log2 buckets
    // approximate but never say.
    if let Some(m) = mean(row.size_sum, samples(&row.size)) {
        bits.push(format!("mean {}", format_bytes(m)));
    }
    if let Some(worst) = tail_entries(&row.tail).iter().map(|t| t.size).max() {
        bits.push(format!("worst {}", format_bytes(worst)));
    }
    let size: Vec<String> = [500, 950, 990]
        .iter()
        .filter_map(|&p| fmt_q(&row.size, p, |v| format_bytes(v).to_string()))
        .collect();
    if !size.is_empty() {
        bits.push(format!("size {}", size.join(" ")));
    }
    let srtt: Vec<String> = [500, 950, 990]
        .iter()
        .filter_map(|&p| fmt_q(&row.srtt, p, format_srtt_lower_bound))
        .collect();
    if !srtt.is_empty() {
        bits.push(format!("srtt {}", srtt.join(" ")));
    }
    let quantiles = if bits.is_empty() {
        String::new()
    } else {
        format!(" — {}", bits.join(" · "))
    };
    format!(
        "{label}, {} samples{}",
        format_count(samples(&row.size)),
        quantiles
    )
}

/// Push the histogram lines (night-frontier-2B): one kv row per
/// direction with samples — the log2 buckets the kernel took at
/// 1/1024 per CPU, read as the bucket-bounded quantiles (a value in
/// [2^b, 2^(b+1)), the lower bound reported). Absent = no samples
/// yet (or a pre-v34 pin), the honest absence — never a zero row
/// dressed as data.
pub(crate) fn push_hist_lines(lines: &mut Vec<String>, histogram: &Option<HistSection>) {
    if let Some(h) = histogram {
        for (label, row) in [("download", &h.download), ("upload", &h.upload)] {
            if let Some(row) = row {
                lines.push(kv("histogram", &hist_half_sentence(label, row)));
            }
        }
    }
}

/// The mirror's one-line read (night-frontier-Z6, schema v36): the
/// sampled count, the exact mean the kernel's sum/count law carries,
/// and the bucket-bounded p50/p95/p99 of the verdict path's wall
/// time — the >= prefix stays a true lower bound at every tier, the
/// same honesty the histogram rows print. The tax is the enforcer's
/// own; both directions pooled.
pub fn self_cost_sentence(folded: &SelfCostFolded) -> String {
    let count = self_cost_samples(folded);
    let mut bits: Vec<String> = Vec::new();
    if let Some(m) = mean(folded.sum_ns, count) {
        bits.push(format!("mean {}", format_ns(m)));
    }
    let quantiles: Vec<String> = [500, 950, 990]
        .iter()
        .filter_map(|&p| {
            quantile_permille(&folded.buckets, p).map(|v| format!("p{} ≥{}", p / 10, format_ns(v)))
        })
        .collect();
    if !quantiles.is_empty() {
        bits.push(quantiles.join(" "));
    }
    let detail = if bits.is_empty() {
        String::new()
    } else {
        format!(" — {}", bits.join(" · "))
    };
    format!("{count} samples{detail}",)
}

/// Push the self-cost line (night-frontier-Z6): one kv row under the
/// machine-scope block — the enforcer's own per-packet tax, sampled
/// at 1/1024 per CPU and folded across them. Absent = no packet has
/// sampled yet (or a pre-v36 pin), the honest absence — never a zero
/// row dressed as data.
pub fn push_self_cost_lines(lines: &mut Vec<String>, self_cost: &Option<SelfCostFolded>) {
    if let Some(folded) = self_cost {
        lines.push(kv("self cost", &self_cost_sentence(folded)));
    }
}
