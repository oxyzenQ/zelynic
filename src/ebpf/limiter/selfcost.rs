// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The mirror's userspace twin (night-frontier-Z6, schema v36): the
//! SelfCostRowRaw layout mirror (the kernel's selfcost::SelfCostRow —
//! ebpf/src/selfcost.rs — hand-copied under the schema pin, the
//! HistRowRaw discipline: a repr(C) all-u64 row whose value contract
//! aya::Pod requires for a BPF map value) and the read-side math the
//! depth surface computes from the PER-CPU row: the cross-CPU fold
//! law, the bucket-bounded quantiles (the hist twin's own ladder
//! read), and the exact aggregates. Pure: no aya types beyond the Pod
//! impl, no crate paths — the rootless pins in
//! test/ebpf/limiter/selfcost_tests.rs compile this exact file beside
//! the kernel core, so a mirror drift breaks the pins before any
//! binary ships.

/// The kernel's SELF_COST_BUCKETS (ebpf/src/selfcost.rs) — the schema
/// pin keeps the two in lockstep (the row-shape pins assert both).
pub const SELF_COST_BUCKETS: usize = 32;

/// The kernel's sampling cadence (hist::HIST_SAMPLE_SHIFT — the
/// mirror rides the depth histogram's own 1-in-1024 per-CPU tick; one
/// tick decision, two consumers). The JSON surface reports it
/// (`sample_shift`) so a script can turn sample counts into packet
/// counts.
pub const SELF_COST_SAMPLE_SHIFT: u32 = 10;

/// One CPU's cost row, the mirror of ebpf/src/selfcost.rs's
/// SelfCostRow (v36): the 32 log2 buckets of the verdict path's wall
/// time in nanoseconds plus the exact mass (the COUNT rides no word
/// — the buckets ARE the count, the Z1 structural law; the min/max
/// words the first sketch carried are gone — the C77 live leg
/// measured their replace pairs multiplying the verifier's explored
/// states past the walk budget at the wrapper's position, and the
/// bounds ride the buckets themselves, the userspace fold's own
/// read). 264 bytes. The kernel writes plain RMW through the per-CPU
/// slot (no atomics owed — per-CPU isolation); the userspace read is
/// one 264-byte-per-CPU map copy, folded by [`fold_self_cost`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(align(8))]
pub struct SelfCostRowRaw {
    /// Verdict-path cost distribution, log2 of nanoseconds (bucket b
    /// covers [2^b, 2^(b+1)) ns).
    pub buckets: [u64; SELF_COST_BUCKETS],
    /// The sampled set's exact mass, nanoseconds.
    pub sum_ns: u64,
}

const _: () = assert!(core::mem::size_of::<SelfCostRowRaw>() == 264);
// SAFETY: all-u64 #[repr(C)] arrays — every bit pattern is a valid
// value, the same class the HistRowRaw/PolicyRaw mirrors ride.
unsafe impl aya::Pod for SelfCostRowRaw {}

/// The folded row the depth surface renders: every per-CPU row folded
/// into one machine-wide view (the depth histogram's own machine-wide
/// posture — the tax is the enforcer's, not a CPU's or a direction's).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SelfCostFolded {
    /// The folded bucket counts: bucket b carries the machine-wide
    /// sample count of costs in [2^b, 2^(b+1)) ns.
    pub buckets: [u64; SELF_COST_BUCKETS],
    /// The folded exact mass, nanoseconds (the per-CPU sums added).
    pub sum_ns: u64,
}

/// The cross-CPU fold law: buckets and sums ADD across CPUs — no
/// other word exists to fold (the min/max bounds ride the folded
/// buckets themselves, [`bucket_bounded_bounds`]'s read — the same
/// bucket-bounded honesty every quantile in this estate carries).
pub fn fold_self_cost(rows: &[SelfCostRowRaw]) -> SelfCostFolded {
    let mut folded = SelfCostFolded::default();
    for row in rows {
        for (dst, src) in folded.buckets.iter_mut().zip(row.buckets.iter()) {
            *dst = dst.wrapping_add(*src);
        }
        folded.sum_ns = folded.sum_ns.wrapping_add(row.sum_ns);
    }
    folded
}

/// The bucket-bounded bounds read (the min/max words' honest
/// successor): the smallest sampled cost is AT LEAST the first
/// nonempty bucket's lower bound, the largest is BELOW the last
/// nonempty bucket's upper bound — the log2 resolution's own shape,
/// the same lower-bound law the quantiles print. None on an empty
/// fold: the honest absence, never a zero dressed as a measurement.
pub fn bucket_bounded_bounds(folded: &SelfCostFolded) -> Option<(u64, u64)> {
    let first = folded.buckets.iter().position(|&c| c > 0)?;
    let last = folded.buckets.iter().rposition(|&c| c > 0)?;
    Some((1u64 << first, (1u64 << (last + 1)) - 1))
}

/// Total recorded samples across the folded row — sum(buckets) IS the
/// count (the Z1 structural law; no second count source exists).
pub fn self_cost_samples(folded: &SelfCostFolded) -> u64 {
    folded.buckets.iter().sum()
}

/// The nanosecond figure's human form (the text surface's read): ms
/// past a millisecond, us past a microsecond, raw ns below — the
/// three-tier ladder the render labels ride. Quantile bounds carry
/// the >= prefix at the call site (the bucket-bounded read's own
/// honesty); the mean is exact, so its form is a plain figure.
pub fn format_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{ns}ns")
    }
}

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/selfcost_raw_tests.rs"]
mod raw_pins;
