// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The mirror's law file, test-tree resident (night-frontier-Z6):
//! the row shape, the clz bucket law, the record law, and the
//! read-side fold/bounds laws -- every one rootless-pinned by
//! selfcost_core_tests.rs beside it. This is the DEFERRED-BY-VERDICT
//! landing's preserved asset: the laws are proven and ready, and the
//! day a live lane exists (the loader ships func_info so a B2B
//! subprogram gets its own verifier budget, or a walk-cost
//! optimization frees the enforcer's ceiling), the kernel half is a
//! #[path] wiring away -- the whole story rides INNOVATIONS.md's
//! deferred entry and the Z6 audit record.
//!
//! Same discipline as the law files it mirrors (math.rs, hist.rs):
//! zero aya dependencies, standalone in any tree.

/// Bucket count for the cost distribution. log2 scale: bucket b
/// covers [2^b, 2^(b+1)) nanoseconds. 32 buckets reach 2^31 ns
/// (~2.1 seconds) -- far past any single verdict path -- so bucket 31
/// is the honest clamp, never a live reading.
pub const SELF_COST_BUCKETS: usize = 32;

/// The mirror's sampling cadence: record every 2^SHIFT-th packet, per
/// CPU -- the same 1-in-1024 law the estate's samplers carry. (The
/// test-tree compilation has no tick lane reading it -- the pins hold
/// the law; the live lane's kernel half is its reader.)
#[allow(dead_code)]
pub const SELF_COST_SAMPLE_SHIFT: u32 = 10;

/// The tick mask pairing with SELF_COST_SAMPLE_SHIFT: a tick
/// qualifies for recording when `tick & MASK == 0`. (Same posture as
/// SHIFT: the live lane is the reader.)
#[allow(dead_code)]
pub const SELF_COST_SAMPLE_MASK: u64 = (1 << SELF_COST_SAMPLE_SHIFT) - 1;

/// One sampled verdict's cost row, the per-CPU map value the live
/// lane would write (264 bytes, all-u64): the 32 log2 buckets plus
/// the exact mass the bucket bounds can never say. The COUNT rides no
/// word -- sum(buckets) IS the count, the Z1 probe's structural
/// lesson: a second count source can disagree with the buckets it
/// summarizes, and "never a wrong count" is structural, not a hope.
/// The min/max words the first sketch carried are gone -- the live
/// forensic leg measured their replace pairs multiplying the
/// verifier's explored states past the 1M insn walk budget at the
/// wrapper's position -- and the bounds ride the buckets themselves,
/// [`bucket_bounded_bounds`]'s read.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SelfCostRow {
    /// Verdict-path cost distribution, log2 of nanoseconds (bucket b
    /// covers [2^b, 2^(b+1)) ns).
    pub buckets: [u64; SELF_COST_BUCKETS],
    /// The sampled set's exact mass, nanoseconds.
    pub sum_ns: u64,
}

const _: () = assert!(core::mem::size_of::<SelfCostRow>() == 264);

/// The log2 bucket of a cost sample in NANOSECONDS -- the clz law
/// (night-frontier-Z6, the verifier-budget fix the C77 lane found):
/// `floor(log2(ns | 1))` clamped at 31 -- four instructions where the
/// hist.rs ladder spends thirty-two branches. The ladder shape is the
/// RIGHT one for the histogram's row load (the 5.15 lesson: the hooks
/// hand a u32 skb length, so LLVM proves the caps dead and deletes
/// them, and the verifier -- which cannot see LLVM's reasoning --
/// rejected the unbounded index); the mirror's u64 clock delta
/// inverts the story (log2 reaches 63, the clamp CANNOT be proven
/// dead, it stays an instruction the verifier models natively).
/// `| 1` makes zero a legal input (a zero-delta sample is still a
/// sample; it shares bucket 0 with 1 -- a count there beats a clz
/// panic on 0).
#[inline(always)]
pub fn cost_bucket(ns: u64) -> usize {
    let log2 = 63usize - (ns | 1).leading_zeros() as usize;
    if log2 > 31 { 31 } else { log2 }
}

/// The record law, minimal by the verifier's own budget: one bucket
/// add, one exact-mass add -- NO branches (the C77 leg measured the
/// replace pairs multiplying the explored states past the walk budget
/// at this position; the bounds the min/max words approximated ride
/// the buckets themselves, the read-side fold's own read). Plain RMW
/// through the per-CPU map memory, NO atomics owed -- this CPU is the
/// row's only writer between program invocations (the sampler tick's
/// own plain-deref discipline). The bucket index rides an AND mask,
/// not the clamp alone: the 5.15 verifier lesson hist_record's
/// comment carries. Semantically a no-op -- cost_bucket already
/// answers 0..=31.
///
/// SAFETY: the caller hands the per-CPU array's own row pointer
/// (get_ptr_mut on the CPU-local slot) -- stable kernel memory for
/// this invocation, 8-aligned repr(C) fields, this CPU the slot's
/// only writer between invocations. Plain RMW derefs, never aliased
/// with a &mut, never copied out of the map.
#[inline(always)]
pub fn cost_record(row: *mut SelfCostRow, delta_ns: u64) {
    let b = cost_bucket(delta_ns) & (SELF_COST_BUCKETS - 1);
    // SAFETY: the caller hands the per-CPU array's own row pointer
    // (get_ptr_mut on the CPU-local slot) -- stable kernel memory for
    // this invocation, 8-aligned repr(C) fields, this CPU the slot's
    // only writer between invocations. Plain RMW derefs, never
    // aliased with a &mut, never copied out of the map.
    unsafe {
        let bp = core::ptr::addr_of_mut!((*row).buckets[b]);
        *bp = (*bp).wrapping_add(1);
        let sp = core::ptr::addr_of_mut!((*row).sum_ns);
        *sp = (*sp).wrapping_add(delta_ns);
    }
}

/// One CPU's cost row as the userspace mirror would carry it (the
/// read-side shape the fold and the bounds read over -- the twin of
/// the kernel row, the HistRowRaw discipline).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SelfCostRowRaw {
    pub buckets: [u64; SELF_COST_BUCKETS],
    pub sum_ns: u64,
}

/// The cross-CPU fold law: buckets and sums ADD across CPUs -- no
/// other word exists to fold (the bounds ride the folded buckets
/// themselves, [`bucket_bounded_bounds`]'s read -- the same
/// bucket-bounded honesty every quantile in the estate carries).
pub fn fold_self_cost(rows: &[SelfCostRowRaw]) -> SelfCostRowRaw {
    let mut folded = SelfCostRowRaw::default();
    for row in rows {
        for (dst, src) in folded.buckets.iter_mut().zip(row.buckets.iter()) {
            *dst = dst.wrapping_add(*src);
        }
        folded.sum_ns = folded.sum_ns.wrapping_add(row.sum_ns);
    }
    folded
}

/// Total recorded samples across the folded row -- sum(buckets) IS
/// the count (the Z1 structural law; no second count source exists).
pub fn self_cost_samples(folded: &SelfCostRowRaw) -> u64 {
    folded.buckets.iter().sum()
}

/// The bucket-bounded bounds read (the min/max words' honest
/// successor): the smallest sampled cost is AT LEAST the first
/// nonempty bucket's lower bound, the largest is BELOW the last
/// nonempty bucket's upper bound -- the log2 resolution's own shape,
/// the same lower-bound law the quantiles print. None on an empty
/// fold: the honest absence, never a zero dressed as a measurement.
pub fn bucket_bounded_bounds(folded: &SelfCostRowRaw) -> Option<(u64, u64)> {
    let first = folded.buckets.iter().position(|&c| c > 0)?;
    let last = folded.buckets.iter().rposition(|&c| c > 0)?;
    Some((1u64 << first, (1u64 << (last + 1)) - 1))
}

/// The nanosecond figure's human form (the text surface's read): ms
/// past a millisecond, us past a microsecond, raw ns below -- the
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
