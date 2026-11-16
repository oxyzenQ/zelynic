// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The mirror's pure core (night-frontier-Z6, schema v36): the
//! enforcer's own per-packet cost, sampled by the SAME 1-in-1024
//! per-CPU tick the depth histogram rides. The law files' discipline
//! (math.rs, hist.rs): zero aya dependencies, wired into the limiter
//! with #[path] AND into the userspace test tree, so the row shape
//! and the record law carry rootless pins.
//!
//! WHY THIS LANE EXISTS: every limiter in the comparison table
//! prices its efficiency in prose. zelynic prices it in the datapath's
//! own words — the verdict path's wall time, stamped at program entry
//! and closed at the verdict, one ktime pair per SAMPLED packet only
//! (the two reads ride 1 in 1024 packets per CPU; the unlimited fast
//! path's NIGHT-lts-2 two-lookup law is untouched). The measured
//! window starts AFTER the sampler tick itself: the tick is the
//! meter's own cost, not the metered path.

/// Bucket count for the cost distribution. log2 scale, the hist.rs
/// ladder's own shape: bucket b covers [2^b, 2^(b+1)) nanoseconds.
/// 32 buckets reach 2^31 ns (~2.1 seconds) — far past any single
/// verdict path (the fast path is microseconds; the policed path
/// adds a documented constant chain), so bucket 31 is the honest
/// clamp, never a live reading.
pub const SELF_COST_BUCKETS: usize = 32;

/// The mirror's sampling cadence: record every 2^SHIFT-th packet, per
/// CPU — the observer's OWN tick (the depth histogram's tick rides
/// the limiter object; the two objects never share a map), the same
/// 1-in-1024 cadence law the estate's sampler carries.
pub const SELF_COST_SAMPLE_SHIFT: u32 = 10;

/// The tick mask pairing with SELF_COST_SAMPLE_SHIFT: a tick
/// qualifies for recording when `tick & MASK == 0`.
pub const SELF_COST_SAMPLE_MASK: u64 = (1 << SELF_COST_SAMPLE_SHIFT) - 1;

/// One sampled verdict's cost row, the per-CPU map value (264 bytes,
/// all-u64): the 32 log2 buckets plus the exact mass the bucket
/// bounds can never say. The COUNT rides no word — sum(buckets) IS
/// the count, the Z1 probe's structural lesson: a second count
/// source can disagree with the buckets it summarizes, and "never a
/// wrong count" is structural, not a hope. The min/max words the
/// first v36 sketch carried are GONE — the C77 live leg measured
/// their replace pairs multiplying the verifier's explored states at
/// the wrapper's position (the widest state set in the program, past
/// the 1M insn walk budget) and the honest trade is the Z1 law's own
/// shape: the userspace fold derives bucket-bounded min and max from
/// the buckets (the bounds approximate, the mean and the mass are
/// exact), the same bucket-bounded read every quantile in this
/// estate already carries. Per-CPU isolation means NO atomics are
/// owed: this CPU is the row's only writer between program
/// invocations (the sampler tick's own discipline, the plain-RMW
/// shape enforce_helpers rides).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SelfCostRow {
    /// Verdict-path cost distribution, log2 of nanoseconds (bucket b
    /// covers [2^b, 2^(b+1)) ns).
    pub buckets: [u64; SELF_COST_BUCKETS],
    /// The sampled set's exact mass, nanoseconds (plain add — per-CPU
    /// isolation, no atomics owed).
    pub sum_ns: u64,
}

const _: () = assert!(core::mem::size_of::<SelfCostRow>() == 264);

/// The log2 bucket of a cost sample in NANOSECONDS — the clz law
/// (night-frontier-Z6, the verifier-budget fix the C77 lane found):
/// `floor(log2(ns | 1))` clamped at 31, four instructions where the
/// hist.rs ladder spends thirty-two branches. The ladder shape is
/// the RIGHT one for the histogram's row load (the 5.15 lesson: the
/// hooks hand a u32 skb length, so LLVM proves the caps dead and
/// deletes them — the verifier, which cannot see LLVM's reasoning,
/// rejected the unbounded index; straight-line comparisons are the
/// shape nothing can optimize away). The mirror's input is a u64
/// clock delta, where the story inverts: log2 reaches 63, so the
/// clamp CANNOT be proven dead — it stays an instruction the
/// verifier models natively (a bound it accepts on sight), and the
/// 32-branch ladder at the WRAPPER's position multiplied the
/// verifier's explored states against the six-layer verdict path's
/// whole state space — the live C77 leg measured the walk past the
/// 1M insn budget ("BPF program is too large"). `| 1` makes zero a
/// legal input (a zero-delta sample is still a sample; it shares
/// bucket 0 with 1 — a count there beats a clz panic on 0). The
/// semantics are the ladder's own: bucket b covers [2^b, 2^(b+1))
/// ns, bucket 31 the honest clamp — the rootless pins hold the
/// boundary table byte for byte.
#[inline(always)]
pub fn cost_bucket(ns: u64) -> usize {
    let log2 = 63usize - (ns | 1).leading_zeros() as usize;
    if log2 > 31 { 31 } else { log2 }
}

/// The sampled verdict's record (night-frontier-Z6), minimal by the
/// verifier's own budget: one bucket add, one exact-mass add — NO
/// branches (the C77 leg measured the replace pairs multiplying the
/// explored states past the walk budget at this position; the bounds
/// the min/max words approximated ride the buckets themselves, the
/// userspace fold's own read). All plain RMW through the per-CPU map
/// memory, NO atomics owed (this CPU is the row's only writer between
/// invocations; the sampler tick's own plain-deref discipline). The
/// bucket index rides an AND mask, not the clamp alone: the 5.15
/// verifier lesson hist_record's comment carries (an AND with the
/// power-of-two bucket count is a proof the verifier always sees).
/// Semantically a no-op — cost_bucket already answers 0..=31.
///
/// SAFETY: the caller hands the per-CPU array's own row pointer
/// (get_ptr_mut on the CPU-local slot) — stable kernel memory for
/// this invocation, 8-aligned repr(C) fields, this CPU the slot's
/// only writer. Plain derefs, never aliased with a &mut, never
/// copied out of the map.
#[inline(always)]
pub fn cost_record(row: *mut SelfCostRow, delta_ns: u64) {
    let b = cost_bucket(delta_ns) & (SELF_COST_BUCKETS - 1);
    // SAFETY: the caller hands the per-CPU array's own row pointer
    // (get_ptr_mut on the CPU-local slot) — stable kernel memory for
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
