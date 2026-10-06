// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the atomic-operation family (the DRR token
// primitives, the draw/gen stamps, the stats booking pair, the
// credit refill) moved out of math.rs at the 600-line cap —
// nested #[path], re-exported through math so every consumer
// (the bin root, the rootless test tree) keeps resolving
// math::tokens_cas and its siblings. Core-only, like the parent.
//
// ── The DRR atomic primitive set (NIGHT-upgrade-charger-core-1c) ─────
//
// The access discipline above (volatile loads/stores, atomic RMW
// views) exists to serve enforce()'s field pointers; the DRR
// datapath (drr_flow) needs the same discipline over the SAME
// fields, so the primitives are exported with one helper per
// operation — the DRR pins hold their semantics rootlessly (the
// userspace tree compiles this file).

/// Read a bucket's token count (the volatile single-instruction
/// load, the READ_ONCE discipline).
// NIGHT-improve-44: the parent's types and its private
// RMW view — super:: paths resolve identically in the bin
// root and the rootless test tree's inclusion.
use core::sync::atomic::Ordering;

use super::*;
#[inline(always)]
pub fn tokens_read(bkt: &Bucket) -> u64 {
    // SAFETY: the caller hands a live, 8-aligned field of a map value
    // (or a test-tree struct) — the same contract read_once carries.
    unsafe { core::ptr::addr_of!(bkt.tokens).read_volatile() }
}

/// Compare-and-swap a bucket's token count from `observed` to
/// `new`: true when this caller's view won (the sufficiency-verified
/// deduction and the stale-quantum zeroing both ride it).
#[inline(always)]
pub fn tokens_cas(bkt: &mut Bucket, observed: u64, new: u64) -> bool {
    let ptr = core::ptr::addr_of_mut!(bkt.tokens);
    // SAFETY: the same 8-aligned-field contract every rmw_view caller
    // in this file carries.
    rmw_view(ptr)
        .compare_exchange(observed, new, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Atomically add `add` tokens to a bucket (the draw's credit half —
/// the pool's deduction already landed through [`tokens_cas`], so the
/// pair can only under-deliver, never over-deliver: the lost-CAS
/// branch never adds).
#[inline(always)]
pub fn tokens_fetch_add(bkt: &mut Bucket, add: u64) -> u64 {
    let ptr = core::ptr::addr_of_mut!(bkt.tokens);
    // SAFETY: the same contract as tokens_cas.
    rmw_view(ptr).fetch_add(add, Ordering::AcqRel)
}

/// Take the bucket's draw-stamp ownership: CAS the stamp (the
/// last_refill_ns field) from `last` to `now`, true when won — the
/// window-ownership trick re-applied to the DRR draw (one drawer per
/// leaf per timestamp).
#[inline(always)]
pub fn draw_stamp_take(bkt: &mut Bucket, last: u64, now: u64) -> bool {
    let ptr = core::ptr::addr_of_mut!(bkt.last_refill_ns);
    // SAFETY: the same contract as tokens_cas.
    rmw_view(ptr)
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Read the DRR generation stamp (the frac_rem field, unused by the
/// leaf buckets' arithmetic — the DRR belt stores the AMMSP
/// generation a leaf's quanta were drawn under).
#[inline(always)]
pub fn gen_stamp_read(bkt: &Bucket) -> u64 {
    // SAFETY: the same contract as tokens_read.
    unsafe { core::ptr::addr_of!(bkt.frac_rem).read_volatile() }
}

/// Write the DRR generation stamp.
#[inline(always)]
pub fn gen_stamp_write(bkt: &mut Bucket, generation: u64) {
    let ptr = core::ptr::addr_of_mut!(bkt.frac_rem);
    // SAFETY: the same contract as tokens_cas.
    unsafe { ptr.write_volatile(generation) };
}

/// Book one verdict into a stats entry with atomic increments
/// (NIGHT-boost-38: the v6 `+=` lost increments whenever two CPUs
/// enforced the same cgroup concurrently — the ledger undercounted
/// allowed bytes mid-contention, the exact noise the E2E
/// "BPF accounting matches client bytes" rows kept swallowing).
/// Layout-preserving: the u64 counters are mutated in place through
/// the RMW view, the same fields at the same offsets.
/// NIGHT-master-3 (schema v9): the rate-0 BLOCK verdict rides this
/// too — its v5 `+=` under-counted SMP drops (v7's race class).
#[inline(always)]
pub fn book(stats: &mut LimiterStats, allowed: bool, pkt_len: u32) {
    // Field pointers (8-aligned repr(C) offsets: 0, 8, 16, 24 — the
    // size pin above).
    let packets_allowed_ptr = core::ptr::addr_of_mut!(stats.packets_allowed);
    let packets_dropped_ptr = core::ptr::addr_of_mut!(stats.packets_dropped);
    let bytes_allowed_ptr = core::ptr::addr_of_mut!(stats.bytes_allowed);
    let bytes_dropped_ptr = core::ptr::addr_of_mut!(stats.bytes_dropped);
    if allowed {
        rmw_view(packets_allowed_ptr).fetch_add(1, Ordering::Relaxed);
        rmw_view(bytes_allowed_ptr).fetch_add(u64::from(pkt_len), Ordering::Relaxed);
    } else {
        rmw_view(packets_dropped_ptr).fetch_add(1, Ordering::Relaxed);
        rmw_view(bytes_dropped_ptr).fetch_add(u64::from(pkt_len), Ordering::Relaxed);
    }
}

/// Book an ECN rescue into a stats entry (NIGHT-private-research-4,
/// schema v19): the lane already booked this packet as DROPPED — the
/// rescue re-reads the verdict the kernel helper returned and the
/// packet is being DELIVERED, CE-marked — so the ledger must move the
/// booking from the dropped column to the allowed one before any
/// reader counts it. Exactness: the correction subtracts exactly what
/// this CPU's own drop booking added (counters are monotonic u64 and
/// the add already landed, so the subtraction can never underflow),
/// then adds the allowed pair `book` itself would have written. A
/// concurrent reader between the two pairs may transiently see the
/// packet in both columns — the same relaxed-counter class the
/// boost-38 docs own for the window fractions, eventually exact.
///
/// The subtraction rides `fetch_add` of the two's complement, NOT a
/// native fetch_sub: the BPF backend's selection guarantees are
/// proven for the fetch_add/CAS shapes this file already compiles
/// (the AtomicLoad lesson at the top of the file), and a sub node
/// adds an unproven selection for zero benefit — the wrapping add is
/// bit-identical arithmetic on the same counter word.
#[inline(always)]
pub fn book_rescue(stats: &mut LimiterStats, pkt_len: u32) {
    // Field pointers (8-aligned repr(C) offsets: 0, 8, 16, 24 — the
    // size pin above).
    let packets_allowed_ptr = core::ptr::addr_of_mut!(stats.packets_allowed);
    let packets_dropped_ptr = core::ptr::addr_of_mut!(stats.packets_dropped);
    let bytes_allowed_ptr = core::ptr::addr_of_mut!(stats.bytes_allowed);
    let bytes_dropped_ptr = core::ptr::addr_of_mut!(stats.bytes_dropped);
    rmw_view(packets_dropped_ptr).fetch_add(u64::MAX, Ordering::Relaxed);
    rmw_view(bytes_dropped_ptr).fetch_add(u64::from(pkt_len).wrapping_neg(), Ordering::Relaxed);
    rmw_view(packets_allowed_ptr).fetch_add(1, Ordering::Relaxed);
    rmw_view(bytes_allowed_ptr).fetch_add(u64::from(pkt_len), Ordering::Relaxed);
}

/// Pure refill arithmetic for one owned window (NIGHT-boost-38
/// extracted the branch from the old monolithic enforce so the
/// overflow-guard and carry contracts pin independently): returns
/// `(whole_bytes, frac_rem)` for an elapsed window, including the
/// 1-second idle cap, the fill-detect overflow guard, and the v6
/// frac sanitization (`frac_rem >= NS_PER_SEC` reads as empty —
/// hostile or drifted state, never trusted into the accumulation).
///
/// Contract: `rate_bps > 0` and `burst_bytes <= MAX_ENFORCABLE_BURST`
/// (the security-3 trust boundary — guaranteed by every caller; the
/// guard below protects the division for standalone use).
///
///  * fill-detect: once the true refill reaches 2x burst, the bucket
///    caps at burst anyway — skip the multiply, credit burst, reset
///    the fraction (matching the cap branch in enforce). Not an
///    optimization alone but the OVERFLOW GUARD: the exact branch
///    only runs while `elapsed < fill_ns`, and
///    `fill_ns * rate == 2 * burst * NS_PER_SEC` bounds the product
///    by construction.
#[inline(always)]
pub fn refill_credits(
    rate_bps: u64,
    burst_bytes: u64,
    elapsed_ns: u64,
    frac_rem: u64,
) -> (u64, u64) {
    // v6 sanitize: a healthy remainder is always < NS_PER_SEC.
    let healthy_frac = if frac_rem < NS_PER_SEC { frac_rem } else { 0 };
    // Cap elapsed at 1 second to limit burst after idle.
    let mut elapsed = elapsed_ns;
    if elapsed > NS_PER_SEC {
        elapsed = NS_PER_SEC;
    }
    if rate_bps == 0 || elapsed == 0 {
        return (0, healthy_frac);
    }
    let fill_ns = (2 * burst_bytes * NS_PER_SEC) / rate_bps;
    if elapsed >= fill_ns {
        // Refill >= 2x burst: the cap in enforce makes the exact
        // value irrelevant — burst is the answer (the overflow
        // guard; see the function docs).
        return (burst_bytes, 0);
    }
    let product = elapsed * rate_bps;
    let mut whole = product / NS_PER_SEC;
    let mut new_frac = product % NS_PER_SEC;
    // Accumulate the fractional remainder. If it overflows
    // NS_PER_SEC, carry 1 byte into the integer tokens.
    new_frac += healthy_frac;
    if new_frac >= NS_PER_SEC {
        whole += 1;
        new_frac -= NS_PER_SEC;
    }
    (whole, new_frac)
}
