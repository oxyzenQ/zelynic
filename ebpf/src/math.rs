// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The zelynic enforcement math, extracted pure (NIGHT-depthbore-1):
// the token-bucket arithmetic that runs inside the BPF program, with
// zero aya/eBPF dependencies so the SAME file compiles into the
// kernel object (ebpf/src/bin/limiter.rs wires it with #[path]) AND
// into the userspace test tree (src/ebpf/limiter/mod.rs wires it the
// same way), where test/ebpf/limiter/math_tests.rs pins it
// rootlessly. Before the extraction this arithmetic was testable
// only through root-run integration — the sharpest knife in the repo
// had no proof harness. The functions are verbatim moves from the
// limiter program; the one behavioral change (the frac_rem
// sanitization, schema v6) is marked in place.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once.

// ---------------------------------------------------------------------------
// Shared layout contract (kept identical to the userspace mirrors:
// PolicyRaw, BucketRaw, LimiterStatsRaw in src/ebpf/limiter/types.rs).
// The compile-time size pins guarantee the layouts can never drift
// silently; the userspace tests assert the third copy.
// ---------------------------------------------------------------------------

/// The BPF-side policy layout; the userspace mirror is `PolicyRaw`
/// in src/ebpf/limiter/types.rs (layout contract). group_id == 0 means
/// "individual" (use cgroup bucket); group_id != 0 means "shared
/// group" (use the group bucket keyed by group_id).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Policy {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
}

/// The BPF-side token-bucket layout, schema v2 (userspace mirror:
/// `BucketRaw` in src/ebpf/limiter/types.rs — the layout contract).
///
/// `frac_rem` tracks the sub-byte fractional remainder from the
/// refill calculation: `(elapsed_ns * rate_bps) % NS_PER_SEC`.
/// Without this, integer division truncates up to ~1 byte per
/// refill, causing 0.5-1% rate error at common rates.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub frac_rem: u64,
}

/// The BPF-side stats layout (userspace mirror: `LimiterStatsRaw`
/// in src/ebpf/limiter/types.rs — the layout contract). Combined
/// download + upload enforcement stats per cgroup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LimiterStats {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

const _: () = assert!(core::mem::size_of::<Policy>() == 24);
const _: () = assert!(core::mem::size_of::<Bucket>() == 24);
const _: () = assert!(core::mem::size_of::<LimiterStats>() == 32);

/// Refill rate math: nanoseconds per second.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Hard ceiling a stored `burst_bytes` may carry INTO the refill
/// math (NIGHT-improve-10 / security-3). The maps are persistent
/// kernel state that outlives any writer: pins survive process exit,
/// and the pin path is writable by any root process. The userspace
/// `default_burst` clamp (100 MB) is a contract, not a guarantee the
/// kernel side may trust — the enforcement boundary sanitizes for
/// itself. The value is the exact mathematical ceiling under which
/// every product `enforce` can form is provably representable in
/// u64: `2 * burst * NS_PER_SEC` (the fill-detect threshold) and
/// `tokens + 2 * burst` (the worst pre-cap sum) both stay in range.
/// A stored burst above the bound is corruption or drift; it is
/// clamped, never honored. Mirrored in userspace as
/// `MAX_ENFORCABLE_BURST` in src/ebpf/limiter/types.rs (layout
/// contract sibling — both sides pin the value in tests).
pub const MAX_ENFORCABLE_BURST: u64 = u64::MAX / (2 * NS_PER_SEC);

/// Refill tokens and enforce. `pol` is the policy, `bkt` the bucket
/// (individual or group), `stats` an optional stats entry (the
/// program passes None when the stats insert failed and keeps
/// enforcing without bookkeeping).
///
/// Fractional remainder tracking keeps the rate precise (see the
/// Bucket docs); the refill multiply is overflow-safe (the
/// NIGHT-cybersecurity-1 fill-detect shape):
///
///  * fill-detect: once elapsed is large enough that the true
///    refill reaches 2x burst, the bucket caps at burst anyway —
///    skip the multiply and credit burst directly (the fraction
///    resets, matching the cap branch below).
///  * exact multiply: below that threshold the product is
///    < 2 * burst * NS_PER_SEC, safely representable in u64 for any
///    burst the clamp admits — the fill-detect threshold is not an
///    optimization alone, it is the overflow guard: the exact branch
///    only ever runs while `elapsed < fill_ns`, and
///    `fill_ns * rate == 2 * burst * NS_PER_SEC` bounds the product
///    by construction.
///
/// Callers guarantee rate_bps > 0 (rate 0 short-circuits to the
/// block drop before enforce) and pass a policy whose burst_bytes
/// is already clamped to [`MAX_ENFORCABLE_BURST`] (the security-3
/// trust boundary in the program's try_enforce); the explicit guard
/// keeps that invariant local and protects the division.
///
/// Schema v6 (NIGHT-depthbore-1): `frac_rem` is sanitized on read —
/// the third persistent stored field, and the one the v4 clamp
/// family missed. A healthy remainder is always < NS_PER_SEC (the
/// math maintains that invariant itself: the exact branch stores
/// the post-carry remainder, the fill-detect and cap branches store
/// zero), so a value >= NS_PER_SEC is drift or hostile writes, and
/// `frac_rem + refill_frac` on top of it can wrap u64 — silent
/// garbage in the release BPF build, a panic under the userspace
/// test tree's overflow checks. Treating the anomalous remainder as
/// empty completes the clamp family: burst, tokens, and now frac are
/// each clamped to the healthy value the math itself would have
/// stored. Invisible for healthy state, total for hostile state.
#[inline(always)]
pub fn enforce(
    pol: &Policy,
    bkt: &mut Bucket,
    pkt_len: u32,
    now: u64,
    stats: Option<&mut LimiterStats>,
) -> i32 {
    // Refill tokens based on elapsed time. saturating_sub is the
    // explicit form of the C twin's guard: time at or before the
    // last refill means zero elapsed (monotonic clock; the guard
    // exists for hostile or drifted bucket state).
    let mut elapsed = now.saturating_sub(bkt.last_refill_ns);

    // Cap elapsed at 1 second to limit burst after idle.
    if elapsed > NS_PER_SEC {
        elapsed = NS_PER_SEC;
    }

    let mut refill_whole: u64 = 0;
    // v6: sanitize the stored remainder before any arithmetic on it
    // (see the function docs — completes the v4 clamp family).
    let mut new_frac: u64 = if bkt.frac_rem < NS_PER_SEC {
        bkt.frac_rem
    } else {
        0
    };
    if elapsed > 0 && pol.rate_bps > 0 {
        let fill_ns = (2 * pol.burst_bytes * NS_PER_SEC) / pol.rate_bps;
        if elapsed >= fill_ns {
            // Refill >= 2x burst: the cap below makes the exact value
            // irrelevant — burst is the answer.
            refill_whole = pol.burst_bytes;
            new_frac = 0;
        } else {
            let product = elapsed * pol.rate_bps;
            refill_whole = product / NS_PER_SEC;
            let refill_frac = product % NS_PER_SEC;

            // Accumulate the fractional remainder. If it overflows
            // NS_PER_SEC, carry 1 byte into the integer tokens.
            new_frac += refill_frac;
            if new_frac >= NS_PER_SEC {
                refill_whole += 1;
                new_frac -= NS_PER_SEC;
            }
        }
    }

    // New token count, capped at burst. The tokens seed is clamped
    // first (security-3): the bucket map is persistent state like
    // the policy map — a bucket written by an older schema, a
    // shrunk-burst residue, or raw corruption can carry tokens
    // above the current burst, and `tokens + refill_whole` would
    // wrap on u64::MAX-seeded garbage. Clamping to burst treats the
    // anomalous bucket as full — exactly the value the cap branch
    // below would have produced for a healthy one.
    let tokens = if bkt.tokens > pol.burst_bytes {
        pol.burst_bytes
    } else {
        bkt.tokens
    };
    let mut new_tokens = tokens + refill_whole;
    if new_tokens > pol.burst_bytes {
        new_tokens = pol.burst_bytes;
        // Reset the fraction on cap — at burst, no accumulation is
        // needed.
        new_frac = 0;
    }

    bkt.last_refill_ns = now;
    bkt.frac_rem = new_frac;

    // Check if enough tokens for this packet.
    if new_tokens >= u64::from(pkt_len) {
        bkt.tokens = new_tokens - u64::from(pkt_len);
        if let Some(s) = stats {
            s.packets_allowed += 1;
            s.bytes_allowed += u64::from(pkt_len);
        }
        1
    } else {
        bkt.tokens = new_tokens;
        if let Some(s) = stats {
            s.packets_dropped += 1;
            s.bytes_dropped += u64::from(pkt_len);
        }
        0
    }
}
