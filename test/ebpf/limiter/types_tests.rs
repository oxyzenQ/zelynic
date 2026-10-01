// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The types.rs pins (Target parsing, rate bounds, the schema-layout
//! size pins, the burst family) — split from types.rs's inline test
//! module at NIGHT-upgrade-charger-core-3b when PolicyRaw's new
//! flags field grew the file past the 500-LOC owner cap: pins live
//! under the single test/ tree, #[path]-wired (cosmostrix Pattern C,
//! the policy_tests/docker_tests lineage). `use super::*` becomes an
//! explicit import list because the parent here is the test wiring,
//! not the module under test.

use crate::ebpf::limiter::types::*;

#[test]
fn test_target_parse_numeric() {
    match Target::parse("73386") {
        Target::CgroupId(id) => assert_eq!(id, 73386),
        _ => panic!("expected CgroupId"),
    }
}

#[test]
fn test_target_parse_name() {
    match Target::parse("firefox") {
        Target::ProcessName(name) => assert_eq!(name, "firefox"),
        _ => panic!("expected ProcessName"),
    }
}

/// NIGHT-boost-37: the canonical display prefix parses to the
/// same direct cgroup ID as the bare numeric form — the output
/// surfaces print `cg:48181` and the suggested command
/// (`sudo zelynic ss cg:48181 100kb`) must work verbatim.
#[test]
fn test_target_parse_cg_prefix_numeric() {
    match Target::parse("cg:48181") {
        Target::CgroupId(id) => assert_eq!(id, 48181),
        _ => panic!("expected CgroupId for cg:-prefixed numeric"),
    }
    // Prefix and bare forms resolve identically — one target.
    assert!(matches!(Target::parse("cg:73386"), Target::CgroupId(id) if id == 73386));
}

/// A non-numeric remainder keeps the WHOLE string as a process
/// name (never the stripped part): a typo like `cg:brave` is the
/// graceful no-match it always was — the prefix never silently
/// rewrites a name target into a different process.
#[test]
fn test_target_parse_cg_prefix_non_numeric_keeps_full_name() {
    match Target::parse("cg:brave") {
        Target::ProcessName(name) => assert_eq!(name, "cg:brave"),
        _ => panic!("expected ProcessName for cg:-prefixed non-numeric"),
    }
}

/// A u32 overflow after the prefix stays a name (graceful no-op,
/// same contract as the bare beyond-u32 target the CLI pins).
#[test]
fn test_target_parse_cg_prefix_overflow_stays_name() {
    match Target::parse("cg:99999999999999999999") {
        Target::ProcessName(name) => assert_eq!(name, "cg:99999999999999999999"),
        _ => panic!("expected ProcessName for cg:-prefixed overflow"),
    }
}

#[test]
fn test_direction_suffix() {
    assert_eq!(Direction::Download.suffix(), "dl");
    assert_eq!(Direction::Upload.suffix(), "ul");
}

#[test]
fn test_bucket_raw_has_frac_rem() {
    // Verify BucketRaw has 3 fields (24 bytes) for schema v2.
    // v1 was 16 bytes (tokens + last_refill_ns only).
    let b = BucketRaw {
        tokens: 1000,
        last_refill_ns: 12345,
        frac_rem: 999_999_999,
    };
    assert_eq!(b.tokens, 1000);
    assert_eq!(b.last_refill_ns, 12345);
    assert_eq!(b.frac_rem, 999_999_999);
    assert_eq!(
        std::mem::size_of::<BucketRaw>(),
        24,
        "BucketRaw must be 24 bytes (3 × u64) for schema v2"
    );
}

#[test]
fn test_fractional_tracking_precision() {
    const NS_PER_SEC: u64 = 1_000_000_000;

    // Simulate: rate = 97,700 bps (97.7 KB/s), 1000 refills of 1ms each.
    let rate_bps: u64 = 97_700;
    let elapsed_ns: u64 = 1_000_000; // 1ms

    let mut tokens: u64 = 0;
    let mut frac_rem: u64 = 0;

    for _ in 0..1000 {
        let product = elapsed_ns * rate_bps;
        let mut refill_whole = product / NS_PER_SEC;
        let refill_frac = product % NS_PER_SEC;

        let mut new_frac = frac_rem + refill_frac;
        if new_frac >= NS_PER_SEC {
            refill_whole += 1;
            new_frac -= NS_PER_SEC;
        }
        frac_rem = new_frac;
        tokens += refill_whole;
    }

    // With fractional tracking, 1000 × 1ms = 1 second of tokens.
    // Expected: 97,700 bytes (exact rate × 1 second).
    // Without fractional tracking: 97,000 bytes (truncated).
    assert_eq!(
        tokens, 97_700,
        "fractional tracking should give exact rate over 1 second"
    );

    // Verify the error is zero (was 0.72% without fractional tracking).
    let error_pct = ((tokens as i64 - 97_700) as f64 / 97_700.0).abs() * 100.0;
    assert!(
        error_pct < 0.01,
        "error should be < 0.01%, got {error_pct}%"
    );
}

#[test]
fn test_truncation_error_without_fractional() {
    const NS_PER_SEC: u64 = 1_000_000_000;

    let rate_bps: u64 = 97_700;
    let elapsed_ns: u64 = 1_000_000;

    let mut tokens: u64 = 0;

    for _ in 0..1000 {
        // Old formula: integer division, no fractional tracking.
        let refill = (elapsed_ns * rate_bps) / NS_PER_SEC;
        tokens += refill;
    }

    // Without fractional tracking: 97,000 (truncated from 97,700).
    // This is a 0.72% error — the problem fractional tracking fixes.
    assert_eq!(tokens, 97_000);
    let error_pct = (97_700 - tokens) as f64 / 97_700.0 * 100.0;
    assert!(error_pct > 0.5, "truncation error should be > 0.5%");
}

#[test]
fn test_schema_version_constant() {
    // Must match SCHEMA_VERSION in ebpf/src/bin/limiter.rs.
    // When this changes, the BPF code must also change.
    // v11 (NIGHT-think-like-light-years-3): the init-path
    // inserts ride BPF_NOEXIST — the first-packet init race
    // can no longer resurrect tokens or roll the window stamp
    // back under a many-CPU burst on a fresh bucket.
    // v12 (NIGHT-perf-0): AMMSP memos are generation-stamped —
    // the leaf-cache value packs (generation << 32) | root and
    // the new ammsp_generation array invalidates every memo a
    // mutation outlives, one O(1) bump per mutation.
    // v13 (charger-core-1c): the individual lane becomes DRR —
    // the shared bucket a pool, every packet spending from a
    // per-leaf quantum bucket (leaf_bucket_dl/ul).
    // v14 (charger-core-3a): the time-series rings. v15
    // (charger-core-3b): Policy.flags (offset-20 padding becomes
    // contract, bit 0 = per-socket) + the socket bucket maps.
    // v16 (dinner-28): the learned-share draw — the DRR take
    // capped by pool/(learned+2) through the two new
    // drr_pool_state_dl/ul maps.
    // v17 (repair-3): the epoch ledger — the take further capped
    // by the leaf's remaining per-epoch allowance (the pool's
    // 100ms refill split across the learned count) through the
    // two new drr_leaf_state_dl/ul maps, and the pool-share note
    // atomic (the v16 plain-read-plus-BPF_ANY insert lost
    // increments to racing writers until the count itself lied).
    // The full sync contract (this constant vs the BPF-side
    // anchor) lives in schema.rs's sync_pin — the v13 lesson.
    assert_eq!(SCHEMA_VERSION_EXPECTED, 17);
}

// ── NIGHT-improve-10 / security-3: overflow-bound pins ──────────

#[test]
fn test_max_enforcable_burst_exact_bound() {
    // The bound is exact, not rounded: the fill-detect product
    // at the bound stays representable, one past it overflows.
    // This is the invariant the BPF-side clamp (MAX_ENFORCABLE_BURST
    // in ebpf/src/bin/limiter.rs) derives its totality proof from —
    // keep both constants textually in sync. Pinned as VALUES
    // (clippy folds boolean asserts on constants, and a pinned
    // number forces a conscious update when the bound moves).
    assert_eq!(MAX_ENFORCABLE_BURST, 9_223_372_036);
    assert_eq!(
        2 * MAX_ENFORCABLE_BURST * 1_000_000_000,
        18_446_744_072_000_000_000,
        "2 * bound * NS_PER_SEC must be the largest representable multiple"
    );
    // Worst pre-cap token sum: sanitized seed + a full fill-detect
    // refill plus the exact-multiply bound — 3 * bound, still far
    // inside u64.
    assert_eq!(
        3 * MAX_ENFORCABLE_BURST,
        27_670_116_108,
        "worst-case tokens + 2*burst must stay representable (and pinned)"
    );
}

#[test]
fn test_max_enforcable_burst_dwarfs_userspace_burst_ceiling() {
    // default_burst clamps to 100 MB; the enforcement-boundary
    // clamp is ~9.2 GB — every legit userspace write passes the
    // kernel-side clamp untouched (invisible for healthy state).
    use crate::ebpf::limiter::format::default_burst;
    assert!(
        default_burst(u64::MAX) <= MAX_ENFORCABLE_BURST,
        "userspace burst clamp must never trip the enforcement bound"
    );
    assert_eq!(default_burst(u64::MAX), 100_000_000);
}

#[test]
fn test_enforce_math_total_for_corrupt_policy() {
    // Mirror of the ebpf-side security-3 sanitize: ANY stored
    // burst value must leave the refill math overflow-free after
    // the trust-boundary clamp. This simulates the exact sequence
    // ebpf enforce() runs — including the u64::MAX adversary —
    // where the pre-fix math would wrap on the fill-detect
    // multiply and produce garbage enforcement.
    const NS_PER_SEC: u64 = 1_000_000_000;

    for corrupt_burst in [u64::MAX, u64::MAX - 1, MAX_ENFORCABLE_BURST + 1] {
        // The trust-boundary clamp (try_enforce side).
        let burst = corrupt_burst.min(MAX_ENFORCABLE_BURST);
        // Corrupt bucket seed: garbage tokens above the burst.
        let stored_tokens = u64::MAX;

        // The tokens clamp (enforce side).
        let tokens = stored_tokens.min(burst);

        // Refill math with elapsed capped at 1s, rate arbitrary.
        for rate_bps in [1u64, 1_000, 1_000_000_000, u64::MAX] {
            let elapsed = NS_PER_SEC; // worst case after the cap
            let fill_ns = 2 * burst * NS_PER_SEC / rate_bps; // must not overflow
            let refill_whole = if elapsed >= fill_ns {
                burst
            } else {
                // Only reachable when product < 2 * burst * NS_PER_SEC.
                let product = elapsed
                    .checked_mul(rate_bps)
                    .expect("product must be representable inside the fill-detect bound");
                product / NS_PER_SEC
            };
            let new_tokens = tokens
                .checked_add(refill_whole)
                .expect("tokens + refill must be representable after both clamps");
            let capped = new_tokens.min(burst);
            assert_eq!(
                capped, burst,
                "a clamped adversary lands at burst, not garbage"
            );
        }
    }
}

// ── charger-core-3b: the flags field's layout contract pins ────────

/// The offset-20 padding is now the flags field: the struct stays
/// exactly 24 bytes (the BPF size pin's value), the field sits at
/// offset 20, and the per-socket bit is 1 — the three numbers the
/// v15 layout contract rides, pinned so no future field can silently
/// shift the layout the pinned maps carry.
#[test]
fn policy_raw_flags_layout_is_pinned() {
    use crate::ebpf::limiter::types::{PolicyRaw, POLICY_FLAG_PER_SOCKET};

    assert_eq!(core::mem::size_of::<PolicyRaw>(), 24);
    assert_eq!(
        core::mem::offset_of!(PolicyRaw, flags),
        20,
        "flags must stay at the former padding offset 20"
    );
    assert_eq!(core::mem::offset_of!(PolicyRaw, group_id), 16);
    assert_eq!(POLICY_FLAG_PER_SOCKET, 1);
    // The default write is the legacy cgroup lane: flags 0.
    assert_eq!(PolicyRaw::default().flags, 0);
}
