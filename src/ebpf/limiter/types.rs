// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Limiter constants and data types.
//!
//! BPF map value structs mirror the limiter program's structs in
//! `ebpf/src/bin/limiter.rs` (layout contract); the high-level types
//! drive the CLI-facing API.

// ━━ Constants ━━

/// The embedded pure-Rust limiter object (NIGHT-improve-1 phase 3):
/// the aya-ebpf ELF staged into OUT_DIR by build.rs's nested nightly
/// build, riding inside the binary via include_bytes!. `EbpfLoader`
/// takes the bytes directly — no file path, no object discovery.
///
/// NIGHT-hunt-30: the bytes ride inside [`AlignedElf`] so their
/// address is 8-byte aligned BY CONSTRUCTION — the `object` crate's
/// ELF64 parser reads its structures straight out of the buffer and
/// requires that alignment, and the plain align-1 `include_bytes!`
/// static landed unaligned on the owner host's builds (deterministic
/// per host: every build there failed, every build in the dev
/// container passed — the artifact itself was healthy the whole
/// time). See src/ebpf/embedded.rs for the full hunt record.
pub static LIMITER_ELF: &[u8] = &crate::ebpf::embedded::AlignedElf::new(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/zelynic-limiter"
)))
.bytes;

/// Minimum allowed rate: 1 KB/s (1000 B/s, decimal SI).
///
/// NIGHT-hunt-5 harmonization: matches `parse_rate`, where 1kb = 1000
/// (decimal SI, the documented contract). The old value 1024 was a
/// binary-unit leftover that rejected the documented minimum input
/// `1kb` (1000 < 1024) — the parser, the guard, and the docs disagreed.
pub const MIN_RATE: u64 = 1000;

/// Maximum allowed rate: 1 TB/s.
///
/// Owner-approved option B (NIGHT-research-1): 8-TbE-class headroom —
/// a decade of margin over shipping NICs — while staying far inside
/// u64 and the BPF refill guard's exact-multiply bound (the
/// cybersecurity-1 fill-detect fix is rate-agnostic: at this ceiling
/// it engages after 200us of idle, and the product bound stays
/// 2 * burst * NS_PER_SEC <= 2e17 at the 100 MB burst clamp).
/// zelynic can enforce up to infinity; use `--allow-dangerous` to
/// override.
pub const MAX_RATE: u64 = 1_000_000_000_000;

/// BPF schema version. Must match `SCHEMA_VERSION` in
/// `ebpf/src/bin/limiter.rs`.
/// Increment both when BPF struct layouts or semantics change. Userspace checks
/// the pinned schema_version map on attach — if mismatch, cleans up + reloads.
/// v1: initial (no frac_rem in bucket, no schema_version map)
/// v2: added frac_rem to bucket for fractional token tracking
/// v3: rate_bps == 0 changed from "allow all" to "block all" (block-single)
/// v4: enforcement-boundary sanitization (NIGHT-improve-10 / security-3) —
///     burst and tokens clamped before any refill math; no layout change.
///     The bump forces pinned v3 programs to reload into the hardened
///     object (active limits are dropped once — re-apply after upgrade).
/// v5: the rate-0 block verdict books its drops into cgroup_limiter_stats
///     (NIGHT-improve-14) — verdict unchanged; pinned v4 programs otherwise
///     keep dropping blocked traffic with an empty, invisible drop counter.
///     Same one-time re-apply contract as the v3 -> v4 bump.
pub const SCHEMA_VERSION_EXPECTED: u32 = 5;

/// Hard ceiling a stored `burst_bytes` may carry into the BPF refill
/// math (NIGHT-improve-10 / security-3). Mirror of `MAX_ENFORCABLE_BURST`
/// in `ebpf/src/bin/limiter.rs` — the exact mathematical ceiling under
/// which every product the refill can form is representable in u64:
/// `2 * burst * NS_PER_SEC` (the fill-detect threshold) and
/// `tokens + 2 * burst` (worst pre-cap sum). Userspace writes are
/// clamped to 100 MB by `default_burst`, far below this bound — the
/// kernel-side clamp exists for the values no legit writer produces
/// (map corruption, schema drift, raw pin writes). Both sides pin
/// this value in tests; keep them textually in sync when either
/// changes.
pub const MAX_ENFORCABLE_BURST: u64 = u64::MAX / (2 * 1_000_000_000);

// ━━ BPF map value structs (must match the ebpf crate's structs) ━━

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct PolicyRaw {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
}

unsafe impl aya::Pod for PolicyRaw {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
// Userspace mirror of the BPF token-bucket map value. Production
// never constructs a value (buckets are kernel-internal state), but
// the type carries two contracts: the schema-layout pin (size/field
// assertions below guard drift against `struct Bucket` in
// ebpf/src/bin/limiter.rs) and the key type of the unstrict/recover
// reclaim path (NIGHT-improve-10), which deletes stale per-cgroup
// entries so the 1024-slot bucket maps never fill with dead state.
#[allow(dead_code)]
pub struct BucketRaw {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub frac_rem: u64,
}

unsafe impl aya::Pod for BucketRaw {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct LimiterStatsRaw {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

unsafe impl aya::Pod for LimiterStatsRaw {}

// ━━ High-level API types ━━

#[derive(Debug, Clone)]
pub struct RateSpec {
    pub download: Option<u64>,
    pub upload: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum Target {
    CgroupId(u32),
    ProcessName(String),
}

impl Target {
    pub fn parse(s: &str) -> Self {
        if let Ok(id) = s.parse::<u32>() {
            Target::CgroupId(id)
        } else {
            Target::ProcessName(s.to_string())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn suffix(&self) -> &'static str {
        match self {
            Direction::Download => "dl",
            Direction::Upload => "ul",
        }
    }

    /// Human-readable direction name for the verbose trace surface
    /// (NIGHT-hunt-9): `suffix()` is the BPF map-name fragment
    /// ("dl"/"ul"); this is the full word the diagnostic lines print.
    pub fn label(&self) -> &'static str {
        match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(SCHEMA_VERSION_EXPECTED, 5);
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
}
