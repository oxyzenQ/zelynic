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
pub const SCHEMA_VERSION_EXPECTED: u32 = 3;

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
// Userspace mirror of the BPF token-bucket map value. The bucket maps
// are kernel-internal after the serve-mode removal (userspace last read
// them via the deleted clear_bucket_map), so this type is never
// constructed in production — but it stays as the schema-layout contract:
// the size/field assertions in the tests below guard drift against
// `struct Bucket` in ebpf/src/bin/limiter.rs.
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
        assert_eq!(SCHEMA_VERSION_EXPECTED, 3);
    }
}
