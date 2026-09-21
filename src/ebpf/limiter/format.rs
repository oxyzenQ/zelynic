// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Rate and duration parsing/formatting, and small terminal/sysfs
//! helpers for the limiter.

use anyhow::{bail, Result};

use super::types::{MAX_RATE, MIN_RATE};

/// Parse a time duration string. Formats: 1s, 3m, 10h, or plain number (seconds).
/// Returns duration in seconds. 0 = infinity.
pub fn parse_time_duration(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("h") {
        (v, 3600u64)
    } else if let Some(v) = s.strip_suffix("m") {
        (v, 60u64)
    } else if let Some(v) = s.strip_suffix("s") {
        (v, 1u64)
    } else {
        // Flagship typo rescue: suggest the near-miss duration the user
        // probably meant (`3min` -> `3m`, `10sec` -> `10s`, `5H` -> `5h`).
        // The tip line renders white via the line-aware error renderer.
        let mut msg =
            format!("Invalid duration '{s}'. Use format: 1s, 3m, 10h, or plain number (seconds)");
        if let Some(tip) = crate::cli::ux::duration_tip(s) {
            msg.push_str(&tip);
        }
        bail!("{msg}")
    };

    let n: u64 = num_part.trim().parse().map_err(|e| {
        // Same typo rescue as the suffix branch: a near-miss unit
        // (`1kib` strips to number "1ki" + implied b) surfaces here.
        let mut msg = format!("Invalid number in duration '{s}': {e}");
        if let Some(tip) = crate::cli::ux::duration_tip(s) {
            msg.push_str(&tip);
        }
        anyhow::anyhow!(msg)
    })?;

    // NIGHT-improve-10: checked, not saturating. A duration that
    // overflows 64-bit seconds is a meaningless input — silently
    // returning u64::MAX seconds ("~585 billion years") would arm
    // every future consumer of this parser with an effectively
    // infinite value that looks legitimate. Same contract as
    // parse_rate: error with the original input shown, never the
    // wrapped or saturated value.
    match n.checked_mul(multiplier) {
        Some(result) => Ok(result),
        None => bail!("Duration '{s}' is too large — the value overflows 64-bit math."),
    }
}

/// Parse a monitor refresh interval (NIGHT-hunt-7): 1s to 60s.
///
/// Accepts the same duration grammar as [`parse_time_duration`]
/// (plain seconds, `2s`, `1m`), then clamps to the owner-mandated
/// realtime window: anything below 1s spams the CPU with full-frame
/// redraws, anything above 60s stops feeling like a live monitor.
/// Out-of-range values fail with the bounds spelled out so the fix
/// is obvious.
pub fn parse_monitor_interval(s: &str) -> Result<u64> {
    let secs = parse_time_duration(s)?;
    if !(1..=60).contains(&secs) {
        bail!("Invalid interval '{s}': refresh interval must be between 1s and 60s");
    }
    Ok(secs)
}

/// Parse a rate string. Lowercase units only: kb, mb, gb, tb, b.
///
/// Returns the rate in bytes per second. On overflow (input too large for u64),
/// returns an error with the original input shown — not the wrapped value.
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("tb") {
        (v, 1_000_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("gb") {
        (v, 1_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("mb") {
        (v, 1_000_000u64)
    } else if let Some(v) = s.strip_suffix("kb") {
        (v, 1_000u64)
    } else if let Some(v) = s.strip_suffix("b") {
        (v, 1u64)
    } else {
        // Flagship typo rescue: suggest the near-miss rate the user
        // probably meant (`1MB` -> `1mb`, `1kib` -> `1kb`, `10mbps` ->
        // `10mb`). The tip line renders white via the line-aware error
        // renderer in the output layer.
        let mut msg =
            format!("Invalid rate '{s}'. Use lowercase: 1mb, 500kb, 1gb, 1tb, or plain number");
        if let Some(tip) = crate::cli::ux::rate_tip(s) {
            msg.push_str(&tip);
        }
        bail!("{msg}")
    };

    let n: u64 = num_part.trim().parse().map_err(|e| {
        // Same typo rescue as the suffix branch: a near-miss unit
        // like `1kib` strips its trailing 'b' and lands here with
        // the unparsable number "1ki".
        let mut msg = format!("Invalid number in rate '{s}': {e}");
        if let Some(tip) = crate::cli::ux::rate_tip(s) {
            msg.push_str(&tip);
        }
        anyhow::anyhow!(msg)
    })?;

    // Use checked_mul to detect overflow. saturating_mul would return u64::MAX
    // which is misleading (user sees 18446744073709551615 instead of their input).
    match n.checked_mul(multiplier) {
        Some(result) => Ok(result),
        None => bail!("Rate '{s}' is too large — the value overflows 64-bit math."),
    }
}

/// Validate rate is within bounds.
/// rate = 0 is allowed (means BLOCK in BPF schema v3+).
/// rate 1-999 is rejected (below minimum, would brick apps).
pub fn validate_rate(rate_bps: u64) -> Result<()> {
    if rate_bps > 0 && rate_bps < MIN_RATE {
        bail!(
            "Rate {} is below minimum ({} B/s = 1 KB/s, decimal SI).\n\
             Use --allow-dangerous to override. Use 0 for block.",
            rate_bps,
            MIN_RATE
        );
    }
    if rate_bps > MAX_RATE {
        bail!(
            "Rate {} is above maximum ({} B/s = 1 TB/s).\n\
             Use --allow-dangerous to override.",
            rate_bps,
            MAX_RATE
        );
    }
    Ok(())
}

/// Compute burst size: 1 second of traffic, clamped 4KB–100MB.
pub fn default_burst(rate_bps: u64) -> u64 {
    rate_bps.clamp(4096, 100_000_000)
}

/// Get monotonic time in nanoseconds (CLOCK_MONOTONIC).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

/// Format a byte count using decimal SI units (1 KB = 1000 bytes).
///
/// This is consistent with `parse_rate` which uses decimal units (1kb = 1000).
/// Network rates conventionally use SI units (1 Mbps = 1,000,000 bps).
///
/// One decimal on EVERY tier (status-style audit, NIGHT-style flagship
/// bar: compact/simple/elegant/precise): mixed digit counts read as
/// raggedness inside one aligned column ("100.0 MB/s" above "1.00 GB/s").
/// The TB tier exists because the parser accepts 1tb (MAX_RATE = 1e12)
/// and pre-audit a max-rate policy rendered "1000.00 GB/s" — the CLI
/// said 1tb, the status row disagreed.
///
/// Tier-boundary promotion (improve-13 precision): a value that ROUNDS
/// UP to 1000.0 of its unit renders in the next unit — 999_950 B is
/// "1.0 MB", never "1000.0 KB": a four-digit cell is a ragged column
/// ("999.9 KB" above "1000.0 KB"), and "1000.0 KB/s" (11 columns)
/// pushed the monitor's fixed 10-column RATE budget right by one at
/// exactly the tier edge. The B tier stays integer (no decimal to
/// round up).
///
/// Examples: 500 → "500 B", 1500 → "1.5 KB", 999_949 → "999.9 KB",
///           999_950 → "1.0 MB", 1_500_000_000_000 → "1.5 TB"
pub fn format_bytes(bytes: u64) -> String {
    const DIVS: [u64; 5] = [1, 1_000, 1_000_000, 1_000_000_000, 1_000_000_000_000];
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    // Walk up while the one-decimal display of this tier would carry a
    // thousands digit — exact integer threshold (999.95 of a unit,
    // i.e. 1000*div - div/20, the smallest value whose one-decimal
    // rounding reads 1000.0; every DIVS entry divides by 20 exactly,
    // so no float-edge wobble). Tier 4 is the TB terminal: u64::MAX
    // is ~18.4 TB, no fifth unit is reachable.
    let mut tier = 0usize;
    while tier < 4 && bytes >= 1000 * DIVS[tier] - DIVS[tier] / 20 {
        tier += 1;
    }

    if tier == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.1} {}", bytes as f64 / DIVS[tier] as f64, UNITS[tier])
    }
}

/// Format a rate (bytes per second) with "/s" suffix.
/// Uses decimal SI units, consistent with `parse_rate` and `format_bytes`.
///
/// Examples: 100_000 → "100.0 KB/s", 1_000_000 → "1.0 MB/s"
pub fn format_rate(bps: u64) -> String {
    if bps == 0 {
        "BLOCKED".to_string()
    } else {
        format!("{}/s", format_bytes(bps))
    }
}

/// Get terminal width in columns via the shared TIOCGWINSZ probe
/// (the one canonical copy lives in the terminal layer,
/// terminal/diff.rs — NIGHT-hunt-15). Falls back to 80 if detection
/// fails (piped output, no tty).
pub fn terminal_width() -> usize {
    crate::terminal::winsize().map_or(80, |(cols, _)| cols as usize)
}

// NIGHT-hunt-15: terminal_height() was deleted — after the render
// engine's geometry probe switched to the one-call winsize(), no
// caller remained (the status table renders width-only). A fresh
// height consumer should call crate::terminal::winsize() directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_plain_number() {
        assert_eq!(parse_rate("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn test_parse_rate_kb() {
        assert_eq!(parse_rate("1kb").unwrap(), 1_000);
        assert_eq!(parse_rate("500kb").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_rate_mb() {
        assert_eq!(parse_rate("1mb").unwrap(), 1_000_000);
        assert_eq!(parse_rate("5mb").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_rate_gb() {
        assert_eq!(parse_rate("1gb").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_bytes() {
        assert_eq!(parse_rate("500b").unwrap(), 500);
    }

    #[test]
    fn test_parse_rate_rejects_uppercase() {
        assert!(parse_rate("1KB").is_err());
        assert!(parse_rate("1MB/s").is_err());
        assert!(parse_rate("1GB").is_err());
    }

    #[test]
    fn test_parse_rate_uppercase_error_suggests_lowercase_twin() {
        // Flagship typo rescue: the error must carry a tip line pointing
        // at the lowercase twin (NIGHT-hunt-5).
        let err_msg = format!("{}", parse_rate("1MB").unwrap_err());
        assert!(
            err_msg.contains("tip: a similar value exists: '1mb'"),
            "error must suggest the lowercase twin, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_rate_near_miss_unit_suggestion() {
        let err_msg = format!("{}", parse_rate("1kib").unwrap_err());
        assert!(
            err_msg.contains("tip: a similar value exists: '1kb'"),
            "error must suggest the near-miss unit, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_rate_invalid() {
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("1xb").is_err());
        assert!(parse_rate("").is_err());
    }

    #[test]
    fn test_parse_rate_overflow_detects_and_shows_input() {
        // 1e17 × 1000 = 1e20, overflows u64 (max ~1.8e19).
        // Must return Err, NOT saturate to u64::MAX.
        let result = parse_rate("100000000000000000kb");
        assert!(result.is_err());

        let err_msg = format!("{}", result.unwrap_err());
        // Error must show the original input, not the wrapped u64::MAX value.
        assert!(
            err_msg.contains("100000000000000000kb"),
            "error should show original input, got: {err_msg}"
        );
        // Must name the overflow plainly. The old message carried a
        // bogus "Maximum is 1gb" from a pre-100gb era and a misleading
        // "Warning:" prefix on a hard error (NIGHT-hunt-5).
        assert!(
            err_msg.contains("overflows 64-bit math"),
            "error should name the overflow, got: {err_msg}"
        );
        // Must NOT show the wrapped u64::MAX value.
        assert!(
            !err_msg.contains("18446744073709551615"),
            "error must not show u64::MAX wrapped value, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_rate_max_gb_does_not_overflow() {
        // 1gb = 1e9, should parse fine.
        assert_eq!(parse_rate("1gb").unwrap(), 1_000_000_000);
        // 1000gb = 1e12, still fits u64.
        assert_eq!(parse_rate("1000gb").unwrap(), 1_000_000_000_000);
    }

    #[test]
    fn test_parse_rate_tb_suffix_matches_new_ceiling() {
        // NIGHT-research-1 option B: the 1 TB/s ceiling is expressible
        // ergonomically; the old gb spelling parses identically.
        assert_eq!(parse_rate("1tb").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_rate("500gb").unwrap(), 500_000_000_000);
        assert_eq!(parse_rate("1000gb").unwrap(), parse_rate("1tb").unwrap());
        assert!(validate_rate(parse_rate("1tb").unwrap()).is_ok());
    }

    #[test]
    fn test_validate_rate_minimum() {
        assert!(validate_rate(512).is_err());
        assert!(validate_rate(1000).is_ok());
        assert!(validate_rate(1024).is_ok());
    }

    #[test]
    fn test_validate_rate_minimum_harmonized_with_parser() {
        // NIGHT-hunt-5 harmonization: MIN_RATE is decimal SI (1000 B/s),
        // matching parse_rate where 1kb = 1000. The documented minimum
        // "1 KB/s" must accept the documented input "1kb" — before the
        // fix, MIN_RATE was 1024 and `strict-single brave 1kb` was
        // rejected as below-minimum, contradicting every doc.
        let rate = parse_rate("1kb").unwrap();
        assert_eq!(rate, 1000);
        assert!(validate_rate(rate).is_ok());
    }

    #[test]
    fn test_validate_rate_maximum() {
        // Owner-approved option B (NIGHT-research-1): the ceiling is
        // 1 TB/s; 100 GB/s remains valid far below it.
        assert!(validate_rate(2_000_000_000_000).is_err());
        assert!(validate_rate(1_000_000_000_000).is_ok());
        assert!(validate_rate(200_000_000_000).is_ok());
        assert!(validate_rate(100_000_000_000).is_ok());
    }

    #[test]
    fn test_default_burst_normal() {
        assert_eq!(default_burst(1_000_000), 1_000_000);
    }

    #[test]
    fn test_default_burst_minimum() {
        assert_eq!(default_burst(100), 4096);
    }

    #[test]
    fn test_default_burst_maximum() {
        assert_eq!(default_burst(1_000_000_000_000), 100_000_000);
    }

    #[test]
    fn test_format_bytes_decimal_si() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1000), "1.0 KB");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(100_000), "100.0 KB");
        // improve-13 promotion: 999_999 KB-rounds to 1000.0, so it
        // renders as the next unit.
        assert_eq!(format_bytes(999_999), "1.0 MB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        // One decimal on every tier, TB tier included — and improve-13
        // promotion: the threshold is inclusive (999_949 stays KB,
        // 999_950 IS 1.0 MB), the forms never carry four digits.
        assert_eq!(format_bytes(1_000_000_000), "1.0 GB");
        assert_eq!(format_bytes(1_500_000_000), "1.5 GB");
        assert_eq!(format_bytes(999_949_999_999), "999.9 GB");
        assert_eq!(format_bytes(999_950_000_000), "1.0 TB");
        assert_eq!(format_bytes(1_000_000_000_000), "1.0 TB");
        assert_eq!(format_bytes(1_500_000_000_000), "1.5 TB");
    }

    /// Tier-boundary promotion (improve-13): values that would round
    /// to a thousands digit render in the next unit. Every tier edge
    /// is pinned at its exact threshold.
    #[test]
    fn test_format_bytes_promotes_at_rounding_boundary() {
        // Just under each edge: the three-digit form holds.
        assert_eq!(format_bytes(999_949), "999.9 KB");
        assert_eq!(format_bytes(999_949_999), "999.9 MB");
        assert_eq!(format_bytes(999_949_999_999), "999.9 GB");
        // At/over the edge (the value that ROUNDS to 1000.0): promoted.
        assert_eq!(format_bytes(999_950), "1.0 MB");
        assert_eq!(format_bytes(999_950_999), "1.0 GB");
        assert_eq!(format_bytes(999_950_999_999), "1.0 TB");
        // Rate cells fit the 10-column monitor budget after promotion.
        assert_eq!(format_rate(999_949).chars().count(), 10);
        assert_eq!(format_rate(999_950).chars().count(), 8);
    }

    #[test]
    fn test_format_rate_with_suffix() {
        assert_eq!(format_rate(0), "BLOCKED");
        assert_eq!(format_rate(100_000), "100.0 KB/s");
        assert_eq!(format_rate(1_000_000), "1.0 MB/s");
        assert_eq!(format_rate(1_000_000_000), "1.0 GB/s");
        // The input-output symmetry pin: the CLI accepts "1tb" and
        // the status row now answers in the same unit.
        assert_eq!(format_rate(1_000_000_000_000), "1.0 TB/s");
    }

    #[test]
    fn test_parse_rate_consistent_with_format() {
        // Round-trip: parse("100kb") → 100000 → format → "100.0 KB/s"
        let rate = parse_rate("100kb").unwrap();
        assert_eq!(rate, 100_000);
        assert_eq!(format_rate(rate), "100.0 KB/s");

        let rate = parse_rate("1mb").unwrap();
        assert_eq!(rate, 1_000_000);
        assert_eq!(format_rate(rate), "1.0 MB/s");

        // The max-rate twin (status-style audit): parse("1tb") is the
        // parser's ceiling; the formatter must answer in TB, not in a
        // four-digit GB figure.
        let rate = parse_rate("1tb").unwrap();
        assert_eq!(rate, 1_000_000_000_000);
        assert_eq!(format_rate(rate), "1.0 TB/s");
    }

    // ── NIGHT-improve-10: duration overflow pins ────────────────────

    #[test]
    fn test_parse_time_duration_plain_and_units() {
        assert_eq!(parse_time_duration("30").unwrap(), 30);
        assert_eq!(parse_time_duration("30s").unwrap(), 30);
        assert_eq!(parse_time_duration("5m").unwrap(), 300);
        assert_eq!(parse_time_duration("2h").unwrap(), 7200);
    }

    #[test]
    fn test_parse_time_duration_overflow_errors_not_saturates() {
        // 1e17 × 3600 (h) overflows u64 (max ~1.8e19). Must return Err
        // naming the overflow with the original input — never a silent
        // u64::MAX saturation that consumers would treat as "infinity".
        let result = parse_time_duration("100000000000000000h");
        assert!(result.is_err());

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("100000000000000000h"),
            "error should show original input, got: {err_msg}"
        );
        assert!(
            err_msg.contains("overflows 64-bit math"),
            "error should name the overflow, got: {err_msg}"
        );
        assert!(
            !err_msg.contains("18446744073709551615"),
            "error must not show a saturated u64::MAX value, got: {err_msg}"
        );
    }
}
