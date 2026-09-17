// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Rate and duration parsing/formatting, BPF object discovery, and
//! small terminal/sysfs helpers for the limiter.

use anyhow::{bail, Result};
use std::path::PathBuf;

use super::types::{BPF_OBJECT_PATH, MAX_RATE, MIN_RATE};

pub fn find_bpf_object() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from(BPF_OBJECT_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BPF_OBJECT_PATH),
        PathBuf::from("/usr/lib/zelynic/limiter.bpf.o"),
        PathBuf::from("/usr/local/lib/zelynic/limiter.bpf.o"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    bail!(
        "BPF object file not found. Compile with:\n  \
         clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o\n  \
         Searched: {:?}",
        candidates
    )
}

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
        bail!(
            "Invalid duration '{}'. Use format: 1s, 3m, 10h, or plain number (seconds)",
            s
        );
    };

    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid number in duration '{}': {}", s, e))?;

    Ok(n.saturating_mul(multiplier))
}

/// Parse a rate string. Lowercase units only: kb, mb, gb, b.
///
/// Returns the rate in bytes per second. On overflow (input too large for u64),
/// returns an error with the original input shown — not the wrapped value.
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("gb") {
        (v, 1_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("mb") {
        (v, 1_000_000u64)
    } else if let Some(v) = s.strip_suffix("kb") {
        (v, 1_000u64)
    } else if let Some(v) = s.strip_suffix("b") {
        (v, 1u64)
    } else {
        bail!(
            "Invalid rate '{}'. Use lowercase: 1mb, 500kb, 1gb, or plain number",
            s
        );
    };

    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid number in rate '{}': {}", s, e))?;

    // Use checked_mul to detect overflow. saturating_mul would return u64::MAX
    // which is misleading (user sees 18446744073709551615 instead of their input).
    match n.checked_mul(multiplier) {
        Some(result) => Ok(result),
        None => bail!(
            "Warning: rate '{s}' is too large (overflow). Maximum is 1gb (1,000,000,000 b/s)."
        ),
    }
}

/// Validate rate is within bounds.
/// rate = 0 is allowed (means BLOCK in BPF schema v3+).
/// rate 1-1023 is rejected (below minimum, would brick apps).
pub fn validate_rate(rate_bps: u64) -> Result<()> {
    if rate_bps > 0 && rate_bps < MIN_RATE {
        bail!(
            "Rate {} is below minimum ({} B/s = 1 KB/s).\n\
             Use --allow-dangerous to override. Use 0 for block.",
            rate_bps,
            MIN_RATE
        );
    }
    if rate_bps > MAX_RATE {
        bail!(
            "Rate {} is above maximum ({} B/s = 100 GB/s).\n\
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
/// Examples: 500 → "500 B", 1500 → "1.5 KB", 1_500_000 → "1.5 MB",
///           1_500_000_000 → "1.50 GB"
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1000 {
        format!("{bytes} B")
    } else if bytes < 1_000_000 {
        format!("{:.1} KB", bytes as f64 / 1000.0)
    } else if bytes < 1_000_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
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

/// Get terminal width in columns. Uses ioctl TIOCGWINSZ.
/// Falls back to 80 if detection fails (piped output, no tty).
pub fn terminal_width() -> usize {
    use libc::{ioctl, winsize, STDOUT_FILENO, TIOCGWINSZ};
    let mut ws: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ioctl with TIOCGWINSZ writes to a valid winsize struct.
    let ret = unsafe { ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
}

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
        // Must say "Warning:" not be a raw overflow.
        assert!(
            err_msg.starts_with("Warning:"),
            "error should start with 'Warning:', got: {err_msg}"
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
    fn test_validate_rate_minimum() {
        assert!(validate_rate(512).is_err());
        assert!(validate_rate(1024).is_ok());
    }

    #[test]
    fn test_validate_rate_maximum() {
        assert!(validate_rate(200_000_000_000).is_err());
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
        assert_eq!(format_bytes(999_999), "1000.0 KB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(1_000_000_000), "1.00 GB");
    }

    #[test]
    fn test_format_rate_with_suffix() {
        assert_eq!(format_rate(0), "BLOCKED");
        assert_eq!(format_rate(100_000), "100.0 KB/s");
        assert_eq!(format_rate(1_000_000), "1.0 MB/s");
        assert_eq!(format_rate(1_000_000_000), "1.00 GB/s");
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
    }
}
