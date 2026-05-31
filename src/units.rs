// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fmt;
use std::str::FromStr;

/// Supported bandwidth metric units for rate specification.
///
/// All units represent per-second rates (bytes or bits per second).
/// The tool supports both byte-based units (common in computing) and
/// bit-based units (common in networking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum BandwidthUnit {
    /// Bytes per second
    BytesPerSec,
    /// Kilobytes per second (1 KB = 1024 bytes)
    KilobytesPerSec,
    /// Megabytes per second (1 MB = 1024 KB)
    MegabytesPerSec,
    /// Gigabytes per second (1 GB = 1024 MB)
    GigabytesPerSec,
    /// Kilobits per second (1 Kbit = 1024 bits = 128 bytes)
    KilobitsPerSec,
    /// Megabits per second (1 Mbit = 1024 Kbit)
    MegabitsPerSec,
    /// Gigabits per second (1 Gbit = 1024 Mbit)
    GigabitsPerSec,
}

impl BandwidthUnit {
    /// Parse a unit string into a BandwidthUnit.
    ///
    /// Supports multiple aliases for each unit type:
    /// - Byte-based: b, byte, bytes, bs
    /// - Kilobyte: kb, kbs, kb/s
    /// - Megabyte: mb, mbs, mb/s
    /// - Gigabyte: gb, gbs, gb/s
    /// - Kilobit: kbit, kbits, kbps, kb/s
    /// - Megabit: mbit, mbits, mbps, mb/s
    /// - Gigabit: gbit, gbits, gbps, gb/s
    pub fn from_str_unit(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "b" | "byte" | "bytes" | "bs" => Some(Self::BytesPerSec),
            "kb" | "kbs" | "kb/s" => Some(Self::KilobytesPerSec),
            "mb" | "mbs" | "mb/s" => Some(Self::MegabytesPerSec),
            "gb" | "gbs" | "gb/s" => Some(Self::GigabytesPerSec),
            "kbit" | "kbits" => Some(Self::KilobitsPerSec),
            "mbit" | "mbits" => Some(Self::MegabitsPerSec),
            "gbit" | "gbits" => Some(Self::GigabitsPerSec),
            _ => None,
        }
    }

    /// Return the multiplier to convert a value in this unit to bytes per second.
    ///
    /// For byte-based units, the multiplier is a power of 1024.
    /// For bit-based units, the multiplier is divided by 8 (bits to bytes).
    pub fn bytes_multiplier(self) -> u64 {
        match self {
            Self::BytesPerSec => 1,
            Self::KilobytesPerSec => 1024,
            Self::MegabytesPerSec => 1024 * 1024,
            Self::GigabytesPerSec => 1024 * 1024 * 1024,
            Self::KilobitsPerSec => 1024 / 8,
            Self::MegabitsPerSec => (1024 * 1024) / 8,
            Self::GigabitsPerSec => (1024 * 1024 * 1024) / 8,
        }
    }

    /// Short human-readable label for this unit.
    pub fn short_label(&self) -> &'static str {
        match self {
            Self::BytesPerSec => "B/s",
            Self::KilobytesPerSec => "KB/s",
            Self::MegabytesPerSec => "MB/s",
            Self::GigabytesPerSec => "GB/s",
            Self::KilobitsPerSec => "Kbit/s",
            Self::MegabitsPerSec => "Mbit/s",
            Self::GigabitsPerSec => "Gbit/s",
        }
    }
}

/// Parsed bandwidth rate value with its unit.
#[derive(Debug, Clone)]
pub struct BandwidthRate {
    /// Value in bytes per second (canonical form)
    pub bytes_per_sec: u64,
    /// The numeric value as parsed
    pub value: u64,
    /// The unit that was parsed
    pub unit: BandwidthUnit,
}

impl BandwidthRate {
    /// Parse a bandwidth rate string (e.g., "500kb", "1mb", "2gb", "100byte").
    ///
    /// The string should contain a numeric value followed by a unit identifier.
    /// Whitespace between the value and unit is optional.
    ///
    /// # Examples
    /// ```
    /// BandwidthRate::parse("500kb")  // 500 KB/s
    /// BandwidthRate::parse("1.5mb")  // Error: no floating point
    /// BandwidthRate::parse("2gb")    // 2 GB/s
    /// ```
    /// Minimum bandwidth rate: 1 KB/s (1024 bytes/s).
    /// Rates below this cannot be accurately enforced by the Linux kernel's
    /// HTB scheduler due to clock tick granularity (~1-4ms).
    pub const MIN_BYTES_PER_SEC: u64 = 1024;

    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();

        // Reject empty input
        if trimmed.is_empty() {
            bail!("bandwidth rate cannot be empty. Examples: 500kb, 1mb, 2gb, 100byte");
        }

        // Reject leading signs (+/-)
        let first = trimmed.chars().next().unwrap();
        if first == '+' || first == '-' {
            bail!(
                "invalid bandwidth rate '{}': leading '{}' is not allowed. \n  {} Use positive values only (e.g., 100kb, 1mb, 500kb)",
                input, first, "Hint:".yellow()
            );
        }

        // Reject values that start with a non-digit (but not caught above)
        if !first.is_ascii_digit() {
            bail!(
                "invalid bandwidth rate '{}': must start with a numeric value. \n  {} Examples: 100kb, 1mb, 500kb, 10byte",
                input, "Hint:".yellow()
            );
        }

        // Reject values containing spaces in the middle (e.g., "10 kb x")
        if trimmed.contains(' ') && trimmed.split_whitespace().count() > 2 {
            bail!(
                "invalid bandwidth rate '{}': unexpected extra characters. \n  {} Use a single value + unit (e.g., 100kb, 1mb)",
                input, "Hint:".yellow()
            );
        }

        // Find the boundary between numeric and alphabetic characters
        let digit_end = trimmed
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(trimmed.len());

        if digit_end == 0 {
            bail!(
                "invalid bandwidth rate '{}': must start with a numeric value (e.g., 500kb, 1mb)",
                input
            );
        }

        let value_str = &trimmed[..digit_end];
        let unit_str = trimmed[digit_end..].trim();

        let value: u64 = u64::from_str(value_str).with_context(|| {
            format!(
                "invalid numeric value '{}' in bandwidth rate '{}'. \n  {} Use a positive integer (e.g., 100kb, 1mb)",
                value_str, input, "Hint:".yellow()
            )
        })?;

        if value == 0 {
            bail!(
                "bandwidth rate must be greater than zero, got '{}'. \n  {} Minimum: 1kb (1 KB/s)",
                input,
                "Hint:".yellow()
            );
        }

        if unit_str.is_empty() {
            bail!(
                "missing unit in bandwidth rate '{}'. \n  {} Supported units: byte/bs, kb, mb, gb, kbit, mbit, gbit",
                input, "Hint:".yellow()
            );
        }

        let unit = BandwidthUnit::from_str_unit(unit_str).with_context(|| {
            format!(
                "unknown bandwidth unit '{}' in '{}'. \n  {} Supported: byte/bs, kb/kbs, mb/mbs, gb/gbs, kbit, mbit, gbit",
                unit_str, input, "Hint:".yellow()
            )
        })?;

        let bytes_per_sec = value * unit.bytes_multiplier();

        // Enforce minimum rate (1 KB/s — below this HTB cannot enforce accurately)
        if bytes_per_sec < Self::MIN_BYTES_PER_SEC {
            bail!(
                "bandwidth rate {} {} is below the minimum allowed (1 KB/s).\n  {} Minimum: 1kb (kernel HTB scheduler cannot enforce sub-KB/s rates accurately)",
                value,
                unit.short_label(),
                "Hint:".yellow()
            );
        }

        Ok(Self {
            bytes_per_sec,
            value,
            unit,
        })
    }
}

impl fmt::Display for BandwidthRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.value, self.unit.short_label())
    }
}

/// Format a byte count into a human-readable string with the best-fit unit.
///
/// Automatically selects the largest unit where the value is >= 1.
/// Uses binary prefixes (1024-based).
///
/// # Examples
/// - `format_bytes(500)` -> "500 B"
/// - `format_bytes(1536)` -> "1.50 KB"
/// - `format_bytes(1048576)` -> "1.00 MB"
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut value = bytes as f64;
    let mut unit_idx = 0;

    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[unit_idx])
    }
}

/// Format a byte count into a human-readable string, always using specific unit.
#[allow(dead_code)]
pub fn format_bytes_with_unit(bytes: u64) -> (f64, &'static str) {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return (0.0, "B");
    }

    let mut value = bytes as f64;
    let mut unit_idx = 0;

    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }

    (value, UNITS[unit_idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bytes() {
        let rate = BandwidthRate::parse("2048byte").unwrap();
        assert_eq!(rate.bytes_per_sec, 2048);
        assert_eq!(rate.unit, BandwidthUnit::BytesPerSec);
    }

    #[test]
    fn test_reject_below_minimum() {
        // Below 1 KB/s should be rejected
        assert!(BandwidthRate::parse("100byte").is_err());
        assert!(BandwidthRate::parse("500b").is_err());
        assert!(BandwidthRate::parse("1b").is_err());
    }

    #[test]
    fn test_minimum_boundary() {
        // 1 KB/s (1024 bytes) should pass
        let rate = BandwidthRate::parse("1kb").unwrap();
        assert_eq!(rate.bytes_per_sec, 1024);
    }

    #[test]
    fn test_parse_kb() {
        let rate = BandwidthRate::parse("500kb").unwrap();
        assert_eq!(rate.bytes_per_sec, 500 * 1024);
        assert_eq!(rate.unit, BandwidthUnit::KilobytesPerSec);
    }

    #[test]
    fn test_parse_mb() {
        let rate = BandwidthRate::parse("2mb").unwrap();
        assert_eq!(rate.bytes_per_sec, 2 * 1024 * 1024);
        assert_eq!(rate.unit, BandwidthUnit::MegabytesPerSec);
    }

    #[test]
    fn test_parse_gb() {
        let rate = BandwidthRate::parse("1gb").unwrap();
        assert_eq!(rate.bytes_per_sec, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_kbit() {
        let rate = BandwidthRate::parse("100kbit").unwrap();
        assert_eq!(rate.bytes_per_sec, (100 * 1024) / 8);
        assert_eq!(rate.unit, BandwidthUnit::KilobitsPerSec);
    }

    #[test]
    fn test_parse_with_space() {
        let rate = BandwidthRate::parse("500 kb").unwrap();
        assert_eq!(rate.bytes_per_sec, 500 * 1024);
    }

    #[test]
    fn test_reject_negative() {
        assert!(BandwidthRate::parse("-100kb").is_err());
    }

    #[test]
    fn test_reject_plus_sign() {
        assert!(BandwidthRate::parse("+100kb").is_err());
    }

    #[test]
    fn test_reject_non_digit_start() {
        assert!(BandwidthRate::parse("x10kxb").is_err());
    }

    #[test]
    fn test_reject_empty() {
        assert!(BandwidthRate::parse("").is_err());
    }

    #[test]
    fn test_reject_zero() {
        assert!(BandwidthRate::parse("0kb").is_err());
    }

    #[test]
    fn test_reject_no_unit() {
        assert!(BandwidthRate::parse("100").is_err());
    }

    #[test]
    fn test_reject_unknown_unit() {
        assert!(BandwidthRate::parse("100xkb").is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert!(format_bytes(1536).contains("KB"));
        assert!(format_bytes(1048576).contains("MB"));
    }
}
