use anyhow::{bail, Context, Result};
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

/// Parsed bandwidth rate value with its unit and raw string representation.
#[derive(Debug, Clone)]
pub struct BandwidthRate {
    /// Value in bytes per second (canonical form)
    pub bytes_per_sec: u64,
    /// The numeric value as parsed
    pub value: u64,
    /// The unit that was parsed
    pub unit: BandwidthUnit,
    /// The original string that was parsed
    pub raw: String,
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
    /// BandwidthRate::parse("100byte") // 100 B/s
    /// BandwidthRate::parse("2gb")    // 2 GB/s
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();

        // Special keyword: "only" means no limit for this direction
        if trimmed.eq_ignore_ascii_case("only") {
            bail!("'only' is not a rate value; it is a flag meaning 'limit only this direction'");
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
                "invalid numeric value '{}' in bandwidth rate '{}'",
                value_str, input
            )
        })?;

        if value == 0 {
            bail!("bandwidth rate must be greater than zero, got '{}'", input);
        }

        let unit = BandwidthUnit::from_str_unit(unit_str).with_context(|| {
            format!(
                "unknown bandwidth unit '{}' in '{}'. Supported: byte/bs, kb, mb, gb, kbit, mbit, gbit",
                unit_str, input
            )
        })?;

        let bytes_per_sec = value * unit.bytes_multiplier();

        Ok(Self {
            bytes_per_sec,
            value,
            unit,
            raw: input.to_string(),
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
        let rate = BandwidthRate::parse("100byte").unwrap();
        assert_eq!(rate.bytes_per_sec, 100);
        assert_eq!(rate.unit, BandwidthUnit::BytesPerSec);
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
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert!(format_bytes(1536).contains("KB"));
        assert!(format_bytes(1048576).contains("MB"));
    }
}
