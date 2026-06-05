// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure interface counter model and `/proc/net/dev` parser.
//!
//! This module provides types and pure functions for parsing `/proc/net/dev`-style
//! text into structured interface counters. **No** live system reads, **no**
//! filesystem access, **no** enforcement, **no** per-app attribution claims.
//!
//! Types and functions in this module are `pub(crate)` for use by tests and future
//! v2.9 phases. They are not yet referenced from `main()` — no CLI command exists
//! in v2.9 phase 2.

#![allow(dead_code)]

use std::fmt;

/// Identifies the source of parsed counter data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceLabel {
    /// Parsed from a sample `/proc/net/dev` string (test/preview mode).
    ProcNetDevSample,
    /// Parsed from a real `/proc/net/dev` read (not used in v2.9 phase 2).
    ParsedProcNetDev,
}

impl fmt::Display for SourceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceLabel::ProcNetDevSample => write!(f, "proc_net_dev_sample"),
            SourceLabel::ParsedProcNetDev => write!(f, "parsed_proc_net_dev"),
        }
    }
}

/// Per-interface network counters parsed from `/proc/net/dev`.
///
/// These counters are aggregate per-interface. They do **not** represent
/// per-app or per-PID traffic. They are cumulative since interface creation
/// (typically since boot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCounter {
    /// Network interface name (e.g., `lo`, `wlan0`, `eth0`, `wlp2s0`, `enp3s0`).
    pub interface: String,
    /// Cumulative received bytes since interface creation.
    pub rx_bytes: u64,
    /// Cumulative transmitted bytes since interface creation.
    pub tx_bytes: u64,
    /// Cumulative received packets since interface creation.
    pub rx_packets: u64,
    /// Cumulative transmitted packets since interface creation.
    pub tx_packets: u64,
}

impl InterfaceCounter {
    /// Returns the total bytes (RX + TX) for this interface.
    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes.saturating_add(self.tx_bytes)
    }

    /// Returns true if this is a loopback interface.
    pub fn is_loopback(&self) -> bool {
        self.interface == "lo"
    }
}

/// A snapshot of multiple interface counters, preserving input order.
///
/// The snapshot is read-only and observational. It does **not** claim
/// per-app attribution, enforcement, quota guard, or blocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCounterSnapshot {
    /// The interfaces parsed from the input, in input order.
    pub interfaces: Vec<InterfaceCounter>,
    /// Label identifying the data source.
    pub source: SourceLabel,
}

impl InterfaceCounterSnapshot {
    /// Returns the number of interfaces in this snapshot.
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Returns true if the snapshot contains no interfaces.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Returns the aggregate RX bytes across all interfaces in the snapshot.
    pub fn total_rx_bytes(&self) -> u64 {
        self.interfaces
            .iter()
            .map(|i| i.rx_bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// Returns the aggregate TX bytes across all interfaces in the snapshot.
    pub fn total_tx_bytes(&self) -> u64 {
        self.interfaces
            .iter()
            .map(|i| i.tx_bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// Returns the aggregate total bytes (RX + TX) across all interfaces.
    pub fn total_bytes(&self) -> u64 {
        self.total_rx_bytes().saturating_add(self.total_tx_bytes())
    }

    /// Returns aggregate bytes excluding loopback interfaces.
    pub fn total_bytes_excluding_loopback(&self) -> u64 {
        self.interfaces
            .iter()
            .filter(|i| !i.is_loopback())
            .map(|i| i.total_bytes())
            .fold(0u64, u64::saturating_add)
    }

    /// Finds an interface counter by name.
    pub fn get(&self, name: &str) -> Option<&InterfaceCounter> {
        self.interfaces.iter().find(|i| i.interface == name)
    }
}

/// Errors that can occur during `/proc/net/dev` parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A line is missing the required colon after the interface name.
    MissingColon { line_number: usize, line: String },
    /// A line has too few fields to extract RX/TX byte counters.
    TooFewFields {
        line_number: usize,
        line: String,
        field_count: usize,
    },
    /// The RX bytes field is not a valid u64.
    InvalidRxBytes {
        line_number: usize,
        line: String,
        value: String,
    },
    /// The TX bytes field is not a valid u64.
    InvalidTxBytes {
        line_number: usize,
        line: String,
        value: String,
    },
    /// A numeric field would overflow u64.
    Overflow {
        line_number: usize,
        line: String,
        field: String,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingColon { line_number, line } => {
                write!(
                    f,
                    "line {}: missing colon after interface name: {:?}",
                    line_number, line
                )
            }
            ParseError::TooFewFields {
                line_number,
                field_count,
                line,
            } => {
                write!(
                    f,
                    "line {}: too few fields ({}): {:?}",
                    line_number, field_count, line
                )
            }
            ParseError::InvalidRxBytes {
                line_number,
                value,
                line,
            } => {
                write!(
                    f,
                    "line {}: invalid RX bytes {:?}: {:?}",
                    line_number, value, line
                )
            }
            ParseError::InvalidTxBytes {
                line_number,
                value,
                line,
            } => {
                write!(
                    f,
                    "line {}: invalid TX bytes {:?}: {:?}",
                    line_number, value, line
                )
            }
            ParseError::Overflow {
                line_number,
                field,
                line,
            } => {
                write!(
                    f,
                    "line {}: {} would overflow u64: {:?}",
                    line_number, field, line
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Number of fields expected after splitting a `/proc/net/dev` data line by whitespace.
///
/// `/proc/net/dev` format:
///   `Interface: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast tx_bytes tx_packets ...`
///
/// We need at least 11 fields to extract rx_bytes (index 0), rx_packets (index 1),
/// tx_bytes (index 8), and tx_packets (index 9).
const MIN_FIELDS: usize = 11;

/// Parse a single `/proc/net/dev` data line into an `InterfaceCounter`.
///
/// The line must have the format:
/// ```text
///   iface: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast \
///           tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
/// ```
///
/// Leading whitespace and interface name whitespace are trimmed.
///
/// # Errors
///
/// Returns `ParseError` if the line is malformed: missing colon, too few fields,
/// non-numeric values, or overflow.
pub fn parse_proc_net_dev_line(line: &str) -> Result<InterfaceCounter, ParseError> {
    let trimmed = line.trim();

    // Skip empty lines.
    if trimmed.is_empty() {
        return Err(ParseError::TooFewFields {
            line_number: 0,
            line: trimmed.to_string(),
            field_count: 0,
        });
    }

    // Find the colon that separates interface name from counters.
    let colon_pos = trimmed.find(':').ok_or_else(|| ParseError::MissingColon {
        line_number: 0,
        line: trimmed.to_string(),
    })?;

    let interface = trimmed[..colon_pos].trim().to_string();
    if interface.is_empty() {
        return Err(ParseError::MissingColon {
            line_number: 0,
            line: trimmed.to_string(),
        });
    }

    // Split everything after the colon by whitespace.
    let after_colon = &trimmed[colon_pos + 1..];
    let fields: Vec<&str> = after_colon.split_whitespace().collect();

    if fields.len() < MIN_FIELDS {
        return Err(ParseError::TooFewFields {
            line_number: 0,
            line: trimmed.to_string(),
            field_count: fields.len(),
        });
    }

    // Fields after colon:
    //   0: rx_bytes    1: rx_packets   2: rx_errs    3: rx_drop
    //   4: rx_fifo     5: rx_frame     6: rx_compressed  7: rx_multicast
    //   8: tx_bytes    9: tx_packets   10: tx_errs   11: tx_drop  ...
    let rx_bytes_str = fields[0];
    let rx_packets_str = fields[1];
    let tx_bytes_str = fields[8];
    let tx_packets_str = fields[9];

    let rx_bytes = parse_u64_field(rx_bytes_str, "rx_bytes", 0, trimmed)?;
    let rx_packets = parse_u64_field(rx_packets_str, "rx_packets", 0, trimmed)?;
    let tx_bytes = parse_u64_field(tx_bytes_str, "tx_bytes", 0, trimmed)?;
    let tx_packets = parse_u64_field(tx_packets_str, "tx_packets", 0, trimmed)?;

    Ok(InterfaceCounter {
        interface,
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
    })
}

/// Parse a u64 field, returning an appropriate `ParseError` on failure.
fn parse_u64_field(
    value: &str,
    field_name: &str,
    _line_number: usize,
    line: &str,
) -> Result<u64, ParseError> {
    value.parse::<u64>().map_err(|e| {
        if matches!(
            e.kind(),
            std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
        ) {
            ParseError::Overflow {
                line_number: 0,
                line: line.to_string(),
                field: field_name.to_string(),
            }
        } else {
            // Invalid digit or empty
            match field_name {
                "rx_bytes" => ParseError::InvalidRxBytes {
                    line_number: 0,
                    line: line.to_string(),
                    value: value.to_string(),
                },
                "tx_bytes" => ParseError::InvalidTxBytes {
                    line_number: 0,
                    line: line.to_string(),
                    value: value.to_string(),
                },
                _ => ParseError::InvalidRxBytes {
                    line_number: 0,
                    line: line.to_string(),
                    value: value.to_string(),
                },
            }
        }
    })
}

/// Parse a full `/proc/net/dev` text into an `InterfaceCounterSnapshot`.
///
/// This function parses the standard `/proc/net/dev` format, which has two header
/// lines followed by per-interface data lines. Header lines are skipped
/// automatically (they contain `Inter-|` and `face` markers).
///
/// Empty input returns an empty snapshot (no error).
///
/// # Arguments
///
/// * `content` - The full text content to parse (typically from `/proc/net/dev`).
///
/// # Returns
///
/// An `InterfaceCounterSnapshot` with all successfully parsed interfaces in input
/// order, using `SourceLabel::ProcNetDevSample`.
///
/// # Errors
///
/// Returns the first `ParseError` encountered. Processing stops at the first error.
pub fn parse_proc_net_dev(content: &str) -> Result<InterfaceCounterSnapshot, ParseError> {
    let mut interfaces = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        // Skip empty lines and header lines.
        // Standard /proc/net/dev headers:
        //   Inter-|   Receive                                                  |  Transmit
        //    face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
        if trimmed.is_empty() || is_header_line(trimmed) {
            continue;
        }

        match parse_proc_net_dev_line(line) {
            Ok(counter) => interfaces.push(counter),
            Err(e) => {
                // Wrap with the actual line number for better error reporting.
                return Err(enrich_error_with_line_number(e, line_num));
            }
        }
    }

    Ok(InterfaceCounterSnapshot {
        interfaces,
        source: SourceLabel::ProcNetDevSample,
    })
}

/// Check if a line is a `/proc/net/dev` header line.
fn is_header_line(line: &str) -> bool {
    // Header lines contain pipe characters or the word "face" without a colon.
    line.contains('|') || (line.contains("face") && !line.contains(':'))
}

/// Enrich a `ParseError` with the actual line number from the full-content parse.
fn enrich_error_with_line_number(mut err: ParseError, line_number: usize) -> ParseError {
    match &mut err {
        ParseError::MissingColon { line_number: n, .. } => *n = line_number,
        ParseError::TooFewFields { line_number: n, .. } => *n = line_number,
        ParseError::InvalidRxBytes { line_number: n, .. } => *n = line_number,
        ParseError::InvalidTxBytes { line_number: n, .. } => *n = line_number,
        ParseError::Overflow { line_number: n, .. } => *n = line_number,
    }
    err
}

/// Render an `InterfaceCounterSnapshot` as a human-readable summary string.
///
/// The output clearly states:
/// - "read-only parsed sample/model" (observational, not enforcement)
/// - "aggregate interface traffic" (not per-app)
/// - "no enforcement", "no quota guard", "no per-app attribution"
///
/// # Example output
///
/// ```text
/// Zelynic v2.9 interface counter snapshot (read-only parsed sample)
/// Source: proc_net_dev_sample
///
/// Interface counters (aggregate interface traffic, not per-app):
///   lo:        RX 1234 bytes (10 packets)  TX 5678 bytes (20 packets)  [loopback]
///   wlan0:     RX 1324567890 bytes (1234567 packets)  TX 356789012 bytes (345678 packets)
///
/// Totals (excluding loopback):
///   RX: 1324567890 bytes  TX: 356789012 bytes  Total: 1681357902 bytes
///
/// Note: read-only parsed sample/model. No enforcement. No quota guard. No per-app attribution.
/// ```
pub fn render_interface_counter_snapshot(snapshot: &InterfaceCounterSnapshot) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 interface counter snapshot (read-only parsed sample)\n");
    out.push_str(&format!("Source: {}\n", snapshot.source));
    out.push('\n');

    if snapshot.is_empty() {
        out.push_str("No interface counters parsed.\n");
        out.push('\n');
    } else {
        out.push_str("Interface counters (aggregate interface traffic, not per-app):\n");
        for iface in &snapshot.interfaces {
            let loopback_tag = if iface.is_loopback() {
                " [loopback]"
            } else {
                ""
            };
            out.push_str(&format!(
                "  {:16} RX {:>12} bytes ({:>10} packets)  TX {:>12} bytes ({:>10} packets){}\n",
                iface.interface,
                iface.rx_bytes,
                iface.rx_packets,
                iface.tx_bytes,
                iface.tx_packets,
                loopback_tag,
            ));
        }
        out.push('\n');
    }

    // Totals excluding loopback
    let total_rx = snapshot
        .interfaces
        .iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.rx_bytes)
        .fold(0u64, u64::saturating_add);
    let total_tx = snapshot
        .interfaces
        .iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.tx_bytes)
        .fold(0u64, u64::saturating_add);
    let grand_total = total_rx.saturating_add(total_tx);

    out.push_str("Totals (excluding loopback):\n");
    out.push_str(&format!(
        "  RX: {} bytes  TX: {} bytes  Total: {} bytes\n",
        total_rx, total_tx, grand_total
    ));
    out.push('\n');

    out.push_str(
        "Note: read-only parsed sample/model. No enforcement. No quota guard. No per-app attribution.\n",
    );

    out
}
