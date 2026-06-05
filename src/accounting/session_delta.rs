// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Read-only session delta model for v2.9 Network Accounting Lab.
//!
//! This module computes network usage differences between two parsed interface
//! counter snapshots. It is a **pure model** — no live system reads, **no**
//! filesystem access, **no** enforcement, **no** quota management, **no**
//! network blocking, **no** eBPF, **no** PID movement, **no** cgroup writes.
//!
//! # Safety
//!
//! - No live `/proc/net/dev` reads — operates on in-memory snapshots only.
//! - No live sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Counter Reset Behavior
//!
//! If a counter in the end snapshot is lower than in the start snapshot,
//! this indicates a counter reset (e.g., interface down/up, driver reload,
//! or reboot). The delta for that counter is reported as **0** with an
//! explicit warning. No negative values are ever produced.
//!
//! # Honesty
//!
//! - Session deltas are interface-level only, **not** per-app attribution.
//! - This module does **not** claim per-app attribution.
//! - This module does **not** claim enforcement, quota guard, or blocking.
//! - When counter resets are detected, the output explicitly states that
//!   exact usage is unknown for that counter.

#![allow(dead_code)]

use super::interface_counters::InterfaceCounterSnapshot;

/// Warning about a counter reset/decrease detected during delta computation.
///
/// Produced when a counter value in the end snapshot is lower than the
/// corresponding counter in the start snapshot, indicating a counter reset
/// (e.g., interface down/up, reboot, driver reload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterResetWarning {
    /// Interface name where the reset was detected.
    pub interface: String,
    /// Counter field name ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets").
    pub counter_field: String,
    /// Counter value at the start snapshot.
    pub start_value: u64,
    /// Counter value at the end snapshot (lower than start).
    pub end_value: u64,
}

impl std::fmt::Display for CounterResetWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "counter reset/decrease on '{}' field '{}': start={} end={} \
             (delta reported as 0 \u{2014} exact usage unknown)",
            self.interface, self.counter_field, self.start_value, self.end_value
        )
    }
}

/// Per-interface delta row in a session delta computation.
///
/// Each row represents the usage difference for one interface between
/// the start and end snapshots. Fields are `0` when the interface is
/// missing from one snapshot or when a counter reset is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDeltaRow {
    /// Network interface name.
    pub interface: String,
    /// Delta RX bytes (end - start, or 0 if reset/missing).
    pub rx_delta_bytes: u64,
    /// Delta TX bytes (end - start, or 0 if reset/missing).
    pub tx_delta_bytes: u64,
    /// Combined delta bytes (RX + TX, saturating).
    pub combined_delta_bytes: u64,
    /// Delta RX packets (end - start, or 0 if reset/missing).
    pub rx_delta_packets: u64,
    /// Delta TX packets (end - start, or 0 if reset/missing).
    pub tx_delta_packets: u64,
    /// True if RX byte counter decreased (reset detected).
    pub rx_reset: bool,
    /// True if TX byte counter decreased (reset detected).
    pub tx_reset: bool,
    /// True if RX packet counter decreased (reset detected).
    pub rx_packets_reset: bool,
    /// True if TX packet counter decreased (reset detected).
    pub tx_packets_reset: bool,
    /// True if interface was present in the start snapshot.
    pub present_in_start: bool,
    /// True if interface was present in the end snapshot.
    pub present_in_end: bool,
}

/// Session delta model: usage differences between two counter snapshots.
///
/// This is a **read-only, model-only** computation. It takes two
/// `InterfaceCounterSnapshot` values and produces per-interface deltas
/// with overflow-safe saturating totals and explicit reset warnings.
///
/// No enforcement, no quota management, no network blocking, no per-app
/// attribution. The deltas represent interface-level usage changes only.
///
/// # Interface Union
///
/// The delta covers the union of all interfaces from both snapshots:
/// - Present in both: normal delta computation.
/// - Start only: row with all deltas = 0, `present_in_end = false`.
/// - End only: row with all deltas = 0, `present_in_start = false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDelta {
    /// Per-interface delta rows in deterministic order
    /// (start interfaces first, then end-only interfaces).
    pub rows: Vec<SessionDeltaRow>,
    /// Warnings about counter resets/decreases detected.
    pub warnings: Vec<CounterResetWarning>,
    /// Total RX delta bytes across all interfaces (saturating).
    pub total_rx_delta_bytes: u64,
    /// Total TX delta bytes across all interfaces (saturating).
    pub total_tx_delta_bytes: u64,
    /// Total combined delta bytes (saturating).
    pub total_combined_delta_bytes: u64,
    /// Number of interface rows.
    pub interface_count: usize,
    /// Source label (combination of start and end source labels).
    pub source_label: String,
    /// Attribution scope: always "interface-level only".
    pub attribution_scope: String,
    /// Enforcement status: always "inactive/not implemented".
    pub enforcement_status: String,
    /// Read-only flag: always "model-only".
    pub read_only: String,
}

/// Compute safe delta for a single u64 counter value.
///
/// - If `end >= start`: returns `(end - start, false)`.
/// - If `end < start`: returns `(0, true)` — counter reset detected.
///
/// This function never produces negative values.
#[inline]
fn safe_delta(start: u64, end: u64) -> (u64, bool) {
    if end >= start {
        (end - start, false)
    } else {
        (0, true)
    }
}

/// Build a session delta from two interface counter snapshots.
///
/// Computes per-interface deltas for RX/TX bytes and packets with
/// deterministic ordering, overflow-safe totals, and explicit reset
/// warnings. The union of all interfaces from both snapshots is used.
/// Start interfaces appear first (in input order), followed by end-only
/// interfaces (in input order).
///
/// # Arguments
///
/// * `start` - The earlier counter snapshot.
/// * `end` - The later counter snapshot.
///
/// # Returns
///
/// A `SessionDelta` with per-interface rows, reset warnings, and
/// saturating totals.
pub fn build_session_delta(
    start: &InterfaceCounterSnapshot,
    end: &InterfaceCounterSnapshot,
) -> SessionDelta {
    let mut rows = Vec::new();
    let mut warnings = Vec::new();

    // Collect all unique interface names preserving order:
    // start interfaces first, then end-only interfaces.
    let mut seen = std::collections::HashSet::new();
    let mut ordered_names: Vec<String> = Vec::new();

    for iface in &start.interfaces {
        if seen.insert(iface.interface.clone()) {
            ordered_names.push(iface.interface.clone());
        }
    }
    for iface in &end.interfaces {
        if seen.insert(iface.interface.clone()) {
            ordered_names.push(iface.interface.clone());
        }
    }

    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;

    for name in &ordered_names {
        let start_iface = start.get(name);
        let end_iface = end.get(name);

        let present_in_start = start_iface.is_some();
        let present_in_end = end_iface.is_some();

        // Compute RX bytes delta
        let (rx_delta, rx_reset) = match (start_iface, end_iface) {
            (Some(s), Some(e)) => {
                let (delta, reset) = safe_delta(s.rx_bytes, e.rx_bytes);
                if reset {
                    warnings.push(CounterResetWarning {
                        interface: name.clone(),
                        counter_field: "rx_bytes".to_string(),
                        start_value: s.rx_bytes,
                        end_value: e.rx_bytes,
                    });
                }
                (delta, reset)
            }
            _ => (0, false), // Missing from one snapshot: delta = 0
        };

        // Compute TX bytes delta
        let (tx_delta, tx_reset) = match (start_iface, end_iface) {
            (Some(s), Some(e)) => {
                let (delta, reset) = safe_delta(s.tx_bytes, e.tx_bytes);
                if reset {
                    warnings.push(CounterResetWarning {
                        interface: name.clone(),
                        counter_field: "tx_bytes".to_string(),
                        start_value: s.tx_bytes,
                        end_value: e.tx_bytes,
                    });
                }
                (delta, reset)
            }
            _ => (0, false),
        };

        // Compute RX packets delta
        let (rx_pkt_delta, rx_pkt_reset) = match (start_iface, end_iface) {
            (Some(s), Some(e)) => {
                let (delta, reset) = safe_delta(s.rx_packets, e.rx_packets);
                if reset {
                    warnings.push(CounterResetWarning {
                        interface: name.clone(),
                        counter_field: "rx_packets".to_string(),
                        start_value: s.rx_packets,
                        end_value: e.rx_packets,
                    });
                }
                (delta, reset)
            }
            _ => (0, false),
        };

        // Compute TX packets delta
        let (tx_pkt_delta, tx_pkt_reset) = match (start_iface, end_iface) {
            (Some(s), Some(e)) => {
                let (delta, reset) = safe_delta(s.tx_packets, e.tx_packets);
                if reset {
                    warnings.push(CounterResetWarning {
                        interface: name.clone(),
                        counter_field: "tx_packets".to_string(),
                        start_value: s.tx_packets,
                        end_value: e.tx_packets,
                    });
                }
                (delta, reset)
            }
            _ => (0, false),
        };

        let combined = rx_delta.saturating_add(tx_delta);

        total_rx = total_rx.saturating_add(rx_delta);
        total_tx = total_tx.saturating_add(tx_delta);

        rows.push(SessionDeltaRow {
            interface: name.clone(),
            rx_delta_bytes: rx_delta,
            tx_delta_bytes: tx_delta,
            combined_delta_bytes: combined,
            rx_delta_packets: rx_pkt_delta,
            tx_delta_packets: tx_pkt_delta,
            rx_reset,
            tx_reset,
            rx_packets_reset: rx_pkt_reset,
            tx_packets_reset: tx_pkt_reset,
            present_in_start,
            present_in_end,
        });
    }

    let total_combined = total_rx.saturating_add(total_tx);
    let source_label = format!("session_delta(start={}, end={})", start.source, end.source);

    SessionDelta {
        interface_count: rows.len(),
        total_rx_delta_bytes: total_rx,
        total_tx_delta_bytes: total_tx,
        total_combined_delta_bytes: total_combined,
        rows,
        warnings,
        source_label,
        attribution_scope: "interface-level only".to_string(),
        enforcement_status: "inactive/not implemented".to_string(),
        read_only: "model-only".to_string(),
    }
}

/// Render a session delta as a human-readable string.
///
/// The output includes comprehensive safety disclaimers:
/// - "read-only session delta model"
/// - "interface-level only"
/// - "not per-app attribution"
/// - "no quota enforcement active"
/// - "no network blocking active"
/// - "no limiter attach performed"
/// - "no nft/tc/Zelynic state mutation performed"
/// - "no live /proc or sysfs read performed"
/// - Counter reset/decrease warnings if present
pub fn render_session_delta(delta: &SessionDelta) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 session delta (read-only session delta model)\n");
    out.push_str(&format!("Source: {}\n", delta.source_label));
    out.push('\n');

    if delta.rows.is_empty() {
        out.push_str("No interface deltas computed.\n");
        out.push('\n');
    } else {
        out.push_str("Session delta (interface-level only, not per-app attribution):\n");
        out.push_str(&format!(
            "  {:16} {:>14} {:>14} {:>18} {:>12} {:>12}\n",
            "Interface", "RX delta", "TX delta", "Combined delta", "RX pkt", "TX pkt"
        ));
        for row in &delta.rows {
            let mut tags = Vec::new();
            if row.rx_reset || row.tx_reset || row.rx_packets_reset || row.tx_packets_reset {
                tags.push("[COUNTER RESET]");
            }
            if !row.present_in_start {
                tags.push("[start-missing]");
            } else if !row.present_in_end {
                tags.push("[end-missing]");
            }
            let tag_str = if tags.is_empty() {
                String::new()
            } else {
                format!(" {}", tags.join(""))
            };

            out.push_str(&format!(
                "  {:16} {:>12} B {:>12} B {:>14} B {:>12} {:>12}{}\n",
                row.interface,
                row.rx_delta_bytes,
                row.tx_delta_bytes,
                row.combined_delta_bytes,
                row.rx_delta_packets,
                row.tx_delta_packets,
                tag_str,
            ));
        }
        out.push('\n');
    }

    // Totals
    out.push_str("Session totals (saturating, overflow-safe):\n");
    out.push_str(&format!(
        "  RX: {} bytes  TX: {} bytes  Combined: {} bytes\n",
        delta.total_rx_delta_bytes, delta.total_tx_delta_bytes, delta.total_combined_delta_bytes
    ));
    out.push_str(&format!("  Interfaces: {}\n", delta.interface_count));
    out.push('\n');

    // Warnings
    if !delta.warnings.is_empty() {
        out.push_str("Counter reset/decrease warnings:\n");
        for w in &delta.warnings {
            out.push_str(&format!("  {}\n", w));
        }
        out.push('\n');
    }

    // Attribution and enforcement
    out.push_str(&format!(
        "Attribution scope: {} (this is not per-app attribution)\n",
        delta.attribution_scope
    ));
    out.push_str(&format!(
        "Enforcement status: {} (no quota enforcement active)\n",
        delta.enforcement_status
    ));
    out.push_str(&format!("Read-only: {}\n", delta.read_only));
    out.push('\n');

    // Comprehensive safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - read-only session delta model\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - no quota enforcement active\n");
    out.push_str("  - no network blocking active\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");
    out.push_str("  - no live /proc or sysfs read performed\n");

    out
}
