// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure delta output model and renderer for future `zelynic usage --sample --delta` (v3.0 phase 10).
//!
//! This module provides a pure Rust model for rendering delta output from an existing
//! `SessionDelta`. It builds a structured delta output representation and renders it
//! with comprehensive honesty labels and safety disclaimers.
//!
//! This is a **model-only, render-only** layer — no CLI flag is registered, no live
//! filesystem reads are performed, no interval sampling is implemented, no loop/watch
//! mode exists. All data comes from an existing `SessionDelta` passed by the caller.
//!
//! # Safety
//!
//! - No live `/proc/net/dev` reads — operates on in-memory `SessionDelta` only.
//! - No live sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//! - No eBPF, no quota enforcement, no network blocking, no limiter attach.
//! - No nft/tc mutation, no state mutation, no PID movement.
//! - No cgroup.procs write, no /sys/fs/cgroup access.
//! - No filesystem writes, no ledger persistence.
//! - No interval sampling, no loop/watch mode.
//!
//! # Honesty
//!
//! - Delta output is interface-level only, **not** per-app attribution.
//! - No quota enforcement is active.
//! - No network blocking is active.
//! - No limiter attach was performed.
//! - No nft/tc/Zelynic state mutation was performed.
//! - No ledger persistence was performed.
//! - No eBPF was used.
//! - No cgroup mutation was performed.
//! - No PID movement was performed.
//! - No filesystem write was performed.
//! - No state mutation was performed.
//! - Delta may be incomplete if counter reset/decrease occurred.

#![allow(dead_code)]

use super::session_delta::{CounterResetWarning, SessionDelta};

/// Per-interface delta output row for the future `usage --sample --delta` display.
///
/// This is a display-oriented wrapper around `SessionDeltaRow` with human-readable
/// formatting fields. It does not perform any live system reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageDeltaRow {
    /// Network interface name.
    pub interface: String,
    /// Delta RX bytes (raw).
    pub rx_delta_bytes: u64,
    /// Delta TX bytes (raw).
    pub tx_delta_bytes: u64,
    /// Combined delta bytes (raw, saturating).
    pub combined_delta_bytes: u64,
    /// Human-readable RX delta bytes.
    pub rx_delta_human: String,
    /// Human-readable TX delta bytes.
    pub tx_delta_human: String,
    /// Human-readable combined delta bytes.
    pub combined_delta_human: String,
    /// True if any counter reset was detected on this interface.
    pub has_reset: bool,
}

/// Pure delta output model for future `zelynic usage --sample --delta`.
///
/// This is a **model-only** structure built from an existing `SessionDelta`.
/// It contains all fields needed for rendering the delta output with
/// comprehensive honesty labels. No CLI flag is wired to this model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageDeltaOutput {
    /// Schema/source label for future usage delta.
    pub schema_source_label: String,
    /// Source label of the start snapshot.
    pub start_source_label: String,
    /// Source label of the end snapshot.
    pub end_source_label: String,
    /// Per-interface delta rows in deterministic order.
    pub rows: Vec<UsageDeltaRow>,
    /// Total RX delta bytes across all interfaces (saturating).
    pub total_rx_delta_bytes: u64,
    /// Total TX delta bytes across all interfaces (saturating).
    pub total_tx_delta_bytes: u64,
    /// Total combined delta bytes (saturating).
    pub total_combined_delta_bytes: u64,
    /// Number of interface rows.
    pub interface_count: usize,
    /// Counter reset/decrease warnings.
    pub warnings: Vec<CounterResetWarning>,
    /// Reset/decrease warning count.
    pub warning_count: usize,
}

/// Build a `UsageDeltaOutput` from an existing `SessionDelta`.
///
/// This function transforms the pure `SessionDelta` model into a display-oriented
/// `UsageDeltaOutput` with human-readable formatting. It does not perform any live
/// system reads, interval sampling, or CLI wiring.
///
/// # Arguments
///
/// * `session_delta` - An existing `SessionDelta` computed from two snapshots.
///
/// # Returns
///
/// A `UsageDeltaOutput` ready for rendering.
pub fn build_usage_delta_from_session_delta(session_delta: &SessionDelta) -> UsageDeltaOutput {
    let rows: Vec<UsageDeltaRow> = session_delta
        .rows
        .iter()
        .map(|row| {
            let has_reset =
                row.rx_reset || row.tx_reset || row.rx_packets_reset || row.tx_packets_reset;
            UsageDeltaRow {
                interface: row.interface.clone(),
                rx_delta_bytes: row.rx_delta_bytes,
                tx_delta_bytes: row.tx_delta_bytes,
                combined_delta_bytes: row.combined_delta_bytes,
                rx_delta_human: format_bytes_human(row.rx_delta_bytes),
                tx_delta_human: format_bytes_human(row.tx_delta_bytes),
                combined_delta_human: format_bytes_human(row.combined_delta_bytes),
                has_reset,
            }
        })
        .collect();

    // Extract start/end source labels from the session_delta source_label.
    // The source_label format is "session_delta(start=X, end=Y)".
    let start_source_label = "model-only (no live sample)".to_string();
    let end_source_label = "model-only (no live sample)".to_string();

    UsageDeltaOutput {
        schema_source_label: "usage_delta_output_model".to_string(),
        start_source_label,
        end_source_label,
        total_rx_delta_bytes: session_delta.total_rx_delta_bytes,
        total_tx_delta_bytes: session_delta.total_tx_delta_bytes,
        total_combined_delta_bytes: session_delta.total_combined_delta_bytes,
        interface_count: session_delta.interface_count,
        warnings: session_delta.warnings.clone(),
        warning_count: session_delta.warnings.len(),
        rows,
    }
}

/// Render a `UsageDeltaOutput` as a human-readable string.
///
/// The output includes comprehensive safety disclaimers:
/// - Future delta output model only (no CLI flag enabled yet)
/// - No live second sample was taken by this model
/// - Interface-level only (not per-app attribution)
/// - No quota enforcement active
/// - No network blocking active
/// - No limiter attach performed
/// - No nft/tc/Zelynic state mutation performed
/// - No ledger persistence performed
/// - No eBPF used
/// - No cgroup mutation performed
/// - No PID movement performed
/// - Filesystem write not performed
/// - State mutation not performed
/// - Counter reset/decrease warnings if present
/// - Delta may be incomplete if counter reset/decrease occurred
pub fn render_usage_delta(output: &UsageDeltaOutput) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v3.0 usage delta (future delta output model only)\n");
    out.push_str("NOTE: --delta CLI flag is not enabled yet\n");
    out.push_str("NOTE: no live second sample was taken by this model\n");
    out.push('\n');

    // Attribution and enforcement
    out.push_str("Attribution: interface-level only (not per-app attribution)\n");
    out.push_str("Source: future usage delta output model\n");
    out.push('\n');

    if output.rows.is_empty() {
        out.push_str("No interface deltas computed.\n");
        out.push('\n');
    } else {
        out.push_str("Interface delta (interface-level only, not per-app attribution):\n");
        out.push_str(&format!(
            "  {:16} {:>14} {:>14} {:>18}\n",
            "Interface", "RX delta", "TX delta", "Combined delta"
        ));
        for row in &output.rows {
            let reset_tag = if row.has_reset {
                " [COUNTER RESET]"
            } else {
                ""
            };
            out.push_str(&format!(
                "  {:16} {:>12} B {:>12} B {:>14} B{}\n",
                row.interface,
                row.rx_delta_bytes,
                row.tx_delta_bytes,
                row.combined_delta_bytes,
                reset_tag,
            ));
        }
        out.push('\n');
    }

    // Totals
    out.push_str("Delta totals (saturating, overflow-safe):\n");
    out.push_str(&format!(
        "  RX: {} bytes  TX: {} bytes  Combined: {} bytes\n",
        output.total_rx_delta_bytes, output.total_tx_delta_bytes, output.total_combined_delta_bytes
    ));
    out.push_str(&format!("  Interfaces: {}\n", output.interface_count));
    out.push('\n');

    // Warnings
    if !output.warnings.is_empty() {
        out.push_str("Counter reset/decrease warnings:\n");
        for w in &output.warnings {
            out.push_str(&format!("  {}\n", w));
        }
        out.push('\n');
        out.push_str(
            "WARNING: delta may be incomplete if interface counter reset/decrease occurred\n",
        );
        out.push('\n');
    }

    // Comprehensive safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - future delta output model only (no CLI flag enabled yet)\n");
    out.push_str("  - no live second sample was taken by this model\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - no quota enforcement active\n");
    out.push_str("  - no network blocking active\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");
    out.push_str("  - no ledger persistence performed\n");
    out.push_str("  - no eBPF used\n");
    out.push_str("  - no cgroup mutation performed\n");
    out.push_str("  - no PID movement performed\n");
    out.push_str("  - filesystem write not performed\n");
    out.push_str("  - state mutation not performed\n");
    out.push_str("  - counters may reset after reboot or interface reset\n");

    out
}

/// Format a byte count as a human-readable string using binary prefixes (IEC).
///
/// Reuses the same formatting logic as `usage_preview::format_bytes_human`.
/// Uses saturating arithmetic internally to avoid overflow during division.
///
/// # Format
///
/// - 0 → "0 B"
/// - < 1024 → "X B"
/// - < 1024^2 → "X.XX KiB"
/// - < 1024^3 → "X.XX MiB"
/// - < 1024^4 → "X.XX GiB"
/// - >= 1024^4 → "X.XX TiB"
fn format_bytes_human(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes < KIB {
        format!("{} B", bytes)
    } else if bytes < MIB {
        let val = bytes as f64 / KIB as f64;
        format!("{:.2} KiB", val)
    } else if bytes < GIB {
        let val = bytes as f64 / MIB as f64;
        format!("{:.2} MiB", val)
    } else if bytes < TIB {
        let val = bytes as f64 / GIB as f64;
        format!("{:.2} GiB", val)
    } else {
        let val = bytes as f64 / TIB as f64;
        format!("{:.2} TiB", val)
    }
}
