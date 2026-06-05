// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Read-only usage preview renderer for v2.9 Network Accounting Lab.
//!
//! This module provides a display contract for the future `zelynic usage` command.
//! It builds a structured usage preview from an `InterfaceCounterSnapshot` and
//! renders it with human-readable byte formatting and comprehensive honesty labels.
//!
//! **No** live system reads, **no** filesystem access, **no** CLI command,
//! **no** enforcement, **no** per-app attribution claims.

#![allow(dead_code)]

use super::interface_counters::InterfaceCounterSnapshot;

/// A per-interface row in the usage preview, with human-readable formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsagePreviewRow {
    /// Network interface name.
    pub interface: String,
    /// Cumulative received bytes (raw).
    pub rx_bytes: u64,
    /// Cumulative transmitted bytes (raw).
    pub tx_bytes: u64,
    /// Combined RX + TX bytes (raw, saturating).
    pub total_bytes: u64,
    /// Human-readable RX bytes (e.g., "1.23 GiB").
    pub rx_human: String,
    /// Human-readable TX bytes.
    pub tx_human: String,
    /// Human-readable combined bytes.
    pub total_human: String,
    /// Whether this is a loopback interface.
    pub is_loopback: bool,
}

/// A read-only usage preview built from an `InterfaceCounterSnapshot`.
///
/// This is a **display contract** for the future `zelynic usage` command.
/// It does **not** claim per-app attribution, enforcement, quota guard, or blocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsagePreview {
    /// Aggregate RX bytes across all interfaces (raw).
    pub total_rx_bytes: u64,
    /// Aggregate TX bytes across all interfaces (raw).
    pub total_tx_bytes: u64,
    /// Aggregate combined bytes (raw, saturating).
    pub total_combined_bytes: u64,
    /// Number of interfaces in the preview.
    pub interface_count: usize,
    /// Per-interface rows in input order.
    pub rows: Vec<UsagePreviewRow>,
    /// Data source label.
    pub source_label: String,
    /// Attribution scope: always "interface-only" — never per-app.
    pub attribution_scope: String,
    /// Enforcement status: always "inactive" — never enforced.
    pub enforcement_status: String,
}

/// Build a usage preview from an interface counter snapshot.
///
/// Uses saturating arithmetic for all totals to avoid overflow panics.
/// The preview is read-only and observational: it does not trigger any
/// enforcement, blocking, or state mutation.
pub fn build_usage_preview(snapshot: &InterfaceCounterSnapshot) -> UsagePreview {
    let mut rows = Vec::with_capacity(snapshot.interfaces.len());

    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;

    for iface in &snapshot.interfaces {
        let rx = iface.rx_bytes;
        let tx = iface.tx_bytes;
        let combined = rx.saturating_add(tx);

        total_rx = total_rx.saturating_add(rx);
        total_tx = total_tx.saturating_add(tx);

        rows.push(UsagePreviewRow {
            interface: iface.interface.clone(),
            rx_bytes: rx,
            tx_bytes: tx,
            total_bytes: combined,
            rx_human: format_bytes_human(rx),
            tx_human: format_bytes_human(tx),
            total_human: format_bytes_human(combined),
            is_loopback: iface.is_loopback(),
        });
    }

    let total_combined = total_rx.saturating_add(total_tx);

    UsagePreview {
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
        total_combined_bytes: total_combined,
        interface_count: rows.len(),
        rows,
        source_label: snapshot.source.to_string(),
        attribution_scope: "interface-only".to_string(),
        enforcement_status: "inactive/not implemented".to_string(),
    }
}

/// Render a usage preview as a human-readable string.
///
/// The output includes comprehensive honesty labels:
/// - "read-only parsed snapshot/model"
/// - "interface-level only"
/// - "not per-app attribution"
/// - "no quota enforcement active"
/// - "no network blocking active"
/// - "no limiter attach performed"
/// - "no nft/tc/Zelynic state mutation performed"
/// - "no live /proc or sysfs read" (for sample data)
pub fn render_usage_preview(preview: &UsagePreview) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 usage preview (read-only parsed snapshot/model)\n");
    out.push_str(&format!("Source: {}\n", preview.source_label));
    out.push('\n');

    if preview.rows.is_empty() {
        out.push_str("No interfaces found in parsed snapshot.\n");
        out.push('\n');
    } else {
        out.push_str("Interface usage (interface-level only, not per-app attribution):\n");
        out.push_str(&format!(
            "  {:16} {:>12} {:>12} {:>14}\n",
            "Interface", "RX", "TX", "Total"
        ));
        for row in &preview.rows {
            let loopback_tag = if row.is_loopback { " [lo]" } else { "" };
            out.push_str(&format!(
                "  {:16} {:>12} {:>12} {:>14}{}\n",
                row.interface, row.rx_human, row.tx_human, row.total_human, loopback_tag,
            ));
        }
        out.push('\n');
    }

    // Aggregate totals
    out.push_str("Aggregate totals (all interfaces):\n");
    out.push_str(&format!(
        "  RX: {} ({})  TX: {} ({})  Total: {} ({})\n",
        format_bytes_human(preview.total_rx_bytes),
        preview.total_rx_bytes,
        format_bytes_human(preview.total_tx_bytes),
        preview.total_tx_bytes,
        format_bytes_human(preview.total_combined_bytes),
        preview.total_combined_bytes,
    ));
    out.push('\n');

    out.push_str(&format!(
        "Attribution scope: {} (this is not per-app attribution)\n",
        preview.attribution_scope
    ));
    out.push_str(&format!(
        "Enforcement status: {} (no quota enforcement active)\n",
        preview.enforcement_status
    ));
    out.push('\n');

    // Comprehensive safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - read-only parsed snapshot/model\n");
    out.push_str("  - no quota enforcement active\n");
    out.push_str("  - no network blocking active\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");
    out.push_str("  - no live /proc or sysfs read performed\n");
    out.push_str("  - no per-app attribution (interface-level only)\n");

    out
}

/// Format a byte count as a human-readable string using binary prefixes (IEC).
///
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
pub fn format_bytes_human(bytes: u64) -> String {
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
