// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Delta render: text rendering for the live two-sample delta output.
//!
//! This module renders a `UsageDeltaOutput` for the live two-sample delta CLI,
//! producing human-readable text output with comprehensive safety disclaimers.

use crate::accounting::UsageDeltaOutput;
use crate::commands::usage::DEFAULT_DELTA_WAIT_DURATION;

/// Render a `UsageDeltaOutput` for the live two-sample delta CLI.
///
/// This render function replaces the phase-10 model-only renderer with
/// live-appropriate text that indicates an actual two-sample delta was
/// performed from `/proc/net/dev`.
///
/// The output includes comprehensive safety disclaimers matching the
/// phase-12 requirements: two-sample read-only delta, source path,
/// interface-level only, all denial statements, counter reset warnings.
pub(crate) fn render_usage_delta_live(output: &UsageDeltaOutput) -> String {
    let mut out = String::new();

    out.push_str("zelynic usage --sample --delta -- live read-only two-sample delta\n");
    out.push_str("Source: /proc/net/dev (two reads)\n");
    out.push_str(&format!(
        "Delta wait: {}s between samples\n",
        DEFAULT_DELTA_WAIT_DURATION.as_secs()
    ));
    out.push('\n');

    // Attribution and scope
    out.push_str("Attribution: interface-level only (not per-app attribution)\n");
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

    // Comprehensive safety disclaimers (all required by phase 12)
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - two-sample read-only delta\n");
    out.push_str("  - source path: /proc/net/dev\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - no quota enforcement active\n");
    out.push_str("  - no network blocking active\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");
    out.push_str("  - no ledger persistence performed\n");
    out.push_str("  - no eBPF used\n");
    out.push_str("  - no cgroup mutation\n");
    out.push_str("  - no PID movement\n");
    out.push_str("  - filesystem write not performed\n");
    out.push_str("  - state mutation not performed\n");
    out.push_str("  - counters may reset after reboot or interface reset\n");
    out.push_str("  - delta may be incomplete if counter reset/decrease occurred\n");

    out
}
