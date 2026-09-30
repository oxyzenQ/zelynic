// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The bypass audit's report surface (NIGHT-upgrade-charger-core-1-a):
//! the machine-scope shadow section the eagle-eyes --depth report
//! prints after the per-target blocks — the honest one-glance answer
//! to "did anything on this machine move bytes the cgroup_skb hooks
//! never saw".
//!
//! Composition is PURE: the handler composes the [`ShadowAudit`]
//! value (src/ebpf/bypass.rs — the sysfs reads and the verdict
//! bands); this module turns it into the report's section lines. The
//! compact-clean shape keeps a healthy machine to one line (the
//! check RAN and agrees — the fact the owner asked for), while a
//! flagged window expands to the full block: both sides' numbers,
//! the shadow's share, the likely bypass paths, and the triage
//! commands — a report that flags without telling the owner what to
//! do next just moves the anxiety. The JSON twin
//! (`depth_json::bypass_audit_json`) carries the same fields for
//! scripts.

use crate::ebpf::bypass::{shadow_percent, ShadowAudit, ShadowVerdict};
use crate::ebpf::limiter::{format_bytes, format_rate};
use crate::output::warn_bold;

use super::report::kv;

/// The one-side figure pair the block rows print: window bytes and
/// the derived rate, "tx 4.8 MB (1.6 MB/s)" (pure).
fn side_figures(bytes: u64, window_secs: u64) -> String {
    let rate = format_rate(bytes / window_secs.max(1));
    format!("{} ({rate})", format_bytes(bytes))
}

/// Render the bypass audit section (pure). One line when clean, the
/// full block when a side exceeded its thresholds, one line when the
/// window ran but the interface counters could not be read — every
/// verdict says what it is, none is silent.
#[must_use]
pub fn bypass_section(audit: &ShadowAudit) -> Vec<String> {
    let mut lines = Vec::new();
    if !audit.measured {
        lines.push(kv(
            "bypass audit",
            "unavailable — interface counters unreadable (the traffic window measured fine)",
        ));
        return lines;
    }
    match audit.verdict {
        ShadowVerdict::Clean => {
            lines.push(kv(
                "bypass audit",
                &format!(
                    "clean — cgroup hooks and interfaces agree \
                     (tx shadow {}%, rx shadow {}%)",
                    shadow_percent(audit.shadow_tx, audit.nic_tx),
                    shadow_percent(audit.shadow_rx, audit.nic_rx)
                ),
            ));
        }
        ShadowVerdict::Unavailable => {
            // Unreachable with measured == true (the constructor
            // pairs them); kept total anyway so a future caller
            // cannot render an unnamed verdict.
            lines.push(kv("bypass audit", "unavailable"));
        }
        verdict => {
            lines.push(warn_bold(&format!(
                "  bypass audit:   BYPASS-SHAPED TRAFFIC DETECTED — {} side",
                match verdict {
                    ShadowVerdict::BypassedTx => "tx",
                    ShadowVerdict::BypassedRx => "rx",
                    _ => "tx + rx",
                }
            )));
            lines.push(kv(
                "window",
                &format!("{}s (machine-scope, every interface)", audit.window_secs),
            ));
            lines.push(kv(
                "interfaces",
                &format!(
                    "tx {} · rx {}",
                    side_figures(audit.nic_tx, audit.window_secs),
                    side_figures(audit.nic_rx, audit.window_secs)
                ),
            ));
            lines.push(kv(
                "cgroup hooks",
                &format!(
                    "tx {} · rx {}",
                    side_figures(audit.bpf_tx, audit.window_secs),
                    side_figures(audit.bpf_rx, audit.window_secs)
                ),
            ));
            lines.push(kv(
                "shadow",
                &format!(
                    "tx {} ({}% of interface tx) · rx {} ({}% of interface rx) — \
                     traffic the cgroup_skb hooks never saw; a cgroup rate \
                     limit cannot see or shape it",
                    side_figures(audit.shadow_tx, audit.window_secs),
                    shadow_percent(audit.shadow_tx, audit.nic_tx),
                    side_figures(audit.shadow_rx, audit.window_secs),
                    shadow_percent(audit.shadow_rx, audit.nic_rx)
                ),
            ));
            lines.push(kv(
                "likely paths",
                "AF_XDP, RDMA/RoCE, AF_PACKET raw injection (USAGE.md: bypass audit)",
            ));
            lines.push(kv(
                "triage",
                "'ss -etu' / 'lsof -i' — find the mover with no ordinary socket",
            ));
        }
    }
    lines
}

// The bypass section pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the report pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/bypass_tests.rs"]
mod tests;
