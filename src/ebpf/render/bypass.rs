// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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

use crate::ebpf::bypass::{
    SHADOW_RX_FLOOR_BYTES, SHADOW_RX_NUM_PERCENT, SHADOW_TX_FLOOR_BYTES, SHADOW_TX_NUM_PERCENT,
    ShadowAudit, ShadowVerdict, shadow_percent,
};
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
/// verdict says what it is, none is silent. The clean line names the
/// basis it cleared (night-ux-1, the owner's 200kb-on-Brave session:
/// "clean" beside a 22% figure forced the reader to guess whether 22%
/// sat inside the band — the line carries the band, the constants
/// imported, never restated).
///
/// NIGHT-ux-3 (the live run's tx shadow 0% / rx shadow 100% window):
/// a CLEAN verdict can be floor-bound, not band-bound — a side flags
/// only past BOTH gates (`side_flagged`: shadow > floor AND share >
/// band), so a 100% rx share on a quiet interface is the FLOOR
/// holding, and "under thresholds" beside it was false. The line
/// names which gate held, per side: both shadows at-or-under their
/// floors render the quiet-window wording, both above render the
/// band wording, and a mixed window names each side's own basis —
/// the branch condition is the exact complement of `side_flagged`'s
/// strict `>` on the floor gate (`shadow <= floor`). The printed
/// percents stay the shadow's whole-window share; the MiB figures
/// derive from the floor consts (the floors are MiB-round by
/// definition), never restated.
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
            // night-ux-1 / night-ux-3: the verdict prints the gate it
            // cleared — per side, from the same constants the verdict
            // was computed from, so the line can never drift from
            // the law. A floor-bound side cannot flag whatever its
            // share reads; a share over the band beside "clean" now
            // names the floor that held instead of a false band.
            let tx_quiet = audit.shadow_tx <= SHADOW_TX_FLOOR_BYTES;
            let rx_quiet = audit.shadow_rx <= SHADOW_RX_FLOOR_BYTES;
            let tx_mib = SHADOW_TX_FLOOR_BYTES / (1024 * 1024);
            let rx_mib = SHADOW_RX_FLOOR_BYTES / (1024 * 1024);
            let basis = match (tx_quiet, rx_quiet) {
                (true, true) => {
                    format!("quiet window — under {tx_mib} MiB tx / {rx_mib} MiB rx floor")
                }
                (false, false) => {
                    format!("under {SHADOW_TX_NUM_PERCENT}%/{SHADOW_RX_NUM_PERCENT}% thresholds")
                }
                (true, false) => format!(
                    "tx under {tx_mib} MiB floor; rx under {SHADOW_RX_NUM_PERCENT}% thresholds"
                ),
                (false, true) => format!(
                    "tx under {SHADOW_TX_NUM_PERCENT}% thresholds; rx under {rx_mib} MiB floor"
                ),
            };
            lines.push(kv(
                "bypass audit",
                &format!(
                    "clean ({basis}; \
                     tx shadow {}%, rx shadow {}%)",
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
