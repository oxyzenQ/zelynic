// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from the limiter core to keep every module under the
//! 500-line cap (scripts/check-loc.sh).

use anyhow::Result;
use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{
    format_bytes, format_rate, monotonic_ns, terminal_width, LimiterStatsRaw, PolicyRaw,
};

/// Combined policy data for display.
struct DisplayData {
    cgroup_id: u32,
    dl_bps: Option<u64>,
    ul_bps: Option<u64>,
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
}

/// Collect display data from policies + stats.
fn collect_display_data(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
) -> Vec<DisplayData> {
    let mut combined: HashMap<u32, (Option<u64>, Option<u64>)> = HashMap::new();
    for (id, p) in dl_policies {
        combined.entry(*id).or_default().0 = Some(p.rate_bps);
    }
    for (id, p) in ul_policies {
        combined.entry(*id).or_default().1 = Some(p.rate_bps);
    }

    let mut sorted: Vec<_> = combined.into_iter().collect();
    sorted.sort_by_key(|(id, _)| *id);

    sorted
        .iter()
        .map(|(cgroup_id, (dl, ul))| {
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            DisplayData {
                cgroup_id: *cgroup_id,
                dl_bps: *dl,
                ul_bps: *ul,
                packets_allowed: s.map(|(_, s)| s.packets_allowed).unwrap_or(0),
                packets_dropped: s.map(|(_, s)| s.packets_dropped).unwrap_or(0),
                bytes_allowed: s.map(|(_, s)| s.bytes_allowed).unwrap_or(0),
                bytes_dropped: s.map(|(_, s)| s.bytes_dropped).unwrap_or(0),
            }
        })
        .collect()
}

/// One status row's display cells (pure, improve-13: extracted for
/// the same reason `status_json` was — the human table's contract is
/// now unit-pinnable without capturing stdout).
///
/// ALLOWED and DROPPED carry BYTES only, one metric per cell: the
/// render engine's own flagship rule (src/ebpf/render.rs module
/// docs) bans per-cell packing ("89 (1.2 MB)") — the status table
/// was the last surface still doing it. Packet counts stay in
/// `--print-json` where automation reads them; the human eye scans
/// magnitudes, and bytes carry the enforcement verdict.
fn status_cells(
    d: &DisplayData,
    identity: &IdentityMap,
) -> (String, String, String, String, String) {
    let label = identity.label(d.cgroup_id);
    let dl = d.dl_bps.map(format_rate).unwrap_or_else(|| "—".to_string());
    let ul = d.ul_bps.map(format_rate).unwrap_or_else(|| "—".to_string());
    (
        label,
        dl,
        ul,
        format_bytes(d.bytes_allowed),
        format_bytes(d.bytes_dropped),
    )
}

/// Print human-readable status table.
pub fn print_status(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) {
    println_safe!("\n{}", crate::output::brand_bold("━━━ zelynic Status ━━━"));

    match watchdog_deadline {
        Some(0) | None => {
            println_safe!("  Watchdog: not set (enforcing)");
        }
        Some(deadline) => {
            let now = monotonic_ns();
            if deadline > now {
                let remaining = (deadline - now) / 1_000_000_000;
                println_safe!("  Watchdog: {remaining}s remaining");
            } else {
                println_safe!("  Watchdog: EXPIRED (BPF is no-op)");
            }
        }
    }

    if dl_policies.is_empty() && ul_policies.is_empty() {
        println_safe!("  Active limits: none");
        return;
    }

    println_safe!(
        "  Active limits: {} dl, {} ul",
        dl_policies.len(),
        ul_policies.len()
    );
    println_safe!();

    let data = collect_display_data(dl_policies, ul_policies, stats);
    if data.is_empty() {
        return;
    }

    let rows: Vec<(String, String, String, String, String)> =
        data.iter().map(|d| status_cells(d, identity)).collect();

    let term_w = terminal_width().saturating_sub(4);
    let headers = ["CGROUP", "DOWNLOAD", "UPLOAD", "ALLOWED", "DROPPED"];

    let mut col_widths = [0usize; 5];
    for (i, h) in headers.iter().enumerate() {
        col_widths[i] = h.len();
    }
    for row in &rows {
        col_widths[0] = col_widths[0].max(row.0.chars().count());
        col_widths[1] = col_widths[1].max(row.1.len());
        col_widths[2] = col_widths[2].max(row.2.len());
        col_widths[3] = col_widths[3].max(row.3.len());
        col_widths[4] = col_widths[4].max(row.4.len());
    }

    let total: usize = col_widths.iter().sum::<usize>() + 4;
    if total > term_w {
        let excess = total - term_w;
        col_widths[0] = col_widths[0].saturating_sub(excess).max(10);
    }

    println_safe!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        headers[4],
        w0 = col_widths[0],
        w1 = col_widths[1],
        w2 = col_widths[2],
        w3 = col_widths[3],
        w4 = col_widths[4]
    );
    let sep_len: usize = col_widths.iter().sum::<usize>() + 4;
    println_safe!("  {}", "─".repeat(sep_len));

    for row in &rows {
        let label = if row.0.chars().count() > col_widths[0] {
            let truncated: String = row
                .0
                .chars()
                .take(col_widths[0].saturating_sub(1))
                .collect();
            format!("{truncated}…")
        } else {
            row.0.clone()
        };
        println_safe!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
            label,
            row.1,
            row.2,
            row.3,
            row.4,
            w0 = col_widths[0],
            w1 = col_widths[1],
            w2 = col_widths[2],
            w3 = col_widths[3],
            w4 = col_widths[4]
        );
    }
}

/// Print JSON status (for --print-json / scripting).
pub fn print_status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) -> Result<()> {
    let status = status_json(dl_policies, ul_policies, stats, identity, watchdog_deadline);
    println_safe!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

/// Assemble the status JSON document (pure, NIGHT-hunt-22: extracted
/// so the scripting contract — field names, watchdog wording, count
/// semantics — is unit-pinnable without capturing stdout). The shape
/// is the `--print-json` contract scripts parse; changing a field
/// name is a breaking change for automation.
fn status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) -> StatusJson {
    let watchdog = match watchdog_deadline {
        Some(0) | None => "enforcing",
        Some(d) if d > monotonic_ns() => "active",
        Some(_) => "expired",
    };

    let data = collect_display_data(dl_policies, ul_policies, stats);

    let limits: Vec<LimitEntry> = data
        .iter()
        .map(|d| LimitEntry {
            cgroup_id: d.cgroup_id,
            label: identity.label(d.cgroup_id),
            download_bps: d.dl_bps,
            upload_bps: d.ul_bps,
            packets_allowed: d.packets_allowed,
            packets_dropped: d.packets_dropped,
            bytes_allowed: d.bytes_allowed,
            bytes_dropped: d.bytes_dropped,
        })
        .collect();

    StatusJson {
        watchdog,
        active_limits: limits.len(),
        limits,
    }
}

#[derive(serde::Serialize)]
struct LimitEntry {
    cgroup_id: u32,
    label: String,
    download_bps: Option<u64>,
    upload_bps: Option<u64>,
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
}

#[derive(serde::Serialize)]
struct StatusJson {
    watchdog: &'static str,
    active_limits: usize,
    limits: Vec<LimitEntry>,
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../test/ebpf/display_tests.rs"]
mod display_tests;
