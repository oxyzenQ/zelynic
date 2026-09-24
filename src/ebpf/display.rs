// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from the limiter core to keep every module under the
//! 500-line cap (scripts/gates/check-loc.sh).

use anyhow::Result;
use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{
    format_bytes, format_rate, monotonic_ns, terminal_width, LimiterStatsRaw, PolicyRaw,
};
use crate::ebpf::render::{grid_line, title_bar};
use crate::output::{brand, grey, ok, signature_footer, suggestion, warn};

/// The status table's column titles (NIGHT-engrave-5): lowercase —
/// the eagle-eyes table contract (engrave-1 lowercased the monitor's
/// titles; this surface was the last uppercase holdout the owner
/// caught). Verdict VALUES keep their case (BLOCKED) — titles are
/// furniture, verdicts are states.
const STATUS_HEADERS: [&str; 5] = ["cgroup", "download", "upload", "allowed", "dropped"];

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

/// The status table's header row (pure, NIGHT-engrave-5): lowercase
/// titles in regular purple — the exact contract the eagle-eyes
/// header row carries (`top process` / `download` / `upload` /
/// `total`, brand-wrapped) — so the two report tables read as one
/// family. Extracted so the wording and alignment are unit-pinnable
/// without capturing stdout.
fn status_header_line(col_widths: &[usize; 5]) -> String {
    brand(&format!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        STATUS_HEADERS[0],
        STATUS_HEADERS[1],
        STATUS_HEADERS[2],
        STATUS_HEADERS[3],
        STATUS_HEADERS[4],
        w0 = col_widths[0],
        w1 = col_widths[1],
        w2 = col_widths[2],
        w3 = col_widths[3],
        w4 = col_widths[4]
    ))
}

/// One status data row (pure, NIGHT-engrave-5): the whole row in
/// status green — the eagle table's calm tier (rank 3 and below
/// render the same way). Every row here IS a live, enforced limit —
/// the affirmative state — so the table reads like a calm monitor
/// board, not a white wall of text.
fn status_row_line(
    label: &str,
    row: &(String, String, String, String, String),
    col_widths: &[usize; 5],
) -> String {
    ok(&format!(
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
    ))
}

/// The list-apps table's header row (pure, NIGHT-engrave-5 hunt
/// find): the same eagle-eyes contract as the status header —
/// lowercase purple titles — so the two REPORT tables read as one
/// family. Extracted here (the display module owns table style) so
/// the wording is pinnable next to the status pins.
#[must_use]
pub(crate) fn list_apps_header_line(widths: &[usize; 5]) -> String {
    brand(&format!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        "process",
        "procs",
        "sockets",
        "cgroup id",
        "uid",
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4]
    ))
}

/// The watchdog prose line (pure, NIGHT-engrave-5): grey while the
/// deadline counts down (a subordinate fact — the census family),
/// warn yellow once expired (the enforcement verdict went dark).
fn watchdog_line(remaining_secs: Option<u64>) -> String {
    match remaining_secs {
        Some(secs) => grey(&format!("  watchdog: {secs}s remaining")),
        None => warn("  watchdog: expired (bpf is no-op)"),
    }
}

/// The enforcement census line (pure, NIGHT-engrave-5): grey,
/// lowercase — the same subordinate family the monitor's footer
/// census renders in.
fn active_limits_line(dl: usize, ul: usize) -> String {
    grey(&format!("  active limits: {dl} dl, {ul} ul"))
}

/// The clean-state frame (no pins, NIGHT-engrave-5): the flagship
/// chrome and one grey line — "no active limits" is a verdict, not
/// an absence of output. The title bar spans the terminal width
/// (there is no table to size to).
#[must_use]
pub(crate) fn status_clean_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        String::new(),
        grey("  no active limits"),
        String::new(),
        format!("  {}", signature_footer()),
    ]
}

/// The stale-pins frame (NIGHT-engrave-5): the flagship chrome with
/// the warning in warn yellow and the recovery command in suggestion
/// white — the same actionable-accent contract the monitor's limit
/// suggestion line carries.
#[must_use]
pub(crate) fn status_stale_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        String::new(),
        warn("  stale bpf pin files detected (partial enforcement state)"),
        format!(
            "  {} {} {}",
            grey("run"),
            suggestion("'zelynic recover'"),
            grey("to clean up, then re-apply limits")
        ),
        String::new(),
        format!("  {}", signature_footer()),
    ]
}

/// Print human-readable status table.
///
/// Flagship engraving (NIGHT-boost-5): the surface opens with the
/// same purple title bar the eagle-eyes monitor carries and signs
/// off with the signature footer — status is not an afterthought
/// table, it is the second flagship surface. The title bar spans
/// the table's own width (content-width table + its gutter), not
/// the full terminal — the status grid sizes to its rows, and a
/// full-width bar would overhang it on wide screens.
///
/// NIGHT-engrave-5 (the eagle-eyes style match, the owner's audit):
/// the table itself answers to the monitor's contract — lowercase
/// purple column headers over a full-width purple grid flush with
/// the left edge, data rows in status green (the calm tier), the
/// watchdog/census prose in grey (warn yellow when the watchdog
/// expires), and a breathing gap under the title bar. The uppercase
/// headers and the plain separator were the last pre-eagle carriers
/// on a flagship surface.
///
/// Watchdog honesty (NIGHT-boost-5): the line appears only when a
/// deadline is actually ARMED. The retired "not set (enforcing)"
/// line read like a state but was the absence of one — a dormant
/// auto-expiry timer printed on every check the owner actually
/// runs, noise pretending to be information. `--print-json` keeps
/// the `"watchdog"` field semantics unchanged (pinned scripting
/// contract, test/ebpf/display_tests.rs).
pub fn print_status(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) {
    let data = collect_display_data(dl_policies, ul_policies, stats);
    let rows: Vec<(String, String, String, String, String)> =
        data.iter().map(|d| status_cells(d, identity)).collect();

    let term_w = terminal_width().saturating_sub(4);

    let mut col_widths = [0usize; 5];
    for (i, h) in STATUS_HEADERS.iter().enumerate() {
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

    let sep_len: usize = col_widths.iter().sum::<usize>() + 4;
    // NIGHT-engrave-5: the eagle-eyes composition — the title bar
    // opens the frame, one breathing gap under it (the monitor's
    // top-chrome ladder), and the frame STARTS at the title: the old
    // leading blank line is gone, the chrome is the first thing the
    // eye meets.
    println_safe!("{}", title_bar("zelynic status", sep_len + 2));
    println_safe!();

    match watchdog_deadline {
        Some(deadline) if deadline > 0 => {
            let now = monotonic_ns();
            let line = if deadline > now {
                watchdog_line(Some((deadline - now) / 1_000_000_000))
            } else {
                watchdog_line(None)
            };
            println_safe!("{line}");
        }
        // Dormant (deadline 0 / None): no line at all — the function
        // docs above hold the why.
        _ => {}
    }

    if dl_policies.is_empty() && ul_policies.is_empty() {
        println_safe!("{}", grey("  active limits: none"));
        println_safe!("\n  {}", signature_footer());
        return;
    }

    println_safe!(
        "{}",
        active_limits_line(dl_policies.len(), ul_policies.len())
    );
    println_safe!();

    // NIGHT-engrave-5: the header row and the grid under it are the
    // eagle table contract — lowercase purple titles, then the
    // monitor's own purple grid spanning the full title width and
    // flush with the left edge (the `|---` shape, never `| ---`):
    // one border family across every zelynic table.
    println_safe!("{}", status_header_line(&col_widths));
    println_safe!("{}", grid_line(sep_len + 2));

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
        println_safe!("{}", status_row_line(&label, row, &col_widths));
    }

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // one blank line of breathing room above it.
    println_safe!("\n  {}", signature_footer());
}

/// Print JSON status (for --print-json / scripting).
///
/// NIGHT-boost-3: the write rides the unified
/// [`crate::output::print_json`] primitive — one compact line,
/// serialized field-by-field straight into the locked stdout (the old
/// path allocated the full pretty document as a String, then copied
/// it a second time through the format machinery). The document shape
/// (field names, order) is unchanged; scripts that parsed the pretty
/// layout with `jq` are unaffected, and the one-line contract is the
/// machine-first format the scripting docs promise.
pub fn print_status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) -> Result<()> {
    let status = status_json(dl_policies, ul_policies, stats, identity, watchdog_deadline);
    crate::output::print_json(&status);
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
