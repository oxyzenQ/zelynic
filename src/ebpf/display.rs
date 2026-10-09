// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from the limiter core to keep every module under the
//! 500-line cap (scripts/gates/check-loc.sh).

use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::types::{BracketPair, POLICY_FLAG_PER_SOCKET, PolicyWindowRaw};
use crate::ebpf::limiter::{LimiterStatsRaw, PolicyRaw, monotonic_ns, terminal_width, wall_now_ns};
use crate::ebpf::render::{grid_line, title_bar};
use crate::output::{grey, signature_footer, suggestion, warn};

/// The status table's column titles (NIGHT-engrave-5): lowercase —
/// the eagle-eyes table contract (engrave-1 lowercased the monitor's
/// titles; this surface was the last uppercase holdout the owner
/// caught). Verdict VALUES keep their case (BLOCKED) — titles are
/// furniture, verdicts are states.
pub(super) const STATUS_HEADERS: [&str; 5] = ["cgroup", "download", "upload", "allowed", "dropped"];

/// Combined policy data for display.
pub(crate) struct DisplayData {
    pub(crate) cgroup_id: u32,
    pub(crate) dl_bps: Option<u64>,
    pub(crate) ul_bps: Option<u64>,
    pub(crate) dl_per_socket: bool,
    pub(crate) ul_per_socket: bool,
    pub(crate) packets_allowed: u64,
    pub(crate) packets_dropped: u64,
    pub(crate) bytes_allowed: u64,
    pub(crate) bytes_dropped: u64,
    /// The row's --during window, when it carries one (night-during,
    /// schema v23) — the lifetime line under the row renders it.
    pub(crate) window: Option<PolicyWindowRaw>,
    /// The row's guarantee bracket (improve-40, schema v24;
    /// improve-40-b the per-direction shape): one pair per
    /// direction, each leg read off its own policy row — the zero
    /// sentinel is unset (most rows carry none, and the subordinate
    /// line renders only when a side is set).
    pub(crate) download: BracketPair,
    pub(crate) upload: BracketPair,
}

// improve-40 (schema v24): the pure line renderers live in the
// display_lines sibling (the policy_lines discipline — this file
// rode the 500-LOC owner cap when the guarantee line joined the
// window family). Re-exported so the pins in display_tests
// (use super::*) and the list-apps surface see the same paths as
// before the split.
pub(crate) use super::display_lines::{
    active_limits_line, guarantee_line, list_apps_header_line, status_cells, status_header_line,
    status_row_line, watchdog_line, window_lifetime_line,
};

/// Collect display data from policies + stats (+ the window join).
pub(super) fn collect_display_data(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    windows: &[(u32, PolicyWindowRaw)],
) -> Vec<DisplayData> {
    // The census row: (dl, ul, dl per-socket, ul per-socket, the
    // per-direction guarantee pairs — improve-40-b: each leg's pair
    // read off its own policy row, the one-flag law's equal pairs
    // a special case of the split).
    type CombinedRow = (
        Option<u64>,
        Option<u64>,
        bool,
        bool,
        BracketPair,
        BracketPair,
    );
    let mut combined: HashMap<u32, CombinedRow> = HashMap::new();
    for (id, p) in dl_policies {
        let e = combined.entry(*id).or_default();
        e.0 = Some(p.rate_bps);
        e.2 = p.flags & POLICY_FLAG_PER_SOCKET != 0;
        e.4 = BracketPair {
            floor_bps: p.floor_bps,
            ceil_bps: p.ceil_bps,
        };
    }
    for (id, p) in ul_policies {
        let e = combined.entry(*id).or_default();
        e.1 = Some(p.rate_bps);
        e.3 = p.flags & POLICY_FLAG_PER_SOCKET != 0;
        e.5 = BracketPair {
            floor_bps: p.floor_bps,
            ceil_bps: p.ceil_bps,
        };
    }

    let mut sorted: Vec<_> = combined.into_iter().collect();
    sorted.sort_by_key(|(id, _)| *id);

    sorted
        .iter()
        .map(|(cgroup_id, (dl, ul, dl_ps, ul_ps, download, upload))| {
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            DisplayData {
                cgroup_id: *cgroup_id,
                dl_bps: *dl,
                ul_bps: *ul,
                dl_per_socket: *dl_ps,
                ul_per_socket: *ul_ps,
                packets_allowed: s.map(|(_, s)| s.packets_allowed).unwrap_or(0),
                packets_dropped: s.map(|(_, s)| s.packets_dropped).unwrap_or(0),
                bytes_allowed: s.map(|(_, s)| s.bytes_allowed).unwrap_or(0),
                bytes_dropped: s.map(|(_, s)| s.bytes_dropped).unwrap_or(0),
                window: windows
                    .iter()
                    .find(|(id, _)| id == cgroup_id)
                    .map(|(_, w)| *w),
                download: *download,
                upload: *upload,
            }
        })
        .collect()
}

/// The clean-state frame (no pins, NIGHT-engrave-5; compacted in
/// NIGHT-private-research-3): the flagship chrome and one grey line
/// — "no active limits" is a verdict, not an absence of output.
/// The title bar spans the terminal width (there is no table to
/// size to). The compact pass retired the breathing-gap fillers on
/// every report surface (the owner's more-compact-and-simple
/// directive): title, verdict, stamp — zero filler lines.
#[must_use]
pub(crate) fn status_clean_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        grey("  no active limits"),
        format!("  {}", signature_footer()),
    ]
}

/// The stale-pins frame (NIGHT-engrave-5; compacted in
/// NIGHT-private-research-3): the flagship chrome with the warning
/// in warn yellow and the recovery command in suggestion white —
/// the same actionable-accent contract the monitor's limit
/// suggestion line carries, zero filler lines.
#[must_use]
pub(crate) fn status_stale_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        warn("  stale bpf pin files detected (partial enforcement state)"),
        format!(
            "  {} {} {}",
            grey("run"),
            suggestion("'zelynic recover'"),
            grey("to clean up, then re-apply limits")
        ),
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
    windows: &[(u32, PolicyWindowRaw)],
) {
    let data = collect_display_data(dl_policies, ul_policies, stats, windows);
    let rows: Vec<(String, String, String, String, String)> =
        data.iter().map(|d| status_cells(d, identity)).collect();
    // night-during (schema v23): one clock pair for every lifetime
    // line under the rows that carry windows.
    let (wall_now, mono_now) = (wall_now_ns(), monotonic_ns());

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
    // NIGHT-engrave-5 opened the frame with the title bar and a
    // breathing gap; NIGHT-private-research-3 (the owner's
    // compact-and-simple directive) retired the gap on the report
    // surfaces: the frame starts at the title and every following
    // line is content — the watchdog, the census, and the table
    // stack directly under the bar.
    println_safe!("{}", title_bar("zelynic status", sep_len + 2));

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
        println_safe!("  {}", signature_footer());
        return;
    }

    // The census line lands directly above the header row it
    // counts (NIGHT-private-research-3): one table cluster, zero
    // filler between the summary and the columns it summarizes.
    println_safe!(
        "{}",
        active_limits_line(dl_policies.len(), ul_policies.len())
    );
    // NIGHT-engrave-5: the header row and the grid under it are the
    // eagle table contract — lowercase purple titles, then the
    // monitor's own purple grid spanning the full title width and
    // flush with the left edge (the `|---` shape, never `| ---`):
    // one border family across every zelynic table.
    println_safe!("{}", status_header_line(&col_widths));
    println_safe!("{}", grid_line(sep_len + 2));

    for (row, d) in rows.iter().zip(data.iter()) {
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
        // night-during (schema v23): the lifetime line lands directly
        // under its row — one indent deeper than the table, the same
        // grey subordinate family the watchdog prose rides (warn
        // yellow when the span has ended and the sweep has not
        // collected the row yet).
        if let Some(win) = &d.window {
            println_safe!("{}", window_lifetime_line(win, wall_now, mono_now));
        }
        // improve-40 (schema v24): the bracket's own subordinate
        // line, the window family's indent and grey — only the rows
        // that carry a side render one.
        if let Some(line) = guarantee_line(d.download, d.upload) {
            println_safe!("{line}");
        }
    }

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // flush with the last row (NIGHT-private-research-3: the blank
    // line of breathing room above it retired with the rest of the
    // report-surface fillers).
    println_safe!("  {}", signature_footer());
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../test/ebpf/display_tests.rs"]
mod display_tests;

// improve-40-b: the per-direction bracket's read-surface pins,
// split from display_tests.rs at the 500-LOC owner cap (the
// guarantee line's split shapes and the census's per-leg join).
#[cfg(test)]
#[path = "../../test/ebpf/display_bracket_tests.rs"]
mod display_bracket_tests;
