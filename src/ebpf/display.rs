// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from the limiter core to keep every module under the
//! 500-line cap (scripts/gates/check-loc.sh).

use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::types::{
    BracketPair, POLICY_FLAG_PER_SOCKET, PolicyRaw, PolicyWindowRaw,
};
use crate::ebpf::limiter::{LimiterStatsRaw, monotonic_ns, terminal_width, wall_now_ns};
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
    /// night-spark-4, schema v26 (the CE ledger): the ECN-first
    /// lane's own truth, read off the same stats row — the volume
    /// book_rescue delivered CE-marked. The subordinate CE Marked
    /// line renders it; zeros stay silent (the dormant-watchdog
    /// precedent).
    pub(crate) ce_marked_packets: u64,
    pub(crate) ce_marked_bytes: u64,
    /// night-spark-7, schema v28 (the quota telemetry's math — Layer
    /// 4 of the quota saver): the egress pacing lane's saved word,
    /// read off the stats row's tail — (rate x elapsed) - uploaded
    /// until night-quota-audit (schema v29) retired the kernel
    /// booking (the counterfactual's only nonzero content was the
    /// budget an idle sender never used). The Quota Saved line's EDT
    /// half, zero from v29 on.
    pub(crate) bytes_saved_by_edt: u64,
    /// night-spark-7, Layer 4: the RECWN lane's saved-volume word —
    /// RETIRED (night-recvn-audit, schema v30). The window-law
    /// counterfactual this field carried until v30
    /// ((allowed / clamped) x (default - clamped), the userspace
    /// estimate against the documented 128 KiB default window) booked
    /// a clamp that rarely binds on a real link: the owner's live
    /// ss -tip reading (2026-11-09, brave at 200kb) had 1 of 11
    /// connections with a BDP at or above the 40 KB clamp, the other
    /// ten at 1.8-14.7 KB, almost every socket app_limited, and
    /// autotuned windows of 48-78 KB — the formula booked 165 MB
    /// against an honest upper bound of a few MB, 10-30x HIGH against
    /// the quota doc's "errs LOW, never high" contract. The honest
    /// booking is zero: the field keeps its place (the JSON key
    /// stays, the additive contract) and reads zero from v30 on. The
    /// lane's real work — the SO_RCVBUF clamp, the bufferbloat
    /// reduction — is untouched; its wire effect is the A/B harness's
    /// measurement, never a booked number.
    pub(crate) bytes_saved_by_recwn: u64,
    /// night-spark-7, Layer 4: the ECN lane's saved volume, read off
    /// the stats row's v28 tail — one-for-one with ce_marked_bytes,
    /// booked by book_rescue beside the raw pair: every delivered
    /// CE-marked byte is a byte that never becomes a
    /// loss-and-retransmission pair.
    pub(crate) bytes_saved_by_ecn: u64,
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
    StatusLineKind, active_limits_line, ce_marked_line, counters_footer_lines, frame_status_output,
    guarantee_line, list_apps_header_line, pacing_line, quota_saved_line, status_cells,
    status_header_line, status_row_line, watchdog_line, window_lifetime_line,
};

// night-verify-final (schema v33): the RECWN lane's derivation and
// its line live in the display_recwn sibling (the display_lines
// discipline — this file rode the 600-LOC owner cap when the
// measured twin joined the family). Re-exported so every existing
// path rides unchanged. The line's own pin family split into its
// file the same hour (the wording pins' 600-LOC hour).
pub(crate) use super::display_recwn::{
    RECWN_RTT_ESTIMATE_US, RecwnLane, recwn_lane, recwn_line, recwn_window_bytes,
};
// The measured twin's external consumer is the rootless parity pin
// (cfg test): the derivation itself calls it inside the sibling.
#[cfg(test)]
pub(crate) use super::display_recwn::recwn_measured_window_bytes;

#[cfg(test)]
#[path = "../../test/ebpf/display_recwn_line_tests.rs"]
mod display_recwn_line_tests;

/// Collect display data from policies + stats (the window join).
/// The RECWN lane join the Layer 4 estimate once rode came out with
/// the estimate itself (night-recvn-audit, schema v30 — the saved
/// word reads zero unconditionally); the lane's own window
/// derivation lives in [`recwn_lane`], the bottom RECWN line's belt.
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
                ce_marked_packets: s.map(|(_, s)| s.ce_marked_packets).unwrap_or(0),
                ce_marked_bytes: s.map(|(_, s)| s.ce_marked_bytes).unwrap_or(0),
                // night-spark-7 (the quota telemetry's math — Layer
                // 4): the kernel-booked ECN column copies straight off
                // the stats tail, the EDT column rides the same tail
                // but reads zero from schema v29 on (night-quota-audit
                // retired the kernel booking), and the RECWN word reads
                // zero from schema v30 on (night-recvn-audit retired
                // the userspace estimate — it booked a clamp that
                // rarely binds, 10-30x HIGH on the owner's live
                // reading). A row with no stats entry books nothing
                // (the unwrap_or(0) family's own honesty).
                bytes_saved_by_edt: s.map(|(_, s)| s.bytes_saved_by_edt).unwrap_or(0),
                // night-recvn-audit (schema v30): the retired word,
                // zero unconditionally — the field's own doc carries
                // the retirement record.
                bytes_saved_by_recwn: 0,
                bytes_saved_by_ecn: s.map(|(_, s)| s.bytes_saved_by_ecn).unwrap_or(0),
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

// night-recvn-audit (schema v30): the RECWN saved-volume estimate
// (recwn_saved_bytes, the window-law counterfactual against the 128 KiB
// default-window assumption) is RETIRED — the machinery came out of the
// display layer the way the v29 EDT retirement took the kernel accrual
// out of the object. The field stays at zero; DisplayData's
// bytes_saved_by_recwn doc carries the retirement record.

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
/// table, it is the second flagship surface.
///
/// night-ux-5 (Shape B, the owner's 2026-11-08 live run): the title
/// bar and the grid span the WIDEST line the output prints — the
/// table's own width when the table is the widest content, the
/// footer prose's width when the prose runs longer — and every
/// line pads to that one width, so the frame's right edge is a
/// straight column instead of prose bleeding past a table-sized
/// bar. On a terminal narrower than the content, the truncation
/// ladder cuts the sacrifice lines (footer prose first, table and
/// stamp never) — [`super::display_lines::frame_status_output`]
/// owns the law, this composition owns the lines.
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
    recwn: &RecwnLane,
) {
    let mut data = collect_display_data(dl_policies, ul_policies, stats, windows);
    // night-ux-6: the name-first row order, the one law the JSON
    // document shares (crate::ebpf::display_order).
    super::display_order::sort_status_rows(&mut data, identity);
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

    // night-ux-5 (Shape B, the owner's 2026-11-08 live run): the
    // frame is the CONTENT's own width — compose every line the
    // status output will print FIRST, then size the title bar and
    // the grid to the widest of them and pad the rest to the same
    // right edge. The old shape sized the chrome to the table alone
    // (57 columns) while the counter footer prose and the RECWN
    // line printed beside it at 115 and 74 — the frame stopped and
    // the prose kept going. [`frame_status_output`] owns the
    // truncate-to-terminal belt (the footer prose cuts first, the
    // table and the stamp never cut) and the pad pass; the
    // composition below only decides WHICH lines exist, in the
    // order they print.
    let show_grid = !dl_policies.is_empty() || !ul_policies.is_empty();
    let mut above: Vec<(StatusLineKind, String)> = Vec::new();
    let mut below: Vec<(StatusLineKind, String)> = Vec::new();

    // Watchdog honesty (NIGHT-boost-5): the line appears only when
    // a deadline is actually ARMED — dormant (deadline 0 / None)
    // prints no line at all.
    match watchdog_deadline {
        Some(deadline) if deadline > 0 => {
            let now = monotonic_ns();
            let line = if deadline > now {
                watchdog_line(Some((deadline - now) / 1_000_000_000))
            } else {
                watchdog_line(None)
            };
            above.push((StatusLineKind::Watchdog, line));
        }
        _ => {}
    }

    if !show_grid {
        // The clean board is still a verdict (NIGHT-engrave-5):
        // "no active limits" names the state — no table, no grid,
        // the frame fits the verdict and the stamp.
        above.push((StatusLineKind::Census, grey("  active limits: none")));
    } else {
        // The census line lands directly above the header row it
        // counts (NIGHT-private-research-3): one table cluster, zero
        // filler between the summary and the columns it summarizes.
        above.push((
            StatusLineKind::Census,
            active_limits_line(dl_policies.len(), ul_policies.len()),
        ));
        // NIGHT-engrave-5: lowercase purple titles over the grid —
        // the eagle table contract, flush with the left edge (the
        // `|---` shape, never `| ---`): one border family across
        // every zelynic table.
        above.push((StatusLineKind::Protected, status_header_line(&col_widths)));

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
            below.push((
                StatusLineKind::Protected,
                status_row_line(&label, row, &col_widths),
            ));
            // The row's subordinate family — the window lifetime
            // line (night-during, schema v23), the guarantee bracket
            // (improve-40, schema v24), the CE ledger (night-spark-4,
            // schema v26), the egress pacing lane (night-spark-5,
            // schema v27): one indent under the row that carries
            // them, the grey window family, each rendered only when
            // its lane actually holds something (absence stays
            // silence, never a zero).
            if let Some(win) = &d.window {
                below.push((
                    StatusLineKind::RowSubordinate,
                    window_lifetime_line(win, wall_now, mono_now),
                ));
            }
            if let Some(line) = guarantee_line(d.download, d.upload) {
                below.push((StatusLineKind::RowSubordinate, line));
            }
            if let Some(line) = ce_marked_line(d) {
                below.push((StatusLineKind::RowSubordinate, line));
            }
            if let Some(line) = pacing_line(d) {
                below.push((StatusLineKind::RowSubordinate, line));
            }
            // night-spark-6/7 (the quota saver's Layer 4): the saved
            // volume's line, the narrow-form switch still keyed on
            // the terminal's own width (night-ux-2 — the wide
            // honesty label never wraps; the narrow form fires
            // BEFORE the frame law sees the line, so a narrow-quota
            // row never drives the frame width past the footer).
            if let Some(line) = quota_saved_line(d, terminal_width()) {
                below.push((StatusLineKind::Quota, line));
            }
        }

        // night-ux-1 (the owner's 200kb-on-Brave session): the
        // counter footer — the allowed / dropped columns' own
        // units-and-window line, the --help grammar's NIGHT-dinner-11
        // contract carried onto the surface the owner was actually
        // reading. night-docs-1: TWO grey lines under the table it
        // explains — the window line and the direction law — each
        // its own frame-law entry (the frame measures one line per
        // entry), so the 80-column budget never cuts the direction
        // clause.
        for line in counters_footer_lines() {
            below.push((StatusLineKind::FooterProse, line));
        }

        // night-spark-2 (RECWN, schema v25): the receive-window
        // lane's own subordinate line — the watchdog's grey family,
        // one line under the table, rendered ONLY when the lane is
        // actively shaping a window.
        if let Some(line) = recwn_line(recwn) {
            below.push((StatusLineKind::Recwn, line));
        }
    }

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // flush with the last row — under the frame at the left, not
    // part of the table (its width rides the composition; it never
    // truncates).
    below.push((
        StatusLineKind::Protected,
        format!("  {}", signature_footer()),
    ));

    // The Shape B frame: cut, measure, pad — then the chrome sizes
    // to the same width (the title bar above the upper flank, the
    // grid between header and rows on the populated path only).
    let frame = frame_status_output(above, below, term_w);
    println_safe!("{}", title_bar("zelynic status", frame.width));
    for line in &frame.above_grid {
        println_safe!("{line}");
    }
    if show_grid {
        println_safe!("{}", grid_line(frame.width));
    }
    for line in &frame.below_grid {
        println_safe!("{line}");
    }
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

// night-spark-6 (the quota saver's Layer 4 PREP): the Quota Saved
// subordinate line's family, split from display_tests.rs at the
// 600-line owner cap (the sibling-split lineage, one family over).
#[cfg(test)]
#[path = "../../test/ebpf/display_quota_tests.rs"]
mod display_quota_tests;
