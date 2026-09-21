// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Observe renderers (NIGHT-hunt-7): the aggregate traffic monitor
//! frame and the single-cgroup filtered view.

use std::time::Duration;

use super::{
    detail_lines, format_rate_or_dash, label_with_count, rate_bps, rows_for_height, title_bar,
    truncate_label,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::output::brand;
/// Observe column layout derived from the frame width.
///
/// Degradation ladder (2-column margin, 2-column gaps):
/// - width >= 50: PROCESS | DOWNLOAD | UPLOAD | RATE
/// - width >= 38: PROCESS | DOWNLOAD | UPLOAD       (RATE dropped)
/// - width  < 38: PROCESS (min 12) | DOWNLOAD | UPLOAD at 9-wide numerics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObserveColumns {
    label_w: usize,
    dl_w: usize,
    ul_w: usize,
    show_rate: bool,
}

/// Plan the observe column layout for a given terminal width.
#[must_use]
fn plan_observe_columns(width: usize) -> ObserveColumns {
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;

    // Full layout: 2 margin + label + 3 numeric columns + 3 gaps.
    if width >= 2 + LABEL_MIN + 3 * NUM_W + 3 * 2 {
        return ObserveColumns {
            label_w: width - 2 - 3 * NUM_W - 3 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_rate: true,
        };
    }

    // Rate dropped: 2 margin + label + 2 numeric columns + 2 gaps.
    if width >= 2 + LABEL_MIN + 2 * NUM_W + 2 * 2 {
        return ObserveColumns {
            label_w: width - 2 - 2 * NUM_W - 2 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_rate: false,
        };
    }

    // Narrow fallback: tighter numerics, label pinned to the minimum.
    ObserveColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        show_rate: false,
    }
}

/// Render one observe frame (NIGHT-improve-2: line-building — the
/// caller submits the vector to the diff-based screen engine, which
/// emits only the rows that changed).
///
/// `interval` is the poll interval between frames; the RATE column
/// reports `delta / interval` as bytes per second. `conns`
/// (NIGHT-hunt-8) supplies per-cgroup process/connection detail:
/// pass `None` when socket detail is unavailable (deterministic
/// harnesses) — rows then render plain.
pub fn render_observe_frame(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();
    let cols = plan_observe_columns(geo.width);

    let interval_str = if interval.as_secs() >= 1 {
        format!("{}s refresh", interval.as_secs())
    } else {
        format!("{:.1}s refresh", interval.as_secs_f64())
    };
    lines.push(title_bar(
        &format!("zelynic observe — {interval_str}"),
        "q quit",
        geo.width,
    ));

    if summary.total_packets == 0 && summary.total_ingress_packets == 0 {
        lines.push("  waiting for traffic…".to_string());
        return;
    }

    // Header row (regular purple — brand layer, NIGHT-hunt-5).
    if cols.show_rate {
        lines.push(format!(
            "  {} {:>w1$} {:>w2$} {:>w3$}",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            "RATE",
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        ));
    } else {
        lines.push(format!(
            "  {} {:>w1$} {:>w2$}",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));

    let mut sorted = summary.cgroups.clone();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.bytes + c.ingress_bytes));

    // Row budget counts detail lines too (NIGHT-hunt-8): a row plus
    // its eagle-eyes lines must fit as a unit.
    let line_budget = rows_for_height(geo.height);
    let mut used = 0usize;
    let mut emitted = 0usize;
    for c in &sorted {
        let details = detail_lines(conns, c.cgroup_id);
        let need = 1 + details.len();
        if used + need > line_budget && emitted > 0 {
            break;
        }
        render_observe_row(lines, c, identity, conns, &cols, interval);
        for line in details {
            lines.push(line);
        }
        used += need;
        emitted += 1;
    }
    if sorted.len() > emitted {
        lines.push(format!(
            "  (+{} more cgroups hidden — raise the window)",
            sorted.len() - emitted
        ));
    }

    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));
    // improve-13 flagship footer: a column-aligned TOTAL row — the
    // aggregate numbers sit under the exact columns they sum, in the
    // same width slots the data rows use (the old run-on "total down
    // X up Y" line put the sums at arbitrary offsets under a grid
    // whose whole point is column alignment). The label cell carries
    // TOTAL in the header's casing; the aggregate rate fills the RATE
    // slot when that column exists, mirroring every data row.
    if cols.show_rate {
        lines.push(format!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            "TOTAL",
            format_bytes(summary.total_ingress_bytes),
            format_bytes(summary.total_bytes),
            format_rate_or_dash(rate_bps(
                summary.total_ingress_bytes + summary.total_bytes,
                interval
            )),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        ));
    } else {
        lines.push(format!(
            "  {:<w0$} {:>w1$} {:>w2$}",
            "TOTAL",
            format_bytes(summary.total_ingress_bytes),
            format_bytes(summary.total_bytes),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
    // Meta line (compact): scale of the frame, one line, bullet-
    // separated — never mixed into the numeric grid.
    lines.push(format!(
        "  {} packets · {} cgroups",
        summary.total_packets + summary.total_ingress_packets,
        sorted.len()
    ));
    if identity.is_empty() {
        // Rare: the /proc walk resolved nothing (permissions, a
        // stripped container). Say so instead of pretending the raw
        // cgroup IDs are app names.
        lines.push("  (identities unresolved — labels show raw cgroup IDs)".to_string());
    }
}

/// One observe data row.
fn render_observe_row(
    lines: &mut Vec<String>,
    c: &CgroupDelta,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cols: &ObserveColumns,
    interval: Duration,
) {
    let label = truncate_label(
        &label_with_count(identity, conns, c.cgroup_id),
        cols.label_w,
    );
    let dl = format_bytes(c.ingress_bytes);
    let ul = format_bytes(c.bytes);

    if cols.show_rate {
        let rate = format_rate_or_dash(rate_bps(c.ingress_bytes + c.bytes, interval));
        lines.push(format!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            label,
            dl,
            ul,
            rate,
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        ));
    } else {
        lines.push(format!(
            "  {:<w0$} {:>w1$} {:>w2$}",
            label,
            dl,
            ul,
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
}

/// Render one filtered observe frame (single cgroup, `--cgroup`).
///
/// The single-cgroup view switches to a key/value block: with one
/// process, the delta, rate, and lifetime totals are the interesting
/// numbers and a table wastes the width. Line-building contract per
/// [`render_observe_frame`] (NIGHT-improve-2).
pub fn render_observe_filtered(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();

    lines.push(title_bar(
        &format!("zelynic observe — cgroup {cgroup_id}"),
        "q quit",
        geo.width,
    ));

    let Some(c) = summary.cgroups.iter().find(|c| c.cgroup_id == cgroup_id) else {
        lines.push(format!(
            "  no traffic for cgroup {cgroup_id} since last check"
        ));
        return;
    };

    lines.push(format!(
        "  process   {}",
        label_with_count(identity, conns, cgroup_id)
    ));
    lines.push(format!(
        "  download  {} ({})",
        format_bytes(c.ingress_bytes),
        c.ingress_packets
    ));
    lines.push(format!(
        "  upload    {} ({})",
        format_bytes(c.bytes),
        c.packets
    ));
    lines.push(format!(
        "  rate      {}",
        format_rate_or_dash(rate_bps(c.ingress_bytes + c.bytes, interval))
    ));
    lines.push(format!(
        "  lifetime  {}",
        // Both lifetime counters (improve-13 precision): the ingress
        // map's cumulative download + the egress map's cumulative
        // upload — one horizon, since attach. The old sum mixed a
        // per-poll download delta in, so the row shrank frame over
        // frame on a 1s refresh.
        format_bytes(c.ingress_total_bytes + c.total_bytes)
    ));

    // Full eagle-eyes view for the filtered cgroup: every
    // socket-holding process with its endpoints, uncapped (the
    // single-cgroup view exists precisely to answer "who exactly").
    for line in super::full_detail_lines(conns, cgroup_id) {
        lines.push(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full column set at a comfortable width, label absorbing the rest.
    #[test]
    fn observe_columns_full_width() {
        let cols = plan_observe_columns(100);
        assert!(cols.show_rate);
        assert_eq!(cols.dl_w, 10);
        assert_eq!(cols.label_w, 100 - 2 - 3 * 10 - 3 * 2);
    }

    /// RATE is the first column to go on narrow frames (full layout
    /// starts at width 50: 2 margin + 12 label + 30 numerics + 6 gaps).
    #[test]
    fn observe_columns_drop_rate_below_50() {
        let cols = plan_observe_columns(49);
        assert!(!cols.show_rate);
        assert_eq!(cols.label_w, 49 - 2 - 2 * 10 - 2 * 2);
    }

    /// Ultra-narrow frames pin the label to the minimum and tighten
    /// the numeric columns rather than overflowing the line.
    #[test]
    fn observe_columns_narrow_floor() {
        let cols = plan_observe_columns(30);
        assert!(!cols.show_rate);
        assert_eq!(cols.label_w, 12);
        assert_eq!(cols.dl_w, 9);
    }

    /// NIGHT-improve-2 line-building pin: the renderer fills the
    /// caller's vector (title bar first, waiting-note when idle) —
    /// the diff engine's input contract.
    #[test]
    fn observe_frame_builds_lines() {
        let mut lines = Vec::new();
        let summary = CounterSummary::default();
        render_observe_frame(
            &mut lines,
            &summary,
            &IdentityMap::new(),
            None,
            Duration::from_secs(1),
        );
        assert_eq!(lines.len(), 2, "idle frame = title + waiting note");
        assert!(lines[0].starts_with("─── zelynic observe — 1s refresh"));
        assert_eq!(lines[1], "  waiting for traffic…");
    }

    /// improve-13 footer pin: the run-on "total down X up Y" line is
    /// gone, replaced by a column-aligned TOTAL row (same width slots
    /// as the data rows — a single-cgroup frame's TOTAL cells equal
    /// that row's cells, and both lines share the column-grid width)
    /// plus a bullet-separated meta line.
    #[test]
    fn observe_footer_total_row_aligns_with_columns() {
        let mut lines = Vec::new();
        let summary = CounterSummary {
            total_packets: 57,
            total_bytes: 240_000,
            total_ingress_packets: 421,
            total_ingress_bytes: 1_400_000,
            cgroups: vec![CgroupDelta {
                cgroup_id: 7001,
                packets: 57,
                bytes: 240_000,
                total_bytes: 240_000,
                ingress_packets: 421,
                ingress_bytes: 1_400_000,
                ingress_total_bytes: 1_400_000,
            }],
        };
        render_observe_frame(
            &mut lines,
            &summary,
            &IdentityMap::new(),
            None,
            Duration::from_secs(1),
        );
        let joined = lines.join("\n");

        // The old run-on footer wording is retired.
        assert!(
            !joined.contains("total  down"),
            "run-on footer must be gone: {joined}"
        );

        // TOTAL row renders in the label column with the header's casing.
        let total_row = lines
            .iter()
            .find(|l| l.split_whitespace().next() == Some("TOTAL"))
            .unwrap_or_else(|| panic!("no TOTAL row in: {joined}"));
        // Single cgroup: the TOTAL cells are exactly the row's values.
        assert!(total_row.contains("1.4 MB"), "TOTAL dl sum: {total_row}");
        assert!(total_row.contains("240.0 KB"), "TOTAL ul sum: {total_row}");
        assert!(total_row.contains("1.6 MB/s"), "TOTAL rate: {total_row}");

        // Column-grid integrity: the TOTAL row occupies the same
        // width slots as a data row (identical line width, both in
        // the 80-column piped layout: 2 + 42 label + 10 + 10 + 10 + gaps).
        let data_row = lines
            .iter()
            .find(|l| l.starts_with("  cg:7001"))
            .unwrap_or_else(|| panic!("no data row in: {joined}"));
        assert_eq!(
            total_row.chars().count(),
            data_row.chars().count(),
            "TOTAL row must share the column grid: {total_row} vs {data_row}"
        );

        // Meta line: scale of the frame, bullet-separated.
        assert!(
            joined.contains("478 packets · 1 cgroups"),
            "meta line wording: {joined}"
        );
    }

    /// Single-cgroup view (improve-13 precision): the lifetime row
    /// sums the two LIFETIME counters, never a per-poll delta — with
    /// delta 5 MB but lifetime ingress 900 MB, the row must read the
    /// lifetime figure.
    #[test]
    fn observe_filtered_lifetime_uses_lifetime_counters() {
        let mut lines = Vec::new();
        let summary = CounterSummary {
            total_packets: 5,
            total_bytes: 10_000_000,
            total_ingress_packets: 50,
            total_ingress_bytes: 5_000_000,
            cgroups: vec![CgroupDelta {
                cgroup_id: 7001,
                packets: 5,
                bytes: 10_000_000,
                total_bytes: 90_000_000,
                ingress_packets: 50,
                ingress_bytes: 5_000_000,
                ingress_total_bytes: 900_000_000,
            }],
        };
        render_observe_filtered(
            &mut lines,
            &summary,
            &IdentityMap::new(),
            None,
            7001,
            Duration::from_secs(1),
        );
        let joined = lines.join("\n");
        // lifetime = 900 MB (dl lifetime) + 90 MB (ul lifetime) — the
        // mixed-horizon "5 MB + 90 MB" figure must not appear.
        assert!(
            joined.contains("lifetime  990.0 MB"),
            "lifetime sums both lifetime counters: {joined}"
        );
    }
}
