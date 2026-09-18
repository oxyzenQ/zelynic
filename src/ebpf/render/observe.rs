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

/// Render one observe frame (alt screen).
///
/// `interval` is the poll interval between frames; the RATE column
/// reports `delta / interval` as bytes per second. `conns`
/// (NIGHT-hunt-8) supplies per-cgroup process/connection detail:
/// pass `None` when socket detail is unavailable (deterministic
/// harnesses) — rows then render plain.
pub fn render_observe_frame(
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
    println_safe!(
        "{}",
        title_bar(
            &format!("zelynic observe — {interval_str}"),
            "q/ESC quit",
            geo.width
        )
    );

    if summary.total_packets == 0 && summary.total_ingress_packets == 0 {
        println_safe!("  waiting for traffic…");
        return;
    }

    // Header row (regular purple — brand layer, NIGHT-hunt-5).
    if cols.show_rate {
        println_safe!(
            "  {} {:>w1$} {:>w2$} {:>w3$}",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            "RATE",
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        );
    } else {
        println_safe!(
            "  {} {:>w1$} {:>w2$}",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            w1 = cols.dl_w,
            w2 = cols.ul_w
        );
    }
    println_safe!("  {}", "─".repeat(geo.width.saturating_sub(2)));

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
        render_observe_row(c, identity, conns, &cols, interval);
        for line in details {
            println_safe!("{line}");
        }
        used += need;
        emitted += 1;
    }
    if sorted.len() > emitted {
        println_safe!(
            "  (+{} more cgroups hidden — raise the window)",
            sorted.len() - emitted
        );
    }

    println_safe!("  {}", "─".repeat(geo.width.saturating_sub(2)));
    println_safe!(
        "  total  down {}  up {}  {} packets  {} cgroups",
        format_bytes(summary.total_ingress_bytes),
        format_bytes(summary.total_bytes),
        summary.total_packets + summary.total_ingress_packets,
        sorted.len()
    );
    if identity.is_empty() {
        // Rare: the /proc walk resolved nothing (permissions, a
        // stripped container). Say so instead of pretending the raw
        // cgroup IDs are app names.
        println_safe!("  (identities unresolved — labels show raw cgroup IDs)");
    }
}

/// One observe data row.
fn render_observe_row(
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
        println_safe!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            label,
            dl,
            ul,
            rate,
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        );
    } else {
        println_safe!(
            "  {:<w0$} {:>w1$} {:>w2$}",
            label,
            dl,
            ul,
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        );
    }
}

/// Render one filtered observe frame (single cgroup, `--cgroup`).
///
/// The single-cgroup view switches to a key/value block: with one
/// process, the delta, rate, and lifetime totals are the interesting
/// numbers and a table wastes the width.
pub fn render_observe_filtered(
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();

    println_safe!(
        "{}",
        title_bar(
            &format!("zelynic observe — cgroup {cgroup_id}"),
            "q/ESC quit",
            geo.width
        )
    );

    let Some(c) = summary.cgroups.iter().find(|c| c.cgroup_id == cgroup_id) else {
        println_safe!("  no traffic for cgroup {cgroup_id} since last check");
        return;
    };

    println_safe!(
        "  process   {}",
        label_with_count(identity, conns, cgroup_id)
    );
    println_safe!(
        "  download  {} ({})",
        format_bytes(c.ingress_bytes),
        c.ingress_packets
    );
    println_safe!("  upload    {} ({})", format_bytes(c.bytes), c.packets);
    println_safe!(
        "  rate      {}",
        format_rate_or_dash(rate_bps(c.ingress_bytes + c.bytes, interval))
    );
    println_safe!(
        "  lifetime  {}",
        format_bytes(c.ingress_bytes + c.total_bytes)
    );

    // Full eagle-eyes view for the filtered cgroup: every
    // socket-holding process with its endpoints, uncapped (the
    // single-cgroup view exists precisely to answer "who exactly").
    for line in super::full_detail_lines(conns, cgroup_id) {
        println_safe!("{line}");
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
}
