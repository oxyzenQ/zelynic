// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Top-talkers renderer (NIGHT-hunt-7): one responsive live table.
//!
//! Always live (NIGHT-hunt-12): the former snapshot/sample mode and
//! the `TopMode` enum are gone — there is exactly one presentation,
//! the live box.

use std::collections::HashMap;
use std::time::Duration;

use super::{
    comm_from_label, detail_lines, label_with_count, rows_for_height, title_bar, truncate_label,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::output::{brand, warn_bold};

/// Top-talkers column layout derived from the frame width.
///
/// Degradation ladder:
/// - width >= 56: # | PROCESS | DOWNLOAD | UPLOAD | TOTAL
/// - width >= 44: # | PROCESS | DOWNLOAD | UPLOAD      (TOTAL dropped)
/// - width  < 44: # | PROCESS (min 14) | DOWNLOAD | UPLOAD at 9-wide
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TopColumns {
    label_w: usize,
    dl_w: usize,
    ul_w: usize,
    show_total: bool,
}

/// Plan the top-table column layout for a given terminal width.
#[must_use]
fn plan_top_columns(width: usize) -> TopColumns {
    const RANK_W: usize = 6; // "  N  " rank column incl. margins
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 14;

    if width >= RANK_W + LABEL_MIN + 3 * NUM_W + 3 * 2 {
        return TopColumns {
            label_w: width - RANK_W - 3 * NUM_W - 3 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: true,
        };
    }

    if width >= RANK_W + LABEL_MIN + 2 * NUM_W + 2 * 2 {
        return TopColumns {
            label_w: width - RANK_W - 2 * NUM_W - 2 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: false,
        };
    }

    TopColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        show_total: false,
    }
}

/// Render the live top-talkers table (NIGHT-improve-2:
/// line-building — the caller submits the vector to the diff-based
/// screen engine).
///
/// `cumulative` maps cgroup_id -> (download, upload, packets),
/// accumulated across every poll so far. `interval` is the live
/// refresh cadence (drives the title bar).
pub fn render_top_table(
    lines: &mut Vec<String>,
    cumulative: &HashMap<u32, (u64, u64, u64)>,
    limit: usize,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();
    let cols = plan_top_columns(geo.width);

    let core = format!("zelynic top — live, {}s refresh", interval.as_secs());
    lines.push(title_bar(&core, "q quit", geo.width));

    let mut talkers: Vec<(u32, u64, u64, u64, u64)> = cumulative
        .iter()
        .map(|(cg, (dl, ul, pkt))| (*cg, *dl, *ul, dl + ul, *pkt))
        .filter(|(_, _, _, total, _)| *total > 0)
        .collect();

    if talkers.is_empty() {
        lines.push("  waiting for traffic…".to_string());
        return;
    }

    talkers.sort_by_key(|t| std::cmp::Reverse(t.3));

    // Header row (regular purple).
    if cols.show_total {
        lines.push(format!(
            "  {:>2}  {} {:>w1$} {:>w2$} {:>w3$}",
            "#",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            "TOTAL",
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        ));
    } else {
        lines.push(format!(
            "  {:>2}  {} {:>w1$} {:>w2$}",
            "#",
            brand(&truncate_label("PROCESS", cols.label_w)),
            "DOWNLOAD",
            "UPLOAD",
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));

    // Row budget counts detail lines too (NIGHT-hunt-8): a row plus
    // its eagle-eyes lines must fit as a unit.
    let line_budget = rows_for_height(geo.height);
    let mut used = 0usize;
    let mut emitted = 0usize;
    let mut top_proc_name: Option<String> = None;
    let mut grand_total_pkt: u64 = 0;

    for (i, (cgroup_id, dl_bytes, ul_bytes, total, total_pkt)) in talkers.iter().enumerate() {
        if emitted >= limit {
            break;
        }
        let details = detail_lines(conns, *cgroup_id);
        let need = 1 + details.len();
        if used + need > line_budget && emitted > 0 {
            break;
        }

        let label = truncate_label(&label_with_count(identity, conns, *cgroup_id), cols.label_w);
        grand_total_pkt += total_pkt;

        if cols.show_total {
            lines.push(format!(
                "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
                i + 1,
                label,
                format_bytes(*dl_bytes),
                format_bytes(*ul_bytes),
                format_bytes(*total),
                w0 = cols.label_w,
                w1 = cols.dl_w,
                w2 = cols.ul_w,
                w3 = cols.dl_w
            ));
        } else {
            lines.push(format!(
                "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
                i + 1,
                label,
                format_bytes(*dl_bytes),
                format_bytes(*ul_bytes),
                w0 = cols.label_w,
                w1 = cols.dl_w,
                w2 = cols.ul_w
            ));
        }
        for line in details {
            lines.push(line);
        }
        used += need;
        emitted += 1;

        if i == 0 {
            // Eagle-eyes hint (NIGHT-hunt-8): when socket detail is
            // available, name the busiest process INSIDE the top
            // cgroup, not just the cgroup's first-resolved comm —
            // "Top consumer: curl" instead of "alacritty".
            top_proc_name = conns
                .and_then(|c| c.get(*cgroup_id))
                .and_then(|d| d.socket_holders.first())
                .map(|p| p.comm.clone())
                .or_else(|| comm_from_label(&label));
        }
    }

    if talkers.len() > emitted {
        lines.push(format!(
            "  (+{} more talkers hidden — raise --limit or the window)",
            talkers.len() - emitted
        ));
    }

    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));
    lines.push(format!("  {grand_total_pkt} packets total"));

    if let Some(proc_name) = top_proc_name {
        lines.push(format!("  {} Top consumer: {proc_name}", warn_bold("→")));
        lines.push(format!(
            "  Limit it: sudo zelynic strict-single {proc_name} 100kb"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Top table keeps TOTAL at wide widths.
    #[test]
    fn top_columns_full_width() {
        let cols = plan_top_columns(100);
        assert!(cols.show_total);
        assert_eq!(cols.label_w, 100 - 6 - 3 * 10 - 3 * 2);
    }

    /// TOTAL drops before DOWNLOAD/UPLOAD on narrow frames (full
    /// layout starts at width 56: 6 rank + 14 label + 30 numerics
    /// + 6 gaps).
    #[test]
    fn top_columns_drop_total_below_56() {
        let cols = plan_top_columns(55);
        assert!(!cols.show_total);
        assert_eq!(cols.label_w, 55 - 6 - 2 * 10 - 2 * 2);
    }

    /// Ultra-narrow floor: label minimum, tightened numerics.
    #[test]
    fn top_columns_narrow_floor() {
        let cols = plan_top_columns(40);
        assert!(!cols.show_total);
        assert_eq!(cols.label_w, 14);
        assert_eq!(cols.dl_w, 9);
    }

    /// NIGHT-improve-2 line-building pin: the renderer fills the
    /// caller's vector (title bar first, waiting-note when idle) —
    /// the diff engine's input contract.
    #[test]
    fn top_table_builds_lines() {
        let mut lines = Vec::new();
        let empty: HashMap<u32, (u64, u64, u64)> = HashMap::new();
        render_top_table(
            &mut lines,
            &empty,
            10,
            &IdentityMap::new(),
            None,
            Duration::from_secs(5),
        );
        assert_eq!(lines.len(), 2, "idle table = title + waiting note");
        assert!(lines[0].starts_with("─── zelynic top — live, 5s refresh"));
        assert_eq!(lines[1], "  waiting for traffic…");
    }
}
