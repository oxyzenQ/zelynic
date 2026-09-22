// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes ranked renderer (NIGHT-boost-1): the unified live
//! monitor that merged the former observe and top commands.
//!
//! One ranked table, consumption-ordered — rank 1 is whoever is
//! eating the internet right now. The row budget is the terminal
//! height (no --limit, no hard cap): a short window shows the top
//! few, a tall one spans the list down to the quiet apps. With
//! targets the same table filters to the watched set; a single
//! target that resolves to one cgroup switches to the deep focus
//! view (see [`super::focus`]).

use std::time::Duration;

use super::{
    comm_from_label, detail_lines, focus::render_eagle_focus, format_rate_or_dash,
    label_with_count, rate_bps, rows_for_height, title_bar, truncate_label,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::Target;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::output::{brand, suggestion, warn_bold};

/// Eagle-eyes column layout derived from the frame width.
///
/// Degradation ladder (2-column gaps, 6-column rank cell):
/// - width >= 54: # | PROCESS | DOWNLOAD | UPLOAD | RATE
/// - width >= 42: # | PROCESS | DOWNLOAD | UPLOAD      (RATE dropped)
/// - width  < 42: # | PROCESS (min 12) | DOWNLOAD | UPLOAD at 9-wide numerics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EagleColumns {
    label_w: usize,
    dl_w: usize,
    ul_w: usize,
    show_rate: bool,
}

/// Plan the eagle-eyes column layout for a given terminal width.
#[must_use]
fn plan_eagle_columns(width: usize) -> EagleColumns {
    const RANK_W: usize = 6; // "  N  " rank column incl. margins
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;

    // Full layout: rank + label + 3 numeric columns (dl, ul, rate).
    if width >= RANK_W + LABEL_MIN + 3 * NUM_W + 3 * 2 {
        return EagleColumns {
            label_w: width - RANK_W - 3 * NUM_W - 3 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_rate: true,
        };
    }

    // RATE dropped (the realtime-precision column is also the widest
    // sacrifice on a narrow frame — dl/ul deltas survive): rank +
    // label + 2 numeric columns.
    if width >= RANK_W + LABEL_MIN + 2 * NUM_W + 2 * 2 {
        return EagleColumns {
            label_w: width - RANK_W - 2 * NUM_W - 2 * 2,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_rate: false,
        };
    }

    // Narrow fallback: tighter numerics, label pinned to the minimum.
    EagleColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        show_rate: false,
    }
}

/// Resolve target tokens against the identity map.
///
/// Numeric tokens are cgroup IDs verbatim; name tokens expand to
/// every cgroup whose comm matches (case-insensitive) — `brave`
/// watches ALL brave cgroups, the whole-app semantics the
/// strict/block family's /proc resolution gives. Names that match
/// nothing come back separately so the frame can say so (a typo'd
/// app name must not silently render an empty table).
#[must_use]
fn resolve_targets(tokens: &[Target], identity: &IdentityMap) -> (Vec<u32>, Vec<String>) {
    let mut ids: Vec<u32> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    for token in tokens {
        match token {
            Target::CgroupId(id) => {
                if !ids.contains(id) {
                    ids.push(*id);
                }
            }
            Target::ProcessName(name) => {
                let name_lower = name.to_lowercase();
                let mut matched = false;
                for entry in identity.all() {
                    if entry.comm.to_lowercase() == name_lower && !ids.contains(&entry.cgroup_id) {
                        ids.push(entry.cgroup_id);
                        matched = true;
                    }
                }
                if !matched {
                    unresolved.push(name.clone());
                }
            }
        }
    }
    (ids, unresolved)
}

/// Render one eagle-eyes frame (NIGHT-improve-2: line-building — the
/// caller submits the vector to the diff-based screen engine, which
/// emits only the rows that changed).
///
/// `tokens` is the parsed positional TARGETS spec (empty = watch
/// all). Resolution runs per frame against the LIVE identity map,
/// so an app started mid-session appears on the next refresh — the
/// monitor follows reality, no restart. A single token resolving to
/// exactly one cgroup switches to the deep focus view (the old
/// `observe --cgroup` depth, now autodetected). `interval` is the
/// poll interval between frames; the RATE column reports
/// `delta / interval` as bytes per second.
pub fn render_eagle_eyes(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    tokens: &[Target],
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();
    let cols = plan_eagle_columns(geo.width);

    let (ids, unresolved) = resolve_targets(tokens, identity);

    // Single token, single cgroup: the deep focus view.
    if tokens.len() == 1 && ids.len() == 1 && unresolved.is_empty() {
        render_eagle_focus(lines, summary, identity, conns, ids[0], interval);
        return;
    }

    let interval_str = if interval.as_secs() >= 1 {
        format!("{}s refresh", interval.as_secs())
    } else {
        format!("{:.1}s refresh", interval.as_secs_f64())
    };
    let title_core = if tokens.is_empty() {
        format!("zelynic eagle-eyes — {interval_str}")
    } else {
        let n = ids.len();
        format!(
            "zelynic eagle-eyes — {n} target{} — {interval_str}",
            if n == 1 { "" } else { "s" }
        )
    };
    lines.push(title_bar(&title_core, "q quit", geo.width));

    // A watched name with no live cgroup says so — the empty-table
    // lie is exactly what the discovery stage must not tell.
    for name in &unresolved {
        lines.push(format!("  no app named '{name}' — see 'zelynic list-apps'"));
    }

    if summary.total_packets == 0 && summary.total_ingress_packets == 0 {
        lines.push("  waiting for traffic…".to_string());
        return;
    }

    // Candidate rows: every talking cgroup, or the watched subset.
    let mut sorted: Vec<CgroupDelta> = if tokens.is_empty() {
        summary.cgroups.clone()
    } else {
        summary
            .cgroups
            .iter()
            .filter(|c| ids.contains(&c.cgroup_id))
            .cloned()
            .collect()
    };
    if !tokens.is_empty() && sorted.is_empty() {
        lines.push("  no traffic for the watched targets since last check".to_string());
        return;
    }

    // Rank 1 = the heaviest consumer of THIS interval (the
    // realtime-precision sort; the old top ranked lifetime
    // cumulative, the old observe ranked per-frame — eagle-eyes is
    // the live one, and the focus view carries the lifetime story).
    sorted.sort_by_key(|c| std::cmp::Reverse(c.bytes + c.ingress_bytes));

    // Header row (regular purple — brand layer, NIGHT-hunt-5).
    if cols.show_rate {
        lines.push(format!(
            "  {:>2}  {} {:>w1$} {:>w2$} {:>w3$}",
            "#",
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
    // its eagle-eyes lines must fit as a unit. The budget is the
    // terminal height (NIGHT-boost-1: the former --limit and the
    // 20-row cap are gone — raise the window to see more).
    let line_budget = rows_for_height(geo.height);
    let mut used = 0usize;
    let mut emitted = 0usize;
    let mut top_proc_name: Option<String> = None;
    for (i, c) in sorted.iter().enumerate() {
        let details = detail_lines(conns, c.cgroup_id);
        let need = 1 + details.len();
        if used + need > line_budget && emitted > 0 {
            break;
        }
        render_eagle_row(lines, c, identity, conns, &cols, interval, i + 1);
        for line in details {
            lines.push(line);
        }
        used += need;
        emitted += 1;

        if i == 0 {
            // Eagle-eyes hint (NIGHT-hunt-8): when socket detail is
            // available, name the busiest process INSIDE the rank-1
            // cgroup, not just the cgroup's first-resolved comm —
            // "Top consumer: curl" instead of "alacritty".
            top_proc_name = conns
                .and_then(|cm| cm.get(c.cgroup_id))
                .and_then(|d| d.socket_holders.first())
                .map(|p| p.comm.clone())
                .or_else(|| comm_from_label(&label_with_count(identity, conns, c.cgroup_id)));
        }
    }
    if sorted.len() > emitted {
        lines.push(format!(
            "  (+{} more hidden — raise the window)",
            sorted.len() - emitted
        ));
    }

    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));
    // improve-13 flagship footer: a column-aligned TOTAL row — the
    // aggregate sits under the exact columns it sums (the rank cell
    // stays blank). Footer honesty (NIGHT-hunt-15): every candidate
    // counts, not just the rows the window budget could show.
    let dl_sum: u64 = sorted.iter().map(|c| c.ingress_bytes).sum();
    let ul_sum: u64 = sorted.iter().map(|c| c.bytes).sum();
    if cols.show_rate {
        lines.push(format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            "",
            "TOTAL",
            format_bytes(dl_sum),
            format_bytes(ul_sum),
            format_rate_or_dash(rate_bps(dl_sum + ul_sum, interval)),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        ));
    } else {
        lines.push(format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
            "",
            "TOTAL",
            format_bytes(dl_sum),
            format_bytes(ul_sum),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
    // Meta line (compact): scale of the frame, one line, bullet-
    // separated — never mixed into the numeric grid. Filtered frames
    // name their share of the cgroup census.
    let packets = sorted
        .iter()
        .map(|c| c.packets + c.ingress_packets)
        .sum::<u64>();
    if tokens.is_empty() {
        lines.push(format!("  {packets} packets · {} cgroups", sorted.len()));
    } else {
        lines.push(format!(
            "  {packets} packets · {} of {} cgroups",
            sorted.len(),
            summary.cgroups.len()
        ));
    }
    if identity.is_empty() {
        // Rare: the /proc walk resolved nothing (permissions, a
        // stripped container). Say so instead of pretending the raw
        // cgroup IDs are app names.
        lines.push("  (identities unresolved — labels show raw cgroup IDs)".to_string());
    }

    // Discovery hint (unfiltered frames only): the rank-1 cgroup's
    // busiest process plus the exact strict-single command to cap it.
    if let Some(proc_name) = top_proc_name.filter(|_| tokens.is_empty()) {
        lines.push(format!("  {} Top consumer: {proc_name}", warn_bold("→")));
        // The actionable tip renders in the documented suggestion
        // tier (crystal white, the "tip:" contract) instead of plain
        // body text — improve-13 color-precision: the yellow arrow
        // flags, the white line tells you what to do.
        lines.push(format!(
            "  {}",
            suggestion(&format!(
                "Limit it: sudo zelynic strict-single {proc_name} 100kb"
            ))
        ));
    }
}

/// One ranked data row.
fn render_eagle_row(
    lines: &mut Vec<String>,
    c: &CgroupDelta,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cols: &EagleColumns,
    interval: Duration,
    rank: usize,
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
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            rank,
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
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
            rank,
            label,
            dl,
            ul,
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
}

// NIGHT-boost-1: the renderer pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like the
// limiter's math_tests and the diff engine's pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_tests.rs"]
mod eagle_tests;
