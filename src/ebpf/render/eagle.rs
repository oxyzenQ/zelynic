// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes ranked renderer (NIGHT-boost-1): the unified live
//! monitor that merged the former observe and top commands.
//!
//! One leaderboard, session-ranked (NIGHT-boost-5): rank 1 is whoever
//! has eaten the most bytes SINCE THE MONITOR STARTED, not whoever
//! twitched in the last interval. The owner's scenario: A downloads
//! hard, accumulates 10 GB, stops — A keeps the crown until B's
//! accumulated total passes it, and the takeover blinks. Rows persist
//! across quiet frames (the board renders from the session
//! accumulator; a one-second hush no longer wipes the table), the
//! per-frame DOWNLOAD/UPLOAD rates refresh every interval, and the
//! TOTAL column carries the accumulated figure — the v10 function
//! restored. Rank 1 wears champion red (blinking for the first 3s of
//! a takeover), rank 2 warning yellow, rank 3 and below white.
//!
//! The row budget is the terminal height (no --limit, no cap): a
//! short window shows the top few consumers, a tall one spans the
//! list down to the quiet apps. With targets the same table filters
//! to the watched set; a single target that resolves to one cgroup
//! switches to the deep focus view (see [`super::focus`]).

use std::time::{Duration, Instant};

use super::{
    comm_from_label, detail_lines, focus::render_eagle_focus, format_rate_or_dash,
    label_with_count, rate_bps, rows_for_height, title_bar, truncate_label, SessionAcc,
    SessionState,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::Target;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::output::{brand, hot, hot_blink, signature_footer, suggestion, warn, warn_bold};

/// Eagle-eyes column layout derived from the frame width.
///
/// Degradation ladder (6-column rank cell, 1-column gaps):
/// - width >= 51: (rank) | PROCESS | DOWNLOAD | UPLOAD | TOTAL
/// - width >= 40: (rank) | PROCESS | DOWNLOAD | UPLOAD   (TOTAL dropped)
/// - width  < 40: (rank) | PROCESS (min 12) | DOWNLOAD | UPLOAD at 9-wide
///
/// DOWNLOAD and UPLOAD carry per-frame RATES (delta / interval —
/// "what is moving right now"); TOTAL carries the session-accumulated
/// bytes (NIGHT-boost-5: the v10 "total accumulated" function
/// restored as the ranking key's own column). The old combined RATE
/// column was dl+ul restated — the TOTAL column replaces it.
///
/// NIGHT-boost-5: the header rank cell is blank (the owner's "#"
/// header retired) and the absorption math makes every data row end
/// flush at the frame width — the label column absorbs exactly what
/// the rank cell, the gaps, and the numeric columns leave, so the
/// right border (title bar, separators, rows, TOTAL) is one straight
/// edge mirroring the left. The old reserve formula over-allocated
/// three spare columns, leaving every row 3 short of the separator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EagleColumns {
    label_w: usize,
    dl_w: usize,
    ul_w: usize,
    show_total: bool,
}

/// Plan the eagle-eyes column layout for a given terminal width.
#[must_use]
fn plan_eagle_columns(width: usize) -> EagleColumns {
    const RANK_W: usize = 6; // 2 gutter + 2 rank digits + 2 gap
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;

    // Full layout: rank + label + 3 numeric columns (dl, ul, total).
    // Reserve = rank cell + 3 x (gap + numeric): the label absorbs
    // the rest, so a full row spans exactly the frame width.
    if width >= RANK_W + LABEL_MIN + 3 * (1 + NUM_W) {
        return EagleColumns {
            label_w: width - RANK_W - 3 * (1 + NUM_W),
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: true,
        };
    }

    // TOTAL dropped (the session figure survives in the focus view;
    // the live rates are the realtime sacrifice ladder's first cut):
    // rank + label + 2 numeric columns.
    if width >= RANK_W + LABEL_MIN + 2 * (1 + NUM_W) {
        return EagleColumns {
            label_w: width - RANK_W - 2 * (1 + NUM_W),
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: false,
        };
    }

    // Narrow fallback: tighter numerics, label pinned to the minimum.
    EagleColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        show_total: false,
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
/// poll interval between frames; the DOWNLOAD and UPLOAD columns
/// report `delta / interval` as bytes per second.
///
/// `session` is the monitor's memory (NIGHT-boost-5): each frame's
/// deltas fold in FIRST, then the table renders from the accumulated
/// leaderboard — ranking by session total, rows persisting across
/// quiet frames, and the TOTAL column carrying the accumulated
/// figure. The frame ends with the signature footer, bottom-left.
pub fn render_eagle_eyes(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    tokens: &[Target],
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
    session: &mut SessionState,
) {
    let geo = super::FrameGeometry::probe();
    let cols = plan_eagle_columns(geo.width);

    // The fold happens before anything renders: even an idle frame
    // (or the one-frame tolerance for a transient map-read error —
    // an Err poll folds an empty summary) leaves the board intact.
    session.absorb(summary);

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

    // The leaderboard: session-accumulated per cgroup, consumption-
    // ordered, filtered to the watched set when targets narrow the
    // frame (NIGHT-boost-5 — the old per-frame delta sort made every
    // quiet second reshuffle the board and wiped idle apps entirely).
    let board: Vec<(u32, SessionAcc)> = if tokens.is_empty() {
        session.ranked()
    } else {
        session
            .ranked()
            .into_iter()
            .filter(|(id, _)| ids.contains(id))
            .collect()
    };

    // Empty-board honesty: before the first packet, the frame says
    // so; a watched set that never talked says so. Both keep the
    // title and the signature footer — the frame identity never
    // collapses, and once traffic HAS been seen this branch is dead:
    // the board holds every row it ever ranked.
    if session.is_empty() {
        lines.push("  waiting for traffic…".to_string());
        lines.push(String::new());
        lines.push(format!("  {}", signature_footer()));
        return;
    }
    if !tokens.is_empty() && board.is_empty() {
        lines.push("  no traffic for the watched targets yet".to_string());
        lines.push(String::new());
        lines.push(format!("  {}", signature_footer()));
        return;
    }

    // Header row (regular purple — brand layer, NIGHT-hunt-5). The
    // rank cell is BLANK (NIGHT-boost-5: the owner retired the "#"
    // header — the digits below speak for themselves) and PROCESS is
    // padded to the label width BEFORE coloring, so the header cells
    // sit exactly over the columns they name — the old header left
    // the label unpadded, cramming every column header to the left
    // of the data grid (the "mismatch positions" the owner reported).
    if cols.show_total {
        lines.push(brand(&format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            "",
            truncate_label("PROCESS", cols.label_w),
            "DOWNLOAD",
            "UPLOAD",
            "TOTAL",
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        )));
    } else {
        lines.push(brand(&format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
            "",
            truncate_label("PROCESS", cols.label_w),
            "DOWNLOAD",
            "UPLOAD",
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        )));
    }
    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));

    // Champion bookkeeping (NIGHT-boost-5): the rank-1 row blinks
    // champion red for 3s after a takeover, then goes solid; rank 2
    // renders warning yellow; the rest stay white.
    let blink = board
        .first()
        .map(|(id, _)| session.note_rank1(*id, Instant::now()))
        .unwrap_or(false);

    // Row budget counts detail lines too (NIGHT-hunt-8): a row plus
    // its eagle-eyes lines must fit as a unit. The budget is the
    // terminal height (NIGHT-boost-1: the former --limit and the
    // 20-row cap are gone — raise the window to see more).
    let line_budget = rows_for_height(geo.height);
    let mut used = 0usize;
    let mut emitted = 0usize;
    let mut top_proc_name: Option<String> = None;
    for (i, (cgroup_id, acc)) in board.iter().enumerate() {
        let details = detail_lines(conns, *cgroup_id);
        let need = 1 + details.len();
        if used + need > line_budget && emitted > 0 {
            break;
        }
        // This frame's deltas for the rates (a quiet app renders
        // em dashes — it stays on the board with its totals).
        let delta = summary.cgroups.iter().find(|c| c.cgroup_id == *cgroup_id);
        let dl_rate = delta
            .map(|c| rate_bps(c.ingress_bytes, interval))
            .unwrap_or(0);
        let ul_rate = delta.map(|c| rate_bps(c.bytes, interval)).unwrap_or(0);

        render_eagle_row(
            lines,
            *cgroup_id,
            *acc,
            dl_rate,
            ul_rate,
            identity,
            conns,
            &cols,
            i + 1,
            blink,
        );
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
                .and_then(|cm| cm.get(*cgroup_id))
                .and_then(|d| d.socket_holders.first())
                .map(|p| p.comm.clone())
                .or_else(|| comm_from_label(&label_with_count(identity, conns, *cgroup_id)));
        }
    }
    if board.len() > emitted {
        lines.push(format!(
            "  (+{} more hidden — raise the window)",
            board.len() - emitted
        ));
    }

    lines.push(format!("  {}", "─".repeat(geo.width.saturating_sub(2))));
    // improve-13 flagship footer: a column-aligned TOTAL row — the
    // aggregate sits under the exact columns it sums (the rank cell
    // stays blank). Footer honesty (NIGHT-hunt-15): every candidate
    // counts, not just the rows the window budget could show — the
    // rates sum this frame's deltas over the whole (filtered)
    // summary, and the TOTAL sums the session leaderboard's grand
    // total over the same set.
    let candidates: Vec<&CgroupDelta> = if tokens.is_empty() {
        summary.cgroups.iter().collect()
    } else {
        summary
            .cgroups
            .iter()
            .filter(|c| ids.contains(&c.cgroup_id))
            .collect()
    };
    let dl_sum: u64 = candidates.iter().map(|c| c.ingress_bytes).sum();
    let ul_sum: u64 = candidates.iter().map(|c| c.bytes).sum();
    let grand: u64 = board.iter().map(|(_, a)| a.dl + a.ul).sum();
    if cols.show_total {
        lines.push(format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            "",
            "TOTAL",
            format_rate_or_dash(rate_bps(dl_sum, interval)),
            format_rate_or_dash(rate_bps(ul_sum, interval)),
            format_bytes(grand),
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
            format_rate_or_dash(rate_bps(dl_sum, interval)),
            format_rate_or_dash(rate_bps(ul_sum, interval)),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        ));
    }
    // Meta line (compact): scale of the frame, one line, bullet-
    // separated — never mixed into the numeric grid. Filtered frames
    // name their share of the session census.
    let packets = candidates
        .iter()
        .map(|c| c.packets + c.ingress_packets)
        .sum::<u64>();
    if tokens.is_empty() {
        lines.push(format!("  {packets} packets · {} cgroups", board.len()));
    } else {
        lines.push(format!(
            "  {packets} packets · {} of {} cgroups",
            board.len(),
            session.len()
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

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // one blank line of breathing room above it.
    lines.push(String::new());
    lines.push(format!("  {}", signature_footer()));
}

/// One ranked data row. Rank 1 renders champion red — blinking while
/// the takeover window is live — rank 2 warning yellow, and the rest
/// plain white (the owner's exact color contract, NIGHT-boost-5).
#[allow(clippy::too_many_arguments)]
fn render_eagle_row(
    lines: &mut Vec<String>,
    cgroup_id: u32,
    acc: SessionAcc,
    dl_rate: u64,
    ul_rate: u64,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cols: &EagleColumns,
    rank: usize,
    blink: bool,
) {
    let label = truncate_label(&label_with_count(identity, conns, cgroup_id), cols.label_w);
    let body = if cols.show_total {
        format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            format_bytes(acc.dl + acc.ul),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        )
    } else {
        format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        )
    };
    let painted = match rank {
        1 if blink => hot_blink(&body),
        1 => hot(&body),
        2 => warn(&body),
        _ => body,
    };
    lines.push(painted);
}

// NIGHT-boost-1: the renderer pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like the
// limiter's math_tests and the diff engine's pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_tests.rs"]
mod eagle_tests;
