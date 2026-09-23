// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes ranked renderer (NIGHT-boost-1): the unified live
//! monitor that merged the former observe and top commands.
//!
//! One leaderboard, session-ranked (NIGHT-boost-5): rank 1 is whoever
//! has eaten the most bytes SINCE THE MONITOR STARTED, not whoever
//! twitched in the last interval. The owner's scenario: A downloads
//! hard, accumulates 10 GB, stops — A keeps the crown until B's
//! accumulated total passes it. Rows persist across quiet frames (the
//! board renders from the session accumulator; a one-second hush no
//! longer wipes the table), the per-frame DOWNLOAD/UPLOAD rates
//! refresh every interval, and the TOTAL column carries the
//! accumulated figure — the v10 function restored.
//!
//! NIGHT-boost-14 (the owner's masterclass engraving) made the frame a
//! PINNED composition; the footer half of that contract — the grip
//! block, its tiers, its compression ladder — lives in
//! [`super::footer`]. The table half lives here:
//!
//! - **Static traffic-light tiers**: rank 1 champion red, rank 2
//!   warning yellow, rank 3 and below status green — the takeover
//!   BLINK is gone (eye strain): crowns read by color, never by
//!   animation.
//! - **Grey subordinates**: the subprocess usage lines render calm
//!   grey — context, not content.
//! - **Breathing gap**: one blank line below the title bar — the
//!   header used to sit too near the brand.
//! - **Adaptive compact** (dynamic WxH): subprocess detail hides and
//!   long text is cut down on narrow frames; the label column already
//!   degraded, the detail lines are the next casualty.
//! - **The pin**: the frame spans the terminal height, the table
//!   floats under the header, and the built footer pins to the bottom
//!   through measured padding — it never follows the table's length.
//!
//! The row budget follows the terminal height (no --limit, no cap):
//! a short window shows the top few consumers, a tall one spans the
//! list down to the quiet apps. With targets the same table filters
//! to the watched set; a single target that resolves to one cgroup
//! switches to the deep focus view (see [`super::focus`]).

use std::time::Duration;

use super::footer::{build_grip_footer, grid_line, plan_footer_tier, FooterCensus, TOP_CHROME};
use super::{
    comm_from_label, detail_lines, focus::render_eagle_focus, format_rate_or_dash,
    label_with_count, plan_eagle_columns, rate_bps, title_bar, truncate_label, EagleColumns,
    FrameGeometry, SessionAcc, SessionState,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::Target;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::output::{brand, grey, hot, ok, warn};

/// Subprocess detail hide threshold (NIGHT-boost-14 adaptive
/// compact): below the width where the TOTAL column itself degrades
/// away, the endpoint lines go too — a frame too narrow for the
/// session figure is too narrow for endpoint text. Wider frames
/// show them grey, each trimmed to the frame width so no row ever
/// wraps and shifts the pinned composition.
const DETAIL_HIDE_BELOW: usize = 51;

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
/// figure. Since NIGHT-boost-14 the frame is pinned to the full
/// terminal height with the grip footer near the bottom.
///
/// `uptime` (NIGHT-boost-17): the session age, grey `uptime 1m:10s`
/// below the footer block in every compression tier.
#[allow(clippy::too_many_arguments)]
pub fn render_eagle_eyes(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    tokens: &[Target],
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
    session: &mut SessionState,
    uptime: Duration,
) {
    let geo = FrameGeometry::probe();
    render_eagle_eyes_at(
        lines, summary, tokens, identity, conns, interval, session, uptime, geo,
    );
}

/// Size-injectable core of [`render_eagle_eyes`] (the emit/emit_at
/// discipline of the diff engine): contract pins drive deterministic
/// widths and heights instead of the piped-fallback probe, so the
/// adaptive ladder and the pinned footer are testable at every size.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_eagle_eyes_at(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    tokens: &[Target],
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
    session: &mut SessionState,
    uptime: Duration,
    geo: FrameGeometry,
) {
    let cols = plan_eagle_columns(geo.width);

    // The fold happens before anything renders: even an idle frame
    // (or the one-frame tolerance for a transient map-read error —
    // an Err poll folds an empty summary) leaves the board intact.
    session.absorb(summary);

    let (ids, unresolved) = resolve_targets(tokens, identity);

    // Single token, single cgroup: the deep focus view.
    if tokens.len() == 1 && ids.len() == 1 && unresolved.is_empty() {
        render_eagle_focus(
            lines, summary, identity, conns, ids[0], interval, uptime, geo,
        );
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
        let plural = if n == 1 { "" } else { "s" };
        format!("zelynic eagle-eyes — {n} target{plural} — {interval_str}")
    };
    lines.push(title_bar(&title_core, "q quit", geo.width));

    // The breathing gap (NIGHT-boost-14): the column header used to
    // sit one row under the title bar — too near the brand, the
    // owner's call. One blank line of air.
    lines.push(String::new());

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
    // title and the pinned footer — the frame identity never
    // collapses, and once traffic HAS been seen this branch is dead:
    // the board holds every row it ever ranked.
    if session.is_empty() {
        lines.push("  waiting for traffic…".to_string());
    } else if !tokens.is_empty() && board.is_empty() {
        lines.push("  no traffic for the watched targets yet".to_string());
    }

    // Footer planning FIRST (NIGHT-boost-14): the pinned footer is
    // BUILT before the table renders, so the pin's line count is the
    // MEASURED footer length — the optional discovery hint shortens
    // the block without shifting the pin off the bottom. The tier
    // ladder picks the compression level; the table gets whatever
    // height remains after the built block.
    let extra = usize::from(identity.is_empty());
    let tier = plan_footer_tier(geo.height, extra);

    // Top consumer (autodetect on the rank-1 cgroup, NIGHT-hunt-8):
    // when socket detail is available, name the busiest process
    // INSIDE the champion cgroup, not just its first-resolved comm —
    // "Top consumer: curl" instead of "alacritty".
    let top_proc_name = board.first().and_then(|(cgroup_id, _)| {
        conns
            .and_then(|cm| cm.get(*cgroup_id))
            .and_then(|d| d.socket_holders.first())
            .map(|p| p.comm.clone())
            .or_else(|| comm_from_label(&label_with_count(identity, conns, *cgroup_id)))
    });

    // Footer honesty (NIGHT-hunt-15): every candidate counts, not
    // just the rows the window budget could show. All four sums are
    // SATURATING (NIGHT-boost-16): a debug build used to panic at
    // u64::MAX and a release build wrapped — saturated sums read as
    // u64::MAX, the honest ceiling of the u64 accumulator.
    let candidates: Vec<&CgroupDelta> = if tokens.is_empty() {
        summary.cgroups.iter().collect()
    } else {
        summary
            .cgroups
            .iter()
            .filter(|c| ids.contains(&c.cgroup_id))
            .collect()
    };
    let dl_sum: u64 = candidates
        .iter()
        .map(|c| c.ingress_bytes)
        .fold(0, u64::saturating_add);
    let ul_sum: u64 = candidates
        .iter()
        .map(|c| c.bytes)
        .fold(0, u64::saturating_add);
    let grand: u64 = board
        .iter()
        .map(|(_, a)| a.dl.saturating_add(a.ul))
        .fold(0, u64::saturating_add);
    let packets = candidates
        .iter()
        .map(|c| c.packets.saturating_add(c.ingress_packets))
        .fold(0, u64::saturating_add);
    // The census: scale of the frame, one line, "+"-joined (the
    // owner's NIGHT-boost-14 wording) — never mixed into the numeric
    // grid. Filtered frames name their share of the session census.
    let census_text = if tokens.is_empty() {
        format!("{packets} packets + {} cgroups", board.len())
    } else {
        format!(
            "{packets} packets + {} of {} cgroups",
            board.len(),
            session.len()
        )
    };

    // ── The grip footer (NIGHT-boost-14), the owner's exact spec ──
    //
    // Built BEFORE the table renders (see render/footer.rs): the
    // MEASURED length of the block is what pins it to the bottom,
    // and the table renders into whatever height remains.
    let footer = build_grip_footer(
        &FooterCensus {
            tier,
            dl_sum,
            ul_sum,
            grand,
            census_text,
            identities_unresolved: identity.is_empty(),
            top_proc_name,
            unfiltered: tokens.is_empty(),
            uptime,
        },
        &cols,
        geo,
        interval,
    );

    // The pin line: the footer's measured length fixes where the
    // frame's content must stop.
    let footer_start = geo.height.saturating_sub(footer.len());

    // Header row (regular purple — brand layer, NIGHT-hunt-5). The
    // rank cell is BLANK (NIGHT-boost-5: the owner retired the "#"
    // header — the digits below speak for themselves) and PROCESS is
    // padded to the label width BEFORE coloring, so the header cells
    // sit exactly over the columns they name. The grid line below
    // the header renders purple too (NIGHT-boost-14: "same as
    // above") — the border family shares the header's color.
    let table_room = footer_start.saturating_sub(lines.len());
    let show_table = !session.is_empty() && (tokens.is_empty() || !board.is_empty());
    // The table needs room for its own chrome (header + grid) plus at
    // least one data row; below that the footer carries the story.
    if show_table && table_room >= TOP_CHROME - 1 {
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
        lines.push(grid_line(geo.width));

        // Row budget counts detail lines too (NIGHT-hunt-8): a row
        // plus its eagle-eyes lines must fit as a unit. The budget
        // is what remains of the height after the top chrome and the
        // pinned footer (NIGHT-boost-1 removed --limit and the cap —
        // the window IS the budget; NIGHT-boost-14 made the footer's
        // claim on it explicit).
        let row_room = footer_start.saturating_sub(lines.len());
        let mut used = 0usize;
        let mut emitted = 0usize;
        for (i, (cgroup_id, acc)) in board.iter().enumerate() {
            // Adaptive subprocess detail (NIGHT-boost-14): grey, and
            // width-aware — hidden below the TOTAL-column boundary,
            // each line trimmed to the frame width above it, so a
            // long process/endpoint string can never wrap the frame
            // or shift the pinned footer.
            let mut details = if geo.width >= DETAIL_HIDE_BELOW {
                detail_lines(conns, *cgroup_id)
            } else {
                Vec::new()
            };
            for line in &mut details {
                *line = grey(&truncate_label(line, geo.width));
            }
            let need = 1 + details.len();
            if used + need > row_room {
                if emitted == 0 {
                    // The champion always shows (NIGHT-boost-5): trim
                    // its own detail to what the window can hold.
                    let room = row_room.saturating_sub(1).min(details.len());
                    details.truncate(room);
                } else {
                    break;
                }
            }
            // This frame's deltas for the rates (a quiet app renders
            // em dashes — it stays on the board with its totals).
            let delta = summary.cgroups.iter().find(|c| c.cgroup_id == *cgroup_id);
            let dl_rate = delta
                .map(|c| rate_bps(c.ingress_bytes, interval))
                .unwrap_or(0);
            let ul_rate = delta.map(|c| rate_bps(c.bytes, interval)).unwrap_or(0);

            let shown_details = details.len();
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
            );
            for line in details {
                lines.push(line);
            }
            used += 1 + shown_details;
            emitted += 1;
        }
        if board.len() > emitted {
            lines.push(format!(
                "  {}",
                grey(&format!(
                    "(+{} more hidden — raise the window)",
                    board.len() - emitted
                ))
            ));
        }
    }

    // ── The pin (NIGHT-boost-14) ──────────────────────────────────
    //
    // The footer lands at the bottom of the terminal, never
    // following the table: blank padding absorbs the middle, and on
    // the pathological over-height frame the pin outranks the lowest
    // table rows (popped from the end — the least important ranks
    // go first, never the footer).
    while lines.len() > footer_start {
        lines.pop();
    }
    while lines.len() < footer_start {
        lines.push(String::new());
    }
    lines.extend(footer);
}

/// One ranked data row. The static traffic-light tiers
/// (NIGHT-boost-14): rank 1 champion red, rank 2 warning yellow,
/// rank 3 and below status green — the owner's exact color contract,
/// calmer than the white it replaced and with no blink anywhere.
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
) {
    let label = truncate_label(&label_with_count(identity, conns, cgroup_id), cols.label_w);
    // Saturating session sum (NIGHT-boost-16): saturation, not
    // panic or wrap, in the TOTAL cell.
    let session_total = acc.dl.saturating_add(acc.ul);
    let body = if cols.show_total {
        format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            format_bytes(session_total),
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
        1 => hot(&body),
        2 => warn(&body),
        _ => ok(&body),
    };
    lines.push(painted);
}

// NIGHT-boost-1: the renderer pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like the
// limiter's math_tests and the diff engine's pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_tests.rs"]
mod eagle_tests;
