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
//! longer wipes the table), the per-frame download/upload rates
//! refresh every interval, and the total column carries the
//! accumulated figure — the v10 function restored (engrave-1
//! lowercased the titles: top process, download, upload, total;
//! engrave-4 re-seated them: the process title spans the identity
//! region from the canonical text column, and every row ends on the
//! two-column right gutter — symmetric air at both rails).
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
//!   degraded, the detail lines are the next casualty — and since
//!   NIGHT-engrave-4 the column ladder itself is the threshold
//!   (`cols.show_total`), one source of truth where a parallel
//!   constant used to drift.
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

use super::border;
use super::footer::{build_grip_footer, grid_line, plan_footer_tier, FooterCensus, TOP_CHROME};
use super::{
    detail_lines, focus::render_eagle_focus, format_rate_or_dash, label_with_count,
    plan_eagle_columns, rate_bps, title_bar, truncate_label, EagleColumns, FrameGeometry,
    SessionAcc, SessionState,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::format_count;
use crate::ebpf::limiter::Target;
use crate::ebpf::loader::CounterSummary;
use crate::output::{brand, grey, hot, ok, warn};

/// Columns the rank furniture occupies between the shared gutter
/// and the label column: the two-wide rank cell plus its two-wide
/// gap (NIGHT-engrave-4). The header's process title spans this plus
/// the label width — one identity region (rank + process), titled
/// from the frame's canonical text column. Kept in step with
/// render::plan_eagle_columns' rank reserve (the reserve's non-gutter
/// half); the header-alignment pins catch any drift.
const RANK_SPAN: usize = 4;

/// Resolve target tokens against the identity map.
///
/// Numeric tokens (bare or `cg:`-prefixed — the display prefix
/// round-trips since NIGHT-boost-37, so a label copied off the
/// table watches the cgroup it names) are cgroup IDs verbatim;
/// name tokens expand to every cgroup whose comm matches
/// (case-insensitive) — `brave`
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
/// configured cadence (the status line's identity); `span` is the
/// MEASURED poll-to-poll span (NIGHT-lts-3): the DOWNLOAD and
/// UPLOAD columns report `delta / span` — the beat scheduler fires
/// on the first 50ms wake past the cadence, so the honest
/// denominator is the span the counters actually accumulated over
/// (nominal division overstated every rate, and doubled the
/// recovery spike after a transient map-read error).
///
/// `session` is the monitor's memory (NIGHT-boost-5): each frame's
/// deltas fold in FIRST, then the table renders from the accumulated
/// leaderboard — ranking by session total, rows persisting across
/// quiet frames, and the TOTAL column carrying the accumulated
/// figure. Since NIGHT-boost-14 the frame is pinned to the full
/// terminal height with the grip footer near the bottom. `uptime`
/// (NIGHT-boost-17; folded into the census row by NIGHT-engrave-1):
/// the session age, riding the total row in every tier — and, since
/// NIGHT-engrave-6, dividing the footer speed pair's AVG legs; the
/// session's watched-set peaks (the pair's MAX figures) fold in with
/// the same frame's deltas.
#[allow(clippy::too_many_arguments)]
pub fn render_eagle_eyes(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    tokens: &[Target],
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    interval: Duration,
    span: Duration,
    session: &mut SessionState,
    uptime: Duration,
) {
    let geo = FrameGeometry::probe();
    render_eagle_eyes_at(
        lines, summary, tokens, identity, conns, interval, span, session, uptime, geo,
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
    span: Duration,
    session: &mut SessionState,
    uptime: Duration,
    geo: FrameGeometry,
) {
    // NIGHT-boost-20: compose into the bordered inset (render/border.rs).
    let full_width = geo.width;

    // The fold happens before anything renders: even an idle frame
    // (or the one-frame tolerance for a transient map-read error —
    // an Err poll folds an empty summary) leaves the board intact.
    session.absorb(summary);

    let (ids, unresolved) = resolve_targets(tokens, identity);

    // The session peaks (NIGHT-engrave-6): one more fold pass over
    // the same summary, noting the watched set's aggregate into the
    // running maxima the footer's `total max dl | ul` line renders.
    // The scope matches the board filter exactly — `None` on an
    // unfiltered frame (the machine-wide aggregate), `Some(ids)` on
    // a filtered one — and it notes BEFORE the focus branch returns,
    // so a focus episode's peaks track the focused cgroup too (the
    // peaks persist across the view switch, like every session
    // figure; the max line renders on the ranked frames).
    session.note_frame(summary, if tokens.is_empty() { None } else { Some(&ids) });

    // Single token, single cgroup: the focus view (own border inset).
    if tokens.len() == 1 && ids.len() == 1 && unresolved.is_empty() {
        render_eagle_focus(
            lines, summary, identity, conns, ids[0], interval, span, uptime, geo,
        );
        return;
    }

    let geo = border::content_geo(geo);
    let cols = plan_eagle_columns(geo.width);

    // NIGHT-engrave-3: identity only — the top-right key hint
    // retired with the census (the legend's only home is the
    // footer's status line, which is why it rides every tier).
    let title_core = if tokens.is_empty() {
        "zelynic eagle-eyes".to_string()
    } else {
        let n = ids.len();
        let plural = if n == 1 { "" } else { "s" };
        format!("zelynic eagle-eyes — {n} target{plural}")
    };
    // NIGHT-engrave-8: the bar composes at the FRAME's width —
    // one column inside the terminal — so wrap's leading inset
    // lands the corners one column from each edge.
    lines.push(title_bar(&title_core, border::frame_width(full_width)));

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
    // MEASURED footer length — a shortened block adds middle padding
    // without shifting the pin off the bottom. The tier ladder picks
    // the compression level; the table gets whatever height remains
    // after the built block.
    let extra = usize::from(identity.is_empty());
    let tier = plan_footer_tier(geo.height, extra);

    // ── The engraved footer (NIGHT-boost-14 / NIGHT-engrave-4) ──
    //
    // Built BEFORE the table renders (see render/footer.rs): the
    // MEASURED length of the block is what pins it to the bottom,
    // and the table renders into whatever height remains. The census
    // gathers itself from the live board since NIGHT-engrave-4 — the
    // consumer autodetect, the session packets, the cgroup count,
    // the grand (all saturating, the boost-16 discipline) — footer
    // data, gathered where it renders; the eagle renderer hands the
    // board over and walks on. The session peaks ride along since
    // NIGHT-engrave-6 (the speed pair's maxima, noted above).
    let footer = build_grip_footer(
        &FooterCensus::gather(tier, &board, identity, conns, uptime, session.peaks()),
        geo,
        interval,
        span,
    );
    // The pin line: the footer's measured length fixes where the
    // frame's content must stop.
    let footer_start = geo.height.saturating_sub(footer.len());

    // Header row (regular purple — brand layer, NIGHT-hunt-5). The
    // rank cell is BLANK (NIGHT-boost-5: "#" retired — the digits
    // speak for themselves); NIGHT-engrave-4: the process title
    // SPANS the identity region — the rank cell plus its gap plus
    // the label column — so "top process" starts at the frame's
    // canonical text column (the same two-column gutter every
    // footer and note line uses) instead of floating six columns
    // off the left rail the way it did past the blank rank cell.
    // The numeric titles stay right-aligned over their columns, and
    // the row closes on the same two-column right gutter the data
    // rows end on. The grid below renders purple too
    // (NIGHT-boost-14) — one border family.
    let table_room = footer_start.saturating_sub(lines.len());
    let show_table = !session.is_empty() && (tokens.is_empty() || !board.is_empty());
    // The table needs room for its own chrome (header + grid) plus at
    // least one data row; below that the footer carries the story.
    if show_table && table_room >= TOP_CHROME - 1 {
        // The identity span the header's title cell covers.
        let title_w = cols.label_w + RANK_SPAN;
        if cols.show_total {
            lines.push(brand(&format!(
                "  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
                truncate_label("top process", title_w),
                "download",
                "upload",
                "total",
                w0 = title_w,
                w1 = cols.dl_w,
                w2 = cols.ul_w,
                w3 = cols.dl_w
            )));
        } else {
            lines.push(brand(&format!(
                "  {:<w0$} {:>w1$} {:>w2$}",
                truncate_label("top process", title_w),
                "download",
                "upload",
                w0 = title_w,
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
            // width-aware — hidden below the TOTAL-column boundary
            // (the column ladder IS the threshold since NIGHT-engrave-4:
            // a frame too narrow for the session figure is too narrow
            // for endpoint text — `cols.show_total`, one source of
            // truth, where a parallel DETAIL_HIDE_BELOW constant used
            // to drift), each line trimmed to the frame width above
            // it, so a long process/endpoint string can never wrap
            // the frame or shift the pinned footer.
            let mut details = if cols.show_total {
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
            // The denominator is the MEASURED span (NIGHT-lts-3),
            // not the nominal cadence — see the render entry doc.
            let delta = summary.cgroups.iter().find(|c| c.cgroup_id == *cgroup_id);
            let dl_rate = delta.map(|c| rate_bps(c.ingress_bytes, span)).unwrap_or(0);
            let ul_rate = delta.map(|c| rate_bps(c.bytes, span)).unwrap_or(0);

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
                    format_count((board.len() - emitted) as u64)
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
    border::wrap(lines, full_width);
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
    // NIGHT-lts-1: the label cell pads by RENDERED width (a CJK
    // label padded by chars would shift the row's numeric cells).
    let label = crate::output::pad_to_width(&label, cols.label_w);
    let body = if cols.show_total {
        format!(
            "  {:>2}  {} {:>w1$} {:>w2$} {:>w3$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            format_bytes(session_total),
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        )
    } else {
        format!(
            "  {:>2}  {} {:>w1$} {:>w2$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
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
// limiter's math_tests and the diff engine's pins. One file per
// contract when a family grows past the owner's LOC cap: the target
// filter (engrave-6) and the display-width CJK family (lts-1) each
// took their own.
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_tests.rs"]
mod eagle_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_filter_tests.rs"]
mod eagle_filter_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_width_tests.rs"]
mod eagle_width_tests;
