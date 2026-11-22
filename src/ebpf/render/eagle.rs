// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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
//! - **Adaptive compact** (dynamic WxH): subprocess detail hides
//!   below the TOTAL-column boundary (`cols.show_total` since
//!   NIGHT-engrave-4 — one source of truth where a parallel
//!   constant used to drift), each line trimmed to the frame width
//!   so nothing wraps the frame or shifts the pinned footer.
//! - **The pin**: the frame spans the terminal height, the table
//!   floats under the header, and the built footer pins to the bottom
//!   through measured padding — it never follows the table's length.
//! - **The panel floor** (night-improve-72): the table's budget is
//!   cut by the baseline panel's guaranteed-visible shape whenever
//!   the panel has rows to show — a full board can never starve the
//!   section out of the frame; a frame too short for both keeps the
//!   table (the ranked view is the primary one).
//!
//! The row budget follows the terminal height (no --limit, no cap):
//! a short window shows the top few consumers, a tall one spans the
//! list down to the quiet apps. With targets the same table filters
//! to the watched set; a single target that resolves to one cgroup
//! switches to the deep focus view (see [`super::focus`]).

use std::time::Duration;

use super::baseline::BaselineLane;
use super::baseline_panel::{PANEL_FLOOR, render_panel, view_rows};
use super::border;
use super::eagle_row::render_eagle_row;
use super::footer::{
    FooterCensus, TOP_CHROME, build_grip_footer_into, grid_line_into, plan_footer_tier,
};
use super::scroll::{ScrollState, Section};
use super::{
    FrameGeometry, SessionState, focus::board_rows_in_place, focus::render_eagle_focus,
    plan_eagle_columns, pooled_line, rate_bps, title_bar_into,
};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::Target;

use std::cell::RefCell;

thread_local! {
    /// The footer block scratch (night-frontier-Z13 stage 4c): the
    /// engraved footer assembles into this capacity-warm buffer, whose
    /// rows land at the pin and return to the line pool with the
    /// frame — the fresh Vec per frame is gone.
    static FOOTER_BLOCK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The headline name scratch (night-frontier-Z13 stage 4c): the
    /// champion's consumer name resolves into this capacity-warm
    /// buffer and the footer reads it as a &str — the census's owned
    /// Option<String> per frame is gone.
    static TOP_NAME: RefCell<String> = const { RefCell::new(String::new()) };
    /// The per-row detail block scratch (night-frontier-Z13 stage
    /// 4c): each cgroup's detail lines compose into this capacity-warm
    /// buffer; append moves the pooled rows into the frame and the
    /// buffer's capacity survives for the next row.
    static DETAIL_BLOCK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The baseline panel scratch (night-frontier-Z13 stage 4c): the
    /// panel renders into this capacity-warm buffer and docks into
    /// the frame — the fresh Vec per frame is gone.
    static PANEL_BLOCK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}
use crate::ebpf::loader::CounterSummary;

/// Columns the rank furniture occupies between the shared gutter
/// and the label column: the two-wide rank cell plus its two-wide
/// gap (NIGHT-engrave-4). The header's process title spans this plus
/// the label width — one identity region (rank + process), titled
/// from the frame's canonical text column. Kept in step with
/// render::plan_eagle_columns' rank reserve; the header-alignment
/// pins catch any drift.
const RANK_SPAN: usize = 4;

/// Resolve target tokens against the identity map — the render
/// family's per-frame resolver, its own module since NIGHT-dinner-18
/// (the LOC-cap split: focus, footer, detail, rank, targets each
/// took a contract). The launch gate's twin
/// (commands::eagle::resolve_live_targets) owns the door verdict —
/// see render/targets.rs for the two-home contract.
use super::targets::resolve_targets;

/// Size-injectable core of [`render_eagle_eyes`] (the emit/emit_at
/// discipline of the diff engine): contract pins drive deterministic
/// sizes, so the adaptive ladder and the pinned footer are testable.
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
    baseline: &BaselineLane,
    uptime: Duration,
    geo: FrameGeometry,
    scroll: &mut ScrollState,
    deep: bool,
) {
    // NIGHT-boost-20: compose into the bordered inset (render/border.rs).
    let full_width = geo.width;

    // The fold happens before anything renders: even an idle frame
    // (or the one-frame tolerance for a transient map-read error —
    // an Err poll folds an empty summary) leaves the board intact.
    session.absorb(summary);

    // NIGHT-mitigate-1: retire the board's dead rows (the mitigate-1
    // audit's finding B — the freeze lifter). Rides the frame after
    // the fold: a row retires only when the board filter below would
    // hide it anyway (no identity entry and no window traffic), on a
    // 3-frame streak, behind the identity signal guard — so the one
    // thing it changes is that a fresh cgroup finds a slot again on
    // a decade-long dense-churn monitor. The pass itself is gated at
    // the cap (MAX_TRACKED_CGROUPS): below a full board it clears the
    // streak era and returns, costing the render path nothing (the
    // frame-bench A/B story). See
    // docs/audits/NIGHT_MITIGATE_1_DATA_EXPLOSION_ENDURANCE_AUDIT_2026-10-07.md
    // section 7.
    session.retire_dead(identity, summary);

    let (ids, unresolved) = resolve_targets(tokens, identity);

    // The session peaks (NIGHT-engrave-6): one more fold pass over
    // the same summary, noting the watched set's aggregate into the
    // running maxima the footer's `peak arrival dl | ul` line renders.
    // The scope matches the board filter exactly — `None` on an
    // unfiltered frame (the machine-wide aggregate), `Some(ids)` on
    // a filtered one — and it notes BEFORE the focus branch returns,
    // so a focus episode's peaks track the focused cgroup too (the
    // peaks persist across the view switch, like every session
    // figure; the max line renders on the ranked frames). Since
    // NIGHT-hunt-38 the span rides along: the peak tracks the RATE
    // (the delta over the span IT was measured on), so the max line
    // never wobbles with a later frame's span jitter.
    session.note_frame(
        summary,
        span,
        if tokens.is_empty() { None } else { Some(&ids) },
    );

    // Single token, single cgroup: the focus view (own border inset).
    // night-improve-58: the scroll state is INERT here by design —
    // the focus view renders one cgroup's own deep detail, no
    // ranked sections to steer; the arrow keys drain as actions
    // and move nothing (the six-key surface stays the same key
    // count, the focus frame just holds nothing scrollable).
    if tokens.len() == 1 && ids.len() == 1 && unresolved.is_empty() {
        render_eagle_focus(
            lines, summary, identity, conns, baseline, ids[0], interval, span, uptime, geo, deep,
        );
        return;
    }

    let geo = border::content_geo(geo);
    let cols = plan_eagle_columns(geo.width);

    // NIGHT-engrave-3: identity only — the top-right key hint
    // retired with the census (the legend's only home is the
    // footer's status line, which is why it rides every tier).
    // The pooled title scratch (night-frontier-Z4): the same core
    // text, written into a warm String instead of allocating one.
    let mut title_core = pooled_line();
    {
        use std::fmt::Write as _;
        if tokens.is_empty() {
            let _ = write!(title_core, "zelynic eagle-eyes");
        } else {
            let n = ids.len();
            let plural = if n == 1 { "" } else { "s" };
            let _ = write!(title_core, "zelynic eagle-eyes — {n} target{plural}");
        }
    }
    // NIGHT-engrave-8: the bar composes at the FRAME's width —
    // one column inside the terminal — so wrap's leading inset
    // lands the corners one column from each edge.
    // night-frontier-Z11: the bar writes into a pooled row (the
    // title_bar_into twin) — the owned title_bar's fresh String per
    // frame was the named allocation-ladder site.
    let mut bar = pooled_line();
    title_bar_into(&title_core, border::frame_width(full_width), &mut bar);
    lines.push(bar);
    super::recycle_line(title_core);

    // The breathing gap (NIGHT-boost-14): one blank line of air —
    // the header used to sit too near the brand. night-frontier-Z13
    // stage 4c: the gap row rides the pool — a fresh String::new()
    // carried zero capacity, so the border wrap grew it from scratch
    // every frame (six heap events the walk could see).
    lines.push(super::pooled_line());

    // A watched name with no live cgroup says so — the empty-table
    // lie is exactly what the discovery stage must not tell.
    for name in &unresolved {
        super::push_pooled(
            lines,
            format_args!("   no app named '{name}' — see 'zelynic list-apps'"),
        );
    }

    // The leaderboard: session-accumulated per cgroup, consumption-
    // ordered (NIGHT-boost-5 — the old per-frame delta sort wiped
    // idle apps entirely); the board filter (NIGHT-hunt-Z1's dead-
    // transient belt composed with the watched-set narrowing) lives
    // in focus.rs beside its active-set helper, pinned at the frame
    // level in the eagle filter pins. night-frontier-Z13 stage 4c:
    // the board composes in the session's capacity-warm scratch and
    // the filters retain in place — the per-frame collect plus the
    // filter's own collect are gone. The session reads this frame
    // still needs (the emptiness, the peaks) hoist above the mutable
    // board borrow.
    let empty = session.is_empty();
    let peaks = session.peaks();
    let board = session.ranked_board();
    board_rows_in_place(
        board,
        identity,
        summary,
        (!tokens.is_empty()).then_some(&ids),
    );

    // Empty-board honesty: before the first packet (or for a watched
    // set that never talked) the frame says so, keeping the title and
    // pinned footer; once traffic HAS been seen this branch is dead
    // (the board holds every live row; transients retire).
    if empty {
        super::push_pooled(lines, format_args!("   waiting for traffic…"));
    } else if !tokens.is_empty() && board.is_empty() {
        super::push_pooled(
            lines,
            format_args!("   no traffic for the watched targets yet"),
        );
    }

    // Footer planning FIRST (NIGHT-boost-14): the pinned footer is
    // BUILT before the table renders, so the pin's line count is the
    // MEASURED footer length — a shortened block adds middle padding
    // without shifting the pin off the bottom. The tier ladder picks
    // the compression level; the table gets the height that remains.
    let extra = usize::from(identity.is_empty());
    let tier = plan_footer_tier(geo.height, extra);

    // ── The engraved footer (NIGHT-boost-14 / NIGHT-engrave-4) ──
    //
    // Built BEFORE the table renders (see render/footer.rs): the
    // MEASURED length of the block is what pins it to the bottom,
    // and the table renders into whatever height remains. The
    // census gathers itself from the live board since
    // NIGHT-engrave-4 (footer data, gathered where it renders); the
    // session peaks ride along since NIGHT-engrave-6.
    // night-frontier-Z13 stage 4c: the whole assembly runs INSIDE
    // the frame's retained blocks — the headline's name resolves
    // into the capacity-warm TOP_NAME buffer (the champion's
    // busiest process comm, then the identity's own comm, then the
    // raw cg: label — the same fallback order the census carried,
    // byte for byte, zero heap events) and the rows compose into
    // the capacity-warm FOOTER_BLOCK, whose length pins the frame.
    let footer_len = TOP_NAME.with(|name_cell| {
        let mut name = name_cell.borrow_mut();
        name.clear();
        let mut resolved = false;
        if let Some((cgroup_id, _)) = board.first() {
            let cgroup_id = *cgroup_id;
            if let Some(cm) = conns
                && let Some(proc) = super::rank::top_consumer(cm, cgroup_id)
            {
                name.push_str(&proc.comm);
                resolved = true;
            }
            if !resolved
                && let Some(record) = identity.get(cgroup_id)
                && record.comm != "unknown"
                && !record.comm.is_empty()
            {
                name.push_str(&record.comm);
                resolved = true;
            }
            if !resolved {
                // The raw label — the identity-honest name the old
                // fallback landed on (the unresolved cg: id, or the
                // unknown-comm record's parenthesized label).
                identity.write_label(cgroup_id, &mut name);
                resolved = true;
            }
        }
        let top_name = resolved.then(|| name.as_str());
        let census = FooterCensus::gather(tier, board, identity, uptime, peaks);
        FOOTER_BLOCK.with(|cell| {
            let mut footer = cell.borrow_mut();
            build_grip_footer_into(&mut footer, &census, geo, interval, deep, top_name);
            footer.len()
        })
    });
    // The pin line: the footer's measured length fixes where the
    // frame's content must stop.
    let footer_start = geo.height.saturating_sub(footer_len);

    // night-improve-72: the panel floor. The table's budget used to
    // run all the way to the footer pin — a board rich enough to
    // fill the frame let the table eat every line, and the baseline
    // panel starved to zero rows and vanished whole (the owner's
    // live find: scroll up to the busy head ranks and the panel's
    // title left with them; only the quiet tail's shorter rows let
    // it back). The floor withholds the panel's guaranteed-visible
    // shape — separator, header, one verdict, the scroll note —
    // from the table's budget BEFORE the table renders, whenever
    // the panel has rows to show and the table can still keep its
    // own minimum (chrome plus one data row). Below that line the
    // degradation is the old behavior by design: the table is the
    // primary view, and a frame too short for both keeps it.
    let panel_filter: Option<&[u32]> = if tokens.is_empty() {
        None
    } else {
        Some(&ids[..])
    };
    let panel_floor = if !view_rows(baseline, panel_filter).is_empty()
        && footer_start.saturating_sub(lines.len()) >= (TOP_CHROME - 1) + PANEL_FLOOR
    {
        PANEL_FLOOR
    } else {
        0
    };
    let table_floor = footer_start.saturating_sub(panel_floor);

    // Header row (regular purple — brand layer, NIGHT-hunt-5). The
    // rank cell is BLANK (NIGHT-boost-5: "#" retired — the digits
    // speak for themselves); NIGHT-engrave-4: "top process" SPANS
    // the identity region (rank cell plus gap plus label column) to
    // the frame's canonical text column, the numeric titles stay
    // right-aligned over their columns, and the grid below renders
    // purple too (NIGHT-boost-14) — one border family.
    let table_room = table_floor.saturating_sub(lines.len());
    let show_table = !empty && (tokens.is_empty() || !board.is_empty());
    // The table needs room for its own chrome (header + grid) plus at
    // least one data row; below that the footer carries the story.
    if show_table && table_room >= TOP_CHROME - 1 {
        // night-improve-58: the table's scroll window, clamped to
        // the rows the board holds this frame (a shrunken board
        // snaps the window back; the clamp writes home so the next
        // arrow step rides it). The champion rule below survives
        // the offset intact: the FIRST VISIBLE row takes the trim
        // role the champion owned at rest — the table never renders
        // empty while a row exists to show.
        let offset = scroll.table_window(board.len());
        // The focus gutter marker (night-improve-58; re-cut by
        // night-improve-61): the focused section's header carries
        // `=> ` in the 3-column marker lane every table row shares —
        // the owner's exact glyph and reading ("=> top process"):
        // the `▸` triangle rendered as an unreadable dot on his
        // terminal, and the ASCII arrow pair plus its air column is
        // what he asked the marker to say. The lane widened by one
        // column (2 -> 3) so the marker never crowds the title; the
        // rank reserve moved with it (render::plan_eagle_columns),
        // so no column ever shifts between header and rows.
        let gutter = if scroll.focused() == Section::TopProcess {
            "=> "
        } else {
            "   "
        };
        // The identity span the header's title cell covers.
        let title_w = cols.label_w + RANK_SPAN;
        super::eagle_row::render_eagle_header(lines, gutter, title_w, &cols);
        // night-frontier-Z11: the grid writes into a pooled row (the
        // grid_line_into twin), the same ladder law the bar rides.
        let mut grid = pooled_line();
        grid_line_into(geo.width, &mut grid);
        lines.push(grid);

        // Row budget counts detail lines too (NIGHT-hunt-8): a row
        // plus its lines fit as a unit, within what remains after
        // the top chrome, the panel floor (night-improve-72), and
        // the pinned footer (--limit and the cap are gone,
        // NIGHT-boost-1: the window IS the budget;
        // NIGHT-boost-14 made the footer's claim explicit;
        // night-improve-58: the window is the budget, the SCROLL is
        // the window's walk — the rank column still carries the
        // board's true rank, never the window's position).
        let row_room = table_floor.saturating_sub(lines.len());
        let mut used = 0usize;
        let mut emitted = 0usize;
        for (i, (cgroup_id, acc)) in board.iter().enumerate().skip(offset) {
            // Adaptive subprocess detail (NIGHT-boost-14): grey, and
            // width-aware — hidden below the TOTAL-column boundary
            // (the column ladder IS the threshold since NIGHT-engrave-4:
            // a frame too narrow for the session figure is too narrow
            // for endpoint text — `cols.show_total`, one source of
            // truth, where a parallel DETAIL_HIDE_BELOW constant used
            // to drift), each line trimmed to the frame width above
            // it, so a long process/endpoint string can never wrap
            // the frame or shift the pinned footer.
            // night-frontier-Z13 stage 4c: the block composes into
            // the retained DETAIL_BLOCK scratch — the fresh Vec per
            // cgroup per frame is gone; append moves the pooled rows
            // into the frame and the scratch keeps its capacity. The
            // trim and the truncation paths hand their dropped rows
            // BACK to the pool (dropping a pooled row starved the
            // warm capacity and made the next frame pay fresh
            // allocations — the starvation the walk's own count
            // could never see).
            enum RowVerdict {
                Break,
                Render,
            }
            let row_verdict = DETAIL_BLOCK.with(|cell| {
                let mut details = cell.borrow_mut();
                details.clear();
                if cols.show_total {
                    // night-frontier-Z11: the detail block pushes pooled
                    // rows (the push_detail_lines twin) — the per-cgroup
                    // owned Vec<String> of fresh Strings was the named
                    // site; the grey trim below stays per line.
                    super::detail::push_detail_lines(&mut details, conns, *cgroup_id, span);
                }
                for line in &mut *details {
                    // The pooled trim-and-grey (night-frontier-Z4): one
                    // warm scratch per line, the same bytes the old
                    // chain returned, minus its Strings.
                    super::grey_trim(line, None, geo.width);
                }
                // The deep line (night-netrunner-4, --deep): ONE grey
                // line after the detail tree — the hungriest endpoint's
                // rtt ± jitter and the window's retransmit share, or the
                // protocol tag. Rides the same row budget the details
                // ride (need grows by one when present); the deep line
                // hides below the same show_total boundary that hides
                // detail lines, and the champion trim below drops it
                // FIRST (detail first, deep figures first to go — the
                // sacrifice ladder's order, the audit's own).
                // night-engrave-1-ee: the line INDENTS to the detail
                // tree's first level (the block's own four columns)
                // BEFORE the width trim — the figures sit under the
                // sockets they summarize; at column 0 the same line read
                // as the next row's opening (the owner's eagle-eyes find).
                let mut deep_line = if deep && cols.show_total {
                    super::deep::row_deep_line(conns, *cgroup_id)
                } else {
                    None
                };
                if let Some(line) = deep_line.as_mut() {
                    // The pooled indent-trim-grey (night-frontier-Z4):
                    // the indent rides the same scratch, the same bytes
                    // the old chain returned, minus its Strings.
                    super::grey_trim(line, Some("    "), geo.width);
                }
                let need = 1 + details.len() + usize::from(deep_line.is_some());
                if used + need > row_room {
                    if emitted == 0 {
                        // The champion always shows (NIGHT-boost-5): trim
                        // its own detail to what the window can hold —
                        // the deep line yields first (the ladder's
                        // order), then the detail lines.
                        let room = row_room.saturating_sub(1);
                        if room == 0 {
                            if let Some(line) = deep_line.take() {
                                super::recycle_line(line);
                            }
                            for line in details.drain(..) {
                                super::recycle_line(line);
                            }
                        } else {
                            if room < need
                                && let Some(line) = deep_line.take()
                            {
                                super::recycle_line(line);
                            }
                            let keep = room.min(details.len());
                            for line in details.drain(keep..) {
                                super::recycle_line(line);
                            }
                        }
                    } else {
                        // The over-budget row's composed block returns
                        // to the pool wholesale — the whole-block drop
                        // starved the warm capacity every frame.
                        for line in details.drain(..) {
                            super::recycle_line(line);
                        }
                        return RowVerdict::Break;
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
                let deep_shown = deep_line.is_some();
                // The row's retrans window (night-netrunner-4): the
                // walk-to-walk TCP truth, or absence (the em dash) when
                // the row holds no measured window.
                let retrans = super::retrans_row_figure(conns, *cgroup_id);
                render_eagle_row(
                    lines,
                    *cgroup_id,
                    *acc,
                    dl_rate,
                    ul_rate,
                    retrans,
                    identity,
                    conns,
                    &cols,
                    i + 1,
                );
                lines.append(&mut details);
                if let Some(line) = deep_line {
                    lines.push(line);
                }
                used += 1 + shown_details + usize::from(deep_shown);
                emitted += 1;
                RowVerdict::Render
            });
            if matches!(row_verdict, RowVerdict::Break) {
                break;
            }
        }
        // night-improve-58: the scroll-position note replaces the
        // old "raise the window" advice — the owner's whole point:
        // the window stays the terminal it is, the arrows walk it.
        // `above` counts the rows the offset skipped, `below` the
        // rows the room cut; no note when the frame holds the
        // whole board (the clean read it always was). The note
        // rides the same budget the rows ride: when the room filled
        // exactly, the LAST data row yields its line to the note
        // (the position readout outranks one row of content —
        // without it a walked window reads as frozen, the pin that
        // caught this very shape).
        let above = offset;
        let below = board.len().saturating_sub(offset + emitted);
        // night-frontier-Z13 stage 4c: the note composes into the
        // pooled scratch directly (the write_scroll_note twin) — the
        // owned Option<String> per frame is gone.
        if above > 0 || below > 0 {
            if emitted > 0 && lines.len() >= table_floor {
                // night-frontier-Z13 stage 4c: the popped row returns
                // to the pool — dropping it starved the warm capacity
                // and made the next frame pay fresh allocations.
                if let Some(line) = lines.pop() {
                    super::recycle_line(line);
                }
            }
            // The pooled grey note (night-frontier-Z4): the leading
            // spaces ride OUTSIDE the paint (the same bytes the old
            // format!("   {}", grey(&note)) produced), the grey
            // paints onto its own warm scratch.
            let mut greyed = super::pooled_line();
            super::scroll::write_scroll_note(above, below, &mut greyed);
            crate::output::paint_in_place(&mut greyed, crate::output::grey_open());
            super::push_pooled(lines, format_args!("   {greyed}"));
            super::recycle_line(greyed);
        }
    }

    // ── EAGLE EYES V2 (NIGHT-improve-1a): the baseline panel ──────
    //
    // The policy-aggregate verdicts under the table: one line per
    // policed target the ring lens holds, filtered to the watched
    // set when targets narrow the frame (a filter is a filter).
    // Rendered from the LANE, not the summary — a policy that has
    // been quiet for a minute still shows its learned-zero baseline
    // here while the observer's table waits for traffic. Since
    // NIGHT-engrave-9 the panel opens with its own ruled separator
    // (air, then the table's grid). Since NIGHT-engrave-10 it DOCKS:
    // rendered into a scratch buffer and landed flush against the
    // pinned footer, so a tall terminal's blank slack rides between
    // the table and the panel's separator — never between the
    // verdict rows and the top-consumer headline they answer to
    // (the owner's gap fix: the section keeps near the bottom).
    // The dock (NIGHT-engrave-10): pad to the panel's floor, then
    // land the block — the pin below tops the frame off. Since
    // night-improve-72 the panel's room is the floor the table
    // left standing PLUS everything the table could not fill: a
    // quiet board still gives the panel the frame's slack, a full
    // one still gives it the withheld five.
    let panel_room = footer_start.saturating_sub(lines.len());
    PANEL_BLOCK.with(|cell| {
        let mut panel = cell.borrow_mut();
        panel.clear();
        render_panel(
            &mut panel,
            baseline,
            identity,
            panel_filter,
            panel_room,
            geo.width,
            scroll,
        );
        // The dock (NIGHT-engrave-10): pad to the panel's floor, then
        // land the block — the pin below tops the frame off. The pad
        // rows ride the pool (night-frontier-Z13 stage 4c: a fresh
        // String::new() carried zero capacity and the wrap grew it
        // every frame), and the append moves the pooled rows while
        // the scratch keeps its capacity.
        let panel_at = footer_start.saturating_sub(panel.len());
        while lines.len() < panel_at {
            lines.push(super::pooled_line());
        }
        lines.append(&mut panel);
    });

    // ── The pin (NIGHT-boost-14) ──────────────────────────────────
    //
    // The footer lands at the bottom of the terminal, never
    // following the table: blank padding absorbs the middle above
    // the docked panel, and on the pathological over-height frame
    // the pin outranks the lowest table rows (popped from the end —
    // the least important ranks go first, never the footer).
    while lines.len() > footer_start {
        // night-frontier-Z13 stage 4c: the popped row returns to the
        // pool (the over-height frame's sacrifice rows keep their
        // warm capacity for the next frame).
        if let Some(line) = lines.pop() {
            super::recycle_line(line);
        }
    }
    while lines.len() < footer_start {
        lines.push(super::pooled_line());
    }
    // The footer's rows land from their retained block (night-
    // frontier-Z13 stage 4c): append moves the pooled rows and keeps
    // the block warm for the next frame.
    FOOTER_BLOCK.with(|cell| {
        let mut footer = cell.borrow_mut();
        lines.append(&mut footer);
    });
    border::wrap(lines, full_width);
}

// NIGHT-boost-1: the renderer pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired like the limiter's
// math_tests. One file per contract when a family grows past the
// owner's LOC cap: the target filter (engrave-6), the CJK width
// family (lts-1), and the baseline dock (engrave-10) each took
// their own.
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_tests.rs"]
mod eagle_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_filter_tests.rs"]
mod eagle_filter_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_width_tests.rs"]
mod eagle_width_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_dock_tests.rs"]
mod eagle_dock_tests;

// night-improve-58: the scroll-integration pins — the arrows
// walking the real render path (split from eagle_tests at the
// 600-LOC owner cap, one file per contract).
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_scroll_tests.rs"]
mod eagle_scroll_tests;

// night-improve-72: the panel-floor pins — the table never starves
// the baseline police (the owner's live find, pinned at both a
// limited and a normal height, through the walk, and at the
// too-short degradation that keeps the table).
#[cfg(test)]
#[path = "../../../test/ebpf/render/eagle_floor_tests.rs"]
mod eagle_floor_tests;

// night-engrave-1-ee: the deep line's indent pins — the figures sit
// under their socket tree, never at column 0 (the owner's find).
#[cfg(test)]
#[path = "../../../test/ebpf/render/deep_layout_tests.rs"]
mod deep_layout_tests;
