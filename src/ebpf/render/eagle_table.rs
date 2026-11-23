// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The ranked table (night-frontier-Z13-6, the 600-LOC owner cap):
//! eagle-eyes' table half as its own module — one file per contract,
//! the same split focus, footer, detail, rank, and targets each took
//! (see [`super::eagle`] for the render family's split history).
//!
//! The contract, moved verbatim from [`super::eagle`]: the header row
//! and its gutter marker, the purple grid, the detail-aware row loop
//! (each row plus its detail lines and the deep line fit as a unit —
//! the champion always shows, the sacrifice order is deep line first,
//! then detail lines), and the scroll-position note. The composition
//! rides the frame's pooled rows and the retained DETAIL_BLOCK scratch
//! — zero fresh heap per steady-state frame, the allocation-lens law
//! the Z13 pins hold.
//!
//! The frame-level budget arithmetic stays in [`super::eagle`] beside
//! the footer planning and the panel dock: the call site keeps the
//! table-room condition, the module renders whatever remains.

use super::eagle_row::render_eagle_row;
use super::footer::grid_line_into;
use super::scroll::{ScrollState, Section};
use super::session::SessionAcc;
use super::{EagleColumns, FrameGeometry, pooled_line, rate_bps};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::loader::CounterSummary;
use std::cell::RefCell;
use std::time::Duration;

thread_local! {
/// The per-row detail block scratch (night-frontier-Z13 stage
/// 4c): each cgroup's detail lines compose into this capacity-warm
/// buffer; append moves the pooled rows into the frame and the
/// buffer's capacity survives for the next row.
static DETAIL_BLOCK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Columns the rank furniture occupies between the shared gutter
/// and the label column: the two-wide rank cell plus its two-wide
/// gap (NIGHT-engrave-4). The header's process title spans this plus
/// the label width — one identity region (rank + process), titled
/// from the frame's canonical text column. Kept in step with
/// render::plan_eagle_columns' rank reserve; the header-alignment
/// pins catch any drift.
const RANK_SPAN: usize = 4;
/// The ranked table's body: [`super::eagle`]'s frame budget
/// arithmetic calls into once the table wins its room. The rows carry
/// the board's true rank — the scroll window's walk never renumbers
/// them (night-improve-58).
#[allow(clippy::too_many_arguments)]
pub(super) fn render_ranked_table(
    lines: &mut Vec<String>,
    board: &[(u32, SessionAcc)],
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    span: Duration,
    deep: bool,
    geo: FrameGeometry,
    cols: &EagleColumns,
    table_floor: usize,
    scroll: &mut ScrollState,
) {
    // Header row (regular purple — brand layer, NIGHT-hunt-5). The
    // rank cell is BLANK (NIGHT-boost-5: "#" retired — the digits
    // speak for themselves); NIGHT-engrave-4: "top process" SPANS
    // the identity region (rank cell plus gap plus label column) to
    // the frame's canonical text column, the numeric titles stay
    // right-aligned over their columns, and the grid below renders
    // purple too (NIGHT-boost-14) — one border family.
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
