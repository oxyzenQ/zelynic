// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The baseline panel's RENDERER (split from baseline.rs at the
//! 600-LOC owner cap, the docker_tests lineage): the ruled section
//! under the table — one verdict row per policy root, the focus
//! gutter marker, and the scroll window night-improve-58 gave it.
//! The lane's fold/state/retire contracts stay one home over; this
//! file owns only what the ranked frame paints. Since
//! night-improve-72 the file also owns the panel's FLOOR — the
//! guaranteed-visible shape the eagle layout withholds from the
//! table's budget, so a full board can never starve the section
//! back out of the frame.

use super::baseline::{BaselineLane, BaselineWord, pair_phrase};
use super::footer::grid_line;
use super::scroll::{ScrollState, Section, scroll_note};
use crate::ebpf::identity::IdentityMap;
use crate::output::{grey, pad_to_width};

/// The panel's guaranteed-visible floor (night-improve-72): the
/// room the eagle layout withholds from the table's budget
/// whenever the panel has rows to show — separator, header, one
/// verdict row, and the scroll note a truncating panel renders
/// instead of a second verdict. Five lines is the smallest room
/// `render_panel` turns into a VISIBLE section: below it the
/// usable-row arithmetic collapses to zero and the renderer
/// returns before drawing a thing (the starvation the floor
/// exists to prevent — a full-board table eating every line to
/// the footer pin while the section title vanished with the
/// rows). One home beside the arithmetic it describes, so the
/// budget and the renderer can never drift apart on what the
/// panel's minimum shape is.
pub(super) const PANEL_FLOOR: usize = 5;

/// The rows the frame's panel actually renders (night-improve-72):
/// the lane's own rows, narrowed to the watched set when targets
/// filter the frame (a filter is a filter), with silent rows —
/// both directions pre-first-fold — dropped as noise. One home for
/// the arithmetic so the eagle layout's floor decision and the
/// panel's renderer answer the same question, "does the panel
/// have anything to say", the same way.
pub(super) fn view_rows(
    lane: &BaselineLane,
    filter: Option<&[u32]>,
) -> Vec<(u32, Option<BaselineWord>, Option<BaselineWord>)> {
    let mut rows = lane.panel_rows();
    if let Some(ids) = filter {
        rows.retain(|(k, _, _)| ids.contains(k));
    }
    rows.retain(|(_, dl, ul)| dl.is_some() || ul.is_some());
    rows
}

/// The ranked view's baseline panel: one line per policy root the
/// lane holds (filtered to the watched set — a filter is a
/// filter), under a grey header naming the lens. Since
/// NIGHT-engrave-9 the section OPENS with a ruled separator (air,
/// then the table's own grid at `width`), so the verdict rows stop
/// reading as the table's last rows; since NIGHT-engrave-10 the
/// caller DOCKS the block flush against the pinned footer (the
/// slack rides above the panel). `room` is the rows the panel may
/// occupy; it skips below separator plus header plus one verdict
/// row. night-improve-58: the panel is the second scrollable
/// section (the baseline police) — `scroll` carries its window
/// (clamped here against the FILTERED row count, the one
/// arithmetic only this function owns) and its focus (the gutter
/// marker on the header), and a truncating panel carries the
/// scroll-position note instead of the old "raise the window"
/// advice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_panel(
    lines: &mut Vec<String>,
    lane: &BaselineLane,
    identity: &IdentityMap,
    filter: Option<&[u32]>,
    room: usize,
    width: usize,
    scroll: &mut ScrollState,
) {
    let rows = view_rows(lane, filter);
    // The panel's scroll window (night-improve-58), clamped to the
    // rows the FILTERED lane holds this frame — the clamp writes
    // home so the next arrow step rides it (a retired root's
    // departure shrinks the board and snaps the window back).
    let offset = scroll.panel_window(rows.len());
    // Chrome budget (NIGHT-engrave-9): air + grid + header are three
    // rows before the first verdict; the skip floor lives in `usable`.
    let fit = room.saturating_sub(3);
    let visible_total = rows.len().saturating_sub(offset);
    let usable = if visible_total > fit {
        fit.saturating_sub(1) // hold one row back for the scroll note
    } else {
        visible_total
    };
    if usable == 0 {
        return;
    }
    // The focus gutter marker (night-improve-58; re-cut by
    // night-improve-61): the focused section's header carries `=> `
    // in the shared 3-column marker lane — the owner's exact glyph
    // ("=> baseline · policy aggregate", the `▸` triangle rendered
    // as an unreadable dot on his terminal), the right arrow's
    // landing visible at a glance, no column shifts.
    let gutter = if scroll.focused() == Section::BaselinePolice {
        "=> "
    } else {
        "   "
    };
    // The ruled separator: a section, not the table's tail.
    lines.push(String::new());
    lines.push(grid_line(width));
    lines.push(format!(
        "{gutter}{}",
        grey("baseline · policy aggregate (8s ring)")
    ));
    for (key, dl, ul) in rows.iter().skip(offset).take(usable) {
        let label = pad_to_width(&super::truncate_label(&identity.label(*key), 24), 24);
        let body = pair_phrase(*dl, *ul);
        lines.push(format!("   {label}  {body}"));
    }
    // The scroll-position note (night-improve-58): the rows above
    // the window and the rows the room cut, one spelling shared
    // with the table's own note — no note when everything fits.
    if let Some(note) = scroll_note(offset, visible_total - usable) {
        lines.push(format!("   {}", grey(&note)));
    }
}
