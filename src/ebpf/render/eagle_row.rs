// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The eagle-eyes ranked data row (split from eagle.rs at the
//! 600-LOC owner cap, night-improve-72 — the same pure-move
//! discipline focus, footer, detail, rank, and targets each took):
//! the one-row renderer with its static traffic-light tiers, the
//! only place a board row becomes frame lines. The layout that
//! budgets the rows (the table, the panel floor, the pinned
//! footer) stays one home over in eagle.rs; this file owns what a
//! single row paints.

use super::{EagleColumns, SessionAcc, pooled_line, recycle_line, write_rate_or_dash};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{format_bytes_wide_into, format_count_into};
use crate::output::{
    brand_open, char_width, fit_to_width_into, hot_open, ok_open, paint_in_place, warn_open,
};

/// The frame pool's cell pads (night-frontier-Z4): the exact bytes
/// the old `format!("{:>w$}"...)` cells produced, written into the
/// row without a temporary. Rust's width formatting pads by CHAR
/// count — the numeric cells are ASCII (the SI ladders, the count
/// ladder) or the one-char em dash, so `chars().count()` is the
/// width the old format! padded by; the insert shifts the cell's
/// bytes right inside the warm row buffer, no allocation anywhere.
fn pad_left_cell(row: &mut String, mark: usize, w: usize) {
    let len = row[mark..].chars().count();
    for _ in len..w {
        row.insert(mark, ' ');
    }
}

/// The pooled twin of `pad_to_width` for a WHOLE scratch string (the
/// label cell): the same fit-or-pad walk the owned form runs, in
/// place — the fast path pads, the truncation path cuts at the
/// display boundary, appends the ellipsis, and pads the shortfall.
fn fit_pad_in_place(s: &mut String, w: usize) {
    let mut width = 0usize;
    let mut over = false;
    for c in s.chars() {
        width += if (c as u32) < 0x0300 {
            1
        } else {
            char_width(c)
        };
        if width > w {
            over = true;
            break;
        }
    }
    if !over {
        for _ in width..w {
            s.push(' ');
        }
        return;
    }
    if w == 0 {
        s.clear();
        return;
    }
    let mut used = 0usize;
    let mut cut = s.len();
    for (idx, c) in s.char_indices() {
        let cw = char_width(c);
        if used + cw > w - 1 {
            cut = idx;
            break;
        }
        used += cw;
    }
    s.truncate(cut);
    s.push('…');
    used += 1;
    for _ in used..w {
        s.push(' ');
    }
}

/// One ranked data row. The static traffic-light tiers
/// (NIGHT-boost-14): rank 1 champion red, rank 2 warning yellow,
/// rank 3 and below status green — the owner's exact color contract,
/// calmer than the white it replaced and with no blink anywhere.
///
/// night-netrunner-4: the retrans cell (when the rung is shown) —
/// the walk-to-walk retransmit count, `—` when the row holds no
/// measured window (the absence law: a QUIC-only row and a
/// first-walk row both render the dash, never a fabricated zero).
#[allow(clippy::too_many_arguments)]
pub(super) fn render_eagle_row(
    lines: &mut Vec<String>,
    cgroup_id: u32,
    acc: SessionAcc,
    dl_rate: u64,
    ul_rate: u64,
    retrans: Option<u64>,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cols: &EagleColumns,
    rank: usize,
) {
    // Saturating session sum (NIGHT-boost-16; u128 since NIGHT-lts-5).
    let session_total = acc.dl.saturating_add(acc.ul);
    // The pooled composition (night-frontier-Z4): one warm row String
    // filled cell by cell — the label cell rides its own pooled
    // scratch (fit-and-pad in place, the same bytes `pad_to_width`
    // returns), the numeric cells write straight into the row and
    // pad by the old format!'s char-count law, and the tier paints
    // in place. Zero heap events per row in the steady state.
    let mut row = pooled_line();
    {
        use std::fmt::Write as _;
        let _ = write!(row, "   {rank:>2}  ");
    }
    // NIGHT-lts-1: the label cell is fit AND padded by RENDERED
    // width in one pass (a CJK label padded by chars would shift
    // the row's numeric cells; one walk spares the double
    // measurement a separate truncate step would pay).
    let mut label = pooled_line();
    super::detail::write_label_with_count(identity, conns, cgroup_id, &mut label);
    fit_pad_in_place(&mut label, cols.label_w);
    row.push_str(&label);
    recycle_line(label);
    // The retrans cell (night-netrunner-4): the count at its own
    // width — right-aligned like every numeric cell — or the em
    // dash when the row holds no measured window. The dash rides
    // the same cell the figure does (the em dash is one column
    // wide in every monospace font the surface targets; the row's
    // alignment is the columns', not the glyphs').
    let retrans_w = cols.retrans_w;
    let cell = |row: &mut String, retrans: Option<u64>, w: usize| {
        let mark = row.len();
        match retrans {
            Some(n) => format_count_into(n, row),
            None => {
                row.push('—');
            }
        }
        pad_left_cell(row, mark, w);
    };
    row.push(' ');
    let mark = row.len();
    write_rate_or_dash(&mut row, dl_rate);
    pad_left_cell(&mut row, mark, cols.dl_w);
    row.push(' ');
    let mark = row.len();
    write_rate_or_dash(&mut row, ul_rate);
    pad_left_cell(&mut row, mark, cols.ul_w);
    if cols.show_total && cols.retrans_w > 0 {
        row.push(' ');
        cell(&mut row, retrans, retrans_w);
    }
    if cols.show_total {
        row.push(' ');
        let mark = row.len();
        format_bytes_wide_into(session_total, &mut row);
        pad_left_cell(&mut row, mark, cols.dl_w);
    }
    // The static traffic-light tiers, painted in place — the same
    // bytes hot()/warn()/ok() returned, minus the per-call String.
    paint_in_place(
        &mut row,
        match rank {
            1 => hot_open(),
            2 => warn_open(),
            _ => ok_open(),
        },
    );
    lines.push(row);
}

/// The ranked table's header row (pure, split from eagle.rs at the
/// 600-LOC law — the column family's one home, beside the row it
/// titles). NIGHT-engrave-4's identity span (the process title
/// covers the rank cell plus gap plus label column, titled from the
/// frame's canonical text column), the right-aligned numeric titles
/// over their columns, and — night-netrunner-4 — the retrans title
/// between upload and total on the full rung (the rung's own header,
/// spelled in full; the ladder's narrower shapes keep exactly the
/// titles their columns carry).
pub(super) fn render_eagle_header(
    lines: &mut Vec<String>,
    gutter: &str,
    title_w: usize,
    cols: &EagleColumns,
) {
    // The pooled composition (night-frontier-Z4): the title cell's
    // fit rides its own pooled scratch (the same bytes
    // `truncate_label` returns), the cells ride one write! into the
    // warm row (the width grammar is unchanged — Rust pads the same
    // CHAR counts it always padded), and the brand paints in place.
    let mut row = pooled_line();
    let mut title = pooled_line();
    fit_to_width_into("top process", title_w, &mut title);
    {
        use std::fmt::Write as _;
        if cols.show_total && cols.retrans_w > 0 {
            // The full rung (night-netrunner-4): retrans sits right
            // of upload, left of total — the session figure keeps
            // the rightmost anchor the right-gutter contract gave it.
            let _ = write!(
                row,
                "{gutter}{title:<title_w$} {:>w1$} {:>w2$} {:>wr$} {:>w3$}",
                "download",
                "upload",
                "retrans",
                "total",
                w1 = cols.dl_w,
                w2 = cols.ul_w,
                wr = cols.retrans_w,
                w3 = cols.dl_w
            );
        } else if cols.show_total {
            let _ = write!(
                row,
                "{gutter}{title:<title_w$} {:>w1$} {:>w2$} {:>w3$}",
                "download",
                "upload",
                "total",
                w1 = cols.dl_w,
                w2 = cols.ul_w,
                w3 = cols.dl_w
            );
        } else {
            let _ = write!(
                row,
                "{gutter}{title:<title_w$} {:>w1$} {:>w2$}",
                "download",
                "upload",
                w1 = cols.dl_w,
                w2 = cols.ul_w
            );
        }
    }
    recycle_line(title);
    paint_in_place(&mut row, brand_open());
    lines.push(row);
}
