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

use super::{EagleColumns, SessionAcc, format_rate_or_dash, label_with_count};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{format_bytes_wide, format_count};
use crate::output::{hot, ok, pad_to_width, warn};

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
    // NIGHT-lts-1: the label cell is fit AND padded by RENDERED
    // width in one pass (a CJK label padded by chars would shift
    // the row's numeric cells; one call spares the double
    // measurement a separate truncate step would pay).
    let label = pad_to_width(&label_with_count(identity, conns, cgroup_id), cols.label_w);
    // The retrans cell (night-netrunner-4): the count at its own
    // width — right-aligned like every numeric cell — or the em
    // dash when the row holds no measured window. The dash rides
    // the same cell the figure does (the em dash is one column
    // wide in every monospace font the surface targets; the row's
    // alignment is the columns', not the glyphs').
    let retrans_cell = |w: usize| match retrans {
        Some(n) => pad_to_width(&format_count(n), w),
        None => "—".to_string(),
    };
    let body = if cols.show_total && cols.retrans_w > 0 {
        format!(
            "   {:>2}  {} {:>w1$} {:>w2$} {:>wr$} {:>w3$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            retrans_cell(cols.retrans_w),
            format_bytes_wide(session_total),
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            wr = cols.retrans_w,
            w3 = cols.dl_w
        )
    } else if cols.show_total {
        format!(
            "   {:>2}  {} {:>w1$} {:>w2$} {:>w3$}",
            rank,
            label,
            format_rate_or_dash(dl_rate),
            format_rate_or_dash(ul_rate),
            format_bytes_wide(session_total),
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        )
    } else {
        format!(
            "   {:>2}  {} {:>w1$} {:>w2$}",
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
