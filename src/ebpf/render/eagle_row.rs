// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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
use crate::ebpf::limiter::format_bytes_wide;
use crate::output::{hot, ok, pad_to_width, warn};

/// One ranked data row. The static traffic-light tiers
/// (NIGHT-boost-14): rank 1 champion red, rank 2 warning yellow,
/// rank 3 and below status green — the owner's exact color contract,
/// calmer than the white it replaced and with no blink anywhere.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_eagle_row(
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
    // Saturating session sum (NIGHT-boost-16; u128 since NIGHT-lts-5).
    let session_total = acc.dl.saturating_add(acc.ul);
    // NIGHT-lts-1: the label cell is fit AND padded by RENDERED
    // width in one pass (a CJK label padded by chars would shift
    // the row's numeric cells; one call spares the double
    // measurement a separate truncate step would pay).
    let label = pad_to_width(&label_with_count(identity, conns, cgroup_id), cols.label_w);
    let body = if cols.show_total {
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
