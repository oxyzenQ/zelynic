// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The frame line pool (night-frontier-Z4) — the composition half's
//! allocation-reuse discipline, split from render.rs at the 600-LOC
//! owner cap (night-improve-44, the same pure-move discipline eagle_row,
//! focus, detail, rank, and targets each took): the composers pop
//! capacity-warm strings, the loop returns the spent ones, and the
//! steady-state live frame performs zero heap events. The diff
//! engine's own zero-alloc law (NIGHT-blade-16) covers the other half;
//! the allocation pin in test/ebpf/render/bench.rs holds the floor
//! end to end.

use std::cell::RefCell;

use crate::ebpf::limiter::format_bytes_into;
use crate::output::{char_width, display_width, grey_open, paint_in_place};

const POOL_CAP: usize = 128;
const POOL_LINE_CAP: usize = 4096;

thread_local! {
    static LINE_POOL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Pop a recycled line (capacity warm) or carve a fresh one — the
/// composer's first touch of every frame line. The pop CLEARS: the
/// pool hands back bytes-free strings, capacity retained — a composer
/// that writes without clearing cannot inherit a previous line's
/// bytes (the deep-layout pins caught exactly that inheritance).
pub(crate) fn pooled_line() -> String {
    let mut line = LINE_POOL
        .with(|p| p.borrow_mut().pop())
        .unwrap_or_else(|| String::with_capacity(96));
    line.clear();
    line
}

/// Return the frame's spent lines to the pool — the loop's clear,
/// pool-shaped: called after the diff engine has swapped the frame
/// out (the caller's vector then holds the PREVIOUS frame's
/// strings, capacities warm, none dropped while the pool has room).
pub(crate) fn recycle_frame_lines(lines: &mut Vec<String>) {
    LINE_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        for line in lines.drain(..) {
            if pool.len() < POOL_CAP && line.capacity() <= POOL_LINE_CAP {
                pool.push(line);
            }
        }
    });
}

/// Return ONE spent line to the pool — the single-line twin of
/// [`recycle_frame_lines`] (a composer's scratch line that never
/// became a frame row).
pub(crate) fn recycle_line(line: String) {
    LINE_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if pool.len() < POOL_CAP && line.capacity() <= POOL_LINE_CAP {
            pool.push(line);
        }
    });
}

/// The pooled twin of [`crate::output::fit_to_width`] for a WHOLE
/// string, in place: the fast path keeps the string untouched (the
/// same bytes fit returns), the truncation path cuts at the display
/// boundary and appends the ellipsis.
pub(crate) fn fit_in_place(s: &mut String, w: usize) {
    if display_width(s) <= w {
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
}

/// Push one composed line: a pooled String filled by the same fmt
/// machinery `format!` runs — the call site's one-line port from
/// `lines.push(format!(...))` with no formatting drift.
pub(crate) fn push_pooled(lines: &mut Vec<String>, args: std::fmt::Arguments<'_>) {
    let mut line = pooled_line();
    // String's fmt writes are infallible (the allocator aborts on
    // exhaustion); the expect names that law.
    std::fmt::Write::write_fmt(&mut line, args).expect("String writes are infallible");
    lines.push(line);
}

/// Like [`crate::ebpf::render::write_rate_or_dash`] but owning — the
/// one-shot callers' face of the same bytes.
pub(crate) fn format_rate_or_dash(bps: u64) -> String {
    let mut out = String::new();
    write_rate_or_dash(&mut out, bps);
    out
}

/// The pooled twin of the em-dash rate (night-frontier-Z4): the same
/// bytes — the em dash for zero, the SI ladder plus "/s" otherwise —
/// into a caller-owned String. The frame pool's row cells consume
/// this form.
pub(crate) fn write_rate_or_dash(out: &mut String, bps: u64) {
    if bps == 0 {
        out.push('—');
    } else {
        format_bytes_into(bps, out);
        out.push_str("/s");
    }
}

/// The pooled grey trim (night-frontier-Z4): the detail lines' one
/// finishing home — copy into a warm scratch, fit to the width in place, paint
/// the grey in place, hand the string back. The same bytes the old
/// `grey(&truncate_label(..))` chain returned, minus its Strings.
pub(crate) fn grey_trim(line: &mut String, indent: Option<&str>, w: usize) {
    let mut fitted = pooled_line();
    if let Some(pre) = indent {
        fitted.push_str(pre);
    }
    fitted.push_str(&*line);
    fit_in_place(&mut fitted, w);
    paint_in_place(&mut fitted, grey_open());
    *line = fitted;
}
