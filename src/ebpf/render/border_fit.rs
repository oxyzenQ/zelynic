// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The border's fit family (night-frontier-Z11) — split from
//! border.rs by the NIGHT-improve-44 LOC law (a pure move, gates
//! green in between): the row fit walks and the background re-open
//! splice, the in-place forms the wrap composes with and the fresh
//! string reference face the drift-guard pin holds them against.

use super::border::RESET;

// The splice's retained replacement scratch (the reset+bg bytes the
// splice lands after every inner reset) — the frame pool's own
// retained-buffer discipline at module scale.
thread_local! {
    static SPLICE: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Fit one composed row to the border's content width: escape
/// sequences are invisible (copied through whole, never cut
/// mid-sequence), visible glyphs count against the budget by their
/// RENDERED width (NIGHT-lts-1: CJK/fullwidth glyphs paint two
/// columns per char — counting chars let a five-ideograph comm
/// paint twice its budget and dent the right rail), an overlong
/// row is cut at the boundary (a reset lands when a color was left
/// open), and a short row pads with spaces — the right rail stays
/// one straight edge whatever the content did.
#[cfg(test)]
pub(super) fn fit(row: &str, width: usize) -> String {
    let mut out = String::with_capacity(row.len() + width);
    let mut visible = 0usize;
    let mut seen_escape = false;
    let mut it = row.chars();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            seen_escape = true;
            out.push(c);
            for n in it.by_ref() {
                out.push(n);
                if n == 'm' {
                    break;
                }
            }
            continue;
        }
        // The ASCII fast path inlined at the call site (the harness
        // runs the dev profile, where a per-char cross-module call
        // is a real frame — the bench showed it as measurable
        // render-throughput cost; the boundary constant is
        // char_width's own, kept in step by its pins).
        let cw = if (c as u32) < 0x0300 {
            1
        } else {
            crate::output::char_width(c)
        };
        if visible + cw > width {
            break;
        }
        out.push(c);
        visible += cw;
    }
    if seen_escape && !out.ends_with(RESET) {
        out.push_str(RESET);
    }
    if visible < width {
        out.push_str(&" ".repeat(width - visible));
    }
    out
}

// night-frontier-Z11 (stage 2): the wrap's retained buffers — the
// terminal background escape, the per-row left rail prefix, and the
// reset+bg splice string each ride a module-local scratch instead of
// owning fresh Strings per row. The frame line pool's own
// discipline at module scale: warm by the second frame, zero heap
// events in steady state.
/// Fit one composed row to the border's content width, IN PLACE
/// (night-frontier-Z11): the into-twin of [`fit`] — the same walk
/// (escapes copied whole, glyphs counted at their rendered width,
/// the boundary cut, the open color closed, the short row padded),
/// writing into the caller's buffer so the pooled row keeps its
/// capacity across frames. The cut lands on a visible glyph (never
/// mid-escape), exactly where [`fit`]'s fresh-string walk stopped
/// copying.
pub(super) fn fit_in_place_border(buf: &mut String, width: usize) {
    let mut visible = 0usize;
    let mut seen_escape = false;
    let mut cut: Option<usize> = None;
    let mut it = buf.char_indices();
    while let Some((idx, c)) = it.next() {
        if c == '\x1b' {
            seen_escape = true;
            for (_i2, n) in it.by_ref() {
                if n == 'm' {
                    break;
                }
            }
            continue;
        }
        // The ASCII fast path inlined at the call site (the same
        // boundary constant [`fit`] inlines; the harness runs the dev
        // profile, where a per-char cross-module call is a real
        // frame).
        let cw = if (c as u32) < 0x0300 {
            1
        } else {
            crate::output::char_width(c)
        };
        if visible + cw > width {
            cut = Some(idx);
            break;
        }
        visible += cw;
    }
    if let Some(idx) = cut {
        buf.truncate(idx);
    }
    if seen_escape && !buf.ends_with(RESET) {
        buf.push_str(RESET);
    }
    while visible < width {
        buf.push(' ');
        visible += 1;
    }
}

/// The background re-open splice, IN PLACE: every inner RESET gains
/// the background back after it (NIGHT-boost-26's
/// `content.replace(RESET, RESET+bg)`, without the owned String the
/// replace built per row). The replacement bytes ride the module's
/// retained splice scratch; the range splices shift bytes inside the
/// warm row buffer.
pub(super) fn splice_bg_reopens(buf: &mut String, bg: &str) {
    SPLICE.with(|cell| {
        let mut repl = cell.borrow_mut();
        let mut pos = 0usize;
        while let Some(found) = buf[pos..].find(RESET) {
            let at = pos + found;
            repl.clear();
            repl.push_str(RESET);
            repl.push_str(bg);
            buf.replace_range(at..at + RESET.len(), &repl);
            pos = at + RESET.len() + bg.len();
        }
    });
}
