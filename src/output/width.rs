// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Terminal display-width measurement and budgeting (NIGHT-lts-1)
//! — the one canonical place a label's RENDERED width is decided.
//!
//! The residual untrusted-input class of the cybersecurity-1
//! family: the sanitizer closed escape-byte injection (a comm can
//! no longer smuggle control sequences), but CJK and fullwidth
//! glyphs render TWO terminal columns per char, and every width
//! decision in the crate counted CHARS. A prctl-set comm like a
//! five-ideograph name — or an honest one: CJK app names are real
//! on real desktops — sat inside every char budget while painting
//! twice it, denting the eagle-eyes right rail and shifting the
//! report tables' columns. The measurement below is the pragmatic
//! wcwidth subset the label column needs, not a typography engine:
//! wide East Asian ranges count 2, combining marks and
//! zero-width joiners count 0, everything else counts 1 (the
//! ellipsis included).
//!
//! Routing discipline (the "one acquisition path per resource"
//! invariant): border.rs's `fit` — the last defense before the
//! rails — measures here; render.rs's `truncate_label` and
//! `title_bar` budget here; the eagle row's label cell and the
//! list-apps comm column pad through [`pad_to_width`] here. A
//! future surface that renders untrusted text measures the same
//! way, not its own.

// NON_LATIN_FIXTURE: the CJK rows in the tests below are runtime
// width-measurement coverage, not prose (scripts/gates/
// check-language.sh exemption — the same marker sanitize.rs carries).

/// The display width of one character: the pragmatic wcwidth.
///
/// Wide (2 columns): Hangul (Jamo, syllables, Ext-A), Hiragana,
/// Katakana, CJK radicals/punctuation/symbols, CJK Unified
/// Ideographs and Extension A, Yi, CJK Compatibility Ideographs,
/// vertical and compatibility forms, fullwidth punctuation,
/// fullwidth forms, fullwidth signs — the ranges a process name
/// or an endpoint label can realistically carry.
///
/// Zero (0 columns): combining diacriticals, zero-width
/// space/joiner/non-joiner, BOM/dirmarks, variation selectors —
/// they stack onto the preceding cell and never claim their own.
///
/// Everything else measures 1, including `…` (the truncation
/// ellipsis) and every ASCII printable — the dominant case, kept
/// on the fast path.
#[inline]
#[must_use]
pub fn char_width(c: char) -> usize {
    let cp = c as u32;
    // The hot-path fast return: everything below the first
    // zero-width class (combining diacritics, U+0300) is width 1 —
    // ASCII and all the Latin/Greek/Cyrillic tables the monitor's
    // own furniture (digits, SI units, box drawing) lives in. One
    // compare for the glyphs that dominate every frame (the fit()
    // loop calls this per visible char per row; the bench showed the
    // per-call range checks as a measurable render-throughput cost).
    if cp < 0x0300 {
        return 1;
    }
    if matches!(cp,
        0x0300..=0x036F       // combining diacriticals
        | 0x200B..=0x200F     // zero-width space, joiners, marks
        | 0x2060..=0x2064     // word joiner, invisible ops
        | 0xFE00..=0xFE0F     // variation selectors
    ) {
        return 0;
    }
    if matches!(cp,
        0x1100..=0x115F       // Hangul Jamo
        | 0x2E80..=0x303E     // CJK radicals, Kangxi, symbols, punctuation
        | 0x3041..=0x33FF     // Hiragana, Katakana, CJK compatibility
        | 0x3400..=0x4DBF     // CJK Unified Ideographs Extension A
        | 0x4E00..=0x9FFF     // CJK Unified Ideographs
        | 0xA000..=0xA4CF     // Yi syllables and radicals
        | 0xA960..=0xA97F     // Hangul Jamo Extension A
        | 0xAC00..=0xD7A3     // Hangul syllables
        | 0xF900..=0xFAFF     // CJK Compatibility Ideographs
        | 0xFE10..=0xFE19     // vertical forms
        | 0xFE30..=0xFE6F     // CJK compatibility forms
        | 0xFF01..=0xFF60     // fullwidth punctuation and letters
        | 0xFFE0..=0xFFE6     // fullwidth signs
    ) {
        return 2;
    }
    1
}

/// The rendered width of a string in terminal columns — the sum of
/// [`char_width`] over its chars. Escape sequences are NOT this
/// function's business: its callers measure already-composed
/// content (the border's `fit` walks escapes separately, and the
/// sanitizer guarantees no escape reaches a label).
#[inline]
#[must_use]
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Fit a string into a display-column budget, truncating with an
/// ellipsis when it does not fit: the budget counts RENDERED
/// columns, so a five-ideograph name (10 columns) fits a 6-column
/// budget as two ideographs plus `…` (5 columns). A string that
/// already fits returns unchanged — the fast path for the ASCII
/// names that dominate every host.
#[must_use]
pub fn fit_to_width(s: &str, w: usize) -> String {
    if display_width(s) <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for c in s.chars() {
        let cw = char_width(c);
        if used + cw > w - 1 {
            break;
        }
        out.push(c);
        used += cw;
    }
    out.push('…');
    out
}

/// Fit AND pad: [`fit_to_width`] plus trailing spaces so the result
/// renders exactly `w` columns — the width-aware replacement for
/// `format!("{:<w$}")` whenever the cell holds untrusted text (a
/// char-padded CJK label pads by the char shortfall while painting
/// the full column width, pushing every following cell of the row
/// out of column). The common already-fits case is ONE measuring
/// scan (the row renderer's per-frame hot path — the bench showed
/// the naive fit-then-measure pair as real render-throughput cost).
#[must_use]
pub fn pad_to_width(s: &str, w: usize) -> String {
    let mut width = 0usize;
    let mut over = false;
    for c in s.chars() {
        // The ASCII fast path inline (the row renderer calls this
        // per label per frame; char_width stays the authority for
        // the ranges above the boundary).
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
        let mut out = String::with_capacity(s.len() + (w - width));
        out.push_str(s);
        out.push_str(&" ".repeat(w - width));
        return out;
    }
    let mut out = fit_to_width(s, w);
    let used = display_width(&out);
    if used < w {
        out.push_str(&" ".repeat(w - used));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Width classes: ASCII 1, ideographs 2, combining 0 — the
    /// pragmatic wcwidth contract the label column budgets by.
    #[test]
    fn width_classes() {
        assert_eq!(display_width("brave"), 5);
        assert_eq!(
            display_width("谷歌浏览器"),
            10,
            "five ideographs, ten columns"
        );
        assert_eq!(
            display_width("ｂｒａｖｅ"),
            10,
            "fullwidth letters render double"
        );
        assert_eq!(
            display_width("e\u{301}"),
            1,
            "combining mark stacks, claims no cell"
        );
        assert_eq!(display_width("…"), 1);
        assert_eq!(display_width(""), 0);
    }

    /// fit_to_width truncates by RENDERED columns, not chars: the
    /// honest-ASCII fast path is byte-stable, the CJK name degrades
    /// to whole ideographs plus the ellipsis inside the budget.
    #[test]
    fn fit_budgets_rendered_columns() {
        assert_eq!(fit_to_width("firefox", 10), "firefox");
        assert_eq!(fit_to_width("firefox", 3), "fi…");
        // 10-column name into 6: two ideographs (4) + ellipsis (1).
        assert_eq!(fit_to_width("谷歌浏览器", 6), "谷歌…");
        // Degenerate budgets stay total.
        assert_eq!(fit_to_width("anything", 0), "");
        assert_eq!(fit_to_width("", 4), "");
    }

    /// pad_to_width lands exactly on the budget in rendered
    /// columns — the char-padding drift (`{:<w$}` pads the char
    /// shortfall while the glyphs paint full width) is the bug this
    /// replaces, pinned as the regression shape.
    #[test]
    fn pad_lands_on_the_rendered_budget() {
        assert_eq!(pad_to_width("ab", 5), "ab   ");
        assert_eq!(display_width(&pad_to_width("谷歌", 9)), 9);
        // The pre-fix shape: format!("{:<4}", "谷歌") renders 4+2
        // columns (2 glyphs + 2 pad) — pad_to_width renders exactly 4.
        assert_eq!(display_width(&pad_to_width("谷歌", 4)), 4);
        // Over-budget degrades through the ellipsis then pads.
        assert_eq!(display_width(&pad_to_width("谷歌浏览器", 6)), 6);
    }
}
