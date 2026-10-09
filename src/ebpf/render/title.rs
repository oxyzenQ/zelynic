// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The eagle-eyes title bar (the frame's TOP border composer) —
//! split from render.rs by the NIGHT-improve-44 LOC law (a pure
//! move, gates green in between): the centered `title_bar` and the
//! `swept_bar` chroma composer it rides, plus their exact-bytes
//! pins. The module map lives in the render root; this file owns
//! one shape: `╭──…── <core> ──…──╮`, the core riding the middle.

use super::{border, capability, display_width, theme, truncate_label, ColorCapability};
use crate::output::brand_bold;

/// Render the title bar — the frame's TOP BORDER (NIGHT-boost-20):
/// bold purple brand text, filled to the full frame width, with
/// rounded corners connecting to the bar's own fill (the cosmostrix
/// msg-border look). Identity only since NIGHT-engrave-3: the
/// top-right key hint retired at the owner's call — the legend's
/// only home is the footer's status line, which is why that row
/// rides every compression tier.
///
/// NIGHT-engrave-11 (the horizontal masterclass): at the
/// sweep-capable depths the bar's furniture (the corner, the flank
/// fills, the closing corner) paints per column with
/// the SAME chroma method the vertical rails ride — the wave runs
/// across the bar (dark edges, glowing center), while the core
/// label stays FLAT bold brand (identity, not furniture: the
/// sweep's dark anchor must never dim the name). The wave's
/// positions advance THROUGH the label's columns, so the fill
/// resumes exactly where the label leaves off. Color16 and Mono
/// keep the exact flat bytes (sixteen colors cannot ramp within
/// one hue; Mono never painted).
///
/// Shape: `╭───…─── <core> ───…───╮` (the flank runs balance around
/// the core; the bar degrades to the plain fill before it loses its
/// corners). NIGHT-engrave-12: the core rides the MIDDLE of the bar
/// — the former fixed `╭─── ` prefix hugged the identity to the
/// top-left corner; the leftover columns now flank it as two
/// balanced dash runs (the floor on the left, the remainder on the
/// right — Rust's own `{:^}` centering convention), one rendered
/// gutter each side. The centering is the bar's own law: every
/// surface that speaks through this composer (eagle, focus, depth
/// report, loading, status, list-apps) centers together.
#[must_use]
pub(crate) fn title_bar(core: &str, width: usize) -> String {
    const CAP: &str = "─╮";
    // NIGHT-lts-1: the core's budget is its RENDERED width — the
    // focus title carries a cgroup's comm, and a CJK name paints
    // two columns per char (the fill math below follows the same
    // measurement; the rails depend on the bar landing exactly on
    // `width` columns).
    //
    // NIGHT-improve-36: the bar ALWAYS lands on exactly `width`
    // columns — the same fit-to-width contract every other frame
    // row carries. The core truncates with an ellipsis before the
    // bar loses its shape; identity degrades gracefully, geometry
    // never breaks.
    let cap_len = display_width(CAP);
    let core_len = display_width(core);

    if width == 0 {
        return String::new();
    }

    // Too narrow to carry a cornered, guttered core (five columns
    // or fewer): the fill carries the bar alone (cornered when the
    // width can carry the cap, plain otherwise). The bar's purple
    // shape still spans the full width so the frame stays
    // rectangular on the narrowest terminals.
    if width <= 5 {
        let tail = if width >= cap_len { CAP } else { "" };
        let glyphs = format!(
            "{}{}",
            "─".repeat(width.saturating_sub(display_width(tail))),
            tail
        );
        if matches!(
            capability(),
            ColorCapability::Mono | ColorCapability::Color16
        ) {
            return brand_bold(&glyphs);
        }
        return swept_bar(&glyphs, None, width);
    }

    // The centered core's budget: two corners, two gutters, and one
    // flank dash a side are reserved; everything else is the core's.
    const RESERVED: usize = 6;
    let budget = width.saturating_sub(RESERVED);
    let fitted = if core_len == 0 || budget == 0 {
        String::new()
    } else if core_len <= budget {
        core.to_string()
    } else {
        truncate_label(core, budget)
    };
    let fitted_len = display_width(&fitted);

    let (glyphs, text) = if fitted_len == 0 {
        // The plain bar (width six, or a core too wide to carry one
        // glyph): corners and fill only — geometry first, identity
        // already yielded everything it had.
        (format!("╭{}╮", "─".repeat(width - 2)), None)
    } else {
        let dashes = width - 4 - fitted_len;
        let left = dashes / 2;
        (
            format!(
                "╭{} {fitted} {}╮",
                "─".repeat(left),
                "─".repeat(dashes - left)
            ),
            Some((left + 2, fitted_len)),
        )
    };
    if matches!(
        capability(),
        ColorCapability::Mono | ColorCapability::Color16
    ) {
        return brand_bold(&glyphs);
    }
    // The label's first column sits one corner + one flank run + one
    // gutter in; its span is the RENDERED width (NIGHT-lts-1 — a
    // CJK name paints two columns per char).
    swept_bar(&glyphs, text, width)
}

/// NIGHT-engrave-11: the swept bar composer. `glyphs` is the bar's
/// one-char-per-column row (corner, flank fill, label, gutter,
/// flank fill, corner — NIGHT-engrave-12 centered the label); the
/// wave runs across the whole `width`, each
/// furniture glyph painted by the chroma method the vertical rails
/// ride ([`super::sweep::sweep_run`] at its own column), while the
/// `text` columns (start, rendered length) stay FLAT bold brand —
/// the label is identity, the sweep is furniture. One bold open
/// and one reset for the whole bar: no inner reset ever closes the
/// terminal background the border wrap opens on row 0
/// (NIGHT-boost-26); the per-column fg escapes replace the
/// foreground only. Bare spaces (the prefix gutter, the separator)
/// paint nothing — the background shows through exactly as the
/// flat bar's brand-colored spaces read.
fn swept_bar(glyphs: &str, text: Option<(usize, usize)>, width: usize) -> String {
    let theme = theme::active();
    let cap = capability();
    // One anchor derivation for the whole bar (the border wrap's
    // per-frame contract — the columns share it).
    let anchor = crate::output::chroma::scale_lightness(theme.brand_rgb(), border::DARK_FACTOR);
    let (text_start, text_end) = text.map_or((usize::MAX, usize::MAX), |(s, len)| {
        (s, s.saturating_add(len))
    });
    let mut bar = String::with_capacity(width * 24 + 32);
    // The render tree assembles its own escapes (the NIGHT-boost-20
    // exception — the border gradient family builds its own ramp
    // bytes; the color layer's wrappers stay the CLI surface's
    // whole API). The bold open carries the brand fg the label
    // inherits; the swept columns replace the fg only, so the bold
    // weight spans the whole bar exactly as the flat bar's did.
    bar.push_str(theme::escape(theme::Slot::Brand, true));
    let mut col = 0usize;
    // The furniture composes in BATCHED runs (the hoist's string
    // half): one sweep_run per contiguous same-glyph stretch, not
    // one call per glyph — the sweep's own per-run endpoint hoist
    // only pays when the run is long.
    let mut seg: Option<(usize, char)> = None;
    for g in glyphs.chars() {
        let in_text = col >= text_start && col < text_end;
        let furniture = !in_text && g != ' ';
        if furniture {
            match seg {
                Some((_s, open)) if open == g => {}
                Some((s, open)) => {
                    bar.push_str(&super::sweep::sweep_run(
                        open,
                        s,
                        col - s,
                        width,
                        theme,
                        Some(anchor),
                        cap,
                    ));
                    seg = Some((col, g));
                }
                None => seg = Some((col, g)),
            }
        } else {
            if let Some((s, open)) = seg.take() {
                bar.push_str(&super::sweep::sweep_run(
                    open,
                    s,
                    col - s,
                    width,
                    theme,
                    Some(anchor),
                    cap,
                ));
            }
            // The label's chars and the bare spaces paint nothing
            // here — the open SGR's bold brand colors the label
            // (identity), the background shows through the spaces.
            bar.push(g);
        }
        // The same rendered-width walk the fit path carries (the
        // ASCII fast path inlined at the call site).
        col += if (g as u32) < 0x0300 {
            1
        } else {
            crate::output::char_width(g)
        };
    }
    if let Some((s, open)) = seg.take() {
        bar.push_str(&super::sweep::sweep_run(
            open,
            s,
            col - s,
            width,
            theme,
            Some(anchor),
            cap,
        ));
    }
    bar.push_str(border::RESET);
    bar
}

// NON_LATIN_FIXTURE: the CJK literal in the narrow-ladder pin below
// is runtime width-measurement coverage, not prose (the same
// exemption sanitize.rs carries for its passthrough pin).
#[cfg(test)]
mod tests {
    use super::*;

    /// Title bar (NIGHT-boost-20 shape): rounded top border, exact
    /// width, graceful degradation on narrow frames. NIGHT-engrave-12:
    /// the core rides the MIDDLE of the bar — balanced flank runs,
    /// one gutter each side, the floor left and the remainder right
    /// (the `{:^}` convention). NIGHT-engrave-1: the hint led with
    /// the theme key; NIGHT-engrave-2: identity only (the legend
    /// moved to the footer's status line); NIGHT-engrave-3: the hint
    /// itself retired — the corners belong to the fill alone.
    #[test]
    fn title_bar_fills_width() {
        let bar = title_bar("zelynic eagle-eyes", 80);
        // Mono mode (tests run piped): plain text, exact width. The
        // centered title at 80: (80 - 4 - 18) / 2 = 29 flank dashes
        // a side around one gutter each side.
        assert_eq!(bar.chars().count(), 80);
        assert_eq!(
            bar,
            format!(
                "\u{256d}{} zelynic eagle-eyes {}\u{256e}",
                "─".repeat(29),
                "─".repeat(29)
            ),
            "engrave-12: the title sits dead center, flanks balanced"
        );
        assert!(
            !bar.contains("t theme") && !bar.contains("q quit"),
            "engrave-3: the key hint is gone from the top-right, the\nlegend lives in the footer's status line alone: {bar}"
        );

        // Narrow (NIGHT-improve-36): the core truncates with an
        // ellipsis so the bar lands on EXACTLY `width` columns —
        // no overflow, no wrap, no alignment shift on the narrowest
        // terminals. The centered form keeps one flank dash a side
        // even under the tightest fit (10 - 4 - 4 = 2).
        let tiny = title_bar("zelynic eagle-eyes", 10);
        assert_eq!(tiny.chars().count(), 10);
        assert_eq!(tiny, "╭─ zel… ─╮");

        // Medium: the flanks carry to both corners, no hint.
        let mid = title_bar("zelynic eagle-eyes", 40);
        assert_eq!(
            mid,
            format!(
                "\u{256d}{} zelynic eagle-eyes {}\u{256e}",
                "─".repeat(9),
                "─".repeat(9)
            )
        );
        assert!(!mid.contains("t theme"));
        assert!(mid.ends_with('╮'));
        assert_eq!(mid.chars().count(), 40);
    }

    /// Narrow-width ladder (NIGHT-improve-36): the title bar's
    /// inviolable contract is that it lands on EXACTLY `width`
    /// columns at every width — the bar never overflows, never
    /// wraps, never shifts the rows below it. The full-core shape
    /// holds while the budget carries it; the ellipsis degrades the
    /// identity one glyph at a time below that; the fill-only floor
    /// keeps the bar's purple shape rectangular on the narrowest
    /// terminals. This pin walks the ladder end to end.
    #[test]
    fn title_bar_narrow_never_overflows() {
        let core = "zelynic eagle-eyes";
        // Every width from 0 to 80: the bar is exactly `width` cols
        // (chars().count() == display_width here — ASCII core + box
        // drawing, every glyph one column).
        for w in 0..=80usize {
            let bar = title_bar(core, w);
            assert_eq!(
                bar.chars().count(),
                w,
                "title_bar must land on exactly {w} cols (got {}): {bar:?}",
                bar.chars().count()
            );
        }

        // The identity holds while the budget carries the full core:
        // at width 24 (corners 2 + gutters 2 + core 18 + flanks 2)
        // the full core is intact and cornered, the flanks one dash
        // a side (NIGHT-engrave-12: the centered form carries the
        // full core one column lower than the old left-hugging
        // prefix — no fixed five-column rent on the identity).
        let just_fits = title_bar(core, 24);
        assert_eq!(just_fits.chars().count(), 24);
        assert_eq!(just_fits, "╭─ zelynic eagle-eyes ─╮");

        // One col narrower: the ellipsis takes the first downgrade
        // (the budget drops to 17, the core yields to 16 cols + the
        // ellipsis; the flanks keep one dash a side).
        let ellipsis_floor = title_bar(core, 23);
        assert_eq!(ellipsis_floor.chars().count(), 23);
        assert_eq!(ellipsis_floor, "╭─ zelynic eagle-ey… ─╮");
        assert!(ellipsis_floor.contains('…'));

        // Width six: the core cannot carry one glyph — the plain
        // bar keeps both corners and the fill, rectangular.
        assert_eq!(title_bar(core, 6), "╭────╮");
        // Width seven: the ellipsis alone rides the middle.
        assert_eq!(title_bar(core, 7), "╭─ … ─╮");

        // Below the prefix: the fill carries the bar alone — no
        // prefix, no core, just the purple shape, still rectangular.
        let floor = title_bar(core, 3);
        assert_eq!(floor.chars().count(), 3);
        assert!(floor.chars().all(|c| c == '─' || c == '╮'));

        // Zero width: the empty string (no allocation worth painting).
        assert_eq!(title_bar(core, 0), "");

        // CJK core (NIGHT-lts-1 lineage): two columns per ideograph,
        // the budget counts rendered columns, the bar still lands
        // exactly on `width` (display columns, not code points —
        // chars().count() undercounts CJK by half).
        let cjk = title_bar("谷歌浏览器监控", 16);
        assert_eq!(display_width(&cjk), 16);
    }
}
