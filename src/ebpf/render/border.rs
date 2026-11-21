// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Eagle-eyes frame borders (NIGHT-boost-20): the left-right border
//! with rounded corners and a vertical gradient — the cosmostrix msg
//! border mode lineage (its BD-02 corner-aware gradient contract),
//! scaled from one message box to the whole live frame.
//!
//! Shape: the title bar IS the top border — its rounded corners
//! connect to the bar's own purple fill ([`super::title_bar`]
//! renders them spanning the full width). Every row below flanks
//! its content with gradient-colored rails, and the frame closes on
//! a dedicated bottom border row in the bright anchor color. The
//! whole monitor reads as one rounded box — calm and static, the
//! same LTS language as the rest of the frame (no animation, no
//! pulse; the rails are furniture, not a heartbeat).
//!
//! The gradient (the cosmostrix triangle-wave contract): the brand
//! color sweeps dark -> bright -> dark down the frame's rows, so the
//! rails glow brightest at the frame's middle and recede at its
//! edges — no single edge dominates. The BD-02 bottom-corner rule
//! rides along: the closing row always uses the BRIGHT anchor — the
//! frame sits on its foundation, visually anchored whatever the wave
//! does above it.
//!
//! NIGHT-boost-23 (gradient enhance): the rail interpolation now
//! runs in LINEAR LIGHT — the sRGB channels decode through the
//! exact IEC 61966-2-1 transfer, blend, and encode back. The naive
//! sRGB lerp darkened the perceptual midtones (the ramp spent its
//! time near the dark anchor and rushed through bright), the
//! classic gradient-banding artifact; the gamma-correct midpoint
//! renders at the brightness the arithmetic claims. The anchors are
//! unchanged (BRANDING.md carries sRGB numbers), the wave is
//! unchanged (the BD-02 triangle is an LTS-stable contract in
//! cosmostrix), and the cost is two powf per channel per row — the
//! frame duty at the 1s cadence is unmoved.
//!
//! NIGHT-improve-41 (the chroma dragon engine): the linear-light
//! ramp is now the LEGACY rung. TrueColor frames ride the chroma
//! dragon engine ported from cosmostrix
//! (crate::output::chroma) — OKLab polar interpolation, the
//! perceptual space where midpoints stay clean and lightness steps
//! read even — and the ramp's floor becomes 42% of the brand's
//! OKLab LIGHTNESS (hue and chroma preserved) instead of 42% of
//! its encoded channels: the anchor is the same hue at the
//! brightness the eye actually attributes to 42%, never the mud
//! the gamma-domain multiply produced. The owner's contract is
//! chroma FIRST, legacy fallback: a terminal that cannot render
//! truecolor keeps the exact legacy bytes it always rendered
//! (linear-light lerp at 256, flat SGR at 16, plain glyphs at
//! Mono) — the port changes what TrueColor frames look like, and
//! nothing else.
//!
//! NIGHT-engrave-11 (the horizontal masterclass): the gradient stops
//! being the rails' private property — every HORIZONTAL line the
//! frame draws (the title bar's top border, the table grid lines,
//! the closing floor) now sweeps the SAME chroma method ACROSS the
//! columns that the rails ride down the rows. The method is
//! orientation-blind by construction (one blend at a position over
//! a span, the triangle wave deciding where in the sweep the cell
//! sits), so the horizontals call the very function the rails call
//! with the column index in the position slot. The frame reads as
//! one continuous wave on all four edges — dark corners, glowing
//! center — instead of flat bright horizontals fighting their own
//! gradient rails. The capability ladder rides along: TrueColor
//! sweeps in OKLab, Color256 sweeps the legacy linear-light ramp
//! quantized per column (exactly what the rails do at 256), and the
//! flat rungs keep their exact bytes (Color16 cannot ramp within
//! one hue — a flat line beats a noisy one; Mono never painted).
//!
//! NIGHT-engrave-8 (symmetric margins): the frame composes ONE
//! column inside the terminal — a leading space column before the
//! left rail and an unpainted final column after the right rail,
//! both rails exactly one column from the terminal's edges (the
//! owner's "both should have a 1px margin" contract, the CSS-margin
//! reading of the border). The unpainted last column is the
//! terminal-physics half of the fix: painting INTO the final column
//! leaves the cursor in pending-wrap state where the emission's
//! trailing erase-to-EOL behaves differently per terminal (some eat
//! the just-written rail) — the composed frame never touches it,
//! so the trailing ESC[K always erases a guaranteed-blank cell and
//! the right rail renders identically everywhere. The content
//! width absorbs the two columns (W-4 at an 80-column terminal).
//!
//! Capability ladder: TrueColor interpolates the brand RGB per row;
//! xterm-256 quantizes each interpolated triple onto the 6x6x6 cube;
//! 16-color terminals render the rails in the theme's flat brand SGR
//! (sixteen colors cannot ramp within one hue — a flat rail beats a
//! noisy one); Mono renders the plain glyphs. The rails follow the
//! ACTIVE theme: cycling with `t` repaints them through the diff
//! engine like every other painted line.

use super::FrameGeometry;
use crate::output::terminal_bg;
use crate::output::theme::{self, Theme};
use crate::output::{ColorCapability, capability};

/// Columns the border claims: one rail each side.
pub(super) const BORDER_W: usize = 2;

/// Rows the border claims: the dedicated closing row.
pub(super) const BORDER_ROWS: usize = 1;

/// NIGHT-engrave-8: the frame's leading space column — the left
/// rail sits one column in from the terminal's left edge, the
/// mirror of the final column the frame never paints (the right
/// rail one column in from the right edge). Both margins are the
/// owner's "1px each side" contract.
const LEFT_INSET: usize = 1;

/// NIGHT-engrave-8: the terminal columns the composed row leaves
/// untouched on the right — the frame's own width is the terminal
/// width minus this margin, so no row ever paints the final column
/// (the pending-wrap hazard the trailing erase-to-EOL makes
/// terminal-dependent).
const RIGHT_MARGIN: usize = 1;

/// The width the frame's PASS-THROUGH row composes at
/// (NIGHT-engrave-8): the title bar builds its `╭...╮` line at this
/// width, and wrap's leading inset column brings the rendered row
/// to `term_width - 1` — one column short of the terminal's right
/// edge, the final column never painted.
#[must_use]
pub(super) fn frame_width(term_width: usize) -> usize {
    term_width
        .saturating_sub(RIGHT_MARGIN)
        .saturating_sub(LEFT_INSET)
}

/// The content width inside the rails (NIGHT-engrave-8): the frame
/// width minus both rails and the leading inset — what [`fit`]
/// pads and truncates to.
fn content_width(term_width: usize) -> usize {
    term_width
        .saturating_sub(RIGHT_MARGIN)
        .saturating_sub(BORDER_W)
        .saturating_sub(LEFT_INSET)
}

/// The SGR reset the flanked rows close with (the same constant the
/// color layer's wrappers append — spelled here because the color
/// module stays output-internal). NIGHT-engrave-11: `pub(super)` —
/// the swept bar composer and the swept grid line close their rows
/// with the family's one spelling.
pub(super) const RESET: &str = "\x1b[0m";

/// The dark anchor's brightness factor: the gradient's floor sits at
/// 42% of the brand color — dark enough to read as recession, bright
/// enough to stay a hue (a zero floor would render black rails on
/// the dark-theme palettes). NIGHT-improve-41: the factor's DOMAIN
/// follows the engine — the chroma path (TrueColor) reads it in
/// OKLab LIGHTNESS (crate::output::chroma::scale_lightness — 42%
/// perceived brightness, hue preserved), the legacy rungs keep the
/// encoded-channel multiply the pre-port ramp carried (their bytes
/// are the fallback contract, unchanged). NIGHT-engrave-11: the
/// factor is the whole sweep family's constant — the horizontal
/// composers (the title bar, the grid line) share this one floor so
/// both axes anchor at the same darkness; `pub(super)` for exactly
/// that reach.
pub(super) const DARK_FACTOR: f32 = 0.42;

/// The content geometry a bordered frame composes into: the rails'
/// two columns and the closing row's one line are budgeted BEFORE
/// anything renders, so every existing width and height decision —
/// the column ladder, the footer pin, the detail trimming — flows
/// through the inset geometry unchanged.
#[must_use]
pub(super) fn content_geo(geo: FrameGeometry) -> FrameGeometry {
    FrameGeometry {
        width: content_width(geo.width),
        height: geo.height.saturating_sub(BORDER_ROWS),
    }
}

/// The gradient's triangle wave (the cosmostrix BD-02 contract):
/// dark -> bright -> dark across t in [0, 1] — the midpoint glows,
/// the edges recede, neither side dominates.
pub(super) fn wave(t: f32) -> f32 {
    if t <= 0.5 { t * 2.0 } else { 2.0 - t * 2.0 }
}

/// sRGB electro-optical decode, the exact IEC 61966-2-1 piecewise
/// transfer (NIGHT-boost-23): a channel value becomes linear light.
pub(super) fn to_linear(c: u8) -> f32 {
    let v = f32::from(c) / 255.0;
    if v <= 0.040_45 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// sRGB electro-optical encode, the inverse transfer: linear light
/// becomes a channel value, rounded half-away at the u8 boundary
/// and clamped as LTS armor (the anchors are in range by
/// construction).
pub(super) fn from_linear(l: f32) -> u8 {
    let v = if l <= 0.003_130_8 {
        l * 12.92
    } else {
        1.055 * l.powf(1.0 / 2.4) - 0.055
    };
    (v * 255.0).round().clamp(0.0, 255.0) as u8
}

/// Interpolate between two RGB triples in LINEAR LIGHT (NIGHT-boost-23
/// gradient enhance), per channel: decode both endpoints, blend,
/// encode. The naive sRGB lerp darkened perceptual midtones — the
/// ramp banded near the dark anchor; the gamma-correct midpoint
/// renders at the brightness the arithmetic claims.
fn lerp(a: (u8, u8, u8), b: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let mix = |x: u8, y: u8| {
        let lx = to_linear(x);
        let ly = to_linear(y);
        from_linear(lx + (ly - lx) * t)
    };
    (mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))
}

/// One swept cell's color: the theme's brand RGB carried by the
/// triangle wave at the cell's position along the span (`span`
/// counts every painted position, the frame's closing row
/// included, so the wave spans the visible extent).
///
/// NIGHT-engrave-11: the function is orientation-BLIND on purpose —
/// the vertical rails call it with the row index over the frame's
/// row count, the horizontal sweep with the column index over the
/// line's column count; the method (anchor, wave, blend) is one
/// and the same on both axes, which is the whole masterclass
/// point. The `pos`/`span` names say position along a span, not
/// row down a frame.
///
/// NIGHT-improve-41: the ramp rides the chroma dragon engine at
/// TrueColor — the dark anchor is the brand scaled to 42% OKLab
/// LIGHTNESS (hue preserved at the gamut boundary) and the sweep
/// blends in the perceptual space (crate::output::chroma,
/// cosmostrix's sole production gradient path). `anchor` carries
/// that pre-derived dark triple — a pure function of the theme,
/// derived ONCE per frame by the caller (24 rows share it; the
/// per-row work is the blend alone); None falls back to deriving
/// it inline (the pins' convenience). Every other depth keeps the
/// legacy ramp (NIGHT-boost-23's linear-light lerp over the
/// encoded-channel anchor) — the chroma-first contract: a system
/// that cannot represent truecolor falls back to the legacy
/// colors, byte-for-byte the ramp it always rendered.
pub(super) fn rail_rgb(
    theme: Theme,
    anchor: Option<(u8, u8, u8)>,
    pos: usize,
    span: usize,
    cap: ColorCapability,
) -> (u8, u8, u8) {
    let brand = theme.brand_rgb();
    let t = if span > 1 {
        pos as f32 / (span - 1) as f32
    } else {
        0.0
    };
    match cap {
        ColorCapability::TrueColor => {
            let dark = anchor
                .unwrap_or_else(|| crate::output::chroma::scale_lightness(brand, DARK_FACTOR));
            crate::output::chroma::oklab_blend_rgb(
                dark.0,
                dark.1,
                dark.2,
                brand.0,
                brand.1,
                brand.2,
                wave(t),
            )
        }
        // The legacy rungs: the encoded-channel anchor and the
        // linear-light blend, unchanged since NIGHT-boost-23 (the
        // anchor argument is a chroma-path concern — ignored here).
        _ => {
            let shade = |c: u8| (f32::from(c) * DARK_FACTOR).round() as u8;
            let dark = (shade(brand.0), shade(brand.1), shade(brand.2));
            lerp(dark, brand, wave(t))
        }
    }
}

/// The escape for one rail color at the probed capability depth.
#[cfg(test)]
pub(super) fn rail_escape(rgb: (u8, u8, u8), theme: Theme, cap: ColorCapability) -> String {
    let mut out = String::new();
    push_rail_escape(&mut out, rgb, theme, cap);
    out
}

/// The into-twin of [`rail_escape`] (night-frontier-Z11 stage 1):
/// the same bytes into a caller-owned buffer — the wrap's per-row
/// rail escape stops owning a fresh String per row and lands in the
/// warm row buffer instead. `write!` into the String carries the
/// same formatting `format!` ran (String's fmt writes are
/// infallible); the retained call-site buffer takes it with zero
/// heap events in steady state.
pub(super) fn push_rail_escape(
    out: &mut String,
    rgb: (u8, u8, u8),
    theme: Theme,
    cap: ColorCapability,
) {
    use std::fmt::Write as _;
    match cap {
        ColorCapability::TrueColor => {
            let _ = write!(out, "\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2);
        }
        ColorCapability::Color256 => {
            // Nearest xterm cube color: 16 + 36r + 6g + b over the
            // 6-per-channel quantization (the standard mapping — the
            // full brand quantizes to its own documented 256 index).
            let q = |c: u8| (usize::from(c) * 6 / 256).min(5);
            let idx = 16 + 36 * q(rgb.0) + 6 * q(rgb.1) + q(rgb.2);
            let _ = write!(out, "\x1b[38;5;{idx}m");
        }
        // Sixteen colors cannot ramp within one hue: the theme's flat
        // brand SGR is the honest rail.
        ColorCapability::Color16 => {
            out.push_str(theme::escape_for(theme, theme::Slot::Brand, false, cap));
        }
        ColorCapability::Mono => {}
    }
}

#[cfg(test)]
use super::border_fit::fit;
/// Wrap the composed frame in its borders. Row 0 is the title bar —
/// [`super::title_bar`] already renders its rounded corners spanning
/// the full width (the top border), so it passes through untouched.
/// Every row below flanks its fitted content with the gradient
/// rails, and the closing row lands last, in the bright anchor.
use super::border_fit::{fit_in_place_border, splice_bg_reopens};

thread_local! {
    static BG: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    static LEFT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

pub(super) fn wrap(lines: &mut Vec<String>, width: usize) {
    if lines.is_empty() {
        return;
    }
    let rows = lines.len() + BORDER_ROWS;
    let content_w = content_width(width);
    let cap = capability();
    let theme = theme::active();
    // NIGHT-boost-26: the frame's background follows the terminal —
    // the OSC 11 triple the monitor's open path queried and the
    // live ask keeps current (NIGHT-boost-32), painted on every row
    // so the frame reads as part of the terminal's own theme (grey
    // terminal, grey frame) instead of the alt screen's default.
    // Empty at Mono/Color16 or when the terminal never answered:
    // those frames render exactly as before. Inner color resets
    // would kill it mid-row, so each one re-opens the background
    // right after; the row's own trailing RESET then closes
    // everything the row opened.
    // night-frontier-Z11: the background escape rides the module's
    // retained scratch (push_terminal_bg_escape writes in place) — the
    // borrow lives across the whole wrap body inside BG.with, a &str
    // instead of an owned String per frame.
    BG.with(|cell| {
        let mut bg_cell = cell.borrow_mut();
        bg_cell.clear();
        terminal_bg::push_terminal_bg_escape(&mut bg_cell);
        let bg: &str = &bg_cell;
        // NIGHT-improve-41: the chroma engine's dark anchor is a pure
        // function of the ACTIVE theme — one derivation per frame, not
        // one per row (every row shares it; the per-row work is the
        // blend alone). None on the legacy rungs, which derive their
        // own encoded-channel anchor per call as they always have.
        let chroma_anchor = (cap == ColorCapability::TrueColor)
            .then(|| crate::output::chroma::scale_lightness(theme.brand_rgb(), DARK_FACTOR));
        // Row 0 (the title bar) passes through the flank loop below
        // untouched — it carries the top border. The inset column and
        // the background still belong to it: the space leads
        // (NIGHT-engrave-8, outside the paint), the background follows
        // (NIGHT-boost-26, closed by the bar's own RESET).
        // The pass-through row's inset + background, inserted in place
        // (the owned lead String's format! was another named site).
        if bg.is_empty() {
            lines[0].insert(0, ' ');
        } else {
            lines[0].insert_str(0, bg);
            lines[0].insert(0, ' ');
        }
        for (i, line) in lines.iter_mut().enumerate().skip(1) {
            // night-frontier-Z11: the composition happens IN the pooled
            // row's own buffer — mem::take hands the buffer out, the fit
            // walks it in place, the splice and the rails land inside it,
            // and the buffer returns with its capacity intact. The old
            // shape built three owned Strings per row (the fit's fresh
            // copy, the replace's fresh copy, the composed row itself,
            // which even DISCARDED the pooled buffer the call site handed
            // over); all three are gone.
            let mut row = std::mem::take(line);
            fit_in_place_border(&mut row, content_w);
            // Re-open the background after every inner reset so the
            // paint survives a mid-row tier change (a grey detail line,
            // a red champion row) — the reset stays honest for the
            // glyphs it closed; the background simply rides on.
            // The escape flags: the fit's own walk said whether the row
            // carried any escape — the right rail re-opens on that (the
            // splice only ever ADDS escapes, so the post-splice answer is
            // the same), and the splice itself rides the background's
            // emptiness exactly as the replace did.
            let raw_escaped = row.contains('\x1b');
            if !bg.is_empty() && raw_escaped {
                splice_bg_reopens(&mut row, bg);
            }
            // The left rail: inset + background + rail color + the rail
            // glyph, spliced ahead of the content from the retained
            // prefix scratch (the rail color varies per row, so the
            // scratch rebuilds; the buffer is warm).
            LEFT.with(|cell| {
                let mut left = cell.borrow_mut();
                left.clear();
                left.push(' ');
                left.push_str(bg);
                push_rail_escape(
                    &mut left,
                    rail_rgb(theme, chroma_anchor, i, rows, cap),
                    theme,
                    cap,
                );
                left.push('│');
                row.insert_str(0, &left);
            });
            // The right rail: a row that carried its own colors ends with
            // the rail color re-opened — the right rail re-opens the
            // gradient. A plain row never disturbed the left rail's
            // color: one escape carries both rails.
            if raw_escaped {
                push_rail_escape(
                    &mut row,
                    rail_rgb(theme, chroma_anchor, i, rows, cap),
                    theme,
                    cap,
                );
            }
            row.push('│');
            if !matches!(cap, ColorCapability::Mono) || !bg.is_empty() {
                row.push_str(RESET);
            }
            *line = row;
        }
        // The closing row (NIGHT-engrave-11: the horizontal masterclass
        // sweep — the BD-02 bright foundation is re-expressed as the
        // sweep's bright midpoint: the same wave the vertical rails
        // ride, run ACROSS the columns, so the frame reads as one
        // continuous wave on all four edges, dark corners and a glowing
        // center; the corners land at the rails' own bottom colors and
        // the box finally closes on itself). One color open per column,
        // no inner reset — the terminal background (NIGHT-boost-26)
        // rides until the row's single closing reset. The flat rungs
        // keep their exact bytes: Color16 renders the bright anchor SGR
        // around a plain glyph run, Mono renders plain glyphs.
        let swept = matches!(cap, ColorCapability::TrueColor | ColorCapability::Color256);
        let span = content_w + BORDER_W;
        // night-frontier-Z11: the closing row rides a pooled buffer too —
        // the three sweep runs append from the memo without cloning, and
        // the flat rungs' bright anchor writes in place.
        let mut closing = super::pool::pooled_line();
        // The closing row opens with the inset column like every other
        // row (NIGHT-engrave-8) and the terminal background
        // (NIGHT-boost-26) — the floor it sits on is the terminal's
        // own. The sweep-capable depths need no open SGR (every glyph
        // carries its own column escape); the flat rungs open with the
        // bright anchor exactly as they always have.
        closing.push(' ');
        closing.push_str(bg);
        if !swept {
            push_rail_escape(&mut closing, theme.brand_rgb(), theme, cap);
        }
        super::sweep::push_sweep_run(&mut closing, '╰', 0, 1, span, theme, chroma_anchor, cap);
        super::sweep::push_sweep_run(
            &mut closing,
            '─',
            1,
            content_w,
            span,
            theme,
            chroma_anchor,
            cap,
        );
        super::sweep::push_sweep_run(
            &mut closing,
            '╯',
            content_w + 1,
            1,
            span,
            theme,
            chroma_anchor,
            cap,
        );
        if !matches!(cap, ColorCapability::Mono) {
            closing.push_str(RESET);
        }
        lines.push(closing);
    });
}

// NIGHT-boost-20: the border pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like
// the eagle and footer pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/border_tests.rs"]
mod border_tests;
