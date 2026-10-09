// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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
use crate::output::{capability, ColorCapability};
use std::collections::HashMap;
use std::sync::Mutex;

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
fn wave(t: f32) -> f32 {
    if t <= 0.5 {
        t * 2.0
    } else {
        2.0 - t * 2.0
    }
}

/// sRGB electro-optical decode, the exact IEC 61966-2-1 piecewise
/// transfer (NIGHT-boost-23): a channel value becomes linear light.
fn to_linear(c: u8) -> f32 {
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
fn from_linear(l: f32) -> u8 {
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
fn rail_rgb(
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
fn rail_escape(rgb: (u8, u8, u8), theme: Theme, cap: ColorCapability) -> String {
    match cap {
        ColorCapability::TrueColor => format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2),
        ColorCapability::Color256 => {
            // Nearest xterm cube color: 16 + 36r + 6g + b over the
            // 6-per-channel quantization (the standard mapping — the
            // full brand quantizes to its own documented 256 index).
            let q = |c: u8| (usize::from(c) * 6 / 256).min(5);
            let idx = 16 + 36 * q(rgb.0) + 6 * q(rgb.1) + q(rgb.2);
            format!("\x1b[38;5;{idx}m")
        }
        // Sixteen colors cannot ramp within one hue: the theme's flat
        // brand SGR is the honest rail.
        ColorCapability::Color16 => {
            theme::escape_for(theme, theme::Slot::Brand, false, cap).to_string()
        }
        ColorCapability::Mono => String::new(),
    }
}

/// The horizontal sweep's run composer (NIGHT-engrave-11): `len`
/// copies of `glyph` at columns `start..start+len` of a `span`-wide
/// line, each colored by the rails' chroma method at its own
/// column — the exact method [`rail_rgb`] rides, run across the
/// width.
///
/// The hoist (the chroma module's own cost note — "endpoints
/// pre-derived per frame would save more"): the pair's OKLab
/// coordinates are RUN-INVARIANT (one theme, one anchor), so the
/// two sRGB -> OKLab conversions happen once per run, and the
/// per-column work is the lightness lerp, the polar chroma lerp,
/// and the gamut-mapped encode alone — the same operations in the
/// same order [`crate::output::chroma::oklab_blend_rgb`] performs,
/// bit-exact, minus the per-cell conversions. The drift killer is
/// the pin: `sweep_run` over a whole span must equal the per-column
/// [`rail_rgb`] + [`rail_escape`] composition, byte for byte (the
/// border pins run both paths against each other).
///
/// TrueColor blends in OKLab per column; Color256 quantizes the
/// legacy linear-light ramp per column (the rails' own 256
/// behavior, one cube index per column, its endpoints hoisted the
/// same way); the flat rungs return the plain glyph run — the
/// caller's open SGR colors it (Color16's flat brand, Mono's
/// no-paint), the exact bytes those depths always rendered. No
/// RESET inside the run: the caller opens once, closes once, and
/// the terminal background (NIGHT-boost-26) rides the whole row
/// unbroken.
pub(super) fn sweep_run(
    glyph: char,
    start: usize,
    len: usize,
    span: usize,
    theme: Theme,
    anchor: Option<(u8, u8, u8)>,
    cap: ColorCapability,
) -> String {
    // The flat rungs bypass the memo: their bytes are the trivial
    // glyph repeat, nothing to remember.
    if !matches!(cap, ColorCapability::TrueColor | ColorCapability::Color256) {
        return glyph.to_string().repeat(len);
    }
    let key = (theme, cap, glyph, start, len, span, anchor);
    if let Some(hit) = swept_runs().get(&key) {
        return hit.clone();
    }
    let composed = compose_sweep_run(glyph, start, len, span, theme, anchor, cap);
    let mut runs = swept_runs();
    if runs.len() >= SWEPT_RUN_CAP {
        runs.clear();
    }
    runs.insert(key, composed.clone());
    composed
}

/// The swept-run memo (NIGHT-engrave-11's LTS half): a composed run
/// is a pure function of its key — theme, capability, glyph, start,
/// len, span, and the anchor triple (which every caller derives
/// from the theme; the key carries it anyway so a foreign anchor
/// can never be masked by a hit) — so the per-column chroma work
/// pays ONCE per shape and every later frame clones the composed
/// bytes. The monitor re-sweeps the same geometry all session at
/// its one-frame cadence: the live loop hits the memo every frame
/// after the first; a theme cycle, a resize, or a capability
/// change misses once and re-fills. The entry cap is the
/// self-healing guard — the working set is a handful of lines (the
/// bar, the grid, the floor, per width), so overflow means a
/// pathological shape churn: clear and start over.
fn swept_runs() -> std::sync::MutexGuard<'static, HashMap<SweptKey, String>> {
    static RUNS: std::sync::OnceLock<Mutex<HashMap<SweptKey, String>>> = std::sync::OnceLock::new();
    RUNS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The memo's key: everything the composed bytes are a function of.
type SweptKey = (
    Theme,
    ColorCapability,
    char,
    usize,
    usize,
    usize,
    Option<(u8, u8, u8)>,
);

/// The memo's entry cap (the self-healing guard's threshold).
const SWEPT_RUN_CAP: usize = 32;

/// The composed run body the memo wraps — the per-column chroma
/// walk with its run-invariant endpoints hoisted (see the pin: the
/// hoisted walk is rail_rgb + rail_escape byte for byte).
fn compose_sweep_run(
    glyph: char,
    start: usize,
    len: usize,
    span: usize,
    theme: Theme,
    anchor: Option<(u8, u8, u8)>,
    cap: ColorCapability,
) -> String {
    match cap {
        ColorCapability::TrueColor => {
            let brand = theme.brand_rgb();
            let dark = anchor
                .unwrap_or_else(|| crate::output::chroma::scale_lightness(brand, DARK_FACTOR));
            let (l0, a0, b0) = crate::output::chroma::srgb_to_oklab(dark.0, dark.1, dark.2);
            let (l1, a1, b1) = crate::output::chroma::srgb_to_oklab(brand.0, brand.1, brand.2);
            let mut run = String::with_capacity(len * 24);
            for col in start..start.saturating_add(len) {
                let t = wave(if span > 1 {
                    col as f32 / (span - 1) as f32
                } else {
                    0.0
                });
                let l = l0 + (l1 - l0) * t;
                let (a, b) = crate::output::chroma::polar_chroma_lerp(a0, b0, a1, b1, t);
                let (r, g, bl) = crate::output::chroma::oklab_to_srgb_mapped(l, a, b);
                run.push_str(&format!("\x1b[38;2;{r};{g};{bl}m"));
                run.push(glyph);
            }
            run
        }
        ColorCapability::Color256 => {
            // The legacy rung's ramp, its endpoints hoisted the same
            // way: the encoded-channel anchor and the brand decode to
            // linear light once, the per-column work is the lerp,
            // encode, and cube quantization (the rail ladder's own
            // bytes, one escape per column).
            let brand = theme.brand_rgb();
            let shade = |c: u8| (f32::from(c) * DARK_FACTOR).round() as u8;
            let dark = (shade(brand.0), shade(brand.1), shade(brand.2));
            let (lr, lg, lb) = (to_linear(dark.0), to_linear(dark.1), to_linear(dark.2));
            let (hr, hg, hb) = (to_linear(brand.0), to_linear(brand.1), to_linear(brand.2));
            let mut run = String::with_capacity(len * 12);
            for col in start..start.saturating_add(len) {
                let t = wave(if span > 1 {
                    col as f32 / (span - 1) as f32
                } else {
                    0.0
                });
                let q = |lv: f32, hv: f32| from_linear(lv + (hv - lv) * t);
                let (r, g, bl) = (q(lr, hr), q(lg, hg), q(lb, hb));
                let cq = |c: u8| (usize::from(c) * 6 / 256).min(5);
                let idx = 16 + 36 * cq(r) + 6 * cq(g) + cq(bl);
                run.push_str(&format!("\x1b[38;5;{idx}m"));
                run.push(glyph);
            }
            run
        }
        _ => glyph.to_string().repeat(len),
    }
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
fn fit(row: &str, width: usize) -> String {
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

/// Wrap the composed frame in its borders. Row 0 is the title bar —
/// [`super::title_bar`] already renders its rounded corners spanning
/// the full width (the top border), so it passes through untouched.
/// Every row below flanks its fitted content with the gradient
/// rails, and the closing row lands last, in the bright anchor.
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
    let bg = terminal_bg::terminal_bg_escape();
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
    let lead = if bg.is_empty() {
        " ".to_string()
    } else {
        format!(" {bg}")
    };
    lines[0].insert_str(0, &lead);
    for (i, line) in lines.iter_mut().enumerate().skip(1) {
        let mut content = fit(line, content_w);
        // Re-open the background after every inner reset so the
        // paint survives a mid-row tier change (a grey detail line,
        // a red champion row) — the reset stays honest for the
        // glyphs it closed; the background simply rides on.
        if !bg.is_empty() && content.contains('\x1b') {
            content = content.replace(RESET, &format!("{RESET}{bg}"));
        }
        let esc = rail_escape(rail_rgb(theme, chroma_anchor, i, rows, cap), theme, cap);
        // A row that carried its own colors ends reset — the right
        // rail re-opens the gradient. A plain row never disturbed
        // the left rail's color: one escape carries both rails.
        let mut row =
            String::with_capacity(LEFT_INSET + bg.len() + esc.len() * 2 + content.len() + 8);
        // NIGHT-engrave-8: the leading space column rides OUTSIDE
        // the paint (the margin the terminal owns), the background
        // opens the canvas at the rail.
        row.push(' ');
        row.push_str(&bg);
        row.push_str(&esc);
        row.push('│');
        row.push_str(&content);
        if content.contains('\x1b') {
            row.push_str(&esc);
        }
        row.push('│');
        if !esc.is_empty() || !bg.is_empty() {
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
    let bright = rail_escape(theme.brand_rgb(), theme, cap);
    let swept = matches!(cap, ColorCapability::TrueColor | ColorCapability::Color256);
    let span = content_w + BORDER_W;
    let mut closing = String::with_capacity(
        LEFT_INSET + width + if swept { span * 24 } else { bright.len() } + bg.len() + RESET.len(),
    );
    // The closing row opens with the inset column like every other
    // row (NIGHT-engrave-8) and the terminal background
    // (NIGHT-boost-26) — the floor it sits on is the terminal's
    // own. The sweep-capable depths need no open SGR (every glyph
    // carries its own column escape); the flat rungs open with the
    // bright anchor exactly as they always have.
    closing.push(' ');
    closing.push_str(&bg);
    if !swept {
        closing.push_str(&bright);
    }
    closing.push_str(&sweep_run('╰', 0, 1, span, theme, chroma_anchor, cap));
    closing.push_str(&sweep_run(
        '─',
        1,
        content_w,
        span,
        theme,
        chroma_anchor,
        cap,
    ));
    closing.push_str(&sweep_run(
        '╯',
        content_w + 1,
        1,
        span,
        theme,
        chroma_anchor,
        cap,
    ));
    if !bright.is_empty() {
        closing.push_str(RESET);
    }
    lines.push(closing);
}

// NIGHT-boost-20: the border pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like
// the eagle and footer pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/border_tests.rs"]
mod border_tests;
