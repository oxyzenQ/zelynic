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
//! Capability ladder: TrueColor interpolates the brand RGB per row;
//! xterm-256 quantizes each interpolated triple onto the 6x6x6 cube;
//! 16-color terminals render the rails in the theme's flat brand SGR
//! (sixteen colors cannot ramp within one hue — a flat rail beats a
//! noisy one); Mono renders the plain glyphs. The rails follow the
//! ACTIVE theme: cycling with `t` repaints them through the diff
//! engine like every other painted line.

use super::FrameGeometry;
use crate::output::theme::{self, Theme};
use crate::output::{capability, ColorCapability};

/// Columns the border claims: one rail each side.
pub(super) const BORDER_W: usize = 2;

/// Rows the border claims: the dedicated closing row.
pub(super) const BORDER_ROWS: usize = 1;

/// The SGR reset the flanked rows close with (the same constant the
/// color layer's wrappers append — spelled here because the color
/// module stays output-internal).
const RESET: &str = "\x1b[0m";

/// The dark anchor's brightness factor: the gradient's floor sits at
/// 42% of the brand color — dark enough to read as recession, bright
/// enough to stay a hue (a zero floor would render black rails on
/// the dark-theme palettes).
const DARK_FACTOR: f32 = 0.42;

/// The content geometry a bordered frame composes into: the rails'
/// two columns and the closing row's one line are budgeted BEFORE
/// anything renders, so every existing width and height decision —
/// the column ladder, the footer pin, the detail trimming — flows
/// through the inset geometry unchanged.
#[must_use]
pub(super) fn content_geo(geo: FrameGeometry) -> FrameGeometry {
    FrameGeometry {
        width: geo.width.saturating_sub(BORDER_W),
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

/// One rail's color: the theme's brand RGB swept by the triangle
/// wave at the row's position down the whole bordered frame (`rows`
/// counts the closing row too, so the wave spans the visible frame).
fn rail_rgb(theme: Theme, row: usize, rows: usize) -> (u8, u8, u8) {
    let brand = theme.brand_rgb();
    let shade = |c: u8| (f32::from(c) * DARK_FACTOR).round() as u8;
    let dark = (shade(brand.0), shade(brand.1), shade(brand.2));
    let t = if rows > 1 {
        row as f32 / (rows - 1) as f32
    } else {
        0.0
    };
    lerp(dark, brand, wave(t))
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

/// Fit one composed row to the border's content width: escape
/// sequences are invisible (copied through whole, never cut
/// mid-sequence), visible glyphs count against the budget, an
/// overlong row is cut at the boundary (a reset lands when a color
/// was left open), and a short row pads with spaces — the right rail
/// stays one straight edge whatever the content did.
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
        if visible >= width {
            break;
        }
        out.push(c);
        visible += 1;
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
    let content_w = width.saturating_sub(BORDER_W);
    let cap = capability();
    let theme = theme::active();
    // NIGHT-boost-26: the frame's background follows the terminal —
    // the OSC 11 triple the monitor's open path queried, painted on
    // every row so the frame reads as part of the terminal's own
    // theme (grey terminal, grey frame) instead of the alt screen's
    // default. Empty at Mono/Color16 or when the terminal never
    // answered: those frames render exactly as before. Inner color
    // resets would kill it mid-row, so each one re-opens the
    // background right after; the row's own trailing RESET then
    // closes everything the row opened.
    let bg = theme::terminal_bg_escape();
    // Row 0 (the title bar) passes through the flank loop below
    // untouched — it carries the top border. The background still
    // belongs to it: prepended here, closed by the bar's own RESET.
    if !bg.is_empty() {
        lines[0].insert_str(0, &bg);
    }
    for (i, line) in lines.iter_mut().enumerate().skip(1) {
        let mut content = fit(line, content_w);
        // Re-open the background after every inner reset so the
        // paint survives a mid-row tier change (a grey detail line,
        // a red champion row) — the reset stays honest for the
        // glyphs it closed; the background simply rides on.
        if !bg.is_empty() && content.contains('\x1b') {
            content = content.replace(RESET, &format!("{RESET}{bg}"));
        }
        let esc = rail_escape(rail_rgb(theme, i, rows), theme, cap);
        // A row that carried its own colors ends reset — the right
        // rail re-opens the gradient. A plain row never disturbed
        // the left rail's color: one escape carries both rails.
        let mut row = String::with_capacity(bg.len() + esc.len() * 2 + content.len() + 8);
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
    // The closing row (BD-02: the bright anchor): the frame's
    // foundation, visually anchored whatever the wave does above it.
    let bright = rail_escape(theme.brand_rgb(), theme, cap);
    let mut closing = String::with_capacity(width + bright.len() + bg.len() + RESET.len());
    // The closing row opens with the terminal background like every
    // other row (NIGHT-boost-26) — the foundation is bright, the
    // floor it sits on is the terminal's own.
    closing.push_str(&bg);
    closing.push_str(&bright);
    closing.push('╰');
    closing.push_str(&"─".repeat(width.saturating_sub(BORDER_W)));
    closing.push('╯');
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
