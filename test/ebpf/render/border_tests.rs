// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Border pins (NIGHT-boost-20): the triangle wave, the rail ramp,
//! the capability ladder (including the 256-cube quantization landing
//! on the brand's own documented index), the escape-aware fit, and
//! the full-frame wrap contract — corners, rails, closing row, exact
//! widths, through the REAL render path at the classic 80x24.

use super::*;
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::{FrameGeometry, SessionState};
use crate::output::theme::Theme;
use std::time::Duration;

/// The triangle wave (the cosmostrix BD-02 contract): dark at the
/// edges, bright at the midpoint, linear both ways.
#[test]
fn wave_is_the_triangle() {
    assert_eq!(wave(0.0), 0.0);
    assert_eq!(wave(0.25), 0.5);
    assert_eq!(wave(0.5), 1.0);
    assert_eq!(wave(0.75), 0.5);
    assert_eq!(wave(1.0), 0.0);
}

/// Per-channel interpolation in LINEAR LIGHT (NIGHT-boost-23): the
/// endpoints are exact, and the perceptual midpoint renders brighter
/// than the naive sRGB lerp's (50, 100, 128) — the gamma-correct
/// correction is the enhancement itself (IEC 61966-2-1 decode, blend,
/// encode, round-half-away at the u8 boundary).
#[test]
fn lerp_mixes_channels_perceptually() {
    assert_eq!(lerp((0, 0, 0), (100, 200, 255), 0.5), (71, 146, 188));
    assert_eq!(lerp((0, 0, 0), (100, 200, 255), 0.25), (50, 106, 137));
    assert_eq!(lerp((10, 10, 10), (20, 20, 20), 0.0), (10, 10, 10));
    assert_eq!(lerp((10, 10, 10), (20, 20, 20), 1.0), (20, 20, 20));
    // The monotonicity and brightness contracts: every channel of the
    // perceptual midpoint is >= its naive-lerp value (never darker
    // than the arithmetic it replaces), and the ramp stays monotone.
    let naive = (50u8, 100u8, 128u8);
    let perceptual = lerp((0, 0, 0), (100, 200, 255), 0.5);
    for (p, n) in [perceptual.0, perceptual.1, perceptual.2]
        .iter()
        .zip([naive.0, naive.1, naive.2].iter())
    {
        assert!(
            p >= n,
            "gamma-correct midpoints never darken: {perceptual:?}"
        );
    }
    let quarter = lerp((0, 0, 0), (100, 200, 255), 0.25);
    let three_quarters = lerp((0, 0, 0), (100, 200, 255), 0.75);
    for (q, h, t) in [
        (quarter.0, perceptual.0, three_quarters.0),
        (quarter.1, perceptual.1, three_quarters.1),
        (quarter.2, perceptual.2, three_quarters.2),
    ] {
        assert!(
            q <= h && h <= t,
            "monotone ramp: {quarter:?} <= {perceptual:?} <= {three_quarters:?}"
        );
    }
}

/// The rail ramp (netrunner): a one-row frame renders the dark
/// anchor; the middle row of a three-row frame glows the full brand;
/// the last row recedes back to dark. The dark floor is 42% of the
/// brand channels.
#[test]
fn rail_rgb_sweeps_dark_bright_dark() {
    let brand = Theme::Netrunner.brand_rgb();
    let shade = |c: u8| (f32::from(c) * 0.42).round() as u8;
    let dark = (shade(brand.0), shade(brand.1), shade(brand.2));
    assert_eq!(rail_rgb(Theme::Netrunner, 0, 1), dark, "solo row: dark");
    assert_eq!(rail_rgb(Theme::Netrunner, 0, 3), dark, "top row: dark");
    assert_eq!(
        rail_rgb(Theme::Netrunner, 1, 3),
        brand,
        "middle row: the full brand"
    );
    assert_eq!(
        rail_rgb(Theme::Netrunner, 2, 3),
        dark,
        "bottom row: dark again"
    );
}

/// The capability ladder: TrueColor formats the interpolated triple,
/// the 256 ladder quantizes onto the xterm cube — the FULL brand
/// lands on its own documented index (135 for netrunner, the same
/// number the theme table and BRANDING.md carry) — the 16-color rail
/// is the theme's flat brand SGR, and Mono renders nothing.
#[test]
fn rail_escape_capability_ladder() {
    let brand = Theme::Netrunner.brand_rgb();
    assert_eq!(
        rail_escape(brand, Theme::Netrunner, ColorCapability::TrueColor),
        "\x1b[38;2;168;85;247m"
    );
    assert_eq!(
        rail_escape(brand, Theme::Netrunner, ColorCapability::Color256),
        "\x1b[38;5;135m"
    );
    // An interpolated mid-ramp triple quantizes onto a neighbor cube
    // cell: (84, 42, 124) -> 16 + 36*1 + 6*0 + 2 = 54.
    assert_eq!(
        rail_escape((84, 42, 124), Theme::Netrunner, ColorCapability::Color256),
        "\x1b[38;5;54m"
    );
    assert_eq!(
        rail_escape(brand, Theme::Netrunner, ColorCapability::Color16),
        "\x1b[35m"
    );
    assert_eq!(
        rail_escape(brand, Theme::Netrunner, ColorCapability::Mono),
        ""
    );
}

/// The escape-aware fit: visible glyphs are budgeted, escapes pass
/// through whole (never cut mid-sequence), an overlong row cuts at
/// the boundary and lands a reset when a color was left open, and a
/// short row pads — the right rail stays one straight edge.
#[test]
fn fit_budgets_escapes_and_pads() {
    // Plain overlong: hard cut.
    assert_eq!(fit("abcdef", 3), "abc");
    // Plain short: padded.
    assert_eq!(fit("ab", 5), "ab   ");
    // Escape-wrapped overlong: the sequence rides through whole, the
    // cut lands after the budgeted glyphs, and the open color closes.
    let cut = fit("\x1b[38;2;1;2;3mabcdef\x1b[0m", 3);
    assert!(
        cut.starts_with("\x1b[38;2;1;2;3mabc"),
        "the escape leads and exactly three glyphs ride: {cut:?}"
    );
    assert!(!cut.contains("def"), "the overlong tail is gone: {cut:?}");
    assert!(cut.ends_with("\x1b[0m"), "the cut row resets: {cut:?}");
    // Escape-wrapped short: padded after the row's own reset.
    assert_eq!(fit("\x1b[35mab\x1b[0m", 4), "\x1b[35mab\x1b[0m  ");
}

/// The inset geometry (NIGHT-engrave-8): two rail columns, the
/// leading inset, and the never-painted right margin are budgeted
/// before anything renders (80 - 2 rails - 1 lead - 1 margin = 76);
/// degenerate sizes saturate.
#[test]
fn content_geo_insets_the_frame() {
    let geo = content_geo(FrameGeometry {
        width: 80,
        height: 24,
    });
    assert_eq!(
        (geo.width, geo.height),
        (76, 23),
        "two rails, the leading inset, the unpainted right margin, one closing row"
    );
    let tiny = content_geo(FrameGeometry {
        width: 1,
        height: 1,
    });
    assert_eq!((tiny.width, tiny.height), (0, 0), "saturates, never wraps");
}

/// The wrap contract on a synthetic frame (mono, as tests run piped):
/// row 0 passes through untouched (title_bar owns the top border),
/// every row below flanks its fitted content, and the closing row is
/// the bright-anchored full-width floor.
#[test]
fn wrap_flanks_and_closes() {
    let mut lines = vec![
        "╭─── title ─╮".to_string(),
        "  hello".to_string(),
        String::new(),
    ];
    wrap(&mut lines, 20);
    assert_eq!(lines.len(), 4, "the closing row joins the frame");
    // NIGHT-engrave-8: every row gains the leading inset column and
    // the frame composes one column short of the terminal (20 -> 19).
    assert_eq!(
        lines[0], " ╭─── title ─╮",
        "row 0 carries the inset before its own top border"
    );
    assert_eq!(lines[1], format!(" │  hello{}│", " ".repeat(9)));
    assert_eq!(lines[2], format!(" │{}│", " ".repeat(16)));
    assert_eq!(lines[3], format!(" ╰{}╯", "─".repeat(16)));
}

/// An empty frame stays empty — nothing to flank, nothing to close.
#[test]
fn wrap_skips_empty_frames() {
    let mut lines: Vec<String> = Vec::new();
    wrap(&mut lines, 80);
    assert!(lines.is_empty());
}

/// The full-frame integration (the REAL render path, classic 80x24,
/// mono pins): every row spans exactly the terminal width, the title
/// carries the rounded corners, the middle rows wear the rails, and
/// the frame closes on the full-width floor.
#[test]
fn full_frame_wears_the_border() {
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &crate::ebpf::loader::CounterSummary::default(),
        &[],
        &crate::ebpf::identity::IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 80,
            height: 24,
        },
    );
    assert_eq!(
        lines.len(),
        24,
        "border included, still pinned to the height"
    );
    assert!(
        lines[0].starts_with(" ╭") && lines[0].ends_with('╮'),
        "the title bar closes the top border one column in: {}",
        lines[0]
    );
    for row in &lines[1..23] {
        assert!(
            row.starts_with(" │") && row.ends_with('│'),
            "every content row wears the rails one column in: {row:?}"
        );
        // NIGHT-engrave-8: the frame composes at terminal-1 — both
        // rails one column from the edges, the final column never
        // painted (no pending-wrap hazard for the trailing EL).
        assert_eq!(
            row.chars().count(),
            79,
            "one straight right edge, one column short of the terminal"
        );
    }
    assert_eq!(
        lines[23],
        format!(" ╰{}╯", "─".repeat(76)),
        "the closing row is the frame-width floor"
    );
    // The rails follow the ACTIVE theme: cycling leaves the glyph
    // geometry untouched (mono pins hold whatever the palette does).
    crate::output::theme::set(Theme::Atomic);
    let mut themed = Vec::new();
    render_eagle_eyes_at(
        &mut themed,
        &crate::ebpf::loader::CounterSummary::default(),
        &[],
        &crate::ebpf::identity::IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 80,
            height: 24,
        },
    );
    crate::output::theme::set(Theme::Netrunner);
    // The rails follow the ACTIVE theme: cycling repaints color and
    // the status line's theme name — never the glyph geometry (the
    // rail columns and the closing row hold, row for row).
    assert_eq!(themed.len(), lines.len());
    assert_eq!(themed[0], lines[0], "the title border is layout-stable");
    assert_eq!(themed[23], lines[23], "the closing row is layout-stable");
    for (cycled, plain) in themed[1..23].iter().zip(lines[1..23].iter()) {
        assert_eq!(
            cycled.chars().count(),
            plain.chars().count(),
            "row width is theme-independent"
        );
        assert!(cycled.starts_with(" │") && cycled.ends_with('│'));
    }
    assert!(
        themed.join("\n").contains("theme atomic"),
        "the status line names the cycled theme"
    );
    assert!(
        lines.join("\n").contains("theme netrunner"),
        "the default names itself"
    );
}
