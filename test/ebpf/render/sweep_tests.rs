// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The swept-run pins (night-improve-64 split of the border pins by
//! the NIGHT-improve-44 LOC law): the sweep test moved with the
//! composer it pins — `sweep_run` over a span must equal the
//! per-column `rail_rgb` + `rail_escape` composition byte for byte
//! (the drift killer), one escape per column, no RESET inside the
//! run, and the flat rungs keep the plain glyph bytes.

use super::sweep_run;
use crate::ebpf::render::border::{rail_escape, rail_rgb};
use crate::output::theme::Theme;
use crate::output::ColorCapability;

#[test]
fn sweep_run_is_the_rails_method_across_the_columns() {
    let brand = Theme::Netrunner.brand_rgb();
    let chroma_dark = crate::output::chroma::scale_lightness(brand, 0.42);
    // The wave shape across a 9-column line, chroma engine: dark at
    // both edges, the exact brand at the middle column (endpoints
    // preserved — the same law the rows pin).
    assert_eq!(
        rail_rgb(
            Theme::Netrunner,
            Some(chroma_dark),
            0,
            9,
            ColorCapability::TrueColor
        ),
        chroma_dark,
        "left edge: the perceptual anchor"
    );
    assert_eq!(
        rail_rgb(
            Theme::Netrunner,
            Some(chroma_dark),
            4,
            9,
            ColorCapability::TrueColor
        ),
        brand,
        "middle column: the full brand, exact"
    );
    assert_eq!(
        rail_rgb(
            Theme::Netrunner,
            Some(chroma_dark),
            8,
            9,
            ColorCapability::TrueColor
        ),
        chroma_dark,
        "right edge: the perceptual anchor again"
    );
    // The legacy engine sweeps the columns identically (the 256
    // rung's own ramp, quantized per column by rail_escape).
    let shade = |c: u8| (f32::from(c) * 0.42).round() as u8;
    let dark = (shade(brand.0), shade(brand.1), shade(brand.2));
    assert_eq!(
        rail_rgb(Theme::Netrunner, None, 0, 9, ColorCapability::Color256),
        dark,
        "legacy column sweep: dark edge"
    );
    assert_eq!(
        rail_rgb(Theme::Netrunner, None, 4, 9, ColorCapability::Color256),
        brand,
        "legacy column sweep: the brand at the glow"
    );
    // The composer: every column carries its own escape, the glyph
    // rides behind it, and no RESET ever lands inside the run. The
    // five-column span is the exact wave: dark, the perceptual
    // midpoint, the brand, the midpoint again, dark.
    let run = sweep_run(
        '─',
        0,
        5,
        5,
        Theme::Netrunner,
        Some(chroma_dark),
        ColorCapability::TrueColor,
    );
    let mid = crate::output::chroma::oklab_blend_rgb(
        chroma_dark.0,
        chroma_dark.1,
        chroma_dark.2,
        brand.0,
        brand.1,
        brand.2,
        0.5,
    );
    assert_eq!(
        run,
        format!(
            "\x1b[38;2;{};{};{}m─\x1b[38;2;{};{};{}m─\x1b[38;2;{};{};{}m─\x1b[38;2;{};{};{}m─\x1b[38;2;{};{};{}m─",
            chroma_dark.0,
            chroma_dark.1,
            chroma_dark.2,
            mid.0,
            mid.1,
            mid.2,
            brand.0,
            brand.1,
            brand.2,
            mid.0,
            mid.1,
            mid.2,
            chroma_dark.0,
            chroma_dark.1,
            chroma_dark.2,
        ),
        "five columns of the sweep, no inner reset (dark, mid, brand, mid, dark)"
    );
    // The drift killer: the hoisted composer must equal the
    // per-cell rail_rgb + rail_escape walk byte for byte, every
    // column of the span, both engines — the hoist moves the
    // endpoint conversions out of the loop, never the math.
    for (cap, anchor) in [
        (ColorCapability::TrueColor, Some(chroma_dark)),
        (ColorCapability::Color256, None),
    ] {
        let hoisted = sweep_run('─', 0, 12, 12, Theme::Netrunner, anchor, cap);
        let mut walked = String::new();
        for col in 0..12 {
            walked.push_str(&rail_escape(
                rail_rgb(Theme::Netrunner, anchor, col, 12, cap),
                Theme::Netrunner,
                cap,
            ));
            walked.push('─');
        }
        assert_eq!(
            hoisted, walked,
            "the hoisted sweep is the rails' own walk, byte for byte"
        );
    }
    // The flat rungs: the plain glyph run, the caller's SGR colors
    // it (Color16's flat brand, Mono's no-paint) — the exact bytes
    // those depths always rendered.
    assert_eq!(
        sweep_run(
            '─',
            0,
            3,
            9,
            Theme::Netrunner,
            Some(chroma_dark),
            ColorCapability::Color16
        ),
        "───"
    );
    assert_eq!(
        sweep_run(
            '╰',
            0,
            1,
            9,
            Theme::Netrunner,
            Some(chroma_dark),
            ColorCapability::Mono
        ),
        "╰"
    );
}
