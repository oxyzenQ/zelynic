// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The NIGHT-lts-9 computed accuracy pin: the xterm-256 cube,
//! rebuilt in test code, grades the catalog's own rendered escapes.
//!
//! The boost-23 fallback contract says the brand/ok slots take the
//! NEAREST xterm cube match (hue must read true) — until lts-9 that
//! contract was pinned only as hand-asserted literals, so a wrong
//! index could sit in the table with nothing to contradict it. The
//! lts-9 computed audit (the scratch matrix over all 11 themes x 5
//! slots) found exactly one such seat: night_cyber's brand rode the
//! pure-cyan corner 51 at 3.4x the nearest error, and it is now its
//! true 45. This pin recomputes the nearest cell from the SAME
//! numbers the table renders — the RGB is parsed from the TrueColor
//! escape, the index from the 256 escape — so the contract can never
//! silently rot again: an edit to any brand/ok index that leaves the
//! nearest-match class reddens here with the exact distance pair.
//!
//! Ties are legal (spaceflight's brand has two equidistant cells; the
//! table may hold either). The one documented exception is carbon's
//! brand, pinned separately with its tier-hierarchy rationale.

use super::{escape_for, Slot, Theme, THEMES};
use crate::output::color::ColorCapability;

/// The xterm 6x6x6 cube cell levels (xterm's own stair: 0, 95, 135,
/// 175, 215, 255 — not a linear ramp, the deliberate xterm choice
/// that buys a perceptual stair with six steps).
const CUBE_LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// The cube cell's RGB for a palette index in 16..=231
/// (`16 + 36*r + 6*g + b`, the xterm encoding).
fn cube_rgb(index: u8) -> (u8, u8, u8) {
    assert!(
        (16..=231).contains(&index),
        "index {index} is not a cube cell"
    );
    let v = index - 16;
    (
        CUBE_LEVELS[usize::from(v / 36)],
        CUBE_LEVELS[usize::from((v / 6) % 6)],
        CUBE_LEVELS[usize::from(v % 6)],
    )
}

/// Squared RGB distance — the documented metric (plain Euclidean,
/// no perceptual weighting: the boost-23 corrections were computed
/// under exactly this arithmetic).
fn dist2(a: (u8, u8, u8), b: (u8, u8, u8)) -> u32 {
    let (dr, dg, db) = (
        u32::from(a.0.saturating_sub(b.0).max(b.0.saturating_sub(a.0))),
        u32::from(a.1.saturating_sub(b.1).max(b.1.saturating_sub(a.1))),
        u32::from(a.2.saturating_sub(b.2).max(b.2.saturating_sub(a.2))),
    );
    dr * dr + dg * dg + db * db
}

/// The minimum squared distance from `rgb` to any cube cell, and the
/// first index achieving it.
fn nearest_cube(rgb: (u8, u8, u8)) -> (u8, u32) {
    let mut best_idx = 16;
    let mut best_dist = dist2(rgb, cube_rgb(16));
    for idx in 17..=231 {
        let d = dist2(rgb, cube_rgb(idx));
        if d < best_dist {
            best_dist = d;
            best_idx = idx;
        }
    }
    (best_idx, best_dist)
}

/// The 256-depth index the table renders for one theme/slot, parsed
/// from the real escape ("\x1b[38;5;N m") — the pin grades the table
/// itself, never a duplicated literal.
fn table_index(theme: Theme, slot: Slot) -> u8 {
    let esc = escape_for(theme, slot, false, ColorCapability::Color256);
    let digits = esc
        .strip_prefix("\x1b[38;5;")
        .and_then(|s| s.strip_suffix('m'))
        .unwrap_or_else(|| panic!("malformed 256 escape: {esc:?}"));
    digits
        .parse()
        .unwrap_or_else(|_| panic!("bad index: {digits}"))
}

/// The TrueColor RGB the table renders for one theme/slot, parsed
/// from the real escape ("\x1b[38;2;R;G;B m").
fn table_rgb(theme: Theme, slot: Slot) -> (u8, u8, u8) {
    let esc = escape_for(theme, slot, false, ColorCapability::TrueColor);
    let body = esc
        .strip_prefix("\x1b[38;2;")
        .and_then(|s| s.strip_suffix('m'))
        .unwrap_or_else(|| panic!("malformed truecolor escape: {esc:?}"));
    let mut parts = body.split(';');
    let mut next = || -> u8 {
        parts
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("bad channel in {esc:?}"))
    };
    (next(), next(), next())
}

/// Every theme's brand and ok slots sit on a NEAREST cube cell of
/// their own TrueColor RGB (ties legal, carbon's documented tier
/// override the one exception — it carries its own pin below). This
/// is the computed core of the "high accuracy" contract: hue reads
/// true at 256 depth for all eleven palettes, machine-checked.
#[test]
fn brand_and_ok_sit_on_a_computed_nearest_cube_cell() {
    for theme in THEMES {
        for slot in [Slot::Brand, Slot::Ok] {
            if (theme, slot) == (Theme::Carbon, Slot::Brand) {
                continue; // the documented tier-hierarchy exception
            }
            let rgb = table_rgb(theme, slot);
            let idx = table_index(theme, slot);
            let (nearest_idx, min_dist) = nearest_cube(rgb);
            let table_dist = dist2(rgb, cube_rgb(idx));
            assert_eq!(
                table_dist, min_dist,
                "{theme:?}/{slot:?}: index {idx} sits at squared distance {table_dist} \
                 while cube cell {nearest_idx} is nearer at {min_dist} — the brand/ok \
                 hue-truth contract (BRANDING.md 2.2) is broken"
            );
        }
    }
}

/// Carbon's silver brand is the ONE deliberate non-nearest seat: the
/// metric-nearest cube cell 188 (215,215,215) would render the 256
/// tier DIMMER than the theme's own 16-color white fallback — a tier
/// hierarchy inversion (the boost-23 finding). The table rides the
/// cube's white corner 231 instead, the brightest cell the palette
/// offers, keeping the 256 tier at/above the 16 tier.
#[test]
fn carbon_brand_is_the_documented_tier_hierarchy_exception() {
    assert_eq!(table_index(Theme::Carbon, Slot::Brand), 231);
    // The rationale, pinned as behavior: the 16-color fallback IS
    // white, and 231 IS the cube's white corner.
    assert_eq!(
        escape_for(Theme::Carbon, Slot::Brand, false, ColorCapability::Color16),
        "\x1b[37m",
        "carbon's 16-color brand fallback is white — the hierarchy the 256 tier must not undercut"
    );
    assert_eq!(cube_rgb(231), (255, 255, 255));
    // And the honest arithmetic: the metric-nearest cell exists and
    // is nearer — the exception is real, not a nearest-match in
    // disguise.
    let (nearest_idx, nearest_dist) = nearest_cube(table_rgb(Theme::Carbon, Slot::Brand));
    assert_eq!(nearest_idx, 188);
    assert_eq!(nearest_dist, 3);
    assert!(dist2(table_rgb(Theme::Carbon, Slot::Brand), cube_rgb(231)) > nearest_dist);
}

/// The lts-9 correction itself, pinned against regression:
/// night_cyber's brand #00E5FF had ridden the pure-cyan corner 51
/// (0,255,255) at 676 squared error — 3.4x its true nearest cell 45
/// (0,215,255) at 196. The neon hue read oversaturated green-ward
/// on every 256-color terminal; it now reads true.
#[test]
fn night_cyber_brand_rides_its_true_cube_cell() {
    assert_eq!(table_index(Theme::NightCyber, Slot::Brand), 45);
    let rgb = table_rgb(Theme::NightCyber, Slot::Brand);
    assert_eq!(rgb, (0, 229, 255));
    assert_eq!(dist2(rgb, cube_rgb(45)), 196);
    // The retired corner is strictly farther (the regression shape:
    // 51 is the saturated corner, not the nearest cell).
    assert_eq!(dist2(rgb, cube_rgb(51)), 676);
}

/// The cube model itself is pinned against a mis-remembered palette:
/// the stair levels, the index encoding, and a known cell identity
/// (45 = (0,215,255), 231 = the white corner, 16 = black).
#[test]
fn cube_model_matches_the_xterm_palette() {
    assert_eq!(CUBE_LEVELS, [0, 95, 135, 175, 215, 255]);
    assert_eq!(cube_rgb(16), (0, 0, 0));
    assert_eq!(cube_rgb(45), (0, 215, 255));
    assert_eq!(cube_rgb(107), (135, 175, 95));
    assert_eq!(cube_rgb(231), (255, 255, 255));
    // The encoding is reversible: every cell's index rebuilds from
    // its levels.
    for idx in (16u16..=231).step_by(7) {
        let (r, g, b) = cube_rgb(idx as u8);
        let rebuilt = 16
            + 36 * CUBE_LEVELS.iter().position(|&l| l == r).unwrap()
            + 6 * CUBE_LEVELS.iter().position(|&l| l == g).unwrap()
            + CUBE_LEVELS.iter().position(|&l| l == b).unwrap();
        assert_eq!(
            rebuilt,
            usize::from(idx),
            "cell {idx} rebuilds from its levels"
        );
    }
}
