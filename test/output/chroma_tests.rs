// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Chroma dragon engine pins (NIGHT-improve-41): the OKLab
//! round-trip contract, the endpoint preservation, the polar
//! saturation law (the property the port EXISTS for), the
//! gray-endpoint Cartesian fallback, the lightness-scaling anchor
//! (hue preserved, L scaled — the perceptual dark anchor), and the
//! same-hue rail sweep's no-drift law (the eagle-eyes rails are one
//! brand hue at two lightnesses; the sweep must never leave that
//! hue).

use super::*;

/// The brand purple (netrunner's #A855F7) — the pin fixture every
/// rail-shaped law below sweeps, so the pins test the exact pair the
/// monitor renders.
const BRAND: (u8, u8, u8) = (168, 85, 247);

/// The srgb -> oklab -> srgb round-trip preserves the original
/// within ±1 unit per channel (cosmostrix's exhaustive-verified
/// contract, sampled on the 17-step grid; the ±1 floor is the final
/// f32 -> u8 rounding, not the math).
#[test]
fn round_trip_within_one_unit() {
    let mut max_err: i32 = 0;
    for r in (0..=255u8).step_by(17) {
        for g in (0..=255u8).step_by(17) {
            for b in (0..=255u8).step_by(17) {
                let (l, a, bb) = srgb_to_oklab(r, g, b);
                let (r2, g2, b2) = oklab_to_srgb(l, a, bb);
                let err = ((i32::from(r) - i32::from(r2)).abs())
                    .max((i32::from(g) - i32::from(g2)).abs())
                    .max((i32::from(b) - i32::from(b2)).abs());
                max_err = max_err.max(err);
            }
        }
    }
    assert!(
        max_err <= 1,
        "OKLab round-trip max channel error = {max_err}, expected <= 1"
    );
}

/// The brand purple's OKLab triple, pinned — a tripwire for the
/// conversion constants (any drift in the matrices moves this
/// triple; the round-trip test alone cannot catch a CONSISTENTLY
/// wrong pair of inverses).
#[test]
fn brand_purple_oklab_triple_is_pinned() {
    let (l, a, b) = srgb_to_oklab(BRAND.0, BRAND.1, BRAND.2);
    assert!((l - 0.6268).abs() < 5e-4, "L: {l}");
    assert!((a - 0.1297).abs() < 5e-4, "a: {a}");
    assert!((b - -0.1930).abs() < 5e-4, "b: {b}");
}

/// Endpoints are preserved exactly: t=0 and t=1 return the anchor
/// bytes themselves (the rail's anchors are the theme's own colors,
/// never re-derived through the space).
#[test]
fn blend_preserves_endpoints_exact() {
    let other = (10, 200, 60);
    assert_eq!(
        oklab_blend_rgb(BRAND.0, BRAND.1, BRAND.2, other.0, other.1, other.2, 0.0),
        BRAND
    );
    assert_eq!(
        oklab_blend_rgb(BRAND.0, BRAND.1, BRAND.2, other.0, other.1, other.2, 1.0),
        other
    );
    // t outside [0,1] clamps — a rail never extrapolates.
    assert_eq!(
        oklab_blend_rgb(BRAND.0, BRAND.1, BRAND.2, other.0, other.1, other.2, -3.0),
        BRAND
    );
    assert_eq!(
        oklab_blend_rgb(BRAND.0, BRAND.1, BRAND.2, other.0, other.1, other.2, 7.0),
        other
    );
}

/// The polar saturation law — the reason the chroma engine exists:
/// opposing-hue midpoints stay saturated where a Cartesian (a, b)
/// lerp collapses toward gray. Red->green and blue->yellow are the
/// canonical hue-crossing pairs (the saturation proxy max-min >= 60
/// catches any collapse; polar typically renders 140+).
#[test]
fn polar_midpoints_stay_saturated() {
    for (x, y) in [((255, 0, 0), (0, 255, 0)), ((0, 0, 255), (255, 255, 0))] {
        let m = oklab_blend_rgb(x.0, x.1, x.2, y.0, y.1, y.2, 0.5);
        let sat = i32::from(m.0.max(m.1).max(m.2)) - i32::from(m.0.min(m.1).min(m.2));
        assert!(
            sat >= 60,
            "polar midpoint of {x:?}->{y:?} is {m:?}, saturation {sat} < 60"
        );
    }
}

/// The gray-endpoint special case: blending toward a gray halves the
/// chroma magnitude (the Cartesian fallback lerps (a, b) directly),
/// and the L at the midpoint is the L-average — the gray midpoint IS
/// the visually correct answer, hue rotation from "no hue" is
/// meaningless.
#[test]
fn gray_endpoint_falls_back_cartesian() {
    let (l0, a0, b0) = srgb_to_oklab(BRAND.0, BRAND.1, BRAND.2);
    let gray = (128, 128, 128);
    let (lg, ag, bg) = srgb_to_oklab(gray.0, gray.1, gray.2);
    // The gray must really be near-gray in OKLab for the pin to mean
    // what it says.
    assert!((ag * ag + bg * bg).sqrt() < 1e-2, "fixture: {ag}, {bg}");
    let (a, b) = polar_chroma_lerp(a0, b0, ag, bg, 0.5);
    assert!((a - (a0 + ag) / 2.0).abs() < 1e-5, "a halved: {a}");
    assert!((b - (b0 + bg) / 2.0).abs() < 1e-5, "b halved: {b}");
    // And the blend's lightness is the linear L-average.
    let m = oklab_blend_rgb(BRAND.0, BRAND.1, BRAND.2, gray.0, gray.1, gray.2, 0.5);
    let (lm, _, _) = srgb_to_oklab(m.0, m.1, m.2);
    assert!((lm - (l0 + lg) / 2.0).abs() < 0.01, "L averaged: {lm}");
}

/// The lightness-scaling anchor: hue angle preserved (the same
/// atan2(b, a) — the gamut mapping reduces chroma, it never rotates
/// hue), L scaled by the factor, and the out-of-gamut case honestly
/// mapped: the brand at 42% L cannot carry its full chroma (the
/// green channel would clamp), so the anchor lands on the gamut
/// boundary at the pinned bytes (52, 0, 89) — the exact color the
/// TrueColor rails now render at their floor. factor 1.0 is the
/// identity (the in-gamut direct path).
#[test]
fn scale_lightness_preserves_hue_and_scales_l() {
    let (l, a, b) = srgb_to_oklab(BRAND.0, BRAND.1, BRAND.2);
    let anchor = scale_lightness(BRAND, 0.42);
    // The pinned anchor bytes — the gamut-mapped floor itself.
    assert_eq!(anchor, (52, 0, 89), "the perceptual anchor, exact");
    let (l2, a2, b2) = srgb_to_oklab(anchor.0, anchor.1, anchor.2);
    // Hue: re-derived from the quantized bytes, so a hair of u8
    // noise is honest — a real drift moves whole radians (the
    // per-channel clamp this port replaces moved it 0.1).
    let hue = b.atan2(a);
    let hue2 = b2.atan2(a2);
    assert!((hue - hue2).abs() < 0.02, "hue drift: {hue} -> {hue2}");
    // L scaled to 42% (the quantized bytes re-derive within 1%).
    assert!(
        (l2 - l * 0.42).abs() < 0.01,
        "L scaled: {l2} vs {}",
        l * 0.42
    );
    // Chroma reduced to the gamut boundary, not to mud: the anchor
    // keeps at least half the brand's chroma at 42% lightness.
    assert!(
        (a2 * a2 + b2 * b2).sqrt() / (a * a + b * b).sqrt() > 0.5,
        "chroma at the boundary: {}",
        (a2 * a2 + b2 * b2).sqrt()
    );
    // Identity: factor 1.0 round-trips within the ±1 floor.
    let same = scale_lightness(BRAND, 1.0);
    for (x, y) in [same.0, same.1, same.2]
        .iter()
        .zip([BRAND.0, BRAND.1, BRAND.2].iter())
    {
        assert!((i32::from(*x) - i32::from(*y)).abs() <= 1);
    }
}

/// The gamut mapping's own law: an out-of-gamut triple maps to the
/// boundary with hue and lightness held — a synthetic dark+chroma
/// purple (the anchor shape) keeps its hue where the per-channel
/// clamp would shift it, and an in-gamut triple rides the direct
/// path (byte-identical to the plain conversion).
#[test]
fn gamut_mapping_holds_hue_and_lightness() {
    // The raw 42%-L full-chroma brand is out of gamut (green < 0);
    // the mapped triple is in gamut by construction and holds L.
    let (l, a, b) = srgb_to_oklab(BRAND.0, BRAND.1, BRAND.2);
    let mapped = oklab_to_srgb_mapped(l * 0.42, a, b);
    let (lm, am, bm) = srgb_to_oklab(mapped.0, mapped.1, mapped.2);
    assert!((lm - l * 0.42).abs() < 0.01, "L held: {lm}");
    assert!(
        (bm.atan2(am) - b.atan2(a)).abs() < 0.02,
        "hue held: {} vs {}",
        bm.atan2(am),
        b.atan2(a)
    );
    // An in-gamut triple takes the direct path — byte-identical.
    assert_eq!(
        oklab_to_srgb_mapped(l, a, b),
        oklab_to_srgb(l, a, b),
        "in-gamut triples never search"
    );
    // The pure gray corner (chroma 0) maps at any lightness.
    let black = oklab_to_srgb_mapped(0.0, 0.0, 0.0);
    assert_eq!(black, (0, 0, 0));
    let white = oklab_to_srgb_mapped(1.0, 0.0, 0.0);
    assert_eq!(white, (255, 255, 255));
}

/// The rail sweep's no-drift law: blending the brand with its own
/// scaled-lightness anchor (the exact pair the eagle-eyes rails
/// interpolate) stays IN HUE at every t — the chroma magnitude
/// moves with the wave (the gamut mapping pulls it in near the
/// floor), the hue angle never leaves the brand's. Quantization
/// noise moves the re-derived angle a hair; the per-channel clamp
/// this port replaces moved it by 0.1 rad — the tolerance splits
/// that distance by an order of magnitude.
#[test]
fn same_hue_sweep_never_drifts_hue() {
    let anchor = scale_lightness(BRAND, 0.42);
    let (_, a0, b0) = srgb_to_oklab(BRAND.0, BRAND.1, BRAND.2);
    let hue = b0.atan2(a0);
    for i in 0..=20u8 {
        let t = f32::from(i) / 20.0;
        let c = oklab_blend_rgb(anchor.0, anchor.1, anchor.2, BRAND.0, BRAND.1, BRAND.2, t);
        let (_, a, b) = srgb_to_oklab(c.0, c.1, c.2);
        assert!(
            (b.atan2(a) - hue).abs() < 0.05,
            "t={t}: hue {} left the brand's {hue}",
            b.atan2(a)
        );
    }
}

/// The lightness ramp is monotone along the sweep — the wave's
/// dark->bright half climbs in OKLab L at every step (the perceptual
/// evenness the legacy gamma-domain anchor could not promise: its
/// 0.42-of-encoded-channels floor sat far darker than 42% lightness,
/// crowding the ramp's low end).
#[test]
fn rail_sweep_lightness_is_monotone() {
    let anchor = scale_lightness(BRAND, 0.42);
    let mut prev = f32::MIN;
    for i in 0..=24u8 {
        let t = f32::from(i) / 24.0;
        let c = oklab_blend_rgb(anchor.0, anchor.1, anchor.2, BRAND.0, BRAND.1, BRAND.2, t);
        let (l, _, _) = srgb_to_oklab(c.0, c.1, c.2);
        assert!(l >= prev - 5e-3, "step {i}: L {l} < prev {prev}");
        prev = l;
    }
}
