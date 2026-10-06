// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

// The OKLab matrix constants below are Ottosson's reference values
// verbatim — they exceed f32 precision ON PURPOSE: truncating them
// would shift the color space and break the round-trip guarantee
// (the same rationale cosmostrix carries in its own lint config,
// where this allowance lived file-local before going project-wide;
// zelynic keeps it file-local — this is the only file that does
// color-math constants).
#![allow(clippy::excessive_precision)]

//! The chroma dragon engine — zelynic's port (NIGHT-improve-41).
//!
//! Ported from the mature sibling (cosmostrix
//! `src/engine/chroma_dragon_engine/gradient/`, the OKLab polar core
//! that repo's v30 made its sole production gradient path): every
//! interpolation decision about what COLOR a cell becomes moves into
//! a perceptual color space, so the monitor's output colors render
//! at the quality the flagship terminal already enjoys.
//!
//! ## Why OKLab?
//!
//! The legacy rail ramp (NIGHT-boost-23) interpolates sRGB channels
//! in LINEAR LIGHT — gamma-correct, but still per-channel: when two
//! stops differ in hue, the straight RGB line cuts through the
//! cube's desaturated center and the midpoints muddy. OKLab (Björn
//! Ottosson, 2020, <https://bottosson.github.io/posts/oklab/>) is a
//! perceptual space built so Euclidean distance matches perceived
//! difference: interpolating there keeps midpoints clean and
//! lightness steps perceptually even — the ramp the eagle-eyes rails
//! sweep reads smooth instead of banded.
//!
//! ## Why polar?
//!
//! The (a, b) chroma axes can be lerped two ways. Cartesian (lerp a
//! and b) passes near (0, 0) = gray on opposing-hue pairs — the
//! canonical "shortcut through gray" failure. Polar lerps the chroma
//! magnitude `C = sqrt(a^2 + b^2)` and rotates the hue angle through
//! the shortest arc: midpoints stay saturated, and on same-hue pairs
//! (the rails' own shape — one brand hue, two lightnesses) the two
//! readings agree exactly. Polar never regresses against Cartesian;
//! it also matches the W3C CSS Color 4 default for `oklch`
//! interpolation (shortest-arc hue rotation).
//!
//! ## Chroma first, legacy fallback (the owner's contract)
//!
//! The engine is the PRIMARY path wherever the terminal can render
//! what it computes: TrueColor frames interpolate the rails in OKLab
//! polar space. A terminal that cannot represent truecolor falls
//! back to the LEGACY color math (NIGHT-boost-23's linear-light
//! ramp, quantized or flattened per depth) — the exact bytes those
//! depths rendered before this port, the same "chroma dragon first
//! -> fallback legacy rgb/srgb" ladder cosmostrix's detection carries
//! (`termdetect`: a truecolor-by-construction terminal keeps the
//! chroma engine active instead of silently degrading).
//!
//! ## Cost
//!
//! ~12 multiplies + 3 cbrt() per conversion, 2 conversions per rail
//! color (endpoints pre-derived per frame would save more, but the
//! rails render one blend per ROW at the 1s cadence — the frame duty
//! is unmoved; the A/B record in PERFORMANCE.md pins that).
//!
//! ## Gamut mapping (the port's own hardening)
//!
//! cosmostrix's conversion clamps per CHANNEL on the way out of
//! OKLab — a blend that exits the sRGB gamut gets each channel
//! clamped independently, and the clamped triple's HUE is not the
//! blended hue (the zelynic port's own pins caught it live: the
//! brand purple scaled to 42% lightness clamps the green channel
//! negative, and the anchor's hue shifts by 0.1 rad). This port
//! maps the gamut the CSS Color 4 way instead: when a triple is
//! out of gamut, its CHROMA is reduced — hue and lightness held
//! exactly — until it re-enters (a binary search on the chroma
//! scale; see [`oklab_to_srgb_mapped`]). The anchor law stays
//! perceptually honest: same hue, scaled lightness, as much chroma
//! as the gamut can carry at that lightness.
//!
//! ## Round-trip accuracy
//!
//! `srgb -> oklab -> srgb` round-trips within ±1 unit per channel
//! for all 16M sRGB values (cosmostrix's exhaustive verification);
//! the ±1 floor is the final `f32 -> u8` rounding, not the math. The
//! constants below are Ottosson's reference values verbatim — they
//! exceed f32 precision on purpose: truncating them would shift the
//! space and break the round-trip guarantee.

/// Convert an sRGB byte (0-255) to linear light (0.0-1.0), the exact
/// IEC 61966-2-1 transfer (the same decode the legacy ramp's
/// NIGHT-boost-23 carries — one transfer function, two spaces that
/// consume it).
#[inline]
fn srgb_to_linear(c: u8) -> f32 {
    let cs = f32::from(c) / 255.0;
    if cs <= 0.040_45 {
        cs / 12.92
    } else {
        ((cs + 0.055) / 1.055).powf(2.4)
    }
}

/// Convert linear light (0.0-1.0) to an sRGB byte (0-255), the
/// inverse transfer: rounded half-away at the u8 boundary and
/// clamped as LTS armor (anchors are in range by construction).
#[inline]
fn linear_to_srgb(c: f32) -> u8 {
    let cs = if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    };
    (cs * 255.0).round().clamp(0.0, 255.0) as u8
}

/// Convert linear-light sRGB to OKLab: `(L, a, b)` — L lightness
/// (0-1), a/b the chroma axes (roughly green-red and blue-yellow).
///
/// Reference: Björn Ottosson, "A perceptual color space for image
/// processing", 2020 — constants verbatim from the reference
/// implementation.
#[inline]
fn linear_to_oklab(r: f32, g: f32, b: f32) -> (f32, f32, f32) {
    let l = 0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b;
    let m = 0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b;
    let s = 0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b;

    let l_ = l.cbrt();
    let m_ = m.cbrt();
    let s_ = s.cbrt();

    (
        0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_,
        1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_,
        0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_,
    )
}

/// Convert OKLab back to linear-light sRGB (constants verbatim from
/// the reference implementation — the inverse of
/// [`linear_to_oklab`]).
#[inline]
fn oklab_to_linear(l: f32, a: f32, b: f32) -> (f32, f32, f32) {
    let l_ = l + 0.3963377774 * a + 0.2158037573 * b;
    let m_ = l - 0.1055613458 * a - 0.0638541728 * b;
    let s_ = l - 0.0894841775 * a - 1.2914855480 * b;

    let li = l_ * l_ * l_;
    let mi = m_ * m_ * m_;
    let si = s_ * s_ * s_;

    (
        4.0767416621 * li - 3.3077115913 * mi + 0.2309699292 * si,
        -1.2684380046 * li + 2.6097574011 * mi - 0.3413193965 * si,
        -0.0041960863 * li - 0.7034186147 * mi + 1.7076147010 * si,
    )
}

/// sRGB byte triple to OKLab.
#[inline]
pub(crate) fn srgb_to_oklab(r: u8, g: u8, b: u8) -> (f32, f32, f32) {
    linear_to_oklab(srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b))
}

/// OKLab to sRGB byte triple.
#[inline]
pub(crate) fn oklab_to_srgb(l: f32, a: f32, b: f32) -> (u8, u8, u8) {
    let (r, g, b) = oklab_to_linear(l, a, b);
    (linear_to_srgb(r), linear_to_srgb(g), linear_to_srgb(b))
}

/// Is the OKLab triple inside the sRGB gamut? The linear channels
/// must land in [0, 1] (a hair of epsilon for touches — the encode
/// clamps anyway, the epsilon only keeps boundary colors on the
/// direct path).
#[inline]
fn in_gamut(l: f32, a: f32, b: f32) -> bool {
    let (r, g, bl) = oklab_to_linear(l, a, b);
    const EPS: f32 = 1e-4;
    const GAMUT: std::ops::RangeInclusive<f32> = -EPS..=1.0 + EPS;
    GAMUT.contains(&r) && GAMUT.contains(&g) && GAMUT.contains(&bl)
}

/// OKLab to sRGB with HUE-PRESERVING gamut mapping: an in-gamut
/// triple converts directly (the round-trip identity path); an
/// out-of-gamut triple keeps its lightness and hue exactly while
/// its chroma is binary-searched down to the gamut boundary — the
/// CSS Color 4 `oklch` mapping discipline, and the port's own
/// hardening over the per-channel clamp (which shifts hue; see the
/// module docs). Called only when a blend or a lightness scaling
/// lands outside the gamut — the rails' anchors and sweeps on the
/// dark themes do, and the u8 encode's clamp would otherwise eat
/// the hue the engine exists to preserve.
pub(crate) fn oklab_to_srgb_mapped(l: f32, a: f32, b: f32) -> (u8, u8, u8) {
    if in_gamut(l, a, b) {
        return oklab_to_srgb(l, a, b);
    }
    let mut lo = 0.0f32; // chroma scale: in gamut (gray is always in)
    let mut hi = 1.0f32; // out of gamut (the caller's triple)
    for _ in 0..20 {
        let mid = (lo + hi) * 0.5;
        if in_gamut(l, a * mid, b * mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    oklab_to_srgb(l, a * lo, b * lo)
}

/// Polar (chroma + hue) interpolation between two OKLab (a, b)
/// chroma points: the chroma magnitude lerps linearly, the hue angle
/// rotates through the shortest arc — the midpoint stays saturated
/// on opposing-hue pairs where a Cartesian (a, b) lerp collapses
/// toward gray.
///
/// Gray-endpoint special case: if either side's chroma is ~0 the hue
/// is undefined, so the pair falls back to the Cartesian lerp — the
/// gray midpoint IS the visually correct answer when one endpoint
/// has no hue to rotate from.
#[inline]
pub(crate) fn polar_chroma_lerp(a0: f32, b0: f32, a1: f32, b1: f32, t: f32) -> (f32, f32) {
    let c0 = (a0 * a0 + b0 * b0).sqrt();
    let c1 = (a1 * a1 + b1 * b1).sqrt();

    if c0 < 1e-6 || c1 < 1e-6 {
        return (a0 + (a1 - a0) * t, b0 + (b1 - b0) * t);
    }

    // Hue angles in radians, in (-pi, pi]; the rotation takes the
    // shortest arc (the W3C oklch default).
    let h0 = b0.atan2(a0);
    let h1 = b1.atan2(a1);
    let mut delta = h1 - h0;
    if delta > std::f32::consts::PI {
        delta -= 2.0 * std::f32::consts::PI;
    } else if delta < -std::f32::consts::PI {
        delta += 2.0 * std::f32::consts::PI;
    }

    let c = c0 + (c1 - c0) * t;
    let h = h0 + delta * t;
    (c * h.cos(), c * h.sin())
}

/// Perceptual (OKLab polar) blend between two sRGB colors — the
/// chroma engine's rail API (NIGHT-improve-41): lightness lerps
/// linearly, chroma rides [`polar_chroma_lerp`], and the endpoints
/// are preserved exactly (`t` clamped to [0, 1] — a rail never
/// extrapolates past its anchors). The return trip rides
/// [`oklab_to_srgb_mapped`]: a sweep that bows out of the sRGB
/// gamut keeps its hue (chroma reduced, never channel-clamped).
#[inline]
#[must_use]
pub(crate) fn oklab_blend_rgb(
    r0: u8,
    g0: u8,
    b0: u8,
    r1: u8,
    g1: u8,
    b1: u8,
    t: f32,
) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    let (l0, a0, b0) = srgb_to_oklab(r0, g0, b0);
    let (l1, a1, b1) = srgb_to_oklab(r1, g1, b1);
    let l = l0 + (l1 - l0) * t;
    let (a, b) = polar_chroma_lerp(a0, b0, a1, b1, t);
    oklab_to_srgb_mapped(l, a, b)
}

/// Scale one color's OKLab LIGHTNESS by `factor`, hue preserved
/// exactly — the perceptually uniform dark anchor (the chroma
/// path's ramp floor). The legacy anchor multiplied the ENCODED
/// channels (0.42 in gamma space reads far darker than 42%
/// lightness); the chroma anchor reads the factor in the lightness
/// domain, so "42%" means what the eye sees: the same hue at 42%
/// perceived brightness. When the scaled triple leaves the sRGB
/// gamut (a dark purple cannot carry its full chroma — the green
/// channel would go negative), [`oklab_to_srgb_mapped`] reduces
/// the chroma to the boundary instead of letting the u8 clamp
/// shift the hue: the anchor stays the brand's hue with as much
/// saturation as 42% lightness can honestly carry.
#[inline]
#[must_use]
pub(crate) fn scale_lightness(rgb: (u8, u8, u8), factor: f32) -> (u8, u8, u8) {
    let (l, a, b) = srgb_to_oklab(rgb.0, rgb.1, rgb.2);
    oklab_to_srgb_mapped(l * factor, a, b)
}

// NIGHT-improve-41: the chroma pins live under the single test/
// tree (cosmostrix Pattern C), #[path]-wired across trees exactly
// like the color and theme pins.
#[cfg(test)]
#[path = "../../test/output/chroma_tests.rs"]
mod chroma_tests;
