// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The swept-run composer (NIGHT-engrave-11's horizontal chroma
//! engine) — split from border.rs by the NIGHT-improve-44 LOC law (a
//! pure move, gates green in between): `sweep_run` and the memo that
//! makes the per-column chroma work pay once per shape. The wave
//! math and the rails' color derivation stay in [`super::border`];
//! this module runs the SAME method ACROSS the columns — the title
//! bar, the grid lines, the closing floor, and the rails' own
//! closing row all speak through here.

use super::border::{DARK_FACTOR, from_linear, to_linear, wave};
use crate::output::ColorCapability;
use crate::output::theme::Theme;
use std::collections::HashMap;
use std::sync::Mutex;

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

// night-improve-64: the sweep pins moved with the composer (the
// border_tests split the NIGHT-improve-44 LOC law drove).
#[cfg(test)]
#[path = "../../../test/ebpf/render/sweep_tests.rs"]
mod sweep_tests;
