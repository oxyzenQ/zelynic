// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The monitor's opening frame (NIGHT-boost-25) — the prelude the
//! smooth open paints the moment the alt screen enters, so the BPF
//! load runs UNDER the product's chrome instead of after a frozen
//! blank screen.
//!
//! Composition (the live frame's own shapes, deliberately): the
//! eagle-eyes title bar, the breathing gap, one grey
//! `loading observer…` note, and the PINNED footer an empty session
//! renders — the same `build_grip_footer` census-of-nothing the
//! first live frame carries at t=0. The result is the one-row
//! morph: when the observer comes up, the first live frame rewrites
//! the note row (`loading observer…` becomes `waiting for
//! traffic…`) plus whatever traffic already exists; every other row
//! carries byte-identical content (the title bar, the pinned
//! footer), so the in-place rewrite lands the same glyphs — no
//! clear, no flash, no dead air, the masterclass loading the owner
//! asked for.
//!
//! Honesty decisions pinned by tests:
//! - the note says LOADING, not "waiting for traffic" — the observer
//!   is not up yet, and an idle-state message during load would be
//!   a lie (and would make the morph invisible);
//! - the census is the empty session's (no consumer headline, no
//!   limit suggestion — those need a champion the board does not
//!   have yet), with `identities_unresolved: false`: the identity
//!   walk has not RUN, which is not the same as having failed;
//! - the title is the plain `zelynic eagle-eyes` core — the target
//!   count a filtered frame carries is only known after the
//!   identity resolves, so the title row updates in the first live
//!   frame instead of guessing here.

use std::time::Duration;

use super::border;
use super::footer::{build_grip_footer, plan_footer_tier, FooterCensus};
use super::{title_bar, FrameGeometry};
use crate::output::grey;

/// Compose the opening frame: the chrome, the one honest note, and
/// the pinned empty-session footer, wrapped in the frame's rails —
/// exactly `geo.height` rows, like every live frame.
#[must_use]
pub(crate) fn loading_frame(interval: Duration, geo: FrameGeometry) -> Vec<String> {
    let full_width = geo.width;
    let geo = border::content_geo(geo);

    let mut lines = Vec::with_capacity(geo.height + 1);
    lines.push(title_bar("zelynic eagle-eyes", full_width));
    // The breathing gap (the live frame's top-chrome ladder — the
    // header never sat directly under the brand).
    lines.push(String::new());
    // The one honest note: loading, grey — subordinate information
    // like every footer census line, not a headline.
    lines.push(format!("  {}", grey("loading observer…")));

    // The pinned footer an empty session renders at t=0: the tier a
    // terminal of this height earns (extra=0 — see the honesty
    // decisions in the module docs) and the census of nothing. The
    // rows are byte-identical to the first live frame's footer, so
    // the morph never touches them. NIGHT-engrave-6: the speed pair
    // rides the census-of-nothing as honest zeroes (`0 B/s`, never
    // `BLOCKED` — the observer does not judge), and the sub-second
    // uptime the first live frame carries divides the zero legs to
    // the same zeroes — the morph contract holds with the new lines.
    let tier = plan_footer_tier(geo.height, 0);
    let census = FooterCensus {
        tier,
        grand: 0,
        dl: 0,
        ul: 0,
        peak_dl: 0,
        peak_ul: 0,
        packets: 0,
        cgroups: 0,
        top_proc_name: None,
        identities_unresolved: false,
        uptime: Duration::ZERO,
    };
    let footer = build_grip_footer(&census, geo, interval);

    // The pin: the footer lands at the bottom of the frame, blank
    // padding absorbing the middle — the same pin math the eagle
    // renderer applies.
    let footer_start = geo.height.saturating_sub(footer.len());
    while lines.len() < footer_start {
        lines.push(String::new());
    }
    lines.extend(footer);
    border::wrap(&mut lines, full_width);
    lines
}

// NIGHT-boost-25: the loading-frame pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// eagle and footer pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/loading_tests.rs"]
mod loading_tests;
