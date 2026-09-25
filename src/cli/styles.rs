// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Clap brand styling (cosmostrix contract, NIGHT-hunt-5) — the one
//! place clap's rendered surfaces (usage lines, errors the bridge
//! does not intercept) pick up the brand palette.
//!
//! Purple brand identity: section headings (Usage, Commands, Options)
//! render in bold truecolor purple #A855F7 — the same RGB as the
//! [`crate::output`] brand layer, so every purple element in --help,
//! -V, and errors uses the exact same value. Literals render bold;
//! placeholders stay in the terminal default color.
//!
//! Style harmony (owner mandate): clap's default styles leave error
//! labels plain red and tip/suggestion lines GREEN — hues that disagree
//! with the branded error path (error red #FF5A5A, suggestion white
//! #DCEBFF, warn yellow #FFEB3C). These entries align clap's error
//! rendering with the output-layer semantic palette so both surfaces
//! (clap-rendered and ux-rendered) look identical.
//!
//! Split out of cli/mod.rs by NIGHT-master-1 when the depth surface's
//! docs pushed the CLI definition past the 500-line cap — same theme,
//! one concern, re-exported so the `#[command(styles = ...)]`
//! attribute resolves unchanged.

use clap::builder::styling::{Color, Effects, RgbColor, Style};
use clap::builder::Styles;

#[must_use]
pub(crate) fn clap_styles() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .usage(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .literal(Style::new().effects(Effects::BOLD))
        .placeholder(Style::new())
        .error(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(255, 90, 90)))),
        )
        .valid(Style::new().fg_color(Some(Color::Rgb(RgbColor(220, 235, 255)))))
        .invalid(Style::new().fg_color(Some(Color::Rgb(RgbColor(255, 235, 60)))))
}
