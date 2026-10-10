// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The one-color-law pins (NIGHT-improve-73): the clap error surface
//! renders through the same capability ladder every other surface
//! answers to, and the forced 16-color rung carries the palette
//! mapping. Lives under the single test/ tree (cosmostrix Pattern C)
//! and is #[path]-wired from src/cli/ux.rs, so `super::` reaches the
//! bridge harness exactly like the sibling test modules do.

use super::*;

// ── The one-color-law contract (NIGHT-improve-73) ──────────────────

/// The owner's live repro: `--color-mode 0 ss brave 100kb` died on
/// clap's InvalidSubcommand path, which used to bypass the capability
/// ladder (clap's private auto probe kept the colored half colored
/// while the ux-rendered half went plain). The bridge now owns the
/// bytes: in the Mono lane the whole render — clap render plus
/// footer — is plain text with zero escape bytes, matching the
/// ux-rendered half of the same terminal.
#[test]
fn mono_lane_render_carries_zero_escape_bytes() {
    // Both --color-mode forms ride a failing parse (the typo'd 'ss'
    // subcommand): the bridge must render plain in the Mono lane. The
    // valid-spelling line (`s brave 100kb`) parses fine and dies at
    // the runtime root check instead — that half of the owner's repro
    // is the labeled renderer's Mono lane, covered by the plain-text
    // pins in the labeled and color modules.
    for argv in [
        vec!["zelynic", "-v", "--color-mode", "0", "ss", "brave", "100kb"],
        vec!["zelynic", "-v", "--color-mode=0", "ss", "brave", "100kb"],
    ] {
        let rendered = render_via_bridge(&argv);
        assert!(
            !rendered.contains('\x1b'),
            "the mono lane must carry no escape bytes for {argv:?}, got:\n{rendered}"
        );
    }
}

/// The 16-color rung of the clap brand styles encodes the documented
/// palette slots (NIGHT-improve-73): brand purple falls to magenta,
/// error red to bold red, the valid grey to bright black, the invalid
/// yellow to yellow — the same slots the output layer's Color16
/// fallbacks pick, so a forced 16-color terminal never receives RGB
/// bytes from the clap render.
#[test]
fn clap_styles_16_maps_the_documented_palette_slots() {
    use clap::builder::styling::{AnsiColor, Color, Effects, Style};
    let styles = crate::cli::clap_styles_16();
    assert_eq!(
        styles.get_error(),
        &Style::new()
            .effects(Effects::BOLD)
            .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        "error must be bold ANSI red at the 16 rung"
    );
    assert_eq!(
        styles.get_valid(),
        &Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack))),
        "valid must be ANSI bright black (the honest grey) at the 16 rung"
    );
    assert_eq!(
        styles.get_invalid(),
        &Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        "invalid must be ANSI yellow at the 16 rung"
    );
    assert_eq!(
        styles.get_header(),
        &Style::new()
            .effects(Effects::BOLD)
            .fg_color(Some(Color::Ansi(AnsiColor::Magenta))),
        "the brand slot must be bold ANSI magenta at the 16 rung"
    );
}
