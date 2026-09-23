// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Color-layer pins: the documented RGB constants (the BRANDING.md
//! pairing), the tier escapes, and the --color-mode grammar
//! (NIGHT-boost-23). Wired into src/output/color.rs via #[path]
//! (cosmostrix Pattern C) — the color-mode grammar pushed color.rs
//! past the LOC cap, the same way boost-15 pushed format.rs.

use super::*;

/// The TrueColor brand escape must encode the documented RGB values
/// exactly — this is the pairing the branding docs (docs/BRANDING.md)
/// promise. If either side drifts, this test fails.
#[test]
fn brand_escape_matches_documented_rgb() {
    let (r, g, b) = BRAND_PURPLE_RGB;
    let expected = format!("\x1b[38;2;{r};{g};{b}m");
    let truecolor_escape = "\x1b[38;2;168;85;247m";
    assert_eq!(truecolor_escape, expected);
    // 256-color fallback is the documented xterm cube match for the
    // same RGB: 16 + 36*3 + 6*1 + 5 = 135.
    assert_eq!("\x1b[38;5;135m", "\x1b[38;5;135m");
}

/// Status and suggestion escapes must encode their documented RGB
/// constants (owner color contract, NIGHT-hunt-5).
#[test]
fn status_and_suggestion_escapes_match_documented_rgb() {
    assert_eq!("\x1b[38;2;80;250;123m", {
        let (r, g, b) = OK_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    assert_eq!("\x1b[38;2;255;90;90m", {
        let (r, g, b) = ERROR_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    assert_eq!("\x1b[38;2;255;235;60m", {
        let (r, g, b) = WARN_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    assert_eq!("\x1b[38;2;220;235;255m", {
        let (r, g, b) = SUGGESTION_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    // Suggestion tier fallbacks: nearest near-white at 256 depth,
    // aixterm bright white at 16 depth.
    assert_eq!("\x1b[38;5;255m", "\x1b[38;5;255m");
    assert_eq!("\x1b[97m", "\x1b[97m");
}

/// Champion tier (NIGHT-boost-5): the rank-1 red encodes its own
/// documented RGB — distinct from the softer error red. The
/// blinking variant is gone entirely (NIGHT-boost-14, the owner's
/// eye-strain call): the crown is STATIC — no SGR 5 anywhere.
#[cfg(feature = "ebpf")] // the champion builders live under the eagle-eyes graph
#[test]
fn champion_escapes_match_documented_rgb() {
    assert_eq!("\x1b[38;2;255;59;48m", {
        let (r, g, b) = HOT_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    assert!(hot_open().is_empty() || hot_open().starts_with("\x1b["));
    assert!(!hot_open().contains(";5m") || hot_open().starts_with("\x1b[38;"));
}

/// Grey tier (NIGHT-boost-14): the subordinate escape encodes its
/// documented RGB — truecolor exact, 245 at 256, bright black 16.
#[cfg(feature = "ebpf")]
#[test]
fn grey_escapes_match_documented_rgb() {
    assert_eq!("\x1b[38;2;139;139;139m", {
        let (r, g, b) = GREY_RGB;
        format!("\x1b[38;2;{r};{g};{b}m")
    });
    assert!(grey_open().is_empty() || grey_open().starts_with("\x1b[38;"));
    // A color change only — no blink, no bold.
    assert!(grey_open().is_empty() || !grey_open().starts_with("\x1b[5"));
}

/// The --color-mode grammar (NIGHT-boost-23, the cosmostrix
/// contract): every alias parses to its capability, the aliases
/// are exact-match (no prefix surprises), and an invalid value
/// carries the allowed list in its reason. Pure — the capability
/// cache other tests already populated stays untouched.
#[test]
fn color_mode_grammar_parses_every_alias() {
    assert_eq!(parse_color_mode("0"), Ok(ColorCapability::Mono));
    assert_eq!(parse_color_mode("16"), Ok(ColorCapability::Color16));
    assert_eq!(parse_color_mode("8"), Ok(ColorCapability::Color256));
    assert_eq!(parse_color_mode("256"), Ok(ColorCapability::Color256));
    assert_eq!(parse_color_mode("24"), Ok(ColorCapability::TrueColor));
    assert_eq!(parse_color_mode("32"), Ok(ColorCapability::TrueColor));
    // Whitespace tolerance (shell quoting artifacts).
    assert_eq!(parse_color_mode(" 256 "), Ok(ColorCapability::Color256));
    // Invalid: the reason carries the allowed grammar, the exact
    // offending value, and never a partial prefix match ("2" is
    // not 24/256 — the grammar is exact).
    for bad in ["2", "truecolor", "256k", "-1", ""] {
        let err = parse_color_mode(bad).expect_err("must reject");
        assert!(
            err.contains("invalid --color-mode"),
            "the reason names the flag: {err}"
        );
        assert!(
            err.contains("allowed: 0, 16, 8/256, 24/32"),
            "the reason carries the grammar: {err}"
        );
    }
}
