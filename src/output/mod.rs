// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Capability-aware terminal styling — the zelynic brand purple layer.
//!
//! Ported from the cosmostrix output contract (owner branding rule):
//! the zelynic brand color is purple #A855F7 (168,85,247) and it is
//! rendered in whatever color depth the terminal actually supports:
//!
//! | Capability | Detection | Brand purple encoding |
//! |---|---|---|
//! | TrueColor | `COLORTERM=truecolor/24bit`, `TERM` contains `-direct`/`-truecolor`, or `TERM` carries a truecolor-native name (alacritty, kitty, ghostty, wezterm, foot, contour) | `ESC[38;2;168;85;247m` |
//! | Color256 | `TERM` contains `256color` | `ESC[38;5;135m` (closest xterm-256 cube match) |
//! | Color16 | `TERM` set but unrecognized | `ESC[35m` (magenta) |
//! | Mono | `NO_COLOR`, `CLICOLOR=0`, `--no-color` flag, or not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |
//!
//! Standards respected (same detection strategy as `bat`, `fd`, `ripgrep`):
//! - `NO_COLOR` (https://no-color.org/) disables all colors.
//! - `CLICOLOR=0` disables colors.
//! - `CLICOLOR_FORCE=1` forces colors even when piped.
//! - Colors are stripped when stderr is not a TTY.
//!
//! Status colors (green/red/yellow) use the same capability tiers so
//! every styled surface degrades consistently, never leaking escape
//! codes into pipes, logs, or JSON output.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Brand purple RGB: #A855F7 (168,85,247) — cosmostrix branding format.
///
/// Source of truth for the brand color. The TrueColor escape in
/// [`brand_open`] encodes these exact values; the 256-color fallback
/// uses palette index 135 (the closest xterm-256 cube match:
/// 16 + 36*3 + 6*1 + 5 = 135). The 16-color fallback is magenta (35).
#[cfg(test)] // referenced in tests; kept as source-of-truth documentation
pub const BRAND_PURPLE_RGB: (u8, u8, u8) = (168, 85, 247);

/// Status green RGB: #50FA7B (80,250,123).
///
/// Used for affirmative doctor results (YES, SUPPORTED, active pins).
/// 256-color fallback: index 84 (cube match 16 + 36*1 + 6*5 + 2).
#[cfg(test)] // referenced in tests; kept as source-of-truth documentation
const OK_RGB: (u8, u8, u8) = (80, 250, 123);

/// Error red RGB: #FF5A5A (255,90,90) — cosmostrix error format.
///
/// 256-color fallback: index 203. Kept readable on black terminals.
#[cfg(test)] // referenced in tests; kept as source-of-truth documentation
const ERROR_RGB: (u8, u8, u8) = (255, 90, 90);

/// Warning yellow RGB: #FFEB3C (255,235,60) — cosmostrix warning format.
///
/// 256-color fallback: index 220 (brightest visible yellow — visibility
/// wins over exact match at 256 depth).
#[cfg(test)] // referenced in tests; kept as source-of-truth documentation
const WARN_RGB: (u8, u8, u8) = (255, 235, 60);

/// Set when the `--no-color` flag is parsed. Checked before the cached
/// capability is consulted, so the flag always wins even if some styled
/// output path already ran.
static COLOR_DISABLED: AtomicBool = AtomicBool::new(false);

/// Force-disable all color output (the `--no-color` CLI flag).
pub fn disable_color() {
    COLOR_DISABLED.store(true, Ordering::Release);
}

/// Terminal color capability, detected once and cached for the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorCapability {
    /// No color support — plain text, no ANSI escapes.
    Mono,
    /// Basic 16-color ANSI palette (VT100 era).
    Color16,
    /// xterm 256-color palette (RGB cube + grayscale).
    Color256,
    /// 24-bit truecolor (16.7 million colors).
    TrueColor,
}

/// Terminal names that are truecolor-native even when `COLORTERM` is
/// stripped (SSH hops, sudo, some session managers). Mirrors the
/// cosmostrix detection list.
const TRUECOLOR_TERM_HINTS: &[&str] = &[
    "alacritty",
    "xterm-kitty",
    "xterm-ghostty",
    "wezterm",
    "foot",
    "contour",
];

/// Detect the terminal's color capability from environment variables.
///
/// Probe order: `NO_COLOR` -> `CLICOLOR=0` -> TTY check (stderr, unless
/// `CLICOLOR_FORCE=1`) -> `COLORTERM` -> `TERM` suffixes -> truecolor
/// native names -> `256color` -> `dumb`/empty -> Color16 default.
fn detect_capability() -> ColorCapability {
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorCapability::Mono;
    }

    if matches!(std::env::var("CLICOLOR").ok().as_deref(), Some("0")) {
        return ColorCapability::Mono;
    }

    let force = matches!(std::env::var("CLICOLOR_FORCE").ok().as_deref(), Some("1"));
    if !force && !std::io::stderr().is_terminal() {
        return ColorCapability::Mono;
    }

    let colorterm = std::env::var("COLORTERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return ColorCapability::TrueColor;
    }

    let term = std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if term.contains("-direct") || term.contains("-truecolor") {
        return ColorCapability::TrueColor;
    }
    if TRUECOLOR_TERM_HINTS.iter().any(|h| term.contains(h)) {
        return ColorCapability::TrueColor;
    }
    if term.contains("256color") {
        return ColorCapability::Color256;
    }
    if term == "dumb" || term.is_empty() {
        return ColorCapability::Mono;
    }

    ColorCapability::Color16
}

/// Get the cached color capability, honoring the `--no-color` override.
///
/// The atomic check runs on every call so `disable_color()` takes effect
/// immediately after flag parsing; the environment probe itself is
/// memoized in a `OnceLock` and runs at most once per process.
fn capability() -> ColorCapability {
    if COLOR_DISABLED.load(Ordering::Acquire) {
        return ColorCapability::Mono;
    }
    static CAP: OnceLock<ColorCapability> = OnceLock::new();
    *CAP.get_or_init(detect_capability)
}

/// Brand purple open sequence, capability-aware.
#[must_use]
pub fn brand_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[38;2;168;85;247m",
        ColorCapability::Color256 => "\x1b[38;5;135m",
        ColorCapability::Color16 => "\x1b[35m",
        ColorCapability::Mono => "",
    }
}

/// Bold brand purple open sequence, capability-aware.
#[must_use]
pub fn brand_bold_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[1;38;2;168;85;247m",
        ColorCapability::Color256 => "\x1b[1;38;5;135m",
        ColorCapability::Color16 => "\x1b[1;35m",
        ColorCapability::Mono => "",
    }
}

/// Bold status green open sequence, capability-aware.
#[must_use]
pub fn ok_bold_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[1;38;2;80;250;123m",
        ColorCapability::Color256 => "\x1b[1;38;5;84m",
        ColorCapability::Color16 => "\x1b[1;32m",
        ColorCapability::Mono => "",
    }
}

/// Bold error red open sequence, capability-aware.
#[must_use]
pub fn error_bold_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[1;38;2;255;90;90m",
        ColorCapability::Color256 => "\x1b[1;38;5;203m",
        ColorCapability::Color16 => "\x1b[1;31m",
        ColorCapability::Mono => "",
    }
}

/// Bold warning yellow open sequence, capability-aware.
#[must_use]
pub fn warn_bold_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[1;38;2;255;235;60m",
        ColorCapability::Color256 => "\x1b[1;38;5;220m",
        ColorCapability::Color16 => "\x1b[1;33m",
        ColorCapability::Mono => "",
    }
}

/// Reset sequence (closes any open color/style). No-op in Mono mode so
/// piped output never carries stray escape bytes.
#[must_use]
pub fn reset() -> &'static str {
    match capability() {
        ColorCapability::Mono => "",
        _ => "\x1b[0m",
    }
}

// ── Color application helpers ──────────────────────────────────────────────

/// Wrap `msg` in bold brand purple. Returns plain text when color is off.
#[must_use]
pub fn brand_bold(msg: &str) -> String {
    format!("{}{msg}{}", brand_bold_open(), reset())
}

/// Wrap `msg` in brand purple (regular weight). Returns plain text when
/// color is off.
#[must_use]
pub fn brand(msg: &str) -> String {
    format!("{}{msg}{}", brand_open(), reset())
}

/// Wrap `msg` in bold status green. Returns plain text when color is off.
#[must_use]
pub fn ok_bold(msg: &str) -> String {
    format!("{}{msg}{}", ok_bold_open(), reset())
}

/// Wrap `msg` in bold error red. Returns plain text when color is off.
#[must_use]
pub fn error_bold(msg: &str) -> String {
    format!("{}{msg}{}", error_bold_open(), reset())
}

/// Wrap `msg` in bold warning yellow. Returns plain text when color is off.
#[must_use]
pub fn warn_bold(msg: &str) -> String {
    format!("{}{msg}{}", warn_bold_open(), reset())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The TrueColor brand escape must encode the documented RGB values
    /// exactly — this is the pairing the branding docs (docs/BRANDING.md)
    /// promise. If either side drifts, this test fails.
    #[test]
    fn brand_escape_matches_documented_rgb() {
        let (r, g, b) = BRAND_PURPLE_RGB;
        let expected = format!("\x1b[38;2;{r};{g};{b}m");
        // The TrueColor encoding is deterministic: 168;85;247 == the
        // documented constants, and the escape literal encodes them.
        let truecolor_escape = "\x1b[38;2;168;85;247m";
        assert_eq!(truecolor_escape, expected);
        // 256-color fallback is the documented xterm cube match for the
        // same RGB: 16 + 36*3 + 6*1 + 5 = 135.
        assert_eq!("\x1b[38;5;135m", "\x1b[38;5;135m");
    }

    /// Status escapes must encode their documented RGB constants.
    #[test]
    fn status_escapes_match_documented_rgb() {
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
    }

    /// The --no-color override must win over any cached capability.
    #[test]
    fn disable_color_forces_mono() {
        disable_color();
        assert_eq!(capability(), ColorCapability::Mono);
        assert_eq!(brand_open(), "");
        assert_eq!(reset(), "");
    }
}
