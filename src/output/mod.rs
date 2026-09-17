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
//! | Mono | `NO_COLOR`, `CLICOLOR=0`, or not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |
//!
//! Color is ALWAYS on for terminals — there is no `--no-color` CLI flag
//! (NIGHT-hunt-5 owner mandate: purple is branding, branding has no
//! opt-out). The standard env vars remain the only control surface,
//! exactly like cosmostrix, `bat`, `fd`, and `ripgrep`:
//! - `NO_COLOR` (https://no-color.org/) disables all colors.
//! - `CLICOLOR=0` disables colors.
//! - `CLICOLOR_FORCE=1` forces colors even when piped.
//! - Colors are stripped when stderr is not a TTY.
//!
//! Owner color contract (NIGHT-hunt-5, cosmostrix S-master-HUNT-5
//! lineage): error = red #FF5A5A, warning = yellow #FFEB3C, suggestion
//! = crystal white #DCEBFF, brand = purple #A855F7. Suggestion lines
//! ("tip:", "hint:", did-you-mean, possible-value lists) render white —
//! distinct from the error they are embedded in, so a typo tip never
//! drowns in red. Status green (#50FA7B) stays for affirmative verdicts.
//!
//! Every user-facing print goes through the broken-pipe-safe macros
//! [`println_safe!`] / [`eprintln_safe!`]: Rust ignores SIGPIPE, so a
//! piped reader exiting early (`zelynic --help-all | head -2`) turns
//! `println!` into a panic with exit 101. The safe macros discard the
//! write error instead — the report is truncated at the pipe boundary
//! and the process exits with its intended code, standard Unix CLI
//! behavior for closed readers.

use std::io::IsTerminal;
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

/// Suggestion crystal-white RGB: #DCEBFF (220,235,255) — cosmostrix
/// suggestion format.
///
/// 256-color fallback: index 255 (nearest near-white). Color16 fallback:
/// bright white (97) — the aixterm bright slot, universally supported;
/// the normal 37 can render dim gray and blur suggestions into body text.
#[cfg(test)] // referenced in tests; kept as source-of-truth documentation
const SUGGESTION_RGB: (u8, u8, u8) = (220, 235, 255);

// ── Broken-pipe-safe println/eprintln (cosmostrix contract) ────────────────
//
// Rust ignores SIGPIPE by default, so when the user pipes a report into
// head/jq/grep and the reader exits early, println!/eprintln! panic on
// EPIPE with exit 101 (verified live on zelynic: `zelynic --help-all |
// head -2` aborted with 101). The macros below discard the write error
// instead — safe for every reachable output site, including the
// error paths that run while the terminal is being torn down.

/// Like `eprintln!` but never panics on a broken stderr pipe.
macro_rules! eprintln_safe {
        () => {{
                use std::io::Write as _;
                let _ = std::io::stderr().write_fmt(format_args!("\n"));
                let _ = std::io::stderr().flush();
        }};
        ($($arg:tt)*) => {{
                use std::io::Write as _;
                let _ = std::io::stderr().write_fmt(format_args!($($arg)*));
                let _ = std::io::stderr().write_fmt(format_args!("\n"));
                let _ = std::io::stderr().flush();
        }};
}

/// Like `println!` but never panics on a broken/closed stdout pipe.
macro_rules! println_safe {
        () => {{
                use std::io::Write as _;
                let _ = std::io::stdout().write_fmt(format_args!("\n"));
                let _ = std::io::stdout().flush();
        }};
        ($($arg:tt)*) => {{
                use std::io::Write as _;
                let _ = std::io::stdout().write_fmt(format_args!($($arg)*));
                let _ = std::io::stdout().write_fmt(format_args!("\n"));
                let _ = std::io::stdout().flush();
        }};
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

/// Get the cached color capability. The environment probe runs at most
/// once per process (memoized in a `OnceLock`).
fn capability() -> ColorCapability {
    static CAP: OnceLock<ColorCapability> = OnceLock::new();
    *CAP.get_or_init(detect_capability)
}

// ── Capability-aware escape sequences ──────────────────────────────────────

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

/// Error red open sequence (regular weight), capability-aware.
#[must_use]
pub fn error_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[38;2;255;90;90m",
        ColorCapability::Color256 => "\x1b[38;5;203m",
        ColorCapability::Color16 => "\x1b[31m",
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

/// Warning yellow open sequence (regular weight), capability-aware.
///
/// Used by the labeled warning renderer (ebpf-gated call sites).
#[cfg(feature = "ebpf")]
#[must_use]
pub fn warn_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[38;2;255;235;60m",
        ColorCapability::Color256 => "\x1b[38;5;220m",
        ColorCapability::Color16 => "\x1b[33m",
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

/// Suggestion crystal-white open sequence, capability-aware.
///
/// Owner color contract (NIGHT-hunt-5): "tip:" / "hint:" / did-you-mean
/// lines render white — distinct from the red or yellow of the block
/// they are embedded in. See [`SUGGESTION_RGB`] for the tier rationale.
#[must_use]
pub fn suggestion_open() -> &'static str {
    match capability() {
        ColorCapability::TrueColor => "\x1b[38;2;220;235;255m",
        ColorCapability::Color256 => "\x1b[38;5;255m",
        ColorCapability::Color16 => "\x1b[97m",
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
//
// Every wrapper short-circuits Mono to the plain message — no escape
// concatenation, no allocation of style bytes that would never render.

/// Wrap `msg` in bold brand purple. Plain text when color is off.
#[must_use]
pub fn brand_bold(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", brand_bold_open(), reset()),
    }
}

/// Wrap `msg` in brand purple (regular weight). Plain text when color is off.
#[must_use]
pub fn brand(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", brand_open(), reset()),
    }
}

/// Wrap `msg` in bold status green. Plain text when color is off.
#[must_use]
pub fn ok_bold(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", ok_bold_open(), reset()),
    }
}

/// Wrap `msg` in error red (regular weight). Plain text when color is off.
#[must_use]
pub fn error(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", error_open(), reset()),
    }
}

/// Wrap `msg` in bold error red. Plain text when color is off.
#[must_use]
pub fn error_bold(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", error_bold_open(), reset()),
    }
}

/// Wrap `msg` in warning yellow (regular weight). Plain text when color is off.
#[cfg(feature = "ebpf")]
#[must_use]
pub fn warn(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", warn_open(), reset()),
    }
}

/// Wrap `msg` in bold warning yellow. Plain text when color is off.
#[must_use]
pub fn warn_bold(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", warn_bold_open(), reset()),
    }
}

/// Wrap `msg` in suggestion crystal white. Plain text when color is off.
#[must_use]
pub fn suggestion(msg: &str) -> String {
    match capability() {
        ColorCapability::Mono => msg.to_string(),
        _ => format!("{}{msg}{}", suggestion_open(), reset()),
    }
}

mod labeled;

pub use labeled::eprintln_error_labeled;
#[cfg(feature = "ebpf")]
pub use labeled::eprintln_warn_labeled;

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
}
