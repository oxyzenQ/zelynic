// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI UX contract — the single authority for user-facing CLI errors,
//! tips, usage lines, and the help footer (cosmostrix `cli/ux.rs`
//! lineage, ported in NIGHT-hunt-5).
//!
//! Exit-code contract: clap usage errors exit 2 (clap's usage code);
//! runtime failures exit 1 via the anyhow path in `main()`. Every
//! fatal CLI path renders through this module so all layers end
//! identically.
//!
//! Rendering: clap errors are re-rendered with the command's brand
//! styles (purple headers/usage, red error label, white `valid` tips —
//! see [`crate::cli::clap_styles`]); rate/duration value suggestions
//! are appended as canonical `tip:` lines which the line-aware
//! [`crate::output::eprintln_error_labeled`] paints white. The
//! closest-match machinery lives in `cli/suggestion.rs`.

use clap::error::{ContextKind, ContextValue};
use clap::CommandFactory;

use super::suggestion::closest_long_flag_ci;
#[cfg(feature = "ebpf")]
use super::suggestion::closest_value_match;
use crate::cli::Cli;

/// Help footer matching clap's canonical wording, appended to every
/// fatal CLI error so all layers end identically.
const HELP_FOOTER: &str = "For more information, try '--help'.";

// ── Clap error bridge ──────────────────────────────────────────────────────

/// Case-insensitive flag-suggestion fallback for clap UnknownArgument
/// errors.
///
/// When an unknown LONG flag carries no SuggestedArg context, this
/// injects the best case-insensitive match as clap's OWN
/// `SuggestedArg` context, so the tip renders in clap's canonical
/// position and `valid` (white) style — no custom printing, no second
/// tip, no render surgery.
///
/// No-op for: every non-UnknownArgument error kind, errors that
/// already carry a suggestion (clap's tip is never duplicated), and
/// dashes-only inputs (short flags — Jaro of a single char never
/// clears 0.7, matching clap's own silence).
fn enrich_unknown_arg_suggestion(e: &mut clap::Error, cmd: &clap::builder::Command) {
    if e.kind() != clap::error::ErrorKind::UnknownArgument {
        return;
    }
    if e.get(ContextKind::SuggestedArg).is_some() {
        return;
    }
    // The typed flag lives in the InvalidArg context ("--VERBOS");
    // strip the dashes so bare flag names compare against bare names.
    let typed = match e.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(s)) => s.trim_start_matches('-').to_string(),
        _ => return,
    };
    if typed.is_empty() {
        return;
    }
    let candidates: Vec<&str> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter_map(|arg| arg.get_long())
        .collect();
    if let Some(best) = closest_long_flag_ci(&typed, &candidates) {
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String(format!("--{best}")),
        );
    }
}

/// Render a clap parse error in the canonical zelynic shape and exit.
///
/// - `DisplayHelp` / `DisplayVersion` kinds go to stdout with exit 0
///   (clap's own contract), written through the broken-pipe-safe path
///   so `zelynic --help | head` truncates cleanly instead of panicking.
/// - Every error kind: case-insensitive typo rescue first, then the
///   usage context is replaced with the real full usage (clap narrows
///   the usage line to the suggested flag, which reads as if that flag
///   were required), then the error is re-rendered with the command's
///   brand styles and the help footer is appended so clap-side errors
///   end exactly like runtime-side errors.
pub(crate) fn exit_clap_error(e: clap::Error) -> ! {
    match e.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            // clap's print() routes through its Colorizer: the styled
            // content renders on a TTY (brand purple headers via
            // clap_styles) and is stripped when piped, and write errors
            // are returned instead of panicking — broken-pipe safe by
            // construction (`zelynic --help | head` truncates cleanly).
            let _ = e.print();
            std::process::exit(0);
        }
        _ => {}
    }

    let mut e = e;
    let mut cmd = Cli::command();
    enrich_unknown_arg_suggestion(&mut e, &cmd);

    // Replace (or add) the usage context with the real full usage —
    // clap's RichFormatter renders the Usage context verbatim, and
    // suggestion-carrying errors otherwise show the narrowed usage.
    let real_usage = cmd.render_usage();
    e.insert(ContextKind::Usage, ContextValue::StyledStr(real_usage));

    // Re-render with the command's styles applied, then print to the
    // error's own stream (stderr for error kinds). Broken pipe is
    // swallowed, matching clap's own exit() behavior.
    let e = e.format(&mut cmd);
    let _ = e.print();

    eprintln_safe!("\n{HELP_FOOTER}");
    std::process::exit(2);
}

// ── Value suggestion tips (rates + durations) ──────────────────────────────

/// Canonical value-suggestion tip line.
///
/// `  tip: a similar value exists: '<value>'` — the same wording clap
/// uses for its built-in ValueEnum suggestions, so the custom engine
/// and clap's engine render identically. The leading `\n` + two-space
/// indent matches clap's tip composition; the line-aware labeled
/// renderer paints it white.
#[cfg(feature = "ebpf")]
fn value_tip(suggestion: &str) -> String {
    format!("\n  tip: a similar value exists: '{suggestion}'")
}

/// Suggest a corrected rate string for a rejected rate input.
///
/// Two rescue rules, cheapest first:
/// 1. Exact lowercase twin — `1MB` parses fine as `1mb` (the units are
///    lowercase-only by contract, and uppercase is the classic typo).
/// 2. Near-miss unit suffix — the numeric prefix is valid and the unit
///    suffix is within edit distance 2 of a real unit (`1kib` -> `1kb`,
///    `10mbps` -> `10mb`).
#[cfg(feature = "ebpf")]
pub(crate) fn rate_tip(input: &str) -> Option<String> {
    // Multi-char units first: on an edit-distance tie, `1xb` should
    // suggest `1kb` (the common fat-finger), not `1b`.
    const UNITS: [&str; 4] = ["kb", "mb", "gb", "b"];
    let trimmed = input.trim();

    let lower = trimmed.to_ascii_lowercase();
    if lower != trimmed && crate::ebpf::limiter::parse_rate(&lower).is_ok() {
        return Some(value_tip(&lower));
    }

    // Split into numeric prefix + unit suffix at the first non-digit.
    let i = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (prefix, suffix) = (&trimmed[..i], &trimmed[i..]);
    if prefix.is_empty() || suffix.is_empty() {
        return None;
    }
    let unit = closest_value_match(suffix, &UNITS)?;
    if unit == suffix.to_ascii_lowercase() {
        return None; // already a valid unit — the number itself is bad
    }
    let fixed = format!("{prefix}{unit}");
    if crate::ebpf::limiter::parse_rate(&fixed).is_ok() {
        Some(value_tip(&fixed))
    } else {
        None
    }
}

/// Suggest a corrected duration string for a rejected duration input
/// (`3min` -> `3m`, `10sec` -> `10s`, uppercase twins).
#[cfg(feature = "ebpf")]
pub(crate) fn duration_tip(input: &str) -> Option<String> {
    const UNITS: [&str; 3] = ["s", "m", "h"];
    let trimmed = input.trim();

    let lower = trimmed.to_ascii_lowercase();
    if lower != trimmed && crate::ebpf::limiter::parse_time_duration(&lower).is_ok() {
        return Some(value_tip(&lower));
    }

    let i = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (prefix, suffix) = (&trimmed[..i], &trimmed[i..]);
    if prefix.is_empty() || suffix.is_empty() {
        return None;
    }
    let unit = closest_value_match(suffix, &UNITS)?;
    if unit == suffix.to_ascii_lowercase() {
        return None;
    }
    let fixed = format!("{prefix}{unit}");
    if crate::ebpf::limiter::parse_time_duration(&fixed).is_ok() {
        Some(value_tip(&fixed))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_footer_matches_clap_wording() {
        assert_eq!(HELP_FOOTER, "For more information, try '--help'.");
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn value_tip_shape_is_two_space_indented_tip() {
        assert_eq!(value_tip("1mb"), "\n  tip: a similar value exists: '1mb'");
    }

    // ── enrich_unknown_arg_suggestion (end-to-end against the real CLI) ─

    /// The owner's case pattern: `--VERBOS` (uppercase prefix of
    /// --verbose). clap's case-sensitive engine scores zero matches; the
    /// fallback must inject `--verbose` as clap's OWN SuggestedArg
    /// context so the canonical render carries exactly one tip.
    #[cfg(feature = "ebpf")]
    #[test]
    fn case_insensitive_fallback_rescues_verbos() {
        use clap::Parser;
        let mut err = Cli::try_parse_from(["zelynic", "--VERBOS", "doctor"])
            .expect_err("--VERBOS must be unknown");
        assert!(
            err.get(ContextKind::SuggestedArg).is_none(),
            "precondition: clap's case-sensitive engine must miss --VERBOS"
        );
        let cmd = Cli::command();
        enrich_unknown_arg_suggestion(&mut err, &cmd);
        match err.get(ContextKind::SuggestedArg) {
            Some(ContextValue::String(s)) => {
                assert_eq!(s, "--verbose", "--VERBOS must rescue --verbose, got {s:?}")
            }
            other => panic!("expected a rescued SuggestedArg, got {other:?}"),
        }
    }

    /// Full render contract: after enrichment the rendered error carries
    /// exactly one tip, the suggested flag, and the real (never
    /// narrowed) usage line.
    #[cfg(feature = "ebpf")]
    #[test]
    fn rendered_error_carries_one_tip_and_real_usage() {
        use clap::Parser;
        let mut err = Cli::try_parse_from(["zelynic", "--VERBOS", "doctor"])
            .expect_err("--VERBOS must be unknown");
        let mut cmd = Cli::command();
        enrich_unknown_arg_suggestion(&mut err, &cmd);
        err.insert(
            ContextKind::Usage,
            ContextValue::StyledStr(cmd.render_usage()),
        );
        let formatted = err.format(&mut cmd);
        let rendered = formatted.render().to_string();
        assert_eq!(rendered.matches("tip:").count(), 1, "exactly one tip line");
        assert!(rendered.contains("--verbose"));
        assert!(
            rendered.contains("Usage: zelynic"),
            "usage must be the real full usage, got:\n{rendered}"
        );
    }

    // ── rate/duration tips ──────────────────────────────────────────────

    #[cfg(feature = "ebpf")]
    #[test]
    fn rate_tip_suggests_lowercase_twin() {
        assert_eq!(
            rate_tip("1MB").unwrap(),
            "\n  tip: a similar value exists: '1mb'"
        );
        assert_eq!(
            rate_tip("500KB").unwrap(),
            "\n  tip: a similar value exists: '500kb'"
        );
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn rate_tip_suggests_near_miss_units() {
        assert_eq!(
            rate_tip("1kib").unwrap(),
            "\n  tip: a similar value exists: '1kb'"
        );
        assert_eq!(
            rate_tip("10mbps").unwrap(),
            "\n  tip: a similar value exists: '10mb'"
        );
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn rate_tip_stays_silent_when_no_rescue_exists() {
        assert!(rate_tip("abc").is_none());
        assert!(rate_tip("1xyzzy").is_none());
        assert!(rate_tip("").is_none());
        // Near-miss units are rescued, not silenced — including the
        // x-for-k fat-finger (edit distance 1 to `kb`).
        assert!(rate_tip("1xb").is_some());
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn duration_tip_suggests_near_miss_units() {
        assert_eq!(
            duration_tip("3min").unwrap(),
            "\n  tip: a similar value exists: '3m'"
        );
        assert_eq!(
            duration_tip("10sec").unwrap(),
            "\n  tip: a similar value exists: '10s'"
        );
        assert!(duration_tip("1fortnight").is_none());
    }
}
