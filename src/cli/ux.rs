// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI UX contract — the single authority for user-facing CLI errors,
//! tips, and usage lines (cosmostrix `cli/ux.rs` lineage, ported in
//! NIGHT-hunt-5).
//!
//! Exit-code contract: clap usage errors exit 2 (clap's usage code);
//! runtime failures exit 1 via the anyhow path in `main()`. Every
//! fatal CLI path renders through this module so all layers end
//! identically — with exactly one canonical `For more information,
//! try '--help'.` footer. Since NIGHT-improve-3 clap cannot render
//! that footer itself (the footer key comes from an ArgAction::Help
//! argument, and zelynic intercepts `--help` manually to print the
//! end-to-end reference), so the bridge appends the canonical wording
//! itself — exactly once, never duplicated (the NIGHT-improve-1
//! regression the tests below pin).
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

/// Canonical clap help-footer wording — appended by the bridge because
/// clap's own formatter only renders it when an ArgAction::Help argument
/// exists, and zelynic's `--help` is intercepted manually instead
/// (single-tier help surface, NIGHT-improve-3; cosmostrix lineage).
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
/// Help-position rescue (NIGHT-improve-3): `--help`/`-h` parse at the
/// top level, so an UnknownArgument for them can only originate from
/// a subcommand position (the custom help arg is not global). Instead
/// of the generic rescue — which would suggest the very flag the user
/// already typed — the tip points at the one help authority:
/// `zelynic --help`.
///
/// No-op for: every non-UnknownArgument error kind, errors that
/// already carry a suggestion (clap's tip is never duplicated), and
/// dashes-only inputs (short flags — Jaro of a single char never
/// clears 0.7, matching clap's own silence; the `-h` rescue above is
/// the deliberate exception).
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
    if typed == "help" || typed == "h" {
        // Drop clap's trailing-value escape-hatch tip ("to pass '--help'
        // as a value, use '-- --help'") first: subcommands with optional
        // positionals (strict-single, top, ...) get it injected
        // automatically, and two tips dilute the one that matters.
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String("zelynic --help".to_string()),
        );
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
/// Every error kind: case-insensitive typo rescue first (including the
/// help-position rescue), then the usage context is replaced with the
/// real full usage (clap narrows the usage line to the suggested flag,
/// which reads as if that flag were required), then the error is
/// re-rendered with the command's brand styles. clap's DisplayHelp /
/// DisplayVersion kinds can no longer occur: the built-in help flag,
/// help subcommand, and version flag are all disabled and replaced by
/// custom top-level args intercepted in `main` (NIGHT-improve-3). The
/// canonical `For more information, try '--help'.` footer is appended
/// by the bridge itself — clap's formatter skips it without an
/// ArgAction::Help argument — so every fatal CLI error ends with
/// exactly one footer (the NIGHT-improve-1 regression stays pinned by
/// the tests below).
pub(crate) fn exit_clap_error(e: clap::Error) -> ! {
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
    // swallowed, matching clap's own exit() behavior. The clap render
    // ends with a bare newline; the append below closes it into
    // clap's canonical footer spacing ("\n\nFor more information…\n").
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

    /// Canonical clap help-footer wording, matched as a literal so the
    /// regression test below hunts the exact duplication the owner
    /// reported (`zelynic backend` / `zelynic helpp` printed it twice).
    const HELP_FOOTER: &str = "For more information, try '--help'.";

    /// Footer wording is pinned to clap's canonical string byte-for-byte:
    /// the manual append must never drift from what clap itself renders
    /// for commands with a built-in help flag (cosmostrix lineage).
    #[test]
    fn help_footer_matches_clap_wording() {
        assert_eq!(HELP_FOOTER, "For more information, try '--help'.");
    }

    /// Render an error exactly the way [`exit_clap_error`] does (minus
    /// the process::exit), so render-level contracts are testable.
    /// Mirrors the full stderr byte stream: the clap render (which ends
    /// with a bare newline) followed by the bridge's manual footer
    /// append — reproducing clap's canonical "\n\n<footer>\n" tail.
    fn render_via_bridge(argv: &[&str]) -> String {
        use clap::Parser;
        let mut err = Cli::try_parse_from(argv).expect_err("argv must fail to parse");
        let mut cmd = Cli::command();
        enrich_unknown_arg_suggestion(&mut err, &cmd);
        err.insert(
            ContextKind::Usage,
            ContextValue::StyledStr(cmd.render_usage()),
        );
        let rendered = err.format(&mut cmd).render().to_string();
        format!("{rendered}\n{HELP_FOOTER}\n")
    }

    /// Regression (owner-reported, NIGHT-improve-1 session): every
    /// fatal CLI error must end with EXACTLY ONE canonical help footer.
    /// clap's formatter renders the footer from the help_flag context;
    /// the bridge previously appended a second copy on top of clap's
    /// own render. The matrix covers each error family: unknown
    /// subcommand without a tip, unknown subcommand with clap's
    /// did-you-mean tip, unknown flag with the case-insensitive rescue,
    /// and a missing required argument.
    #[test]
    fn rendered_error_carries_exactly_one_help_footer() {
        for argv in [
            vec!["zelynic", "backend"],
            vec!["zelynic", "helpp"],
            vec!["zelynic", "--VERBOS", "doctor"],
            vec!["zelynic", "strict-single"],
        ] {
            let rendered = render_via_bridge(&argv);
            assert_eq!(
                rendered.matches(HELP_FOOTER).count(),
                1,
                "exactly one help footer for {argv:?}, got:\n{rendered}"
            );
            assert!(
                rendered.trim_end().ends_with(HELP_FOOTER),
                "the single footer must terminate the render for {argv:?}, got:\n{rendered}"
            );
        }
    }

    // ── Single-tier help surface (NIGHT-improve-3) ─────────────────────

    /// Subcommand-position --help must fail (exit 2 family) with the
    /// error, the real usage line, a tip pointing at the one help
    /// authority, and exactly one canonical footer. `--help` parses at
    /// the top level, so this UnknownArgument can only mean the user
    /// placed it after a subcommand.
    #[test]
    fn subcommand_help_position_points_at_top_level_help() {
        let rendered = render_via_bridge(&["zelynic", "strict-single", "brave", "--help"]);
        assert!(
            rendered.contains("unexpected argument '--help'"),
            "must name the rejected flag, got:\n{rendered}"
        );
        assert!(
            rendered.contains("'zelynic --help'"),
            "tip must point at the top-level help authority, got:\n{rendered}"
        );
        assert!(
            rendered.contains("Usage: zelynic"),
            "usage must be the real full usage, got:\n{rendered}"
        );
        assert_eq!(rendered.matches(HELP_FOOTER).count(), 1);
    }

    /// The -h short form gets the same rescue as --help when typed in a
    /// subcommand position.
    #[test]
    fn subcommand_short_help_position_points_at_top_level_help() {
        let rendered = render_via_bridge(&["zelynic", "status", "-h"]);
        assert!(
            rendered.contains("unexpected argument '-h'"),
            "must name the rejected flag, got:\n{rendered}"
        );
        assert!(
            rendered.contains("'zelynic --help'"),
            "tip must point at the top-level help authority, got:\n{rendered}"
        );
    }

    /// The removed --help-all flag must still guide the user: the
    /// closest-match rescue suggests --help, so the old muscle memory
    /// lands on the new single surface instead of a dead end.
    #[test]
    fn removed_help_all_flag_suggests_help() {
        let rendered = render_via_bridge(&["zelynic", "--help-all"]);
        assert!(
            rendered.contains("unexpected argument '--help-all'"),
            "must name the removed flag, got:\n{rendered}"
        );
        assert!(
            rendered.contains("--help"),
            "must suggest the merged --help flag, got:\n{rendered}"
        );
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
