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

/// Removed-subcommand redirects (NIGHT-boost-1): the observe/top
/// pair merged into eagle-eyes — old muscle memory gets the
/// successor named instead of a dead end (the same redirect
/// contract --help-all got when the help tiers merged,
/// NIGHT-improve-3). Exact-match only: a fuzzy suggestion for a
/// removed name is overridden, never supplemented — one tip, the
/// right one.
///
/// NIGHT-improve-25: the singular `eagle-eye` alias is removed with
/// the short-alias surface (one canonical name, one short form 'ee')
/// — it joins the redirect table so the old spelling lands on the
/// successor tip, the exact contract observe/top carry.
const REMOVED_SUBCOMMAND_REDIRECTS: &[(&str, &str)] = &[
    ("observe", "eagle-eyes"),
    ("top", "eagle-eyes"),
    ("eagle-eye", "eagle-eyes"),
];

/// Inject the successor for a removed subcommand as clap's OWN
/// SuggestedSubcommand context, so the tip renders in clap's
/// canonical position and `valid` (white) style.
///
/// No-op for every error kind except InvalidSubcommand and every
/// typed name outside the redirect table.
fn enrich_removed_subcommand_redirect(e: &mut clap::Error) {
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let typed = match e.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(s)) => s.as_str(),
        _ => return,
    };
    for (gone, successor) in REMOVED_SUBCOMMAND_REDIRECTS {
        if typed == *gone {
            // Override any fuzzy suggestion clap already attached:
            // for an exact removed name the redirect is strictly
            // more correct than a near-miss candidate.
            e.remove(ContextKind::Suggested);
            e.insert(
                ContextKind::SuggestedSubcommand,
                ContextValue::String((*successor).to_string()),
            );
            return;
        }
    }
}

/// Subcommand spellings whose successor is a top-level FLAG, not
/// another subcommand (NIGHT-boost-13).
///
/// `help` is the muscle memory every clap tool trains — clap's own
/// auto-generated `help` subcommand would answer it — but zelynic
/// runs the single-tier help surface (NIGHT-improve-3: `--help` is
/// the one reference, the auto-generated help subcommand is disabled
/// at every level), so `zelynic help` died as an unrecognized
/// subcommand with no tip: the owner's terminal showed a dead end
/// for the most natural spelling in the vocabulary. The redirect
/// lands that muscle memory on the flag that succeeds it — the same
/// contract the removed-subcommand table above gives observe/top.
const SUBCOMMAND_FLAG_REDIRECTS: &[(&str, &str)] = &[("help", "zelynic --help")];

/// Inject the flag successor for a subcommand spelling in the table
/// above as a canonical `tip:` line.
///
/// The plain `Suggested` context is the only render slot that can
/// carry a non-subcommand successor: `SuggestedSubcommand` renders
/// "a similar subcommand exists" (and there is no help subcommand to
/// name), `SuggestedArg` renders "a similar argument exists" (and
/// `help` was typed as a subcommand). The successor renders in the
/// `valid` (white) style, matching every other tip's highlighted
/// command.
fn enrich_subcommand_flag_redirect(e: &mut clap::Error, cmd: &clap::builder::Command) {
    use std::fmt::Write as _;
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let typed = match e.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(s)) => s.as_str(),
        _ => return,
    };
    let Some(&(_, successor)) = SUBCOMMAND_FLAG_REDIRECTS
        .iter()
        .find(|(name, _)| *name == typed)
    else {
        return;
    };
    // Override any fuzzy suggestion clap already attached — for an
    // exact vocabulary spelling the redirect is strictly more
    // correct than a near-miss candidate.
    e.remove(ContextKind::SuggestedSubcommand);
    e.remove(ContextKind::Suggested);
    let valid = cmd.get_styles().get_valid();
    let mut tip = clap::builder::StyledStr::new();
    let _ = write!(
        tip,
        "to see the reference, run '{valid}{successor}{valid:#}'"
    );
    e.insert(ContextKind::Suggested, ContextValue::StyledStrs(vec![tip]));
}

/// Top-level-authority flags (NIGHT-boost-12, generalizing the
/// NIGHT-improve-3 help rescue): names whose subcommand-position or
/// `--`-escaped appearance must tip the TOP-LEVEL spelling instead of
/// the fuzzy rescue.
///
/// The `-V` incident that generalized this table: the fuzzy rescue
/// scored jaro_ci("V", "verbose") = 0.714 — one matching char against
/// a 7-char candidate clears the 0.7 bar, contradicting the old
/// "single char never clears 0.7" note — and "version" ties at
/// exactly 0.714, the tie broken toward `--verbose` by declaration
/// order (later candidates win ties, mirroring clap). A lone `V` is
/// intent-ambiguous to the fuzzy engine; this table is not.
///
/// `--check-update` rides the same contract: the fuzzy rescue would
/// suggest the very flag the user already typed (a no-op tip), and
/// the update check is deliberately a top-level-only action.
const TOP_LEVEL_FLAG_RESCUES: &[(&str, &str)] = &[
    ("help", "zelynic --help"),
    ("h", "zelynic --help"),
    ("version", "zelynic -V"),
    ("V", "zelynic -V"),
    ("check-update", "zelynic --check-update"),
    ("check-updated", "zelynic --check-update"),
];

/// The top-level spelling a typed flag name must be redirected to,
/// or `None` when it is not a top-level authority.
fn top_level_flag_rescue(typed: &str) -> Option<&'static str> {
    TOP_LEVEL_FLAG_RESCUES
        .iter()
        .find(|(name, _)| *name == typed)
        .map(|(_, authority)| *authority)
}

/// Cross-tool flag vocabulary (NIGHT-boost-13): spellings users bring
/// from other CLIs, mapped to the zelynic flag that answers them.
///
/// `--json` is the convention everywhere else — every modern tool
/// answers it — so the owner typing it on zelynic is intent-clear,
/// yet the fuzzy rescue cannot bridge it: jaro_ci("json",
/// "print-json") scores 0.394 against the hyphenated 11-char name,
/// far below the 0.7 bar, and the owner's terminal showed a tip-less
/// dead end. These rescues run after the top-level authority table
/// and before the fuzzy fallback; like every rescue that injects a
/// suggestion they drop the native trailing escape-hatch tip first
/// (one tip, the right one).
const FLAG_VOCABULARY_RESCUES: &[(&str, &str)] = &[("json", "--print-json")];

/// The zelynic flag a typed name answers to by cross-tool vocabulary,
/// or `None` when it is not in the table.
fn flag_vocabulary_rescue(typed: &str) -> Option<&'static str> {
    FLAG_VOCABULARY_RESCUES
        .iter()
        .find(|(name, _)| *name == typed)
        .map(|(_, flag)| *flag)
}

/// Case-insensitive flag-suggestion fallback for clap UnknownArgument
/// errors.
///
/// When an unknown LONG flag carries no SuggestedArg context, this
/// injects the best case-insensitive match as clap's OWN
/// `SuggestedArg` context, so the tip renders in clap's canonical
/// position and `valid` (white) style — no custom printing, no second
/// tip, no render surgery.
///
/// Top-level-authority rescue first (NIGHT-improve-3 for help,
/// NIGHT-boost-12 for version and check-update): `--help`/`-h` and
/// `--check-update` parse at the top level only, and a typed name in
/// that set is redirected to the top-level spelling instead of the
/// generic rescue — which would suggest the very flag the user
/// already typed. `-V` is global since NIGHT-boost-12, so its rescue
/// fires only for the `--`-escaped positional case.
///
/// The cross-tool vocabulary rescue runs next (NIGHT-boost-13):
/// intent-clear spellings from other CLIs (`--json`) that the fuzzy
/// engine cannot bridge by distance alone.
///
/// Every rescue that injects a suggestion — authority, vocabulary,
/// and the fuzzy fallback itself — drops the native trailing
/// escape-hatch tip FIRST (NIGHT-boost-13): clap injects "to pass
/// '--VERBOS' as a value, use '-- --VERBOS'" whenever the failing
/// command merely HAS positionals, so `zelynic ss brave --VERBOS`
/// rendered two tips at once, the suggestion and the escape hatch,
/// violating the one-tip contract. A suggestion beats the escape
/// hatch every time — the same priority clap's own engine uses
/// ("did_you_mean ... should cause us to skip the -- suggestion").
///
/// No-op for: every non-UnknownArgument error kind, errors that
/// already carry a suggestion (clap's tip is never duplicated), and
/// dashes-only inputs. Single-char inputs CAN clear the 0.7 bar —
/// jaro_ci("V", "verbose") = 0.714, one matching char against a
/// 7-char candidate (the NIGHT-boost-12 `-V` incident) — which is
/// exactly why the authority rescues run before the fuzzy fallback.
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
    if let Some(authority) = top_level_flag_rescue(&typed) {
        // Drop clap's trailing-value escape-hatch tip ("to pass '--help'
        // as a value, use '-- --help'") first: subcommands with optional
        // positionals (strict-single, eagle-eyes, ...) get it injected
        // automatically, and two tips dilute the one that matters. The
        // escape hatch is also a lie for fixed-positional subcommands —
        // the owner's live repro followed it (`zelynic ss brave 550kb
        // -- -V`) and hit "unexpected argument" a second time
        // (NIGHT-boost-12).
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String(authority.to_string()),
        );
        return;
    }
    if let Some(flag) = flag_vocabulary_rescue(&typed) {
        // Same Suggested-drop contract as the authority rescue: a
        // vocabulary hit is a suggestion, and a suggestion replaces
        // the escape hatch rather than riding beside it.
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String((*flag).to_string()),
        );
        return;
    }
    let candidates: Vec<&str> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter_map(|arg| arg.get_long())
        .collect();
    if let Some(best) = closest_long_flag_ci(&typed, &candidates) {
        // The fallback rescue drops the escape-hatch tip too
        // (NIGHT-boost-13): without this remove, a case-variant typo
        // after a positional-bearing subcommand rendered BOTH tips —
        // "a similar argument exists" beside "to pass as a value" —
        // breaking the one-tip contract the bridge exists to keep.
        e.remove(ContextKind::Suggested);
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
    enrich_removed_subcommand_redirect(&mut e);
    enrich_subcommand_flag_redirect(&mut e, &cmd);

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
    const UNITS: [&str; 5] = ["kb", "mb", "gb", "tb", "b"];
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

// The UX bridge pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired across trees exactly like the render and
// limiter test modules.
#[cfg(test)]
#[path = "../../test/cli/ux_tests.rs"]
mod ux_tests;
