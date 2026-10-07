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
//! closest-match machinery lives in `cli/suggestion.rs`; the argv
//! forensics — the escape-hatch honesty probe (NIGHT-boost-13) and
//! the failing-command discovery — live in `cli/argv.rs`.

use clap::error::{ContextKind, ContextValue};
use clap::CommandFactory;
use std::ffi::OsString;

use super::argv::drop_dishonest_escape_hatch;
use super::rescue::{flag_vocabulary_rescue, rescue_shadowed_suggestion, top_level_flag_rescue};
use super::suggestion::closest_long_flag_ci;
use crate::cli::Cli;

// NIGHT-blade-4: the value-suggestion tip family moved to cli/tips.rs
// (the 500-LOC cap split — see that file's header); re-exported so
// every caller's `crate::cli::ux::rate_tip` path and the test tree's
// `super::` reach keep working unchanged. value_tip is tip-internal
// (rate_tip/duration_tip compose it) — re-exported for the pin tests
// only, so a normal build carries no unused-import surface.
#[cfg(all(test, feature = "ebpf"))]
pub(crate) use super::tips::value_tip;
#[cfg(feature = "ebpf")]
pub(crate) use super::tips::{duration_tip, rate_tip};

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
///
/// NIGHT-blade-2: limit-all/la renamed strict-all/sa (strict-family
/// symmetry) — both old spellings join the redirect table's contract.
///
/// NIGHT-improve-54 (the sweep merge): strict-all, block-all, and
/// unstrict-all are LANES of their family verbs now (`s --all`,
/// `b --all`, `u --all`) — the six retired spellings (canonical +
/// short alias each) join the table, and the blade-2 pair above
/// repoints at `strict` with them: every one lands on its family's
/// successor verb.
///
/// NIGHT-improve-53 (the masterclass unification): strict-single +
/// strict-multi, block-single + block-multi, and unstrict-single +
/// unstrict-multi merged into one verb per family (strict / block /
/// unstrict — 's'/'b'/'u' the short forms, '::' the list separator).
/// Twelve retired spellings join the table — every one of them
/// lands on its family's successor verb.
const REMOVED_SUBCOMMAND_REDIRECTS: &[(&str, &str)] = &[
    ("observe", "eagle-eyes"),
    ("top", "eagle-eyes"),
    ("eagle-eye", "eagle-eyes"),
    // NIGHT-improve-54: repointed with the sweep merge — strict-all
    // itself is retired into strict's --all lane, so the blade-2
    // spellings land on the sweep spelling like every -all after
    // them. The successor string names WHAT TO TYPE (verb + flag):
    // a bare 'strict' tip would strand the sweep-seeker on the
    // TARGET-required rung one keystroke later.
    ("limit-all", "strict --all"),
    ("la", "strict --all"),
    // NIGHT-improve-53: the masterclass retirees.
    ("strict-single", "strict"),
    ("strict-multi", "strict"),
    ("ss", "strict"),
    ("sm", "strict"),
    ("block-single", "block"),
    ("block-multi", "block"),
    ("bs", "block"),
    ("bm", "block"),
    ("unstrict-single", "unstrict"),
    ("unstrict-multi", "unstrict"),
    ("us", "unstrict"),
    ("um", "unstrict"),
    // NIGHT-improve-54: the sweep retirees — the -all verbs are
    // --all lanes of the family verbs now (the sa/ba/ua short
    // aliases with them, the short-alias surface's own law). The
    // successors name the runnable spelling (verb + flag), the
    // limit-all contract one entry up.
    ("strict-all", "strict --all"),
    ("sa", "strict --all"),
    ("block-all", "block --all"),
    ("ba", "block --all"),
    ("unstrict-all", "unstrict --all"),
    ("ua", "unstrict --all"),
    // NIGHT-improve-55: the snapshot verb is retired — the owner's
    // live-test verdict was that the dump half of the persistence
    // pair was not worth its workflow (the operator's own script is
    // the state). The pair's survivor owns the muscle memory: the
    // state file is now the operator's hand-maintained desired
    // state, and `restore` is the verb that honors it.
    ("snapshot", "restore"),
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

/// Strip hidden subcommands from clap's typo suggestions
/// (NIGHT-hunt-Z9).
///
/// clap's `did_you_mean` engine scores candidates from
/// `all_subcommand_names()` — hidden ones included — so a near-miss of
/// an internal role (`zelynic __probe-serve`) rendered "some similar
/// subcommands exist: '__probe-client', '__probe-server'": the
/// vocabulary the help hides surfaced as a tip, teaching the operator
/// to run the probe server (an unauthenticated loopback data blast)
/// by hand. The flag-side rescue below already filters
/// `is_hide_set()` candidates; this is the subcommand-side twin —
/// the same one-vocabulary contract, both doors.
///
/// Pure filter over the `SuggestedSubcommand` context (clap stores
/// its candidates there as `Strings`): every candidate that resolves
/// to a hidden subcommand is dropped. When candidates remain, the
/// trimmed list replaces the context (a visible suggestion survives
/// beside a hidden one being removed); when NONE remain the context
/// is removed entirely, leaving the unrecognized-subcommand verdict,
/// the usage line, and the footer — the same honest dead end any
/// no-candidate typo already owns. No-op for every other error kind
/// and for errors carrying no suggestion.
fn drop_hidden_subcommand_suggestions(e: &mut clap::Error, cmd: &clap::builder::Command) {
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let Some(ContextValue::Strings(candidates)) = e.get(ContextKind::SuggestedSubcommand) else {
        return;
    };
    let candidates = candidates.clone();
    let visible: Vec<String> = candidates
        .iter()
        .filter(|name| {
            cmd.find_subcommand(name.as_str())
                .is_none_or(|sub| !sub.is_hide_set())
        })
        .cloned()
        .collect();
    if visible.len() == candidates.len() {
        return; // nothing hidden — clap's own suggestion stands
    }
    if visible.is_empty() {
        e.remove(ContextKind::SuggestedSubcommand);
    } else {
        e.insert(
            ContextKind::SuggestedSubcommand,
            ContextValue::Strings(visible),
        );
    }
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
/// that set is redirected to the top-level spelling — the generic
/// rescue would suggest the very flag the user already typed. `-V` is
/// global since NIGHT-boost-12, firing only for `--`-escaped values.
///
/// The cross-tool vocabulary rescue runs next (NIGHT-boost-13):
/// intent-clear spellings from other CLIs (`--json`) that the fuzzy
/// engine cannot bridge by distance alone.
///
/// Every rescue that injects a suggestion — authority, vocabulary,
/// and the fuzzy fallback itself — drops the native trailing
/// escape-hatch tip FIRST (NIGHT-boost-13): clap injects "to pass
/// '--VERBOS' as a value, use '-- --VERBOS'" whenever the failing
/// command merely HAS positionals, so `zelynic s brave --VERBOS`
/// rendered two tips at once, violating the one-tip contract — a
/// suggestion beats the escape hatch every time, the same priority
/// clap's own engine uses.
///
/// No-op for: every non-UnknownArgument error kind, errors that
/// already carry a suggestion (clap's tip is never duplicated), and
/// dashes-only inputs. Single-char inputs CAN clear the 0.7 bar —
/// jaro_ci("V", "verbose") = 0.714 (the NIGHT-boost-12 `-V`
/// incident) — which is exactly why the authority rescues run before
/// the fuzzy fallback.
fn enrich_unknown_arg_suggestion(e: &mut clap::Error, cmd: &clap::builder::Command) {
    if e.kind() != clap::error::ErrorKind::UnknownArgument {
        return;
    }
    if e.get(ContextKind::SuggestedArg).is_some() {
        // clap fired its own tip — usually the last word, but the
        // shadowed-suggestion rescue (NIGHT-improve-42) gets one
        // look first: clap's suggestion pool at a SUBCOMMAND
        // position carries that subcommand's flags only (the
        // root-level flags never join it), so a fresh subcommand
        // flag can shadow a much closer root-flag typo.
        rescue_shadowed_suggestion(e, cmd);
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
        // positionals (strict, eagle-eyes, ...) get it injected
        // automatically, and two tips dilute the one that matters. The
        // escape hatch is also a lie for fixed-positional subcommands —
        // the owner's live repro followed it (`zelynic ss brave 550kb
        // -- -V`, the NIGHT-boost-12 incident — 'ss' was the spelling
        // of that era) and hit "unexpected argument" a second time.
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
/// help-position rescue), the subcommand-flag redirect, then the
/// escape-hatch honesty probe (a "to pass as a value" tip that fails
/// when followed is dropped, NIGHT-boost-13), then the usage context
/// is replaced with the real full usage (clap narrows the usage line
/// to the suggested flag, which reads as if that flag were required),
/// then the error is re-rendered with the command's brand styles.
/// clap's DisplayHelp / DisplayVersion kinds can no longer occur: the
/// built-in help flag, help subcommand, and version flag are all
/// disabled and replaced by custom top-level args intercepted in
/// `main` (NIGHT-improve-3). The canonical `For more information,
/// try '--help'.` footer is appended by the bridge itself — clap's
/// formatter skips it without an ArgAction::Help argument — so every
/// fatal CLI error ends with exactly one footer (the NIGHT-improve-1
/// regression stays pinned by the tests below).
pub(crate) fn exit_clap_error(e: clap::Error) -> ! {
    let mut e = e;
    let mut cmd = Cli::command();
    let argv: Vec<OsString> = std::env::args_os().collect();
    // Captured BEFORE enrichment: only clap's OWN suggestion narrows
    // the native usage (the parser adds the suggested flag to its
    // matcher, and `create_usage_with_title(&used)` then renders it
    // into the usage line as if it were required) — the suggestions
    // this bridge injects afterwards never touch the matcher.
    let native_usage_narrowed = e.get(ContextKind::SuggestedArg).is_some();
    enrich_unknown_arg_suggestion(&mut e, &cmd);
    enrich_removed_subcommand_redirect(&mut e);
    enrich_subcommand_flag_redirect(&mut e, &cmd);
    // NIGHT-hunt-Z9: clap's typo engine suggests hidden internal
    // roles (the probe pair) — the same engine the flag-side rescue
    // already filters. Runs after the redirect enrichments so an
    // exact removed-name successor (never hidden) keeps its seat.
    drop_hidden_subcommand_suggestions(&mut e, &cmd);
    drop_dishonest_escape_hatch(&mut e, &argv);

    // Usage context: the native usage is already the failing
    // command's own (clap renders the subcommand's usage for
    // subcommand-level deaths), so it stays — NIGHT-boost-13 ended
    // the unconditional top-level replacement that flattened every
    // subcommand error onto "zelynic [OPTIONS] [COMMAND]", a line
    // that says nothing about the command that failed. Only the
    // narrowed usage is regenerated (from the failing command, by
    // walking argv the way the parser descends), and a missing
    // usage context is filled the same way.
    if native_usage_narrowed || e.get(ContextKind::Usage).is_none() {
        let failing_token = match e.get(ContextKind::InvalidArg) {
            Some(ContextValue::String(s)) => Some(s.clone()),
            _ => None,
        };
        let usage = super::argv::failing_command_usage(&mut cmd, &argv, failing_token.as_deref());
        e.insert(ContextKind::Usage, ContextValue::StyledStr(usage));
    }

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

// The value-suggestion tip family (value_tip / rate_tip /
// duration_tip) lives in `cli/tips.rs` since NIGHT-blade-4 — the
// retired `--info` vocabulary entry pushed this file past the
// 500-LOC cap, and the split keeps the ux bridge alone under it
// (the same cap-pressure move that gave cli/styles.rs to
// cli/mod.rs). The re-export above keeps every caller's path (and
// the test module's `super::` reach) working unchanged.

// The UX bridge pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired across trees exactly like the render and
// limiter test modules. The usage-line pins split into their own
// file when they pushed ux_tests past the 500-LOC cap (NIGHT-boost-13,
// the diff_tests/guard_tests discipline); both files share the
// module-level render harness below.
#[cfg(test)]
#[path = "../../test/cli/ux_tests.rs"]
mod ux_tests;

#[cfg(test)]
#[path = "../../test/cli/usage_tests.rs"]
mod usage_tests;

// NIGHT-hunt-Z9: the hidden-vocabulary pins split to their own file
// at the 500-LOC cap (one theme, one file, the usage_tests move).
#[cfg(test)]
#[path = "../../test/cli/hidden_vocab_tests.rs"]
mod hidden_vocab_tests;

// NIGHT-improve-42: the flag-rescue family's pins (the sibling
// rescue.rs module's tables and matchers, driven through this
// module's own render_via_bridge harness — the bridge is the only
// honest way to pin a suggestion: what matters is the rendered tip).
// The ebpf gate is the rates_shadow_tests precedent (commands/rates.rs):
// every pin inside is #[cfg(feature = "ebpf")], so in the dormant lane
// a plain #[cfg(test)] module would compile to nothing but its glob
// import — an unused-import warning the CI leg's RUSTFLAGS=-D warnings
// turns into the error that reddened the audit commit's own check-all.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/cli/rescue_tests.rs"]
mod rescue_tests;

/// Render an error exactly the way [`exit_clap_error`] does (minus
/// the process::exit), so render-level contracts are testable.
/// Mirrors the full stderr byte stream: the clap render (which ends
/// with a bare newline) followed by the bridge's manual footer
/// append — reproducing clap's canonical "\n\n<footer>\n" tail.
/// Lives here (not in a test file) so both #[path]-wired test
/// modules reach it through `super::` — one harness, one source of
/// truth for what the bridge renders.
#[cfg(test)]
fn render_via_bridge(argv: &[&str]) -> String {
    use clap::Parser;
    let mut err = Cli::try_parse_from(argv).expect_err("argv must fail to parse");
    let mut cmd = Cli::command();
    let owned: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let native_usage_narrowed = err.get(ContextKind::SuggestedArg).is_some();
    enrich_unknown_arg_suggestion(&mut err, &cmd);
    enrich_removed_subcommand_redirect(&mut err);
    enrich_subcommand_flag_redirect(&mut err, &cmd);
    drop_hidden_subcommand_suggestions(&mut err, &cmd);
    drop_dishonest_escape_hatch(&mut err, &owned);
    if native_usage_narrowed || err.get(ContextKind::Usage).is_none() {
        let failing_token = match err.get(ContextKind::InvalidArg) {
            Some(ContextValue::String(s)) => Some(s.clone()),
            _ => None,
        };
        let usage = super::argv::failing_command_usage(&mut cmd, &owned, failing_token.as_deref());
        err.insert(ContextKind::Usage, ContextValue::StyledStr(usage));
    }
    let rendered = err.format(&mut cmd).render().to_string();
    format!("{rendered}\n{HELP_FOOTER}\n")
}
