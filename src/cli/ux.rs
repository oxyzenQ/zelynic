// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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
//! styles (purple headers/usage, red error label, grey `valid` tips —
//! see [`crate::cli::clap_styles`]) and routed through the same
//! capability ladder as every other surface (NIGHT-improve-73:
//! plain bytes in Mono, clap's ANSI bytes otherwise — one color law);
//! rate/duration value suggestions are appended as canonical `tip:`
//! lines which the line-aware [`crate::output::eprintln_error_labeled`]
//! paints grey. The closest-match machinery lives in
//! `cli/suggestion.rs`; the argv forensics — the escape-hatch honesty
//! probe (NIGHT-boost-13) and the failing-command discovery — live in
//! `cli/argv.rs`.

use clap::CommandFactory;
use clap::error::{ContextKind, ContextValue};
use std::ffi::OsString;

use super::argv::drop_dishonest_escape_hatch;
use super::redirects::{
    drop_hidden_subcommand_suggestions, enrich_removed_subcommand_redirect,
    enrich_subcommand_flag_redirect,
};
use super::rescue::{flag_vocabulary_rescue, rescue_shadowed_suggestion, top_level_flag_rescue};
use super::suggestion::closest_long_flag_ci;
use crate::cli::Cli;
use crate::output::{ColorCapability, capability, grey};

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
///
/// The hunt-39 peak extension (owner approved, the one-line tier
/// decision): the `--help` spelling is a flag mention on the error
/// lane, so it rides the calm-grey grammar tier — the same law
/// flag_row set on the reference. The span covers the spelling
/// exactly; the quotes, prose, and period stay default, so piped
/// output keeps its plain bytes (grey is capability-aware).
fn help_footer() -> String {
    format!("For more information, try '{}'.", grey("--help"))
}

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

/// The subcommand local-help interception (night-netrunner-5).
///
/// When the error is an UnknownArgument for `-h`/`--help` AND the argv
/// walk places that flag after a subcommand, the user asked THAT
/// command for help — the request renders the subcommand's own local
/// help (synopsis, arguments, options) instead of dying. The walk is
/// the failing_subcommand forensics (`cli::argv`), run WITHOUT the
/// failing-token stop: the flag itself is the failing token, and the
/// subcommand sits before it. `-h` renders the summary help, `--help`
/// the long one — clap's own two-depth contract, on the surface the
/// single-tier law (NIGHT-improve-3) left to the subcommands. The
/// brand styles ride the clone explicitly: the derive hangs them on
/// the root only, and a local render with clap's default palette
/// would break the one-paint law the error bridge keeps. `None` for
/// every other error kind, every other token, and every root-level
/// help request (the root `help` field parses before any error can
/// fire — this door never sees a top-level ask).
fn subcommand_local_help(
    e: &clap::Error,
    cmd: &clap::builder::Command,
    argv: &[OsString],
    forced_16: bool,
) -> Option<clap::builder::StyledStr> {
    if e.kind() != clap::error::ErrorKind::UnknownArgument {
        return None;
    }
    let token = match e.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(s)) => s.as_str(),
        _ => return None,
    };
    if token != "-h" && token != "--help" {
        return None;
    }
    // The escape hatch (`--`) turns every later token into a value: a
    // `-h` that arrived after one is a value-slot error, not a help
    // request — the interception declines, and the escape-hatch honesty
    // probe (the door that owns that contract) answers instead. Both
    // positions come off one full walk: the first `--` and the first
    // verbatim token (a token clap REPORTS but argv does not carry
    // verbatim — a short cluster's tail — never declines here, the
    // same no-proof-no-verdict law the honesty probe runs on).
    let mut dashdash_at: Option<usize> = None;
    let mut token_at: Option<usize> = None;
    for (i, arg) in argv.iter().enumerate().skip(1) {
        if token_at.is_none() && arg.as_os_str() == std::ffi::OsStr::new(token) {
            token_at = Some(i);
        }
        if dashdash_at.is_none() && arg.as_os_str() == std::ffi::OsStr::new("--") {
            dashdash_at = Some(i);
        }
    }
    if let (Some(dd), Some(tp)) = (dashdash_at, token_at)
        && tp > dd
    {
        return None;
    }
    let mut sub = super::argv::failing_subcommand(cmd, argv, None)?;
    let bin = format!("zelynic {}", sub.get_name());
    let styles = if forced_16 {
        crate::cli::clap_styles_16()
    } else {
        crate::cli::clap_styles()
    };
    sub = sub.bin_name(bin).styles(styles);
    Some(if token == "--help" {
        sub.render_long_help()
    } else {
        sub.render_help()
    })
}

/// Render a clap parse error in the canonical zelynic shape and exit.
///
/// Every error kind: case-insensitive typo rescue first (including the
/// help-position rescue), the subcommand-flag redirect, then the
/// escape-hatch honesty probe (a "to pass as a value" tip that fails
/// when followed is dropped, NIGHT-boost-13), then the usage context
/// is replaced with the real full usage (clap narrows the usage line
/// to the suggested flag, which reads as if that flag were required),
/// then the error is re-rendered with the command's brand styles
/// (the 16-color rung swaps in the palette mapping first, so the
/// injected tips carry the matching encoding), and the bytes route
/// through the shared capability ladder — plain in Mono, clap's ANSI
/// otherwise (NIGHT-improve-73). clap's DisplayHelp / DisplayVersion
/// kinds can no longer occur: the
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
    // Night-netrunner-5, the subcommand local-help door: `-h`/`--help`
    // typed after a subcommand is a help REQUEST, not a usage error —
    // the single-tier root reference (NIGHT-improve-3) owns the
    // top-level surface, and the subcommand answers with its OWN local
    // help (its synopsis, its arguments), the way clap's native flag
    // would have, on stdout with exit 0. The interception runs before
    // every enrichment: the top-level authority rescue would suggest
    // the very flag the user just typed.
    if let Some(help) =
        subcommand_local_help(&e, &cmd, &argv, capability() == ColorCapability::Color16)
    {
        // The honesty note (NIGHT-boost-24): help is a text surface —
        // when --print-json rode along, stderr says so BEFORE the help
        // bytes land, so a JSON script watching the stream knows why
        // it is not JSON. stdout and the exit code are untouched.
        if super::argv::print_json_requested() {
            super::warn_print_json_ignored();
        }
        match capability() {
            ColorCapability::Mono => println_safe!("{}", help),
            _ => println_safe!("{}", help.ansi()),
        }
        std::process::exit(0);
    }
    // Night-netrunner-5, the JSON error contract door: the raw argv
    // carried --print-json, so every usage and parse error renders as
    // the contract object on stdout (exit 1) — before the prose
    // enrichment chain, whose styled render and footer are furniture a
    // JSON consumer cannot parse.
    if super::argv::print_json_requested() {
        super::json_error::exit_clap_json(&e);
    }
    // Depth honesty (NIGHT-improve-73): the forced 16-color rung gets
    // the palette mapping (clap_styles_16) BEFORE any enrichment —
    // the subcommand-flag redirect bakes the `valid` style into its
    // injected tip at build time, so the remap must land first or the
    // tip would carry RGB bytes into a 16-color render. Mono strips
    // at the render step below; the 256/24 rungs ride the RGB raw.
    // The usage context is PRE-RENDERED at parse time under the base
    // (RGB) styles, so the remap also regenerates it — the walk in
    // argv reproduces the native line byte-for-byte, now in the
    // forced palette.
    let remapped_16 = capability() == ColorCapability::Color16;
    if remapped_16 {
        cmd = cmd.styles(crate::cli::clap_styles_16());
    }
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
    if remapped_16 || native_usage_narrowed || e.get(ContextKind::Usage).is_none() {
        let failing_token = match e.get(ContextKind::InvalidArg) {
            Some(ContextValue::String(s)) => Some(s.clone()),
            _ => None,
        };
        let usage = super::argv::failing_command_usage(&mut cmd, &argv, failing_token.as_deref());
        e.insert(ContextKind::Usage, ContextValue::StyledStr(usage));
    }

    // Render with the command's styles applied, then route the bytes
    // through the SAME capability ladder every other surface answers
    // to (NIGHT-improve-73): clap's own `Error::print` runs its
    // private auto color probe, which ignored `--color-mode` — the
    // one surface in the binary above the ladder. The styled render
    // is owned here instead: Mono takes the plain-text render (the
    // StyledStr Display — zero escape bytes), every colored rung takes
    // the ANSI bytes clap already embedded (StyledStr::ansi — the
    // exact stream clap's color-passing AutoStream would have kept).
    // One color law, one decision point. Broken pipe is swallowed,
    // matching clap's own exit() behavior. The clap render ends with
    // a bare newline (try_help's no-help-flag arm); the append below
    // closes it into clap's canonical footer spacing
    // ("\n\nFor more information…\n").
    let e = e.format(&mut cmd);
    let rendered = e.render();
    match capability() {
        ColorCapability::Mono => eprint_safe!("{}", rendered),
        _ => eprint_safe!("{}", rendered.ansi()),
    }

    eprintln_safe!("\n{}", help_footer());
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

// NIGHT-improve-73: the one-color-law pins (the ladder-obedient
// render lane and the 16-color palette mapping) split to their own
// file at the 500-line cap pressure — one theme, one file, the
// usage_tests discipline.
#[cfg(test)]
#[path = "../../test/cli/color_law_tests.rs"]
mod color_law_tests;

/// Drive the subcommand local-help door the way the bridge would
/// (minus the process::exit and the stdout write), so the door's
/// contracts are testable: Some(rendered help) means the door fires,
/// None means the error path owns the argv. The test process runs in
/// the Mono lane, so the forced-16 flag mirrors the bridge's
/// condition and stays false under cargo test.
#[cfg(test)]
fn local_help_via_bridge(argv: &[&str]) -> Option<String> {
    use clap::Parser;
    let err = Cli::try_parse_from(argv).expect_err("argv must fail to parse");
    let cmd = Cli::command();
    let owned: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    subcommand_local_help(&err, &cmd, &owned, false).map(|help| help.to_string())
}

/// Render an error exactly the way [`exit_clap_error`] does (minus
/// the process::exit and the capability-lane byte choice), so
/// render-level contracts are testable. Mirrors the full stderr byte
/// stream in the MONO lane (the lane cargo's test process runs in):
/// the plain-text clap render (which ends with a bare newline)
/// followed by the bridge's manual footer append — reproducing clap's
/// canonical "\n<footer>\n" tail. The colored lanes emit the same
/// text with clap's ANSI bytes embedded (StyledStr::ansi) — text
/// identical, so every pin here holds byte-for-byte in all lanes.
/// Lives here (not in a test file) so both #[path]-wired test
/// modules reach it through `super::` — one harness, one source of
/// truth for what the bridge renders.
#[cfg(test)]
fn render_via_bridge(argv: &[&str]) -> String {
    use clap::Parser;
    let mut err = Cli::try_parse_from(argv).expect_err("argv must fail to parse");
    let mut cmd = Cli::command();
    let owned: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    // The test process runs in the Mono lane, so the 16-color remap
    // never fires here — the flag mirrors the bridge's condition and
    // stays false under cargo test.
    let remapped_16 = capability() == ColorCapability::Color16;
    let native_usage_narrowed = err.get(ContextKind::SuggestedArg).is_some();
    enrich_unknown_arg_suggestion(&mut err, &cmd);
    enrich_removed_subcommand_redirect(&mut err);
    enrich_subcommand_flag_redirect(&mut err, &cmd);
    drop_hidden_subcommand_suggestions(&mut err, &cmd);
    drop_dishonest_escape_hatch(&mut err, &owned);
    if remapped_16 || native_usage_narrowed || err.get(ContextKind::Usage).is_none() {
        let failing_token = match err.get(ContextKind::InvalidArg) {
            Some(ContextValue::String(s)) => Some(s.clone()),
            _ => None,
        };
        let usage = super::argv::failing_command_usage(&mut cmd, &owned, failing_token.as_deref());
        err.insert(ContextKind::Usage, ContextValue::StyledStr(usage));
    }
    let rendered = err.format(&mut cmd).render().to_string();
    format!("{rendered}\n{}\n", help_footer())
}
