// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI UX bridge pins: the single help footer, the help-position
//! rescue, the case-insensitive flag fallback, the rate/duration
//! value tips, and the NIGHT-boost-1 removed-subcommand redirects.
//! Lives under the single test/ tree (cosmostrix Pattern C) and is
//! #[path]-wired from src/cli/ux.rs, so `super::` reaches the ux
//! module exactly like inline tests did.

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
    enrich_removed_subcommand_redirect(&mut err);
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

// ── Version-anywhere + top-level-authority rescues (NIGHT-boost-12) ──

/// The owner's live repro: `zelynic -v ss brave 550kb -V` must PARSE
/// (the version flag is global) — before NIGHT-boost-12 it died on
/// the misleading `--verbose` tip, the jaro_ci V-tie broken toward
/// verbose. `main` intercepts `cli.version` before dispatch, so the
/// command never runs.
#[test]
fn version_parses_after_subcommand_positionals() {
    use clap::Parser;
    let cli = Cli::try_parse_from(["zelynic", "-v", "ss", "brave", "550kb", "-V"])
        .expect("-V must parse after subcommand positionals");
    assert!(cli.version, "the -V flag must reach main for interception");
    assert!(cli.verbose, "-v survives alongside");
    assert!(
        matches!(cli.command, Some(crate::cli::Commands::StrictSingle { .. })),
        "the subcommand must still parse behind the flag"
    );
}

/// The long form rides the same anywhere-contract.
#[test]
fn version_long_form_parses_after_subcommand() {
    use clap::Parser;
    let cli = Cli::try_parse_from(["zelynic", "ss", "brave", "550kb", "--version"])
        .expect("--version must parse after subcommand positionals");
    assert!(cli.version);
}

/// The escaped case clap's old tip lied about: `-- -V` is a positional
/// overflow (strict-single takes two), so it errors — but the tip must
/// name the top-level spelling `zelynic -V`, never `--verbose`, and
/// the escape-hatch tip must be gone.
#[test]
fn escaped_version_value_tips_the_top_level_spelling() {
    let rendered = render_via_bridge(&["zelynic", "ss", "brave", "550kb", "--", "-V"]);
    assert!(
        rendered.contains("unexpected argument '-V'"),
        "must name the rejected value, got:\n{rendered}"
    );
    assert!(
        rendered.contains("'zelynic -V'"),
        "tip must point at the top-level version authority, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("'--verbose'"),
        "the fuzzy rescue must not fire for V (the NIGHT-boost-12 lie), got:\n{rendered}"
    );
    assert!(
        !rendered.contains("use '-- -V'"),
        "the escape-hatch tip must be dropped, got:\n{rendered}"
    );
}

/// `--check-update` is a top-level-only action; typed at a subcommand
/// it must tip the top-level spelling instead of suggesting the very
/// flag the user already typed.
#[test]
fn check_update_at_subcommand_tips_top_level_spelling() {
    let rendered = render_via_bridge(&["zelynic", "status", "--check-update"]);
    assert!(
        rendered.contains("unexpected argument '--check-update'"),
        "must name the rejected flag, got:\n{rendered}"
    );
    assert!(
        rendered.contains("'zelynic --check-update'"),
        "tip must point at the top-level spelling, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("use '-- --check-update'"),
        "the escape-hatch tip must be dropped, got:\n{rendered}"
    );
}

// ── Removed-subcommand redirects (NIGHT-boost-1) ───────────────────

/// The merged observe/top commands must land users on eagle-eyes:
/// unrecognized subcommand (exit 2 family) with the successor
/// named in clap's own suggestion slot — one tip, the right one.
/// NIGHT-improve-25: the removed singular 'eagle-eye' alias rides
/// the same contract (one canonical name, one short form 'ee').
#[test]
fn removed_observe_and_top_redirect_to_eagle_eyes() {
    for gone in ["observe", "top", "eagle-eye"] {
        let rendered = render_via_bridge(&["zelynic", gone]);
        assert!(
            rendered.contains(&format!("unrecognized subcommand '{gone}'")),
            "must name the removed subcommand, got:\n{rendered}"
        );
        assert!(
            rendered.contains("eagle-eyes"),
            "removed '{gone}' must redirect to eagle-eyes, got:\n{rendered}"
        );
    }
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
