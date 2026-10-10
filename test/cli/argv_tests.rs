// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI argv-forensics pins: the escape-hatch honesty probe and the
//! gate that drops the tip it disproves (NIGHT-boost-13). Lives under
//! the single test/ tree (cosmostrix Pattern C) and is #[path]-wired
//! from src/cli/argv.rs, so `super::` reaches the argv module exactly
//! like inline tests did.

use super::*;

fn argv(list: &[&str]) -> Vec<std::ffi::OsString> {
    list.iter().map(std::ffi::OsString::from).collect()
}

// ── escape_hatch_is_honest ─────────────────────────────────────────

/// The owner's live case (boost-13's era spelled it 'ss'; the
/// improve-53 masterclass short form is 's' — same two positional
/// slots): both are full, so every advised splice (`-- -i`) still
/// dies on "unexpected argument" — the advice fails when followed,
/// the probe must say dishonest.
#[test]
fn probe_convicts_when_every_splice_still_fails() {
    let a = argv(&["zelynic", "-v", "s", "brave", "550kb", "-i"]);
    assert!(
        !escape_hatch_is_honest(&a, "-i"),
        "positionals full: the splice must fail"
    );
}

/// The honest twin: strict's RATE slot is open, so the advised
/// splice parses with `-i` as the rate value — the advice works, the
/// probe must acquit. This is the pair that forbids the cheap fix
/// (dropping the tip unconditionally): silence here would discard
/// real advice.
#[test]
fn probe_acquits_when_the_splice_parses() {
    let a = argv(&["zelynic", "s", "brave", "-i"]);
    assert!(
        escape_hatch_is_honest(&a, "-i"),
        "rate slot open: the splice must parse"
    );
}

/// eagle-eyes takes an optional TARGETS positional, so its slot is
/// open too — the probe acquits for the same reason.
#[test]
fn probe_acquits_for_open_optional_positionals() {
    let a = argv(&["zelynic", "ee", "-x"]);
    assert!(
        escape_hatch_is_honest(&a, "-x"),
        "targets slot open: the splice must parse"
    );
}

/// A token clap reports but argv lacks verbatim (short clusters
/// report the single char, `--flag=value` reports the flag part) is
/// unprovable: the probe declines to judge rather than convict on
/// missing evidence — a tip is dropped only when disproven.
#[test]
fn probe_declines_to_judge_tokens_argv_lacks() {
    let a = argv(&["zelynic", "s", "brave", "550kb", "-vi"]);
    assert!(
        escape_hatch_is_honest(&a, "-i"),
        "unprovable tokens pass through as honest"
    );
}

// ── failing_subcommand (the parser-descent walk) ───────────────────

/// The walk matches subcommand ALIASES: 's' is strict's short form,
/// and the failing command is the same command either way.
#[test]
fn walk_resolves_aliases_to_the_canonical_command() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    let sub = failing_subcommand(
        &root,
        &argv(&["zelynic", "-v", "s", "brave", "550kb", "-i"]),
        Some("-i"),
    )
    .expect("s must resolve");
    assert_eq!(sub.get_name(), "strict");
}

/// Tokens after the failing token never had a parser look at them:
/// the walk must stop at the failure, not misattribute a top-level
/// death to a subcommand named later.
#[test]
fn walk_stops_at_the_failing_token() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    assert!(
        failing_subcommand(
            &root,
            &argv(&["zelynic", "--verbos", "doctor"]),
            Some("--verbos")
        )
        .is_none(),
        "a death before the subcommand token is a top-level death"
    );
}

/// Nothing after a `--` can start a subcommand.
#[test]
fn walk_never_crosses_the_double_dash() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    assert!(
        failing_subcommand(&root, &argv(&["zelynic", "--", "ss"]), None).is_none(),
        "post-double-dash tokens are values, not subcommands"
    );
}

/// An unrecognized subcommand name is a top-level death: the walk
/// returns None and the root usage is the right usage.
#[test]
fn walk_returns_none_for_unrecognized_names() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    assert!(
        failing_subcommand(&root, &argv(&["zelynic", "stat"]), Some("stat")).is_none(),
        "the walk only resolves real subcommands"
    );
}

/// The two-token space form of --color-mode leaves its value as a
/// bare argv token (NIGHT-total-lts-3 find 1: the walk's boolean-only
/// assumption predates boost-23, so the MODE value was mistaken for
/// the subcommand — a strict-single death rendered the ROOT usage).
/// The walk must consume the value the way the parser does.
#[test]
fn walk_consumes_the_color_mode_value_token() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    let sub = failing_subcommand(
        &root,
        &argv(&["zelynic", "--color-mode", "16", "s", "brave", "--verbos"]),
        Some("--verbos"),
    )
    .expect("the walk must reach s past the consumed MODE value");
    assert_eq!(sub.get_name(), "strict");
}

/// A MODE value that IS a real subcommand name must still be eaten as
/// the value (the pre-fix walk resolved `--color-mode status ss` to
/// the status command — a usage line for a command the parser never
/// entered).
#[test]
fn walk_consumes_a_mode_value_that_names_a_subcommand() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    let sub = failing_subcommand(
        &root,
        &argv(&[
            "zelynic",
            "--color-mode",
            "status",
            "s",
            "brave",
            "--verbos",
        ]),
        Some("--verbos"),
    )
    .expect("the MODE value is a value, never the subcommand");
    assert_eq!(
        sub.get_name(),
        "strict",
        "the walk resolves the subcommand AFTER the consumed value"
    );
}

/// The =-form is one token and rides the dash-skip: the subcommand
/// after it resolves directly.
#[test]
fn walk_resolves_the_subcommand_after_the_equals_form() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    let sub = failing_subcommand(
        &root,
        &argv(&["zelynic", "--color-mode=16", "s", "brave", "--verbos"]),
        Some("--verbos"),
    )
    .expect("the =-form never leaves a bare value token");
    assert_eq!(sub.get_name(), "strict");
}

/// The gate removes exactly the Suggested context the probe
/// convicted — no SuggestedArg is invented, the error kind and the
/// rejected token are untouched.
#[test]
fn gate_drops_only_the_convicted_tip() {
    use clap::Parser;
    let a = argv(&["zelynic", "-v", "s", "brave", "550kb", "-i"]);
    let mut err = Cli::try_parse_from(&a).expect_err("argv must fail to parse");
    assert!(
        err.get(clap::error::ContextKind::Suggested).is_some(),
        "precondition: clap attaches the escape-hatch tip"
    );
    drop_dishonest_escape_hatch(&mut err, &a);
    assert!(
        err.get(clap::error::ContextKind::Suggested).is_none(),
        "the convicted tip must be gone"
    );
    assert!(
        err.get(clap::error::ContextKind::InvalidArg).is_some(),
        "the rejected token context must survive"
    );
}

/// The honest tip passes the gate untouched.
#[test]
fn gate_keeps_the_proven_honest_tip() {
    use clap::Parser;
    let a = argv(&["zelynic", "s", "brave", "-i"]);
    let mut err = Cli::try_parse_from(&a).expect_err("argv must fail to parse");
    drop_dishonest_escape_hatch(&mut err, &a);
    assert!(
        err.get(clap::error::ContextKind::Suggested).is_some(),
        "the honest tip must survive the gate"
    );
}

// ── charger-core-3b / NIGHT-improve-53: the --per-socket flag's
// parse contract ────────────────────────────────────────────────────

/// The flag parses on strict (and its 's' alias — the same command)
/// and lands as per_socket: true; the masterclass surface carries
/// the flag for BOTH lanes, so the parse cannot know the lane — the
/// group-lane refusal is the router's own scope call, unit-pinned in
/// commands/strict_tests (per_socket_is_refused_on_the_group_lane_
/// before_any_parsing). Other verbs do not know the flag at all.
#[test]
fn per_socket_flag_parses_on_strict_only() {
    use crate::cli::Cli;

    for verb in ["strict", "s"] {
        let cli = Cli::try_parse_from(["zelynic", verb, "nginx", "500kb", "--per-socket"])
            .unwrap_or_else(|e| panic!("{verb} must parse --per-socket: {e}"));
        match cli.command {
            Some(crate::cli::Commands::Strict { per_socket, .. }) => {
                assert!(per_socket, "{verb} must carry per_socket: true");
            }
            other => panic!("{verb} must route to Strict, got: {other:?}"),
        }
    }

    let err = Cli::try_parse_from(["zelynic", "block", "nginx", "--per-socket"])
        .expect_err("block must reject --per-socket");
    assert!(
        err.to_string().contains("unexpected argument"),
        "the rejection is clap's unknown-argument error, got: {err}"
    );
}

// ── forced_color_mode_from_argv (NIGHT-improve-73) ─────────────────

use crate::output::ColorCapability;

/// The owner's live repro grammar: the space form before the typo'd
/// subcommand must seed Mono, so the clap-rendered error half obeys
/// the same ladder the ux-rendered half does.
#[test]
fn space_form_before_the_failure_seeds_mono() {
    let a = argv(&["zelynic", "-v", "--color-mode", "0", "ss", "brave", "100kb"]);
    assert_eq!(
        forced_color_mode_from_argv(&a),
        Some(ColorCapability::Mono),
        "the repro line must seed Mono for the error lane"
    );
}

/// The `=` form rides one token and seeds the same way.
#[test]
fn equals_form_seeds_the_same() {
    let a = argv(&["zelynic", "--color-mode=24", "s", "brave", "100kb"]);
    assert_eq!(
        forced_color_mode_from_argv(&a),
        Some(ColorCapability::TrueColor),
        "the one-token form must seed TrueColor"
    );
}

/// clap's ArgAction::Set takes the LAST occurrence; the scan mirrors
/// it, so a later valid value overrides an earlier one.
#[test]
fn last_occurrence_wins() {
    let a = argv(&["zelynic", "--color-mode", "0", "--color-mode", "16"]);
    assert_eq!(
        forced_color_mode_from_argv(&a),
        Some(ColorCapability::Color16),
        "the scan must mirror clap's last-Set contract"
    );
}

/// Nothing after `--` is an option: the scan stops there, the same
/// world-end the parser honors.
#[test]
fn double_dash_ends_the_scan() {
    let a = argv(&["zelynic", "s", "brave", "100kb", "--", "--color-mode", "0"]);
    assert_eq!(
        forced_color_mode_from_argv(&a),
        None,
        "an escaped --color-mode is a value, never a seed"
    );
}

/// An invalid MODE never seeds: the grammar error belongs to main's
/// authoritative check, and the auto ladder renders it.
#[test]
fn invalid_mode_never_seeds() {
    for bad in ["9", "wat", ""] {
        let a = argv(&["zelynic", "--color-mode", bad, "s", "brave", "100kb"]);
        assert_eq!(
            forced_color_mode_from_argv(&a),
            None,
            "invalid MODE {bad:?} must not seed"
        );
    }
    let a = argv(&["zelynic", "--color-mode=wat", "s"]);
    assert_eq!(forced_color_mode_from_argv(&a), None);
}

/// No flag, no seed — the auto ladder stays in charge.
#[test]
fn absence_leaves_the_seed_empty() {
    let a = argv(&["zelynic", "-v", "ss", "brave", "100kb"]);
    assert_eq!(forced_color_mode_from_argv(&a), None);
}

/// A `--color-mode` flag swallowed as another option's value never
/// existed in this grammar (color-mode is the sole value-taker), but
/// a dangling `--color-mode` with no value must not panic the scan —
/// it just leaves the seed empty (clap reports the missing value).
#[test]
fn dangling_flag_without_value_is_harmless() {
    let a = argv(&["zelynic", "s", "brave", "100kb", "--color-mode"]);
    assert_eq!(forced_color_mode_from_argv(&a), None);
}
