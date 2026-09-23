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

/// The owner's live case: strict-single's two positional slots are
/// full, so every advised splice (`-- -i`) still dies on "unexpected
/// argument" — the advice fails when followed, the probe must say
/// dishonest.
#[test]
fn probe_convicts_when_every_splice_still_fails() {
    let a = argv(&["zelynic", "-v", "ss", "brave", "550kb", "-i"]);
    assert!(
        !escape_hatch_is_honest(&a, "-i"),
        "positionals full: the splice must fail"
    );
}

/// The honest twin: strict-single's RATE slot is open, so the advised
/// splice parses with `-i` as the rate value — the advice works, the
/// probe must acquit. This is the pair that forbids the cheap fix
/// (dropping the tip unconditionally): silence here would discard
/// real advice.
#[test]
fn probe_acquits_when_the_splice_parses() {
    let a = argv(&["zelynic", "ss", "brave", "-i"]);
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
    let a = argv(&["zelynic", "ss", "brave", "550kb", "-vi"]);
    assert!(
        escape_hatch_is_honest(&a, "-i"),
        "unprovable tokens pass through as honest"
    );
}

// ── failing_subcommand (the parser-descent walk) ───────────────────

/// The walk matches subcommand ALIASES: 'ss' is strict-single's
/// short form, and the failing command is the same command either
/// way.
#[test]
fn walk_resolves_aliases_to_the_canonical_command() {
    use clap::CommandFactory;
    let root = crate::cli::Cli::command();
    let sub = failing_subcommand(
        &root,
        &argv(&["zelynic", "-v", "ss", "brave", "550kb", "-i"]),
        Some("-i"),
    )
    .expect("ss must resolve");
    assert_eq!(sub.get_name(), "strict-single");
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

/// The gate removes exactly the Suggested context the probe
/// convicted — no SuggestedArg is invented, the error kind and the
/// rejected token are untouched.
#[test]
fn gate_drops_only_the_convicted_tip() {
    use clap::Parser;
    let a = argv(&["zelynic", "-v", "ss", "brave", "550kb", "-i"]);
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
    let a = argv(&["zelynic", "ss", "brave", "-i"]);
    let mut err = Cli::try_parse_from(&a).expect_err("argv must fail to parse");
    drop_dishonest_escape_hatch(&mut err, &a);
    assert!(
        err.get(clap::error::ContextKind::Suggested).is_some(),
        "the honest tip must survive the gate"
    );
}
