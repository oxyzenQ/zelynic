// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The JSON error contract's pins (night-netrunner-5): the message
//! and tip each door hands the renderer — the clap door's verdict
//! sentences rebuilt from the error's own context, the runtime door's
//! embedded-tip split. Lives under the single test/ tree (cosmostrix
//! Pattern C) and is #[path]-wired from src/cli/json_error.rs, so
//! `super::` reaches the contract module exactly like inline tests
//! did.

use super::*;
use crate::cli::Cli;
use clap::Parser;

fn parts_of(argv: &[&str]) -> (String, String) {
    let e = Cli::try_parse_from(argv).expect_err("argv must fail to parse");
    clap_parts(&e)
}

/// The unknown-flag verdict: the sentence the prose render opens
/// with, plus clap's own did-you-mean as the tip.
#[test]
fn unknown_flag_carries_verdict_and_clap_tip() {
    let (message, tip) = parts_of(&["zelynic", "--verbos", "doctor"]);
    assert_eq!(message, "unexpected argument '--verbos' found");
    assert!(
        tip.contains("--verbose"),
        "clap's own suggestion must ride the tip field, got: '{tip}'"
    );
}

/// The unrecognized-subcommand verdict: the removed-verb redirects
/// (observe -> eagle-eyes) live in the bridge's ENRICHMENT chain,
/// which the contract door runs before — the raw error's tip is what
/// a JSON consumer sees, never a fabricated successor.
#[test]
fn unrecognized_subcommand_carries_verdict() {
    let (message, _tip) = parts_of(&["zelynic", "observe"]);
    assert_eq!(message, "unrecognized subcommand 'observe'");
}

/// The missing-required verdict names the missing grammar.
#[test]
fn missing_required_carries_the_argument_names() {
    let (message, _tip) = parts_of(&["zelynic", "strict"]);
    assert!(
        message.starts_with("the following required arguments were not provided"),
        "got: '{message}'"
    );
    assert!(message.contains("TARGET"), "got: '{message}'");
}

/// The runtime door's split: the branded chain books its embedded
/// `tip:` line into the tip field, the body stays the error.
#[test]
fn chain_parts_split_the_embedded_tip() {
    let (error, tip) = chain_parts(
        "Invalid --during '6mn': unit '6mn' is not in the grammar \
         (s, m, h, d, mn, y — months are 'mn', 'm' is minutes)\n  tip: \
         the --during grammar is: <N><unit> — a duration from the apply \
         instant (units s, m, h, d, mn, y; bounds 1s..5y)",
    );
    assert!(error.starts_with("Invalid --during '6mn'"));
    assert!(
        !error.contains("tip:"),
        "the tip leaves the body: '{error}'"
    );
    assert!(
        tip.contains("the --during grammar is"),
        "the tip field carries the grammar, got: '{tip}'"
    );
}

/// No embedded tip means an empty one — the key stays present (a
/// consumer indexes both fields blindly), the contract never
/// fabricates advice.
#[test]
fn chain_parts_without_a_tip_stay_empty() {
    let (error, tip) = chain_parts("cgroup v2 not found at /sys/fs/cgroup");
    assert_eq!(error, "cgroup v2 not found at /sys/fs/cgroup");
    assert_eq!(tip, "");
}

/// night-total-hardening-1 (the owner's "leaks bug"): a value-taking
/// flag with NO value renders the SAME sentence the prose lane
/// renders — "a value is required ... but none was supplied" — never
/// the machine-facing lie "invalid value ''" (the user omitted the
/// value; they did not pass an empty string). Both eagle-eyes flags
/// the live run leaked are pinned.
#[test]
fn valueless_flag_says_value_required_not_invalid_empty() {
    let (message, _tip) = parts_of(&[
        "zelynic",
        "eagle-eyes",
        "cg:8891",
        "--print-json",
        "--focus",
    ]);
    assert_eq!(
        message, "a value is required for '--focus <SECONDS>' but none was supplied",
        "the empty-value shape must match clap's prose verdict, got: '{message}'"
    );
    let (message, _tip) = parts_of(&[
        "zelynic",
        "eagle-eyes",
        "cg:8891",
        "--print-json",
        "--interval",
    ]);
    assert_eq!(
        message, "a value is required for '--interval <INTERVAL>' but none was supplied",
        "the interval twin must match too, got: '{message}'"
    );
}

/// A REAL invalid value keeps its own verdict — the empty-value
/// special case must never swallow genuine value errors. The hidden
/// probe-server's `port: u16` is the CLI's one typed positional: a
/// number past u16 is a genuine clap value error with a non-empty
/// value context.
#[test]
fn a_real_invalid_value_keeps_its_verdict() {
    let (message, _tip) = parts_of(&["zelynic", "__probe-server", "99999999", "dl"]);
    assert!(
        message.starts_with("invalid value '99999999' for"),
        "a genuine bad value keeps the invalid-value verdict, got: '{message}'"
    );
}
