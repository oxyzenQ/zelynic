// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-hunt-Z9: the hidden-vocabulary contract — clap's typo
//! engine scores hidden subcommand names as candidates, so a
//! near-miss of an internal role (`__probe-serve`) used to render
//! "some similar subcommands exist: '__probe-client',
//! '__probe-server'" — the vocabulary the help hides, surfaced as
//! a tip teaching the operator to run the unauthenticated probe
//! server by hand. The bridge now filters the SuggestedSubcommand
//! context (drop_hidden_subcommand_suggestions, cli/ux.rs); these
//! pins hold the filter's two sides — the hidden names never leak,
//! and the visible suggestions and removed-name redirects survive.

/// A near-miss of a hidden internal role must NOT leak the role's
/// name: clap's did-you-mean engine scores hidden subcommand names
/// as candidates (`zelynic __probe-serve` suggested both probe
/// roles), teaching the operator to run the unauthenticated
/// data-blast server by hand. After the filter the suggestion
/// context is gone entirely (every candidate was hidden) — the
/// unrecognized-subcommand verdict, usage, and footer remain.
#[cfg(feature = "ebpf")]
#[test]
fn hidden_subcommand_typo_never_suggests_hidden_roles() {
    let rendered = super::render_via_bridge(&["zelynic", "__probe-serve"]);
    assert!(
        !rendered.contains("__probe-server"),
        "the hidden server role must never be suggested, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("__probe-client"),
        "the hidden client role must never be suggested, got:\n{rendered}"
    );
    assert!(
        rendered.contains("unrecognized subcommand"),
        "the unrecognized verdict stays, got:\n{rendered}"
    );
    assert!(
        rendered.contains("For more information, try '--help'."),
        "the canonical footer stays, got:\n{rendered}"
    );
}

/// The filter is surgical: a VISIBLE near-miss keeps its suggestion.
/// `statu` must still suggest `status` (and any other visible
/// candidates clap found) — hiding the internal vocabulary never
/// thins the public one.
#[cfg(feature = "ebpf")]
#[test]
fn visible_subcommand_typo_keeps_its_suggestion() {
    let rendered = super::render_via_bridge(&["zelynic", "statu"]);
    assert!(
        rendered.contains("status"),
        "the visible candidate must survive the hidden filter, got:\n{rendered}"
    );
    assert!(
        rendered.contains("unrecognized subcommand"),
        "the unrecognized verdict stays, got:\n{rendered}"
    );
}

/// The removed-subcommand redirects ride the same error kind and
/// must not be disturbed by the hidden filter: `observe` still
/// lands on its eagle-eyes successor exactly as before.
#[cfg(feature = "ebpf")]
#[test]
fn removed_subcommand_redirect_survives_the_hidden_filter() {
    let rendered = super::render_via_bridge(&["zelynic", "observe"]);
    assert!(
        rendered.contains("eagle-eyes"),
        "the redirect successor must survive, got:\n{rendered}"
    );
}
