// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Strict family pins — the parse-before-execute ladder (moved out of
//! the inline module at the NIGHT-improve-53 masterclass split, the
//! 600-line cap's own pressure) plus the unification's own law: the
//! '::' routing and the per-socket scope call.

use super::*;

/// Parse-before-execute contract (live smoke-run find): a typo'd
/// rate must surface its did-you-mean tip BEFORE the privilege
/// guard, exactly like clap validates its own arguments before any
/// handler runs. Previously ensure_root() ran first, so a non-root
/// user was told to sudo before learning their rate string was
/// wrong — a wasted privileged round-trip.
///
/// Safe on any uid: the rate error returns before ensure_root(), so
/// the test never reaches BPF attach even when run as root.
#[cfg(feature = "ebpf")]
#[test]
fn rate_typo_surfaces_before_root_guard() {
    let err = handle_strict_single(
        "bash",
        Some("1MB"),
        None,
        None,
        false,
        false,
        false,
        super::super::guarantee::BracketFlags::default(),
        None,
        false,
    )
    .expect_err("typo'd rate must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("Invalid rate '1MB'"),
        "rate error must lead, got: {msg}"
    );
    assert!(
        msg.contains("tip: a similar value exists: '1mb'"),
        "typo tip must ride along, got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "rate error must precede the root guard, got: {msg}"
    );
}

/// Same contract for the dangerous-target blocklist: a policy
/// refusal must surface before the privilege guard.
#[cfg(feature = "ebpf")]
#[test]
fn dangerous_target_refusal_surfaces_before_root_guard() {
    let err = handle_strict_single(
        "sshd",
        Some("1mb"),
        None,
        None,
        false,
        false,
        false,
        super::super::guarantee::BracketFlags::default(),
        None,
        false,
    )
    .expect_err("dangerous target must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("'sshd' is a system process"),
        "dangerous-target refusal must lead, got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "policy refusal must precede the root guard, got: {msg}"
    );
}

/// NIGHT-dinner-16: an empty target dies at the input boundary —
/// before the blocklist and the privilege guard — instead of
/// flowing to the root ask as `Target::parse("")`'s invisible
/// `ProcessName("")` (the parse-before-execute ladder's missing
/// rung, closed by the verifier-lineage mandate).
#[cfg(feature = "ebpf")]
#[test]
fn empty_target_surfaces_before_root_guard() {
    let err = handle_strict_single(
        "",
        Some("1mb"),
        None,
        None,
        false,
        false,
        false,
        super::super::guarantee::BracketFlags::default(),
        None,
        false,
    )
    .expect_err("an empty target must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("target is empty"),
        "the empty-target verdict must lead, got: {msg}"
    );
    assert!(
        msg.contains("zelynic strict brave 100kb"),
        "the refusal must carry the example command, got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "the input error must precede the root guard, got: {msg}"
    );
}

/// NIGHT-improve-53 (the masterclass routing): one verb, two lanes.
/// A '::'-bearing target enters the GROUP lane (the rate parse
/// inside it proves the routing), a plain target enters the SINGLE
/// lane — same typo, same pre-root rate error, different machinery
/// underneath. Safe on any uid: both errors return before
/// ensure_root().
#[cfg(feature = "ebpf")]
#[test]
fn router_picks_the_lane_the_target_grammar_names() {
    let bracket = super::super::guarantee::BracketFlags::default();
    // The single lane: the plain target reaches the single lane's
    // own no-rate rung, whose example names the single grammar.
    let single = handle_strict(
        "bash", None, None, None, false, false, false, bracket, None, false,
    )
    .expect_err("the single-lane no-rate case must fail");
    let msg = format!("{single}");
    assert!(
        msg.contains("No rate specified"),
        "the single lane's no-rate error must lead, got: {msg}"
    );
    assert!(
        msg.contains("zelynic strict brave 100kb"),
        "the single lane's example names the single grammar, got: {msg}"
    );
    // The group lane: the '::' list reaches the group lane's own
    // no-rate rung, whose example names the list grammar — a
    // different example string than the single lane's, so the pin
    // proves WHICH lane the router entered.
    let group = handle_strict(
        "bash::curl",
        None,
        None,
        None,
        false,
        false,
        false,
        bracket,
        None,
        false,
    )
    .expect_err("the group-lane no-rate case must fail");
    let msg = format!("{group}");
    assert!(
        msg.contains("No rate specified"),
        "the group lane's no-rate error must lead, got: {msg}"
    );
    assert!(
        msg.contains("zelynic strict brave::curl"),
        "the group lane's example names the '::' grammar, got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "the group lane's input error must precede the root guard, got: {msg}"
    );
}

/// NIGHT-improve-53 (the per-socket scope call): --per-socket is the
/// single lane's shape — the group lane's one shared bucket cannot
/// stack with the per-connection multiplication, and the refusal is
/// the FIRST rung (before the rate parse, the resolve_guarantee
/// precedent: the combination is refused whatever the values would
/// have been). Safe on any uid: the routing error returns before
/// ensure_root().
#[cfg(feature = "ebpf")]
#[test]
fn per_socket_is_refused_on_the_group_lane_before_any_parsing() {
    let err = handle_strict(
        "brave::curl",
        Some("1MB"),
        None,
        None,
        false,
        false,
        true,
        super::super::guarantee::BracketFlags::default(),
        None,
        false,
    )
    .expect_err("per-socket on a list must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("--per-socket is the single-target lane"),
        "the scope refusal must lead, got: {msg}"
    );
    assert!(
        msg.contains("tip: apply the member alone: zelynic s <member> <rate> --per-socket"),
        "the refusal must teach the runnable exit, got: {msg}"
    );
    assert!(
        !msg.contains("Invalid rate"),
        "the scope call precedes the rate parse (a typo'd rate never shadows it), got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "the scope refusal must precede the root guard, got: {msg}"
    );
}
