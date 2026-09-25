// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the eagle-eyes --depth handler (NIGHT-master-1): the
//! shared '/'-separated target grammar both monitor modes speak, and
//! the parse-before-execute ladder — a missing target and an empty
//! spec both surface BEFORE the root guard, so the pins are
//! deterministic on any uid (the same ladder the live monitor's
//! interval/target pins hold).

use super::*;

/// The spec grammar: names, bare ids, and the cg: display prefix
/// round-trip — the same tokens the live monitor parses, extracted
/// here so the two modes can never drift apart.
#[test]
fn spec_parse_accepts_names_ids_and_cg_prefix() {
    let tokens = parse_target_spec("brave/cg:123/456").expect("the mixed spec parses");
    assert_eq!(tokens.len(), 3, "three tokens from three segments");
    match &tokens[0] {
        Target::ProcessName(name) => assert_eq!(name, "brave"),
        other => panic!("a non-numeric token is a process name, got {other:?}"),
    }
    assert!(matches!(tokens[1], Target::CgroupId(123)));
    assert!(matches!(tokens[2], Target::CgroupId(456)));
    // Whitespace-only segments drop; nothing left is the usage error.
    let trimmed = parse_target_spec(" brave // firefox ").expect("trim parses");
    assert_eq!(trimmed.len(), 2);
    for empty in ["/", " // "] {
        let err = parse_target_spec(empty).expect_err("an empty spec must fail");
        assert!(
            format!("{err}").contains("No targets in"),
            "the error must name the spec, got: {err}"
        );
    }
}

/// NIGHT-master-1: --depth with no target is the actionable usage
/// error, BEFORE the privilege guard — the owner's muscle-memory
/// invocation (`zelynic ee --depth`) teaches the target it needs.
#[test]
fn depth_without_target_surfaces_before_root_guard() {
    let err = handle_eagle_eyes_depth(None, false, false).expect_err("no target must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("--depth needs a TARGET"),
        "the error must teach the missing target, got: {msg}"
    );
    assert!(
        msg.contains("zelynic ee 12345 --depth"),
        "the tip must carry a runnable example, got: {msg}"
    );
    assert!(
        !msg.contains("root required"),
        "the usage error must precede the root guard, got: {msg}"
    );
}

/// An empty spec under --depth fails on the shared grammar's error,
/// also before the root guard (the live monitor's own pin shape).
#[test]
fn empty_spec_under_depth_surfaces_before_root_guard() {
    let err = handle_eagle_eyes_depth(Some("/"), false, false).expect_err("empty spec must fail");
    let msg = format!("{err}");
    assert!(msg.contains("No targets in"), "got: {msg}");
    assert!(
        !msg.contains("root required"),
        "the spec error must precede the root guard, got: {msg}"
    );
}
