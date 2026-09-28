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
    // NIGHT-dinner-16: the trim contract now REFUSES hollow specs.
    // Whitespace around a slash is legal (trim), an empty segment is
    // the usage error — the blade-18 colon contract mirrored onto the
    // slash grammar: `brave//firefox` used to filter the hollow middle
    // away and silently drop whatever the user meant by the third
    // token.
    let trimmed = parse_target_spec(" brave / firefox ").expect("trim parses");
    assert_eq!(trimmed.len(), 2);
    for empty in ["/", " // "] {
        let err = parse_target_spec(empty).expect_err("an empty spec must fail");
        assert!(
            format!("{err}").contains("No targets in"),
            "the error must name the spec, got: {err}"
        );
    }
    for hollow in ["brave//firefox", "brave/", "/brave", " brave /  / firefox"] {
        let err = parse_target_spec(hollow).expect_err("a hollow spec must fail");
        assert!(
            format!("{err}").contains("empty target in"),
            "the error must name the empty segment, got: {err}"
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

// ── NIGHT-dinner-18: the launch-time liveness gate pins ───────────
//
// resolve_live_targets owns the semantics both eagle-eyes modes lean
// on at the door (the verifier-lineage mandate: a target that names
// nothing is refused, never soft-entered). The pins seed an identity
// map through the cfg(test) insert seam — rootless, deterministic,
// no /proc dependency.

use crate::ebpf::identity::ProcessIdentity;

fn identity_with(comms: &[(&str, u32)]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for (comm, cg) in comms {
        identity.insert(ProcessIdentity {
            cgroup_id: *cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });
    }
    identity
}

/// The liveness verdict per token shape: a live id passes, a dead id
/// misses with its display label, a live name matches
/// case-insensitively, a typo'd name misses — and a cgroup whose comm
/// reads empty is ALIVE (the identity walk's crash-recovery contract:
/// the entry exists for every cgroup carrying a live process, so the
/// gate never refuses a live cgroup for an unreadable name).
#[test]
fn liveness_gate_verdicts_per_token_shape() {
    let identity = identity_with(&[("brave", 7001), ("firefox", 7003)]);
    let mut with_empty_comm = identity_with(&[]);
    with_empty_comm.insert(ProcessIdentity {
        cgroup_id: 18526,
        uid: 1000,
        comm: String::new(),
    });

    // A live id passes.
    let (ids, misses) = resolve_live_targets(&[Target::CgroupId(7001)], &identity);
    assert_eq!(ids, vec![7001]);
    assert!(
        misses.is_empty(),
        "a live id is not a miss, got: {misses:?}"
    );

    // A dead id misses with its display label — the fabricated empty
    // report shape is refused, the strict family's no-match verdict.
    let (ids, misses) = resolve_live_targets(&[Target::CgroupId(99999)], &identity);
    assert!(ids.is_empty());
    assert_eq!(misses, vec!["cg:99999".to_string()]);

    // A live name matches case-insensitively.
    let (ids, misses) = resolve_live_targets(&[Target::ProcessName("BRAVE".into())], &identity);
    assert_eq!(ids, vec![7001]);
    assert!(misses.is_empty());

    // A typo'd name misses by name.
    let (ids, misses) = resolve_live_targets(&[Target::ProcessName("brav".into())], &identity);
    assert!(ids.is_empty());
    assert_eq!(misses, vec!["brav".to_string()]);

    // An empty-comm cgroup is ALIVE (crash-recovery contract).
    let (ids, _) = resolve_live_targets(&[Target::CgroupId(18526)], &with_empty_comm);
    assert_eq!(ids, vec![18526]);
}

/// A mixed spec reports the partial miss alongside the hit — the
/// launch gate's all-miss refusal never fires on a spec with at
/// least one live target (the depth report renders the misses; the
/// live frame notes them in place).
#[test]
fn liveness_gate_reports_partial_misses_alongside_hits() {
    let identity = identity_with(&[("brave", 7001), ("firefox", 7003)]);
    let (ids, misses) = resolve_live_targets(
        &[
            Target::parse("brave"),
            Target::parse("cg:99999"),
            Target::parse("chromium"),
        ],
        &identity,
    );
    assert_eq!(ids, vec![7001]);
    assert_eq!(
        misses,
        vec!["cg:99999".to_string(), "chromium".to_string()],
        "the dead id and the typo'd name both carry their display label"
    );
}

/// The duplicate-token contract (the render twin's false-miss, fixed
/// in the same pass): a repeated name token stays a hit on every
/// copy — the launch gate counts misses per token, so a false miss
/// on the second copy would inflate the miss count toward the
/// all-miss refusal.
#[test]
fn liveness_gate_duplicate_token_is_not_a_false_miss() {
    let identity = identity_with(&[("brave", 7001)]);
    let (ids, misses) =
        resolve_live_targets(&[Target::parse("brave"), Target::parse("brave")], &identity);
    assert_eq!(ids, vec![7001]);
    assert!(misses.is_empty(), "got: {misses:?}");
}
