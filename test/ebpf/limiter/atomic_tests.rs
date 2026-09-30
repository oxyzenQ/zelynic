// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the atomic multi-target apply (NIGHT-upgrade-
//! charger-core-2, TIER A #6) — the pure decision cores:
//! the pre-flight verdict (one miss aborts the transaction),
//! the abort error's wording (misses named, resolvable
//! remainder counted, "nothing was limited" stated), and the
//! restore decision (a pre-apply raw is restored verbatim, a
//! fresh leg is removed).

use super::*;

fn raw(rate: u64, burst: u64, group: u32) -> PolicyRaw {
    PolicyRaw {
        rate_bps: rate,
        burst_bytes: burst,
        group_id: group,
    }
}

fn seg(label: &str, ids: &[u32]) -> SegmentResolution {
    SegmentResolution {
        label: label.to_string(),
        ids: ids.to_vec(),
    }
}

/// The happy path: every segment resolves, ids collect in order —
/// the transaction proceeds.
#[test]
fn preflight_all_resolving_collects_ids_in_order() {
    let resolutions = [seg("brave", &[7, 8]), seg("cg:48181", &[48181])];
    let ids = preflight(&resolutions).expect("all-resolving list must pass");
    assert_eq!(ids, vec![7, 8, 48181]);
}

/// THE contract: one miss aborts the whole transaction — the error
/// carries the missed labels and NOTHING ELSE (the resolvable ids
/// are never returned partially).
#[test]
fn preflight_one_miss_aborts_whole_transaction() {
    let resolutions = [seg("brave", &[7]), seg("curlx", &[]), seg("cg:9", &[9])];
    let misses = preflight(&resolutions).expect_err("one miss must abort");
    assert_eq!(misses, vec!["curlx".to_string()]);
}

/// A fully-dead list aborts with every label (the all-miss shape).
#[test]
fn preflight_all_missing_aborts_with_every_label() {
    let resolutions = [seg("a", &[]), seg("b", &[])];
    let misses = preflight(&resolutions).expect_err("all-missing list must abort");
    assert_eq!(misses, vec!["a".to_string(), "b".to_string()]);
}

/// Direct cgroup-id segments never miss (resolve_target's direct
/// lane) — the atomic gate only bites on NAME segments, the exact
/// target the spec calls the failure case.
#[test]
fn preflight_direct_id_segments_are_never_misses() {
    let resolutions = [seg("cg:48181", &[48181]), seg("73386", &[73386])];
    assert!(preflight(&resolutions).is_ok());
}

/// The abort error names one miss with singular grammar.
#[test]
fn multi_no_match_line_single_miss() {
    let line = multi_no_match_line(&["curlx".to_string()], 2);
    assert!(
        line.starts_with("target 'curlx' resolved to no cgroup"),
        "single-miss head must name the target, got: {line}"
    );
    assert!(
        line.contains("strict-multi is atomic, nothing was limited"),
        "the atomic contract must be stated, got: {line}"
    );
    assert!(
        line.contains("(2 of 3 targets were resolvable, 0 applied)"),
        "the resolvable remainder and the zero-applied verdict must ride, got: {line}"
    );
    assert!(
        line.contains("tip: try 'zelynic list-apps' to see live targets"),
        "the discovery tip must ride, got: {line}"
    );
}

/// The abort error names several misses with plural grammar and the
/// exact per-target quoting.
#[test]
fn multi_no_match_line_many_misses() {
    let line = multi_no_match_line(&["a".to_string(), "b".to_string()], 1);
    assert!(
        line.starts_with("targets 'a', 'b' resolved to no cgroup"),
        "multi-miss head must name every target, got: {line}"
    );
    assert!(
        line.contains("(1 of 3 targets were resolvable, 0 applied)"),
        "the count is over the whole list, got: {line}"
    );
}

/// An entirely dead list still states the zero-applied verdict.
#[test]
fn multi_no_match_line_zero_resolvable() {
    let line = multi_no_match_line(&["a".to_string()], 0);
    assert!(
        line.contains("(0 of 1 targets were resolvable, 0 applied)"),
        "the all-dead count must stay honest, got: {line}"
    );
}

/// A leg that HAD a policy restores its raw verbatim — rate, burst,
/// and group id, the exact bytes the snapshot read.
#[test]
fn restore_action_restores_pre_apply_raw_verbatim() {
    let mutation = PolicyMutation {
        cgroup_id: 48181,
        direction: Direction::Download,
        previous: Some(raw(100_000, 65_536, 7)),
    };
    match restore_action(&mutation) {
        RestoreAction::Restore(restored) => {
            assert_eq!(restored.rate_bps, 100_000);
            assert_eq!(restored.burst_bytes, 65_536);
            assert_eq!(restored.group_id, 7);
        }
        RestoreAction::Remove => panic!("a leg with a pre-apply raw must RESTORE it"),
    }
}

/// A fresh leg (no pre-apply policy) is REMOVED — the rollback
/// returns the cgroup to unlimited, the state before the apply.
#[test]
fn restore_action_removes_fresh_leg() {
    let mutation = PolicyMutation {
        cgroup_id: 48181,
        direction: Direction::Upload,
        previous: None,
    };
    assert_eq!(
        restore_action(&mutation),
        RestoreAction::Remove,
        "a leg with no pre-apply policy must be removed"
    );
}

/// The mutation's key is the (cgroup, direction) pair the survivor
/// line and the verbose rollback trace print.
#[test]
fn mutation_key_is_the_printed_pair() {
    let mutation = PolicyMutation {
        cgroup_id: 9,
        direction: Direction::Download,
        previous: None,
    };
    assert_eq!(mutation.key(), (9, Direction::Download));
}
