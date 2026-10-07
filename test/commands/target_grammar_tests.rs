// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The masterclass list-grammar pins (NIGHT-improve-53) — moved out
//! of safety_tests.rs with the fn itself at the target_grammar split.
//! The '::' separator is the law the unified verbs route by; these
//! pins hold every rung of it: the routing test, the fine shapes,
//! the fatal shapes (blade-18's grammar, one separator later), the
//! container refusal, the single-':' member rule, and hunt-30's
//! one-distinct-target refusal in its unified wording.

use super::*;

/// NIGHT-improve-53: the routing law is one substring test — '::'
/// means the group lane, everything else the single lane. The
/// single-lane spellings that carry single colons (the cg: display
/// prefix, both container URI families) can never trip it — that
/// collision-freedom is the reason the separator doubled.
#[test]
fn target_is_list_is_the_double_colon_test() {
    // The group lane.
    assert!(target_is_list("brave::curl"));
    assert!(target_is_list("brave::steam::discord"));
    assert!(target_is_list("cg:1234::1245"));
    assert!(target_is_list("docker://nginx::brave"));
    assert!(
        target_is_list("::brave"),
        "a leading separator still names the lane"
    );
    // The single lane.
    assert!(!target_is_list("brave"));
    assert!(
        !target_is_list("cg:48181"),
        "the display prefix round-trips the single lane"
    );
    assert!(!target_is_list("73386"));
    assert!(
        !target_is_list("docker://nginx"),
        "the container URI owns its single ':' — no '::' substring"
    );
    assert!(
        !target_is_list("k8s://prod/web-abc"),
        "the k8s pod URI owns its single ':' — no '::' substring"
    );
}

/// NIGHT-blade-18's grammar, carried over the separator change: the
/// owner's exact examples are the contract — the fine shapes parse,
/// every fatal shape is named by the grammar. The numeric member's
/// semantics belong to the id guard, not the grammar.
#[test]
fn multi_list_grammar_refuses_the_mistake_shapes() {
    let ex = "zelynic strict brave::curl::pacman 1mb";
    // The fine shapes.
    assert!(
        validate_multi_targets("a::b::c", ex).is_ok(),
        "the plain three-member list"
    );
    assert!(validate_multi_targets("brave::curl::pacman", ex).is_ok());
    assert!(
        validate_multi_targets("  brave :: curl  ", ex).is_ok(),
        "trim is part of the contract"
    );
    assert!(
        validate_multi_targets("x::1", ex).is_ok(),
        "numeric members are grammar-clean; the id guard owns their semantics"
    );
    assert!(
        validate_multi_targets("cg:48181::brave", ex).is_ok(),
        "the display form rides along — the cg: prefix is legal inside a member"
    );
    assert!(
        validate_multi_targets("$(reboot)::b", ex).is_ok(),
        "alnum-bearing garbage keeps the no-execution no-op class the battery pins"
    );
    // The fatal shapes (blade-18's set, one separator later).
    let err = validate_multi_targets("a::a/;/::1", ex).unwrap_err();
    assert!(
        err.to_string().contains("not a valid app name"),
        "the path shape is refused by name: {err}"
    );
    assert!(
        validate_multi_targets("a::::b", ex)
            .unwrap_err()
            .to_string()
            .contains("empty target"),
        "a dropped member is a named mistake, not a silent drop"
    );
    assert!(
        validate_multi_targets("a::", ex)
            .unwrap_err()
            .to_string()
            .contains("empty target"),
        "a trailing separator drops a member the same way"
    );
    assert!(
        validate_multi_targets("x::;;::y", ex)
            .unwrap_err()
            .to_string()
            .contains("not a valid app name"),
        "punctuation-only members can never be a comm"
    );
    assert!(
        validate_multi_targets("a/::b", ex)
            .unwrap_err()
            .to_string()
            .contains("contains '/'"),
        "the path shape names the separator"
    );
    assert!(
        validate_multi_targets("::", ex)
            .unwrap_err()
            .to_string()
            .contains("No targets specified"),
        "the all-empty list keeps the historical error shape"
    );
    assert!(
        validate_multi_targets("  ::  ", ex)
            .unwrap_err()
            .to_string()
            .contains("No targets specified"),
        "whitespace-only members are empty after the contract trim"
    );
}

/// NIGHT-improve-53: a container URI anywhere in the list is a named
/// refusal (charger-core-2's contract, carried over the separator
/// change) — containers are the single lane; the group lane shares
/// one bucket. The refusal names the fix, not the '/' fragment.
#[test]
fn container_targets_do_not_ride_lists() {
    let ex = "zelynic strict brave::curl::pacman 1mb";
    for list in [
        "docker://nginx::brave",
        "brave::docker://nginx",
        "k8s://prod/web-abc::brave::curl",
    ] {
        let err =
            validate_multi_targets(list, ex).expect_err("a container in a list must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("container targets"),
            "the refusal names the container class, got: {msg}"
        );
        assert!(
            msg.contains("do not ride lists"),
            "the refusal names the lane law, got: {msg}"
        );
        assert!(
            msg.contains("no '::' separator"),
            "the refusal teaches the single-lane exit, got: {msg}"
        );
    }
}

/// NIGHT-improve-53: a single ':' inside a member is the prefix
/// grammar's own byte — anything that is not the cg: prefix is the
/// old single-colon list muscle memory half-migrated, and it dies
/// HERE, at the grammar rung, instead of as a late no-match on a
/// process name that can never exist.
#[test]
fn a_single_colon_member_is_the_old_grammar_refused() {
    let ex = "zelynic strict brave::curl::pacman 1mb";
    for list in ["brave:curl::steam", "steam::brave:curl", ":steam::curl"] {
        let err =
            validate_multi_targets(list, ex).expect_err("a single-':' member must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("carries a single ':'"),
            "the refusal names the byte, got: {msg}"
        );
        assert!(
            msg.contains("members separate with '::'"),
            "the refusal teaches the separator, got: {msg}"
        );
    }
    // The cg: prefix stays legal inside a member — numeric or not,
    // it is the prefix grammar's spelling (a non-numeric remainder
    // keeps the single lane's graceful no-match class).
    assert!(validate_multi_targets("cg:48181::cg:48182", ex).is_ok());
    assert!(validate_multi_targets("cg:brave::curl", ex).is_ok());
}

/// NIGHT-hunt-30 (single is single, multi is multi), read through
/// the improve-53 merge: a list carrying ONE distinct target is the
/// right verb wearing a separator it did not need — the refusal
/// names the count and both exits as tips. Every family names itself
/// through the example param.
#[test]
fn multi_list_single_target_needs_no_separator() {
    let ex = "zelynic strict brave::curl::pacman 1mb";
    for one_target in ["brave", " brave ", "brave::brave", "brave :: brave"] {
        let msg = validate_multi_targets(one_target, ex)
            .expect_err("a one-target list must be refused")
            .to_string();
        assert!(
            msg.contains("strict lists need 2 or more distinct targets"),
            "the refusal names the verb and the requirement, got: {msg}"
        );
        assert!(
            msg.contains("a single target needs no separator — 'zelynic strict brave'"),
            "the tip names the separator-free exit, got: {msg}"
        );
    }
    // The sibling verbs name themselves (the example param is the
    // verb's source), so each family's refusal reads its own lane.
    let block = validate_multi_targets("brave", "zelynic block brave::curl::pacman")
        .expect_err("block with one target must be refused")
        .to_string();
    assert!(
        block.contains("block lists need 2 or more distinct targets"),
        "block's refusal names its own verb, got: {block}"
    );
    let unstrict = validate_multi_targets("brave", "zelynic unstrict brave::curl::pacman")
        .expect_err("unstrict with one target must be refused")
        .to_string();
    assert!(
        unstrict.contains("unstrict lists need 2 or more distinct targets"),
        "unstrict's refusal names its own verb, got: {unstrict}"
    );
    // The fine shapes stay fine: two distinct members, either order,
    // numeric or named — the rule counts DISTINCT targets, nothing
    // else about the list changed.
    assert!(validate_multi_targets("brave::curl", ex).is_ok());
    assert!(validate_multi_targets("curl::brave", ex).is_ok());
    assert!(validate_multi_targets("x::1", ex).is_ok());
    assert!(validate_multi_targets("cg:48181::x", ex).is_ok());
}
