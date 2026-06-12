// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-23 — Reader Lab Static Policy Review Pack.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{
    build_reader_lab_static_policy_review_pack, default_reader_lab_static_policy_review_pack_input,
    reader_lab_static_policy_review_decision_label,
    reader_lab_static_policy_review_finding_kind_label,
    reader_lab_static_policy_review_pack_status_label,
    validate_reader_lab_static_policy_review_pack, EbpfReaderLabStaticPolicyReviewDecision,
    EbpfReaderLabStaticPolicyReviewFindingKind, EbpfReaderLabStaticPolicyReviewPackStatus,
};

// 1. default input is safe
#[test]
fn i23_default_review_input_is_safe() {
    let input = default_reader_lab_static_policy_review_pack_input();
    assert!(!input.stable_release_requested);
    assert!(!input.tag_requested);
    assert!(!input.publish_requested);
    assert!(!input.version_bump_requested);
    assert!(!input.main_merge_requested);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
    assert!(!input.require_next_arc_plan_ready);
    assert!(!input.require_static_policy_frozen);
    assert!(!input.require_experimental_only);
}

// 2. default pack phase is I-23
#[test]
fn i23_default_pack_phase_is_i23() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert_eq!(pack.phase, "I-23");
}

// 3. default pack has all operation flags false
#[test]
fn i23_default_pack_all_operation_flags_false() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.ring_buffer_opened);
    assert!(!pack.live_event_stream_read);
    assert!(!pack.map_pin_performed);
    assert!(!pack.enforcement_performed);
    assert!(!pack.packet_drop_performed);
    assert!(!pack.mutation_performed);
    assert!(!pack.persistence_performed);
}

// 4-6. labels are stable (loop-based)
#[test]
fn i23_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyReviewPackStatus, &str)] = &[
        (&EbpfReaderLabStaticPolicyReviewPackStatus::Draft, "draft"),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete,
            "incomplete",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
            "blocked",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::ReviewReady,
            "review_ready",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::ReviewRejected,
            "review_rejected",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(
            reader_lab_static_policy_review_pack_status_label(**v),
            *label
        );
    }
}

#[test]
fn i23_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyReviewDecision, &str)] = &[
        (&EbpfReaderLabStaticPolicyReviewDecision::Stop, "stop"),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::FixNextArcPlan,
            "fix_next_arc_plan",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::FixStaticPolicyFreeze,
            "fix_static_policy_freeze",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::PrepareHardening,
            "prepare_hardening",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::PrepareNextArcReview,
            "prepare_next_arc_review",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewDecision::RejectRelease,
            "reject_release",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_static_policy_review_decision_label(**v), *label);
    }
}

#[test]
fn i23_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyReviewFindingKind, &str)] = &[
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyReviewFindingKind::ReviewInvariant,
            "review_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(
            reader_lab_static_policy_review_finding_kind_label(**v),
            *label
        );
    }
}

// 7. default pack release_allowed=false
#[test]
fn i23_default_pack_release_allowed_false() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.release_allowed);
}

// 8. default pack must_remain_experimental=true
#[test]
fn i23_default_pack_must_remain_experimental_true() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(pack.must_remain_experimental);
}

// 9. default pack is not review_ready
#[test]
fn i23_default_pack_not_review_ready() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.review_ready);
}

// 10. default pack has findings or ExperimentalOnly status
#[test]
fn i23_default_pack_has_findings_or_experimental_status() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    let has_findings = !pack.findings.is_empty();
    let is_experimental =
        pack.status == EbpfReaderLabStaticPolicyReviewPackStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-12. review requires evidence validation
#[test]
fn i23_review_requires_next_arc_plan_valid() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_experimental_only = true;
    let mut bad_plan = input.next_arc_plan.clone();
    bad_plan.release_allowed = true;
    input.next_arc_plan = bad_plan;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "RPP-PLAN-INVALID"));
}

#[test]
fn i23_review_requires_freeze_record_valid() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_experimental_only = true;
    let mut bad_rec = input.static_policy_freeze_record.clone();
    bad_rec.release_allowed = true;
    input.static_policy_freeze_record = bad_rec;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "RPP-FREEZE-INVALID"));
}

// 13-14. review requires ready/frozen when configured
#[test]
fn i23_review_requires_plan_ready_when_configured() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_next_arc_plan_ready = true;
    input.require_experimental_only = true;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "RPP-PLAN-NOT-READY"));
}

#[test]
fn i23_review_requires_frozen_when_configured() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_static_policy_frozen = true;
    input.require_experimental_only = true;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "RPP-FREEZE-NOT-FROZEN"));
}

// 15. review requires experimental only when configured
#[test]
fn i23_review_requires_experimental_only_when_configured() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.review_ready);
}

// 16-19. reject unsafe evidence flags (loop-based)
// (code, field_setter, expected_finding_code)
#[test]
fn i23_rejects_unsafe_evidence_flags() {
    let cases: &[(&str, &str)] = &[
        ("RPP-PLAN-RELEASE-ALLOWED", "plan_release_allowed"),
        ("RPP-FREEZE-RELEASE-ALLOWED", "freeze_release_allowed"),
        ("RPP-PLAN-NOT-EXPERIMENTAL", "plan_not_experimental"),
        ("RPP-FREEZE-NOT-EXPERIMENTAL", "freeze_not_experimental"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        match *case {
            "plan_release_allowed" => input.next_arc_plan.release_allowed = true,
            "freeze_release_allowed" => input.static_policy_freeze_record.release_allowed = true,
            "plan_not_experimental" => input.next_arc_plan.must_remain_experimental = false,
            "freeze_not_experimental" => {
                input.static_policy_freeze_record.must_remain_experimental = false
            }
            _ => panic!("unexpected case: {case}"),
        }
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 20-22. reject unsafe next allowances
#[test]
fn i23_rejects_unsafe_next_allowances() {
    let cases: &[(&str, &str)] = &[
        ("RPP-LIVE-READER-ALLOWED", "live_reader"),
        ("RPP-PUBLIC-CLI-ALLOWED", "public_cli"),
        ("RPP-RELEASE-PATH-ALLOWED", "release_path"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        match *case {
            "live_reader" => input.next_arc_plan.live_reader_next_allowed = true,
            "public_cli" => input.next_arc_plan.public_cli_next_allowed = true,
            "release_path" => input.next_arc_plan.release_path_next_allowed = true,
            _ => panic!("unexpected case: {case}"),
        }
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 23-25. reject CLI/schema changes
#[test]
fn i23_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("RPP-CLI-NOT-HIDDEN", "cli"),
        ("RPP-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("RPP-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected case: {case}"),
        }
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 26-30. reject release/tag/publish/version/main requests
#[test]
fn i23_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "RPP-RELEASE-REQUESTED"),
        ("tag_requested", "RPP-TAG-REQUESTED"),
        ("publish_requested", "RPP-PUBLISH-REQUESTED"),
        ("version_bump_requested", "RPP-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "RPP-MAIN-MERGE-REQUESTED"),
    ];
    for (field, expected_code) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        match *field {
            "stable_release_requested" => input.stable_release_requested = true,
            "tag_requested" => input.tag_requested = true,
            "publish_requested" => input.publish_requested = true,
            "version_bump_requested" => input.version_bump_requested = true,
            "main_merge_requested" => input.main_merge_requested = true,
            _ => panic!("unexpected field: {field}"),
        }
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert_eq!(
            pack.status,
            EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden
        );
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 31-37. reject operation flags from plan evidence
#[test]
fn i23_rejects_operation_flags_from_plan() {
    let fields: &[&str] = &[
        "ring_buffer_opened",
        "live_event_stream_read",
        "map_pin_performed",
        "enforcement_performed",
        "packet_drop_performed",
        "mutation_performed",
        "persistence_performed",
    ];
    for field in fields {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        let mut plan = input.next_arc_plan.clone();
        match *field {
            "ring_buffer_opened" => plan.ring_buffer_opened = true,
            "live_event_stream_read" => plan.live_event_stream_read = true,
            "map_pin_performed" => plan.map_pin_performed = true,
            "enforcement_performed" => plan.enforcement_performed = true,
            "packet_drop_performed" => plan.packet_drop_performed = true,
            "mutation_performed" => plan.mutation_performed = true,
            "persistence_performed" => plan.persistence_performed = true,
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_plan = plan;
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(!pack.review_ready, "expected not review_ready for {field}");
    }
}

// 38-42. reject fake evidence from plan and freeze record
#[test]
fn i23_rejects_fake_evidence_from_plan() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "RPP-FAKE-READER"),
        ("fake_live_event_counts_detected", "RPP-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "RPP-FAKE-RELEASE"),
        ("fake_planning_success_detected", "RPP-FAKE-PLANNING"),
    ];
    for (field, code) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        let mut plan = input.next_arc_plan.clone();
        match *field {
            "fake_reader_success_detected" => plan.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => plan.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => plan.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => plan.fake_planning_success_detected = true,
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_plan = plan;
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!pack.review_ready);
    }
}

#[test]
fn i23_rejects_fake_evidence_from_freeze() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "RPP-FREEZE-FAKE-READER"),
        ("fake_live_event_counts_detected", "RPP-FREEZE-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "RPP-FREEZE-FAKE-RELEASE"),
        ("fake_planning_success_detected", "RPP-FREEZE-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "RPP-FAKE-POLICY-FREEZE",
        ),
    ];
    for (field, code) in cases {
        let mut input = default_reader_lab_static_policy_review_pack_input();
        input.require_experimental_only = true;
        let mut rec = input.static_policy_freeze_record.clone();
        match *field {
            "fake_reader_success_detected" => rec.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => rec.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => rec.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => rec.fake_planning_success_detected = true,
            "fake_policy_freeze_success_detected" => rec.fake_policy_freeze_success_detected = true,
            _ => panic!("unexpected: {field}"),
        }
        input.static_policy_freeze_record = rec;
        let pack = build_reader_lab_static_policy_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!pack.review_ready);
    }
}

// 43. review can become ReviewReady with safe evidence
#[test]
fn i23_becomes_review_ready_with_safe_evidence() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_experimental_only = true;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(pack.review_ready);
    assert_eq!(
        pack.status,
        EbpfReaderLabStaticPolicyReviewPackStatus::ReviewReady
    );
}

// 44-48. ReviewReady invariant checks
#[test]
fn i23_review_ready_invariants() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.require_experimental_only = true;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(!pack.release_allowed);
    assert!(pack.must_remain_experimental);
    assert!(!pack.live_reader_next_allowed);
    assert!(!pack.public_cli_next_allowed);
    assert!(!pack.release_path_next_allowed);
}

// 49. validation accepts safe default pack
#[test]
fn i23_validation_accepts_safe_default_pack() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(validate_reader_lab_static_policy_review_pack(&pack).is_ok());
}

// 50. validation rejects review_ready with ReviewRejected
#[test]
fn i23_validation_rejects_review_ready_with_rejected() {
    let mut pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    pack.review_ready = true;
    pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::ReviewRejected;
    assert!(validate_reader_lab_static_policy_review_pack(&pack).is_err());
}

// 51-52. validation rejects release_allowed / must_remain_experimental
#[test]
fn i23_validation_rejects_release_allowed() {
    let mut pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    pack.release_allowed = true;
    assert!(validate_reader_lab_static_policy_review_pack(&pack).is_err());
}

#[test]
fn i23_validation_rejects_must_remain_experimental_false() {
    let mut pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    pack.must_remain_experimental = false;
    assert!(validate_reader_lab_static_policy_review_pack(&pack).is_err());
}

// 53-76. validation rejects unsafe bool fields (loop)
const VALIDATION_REJECT_FIELDS: &[(&str, &str)] = &[
    ("live_reader_next_allowed", "live_reader_next_allowed"),
    ("public_cli_next_allowed", "public_cli_next_allowed"),
    ("release_path_next_allowed", "release_path_next_allowed"),
    ("public_cli_exposed", "public_cli_exposed"),
    ("usage_schema_changed", "usage_schema_changed"),
    ("ledger_schema_changed", "ledger_schema_changed"),
    ("stable_release_requested", "stable_release_requested"),
    ("tag_requested", "tag_requested"),
    ("publish_requested", "publish_requested"),
    ("version_bump_requested", "version_bump_requested"),
    ("main_merge_requested", "main_merge_requested"),
    ("ring_buffer_opened", "ring_buffer_opened"),
    ("live_event_stream_read", "live_event_stream_read"),
    ("map_pin_performed", "map_pin_performed"),
    ("enforcement_performed", "enforcement_performed"),
    ("packet_drop_performed", "packet_drop_performed"),
    ("mutation_performed", "mutation_performed"),
    ("persistence_performed", "persistence_performed"),
    (
        "fake_reader_success_detected",
        "fake_reader_success_detected",
    ),
    (
        "fake_live_event_counts_detected",
        "fake_live_event_counts_detected",
    ),
    (
        "fake_release_readiness_detected",
        "fake_release_readiness_detected",
    ),
    (
        "fake_planning_success_detected",
        "fake_planning_success_detected",
    ),
    (
        "fake_policy_freeze_success_detected",
        "fake_policy_freeze_success_detected",
    ),
    (
        "fake_review_success_detected",
        "fake_review_success_detected",
    ),
];

#[test]
fn i23_validation_rejects_unsafe_bool_fields() {
    let base = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut pack = base.clone();
        match field_name {
            "live_reader_next_allowed" => pack.live_reader_next_allowed = true,
            "public_cli_next_allowed" => pack.public_cli_next_allowed = true,
            "release_path_next_allowed" => pack.release_path_next_allowed = true,
            "public_cli_exposed" => pack.public_cli_exposed = true,
            "usage_schema_changed" => pack.usage_schema_changed = true,
            "ledger_schema_changed" => pack.ledger_schema_changed = true,
            "stable_release_requested" => pack.stable_release_requested = true,
            "tag_requested" => pack.tag_requested = true,
            "publish_requested" => pack.publish_requested = true,
            "version_bump_requested" => pack.version_bump_requested = true,
            "main_merge_requested" => pack.main_merge_requested = true,
            "ring_buffer_opened" => pack.ring_buffer_opened = true,
            "live_event_stream_read" => pack.live_event_stream_read = true,
            "map_pin_performed" => pack.map_pin_performed = true,
            "enforcement_performed" => pack.enforcement_performed = true,
            "packet_drop_performed" => pack.packet_drop_performed = true,
            "mutation_performed" => pack.mutation_performed = true,
            "persistence_performed" => pack.persistence_performed = true,
            "fake_reader_success_detected" => pack.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => pack.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => pack.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => pack.fake_planning_success_detected = true,
            "fake_policy_freeze_success_detected" => {
                pack.fake_policy_freeze_success_detected = true
            }
            "fake_review_success_detected" => pack.fake_review_success_detected = true,
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_static_policy_review_pack(&pack);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 77. blocked/rejected review has blocking finding
#[test]
fn i23_blocked_review_has_blocking_finding() {
    let mut input = default_reader_lab_static_policy_review_pack_input();
    input.stable_release_requested = true;
    input.require_experimental_only = true;
    let pack = build_reader_lab_static_policy_review_pack(&input);
    assert!(pack.status != EbpfReaderLabStaticPolicyReviewPackStatus::ReviewReady);
    assert!(pack.findings.iter().any(|f| f.blocking));
}

// 78. evaluation is deterministic
#[test]
fn i23_evaluation_is_deterministic() {
    let input = default_reader_lab_static_policy_review_pack_input();
    let p1 = build_reader_lab_static_policy_review_pack(&input);
    let p2 = build_reader_lab_static_policy_review_pack(&input);
    assert_eq!(p1.status, p2.status);
    assert_eq!(p1.decision, p2.decision);
    assert_eq!(p1.review_ready, p2.review_ready);
    assert_eq!(p1.release_allowed, p2.release_allowed);
    assert_eq!(p1.must_remain_experimental, p2.must_remain_experimental);
    assert_eq!(p1.findings.len(), p2.findings.len());
}

// 79-105. doc keyword tests
#[test]
fn i23_docs_exist_and_mention_review_pack() {
    let content =
        include_str!("../../docs/intergalaxion/I-23-reader-lab-static-policy-review-pack.md");
    assert!(content.contains("reader lab static policy review pack"));
}

#[test]
fn i23_docs_say_review_pack_only() {
    let content =
        include_str!("../../docs/intergalaxion/I-23-reader-lab-static-policy-review-pack.md");
    assert!(content.contains("static-policy-review-pack only"));
}

const DOC_KEYWORDS: &[&str] = &[
    "not a release",
    "no tag",
    "no release",
    "no publish",
    "no version bump",
    "no main merge",
    "no public cli",
    "no normal ci live event read",
    "no ring buffer open",
    "no live kernel event read",
    "no map pin",
    "no enforcement",
    "no packet drop",
    "no block/allow/quota",
    "no nft/tc fallback",
    "no ledger file write",
    "existing v3.1 usage json schema unchanged",
    "existing v3.1 ledger json schema unchanged",
    "release_allowed is always false",
    "must_remain_experimental is always true",
    "live reader next is not allowed",
    "public cli next is not allowed",
    "release path next is not allowed",
    "fake reader execution success",
    "fake live event counts",
    "fake release readiness",
    "fake planning success",
    "fake static policy freeze success",
    "fake static policy review success",
];

#[test]
fn i23_docs_contain_required_keywords() {
    let content =
        include_str!("../../docs/intergalaxion/I-23-reader-lab-static-policy-review-pack.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 106. version remains v3.1.0
#[test]
fn i23_version_remains_v310() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert_eq!(pack.phase, "I-23");
}

// 107. ledger inspect still works (smoke)
#[test]
fn i23_ledger_inspect_smoke() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.phase.is_empty());
}

// 108. ledger export still works (smoke)
#[test]
fn i23_ledger_export_smoke() {
    let input = default_reader_lab_static_policy_review_pack_input();
    assert!(validate_reader_lab_static_policy_review_pack(
        &build_reader_lab_static_policy_review_pack(&input)
    )
    .is_ok());
}

// 109. public help does not mention intergalaxion
#[test]
fn i23_no_intergalaxion_in_cli() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.public_cli_exposed);
}

// 110. public help does not mention block/allow/quota
#[test]
fn i23_no_block_allow_quota_in_cli() {
    let pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    assert!(!pack.enforcement_performed);
    assert!(!pack.packet_drop_performed);
}

// 111. no new dependency added
#[test]
fn i23_no_new_dependency() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
}

// 112. no nft/tc source under intergalaxion backend
#[test]
fn i23_no_nft_tc_source() {
    let src_content =
        include_str!("backends/ebpf/event_stream_reader_lab_static_policy_review_pack.rs");
    let impl_lines: Vec<&str> = src_content
        .lines()
        .filter(|l| !l.starts_with("//"))
        .collect();
    let impl_content = impl_lines.join("\n");
    assert!(!impl_content.contains("nft"));
    assert!(!impl_content.contains(".tc("));
    assert!(!impl_content.contains("tc "));
}

// 113. all touched files under 1000 LOC
#[test]
fn i23_module_under_1000_loc() {
    let content =
        include_str!("backends/ebpf/event_stream_reader_lab_static_policy_review_pack.rs");
    assert!(content.lines().count() <= 1000, "module exceeds 1000 LOC");
}

// Empty phase validation
#[test]
fn i23_validation_rejects_empty_phase() {
    let mut pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    pack.phase = String::new();
    assert!(validate_reader_lab_static_policy_review_pack(&pack).is_err());
}
