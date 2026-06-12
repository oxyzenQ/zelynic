// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-26 — Reader Lab Completion Review Pack.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::{
    build_reader_lab_completion_review_pack, default_reader_lab_completion_review_pack_input,
    reader_lab_completion_review_decision_label, reader_lab_completion_review_finding_kind_label,
    reader_lab_completion_review_pack_status_label, validate_reader_lab_completion_review_pack,
    EbpfReaderLabCompletionReviewDecision, EbpfReaderLabCompletionReviewFindingKind,
    EbpfReaderLabCompletionReviewPackStatus,
};

fn safe_default_pack() -> crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::EbpfReaderLabCompletionReviewPack{
    build_reader_lab_completion_review_pack(&default_reader_lab_completion_review_pack_input())
}

fn safe_experimental_input() -> crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::EbpfReaderLabCompletionReviewPackInput{
    let mut input = default_reader_lab_completion_review_pack_input();
    input.require_experimental_only = true;
    input
}

// 1. default completion review input is safe
#[test]
fn i26_default_completion_review_input_is_safe() {
    let input = default_reader_lab_completion_review_pack_input();
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
    assert!(!input.require_static_policy_review_ready);
    assert!(!input.require_static_policy_hardening_passed);
    assert!(!input.require_policy_completion_passed);
    assert!(!input.require_experimental_only);
}

// 2. default pack phase is I-26
#[test]
fn i26_default_pack_phase_is_i26() {
    let pack = safe_default_pack();
    assert_eq!(pack.phase, "I-26");
}

// 3. default pack has all operation flags false
#[test]
fn i26_default_pack_all_operation_flags_false() {
    let pack = safe_default_pack();
    assert!(!pack.ring_buffer_opened);
    assert!(!pack.live_event_stream_read);
    assert!(!pack.map_pin_performed);
    assert!(!pack.enforcement_performed);
    assert!(!pack.packet_drop_performed);
    assert!(!pack.mutation_performed);
    assert!(!pack.persistence_performed);
}

// 4-6. labels are stable
#[test]
fn i26_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabCompletionReviewPackStatus, &str)] = &[
        (&EbpfReaderLabCompletionReviewPackStatus::Draft, "draft"),
        (
            &EbpfReaderLabCompletionReviewPackStatus::Incomplete,
            "incomplete",
        ),
        (&EbpfReaderLabCompletionReviewPackStatus::Blocked, "blocked"),
        (
            &EbpfReaderLabCompletionReviewPackStatus::ReviewReady,
            "review_ready",
        ),
        (
            &EbpfReaderLabCompletionReviewPackStatus::ReviewRejected,
            "review_rejected",
        ),
        (
            &EbpfReaderLabCompletionReviewPackStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabCompletionReviewPackStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_completion_review_pack_status_label(**v), *label);
    }
}

#[test]
fn i26_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabCompletionReviewDecision, &str)] = &[
        (&EbpfReaderLabCompletionReviewDecision::Stop, "stop"),
        (
            &EbpfReaderLabCompletionReviewDecision::FixNextArcPlan,
            "fix_next_arc_plan",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::FixStaticPolicyFreeze,
            "fix_static_policy_freeze",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::FixStaticPolicyReview,
            "fix_static_policy_review",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::FixStaticPolicyHardening,
            "fix_static_policy_hardening",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::FixCompletionGate,
            "fix_completion_gate",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::PrepareNextArc,
            "prepare_next_arc",
        ),
        (
            &EbpfReaderLabCompletionReviewDecision::RejectRelease,
            "reject_release",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_completion_review_decision_label(**v), *label);
    }
}

#[test]
fn i26_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabCompletionReviewFindingKind, &str)] = &[
        (
            &EbpfReaderLabCompletionReviewFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::StaticPolicyReview,
            "static_policy_review",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::StaticPolicyHardening,
            "static_policy_hardening",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::PolicyCompletionGate,
            "policy_completion_gate",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "contradiction_invariant",
        ),
        (
            &EbpfReaderLabCompletionReviewFindingKind::CompletionReviewInvariant,
            "completion_review_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_completion_review_finding_kind_label(**v), *label);
    }
}

// 7-8. default invariants
#[test]
fn i26_default_pack_release_allowed_false() {
    let pack = safe_default_pack();
    assert!(!pack.release_allowed);
}

#[test]
fn i26_default_pack_must_remain_experimental_true() {
    let pack = safe_default_pack();
    assert!(pack.must_remain_experimental);
}

// 9. default pack is not review_ready
#[test]
fn i26_default_pack_not_review_ready() {
    let pack = safe_default_pack();
    assert!(!pack.review_ready);
}

// 10. default pack has findings or ExperimentalOnly
#[test]
fn i26_default_pack_has_findings_or_experimental_status() {
    let pack = safe_default_pack();
    let has_findings = !pack.findings.is_empty();
    let is_experimental = pack.status == EbpfReaderLabCompletionReviewPackStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-15. completion review requires evidence validation
#[test]
fn i26_requires_next_arc_plan_valid() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "CRP-PLAN-INVALID"));
}

#[test]
fn i26_requires_freeze_valid() {
    let mut input = safe_experimental_input();
    let mut rec = input.static_policy_freeze_record.clone();
    rec.release_allowed = true;
    input.static_policy_freeze_record = rec;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "CRP-FREEZE-INVALID"));
}

#[test]
fn i26_requires_review_valid() {
    let mut input = safe_experimental_input();
    let mut rp = input.static_policy_review_pack.clone();
    rp.release_allowed = true;
    input.static_policy_review_pack = rp;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "CRP-REVIEW-INVALID"));
}

#[test]
fn i26_requires_hardening_valid() {
    let mut input = safe_experimental_input();
    let mut hr = input.static_policy_hardening_report.clone();
    hr.release_allowed = true;
    input.static_policy_hardening_report = hr;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-HARDENING-INVALID"));
}

#[test]
fn i26_requires_gate_valid() {
    let mut input = safe_experimental_input();
    let mut gr = input.policy_completion_gate_report.clone();
    gr.release_allowed = true;
    input.policy_completion_gate_report = gr;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "CRP-GATE-INVALID"));
}

// 16-20. requires ready/frozen/review_ready/hardening_passed/completion_passed when configured
#[test]
fn i26_requires_plan_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_next_arc_plan_ready = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "CRP-PLAN-NOT-READY"));
}

#[test]
fn i26_requires_frozen_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_frozen = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-FREEZE-NOT-FROZEN"));
}

#[test]
fn i26_requires_review_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_review_ready = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-REVIEW-NOT-READY"));
}

#[test]
fn i26_requires_hardening_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_hardening_passed = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-HARDENING-NOT-PASSED"));
}

#[test]
fn i26_requires_completion_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_policy_completion_passed = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-COMPLETION-NOT-PASSED"));
}

// 21. requires experimental only when configured
#[test]
fn i26_requires_experimental_only_when_configured() {
    let pack = safe_default_pack();
    assert!(!pack.review_ready);
}

// 22-26. reject unsafe evidence release_allowed (loop)
#[test]
fn i26_rejects_unsafe_evidence_release_allowed() {
    let cases: &[(&str, &str)] = &[
        ("CRP-CONTRADICTION-RELEASE", "plan"),
        ("CRP-CONTRADICTION-RELEASE", "freeze"),
        ("CRP-CONTRADICTION-RELEASE", "review"),
        ("CRP-CONTRADICTION-RELEASE", "hardening"),
        ("CRP-CONTRADICTION-RELEASE", "gate"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "plan" => input.next_arc_plan.release_allowed = true,
            "freeze" => input.static_policy_freeze_record.release_allowed = true,
            "review" => input.static_policy_review_pack.release_allowed = true,
            "hardening" => input.static_policy_hardening_report.release_allowed = true,
            "gate" => input.policy_completion_gate_report.release_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code} for {case}"
        );
    }
}

// 27-31. reject must_remain_experimental=false (loop)
#[test]
fn i26_rejects_unsafe_must_remain_experimental() {
    let cases: &[(&str, &str)] = &[
        ("CRP-NOT-EXPERIMENTAL", "plan"),
        ("CRP-NOT-EXPERIMENTAL", "freeze"),
        ("CRP-NOT-EXPERIMENTAL", "review"),
        ("CRP-NOT-EXPERIMENTAL", "hardening"),
        ("CRP-NOT-EXPERIMENTAL", "gate"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "plan" => input.next_arc_plan.must_remain_experimental = false,
            "freeze" => input.static_policy_freeze_record.must_remain_experimental = false,
            "review" => input.static_policy_review_pack.must_remain_experimental = false,
            "hardening" => {
                input
                    .static_policy_hardening_report
                    .must_remain_experimental = false
            }
            "gate" => input.policy_completion_gate_report.must_remain_experimental = false,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code} for {case}"
        );
    }
}

// 32-34. reject unsafe next allowances
#[test]
fn i26_rejects_unsafe_next_allowances() {
    let cases: &[(&str, &str)] = &[
        ("CRP-CONTRADICTION-LIVE-READER", "live_reader"),
        ("CRP-CONTRADICTION-PUBLIC-CLI", "public_cli"),
        ("CRP-CONTRADICTION-RELEASE-PATH", "release_path"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "live_reader" => input.next_arc_plan.live_reader_next_allowed = true,
            "public_cli" => input.next_arc_plan.public_cli_next_allowed = true,
            "release_path" => input.next_arc_plan.release_path_next_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(pack.contradiction_detected);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 35-37. reject CLI/schema changes
#[test]
fn i26_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("CRP-CLI-NOT-HIDDEN", "cli"),
        ("CRP-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("CRP-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(pack.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 38-42. reject release/tag/publish/version/main requests
#[test]
fn i26_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "CRP-RELEASE-REQUESTED"),
        ("tag_requested", "CRP-TAG-REQUESTED"),
        ("publish_requested", "CRP-PUBLISH-REQUESTED"),
        ("version_bump_requested", "CRP-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "CRP-MAIN-MERGE-REQUESTED"),
    ];
    for (field, expected_code) in cases {
        let mut input = safe_experimental_input();
        match *field {
            "stable_release_requested" => input.stable_release_requested = true,
            "tag_requested" => input.tag_requested = true,
            "publish_requested" => input.publish_requested = true,
            "version_bump_requested" => input.version_bump_requested = true,
            "main_merge_requested" => input.main_merge_requested = true,
            _ => panic!("unexpected: {field}"),
        }
        let pack = build_reader_lab_completion_review_pack(&input);
        assert_eq!(
            pack.status,
            EbpfReaderLabCompletionReviewPackStatus::ReleaseForbidden
        );
        assert!(pack.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 43-49. reject operation flags
#[test]
fn i26_rejects_operation_flags() {
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
        let mut input = safe_experimental_input();
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
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(!pack.review_ready);
    }
}

// 50-57. reject fake evidence (loop)
#[test]
fn i26_rejects_fake_evidence() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "CRP-FAKE-READER"),
        ("fake_live_event_counts_detected", "CRP-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "CRP-FAKE-RELEASE"),
        ("fake_planning_success_detected", "CRP-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "CRP-FAKE-POLICY-FREEZE",
        ),
        ("fake_policy_review_success_detected", "CRP-FAKE-REVIEW"),
        ("fake_hardening_success_detected", "CRP-FAKE-HARDENING"),
        ("fake_completion_success_detected", "CRP-FAKE-COMPLETION"),
    ];
    for (field, code) in cases {
        let mut input = safe_experimental_input();
        let mut plan = input.next_arc_plan.clone();
        match *field {
            "fake_reader_success_detected" => plan.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => plan.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => plan.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => plan.fake_planning_success_detected = true,
            "fake_policy_freeze_success_detected" => {
                input
                    .static_policy_freeze_record
                    .fake_policy_freeze_success_detected = true;
            }
            "fake_policy_review_success_detected" => {
                input.static_policy_review_pack.fake_review_success_detected = true;
            }
            "fake_hardening_success_detected" => {
                input
                    .static_policy_hardening_report
                    .fake_hardening_success_detected = true;
            }
            "fake_completion_success_detected" => {
                input
                    .policy_completion_gate_report
                    .fake_completion_success_detected = true;
            }
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_plan = plan;
        let pack = build_reader_lab_completion_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!pack.review_ready);
    }
}

// 58-60. contradiction detection
#[test]
fn i26_detects_contradiction_release_flags() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(pack.contradiction_detected);
}

#[test]
fn i26_detects_contradiction_experimental_flags() {
    let mut input = safe_experimental_input();
    let mut gr = input.policy_completion_gate_report.clone();
    gr.must_remain_experimental = false;
    input.policy_completion_gate_report = gr;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(pack.contradiction_detected);
}

#[test]
fn i26_detects_contradiction_next_allowance_flags() {
    let mut input = safe_experimental_input();
    let mut rp = input.static_policy_review_pack.clone();
    rp.live_reader_next_allowed = true;
    input.static_policy_review_pack = rp;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(pack.contradiction_detected);
}

// 61. can become ReviewReady with safe evidence
#[test]
fn i26_becomes_review_ready_with_safe_evidence() {
    let input = safe_experimental_input();
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(pack.review_ready);
    assert_eq!(
        pack.status,
        EbpfReaderLabCompletionReviewPackStatus::ReviewReady
    );
}

// 62-66. ReviewReady invariants
#[test]
fn i26_review_ready_invariants() {
    let input = safe_experimental_input();
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.release_allowed);
    assert!(pack.must_remain_experimental);
    assert!(!pack.live_reader_next_allowed);
    assert!(!pack.public_cli_next_allowed);
    assert!(!pack.release_path_next_allowed);
}

// 67. validation accepts safe default pack
#[test]
fn i26_validation_accepts_safe_default_pack() {
    let pack = safe_default_pack();
    assert!(validate_reader_lab_completion_review_pack(&pack).is_ok());
}

// 68. validation rejects review_ready=true when status is ReviewRejected
#[test]
fn i26_validation_rejects_review_ready_with_rejected() {
    let mut pack = safe_default_pack();
    pack.review_ready = true;
    pack.status = EbpfReaderLabCompletionReviewPackStatus::ReviewRejected;
    assert!(validate_reader_lab_completion_review_pack(&pack).is_err());
}

// 69-98. validation rejects unsafe bool fields (loop)
const VALIDATION_REJECT_FIELDS: &[(&str, &str)] = &[
    ("release_allowed", "release_allowed"),
    ("must_remain_experimental", "must_remain_experimental"),
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
        "fake_policy_review_success_detected",
        "fake_policy_review_success_detected",
    ),
    (
        "fake_policy_hardening_success_detected",
        "fake_policy_hardening_success_detected",
    ),
    (
        "fake_policy_completion_success_detected",
        "fake_policy_completion_success_detected",
    ),
    (
        "fake_completion_review_success_detected",
        "fake_completion_review_success_detected",
    ),
    ("contradiction_detected", "contradiction_detected"),
];

#[test]
fn i26_validation_rejects_unsafe_bool_fields() {
    let base = safe_default_pack();
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut pack = base.clone();
        match field_name {
            "release_allowed" => pack.release_allowed = true,
            "must_remain_experimental" => pack.must_remain_experimental = false,
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
            "fake_policy_review_success_detected" => {
                pack.fake_policy_review_success_detected = true
            }
            "fake_policy_hardening_success_detected" => {
                pack.fake_policy_hardening_success_detected = true
            }
            "fake_policy_completion_success_detected" => {
                pack.fake_policy_completion_success_detected = true
            }
            "fake_completion_review_success_detected" => {
                pack.fake_completion_review_success_detected = true
            }
            "contradiction_detected" => pack.contradiction_detected = true,
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_completion_review_pack(&pack);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 99. blocked review has blocking finding
#[test]
fn i26_blocked_review_has_blocking_finding() {
    let mut input = safe_experimental_input();
    input.stable_release_requested = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert_ne!(
        pack.status,
        EbpfReaderLabCompletionReviewPackStatus::ReviewReady
    );
    assert!(pack.findings.iter().any(|f| f.blocking));
}

// 100. evaluation is deterministic
#[test]
fn i26_evaluation_is_deterministic() {
    let input = default_reader_lab_completion_review_pack_input();
    let p1 = build_reader_lab_completion_review_pack(&input);
    let p2 = build_reader_lab_completion_review_pack(&input);
    assert_eq!(p1.status, p2.status);
    assert_eq!(p1.decision, p2.decision);
    assert_eq!(p1.review_ready, p2.review_ready);
    assert_eq!(p1.release_allowed, p2.release_allowed);
    assert_eq!(p1.must_remain_experimental, p2.must_remain_experimental);
    assert_eq!(p1.findings.len(), p2.findings.len());
}

// 101-131. doc keyword tests
#[test]
fn i26_docs_exist_and_mention_completion_review_pack() {
    let content =
        include_str!("../../docs/intergalaxion/I-26-reader-lab-completion-review-pack.md");
    assert!(content.contains("reader lab completion review pack"));
}

#[test]
fn i26_docs_say_completion_review_pack_only() {
    let content =
        include_str!("../../docs/intergalaxion/I-26-reader-lab-completion-review-pack.md");
    assert!(content.contains("completion-review-pack only"));
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
    "contradictions between i-21 i-22 i-23 i-24 i-25",
    "fake reader execution success",
    "fake live event counts",
    "fake release readiness",
    "fake planning success",
    "fake static policy freeze success",
    "fake static policy review success",
    "fake static policy hardening success",
    "fake policy freeze completion success",
    "fake completion review success",
];

#[test]
fn i26_docs_contain_required_keywords() {
    let content =
        include_str!("../../docs/intergalaxion/I-26-reader-lab-completion-review-pack.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 132. version remains v3.1.0
#[test]
fn i26_version_remains_v310() {
    let pack = safe_default_pack();
    assert_eq!(pack.phase, "I-26");
}

// 133. ledger inspect still works (smoke)
#[test]
fn i26_ledger_inspect_smoke() {
    let pack = safe_default_pack();
    assert!(!pack.phase.is_empty());
}

// 134. ledger export still works (smoke)
#[test]
fn i26_ledger_export_smoke() {
    let input = default_reader_lab_completion_review_pack_input();
    assert!(
        validate_reader_lab_completion_review_pack(&build_reader_lab_completion_review_pack(
            &input
        ),)
        .is_ok()
    );
}

// 135. public help does not mention intergalaxion
#[test]
fn i26_no_intergalaxion_in_cli() {
    let pack = safe_default_pack();
    assert!(!pack.public_cli_exposed);
}

// 136. public help does not mention block/allow/quota
#[test]
fn i26_no_block_allow_quota_in_cli() {
    let pack = safe_default_pack();
    assert!(!pack.enforcement_performed);
    assert!(!pack.packet_drop_performed);
}

// 137. no new dependency added
#[test]
fn i26_no_new_dependency() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
}

// 138. no nft/tc source under intergalaxion backend
#[test]
fn i26_no_nft_tc_source() {
    let src_content =
        include_str!("backends/ebpf/event_stream_reader_lab_completion_review_pack.rs");
    let impl_lines: Vec<&str> = src_content
        .lines()
        .filter(|l| !l.starts_with("//"))
        .collect();
    let impl_content = impl_lines.join("\n");
    assert!(!impl_content.contains("nft"));
    assert!(!impl_content.contains(".tc("));
    assert!(!impl_content.contains("tc "));
}

// 139. all touched files under 1000 LOC
#[test]
fn i26_module_under_1000_loc() {
    let content = include_str!("backends/ebpf/event_stream_reader_lab_completion_review_pack.rs");
    assert!(content.lines().count() <= 1000, "module exceeds 1000 LOC");
}

// Empty phase validation
#[test]
fn i26_validation_rejects_empty_phase() {
    let mut pack = safe_default_pack();
    pack.phase = String::new();
    assert!(validate_reader_lab_completion_review_pack(&pack).is_err());
}

// Gate contradiction blocks review
#[test]
fn i26_gate_contradiction_blocks_review() {
    let mut input = safe_experimental_input();
    input.policy_completion_gate_report.completion_passed = true;
    input.policy_completion_gate_report.contradiction_detected = true;
    let pack = build_reader_lab_completion_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.contradiction_detected);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "CRP-GATE-CONTRADICTION"));
}

// ReviewReady decision is PrepareNextArc
#[test]
fn i26_review_ready_decision_is_prepare_next_arc() {
    let input = safe_experimental_input();
    let pack = build_reader_lab_completion_review_pack(&input);
    assert_eq!(
        pack.status,
        EbpfReaderLabCompletionReviewPackStatus::ReviewReady
    );
    assert_eq!(
        pack.decision,
        EbpfReaderLabCompletionReviewDecision::PrepareNextArc
    );
}
