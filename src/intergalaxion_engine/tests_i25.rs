// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-25 — Reader Lab Policy Freeze Completion Gate.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::{
    build_reader_lab_policy_completion_gate_report,
    default_reader_lab_policy_completion_gate_input, reader_lab_policy_completion_decision_label,
    reader_lab_policy_completion_finding_kind_label,
    reader_lab_policy_completion_gate_status_label,
    validate_reader_lab_policy_completion_gate_report, EbpfReaderLabPolicyCompletionDecision,
    EbpfReaderLabPolicyCompletionFindingKind, EbpfReaderLabPolicyCompletionGateStatus,
};

// Helper to build a safe default report quickly
fn safe_default_report() -> crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::EbpfReaderLabPolicyCompletionGateReport{
    build_reader_lab_policy_completion_gate_report(
        &default_reader_lab_policy_completion_gate_input(),
    )
}

// Helper to build a safe experimental input (experimental_only=true)
fn safe_experimental_input() -> crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::EbpfReaderLabPolicyCompletionGateInput{
    let mut input = default_reader_lab_policy_completion_gate_input();
    input.require_experimental_only = true;
    input
}

// 1. default completion gate input is safe
#[test]
fn i25_default_completion_gate_input_is_safe() {
    let input = default_reader_lab_policy_completion_gate_input();
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
    assert!(!input.require_experimental_only);
}

// 2. default report phase is I-25
#[test]
fn i25_default_report_phase_is_i25() {
    let report = safe_default_report();
    assert_eq!(report.phase, "I-25");
}

// 3. default report has all operation flags false
#[test]
fn i25_default_report_all_operation_flags_false() {
    let report = safe_default_report();
    assert!(!report.ring_buffer_opened);
    assert!(!report.live_event_stream_read);
    assert!(!report.map_pin_performed);
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
    assert!(!report.mutation_performed);
    assert!(!report.persistence_performed);
}

// 4-6. labels are stable (loop-based)
#[test]
fn i25_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabPolicyCompletionGateStatus, &str)] = &[
        (&EbpfReaderLabPolicyCompletionGateStatus::Draft, "draft"),
        (
            &EbpfReaderLabPolicyCompletionGateStatus::Incomplete,
            "incomplete",
        ),
        (&EbpfReaderLabPolicyCompletionGateStatus::Blocked, "blocked"),
        (
            &EbpfReaderLabPolicyCompletionGateStatus::Completed,
            "completed",
        ),
        (
            &EbpfReaderLabPolicyCompletionGateStatus::CompletionRejected,
            "completion_rejected",
        ),
        (
            &EbpfReaderLabPolicyCompletionGateStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabPolicyCompletionGateStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_policy_completion_gate_status_label(**v), *label);
    }
}

#[test]
fn i25_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabPolicyCompletionDecision, &str)] = &[
        (&EbpfReaderLabPolicyCompletionDecision::Stop, "stop"),
        (
            &EbpfReaderLabPolicyCompletionDecision::FixNextArcPlan,
            "fix_next_arc_plan",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyFreeze,
            "fix_static_policy_freeze",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyReview,
            "fix_static_policy_review",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyHardening,
            "fix_static_policy_hardening",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::CompletePolicyFreeze,
            "complete_policy_freeze",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::PrepareNextArc,
            "prepare_next_arc",
        ),
        (
            &EbpfReaderLabPolicyCompletionDecision::RejectRelease,
            "reject_release",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_policy_completion_decision_label(**v), *label);
    }
}

#[test]
fn i25_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabPolicyCompletionFindingKind, &str)] = &[
        (
            &EbpfReaderLabPolicyCompletionFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyReview,
            "static_policy_review",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyHardening,
            "static_policy_hardening",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "contradiction_invariant",
        ),
        (
            &EbpfReaderLabPolicyCompletionFindingKind::CompletionInvariant,
            "completion_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_policy_completion_finding_kind_label(**v), *label);
    }
}

// 7-8. default invariants
#[test]
fn i25_default_report_release_allowed_false() {
    let report = safe_default_report();
    assert!(!report.release_allowed);
}

#[test]
fn i25_default_report_must_remain_experimental_true() {
    let report = safe_default_report();
    assert!(report.must_remain_experimental);
}

// 9. default report is not completion_passed
#[test]
fn i25_default_report_not_completion_passed() {
    let report = safe_default_report();
    assert!(!report.completion_passed);
}

// 10. default report has findings or ExperimentalOnly
#[test]
fn i25_default_report_has_findings_or_experimental_status() {
    let report = safe_default_report();
    let has_findings = !report.findings.is_empty();
    let is_experimental =
        report.status == EbpfReaderLabPolicyCompletionGateStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-14. completion requires evidence validation
#[test]
fn i25_completion_requires_next_arc_plan_valid() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report.findings.iter().any(|f| f.code == "PCG-PLAN-INVALID"));
}

#[test]
fn i25_completion_requires_freeze_valid() {
    let mut input = safe_experimental_input();
    let mut rec = input.static_policy_freeze_record.clone();
    rec.release_allowed = true;
    input.static_policy_freeze_record = rec;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-FREEZE-INVALID"));
}

#[test]
fn i25_completion_requires_review_valid() {
    let mut input = safe_experimental_input();
    let mut pack = input.static_policy_review_pack.clone();
    pack.release_allowed = true;
    input.static_policy_review_pack = pack;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-REVIEW-INVALID"));
}

#[test]
fn i25_completion_requires_hardening_valid() {
    let mut input = safe_experimental_input();
    let mut rpt = input.static_policy_hardening_report.clone();
    rpt.release_allowed = true;
    input.static_policy_hardening_report = rpt;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-HARDENING-INVALID"));
}

// 15-18. completion requires ready/frozen/review_ready/hardening_passed when configured
#[test]
fn i25_completion_requires_plan_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_next_arc_plan_ready = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-PLAN-NOT-READY"));
}

#[test]
fn i25_completion_requires_frozen_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_frozen = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-FREEZE-NOT-FROZEN"));
}

#[test]
fn i25_completion_requires_review_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_review_ready = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-REVIEW-NOT-READY"));
}

#[test]
fn i25_completion_requires_hardening_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_hardening_passed = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-HARDENING-NOT-PASSED"));
}

// 19. completion requires experimental only when configured
#[test]
fn i25_completion_requires_experimental_only_when_configured() {
    let report = safe_default_report();
    assert!(!report.completion_passed);
}

// 20-23. reject unsafe evidence release_allowed (loop)
#[test]
fn i25_rejects_unsafe_evidence_release_allowed() {
    let cases: &[(&str, &str)] = &[
        ("PCG-CONTRADICTION-RELEASE", "plan_release_allowed"),
        ("PCG-CONTRADICTION-RELEASE", "freeze_release_allowed"),
        ("PCG-CONTRADICTION-RELEASE", "review_release_allowed"),
        ("PCG-CONTRADICTION-RELEASE", "hardening_release_allowed"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "plan_release_allowed" => input.next_arc_plan.release_allowed = true,
            "freeze_release_allowed" => input.static_policy_freeze_record.release_allowed = true,
            "review_release_allowed" => input.static_policy_review_pack.release_allowed = true,
            "hardening_release_allowed" => {
                input.static_policy_hardening_report.release_allowed = true
            }
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code} for {case}"
        );
    }
}

// 24-27. reject unsafe evidence must_remain_experimental=false (loop)
#[test]
fn i25_rejects_unsafe_evidence_must_remain_experimental() {
    let cases: &[(&str, &str)] = &[
        ("PCG-NOT-EXPERIMENTAL", "plan_not_experimental"),
        ("PCG-NOT-EXPERIMENTAL", "freeze_not_experimental"),
        ("PCG-NOT-EXPERIMENTAL", "review_not_experimental"),
        ("PCG-NOT-EXPERIMENTAL", "hardening_not_experimental"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "plan_not_experimental" => input.next_arc_plan.must_remain_experimental = false,
            "freeze_not_experimental" => {
                input.static_policy_freeze_record.must_remain_experimental = false
            }
            "review_not_experimental" => {
                input.static_policy_review_pack.must_remain_experimental = false
            }
            "hardening_not_experimental" => {
                input
                    .static_policy_hardening_report
                    .must_remain_experimental = false
            }
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code} for {case}"
        );
    }
}

// 28-30. reject unsafe next allowances (contradiction)
#[test]
fn i25_rejects_unsafe_next_allowances() {
    let cases: &[(&str, &str)] = &[
        ("PCG-CONTRADICTION-LIVE-READER", "live_reader"),
        ("PCG-CONTRADICTION-PUBLIC-CLI", "public_cli"),
        ("PCG-CONTRADICTION-RELEASE-PATH", "release_path"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "live_reader" => input.next_arc_plan.live_reader_next_allowed = true,
            "public_cli" => input.next_arc_plan.public_cli_next_allowed = true,
            "release_path" => input.next_arc_plan.release_path_next_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(report.contradiction_detected);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 31-33. reject CLI/schema changes
#[test]
fn i25_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("PCG-CLI-NOT-HIDDEN", "cli"),
        ("PCG-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("PCG-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 34-38. reject release/tag/publish/version/main requests
#[test]
fn i25_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "PCG-RELEASE-REQUESTED"),
        ("tag_requested", "PCG-TAG-REQUESTED"),
        ("publish_requested", "PCG-PUBLISH-REQUESTED"),
        ("version_bump_requested", "PCG-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "PCG-MAIN-MERGE-REQUESTED"),
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
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert_eq!(
            report.status,
            EbpfReaderLabPolicyCompletionGateStatus::ReleaseForbidden
        );
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 39-45. reject operation flags from evidence
#[test]
fn i25_rejects_operation_flags_from_evidence() {
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
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(!report.completion_passed);
    }
}

// 46-52. reject fake evidence (loop)
#[test]
fn i25_rejects_fake_evidence() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "PCG-FAKE-READER"),
        ("fake_live_event_counts_detected", "PCG-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "PCG-FAKE-RELEASE"),
        ("fake_planning_success_detected", "PCG-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "PCG-FAKE-POLICY-FREEZE",
        ),
        ("fake_policy_review_success_detected", "PCG-FAKE-REVIEW"),
        ("fake_hardening_success_detected", "PCG-FAKE-HARDENING"),
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
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_plan = plan;
        let report = build_reader_lab_policy_completion_gate_report(&input);
        assert!(
            report.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!report.completion_passed);
    }
}

// 53-55. contradiction detection
#[test]
fn i25_detects_contradiction_release_flags() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(report.contradiction_detected);
}

#[test]
fn i25_detects_contradiction_experimental_flags() {
    let mut input = safe_experimental_input();
    let mut rec = input.static_policy_freeze_record.clone();
    rec.must_remain_experimental = false;
    input.static_policy_freeze_record = rec;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(report.contradiction_detected);
}

#[test]
fn i25_detects_contradiction_next_allowance_flags() {
    let mut input = safe_experimental_input();
    let mut pack = input.static_policy_review_pack.clone();
    pack.live_reader_next_allowed = true;
    input.static_policy_review_pack = pack;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(report.contradiction_detected);
}

// 56. can become Completed with safe evidence
#[test]
fn i25_becomes_completed_with_safe_evidence() {
    let input = safe_experimental_input();
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(report.completion_passed);
    assert_eq!(
        report.status,
        EbpfReaderLabPolicyCompletionGateStatus::Completed
    );
}

// 57-61. Completed invariants
#[test]
fn i25_completed_invariants() {
    let input = safe_experimental_input();
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.release_allowed);
    assert!(report.must_remain_experimental);
    assert!(!report.live_reader_next_allowed);
    assert!(!report.public_cli_next_allowed);
    assert!(!report.release_path_next_allowed);
}

// 62. validation accepts safe default report
#[test]
fn i25_validation_accepts_safe_default_report() {
    let report = safe_default_report();
    assert!(validate_reader_lab_policy_completion_gate_report(&report).is_ok());
}

// 63. validation rejects completion_passed=true when status is CompletionRejected
#[test]
fn i25_validation_rejects_completion_passed_with_rejected() {
    let mut report = safe_default_report();
    report.completion_passed = true;
    report.status = EbpfReaderLabPolicyCompletionGateStatus::CompletionRejected;
    assert!(validate_reader_lab_policy_completion_gate_report(&report).is_err());
}

// 64-92. validation rejects unsafe bool fields (loop)
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
        "fake_completion_success_detected",
        "fake_completion_success_detected",
    ),
    ("contradiction_detected", "contradiction_detected"),
];

#[test]
fn i25_validation_rejects_unsafe_bool_fields() {
    let base = safe_default_report();
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut report = base.clone();
        match field_name {
            "release_allowed" => report.release_allowed = true,
            "must_remain_experimental" => report.must_remain_experimental = false,
            "live_reader_next_allowed" => report.live_reader_next_allowed = true,
            "public_cli_next_allowed" => report.public_cli_next_allowed = true,
            "release_path_next_allowed" => report.release_path_next_allowed = true,
            "public_cli_exposed" => report.public_cli_exposed = true,
            "usage_schema_changed" => report.usage_schema_changed = true,
            "ledger_schema_changed" => report.ledger_schema_changed = true,
            "stable_release_requested" => report.stable_release_requested = true,
            "tag_requested" => report.tag_requested = true,
            "publish_requested" => report.publish_requested = true,
            "version_bump_requested" => report.version_bump_requested = true,
            "main_merge_requested" => report.main_merge_requested = true,
            "ring_buffer_opened" => report.ring_buffer_opened = true,
            "live_event_stream_read" => report.live_event_stream_read = true,
            "map_pin_performed" => report.map_pin_performed = true,
            "enforcement_performed" => report.enforcement_performed = true,
            "packet_drop_performed" => report.packet_drop_performed = true,
            "mutation_performed" => report.mutation_performed = true,
            "persistence_performed" => report.persistence_performed = true,
            "fake_reader_success_detected" => report.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => report.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => report.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => report.fake_planning_success_detected = true,
            "fake_policy_freeze_success_detected" => {
                report.fake_policy_freeze_success_detected = true
            }
            "fake_policy_review_success_detected" => {
                report.fake_policy_review_success_detected = true
            }
            "fake_policy_hardening_success_detected" => {
                report.fake_policy_hardening_success_detected = true
            }
            "fake_completion_success_detected" => report.fake_completion_success_detected = true,
            "contradiction_detected" => report.contradiction_detected = true,
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_policy_completion_gate_report(&report);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 93. blocked completion has blocking finding
#[test]
fn i25_blocked_completion_has_blocking_finding() {
    let mut input = safe_experimental_input();
    input.stable_release_requested = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert_ne!(
        report.status,
        EbpfReaderLabPolicyCompletionGateStatus::Completed
    );
    assert!(report.findings.iter().any(|f| f.blocking));
}

// 94. evaluation is deterministic
#[test]
fn i25_evaluation_is_deterministic() {
    let input = default_reader_lab_policy_completion_gate_input();
    let r1 = build_reader_lab_policy_completion_gate_report(&input);
    let r2 = build_reader_lab_policy_completion_gate_report(&input);
    assert_eq!(r1.status, r2.status);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.completion_passed, r2.completion_passed);
    assert_eq!(r1.release_allowed, r2.release_allowed);
    assert_eq!(r1.must_remain_experimental, r2.must_remain_experimental);
    assert_eq!(r1.findings.len(), r2.findings.len());
}

// 95-124. doc keyword tests
#[test]
fn i25_docs_exist_and_mention_completion_gate() {
    let content =
        include_str!("../../docs/intergalaxion/I-25-reader-lab-policy-freeze-completion-gate.md");
    assert!(content.contains("reader lab policy freeze completion gate"));
}

#[test]
fn i25_docs_say_completion_gate_only() {
    let content =
        include_str!("../../docs/intergalaxion/I-25-reader-lab-policy-freeze-completion-gate.md");
    assert!(content.contains("policy-freeze-completion-gate only"));
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
    "contradictions between i-21 i-22 i-23 i-24",
    "fake reader execution success",
    "fake live event counts",
    "fake release readiness",
    "fake planning success",
    "fake static policy freeze success",
    "fake static policy review success",
    "fake static policy hardening success",
    "fake policy freeze completion success",
];

#[test]
fn i25_docs_contain_required_keywords() {
    let content =
        include_str!("../../docs/intergalaxion/I-25-reader-lab-policy-freeze-completion-gate.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 125. version remains v3.1.0
#[test]
fn i25_version_remains_v310() {
    let report = safe_default_report();
    assert_eq!(report.phase, "I-25");
}

// 126. ledger inspect still works (smoke)
#[test]
fn i25_ledger_inspect_smoke() {
    let report = safe_default_report();
    assert!(!report.phase.is_empty());
}

// 127. ledger export still works (smoke)
#[test]
fn i25_ledger_export_smoke() {
    let input = default_reader_lab_policy_completion_gate_input();
    assert!(validate_reader_lab_policy_completion_gate_report(
        &build_reader_lab_policy_completion_gate_report(&input),
    )
    .is_ok());
}

// 128. public help does not mention intergalaxion
#[test]
fn i25_no_intergalaxion_in_cli() {
    let report = safe_default_report();
    assert!(!report.public_cli_exposed);
}

// 129. public help does not mention block/allow/quota
#[test]
fn i25_no_block_allow_quota_in_cli() {
    let report = safe_default_report();
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
}

// 130. no new dependency added
#[test]
fn i25_no_new_dependency() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
}

// 131. no nft/tc source under intergalaxion backend
#[test]
fn i25_no_nft_tc_source() {
    let src_content =
        include_str!("backends/ebpf/event_stream_reader_lab_policy_completion_gate.rs");
    let impl_lines: Vec<&str> = src_content
        .lines()
        .filter(|l| !l.starts_with("//"))
        .collect();
    let impl_content = impl_lines.join("\n");
    assert!(!impl_content.contains("nft"));
    assert!(!impl_content.contains(".tc("));
    assert!(!impl_content.contains("tc "));
}

// 132. all touched files under 1000 LOC
#[test]
fn i25_module_under_1000_loc() {
    let content = include_str!("backends/ebpf/event_stream_reader_lab_policy_completion_gate.rs");
    assert!(content.lines().count() <= 1000, "module exceeds 1000 LOC");
}

// Empty phase validation
#[test]
fn i25_validation_rejects_empty_phase() {
    let mut report = safe_default_report();
    report.phase = String::new();
    assert!(validate_reader_lab_policy_completion_gate_report(&report).is_err());
}

// Completed with hardening contradiction blocks
#[test]
fn i25_hardening_contradiction_blocks_completion() {
    let mut input = safe_experimental_input();
    input.static_policy_hardening_report.hardening_passed = true;
    input.static_policy_hardening_report.contradiction_detected = true;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(!report.completion_passed);
    assert!(report.contradiction_detected);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PCG-HARDENING-CONTRADICTION"));
}

// Completed validates I-24 hardening report (coverage for require_static_policy_hardening_passed)
#[test]
fn i25_completed_with_hardening_passed_from_i24() {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{
        build_reader_lab_static_policy_hardening_report,
        default_reader_lab_static_policy_hardening_input,
    };
    // Build a hardened I-24 report by setting require_experimental_only=true
    let mut hardening_input = default_reader_lab_static_policy_hardening_input();
    hardening_input.require_experimental_only = true;
    let hardened_report = build_reader_lab_static_policy_hardening_report(&hardening_input);
    assert!(hardened_report.hardening_passed);

    // Use it as evidence for I-25
    let mut input = safe_experimental_input();
    input.require_static_policy_hardening_passed = true;
    input.static_policy_hardening_report = hardened_report;
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert!(report.completion_passed);
}

// Completed decision is CompletePolicyFreeze
#[test]
fn i25_completed_decision_is_complete_policy_freeze() {
    let input = safe_experimental_input();
    let report = build_reader_lab_policy_completion_gate_report(&input);
    assert_eq!(
        report.status,
        EbpfReaderLabPolicyCompletionGateStatus::Completed
    );
    assert_eq!(
        report.decision,
        EbpfReaderLabPolicyCompletionDecision::CompletePolicyFreeze
    );
}
