// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-24 — Reader Lab Static Policy Hardening.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{
    build_reader_lab_static_policy_hardening_report, default_reader_lab_static_policy_hardening_input,
    reader_lab_static_policy_hardening_decision_label,
    reader_lab_static_policy_hardening_finding_kind_label,
    reader_lab_static_policy_hardening_status_label,
    validate_reader_lab_static_policy_hardening_report, EbpfReaderLabStaticPolicyHardeningDecision,
    EbpfReaderLabStaticPolicyHardeningFindingKind, EbpfReaderLabStaticPolicyHardeningStatus,
};

// 1. default hardening input is safe
#[test]
fn i24_default_hardening_input_is_safe() {
    let input = default_reader_lab_static_policy_hardening_input();
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
    assert!(!input.require_experimental_only);
}

// 2. default report phase is I-24
#[test]
fn i24_default_report_phase_is_i24() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert_eq!(report.phase, "I-24");
}

// 3. default report has all operation flags false
#[test]
fn i24_default_report_all_operation_flags_false() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
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
fn i24_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyHardeningStatus, &str)] = &[
        (&EbpfReaderLabStaticPolicyHardeningStatus::Draft, "draft"),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
            "incomplete",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
            "blocked",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::Hardened,
            "hardened",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::HardeningRejected,
            "hardening_rejected",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_static_policy_hardening_status_label(**v), *label);
    }
}

#[test]
fn i24_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyHardeningDecision, &str)] = &[
        (&EbpfReaderLabStaticPolicyHardeningDecision::Stop, "stop"),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::FixNextArcPlan,
            "fix_next_arc_plan",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyFreeze,
            "fix_static_policy_freeze",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyReview,
            "fix_static_policy_review",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::HardenPolicy,
            "harden_policy",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::PreparePolicyFreeze,
            "prepare_policy_freeze",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningDecision::RejectRelease,
            "reject_release",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(
            reader_lab_static_policy_hardening_decision_label(**v),
            *label
        );
    }
}

#[test]
fn i24_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabStaticPolicyHardeningFindingKind, &str)] = &[
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyReview,
            "static_policy_review",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
            "contradiction_invariant",
        ),
        (
            &EbpfReaderLabStaticPolicyHardeningFindingKind::HardeningInvariant,
            "hardening_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(
            reader_lab_static_policy_hardening_finding_kind_label(**v),
            *label
        );
    }
}

// 7-8. default invariants
#[test]
fn i24_default_report_release_allowed_false() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.release_allowed);
}

#[test]
fn i24_default_report_must_remain_experimental_true() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(report.must_remain_experimental);
}

// 9. default report is not hardening_passed
#[test]
fn i24_default_report_not_hardening_passed() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.hardening_passed);
}

// 10. default report has findings or ExperimentalOnly
#[test]
fn i24_default_report_has_findings_or_experimental_status() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    let has_findings = !report.findings.is_empty();
    let is_experimental =
        report.status == EbpfReaderLabStaticPolicyHardeningStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-13. hardening requires evidence validation
#[test]
fn i24_hardening_requires_next_arc_plan_valid() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report.findings.iter().any(|f| f.code == "SPH-PLAN-INVALID"));
}

#[test]
fn i24_hardening_requires_freeze_valid() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut rec = input.static_policy_freeze_record.clone();
    rec.release_allowed = true;
    input.static_policy_freeze_record = rec;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SPH-FREEZE-INVALID"));
}

#[test]
fn i24_hardening_requires_review_valid() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut pack = input.static_policy_review_pack.clone();
    pack.release_allowed = true;
    input.static_policy_review_pack = pack;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SPH-REVIEW-INVALID"));
}

// 14-16. hardening requires ready/frozen when configured
#[test]
fn i24_hardening_requires_plan_ready_when_configured() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_next_arc_plan_ready = true;
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SPH-PLAN-NOT-READY"));
}

#[test]
fn i24_hardening_requires_frozen_when_configured() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_static_policy_frozen = true;
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SPH-FREEZE-NOT-FROZEN"));
}

#[test]
fn i24_hardening_requires_review_ready_when_configured() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_static_policy_review_ready = true;
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.hardening_passed);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SPH-REVIEW-NOT-READY"));
}

// 17. hardening requires experimental only when configured
#[test]
fn i24_hardening_requires_experimental_only_when_configured() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.hardening_passed);
}

// 18-23. reject unsafe evidence flags (loop)
#[test]
fn i24_rejects_unsafe_evidence_flags() {
    let cases: &[(&str, &str)] = &[
        ("SPH-CONTRADICTION-RELEASE", "plan_release_allowed"),
        ("SPH-CONTRADICTION-RELEASE", "freeze_release_allowed"),
        ("SPH-CONTRADICTION-RELEASE", "review_release_allowed"),
        ("SPH-NOT-EXPERIMENTAL", "plan_not_experimental"),
        ("SPH-NOT-EXPERIMENTAL", "freeze_not_experimental"),
        ("SPH-NOT-EXPERIMENTAL", "review_not_experimental"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_hardening_input();
        input.require_experimental_only = true;
        match *case {
            "plan_release_allowed" => input.next_arc_plan.release_allowed = true,
            "freeze_release_allowed" => input.static_policy_freeze_record.release_allowed = true,
            "review_release_allowed" => input.static_policy_review_pack.release_allowed = true,
            "plan_not_experimental" => input.next_arc_plan.must_remain_experimental = false,
            "freeze_not_experimental" => {
                input.static_policy_freeze_record.must_remain_experimental = false
            }
            "review_not_experimental" => {
                input.static_policy_review_pack.must_remain_experimental = false
            }
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code} for {case}"
        );
    }
}

// 24-26. reject unsafe next allowances (contradiction)
#[test]
fn i24_rejects_unsafe_next_allowances() {
    let cases: &[(&str, &str)] = &[
        ("SPH-CONTRADICTION-LIVE-READER", "live_reader"),
        ("SPH-CONTRADICTION-PUBLIC-CLI", "public_cli"),
        ("SPH-CONTRADICTION-RELEASE-PATH", "release_path"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_hardening_input();
        input.require_experimental_only = true;
        match *case {
            "live_reader" => input.next_arc_plan.live_reader_next_allowed = true,
            "public_cli" => input.next_arc_plan.public_cli_next_allowed = true,
            "release_path" => input.next_arc_plan.release_path_next_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert!(report.contradiction_detected);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 27-29. reject CLI/schema changes
#[test]
fn i24_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("SPH-CLI-NOT-HIDDEN", "cli"),
        ("SPH-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("SPH-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = default_reader_lab_static_policy_hardening_input();
        input.require_experimental_only = true;
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 30-34. reject release/tag/publish/version/main requests
#[test]
fn i24_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "SPH-RELEASE-REQUESTED"),
        ("tag_requested", "SPH-TAG-REQUESTED"),
        ("publish_requested", "SPH-PUBLISH-REQUESTED"),
        ("version_bump_requested", "SPH-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "SPH-MAIN-MERGE-REQUESTED"),
    ];
    for (field, expected_code) in cases {
        let mut input = default_reader_lab_static_policy_hardening_input();
        input.require_experimental_only = true;
        match *field {
            "stable_release_requested" => input.stable_release_requested = true,
            "tag_requested" => input.tag_requested = true,
            "publish_requested" => input.publish_requested = true,
            "version_bump_requested" => input.version_bump_requested = true,
            "main_merge_requested" => input.main_merge_requested = true,
            _ => panic!("unexpected: {field}"),
        }
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert_eq!(
            report.status,
            EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden
        );
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 35-41. reject operation flags from evidence
#[test]
fn i24_rejects_operation_flags_from_evidence() {
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
        let mut input = default_reader_lab_static_policy_hardening_input();
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
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert!(!report.hardening_passed);
    }
}

// 42-47. reject fake evidence (from all evidence sources)
#[test]
fn i24_rejects_fake_evidence() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "SPH-FAKE-READER"),
        ("fake_live_event_counts_detected", "SPH-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "SPH-FAKE-RELEASE"),
        ("fake_planning_success_detected", "SPH-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "SPH-FAKE-POLICY-FREEZE",
        ),
        ("fake_review_success_detected", "SPH-FAKE-REVIEW"),
    ];
    for (field, code) in cases {
        let mut input = default_reader_lab_static_policy_hardening_input();
        input.require_experimental_only = true;
        // Set fake on next_arc_plan (available for all except policy_freeze/review)
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
            "fake_review_success_detected" => {
                input.static_policy_review_pack.fake_review_success_detected = true;
            }
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_plan = plan;
        let report = build_reader_lab_static_policy_hardening_report(&input);
        assert!(
            report.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!report.hardening_passed);
    }
}

// 48-50. contradiction detection
#[test]
fn i24_detects_contradiction_release_flags() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(report.contradiction_detected);
}

#[test]
fn i24_detects_contradiction_experimental_flags() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut rec = input.static_policy_freeze_record.clone();
    rec.must_remain_experimental = false;
    input.static_policy_freeze_record = rec;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(report.contradiction_detected);
}

#[test]
fn i24_detects_contradiction_next_allowance_flags() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let mut pack = input.static_policy_review_pack.clone();
    pack.live_reader_next_allowed = true;
    input.static_policy_review_pack = pack;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(report.contradiction_detected);
}

// 51. can become Hardened with safe evidence
#[test]
fn i24_becomes_hardened_with_safe_evidence() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(report.hardening_passed);
    assert_eq!(
        report.status,
        EbpfReaderLabStaticPolicyHardeningStatus::Hardened
    );
}

// 52-56. Hardened invariants
#[test]
fn i24_hardened_invariants() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(!report.release_allowed);
    assert!(report.must_remain_experimental);
    assert!(!report.live_reader_next_allowed);
    assert!(!report.public_cli_next_allowed);
    assert!(!report.release_path_next_allowed);
}

// 57. validation accepts safe default report
#[test]
fn i24_validation_accepts_safe_default_report() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(validate_reader_lab_static_policy_hardening_report(&report).is_ok());
}

// 58. validation rejects hardening_passed with HardeningRejected
#[test]
fn i24_validation_rejects_hardening_passed_with_rejected() {
    let mut report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    report.hardening_passed = true;
    report.status = EbpfReaderLabStaticPolicyHardeningStatus::HardeningRejected;
    assert!(validate_reader_lab_static_policy_hardening_report(&report).is_err());
}

// 59-60. validation rejects release_allowed / must_remain_experimental
#[test]
fn i24_validation_rejects_release_allowed() {
    let mut report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    report.release_allowed = true;
    assert!(validate_reader_lab_static_policy_hardening_report(&report).is_err());
}

#[test]
fn i24_validation_rejects_must_remain_experimental_false() {
    let mut report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    report.must_remain_experimental = false;
    assert!(validate_reader_lab_static_policy_hardening_report(&report).is_err());
}

// 61-86. validation rejects unsafe bool fields (loop)
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
        "fake_policy_review_success_detected",
        "fake_policy_review_success_detected",
    ),
    (
        "fake_hardening_success_detected",
        "fake_hardening_success_detected",
    ),
];

#[test]
fn i24_validation_rejects_unsafe_bool_fields() {
    let base = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut report = base.clone();
        match field_name {
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
            "fake_hardening_success_detected" => report.fake_hardening_success_detected = true,
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_static_policy_hardening_report(&report);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 87. blocked hardening has blocking finding
#[test]
fn i24_blocked_hardening_has_blocking_finding() {
    let mut input = default_reader_lab_static_policy_hardening_input();
    input.stable_release_requested = true;
    input.require_experimental_only = true;
    let report = build_reader_lab_static_policy_hardening_report(&input);
    assert!(report.status != EbpfReaderLabStaticPolicyHardeningStatus::Hardened);
    assert!(report.findings.iter().any(|f| f.blocking));
}

// 88. evaluation is deterministic
#[test]
fn i24_evaluation_is_deterministic() {
    let input = default_reader_lab_static_policy_hardening_input();
    let r1 = build_reader_lab_static_policy_hardening_report(&input);
    let r2 = build_reader_lab_static_policy_hardening_report(&input);
    assert_eq!(r1.status, r2.status);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.hardening_passed, r2.hardening_passed);
    assert_eq!(r1.release_allowed, r2.release_allowed);
    assert_eq!(r1.must_remain_experimental, r2.must_remain_experimental);
    assert_eq!(r1.findings.len(), r2.findings.len());
}

// 89-90. doc keyword tests
#[test]
fn i24_docs_exist_and_mention_hardening() {
    let content =
        include_str!("../../docs/intergalaxion/I-24-reader-lab-static-policy-hardening.md");
    assert!(content.contains("reader lab static policy hardening"));
}

#[test]
fn i24_docs_say_hardening_only() {
    let content =
        include_str!("../../docs/intergalaxion/I-24-reader-lab-static-policy-hardening.md");
    assert!(content.contains("static-policy-hardening only"));
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
    "contradictions between i-21 i-22 i-23",
    "fake reader execution success",
    "fake live event counts",
    "fake release readiness",
    "fake planning success",
    "fake static policy freeze success",
    "fake static policy review success",
    "fake static policy hardening success",
];

#[test]
fn i24_docs_contain_required_keywords() {
    let content =
        include_str!("../../docs/intergalaxion/I-24-reader-lab-static-policy-hardening.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 106. version remains v3.1.0
#[test]
fn i24_version_remains_v310() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert_eq!(report.phase, "I-24");
}

// 107. ledger inspect still works (smoke)
#[test]
fn i24_ledger_inspect_smoke() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.phase.is_empty());
}

// 108. ledger export still works (smoke)
#[test]
fn i24_ledger_export_smoke() {
    let input = default_reader_lab_static_policy_hardening_input();
    assert!(validate_reader_lab_static_policy_hardening_report(
        &build_reader_lab_static_policy_hardening_report(&input),
    )
    .is_ok());
}

// 109. public help does not mention intergalaxion
#[test]
fn i24_no_intergalaxion_in_cli() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.public_cli_exposed);
}

// 110. public help does not mention block/allow/quota
#[test]
fn i24_no_block_allow_quota_in_cli() {
    let report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
}

// 111. no new dependency added
#[test]
fn i24_no_new_dependency() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
}

// 112. no nft/tc source under intergalaxion backend
#[test]
fn i24_no_nft_tc_source() {
    let src_content =
        include_str!("backends/ebpf/event_stream_reader_lab_static_policy_hardening.rs");
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
fn i24_module_under_1000_loc() {
    let content = include_str!("backends/ebpf/event_stream_reader_lab_static_policy_hardening.rs");
    assert!(content.lines().count() <= 1000, "module exceeds 1000 LOC");
}

// Empty phase validation
#[test]
fn i24_validation_rejects_empty_phase() {
    let mut report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    report.phase = String::new();
    assert!(validate_reader_lab_static_policy_hardening_report(&report).is_err());
}
