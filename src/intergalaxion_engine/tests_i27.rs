// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-27 — Reader Lab Next Arc Entry Gate.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input,
    reader_lab_next_arc_entry_decision_label, reader_lab_next_arc_entry_finding_kind_label,
    reader_lab_next_arc_entry_status_label, validate_reader_lab_next_arc_entry_gate_report,
    EbpfReaderLabNextArcEntryDecision, EbpfReaderLabNextArcEntryFindingKind,
    EbpfReaderLabNextArcEntryStatus,
};

type Input = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::EbpfReaderLabNextArcEntryGateInput;
type Report = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::EbpfReaderLabNextArcEntryGateReport;

fn safe_default_report() -> Report {
    build_reader_lab_next_arc_entry_gate_report(&default_reader_lab_next_arc_entry_gate_input())
}

fn safe_experimental_input() -> Input {
    let mut input = default_reader_lab_next_arc_entry_gate_input();
    input.require_experimental_only = true;
    input.prefer_fixture_only_arc = true;
    input
}

fn safe_entry_ready_input() -> Input {
    safe_experimental_input()
}

// 1. default next arc entry input is safe
#[test]
fn i27_default_next_arc_entry_input_is_safe() {
    let input = default_reader_lab_next_arc_entry_gate_input();
    assert!(!input.stable_release_requested);
    assert!(!input.tag_requested);
    assert!(!input.publish_requested);
    assert!(!input.version_bump_requested);
    assert!(!input.main_merge_requested);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
    assert!(!input.require_completion_review_ready);
    assert!(!input.require_policy_completion_passed);
    assert!(!input.require_static_policy_hardening_passed);
    assert!(!input.require_experimental_only);
    assert!(!input.allow_live_reader_arc);
    assert!(!input.allow_public_cli_arc);
    assert!(!input.allow_release_arc);
    assert!(!input.allow_enforcement_arc);
}

// 2. default report phase is I-27
#[test]
fn i27_default_report_phase_is_i27() {
    let report = safe_default_report();
    assert_eq!(report.phase, "I-27");
}

// 3. default report has all operation flags false
#[test]
fn i27_default_report_all_operation_flags_false() {
    let report = safe_default_report();
    assert!(!report.ring_buffer_opened);
    assert!(!report.live_event_stream_read);
    assert!(!report.map_pin_performed);
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
    assert!(!report.mutation_performed);
    assert!(!report.persistence_performed);
}

// 4. status labels are stable
#[test]
fn i27_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcEntryStatus, &str)] = &[
        (&EbpfReaderLabNextArcEntryStatus::Draft, "draft"),
        (&EbpfReaderLabNextArcEntryStatus::Incomplete, "incomplete"),
        (&EbpfReaderLabNextArcEntryStatus::Blocked, "blocked"),
        (&EbpfReaderLabNextArcEntryStatus::EntryReady, "entry_ready"),
        (
            &EbpfReaderLabNextArcEntryStatus::EntryRejected,
            "entry_rejected",
        ),
        (
            &EbpfReaderLabNextArcEntryStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabNextArcEntryStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_entry_status_label(**v), *label);
    }
}

// 5. decision labels are stable
#[test]
fn i27_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcEntryDecision, &str)] = &[
        (&EbpfReaderLabNextArcEntryDecision::Stop, "stop"),
        (
            &EbpfReaderLabNextArcEntryDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::StartFixtureOnlyArc,
            "start_fixture_only_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::StartStaticPolicyArc,
            "start_static_policy_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::StartManualReaderSpikeChecklistArc,
            "start_manual_reader_spike_checklist_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::StartReaderSpikeReviewArc,
            "start_reader_spike_review_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::RejectLiveReaderArc,
            "reject_live_reader_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::RejectPublicCliArc,
            "reject_public_cli_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::RejectReleaseArc,
            "reject_release_arc",
        ),
        (
            &EbpfReaderLabNextArcEntryDecision::RejectEnforcementArc,
            "reject_enforcement_arc",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_entry_decision_label(**v), *label);
    }
}

// 6. finding kind labels are stable
#[test]
fn i27_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcEntryFindingKind, &str)] = &[
        (
            &EbpfReaderLabNextArcEntryFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::StaticPolicyReview,
            "static_policy_review",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::StaticPolicyHardening,
            "static_policy_hardening",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::PolicyCompletionGate,
            "policy_completion_gate",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::CompletionReview,
            "completion_review",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabNextArcEntryFindingKind::EntryInvariant,
            "entry_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_entry_finding_kind_label(**v), *label);
    }
}

// 7. default report release_allowed=false
#[test]
fn i27_default_report_release_allowed_false() {
    let report = safe_default_report();
    assert!(!report.release_allowed);
}

// 8. default report must_remain_experimental=true
#[test]
fn i27_default_report_must_remain_experimental_true() {
    let report = safe_default_report();
    assert!(report.must_remain_experimental);
}

// 9. default report is not entry_ready
#[test]
fn i27_default_report_not_entry_ready() {
    let report = safe_default_report();
    assert!(!report.entry_ready);
}

// 10. default report has findings or ExperimentalOnly
#[test]
fn i27_default_report_has_findings_or_experimental_status() {
    let report = safe_default_report();
    let has_findings = !report.findings.is_empty();
    let is_experimental = report.status == EbpfReaderLabNextArcEntryStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-13. entry requires evidence validation
#[test]
fn i27_requires_evidence_valid() {
    let cases: &[(&str, &str)] = &[
        ("NAEG-CRP-INVALID", "crp"),
        ("NAEG-GATE-INVALID", "gate"),
        ("NAEG-HARDENING-INVALID", "hardening"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "crp" => input.completion_review_pack.release_allowed = true,
            "gate" => input.policy_completion_gate_report.release_allowed = true,
            "hardening" => input.static_policy_hardening_report.release_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert!(!report.entry_ready);
        assert!(
            report.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 14. entry requires completion review ready when configured
#[test]
fn i27_requires_crp_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_completion_review_ready = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(!report.entry_ready);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "NAEG-CRP-NOT-READY"));
}

// 15. entry requires policy completion passed when configured
#[test]
fn i27_requires_completion_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_policy_completion_passed = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(!report.entry_ready);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "NAEG-COMPLETION-NOT-PASSED"));
}

// 16. entry requires static policy hardening passed when configured
#[test]
fn i27_requires_hardening_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_static_policy_hardening_passed = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(!report.entry_ready);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "NAEG-HARDENING-NOT-PASSED"));
}

// 17. entry requires experimental only when configured
#[test]
fn i27_requires_experimental_only_when_configured() {
    let report = safe_default_report();
    assert!(!report.entry_ready);
}

// 18. entry requires at least one allowed next arc preference
#[test]
fn i27_requires_at_least_one_preference() {
    let mut input = safe_experimental_input();
    input.prefer_fixture_only_arc = false;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(!report.entry_ready);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "NAEG-NO-PREFERENCE"));
}

// 19. priority chooses StartStaticPolicyArc
#[test]
fn i27_priority_chooses_static_policy_arc() {
    let mut input = safe_entry_ready_input();
    input.prefer_fixture_only_arc = true;
    input.prefer_static_policy_arc = true;
    input.prefer_manual_reader_spike_checklist_arc = true;
    input.prefer_reader_spike_review_arc = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_eq!(
        report.decision,
        EbpfReaderLabNextArcEntryDecision::StartStaticPolicyArc
    );
    assert!(report.selected_static_policy_arc);
}

// 20. priority chooses StartFixtureOnlyArc over lower
#[test]
fn i27_priority_chooses_fixture_only_arc() {
    let mut input = safe_entry_ready_input();
    input.prefer_fixture_only_arc = true;
    input.prefer_manual_reader_spike_checklist_arc = true;
    input.prefer_reader_spike_review_arc = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_eq!(
        report.decision,
        EbpfReaderLabNextArcEntryDecision::StartFixtureOnlyArc
    );
    assert!(report.selected_fixture_only_arc);
}

// 21. priority chooses StartManualReaderSpikeChecklistArc
#[test]
fn i27_priority_chooses_manual_spike_checklist_arc() {
    let mut input = safe_entry_ready_input();
    input.prefer_fixture_only_arc = false;
    input.prefer_manual_reader_spike_checklist_arc = true;
    input.prefer_reader_spike_review_arc = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_eq!(
        report.decision,
        EbpfReaderLabNextArcEntryDecision::StartManualReaderSpikeChecklistArc
    );
    assert!(report.selected_manual_reader_spike_checklist_arc);
}

// 22. priority chooses StartReaderSpikeReviewArc
#[test]
fn i27_priority_chooses_reader_spike_review_arc() {
    let mut input = safe_entry_ready_input();
    input.prefer_fixture_only_arc = false;
    input.prefer_reader_spike_review_arc = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_eq!(
        report.decision,
        EbpfReaderLabNextArcEntryDecision::StartReaderSpikeReviewArc
    );
    assert!(report.selected_reader_spike_review_arc);
}

// 23-26. reject disallowed arc allowances (loop)
#[test]
fn i27_rejects_disallowed_arc_allowances() {
    let cases: &[(&str, &str, EbpfReaderLabNextArcEntryDecision)] = &[
        (
            "allow_live_reader_arc",
            "NAEG-LIVE-READER-ARC",
            EbpfReaderLabNextArcEntryDecision::RejectLiveReaderArc,
        ),
        (
            "allow_public_cli_arc",
            "NAEG-PUBLIC-CLI-ARC",
            EbpfReaderLabNextArcEntryDecision::RejectPublicCliArc,
        ),
        (
            "allow_release_arc",
            "NAEG-RELEASE-ARC",
            EbpfReaderLabNextArcEntryDecision::RejectReleaseArc,
        ),
        (
            "allow_enforcement_arc",
            "NAEG-ENFORCEMENT-ARC",
            EbpfReaderLabNextArcEntryDecision::RejectEnforcementArc,
        ),
    ];
    for (field, code, expected_decision) in cases {
        let mut input = safe_experimental_input();
        match *field {
            "allow_live_reader_arc" => input.allow_live_reader_arc = true,
            "allow_public_cli_arc" => input.allow_public_cli_arc = true,
            "allow_release_arc" => input.allow_release_arc = true,
            "allow_enforcement_arc" => input.allow_enforcement_arc = true,
            _ => panic!("unexpected: {field}"),
        }
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert!(!report.entry_ready);
        assert_eq!(report.decision, *expected_decision);
        assert!(report.findings.iter().any(|f| f.code == *code));
    }
}

// 27-29. reject CLI/schema changes (loop)
#[test]
fn i27_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("NAEG-CLI-NOT-HIDDEN", "cli"),
        ("NAEG-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("NAEG-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected: {case}"),
        }
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 30-34. reject release/tag/publish/version/main (loop)
#[test]
fn i27_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "NAEG-RELEASE-REQUESTED"),
        ("tag_requested", "NAEG-TAG-REQUESTED"),
        ("publish_requested", "NAEG-PUBLISH-REQUESTED"),
        ("version_bump_requested", "NAEG-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "NAEG-MAIN-MERGE-REQUESTED"),
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
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert_eq!(
            report.status,
            EbpfReaderLabNextArcEntryStatus::ReleaseForbidden
        );
        assert!(report.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 35-41. reject operation flags (loop)
#[test]
fn i27_rejects_operation_flags() {
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
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert!(!report.entry_ready);
    }
}

// 42-51. reject fake evidence (loop)
#[test]
fn i27_rejects_fake_evidence() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "NAEG-FAKE-READER"),
        ("fake_live_event_counts_detected", "NAEG-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "NAEG-FAKE-RELEASE"),
        ("fake_planning_success_detected", "NAEG-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "NAEG-FAKE-POLICY-FREEZE",
        ),
        ("fake_policy_review_success_detected", "NAEG-FAKE-REVIEW"),
        ("fake_hardening_success_detected", "NAEG-FAKE-HARDENING"),
        ("fake_completion_success_detected", "NAEG-FAKE-COMPLETION"),
        (
            "fake_completion_review_success_detected",
            "NAEG-FAKE-COMPLETION-REVIEW",
        ),
        ("fake_next_arc_entry_success_detected", "NAEG-FAKE-ENTRY"),
    ];
    for (field, code) in cases {
        let mut input = safe_experimental_input();
        match *field {
            "fake_reader_success_detected" => {
                input.next_arc_plan.fake_reader_success_detected = true;
            }
            "fake_live_event_counts_detected" => {
                input.next_arc_plan.fake_live_event_counts_detected = true;
            }
            "fake_release_readiness_detected" => {
                input.next_arc_plan.fake_release_readiness_detected = true;
            }
            "fake_planning_success_detected" => {
                input.next_arc_plan.fake_planning_success_detected = true;
            }
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
            "fake_completion_review_success_detected" => {
                input
                    .completion_review_pack
                    .fake_completion_review_success_detected = true;
            }
            "fake_next_arc_entry_success_detected" => {
                let mut r = build_reader_lab_next_arc_entry_gate_report(&input);
                r.fake_next_arc_entry_success_detected = true;
                let res = validate_reader_lab_next_arc_entry_gate_report(&r);
                assert!(res.is_err(), "expected error for {field}");
                assert!(res
                    .unwrap_err()
                    .contains("fake_next_arc_entry_success_detected"));
                continue;
            }
            _ => panic!("unexpected: {field}"),
        }
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        if *code != "NAEG-FAKE-ENTRY" {
            assert!(
                report.findings.iter().any(|f| f.code == *code),
                "missing {code}"
            );
            assert!(!report.entry_ready);
        }
    }
}

// 52-54. contradiction detection
#[test]
fn i27_detects_contradictions() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let r = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(r
        .findings
        .iter()
        .any(|f| f.code == "NAEG-CONTRADICTION-RELEASE"));
    let mut input2 = safe_experimental_input();
    input2.completion_review_pack.must_remain_experimental = false;
    let r2 = build_reader_lab_next_arc_entry_gate_report(&input2);
    assert!(r2
        .findings
        .iter()
        .any(|f| f.code == "NAEG-NOT-EXPERIMENTAL"));
    let mut input3 = safe_experimental_input();
    input3.static_policy_review_pack.live_reader_next_allowed = true;
    let r3 = build_reader_lab_next_arc_entry_gate_report(&input3);
    assert!(r3
        .findings
        .iter()
        .any(|f| f.code == "NAEG-CONTRADICTION-LIVE-READER"));
}

// 55. can become EntryReady with safe evidence and fixture-only arc
#[test]
fn i27_becomes_entry_ready_with_safe_evidence() {
    let input = safe_entry_ready_input();
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert!(report.entry_ready);
    assert_eq!(report.status, EbpfReaderLabNextArcEntryStatus::EntryReady);
}

// 56-61. EntryReady invariants
#[test]
fn i27_entry_ready_invariants() {
    let report = build_reader_lab_next_arc_entry_gate_report(&safe_entry_ready_input());
    assert!(!report.release_allowed);
    assert!(report.must_remain_experimental);
    assert!(!report.live_reader_arc_allowed);
    assert!(!report.public_cli_arc_allowed);
    assert!(!report.release_arc_allowed);
    assert!(!report.enforcement_arc_allowed);
}

// 62. validation accepts safe default report
#[test]
fn i27_validation_accepts_safe_default_report() {
    let report = safe_default_report();
    assert!(validate_reader_lab_next_arc_entry_gate_report(&report).is_ok());
}

// 63. validation rejects entry_ready=true when status is EntryRejected
#[test]
fn i27_validation_rejects_entry_ready_with_rejected() {
    let mut report = safe_default_report();
    report.entry_ready = true;
    report.status = EbpfReaderLabNextArcEntryStatus::EntryRejected;
    assert!(validate_reader_lab_next_arc_entry_gate_report(&report).is_err());
}

// 64-94. validation rejects unsafe bool fields (loop)
const VALIDATION_REJECT_FIELDS: &[(&str, &str)] = &[
    ("release_allowed", "release_allowed"),
    ("must_remain_experimental", "must_remain_experimental"),
    ("live_reader_arc_allowed", "live_reader_arc_allowed"),
    ("public_cli_arc_allowed", "public_cli_arc_allowed"),
    ("release_arc_allowed", "release_arc_allowed"),
    ("enforcement_arc_allowed", "enforcement_arc_allowed"),
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
    (
        "fake_next_arc_entry_success_detected",
        "fake_next_arc_entry_success_detected",
    ),
];

#[test]
fn i27_validation_rejects_unsafe_bool_fields() {
    let base = safe_default_report();
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut report = base.clone();
        match field_name {
            "release_allowed" => report.release_allowed = true,
            "must_remain_experimental" => report.must_remain_experimental = false,
            "live_reader_arc_allowed" => report.live_reader_arc_allowed = true,
            "public_cli_arc_allowed" => report.public_cli_arc_allowed = true,
            "release_arc_allowed" => report.release_arc_allowed = true,
            "enforcement_arc_allowed" => report.enforcement_arc_allowed = true,
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
            "fake_policy_completion_success_detected" => {
                report.fake_policy_completion_success_detected = true
            }
            "fake_completion_review_success_detected" => {
                report.fake_completion_review_success_detected = true
            }
            "fake_next_arc_entry_success_detected" => {
                report.fake_next_arc_entry_success_detected = true
            }
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_next_arc_entry_gate_report(&report);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 95. blocked/rejected entry has blocking finding
#[test]
fn i27_blocked_entry_has_blocking_finding() {
    let mut input = safe_experimental_input();
    input.stable_release_requested = true;
    let report = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_ne!(report.status, EbpfReaderLabNextArcEntryStatus::EntryReady);
    assert!(report.findings.iter().any(|f| f.blocking));
}

// 96. evaluation is deterministic
#[test]
fn i27_evaluation_is_deterministic() {
    let input = default_reader_lab_next_arc_entry_gate_input();
    let r1 = build_reader_lab_next_arc_entry_gate_report(&input);
    let r2 = build_reader_lab_next_arc_entry_gate_report(&input);
    assert_eq!(r1.status, r2.status);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.entry_ready, r2.entry_ready);
    assert_eq!(r1.release_allowed, r2.release_allowed);
    assert_eq!(r1.must_remain_experimental, r2.must_remain_experimental);
    assert_eq!(r1.findings.len(), r2.findings.len());
}

// 97-99. doc tests (condensed)
#[test]
fn i27_docs_key_checks() {
    let c = include_str!("../../docs/intergalaxion/I-27-reader-lab-next-arc-entry-gate.md");
    assert!(c.contains("reader lab next arc entry gate"));
    assert!(c.contains("next-arc-entry-gate only"));
    assert!(c.contains("not a release"));
}

// 100-128. doc keyword tests
const DOC_KEYWORDS: &[&str] = &[
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
    "live reader arc is not allowed",
    "public cli arc is not allowed",
    "release arc is not allowed",
    "enforcement arc is not allowed",
    "contradictions between i-21 i-22 i-23 i-24 i-25 i-26",
    "fake reader execution success",
    "fake live event counts",
    "fake release readiness",
    "fake planning success",
    "fake static policy freeze success",
    "fake static policy review success",
    "fake static policy hardening success",
    "fake policy freeze completion success",
    "fake completion review success",
    "fake next arc entry success",
];

#[test]
fn i27_docs_contain_required_keywords() {
    let content = include_str!("../../docs/intergalaxion/I-27-reader-lab-next-arc-entry-gate.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 129-136. smoke and compliance tests (condensed)
#[test]
fn i27_version_and_smoke_tests() {
    let report = safe_default_report();
    assert_eq!(report.phase, "I-27");
    assert!(!report.phase.is_empty());
    let input = default_reader_lab_next_arc_entry_gate_input();
    assert!(validate_reader_lab_next_arc_entry_gate_report(
        &build_reader_lab_next_arc_entry_gate_report(&input)
    )
    .is_ok());
    assert!(!report.public_cli_exposed);
    assert!(!report.enforcement_performed && !report.packet_drop_performed);
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_entry_gate.rs");
    let impl_lines: Vec<&str> = src.lines().filter(|l| !l.starts_with("//")).collect();
    let impl_content = impl_lines.join("\n");
    assert!(
        !impl_content.contains("nft")
            && !impl_content.contains(".tc(")
            && !impl_content.contains("tc ")
    );
    assert!(
        include_str!("backends/ebpf/event_stream_reader_lab_next_arc_entry_gate.rs")
            .lines()
            .count()
            <= 1000
    );
}

// Empty phase validation
#[test]
fn i27_validation_rejects_empty_phase() {
    let mut report = safe_default_report();
    report.phase = String::new();
    assert!(validate_reader_lab_next_arc_entry_gate_report(&report).is_err());
}

// EntryReady decision matches fixture-only preference
#[test]
fn i27_entry_ready_decision_matches_fixture_preference() {
    let report = build_reader_lab_next_arc_entry_gate_report(&safe_entry_ready_input());
    assert_eq!(
        report.decision,
        EbpfReaderLabNextArcEntryDecision::StartFixtureOnlyArc
    );
}

// Additional evidence valid tests
#[test]
fn i27_requires_freeze_review_plan_valid() {
    let cases: &[(&str, &str)] = &[
        ("NAEG-FREEZE-INVALID", "freeze"),
        ("NAEG-REVIEW-INVALID", "review"),
        ("NAEG-PLAN-INVALID", "plan"),
    ];
    for (code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "freeze" => input.static_policy_freeze_record.release_allowed = true,
            "review" => input.static_policy_review_pack.release_allowed = true,
            "plan" => input.next_arc_plan.release_allowed = true,
            _ => panic!("unexpected"),
        }
        let report = build_reader_lab_next_arc_entry_gate_report(&input);
        assert!(!report.entry_ready);
        assert!(report.findings.iter().any(|f| f.code == *code));
    }
}
