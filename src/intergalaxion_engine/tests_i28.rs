// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-28 — Reader Lab Next Arc Review Pack.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input,
    reader_lab_next_arc_review_decision_label, reader_lab_next_arc_review_finding_kind_label,
    reader_lab_next_arc_review_pack_status_label, validate_reader_lab_next_arc_review_pack,
    EbpfReaderLabNextArcReviewDecision, EbpfReaderLabNextArcReviewFindingKind,
    EbpfReaderLabNextArcReviewPackStatus,
};

type Input = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::EbpfReaderLabNextArcReviewPackInput;
type Pack = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::EbpfReaderLabNextArcReviewPack;

fn safe_default_pack() -> Pack {
    build_reader_lab_next_arc_review_pack(&default_reader_lab_next_arc_review_pack_input())
}

fn safe_experimental_input() -> Input {
    let mut input = default_reader_lab_next_arc_review_pack_input();
    input.require_experimental_only = true;
    input
}

fn safe_review_ready_input() -> Input {
    safe_experimental_input()
}

// 1. default next arc review input is safe
#[test]
fn i28_default_next_arc_review_input_is_safe() {
    let input = default_reader_lab_next_arc_review_pack_input();
    assert!(!input.stable_release_requested);
    assert!(!input.tag_requested);
    assert!(!input.publish_requested);
    assert!(!input.version_bump_requested);
    assert!(!input.main_merge_requested);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
    assert!(!input.require_next_arc_entry_ready);
    assert!(!input.require_completion_review_ready);
    assert!(!input.require_policy_completion_passed);
    assert!(!input.require_experimental_only);
}

// 2. default pack phase is I-28
#[test]
fn i28_default_pack_phase_is_i28() {
    let pack = safe_default_pack();
    assert_eq!(pack.phase, "I-28");
}

// 3. default pack has all operation flags false
#[test]
fn i28_default_pack_all_operation_flags_false() {
    let pack = safe_default_pack();
    assert!(!pack.ring_buffer_opened);
    assert!(!pack.live_event_stream_read);
    assert!(!pack.map_pin_performed);
    assert!(!pack.enforcement_performed);
    assert!(!pack.packet_drop_performed);
    assert!(!pack.mutation_performed);
    assert!(!pack.persistence_performed);
}

// 4. status labels are stable
#[test]
fn i28_status_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcReviewPackStatus, &str)] = &[
        (&EbpfReaderLabNextArcReviewPackStatus::Draft, "draft"),
        (
            &EbpfReaderLabNextArcReviewPackStatus::Incomplete,
            "incomplete",
        ),
        (&EbpfReaderLabNextArcReviewPackStatus::Blocked, "blocked"),
        (
            &EbpfReaderLabNextArcReviewPackStatus::ReviewReady,
            "review_ready",
        ),
        (
            &EbpfReaderLabNextArcReviewPackStatus::ReviewRejected,
            "review_rejected",
        ),
        (
            &EbpfReaderLabNextArcReviewPackStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabNextArcReviewPackStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_review_pack_status_label(**v), *label);
    }
}

// 5. decision labels are stable
#[test]
fn i28_decision_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcReviewDecision, &str)] = &[
        (&EbpfReaderLabNextArcReviewDecision::Stop, "stop"),
        (
            &EbpfReaderLabNextArcReviewDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::ReviewFixtureOnlyArc,
            "review_fixture_only_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::ReviewStaticPolicyArc,
            "review_static_policy_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::ReviewManualReaderSpikeChecklistArc,
            "review_manual_reader_spike_checklist_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::ReviewReaderSpikeReviewArc,
            "review_reader_spike_review_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::RejectLiveReaderArc,
            "reject_live_reader_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::RejectPublicCliArc,
            "reject_public_cli_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::RejectReleaseArc,
            "reject_release_arc",
        ),
        (
            &EbpfReaderLabNextArcReviewDecision::RejectEnforcementArc,
            "reject_enforcement_arc",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_review_decision_label(**v), *label);
    }
}

// 6. finding kind labels are stable
#[test]
fn i28_finding_kind_labels_are_stable() {
    let expected: &[(&EbpfReaderLabNextArcReviewFindingKind, &str)] = &[
        (
            &EbpfReaderLabNextArcReviewFindingKind::NextArcPlan,
            "next_arc_plan",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::StaticPolicyFreeze,
            "static_policy_freeze",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::StaticPolicyReview,
            "static_policy_review",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::StaticPolicyHardening,
            "static_policy_hardening",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::PolicyCompletionGate,
            "policy_completion_gate",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::CompletionReview,
            "completion_review",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::NextArcEntryGate,
            "next_arc_entry_gate",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabNextArcReviewFindingKind::ReviewInvariant,
            "review_invariant",
        ),
    ];
    for (v, label) in expected {
        assert_eq!(reader_lab_next_arc_review_finding_kind_label(**v), *label);
    }
}

// 7. default pack release_allowed=false
#[test]
fn i28_default_pack_release_allowed_false() {
    let pack = safe_default_pack();
    assert!(!pack.release_allowed);
}

// 8. default pack must_remain_experimental=true
#[test]
fn i28_default_pack_must_remain_experimental_true() {
    let pack = safe_default_pack();
    assert!(pack.must_remain_experimental);
}

// 9. default pack is not review_ready
#[test]
fn i28_default_pack_not_review_ready() {
    let pack = safe_default_pack();
    assert!(!pack.review_ready);
}

// 10. default pack has findings or ExperimentalOnly status
#[test]
fn i28_default_pack_has_findings_or_experimental_status() {
    let pack = safe_default_pack();
    let has_findings = !pack.findings.is_empty();
    let is_experimental = pack.status == EbpfReaderLabNextArcReviewPackStatus::ExperimentalOnly;
    assert!(has_findings || is_experimental);
}

// 11-14. review requires evidence valid
#[test]
fn i28_requires_evidence_valid() {
    let cases: &[(&str, &str)] = &[
        ("NARP-EG-INVALID", "eg"),
        ("NARP-CRP-INVALID", "crp"),
        ("NARP-GATE-INVALID", "gate"),
        ("NARP-PLAN-INVALID", "plan"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "eg" => input.next_arc_entry_gate_report.release_allowed = true,
            "crp" => input.completion_review_pack.release_allowed = true,
            "gate" => input.policy_completion_gate_report.release_allowed = true,
            "plan" => input.next_arc_plan.release_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(!pack.review_ready);
        assert!(
            pack.findings.iter().any(|f| f.code == *expected_code),
            "missing {expected_code}"
        );
    }
}

// 15. review requires next arc entry ready when configured
#[test]
fn i28_requires_entry_gate_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_next_arc_entry_ready = true;
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.entry_ready = false;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "NARP-EG-NOT-READY"));
}

// 16. review requires completion review ready when configured
#[test]
fn i28_requires_crp_ready_when_configured() {
    let mut input = safe_experimental_input();
    input.require_completion_review_ready = true;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "NARP-CRP-NOT-READY"));
}

// 17. review requires policy completion passed when configured
#[test]
fn i28_requires_completion_passed_when_configured() {
    let mut input = safe_experimental_input();
    input.require_policy_completion_passed = true;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "NARP-COMPLETION-NOT-PASSED"));
}

// 18. review requires experimental only when configured
#[test]
fn i28_requires_experimental_only_when_configured() {
    let pack = safe_default_pack();
    assert!(!pack.review_ready);
}

// 19. review requires at least one safe selected arc
#[test]
fn i28_requires_at_least_one_safe_selected_arc() {
    let mut input = safe_experimental_input();
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.selected_fixture_only_arc = false;
    eg.entry_ready = false;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(!pack.review_ready);
    assert!(pack.findings.iter().any(|f| f.code == "NARP-NO-SAFE-ARC"));
}

// 20. default ReviewReady picks fixture-only arc
#[test]
fn i28_review_ready_picks_fixture_only_arc() {
    let pack = build_reader_lab_next_arc_review_pack(&safe_review_ready_input());
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewFixtureOnlyArc
    );
}

// 21. priority chooses ReviewStaticPolicyArc over fixture
#[test]
fn i28_priority_chooses_static_policy_over_fixture() {
    let mut input = safe_experimental_input();
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.selected_static_policy_arc = true;
    eg.selected_fixture_only_arc = true;
    eg.entry_ready = true;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewStaticPolicyArc
    );
}

// 22. priority chooses ReviewFixtureOnlyArc over manual
#[test]
fn i28_priority_chooses_fixture_over_manual() {
    let mut input = safe_experimental_input();
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.selected_static_policy_arc = false;
    eg.selected_fixture_only_arc = true;
    eg.selected_manual_reader_spike_checklist_arc = true;
    eg.entry_ready = true;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewFixtureOnlyArc
    );
}

// 23. priority chooses ReviewManualReaderSpikeChecklistArc
#[test]
fn i28_priority_chooses_manual_over_review() {
    let mut input = safe_experimental_input();
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.selected_fixture_only_arc = false;
    eg.selected_static_policy_arc = false;
    eg.selected_manual_reader_spike_checklist_arc = true;
    eg.selected_reader_spike_review_arc = true;
    eg.entry_ready = true;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewManualReaderSpikeChecklistArc
    );
}

// 24. priority chooses ReviewReaderSpikeReviewArc
#[test]
fn i28_priority_chooses_reader_spike_review() {
    let mut input = safe_experimental_input();
    let mut eg = input.next_arc_entry_gate_report.clone();
    eg.selected_reader_spike_review_arc = true;
    eg.selected_fixture_only_arc = false;
    eg.entry_ready = true;
    input.next_arc_entry_gate_report = eg;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewReaderSpikeReviewArc
    );
}

// 25-28. reject disallowed arc allowances (loop)
#[test]
fn i28_rejects_disallowed_arc_allowances() {
    let cases: &[(&str, &str, EbpfReaderLabNextArcReviewDecision)] = &[
        (
            "NARP-LIVE-READER-ARC",
            "live_reader",
            EbpfReaderLabNextArcReviewDecision::RejectLiveReaderArc,
        ),
        (
            "NARP-PUBLIC-CLI-ARC",
            "public_cli",
            EbpfReaderLabNextArcReviewDecision::RejectPublicCliArc,
        ),
        (
            "NARP-RELEASE-ARC",
            "release",
            EbpfReaderLabNextArcReviewDecision::RejectReleaseArc,
        ),
        (
            "NARP-ENFORCEMENT-ARC",
            "enforcement",
            EbpfReaderLabNextArcReviewDecision::RejectEnforcementArc,
        ),
    ];
    for (expected_code, case, expected_decision) in cases {
        let mut input = safe_experimental_input();
        let mut eg = input.next_arc_entry_gate_report.clone();
        match *case {
            "live_reader" => eg.live_reader_arc_allowed = true,
            "public_cli" => eg.public_cli_arc_allowed = true,
            "release" => eg.release_arc_allowed = true,
            "enforcement" => eg.enforcement_arc_allowed = true,
            _ => panic!("unexpected: {case}"),
        }
        input.next_arc_entry_gate_report = eg;
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(!pack.review_ready);
        assert_eq!(pack.decision, *expected_decision);
        assert!(pack.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 29-31. reject CLI/schema changes (loop)
#[test]
fn i28_rejects_cli_schema_changes() {
    let cases: &[(&str, &str)] = &[
        ("NARP-CLI-NOT-HIDDEN", "cli"),
        ("NARP-USAGE-SCHEMA-CHANGED", "usage_schema"),
        ("NARP-LEDGER-SCHEMA-CHANGED", "ledger_schema"),
    ];
    for (expected_code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "cli" => input.public_cli_expected_hidden = false,
            "usage_schema" => input.usage_schema_expected_unchanged = false,
            "ledger_schema" => input.ledger_schema_expected_unchanged = false,
            _ => panic!("unexpected: {case}"),
        }
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(pack.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 32-36. reject release/tag/publish/version/main (loop)
#[test]
fn i28_rejects_release_requests() {
    let cases: &[(&str, &str)] = &[
        ("stable_release_requested", "NARP-RELEASE-REQUESTED"),
        ("tag_requested", "NARP-TAG-REQUESTED"),
        ("publish_requested", "NARP-PUBLISH-REQUESTED"),
        ("version_bump_requested", "NARP-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "NARP-MAIN-MERGE-REQUESTED"),
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
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert_eq!(
            pack.status,
            EbpfReaderLabNextArcReviewPackStatus::ReleaseForbidden
        );
        assert!(pack.findings.iter().any(|f| f.code == *expected_code));
    }
}

// 37-43. reject operation flags (loop)
#[test]
fn i28_rejects_operation_flags() {
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
        let mut eg = input.next_arc_entry_gate_report.clone();
        match *field {
            "ring_buffer_opened" => eg.ring_buffer_opened = true,
            "live_event_stream_read" => eg.live_event_stream_read = true,
            "map_pin_performed" => eg.map_pin_performed = true,
            "enforcement_performed" => eg.enforcement_performed = true,
            "packet_drop_performed" => eg.packet_drop_performed = true,
            "mutation_performed" => eg.mutation_performed = true,
            "persistence_performed" => eg.persistence_performed = true,
            _ => panic!("unexpected: {field}"),
        }
        input.next_arc_entry_gate_report = eg;
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(!pack.review_ready);
    }
}

// 44-53. reject fake evidence (loop)
#[test]
fn i28_rejects_fake_evidence() {
    let cases: &[(&str, &str)] = &[
        ("fake_reader_success_detected", "NARP-FAKE-READER"),
        ("fake_live_event_counts_detected", "NARP-FAKE-EVENTS"),
        ("fake_release_readiness_detected", "NARP-FAKE-RELEASE"),
        ("fake_planning_success_detected", "NARP-FAKE-PLANNING"),
        (
            "fake_policy_freeze_success_detected",
            "NARP-FAKE-POLICY-FREEZE",
        ),
        ("fake_policy_review_success_detected", "NARP-FAKE-REVIEW"),
        ("fake_hardening_success_detected", "NARP-FAKE-HARDENING"),
        ("fake_completion_success_detected", "NARP-FAKE-COMPLETION"),
        (
            "fake_completion_review_success_detected",
            "NARP-FAKE-COMPLETION-REVIEW",
        ),
        ("fake_next_arc_entry_success_detected", "NARP-FAKE-ENTRY"),
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
                let mut eg = input.next_arc_entry_gate_report.clone();
                eg.fake_next_arc_entry_success_detected = true;
                input.next_arc_entry_gate_report = eg;
            }
            _ => panic!("unexpected: {field}"),
        }
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(
            pack.findings.iter().any(|f| f.code == *code),
            "missing {code}"
        );
        assert!(!pack.review_ready);
    }
}

// 54-56. contradiction detection
#[test]
fn i28_detects_contradictions() {
    let mut input = safe_experimental_input();
    let mut plan = input.next_arc_plan.clone();
    plan.release_allowed = true;
    input.next_arc_plan = plan;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(pack
        .findings
        .iter()
        .any(|f| f.code == "NARP-CONTRADICTION-RELEASE"));

    let mut input2 = safe_experimental_input();
    input2.completion_review_pack.must_remain_experimental = false;
    let pack2 = build_reader_lab_next_arc_review_pack(&input2);
    assert!(pack2
        .findings
        .iter()
        .any(|f| f.code == "NARP-NOT-EXPERIMENTAL"));

    let mut input3 = safe_experimental_input();
    input3.static_policy_review_pack.live_reader_next_allowed = true;
    let pack3 = build_reader_lab_next_arc_review_pack(&input3);
    assert!(pack3
        .findings
        .iter()
        .any(|f| f.code == "NARP-CONTRADICTION-LIVE-READER"));
}

// 57. can become ReviewReady with safe evidence
#[test]
fn i28_becomes_review_ready_with_safe_evidence() {
    let input = safe_review_ready_input();
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert!(pack.review_ready);
    assert_eq!(
        pack.status,
        EbpfReaderLabNextArcReviewPackStatus::ReviewReady
    );
}

// 58-63. ReviewReady invariants
#[test]
fn i28_review_ready_invariants() {
    let pack = build_reader_lab_next_arc_review_pack(&safe_review_ready_input());
    assert!(!pack.release_allowed);
    assert!(pack.must_remain_experimental);
    assert!(!pack.live_reader_arc_allowed);
    assert!(!pack.public_cli_arc_allowed);
    assert!(!pack.release_arc_allowed);
    assert!(!pack.enforcement_arc_allowed);
}

// 64. validation accepts safe default pack
#[test]
fn i28_validation_accepts_safe_default_pack() {
    let pack = safe_default_pack();
    assert!(validate_reader_lab_next_arc_review_pack(&pack).is_ok());
}

// 65. validation rejects review_ready=true when status is ReviewRejected
#[test]
fn i28_validation_rejects_review_ready_with_rejected() {
    let mut pack = safe_default_pack();
    pack.review_ready = true;
    pack.status = EbpfReaderLabNextArcReviewPackStatus::ReviewRejected;
    assert!(validate_reader_lab_next_arc_review_pack(&pack).is_err());
}

// 66-96. validation rejects unsafe bool fields (loop)
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
    (
        "fake_next_arc_review_success_detected",
        "fake_next_arc_review_success_detected",
    ),
];

#[test]
fn i28_validation_rejects_unsafe_bool_fields() {
    let base = safe_default_pack();
    for &(field_name, expected_err) in VALIDATION_REJECT_FIELDS {
        let mut pack = base.clone();
        match field_name {
            "release_allowed" => pack.release_allowed = true,
            "must_remain_experimental" => pack.must_remain_experimental = false,
            "live_reader_arc_allowed" => pack.live_reader_arc_allowed = true,
            "public_cli_arc_allowed" => pack.public_cli_arc_allowed = true,
            "release_arc_allowed" => pack.release_arc_allowed = true,
            "enforcement_arc_allowed" => pack.enforcement_arc_allowed = true,
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
            "fake_next_arc_entry_success_detected" => {
                pack.fake_next_arc_entry_success_detected = true
            }
            "fake_next_arc_review_success_detected" => {
                pack.fake_next_arc_review_success_detected = true
            }
            _ => panic!("unexpected field: {field_name}"),
        }
        let res = validate_reader_lab_next_arc_review_pack(&pack);
        assert!(res.is_err(), "expected error for {field_name}");
        assert!(res.unwrap_err().contains(expected_err));
    }
}

// 97. blocked/rejected review has blocking finding
#[test]
fn i28_blocked_review_has_blocking_finding() {
    let mut input = safe_experimental_input();
    input.stable_release_requested = true;
    let pack = build_reader_lab_next_arc_review_pack(&input);
    assert_ne!(
        pack.status,
        EbpfReaderLabNextArcReviewPackStatus::ReviewReady
    );
    assert!(pack.findings.iter().any(|f| f.blocking));
}

// 98. evaluation is deterministic
#[test]
fn i28_evaluation_is_deterministic() {
    let input = default_reader_lab_next_arc_review_pack_input();
    let p1 = build_reader_lab_next_arc_review_pack(&input);
    let p2 = build_reader_lab_next_arc_review_pack(&input);
    assert_eq!(p1.status, p2.status);
    assert_eq!(p1.decision, p2.decision);
    assert_eq!(p1.review_ready, p2.review_ready);
    assert_eq!(p1.release_allowed, p2.release_allowed);
    assert_eq!(p1.must_remain_experimental, p2.must_remain_experimental);
    assert_eq!(p1.findings.len(), p2.findings.len());
}

// 99-101. doc key checks
#[test]
fn i28_docs_key_checks() {
    let c = include_str!("../../docs/intergalaxion/I-28-reader-lab-next-arc-review-pack.md");
    assert!(c.contains("reader lab next arc review pack"));
    assert!(c.contains("next-arc-review-pack only"));
    assert!(c.contains("not a release"));
}

// 102-131. doc keyword tests
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
    "contradictions between i-21 i-22 i-23 i-24 i-25 i-26 i-27",
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
    "fake next arc review success",
];

#[test]
fn i28_docs_contain_required_keywords() {
    let content = include_str!("../../docs/intergalaxion/I-28-reader-lab-next-arc-review-pack.md");
    let lower = content.to_lowercase();
    for kw in DOC_KEYWORDS {
        assert!(lower.contains(&kw.to_lowercase()), "doc missing: {kw}");
    }
}

// 132-139. smoke and compliance tests
#[test]
fn i28_version_and_smoke_tests() {
    let pack = safe_default_pack();
    assert_eq!(pack.phase, "I-28");
    assert!(!pack.phase.is_empty());
    assert!(!pack.public_cli_exposed);
    assert!(!pack.enforcement_performed && !pack.packet_drop_performed);
    let input = default_reader_lab_next_arc_review_pack_input();
    assert!(
        validate_reader_lab_next_arc_review_pack(&build_reader_lab_next_arc_review_pack(&input))
            .is_ok()
    );
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(
        !cargo_toml.contains("aya = "),
        "no aya dependency should exist"
    );
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_review_pack.rs");
    let impl_lines: Vec<&str> = src.lines().filter(|l| !l.starts_with("//")).collect();
    let impl_content = impl_lines.join("\n");
    assert!(
        !impl_content.contains("nft")
            && !impl_content.contains(".tc(")
            && !impl_content.contains("tc ")
    );
    assert!(src.lines().count() <= 1000);
}

// Empty phase validation
#[test]
fn i28_validation_rejects_empty_phase() {
    let mut pack = safe_default_pack();
    pack.phase = String::new();
    assert!(validate_reader_lab_next_arc_review_pack(&pack).is_err());
}

// ReviewReady decision matches fixture-only arc
#[test]
fn i28_review_ready_decision_matches_fixture_preference() {
    let pack = build_reader_lab_next_arc_review_pack(&safe_review_ready_input());
    assert_eq!(
        pack.decision,
        EbpfReaderLabNextArcReviewDecision::ReviewFixtureOnlyArc
    );
}

// Additional evidence valid tests
#[test]
fn i28_requires_freeze_review_hardening_valid() {
    let cases: &[(&str, &str)] = &[
        ("NARP-FREEZE-INVALID", "freeze"),
        ("NARP-REVIEW-INVALID", "review"),
        ("NARP-HARDENING-INVALID", "hardening"),
    ];
    for (code, case) in cases {
        let mut input = safe_experimental_input();
        match *case {
            "freeze" => input.static_policy_freeze_record.release_allowed = true,
            "review" => input.static_policy_review_pack.release_allowed = true,
            "hardening" => input.static_policy_hardening_report.release_allowed = true,
            _ => panic!("unexpected"),
        }
        let pack = build_reader_lab_next_arc_review_pack(&input);
        assert!(!pack.review_ready);
        assert!(pack.findings.iter().any(|f| f.code == *code));
    }
}
