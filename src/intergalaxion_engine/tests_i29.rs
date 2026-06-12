// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-29 — Reader Lab Next Arc Static Freeze.
#![allow(clippy::bool_assert_comparison)]

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input,
    EbpfReaderLabNextArcEntryGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input,
    EbpfReaderLabNextArcReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{
    build_reader_lab_next_arc_static_freeze_record,
    default_reader_lab_next_arc_static_freeze_input,
    reader_lab_next_arc_static_freeze_decision_label,
    reader_lab_next_arc_static_freeze_finding_kind_label,
    reader_lab_next_arc_static_freeze_status_label,
    validate_reader_lab_next_arc_static_freeze_record, EbpfReaderLabNextArcStaticFreezeDecision,
    EbpfReaderLabNextArcStaticFreezeFindingKind, EbpfReaderLabNextArcStaticFreezeStatus,
};
type Input = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::EbpfReaderLabNextArcStaticFreezeInput;
type Record = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::EbpfReaderLabNextArcStaticFreezeRecord;

fn sdef() -> Record {
    build_reader_lab_next_arc_static_freeze_record(
        &default_reader_lab_next_arc_static_freeze_input(),
    )
}

fn sf() -> Input {
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true;
    gi.prefer_fixture_only_arc = true;
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    Input {
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        next_arc_review_pack: build_reader_lab_next_arc_review_pack(&ri),
        require_next_arc_entry_ready: false,
        require_next_arc_review_ready: false,
        require_experimental_only: true,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
        stable_release_requested: false,
        tag_requested: false,
        publish_requested: false,
        version_bump_requested: false,
        main_merge_requested: false,
    }
}

fn me(f: fn(&mut EbpfReaderLabNextArcEntryGateReport)) -> EbpfReaderLabNextArcEntryGateReport {
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true;
    gi.prefer_fixture_only_arc = true;
    let mut r = build_reader_lab_next_arc_entry_gate_report(&gi);
    f(&mut r);
    r
}

fn mr(f: fn(&mut EbpfReaderLabNextArcReviewPack)) -> EbpfReaderLabNextArcReviewPack {
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    let mut r = build_reader_lab_next_arc_review_pack(&ri);
    f(&mut r);
    r
}

fn has(r: &Record, code: &str) -> bool {
    r.findings.iter().any(|f| f.code == code)
}

#[test]
fn i29_default_input_is_safe() {
    let i = default_reader_lab_next_arc_static_freeze_input();
    assert!(
        i.public_cli_expected_hidden
            && i.usage_schema_expected_unchanged
            && i.ledger_schema_expected_unchanged
            && !i.stable_release_requested
            && !i.tag_requested
            && !i.publish_requested
            && !i.version_bump_requested
            && !i.main_merge_requested
            && !i.require_next_arc_entry_ready
            && !i.require_next_arc_review_ready
            && !i.require_experimental_only
    );
}

#[test]
fn i29_default_record_phase_is_i29() {
    assert_eq!(sdef().phase, "I-29");
}

#[test]
fn i29_default_record_all_operation_flags_false() {
    let r = sdef();
    assert!(
        !r.ring_buffer_opened
            && !r.live_event_stream_read
            && !r.map_pin_performed
            && !r.enforcement_performed
            && !r.packet_drop_performed
            && !r.mutation_performed
            && !r.persistence_performed
    );
}

#[test]
fn i29_status_labels_are_stable() {
    for (v, l) in &[
        (&EbpfReaderLabNextArcStaticFreezeStatus::Draft, "draft"),
        (
            &EbpfReaderLabNextArcStaticFreezeStatus::Incomplete,
            "incomplete",
        ),
        (&EbpfReaderLabNextArcStaticFreezeStatus::Blocked, "blocked"),
        (&EbpfReaderLabNextArcStaticFreezeStatus::Frozen, "frozen"),
        (
            &EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected,
            "freeze_rejected",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ] {
        assert_eq!(reader_lab_next_arc_static_freeze_status_label(**v), *l);
    }
}

#[test]
fn i29_decision_labels_are_stable() {
    for (v, l) in &[
        (&EbpfReaderLabNextArcStaticFreezeDecision::Stop, "stop"),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::FreezeFixtureOnlyArc,
            "freeze_fixture_only_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::FreezeStaticPolicyArc,
            "freeze_static_policy_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::FreezeManualReaderSpikeChecklistArc,
            "freeze_manual_reader_spike_checklist_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::FreezeReaderSpikeReviewArc,
            "freeze_reader_spike_review_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::RejectLiveReaderArc,
            "reject_live_reader_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::RejectPublicCliArc,
            "reject_public_cli_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::RejectReleaseArc,
            "reject_release_arc",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeDecision::RejectEnforcementArc,
            "reject_enforcement_arc",
        ),
    ] {
        assert_eq!(reader_lab_next_arc_static_freeze_decision_label(**v), *l);
    }
}

#[test]
fn i29_finding_kind_labels_are_stable() {
    for (v, l) in &[
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcEntryGate,
            "next_arc_entry_gate",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcReviewPack,
            "next_arc_review_pack",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabNextArcStaticFreezeFindingKind::FreezeInvariant,
            "freeze_invariant",
        ),
    ] {
        assert_eq!(
            reader_lab_next_arc_static_freeze_finding_kind_label(**v),
            *l
        );
    }
}

#[test]
fn i29_default_record_safety_invariants() {
    let r = sdef();
    assert!(
        !r.release_allowed
            && r.must_remain_experimental
            && !r.freeze_passed
            && !r.arc_allowed_live_reader
            && !r.arc_allowed_public_cli
            && !r.arc_allowed_release
            && !r.arc_allowed_enforcement
    );
}

#[test]
fn i29_default_record_all_fake_flags_false() {
    let r = sdef();
    assert!(
        !r.fake_reader_success_detected
            && !r.fake_live_event_counts_detected
            && !r.fake_release_readiness_detected
            && !r.fake_planning_success_detected
            && !r.fake_policy_freeze_success_detected
            && !r.fake_policy_review_success_detected
            && !r.fake_policy_hardening_success_detected
            && !r.fake_policy_completion_success_detected
            && !r.fake_completion_review_success_detected
            && !r.fake_next_arc_entry_success_detected
            && !r.fake_next_arc_review_success_detected
            && !r.fake_next_arc_static_freeze_success_detected
    );
}

// Frozen tests
#[test]
fn i29_frozen_with_experimental_only() {
    let r = build_reader_lab_next_arc_static_freeze_record(&sf());
    assert!(r.freeze_passed && r.experimental_only_confirmed && r.must_remain_experimental);
    assert_eq!(r.status, EbpfReaderLabNextArcStaticFreezeStatus::Frozen);
}
#[test]
fn i29_frozen_decision_fixture_only_arc() {
    let r = build_reader_lab_next_arc_static_freeze_record(&sf());
    assert_eq!(
        r.decision,
        EbpfReaderLabNextArcStaticFreezeDecision::FreezeFixtureOnlyArc
    );
    assert!(r.frozen_fixture_only_arc);
}
#[test]
fn i29_frozen_arc_propagation() {
    let r = build_reader_lab_next_arc_static_freeze_record(&sf());
    let rp = &sf().next_arc_review_pack;
    assert_eq!(r.frozen_fixture_only_arc, rp.selected_fixture_only_arc);
    assert_eq!(r.frozen_static_policy_arc, rp.selected_static_policy_arc);
    assert_eq!(
        r.frozen_manual_reader_spike_checklist_arc,
        rp.selected_manual_reader_spike_checklist_arc
    );
    assert_eq!(
        r.frozen_reader_spike_review_arc,
        rp.selected_reader_spike_review_arc
    );
}
#[test]
fn i29_experimental_only_when_not_confirmed() {
    let mut i = sf();
    i.require_experimental_only = false;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed);
    assert_eq!(
        r.status,
        EbpfReaderLabNextArcStaticFreezeStatus::ExperimentalOnly
    );
}

#[test]
fn i29_blocked_when_release_requested() {
    let mut i = sf();
    i.stable_release_requested = true;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(
        !r.freeze_passed && r.status == EbpfReaderLabNextArcStaticFreezeStatus::ReleaseForbidden
    );
}

#[test]
fn i29_blocked_when_tag_requested() {
    let mut i = sf();
    i.tag_requested = true;
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).status,
        EbpfReaderLabNextArcStaticFreezeStatus::ReleaseForbidden
    );
}

#[test]
fn i29_release_invariants_cycle() {
    for fld in &[
        "stable_release_requested",
        "tag_requested",
        "publish_requested",
        "version_bump_requested",
        "main_merge_requested",
    ] {
        let mut i = sf();
        match *fld {
            "stable_release_requested" => i.stable_release_requested = true,
            "tag_requested" => i.tag_requested = true,
            "publish_requested" => i.publish_requested = true,
            "version_bump_requested" => i.version_bump_requested = true,
            _ => i.main_merge_requested = true,
        }
        let r = build_reader_lab_next_arc_static_freeze_record(&i);
        assert!(!r.freeze_passed && r.findings.iter().any(|f| f.blocking));
    }
}

#[test]
fn i29_schema_invariants_blocked() {
    for fld in &[
        "public_cli_expected_hidden",
        "usage_schema_expected_unchanged",
        "ledger_schema_expected_unchanged",
    ] {
        let mut i = sf();
        match *fld {
            "public_cli_expected_hidden" => i.public_cli_expected_hidden = false,
            "usage_schema_expected_unchanged" => i.usage_schema_expected_unchanged = false,
            _ => i.ledger_schema_expected_unchanged = false,
        }
        assert!(!build_reader_lab_next_arc_static_freeze_record(&i).freeze_passed);
    }
}

// EG forbidden arcs
#[test]
fn i29_eg_forbidden_arcs_live_reader() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.live_reader_arc_allowed = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert_eq!(
        r.decision,
        EbpfReaderLabNextArcStaticFreezeDecision::RejectLiveReaderArc
    );
    assert_eq!(r.status, EbpfReaderLabNextArcStaticFreezeStatus::Blocked);
}

#[test]
fn i29_eg_forbidden_arcs_public_cli() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.public_cli_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::RejectPublicCliArc
    );
}

#[test]
fn i29_eg_forbidden_arcs_release() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.release_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::RejectReleaseArc
    );
}

#[test]
fn i29_eg_forbidden_arcs_enforcement() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.enforcement_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::RejectEnforcementArc
    );
}

// RP forbidden arcs
#[test]
fn i29_rp_forbidden_arcs() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.live_reader_arc_allowed = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-RP-LIVE-READER-ARC"));
    let mut i2 = sf();
    i2.next_arc_review_pack = mr(|r| r.enforcement_arc_allowed = true);
    assert!(!build_reader_lab_next_arc_static_freeze_record(&i2).freeze_passed);
}

// Cross-evidence blocked
#[test]
fn i29_cross_evidence_blocked() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.public_cli_exposed = true);
    assert!(!build_reader_lab_next_arc_static_freeze_record(&i).freeze_passed);
    let mut i2 = sf();
    i2.next_arc_entry_gate_report = me(|r| r.release_allowed = true);
    let r2 = build_reader_lab_next_arc_static_freeze_record(&i2);
    assert!(!r2.freeze_passed && has(&r2, "NASF-CONTRADICTION-RELEASE"));
    let mut i3 = sf();
    i3.next_arc_review_pack = mr(|r| r.live_reader_arc_allowed = true);
    let r3 = build_reader_lab_next_arc_static_freeze_record(&i3);
    assert!(!r3.freeze_passed && has(&r3, "NASF-CONTRADICTION-LIVE-READER"));
    let mut i4 = sf();
    i4.next_arc_review_pack = mr(|r| r.public_cli_arc_allowed = true);
    let r4 = build_reader_lab_next_arc_static_freeze_record(&i4);
    assert!(!r4.freeze_passed && has(&r4, "NASF-CONTRADICTION-PUBLIC-CLI"));
    let mut i5 = sf();
    i5.next_arc_review_pack = mr(|r| r.release_allowed = true);
    let r5 = build_reader_lab_next_arc_static_freeze_record(&i5);
    assert!(!r5.freeze_passed && has(&r5, "NASF-CONTRADICTION-RELEASE"));
}

// Operation flags
#[test]
fn i29_blocked_when_ring_buffer_opened() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.ring_buffer_opened = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(r.ring_buffer_opened && !r.freeze_passed && has(&r, "NASF-OP-FLAGS-TRUE"));
}

#[test]
fn i29_operation_flags_cycle() {
    let ops: &[fn(&mut EbpfReaderLabNextArcEntryGateReport)] = &[
        |r| r.ring_buffer_opened = true,
        |r| r.live_event_stream_read = true,
        |r| r.map_pin_performed = true,
        |r| r.enforcement_performed = true,
        |r| r.packet_drop_performed = true,
        |r| r.mutation_performed = true,
        |r| r.persistence_performed = true,
    ];
    for op in ops {
        let mut i = sf();
        i.next_arc_entry_gate_report = me(*op);
        let r = build_reader_lab_next_arc_static_freeze_record(&i);
        assert!(!r.freeze_passed && r.findings.iter().any(|f| f.blocking));
    }
}

// Fake evidence
#[test]
fn i29_fake_evidence_from_eg_blocks() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.fake_reader_success_detected = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && r.fake_reader_success_detected && has(&r, "NASF-FAKE-READER"));
}

#[test]
fn i29_fake_evidence_from_rp_blocks() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.fake_planning_success_detected = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && r.fake_planning_success_detected && has(&r, "NASF-FAKE-PLANNING"));
}

#[test]
fn i29_fake_flags_cycle() {
    let setters: &[fn(&mut EbpfReaderLabNextArcEntryGateReport)] = &[
        |r| r.fake_reader_success_detected = true,
        |r| r.fake_live_event_counts_detected = true,
        |r| r.fake_release_readiness_detected = true,
        |r| r.fake_planning_success_detected = true,
        |r| r.fake_policy_freeze_success_detected = true,
        |r| r.fake_policy_review_success_detected = true,
        |r| r.fake_policy_hardening_success_detected = true,
        |r| r.fake_policy_completion_success_detected = true,
        |r| r.fake_completion_review_success_detected = true,
        |r| r.fake_next_arc_entry_success_detected = true,
    ];
    let codes = [
        "NASF-FAKE-READER",
        "NASF-FAKE-EVENTS",
        "NASF-FAKE-RELEASE",
        "NASF-FAKE-PLANNING",
        "NASF-FAKE-POLICY-FREEZE",
        "NASF-FAKE-REVIEW",
        "NASF-FAKE-HARDENING",
        "NASF-FAKE-COMPLETION",
        "NASF-FAKE-COMPLETION-REVIEW",
        "NASF-FAKE-ENTRY",
    ];
    for (s, c) in setters.iter().zip(codes.iter()) {
        let mut i = sf();
        i.next_arc_entry_gate_report = me(*s);
        let r = build_reader_lab_next_arc_static_freeze_record(&i);
        assert!(!r.freeze_passed && has(&r, c));
    }
}

#[test]
fn i29_fake_next_arc_review_blocks() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.fake_next_arc_review_success_detected = true);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-FAKE-REVIEW-PACK"));
}

// Evidence validation
#[test]
fn i29_evidence_validation_blocks() {
    let mut eg = me(|_| {});
    eg.phase = String::new();
    let mut i = sf();
    i.next_arc_entry_gate_report = eg;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-EG-INVALID"));
}

#[test]
fn i29_rp_validation_blocks() {
    let mut rp = mr(|_| {});
    rp.phase = String::new();
    let mut i = sf();
    i.next_arc_review_pack = rp;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-RP-INVALID"));
}

// Require flags
#[test]
fn i29_require_entry_ready_blocks() {
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = false;
    let eg = build_reader_lab_next_arc_entry_gate_report(&gi);
    assert!(!eg.entry_ready);
    let mut i = sf();
    i.require_next_arc_entry_ready = true;
    i.next_arc_entry_gate_report = eg;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-EG-NOT-READY"));
}

#[test]
fn i29_require_review_ready_blocks() {
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = false;
    let rp = build_reader_lab_next_arc_review_pack(&ri);
    assert!(!rp.review_ready);
    let mut i = sf();
    i.require_next_arc_review_ready = true;
    i.next_arc_review_pack = rp;
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-RP-NOT-READY"));
}

#[test]
fn i29_no_safe_arc_blocks() {
    let rp = mr(|r| {
        r.selected_fixture_only_arc = false;
        r.selected_static_policy_arc = false;
        r.selected_manual_reader_spike_checklist_arc = false;
        r.selected_reader_spike_review_arc = false;
    });
    let mut i = sf();
    i.next_arc_review_pack = rp;
    assert!(!build_reader_lab_next_arc_static_freeze_record(&i).freeze_passed);
}

// Validate tests
#[test]
fn i29_validate_passes_for_frozen_record() {
    assert!(validate_reader_lab_next_arc_static_freeze_record(
        &build_reader_lab_next_arc_static_freeze_record(&sf())
    )
    .is_ok());
}

#[test]
fn i29_validate_rejects_empty_phase() {
    let mut r = sdef();
    r.phase = String::new();
    assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
}

#[test]
fn i29_validate_rejects_release_allowed() {
    let mut r = sdef();
    r.release_allowed = true;
    assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
}

#[test]
fn i29_validate_rejects_not_experimental() {
    let mut r = sdef();
    r.must_remain_experimental = false;
    assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
}

#[test]
fn i29_validate_rejects_arc_allowed_flags() {
    for fld in &[
        "arc_allowed_live_reader",
        "arc_allowed_public_cli",
        "arc_allowed_release",
        "arc_allowed_enforcement",
    ] {
        let mut r = sdef();
        match *fld {
            "arc_allowed_live_reader" => r.arc_allowed_live_reader = true,
            "arc_allowed_public_cli" => r.arc_allowed_public_cli = true,
            "arc_allowed_release" => r.arc_allowed_release = true,
            _ => r.arc_allowed_enforcement = true,
        }
        assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
    }
}

#[test]
fn i29_validate_rejects_operation_flags() {
    for fld in &[
        "ring_buffer_opened",
        "live_event_stream_read",
        "map_pin_performed",
        "enforcement_performed",
        "packet_drop_performed",
        "mutation_performed",
        "persistence_performed",
    ] {
        let mut r = sdef();
        match *fld {
            "ring_buffer_opened" => r.ring_buffer_opened = true,
            "live_event_stream_read" => r.live_event_stream_read = true,
            "map_pin_performed" => r.map_pin_performed = true,
            "enforcement_performed" => r.enforcement_performed = true,
            "packet_drop_performed" => r.packet_drop_performed = true,
            "mutation_performed" => r.mutation_performed = true,
            _ => r.persistence_performed = true,
        }
        assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
    }
}

#[test]
fn i29_validate_rejects_schema_request_flags() {
    for fld in &[
        "public_cli_exposed",
        "usage_schema_changed",
        "ledger_schema_changed",
        "stable_release_requested",
        "tag_requested",
        "publish_requested",
        "version_bump_requested",
        "main_merge_requested",
    ] {
        let mut r = sdef();
        match *fld {
            "public_cli_exposed" => r.public_cli_exposed = true,
            "usage_schema_changed" => r.usage_schema_changed = true,
            "ledger_schema_changed" => r.ledger_schema_changed = true,
            "stable_release_requested" => r.stable_release_requested = true,
            "tag_requested" => r.tag_requested = true,
            "publish_requested" => r.publish_requested = true,
            "version_bump_requested" => r.version_bump_requested = true,
            _ => r.main_merge_requested = true,
        }
        assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
    }
}

#[test]
fn i29_validate_rejects_all_fake_flags() {
    for fld in &[
        "fake_reader_success_detected",
        "fake_live_event_counts_detected",
        "fake_release_readiness_detected",
        "fake_planning_success_detected",
        "fake_policy_freeze_success_detected",
        "fake_policy_review_success_detected",
        "fake_policy_hardening_success_detected",
        "fake_policy_completion_success_detected",
        "fake_completion_review_success_detected",
        "fake_next_arc_entry_success_detected",
        "fake_next_arc_review_success_detected",
        "fake_next_arc_static_freeze_success_detected",
    ] {
        let mut r = sdef();
        match *fld {
            "fake_reader_success_detected" => r.fake_reader_success_detected = true,
            "fake_live_event_counts_detected" => r.fake_live_event_counts_detected = true,
            "fake_release_readiness_detected" => r.fake_release_readiness_detected = true,
            "fake_planning_success_detected" => r.fake_planning_success_detected = true,
            "fake_policy_freeze_success_detected" => r.fake_policy_freeze_success_detected = true,
            "fake_policy_review_success_detected" => r.fake_policy_review_success_detected = true,
            "fake_policy_hardening_success_detected" => {
                r.fake_policy_hardening_success_detected = true
            }
            "fake_policy_completion_success_detected" => {
                r.fake_policy_completion_success_detected = true
            }
            "fake_completion_review_success_detected" => {
                r.fake_completion_review_success_detected = true
            }
            "fake_next_arc_entry_success_detected" => r.fake_next_arc_entry_success_detected = true,
            "fake_next_arc_review_success_detected" => {
                r.fake_next_arc_review_success_detected = true
            }
            _ => r.fake_next_arc_static_freeze_success_detected = true,
        }
        assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
    }
}

#[test]
fn i29_validate_rejects_freeze_passed_with_rejected() {
    let mut r = sdef();
    r.status = EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected;
    r.freeze_passed = true;
    assert!(validate_reader_lab_next_arc_static_freeze_record(&r).is_err());
}

// Cross-evidence experimental
#[test]
fn i29_must_remain_experimental_cross_blocked() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.must_remain_experimental = false);
    let r = build_reader_lab_next_arc_static_freeze_record(&i);
    assert!(!r.freeze_passed && has(&r, "NASF-NOT-EXPERIMENTAL"));
}

#[test]
fn i29_frozen_record_no_blocking_findings() {
    assert!(build_reader_lab_next_arc_static_freeze_record(&sf())
        .findings
        .is_empty());
}

// Freeze priority
#[test]
fn i29_frozen_priority_static_policy_arc() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| {
        r.selected_static_policy_arc = true;
        r.selected_fixture_only_arc = true;
    });
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::FreezeStaticPolicyArc
    );
}

#[test]
fn i29_frozen_priority_fixture_only_arc() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.selected_fixture_only_arc = true);
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::FreezeFixtureOnlyArc
    );
}

#[test]
fn i29_frozen_priority_manual_checklist_arc() {
    let rp = mr(|r| {
        r.selected_manual_reader_spike_checklist_arc = true;
        r.selected_fixture_only_arc = false;
        r.selected_static_policy_arc = false;
    });
    let mut i = sf();
    i.next_arc_review_pack = rp;
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::FreezeManualReaderSpikeChecklistArc
    );
}

#[test]
fn i29_frozen_priority_reader_spike_review_arc() {
    let rp = mr(|r| {
        r.selected_reader_spike_review_arc = true;
        r.selected_fixture_only_arc = false;
        r.selected_static_policy_arc = false;
        r.selected_manual_reader_spike_checklist_arc = false;
    });
    let mut i = sf();
    i.next_arc_review_pack = rp;
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::FreezeReaderSpikeReviewArc
    );
}

// Propagation
#[test]
fn i29_entry_ready_propagated() {
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&sf()).next_arc_entry_ready,
        sf().next_arc_entry_gate_report.entry_ready
    );
}

#[test]
fn i29_review_ready_propagated() {
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&sf()).next_arc_review_ready,
        sf().next_arc_review_pack.review_ready
    );
}

#[test]
fn i29_schema_flags_propagated() {
    let r = build_reader_lab_next_arc_static_freeze_record(&sf());
    assert!(!r.public_cli_exposed && !r.usage_schema_changed && !r.ledger_schema_changed);
}

#[test]
fn i29_arc_allowed_propagation() {
    let r = build_reader_lab_next_arc_static_freeze_record(&sf());
    assert!(
        !r.arc_allowed_live_reader
            && !r.arc_allowed_public_cli
            && !r.arc_allowed_release
            && !r.arc_allowed_enforcement
    );
}

#[test]
fn i29_stable_release_propagated() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert!(build_reader_lab_next_arc_static_freeze_record(&i).stable_release_requested);
}

// Source integrity
#[test]
fn i29_source_file_copyright_header() {
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_static_freeze.rs");
    assert!(
        src.starts_with("// Copyright (C) 2026 rezky_nightky")
            && src.contains("SPDX-License-Identifier: GPL-3.0-only")
    );
}

#[test]
fn i29_no_forbidden_patterns_in_source() {
    let nc: String =
        include_str!("backends/ebpf/event_stream_reader_lab_next_arc_static_freeze.rs")
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    assert!(!nc.contains("nftables") && !nc.contains("tc qdisc") && !nc.contains("/drop"));
}

#[test]
fn i29_cargo_toml_unchanged() {
    assert!(include_str!("../../Cargo.toml").contains("name = \"zelynic\""));
}

#[test]
fn i29_doc_file_exists() {
    assert!(
        !include_str!("../../docs/intergalaxion/I-29-reader-lab-next-arc-static-freeze.md")
            .is_empty()
    );
}

#[test]
fn i29_no_new_cli_commands() {
    let nc: String =
        include_str!("backends/ebpf/event_stream_reader_lab_next_arc_static_freeze.rs")
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    assert!(!nc.contains("clap") && !nc.contains("Command"));
}

#[test]
fn i29_release_forbidden_decision() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).decision,
        EbpfReaderLabNextArcStaticFreezeDecision::RejectReleaseArc
    );
}

#[test]
fn i29_blocked_multi_arc_conflict() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| {
        r.enforcement_arc_allowed = true;
        r.release_arc_allowed = true;
    });
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).status,
        EbpfReaderLabNextArcStaticFreezeStatus::Blocked
    );
}

#[test]
fn i29_multiple_findings_on_violations() {
    let eg = me(|r| {
        r.release_allowed = true;
        r.public_cli_exposed = true;
        r.ring_buffer_opened = true;
        r.fake_reader_success_detected = true;
    });
    let mut i = sf();
    i.stable_release_requested = true;
    i.next_arc_entry_gate_report = eg;
    assert!(
        build_reader_lab_next_arc_static_freeze_record(&i)
            .findings
            .len()
            >= 3
    );
}

#[test]
fn i29_freeze_rejected_no_arc() {
    let rp = mr(|r| {
        r.selected_fixture_only_arc = false;
        r.selected_static_policy_arc = false;
        r.selected_manual_reader_spike_checklist_arc = false;
        r.selected_reader_spike_review_arc = false;
    });
    let mut i = sf();
    i.next_arc_review_pack = rp;
    assert_eq!(
        build_reader_lab_next_arc_static_freeze_record(&i).status,
        EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected
    );
}

#[test]
fn i29_incomplete_all_invalid() {
    let mut eg = me(|_| {});
    eg.phase = String::new();
    let mut rp = mr(|_| {});
    rp.phase = String::new();
    let mut i = sf();
    i.next_arc_entry_gate_report = eg;
    i.next_arc_review_pack = rp;
    i.require_experimental_only = false;
    assert!(!build_reader_lab_next_arc_static_freeze_record(&i).freeze_passed);
}

#[test]
fn i29_enum_equality() {
    assert_eq!(
        EbpfReaderLabNextArcStaticFreezeStatus::Draft,
        EbpfReaderLabNextArcStaticFreezeStatus::Draft
    );
    assert_eq!(
        EbpfReaderLabNextArcStaticFreezeDecision::Stop,
        EbpfReaderLabNextArcStaticFreezeDecision::Stop
    );
    assert_eq!(
        EbpfReaderLabNextArcStaticFreezeFindingKind::FreezeInvariant,
        EbpfReaderLabNextArcStaticFreezeFindingKind::FreezeInvariant
    );
}

#[test]
fn i29_record_clone_debug() {
    let r = sdef();
    assert_eq!(r, r.clone());
    assert!(format!("{:?}", r).contains("I-29"));
}
