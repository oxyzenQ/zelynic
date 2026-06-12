// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Tests for Phase I-30 — Reader Lab Next Arc Freeze Review Pack.
#![allow(clippy::bool_assert_comparison)]

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_freeze_review_pack::{
    build_reader_lab_next_arc_freeze_review_pack, default_reader_lab_next_arc_freeze_review_pack_input,
    reader_lab_next_arc_freeze_review_decision_label,
    reader_lab_next_arc_freeze_review_finding_kind_label,
    reader_lab_next_arc_freeze_review_pack_status_label, validate_reader_lab_next_arc_freeze_review_pack,
    EbpfReaderLabNextArcFreezeReviewDecision, EbpfReaderLabNextArcFreezeReviewFindingKind,
    EbpfReaderLabNextArcFreezeReviewPackStatus,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input,
    EbpfReaderLabNextArcEntryGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input,
    EbpfReaderLabNextArcReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{
    build_reader_lab_next_arc_static_freeze_record, default_reader_lab_next_arc_static_freeze_input,
    EbpfReaderLabNextArcStaticFreezeRecord,
};
type Input = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_freeze_review_pack::EbpfReaderLabNextArcFreezeReviewPackInput;
type Pack = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_freeze_review_pack::EbpfReaderLabNextArcFreezeReviewPack;

fn sdef() -> Pack {
    build_reader_lab_next_arc_freeze_review_pack(
        &default_reader_lab_next_arc_freeze_review_pack_input(),
    )
}
fn sf() -> Input {
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true;
    gi.prefer_fixture_only_arc = true;
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    let mut fi = default_reader_lab_next_arc_static_freeze_input();
    fi.require_experimental_only = true;
    Input {
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        next_arc_review_pack: build_reader_lab_next_arc_review_pack(&ri),
        next_arc_static_freeze_record: build_reader_lab_next_arc_static_freeze_record(&fi),
        require_next_arc_entry_ready: false,
        require_next_arc_review_ready: false,
        require_next_arc_static_freeze_passed: false,
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
fn msf(
    f: fn(&mut EbpfReaderLabNextArcStaticFreezeRecord),
) -> EbpfReaderLabNextArcStaticFreezeRecord {
    let mut fi = default_reader_lab_next_arc_static_freeze_input();
    fi.require_experimental_only = true;
    let mut r = build_reader_lab_next_arc_static_freeze_record(&fi);
    f(&mut r);
    r
}
fn has(r: &Pack, code: &str) -> bool {
    r.findings.iter().any(|f| f.code == code)
}

#[test]
fn i30_default_input_is_safe() {
    let i = default_reader_lab_next_arc_freeze_review_pack_input();
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
            && !i.require_next_arc_static_freeze_passed
            && !i.require_experimental_only
    );
}
#[test]
fn i30_default_pack_phase() {
    assert_eq!(sdef().phase, "I-30");
}
#[test]
fn i30_all_operation_flags_false() {
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
fn i30_status_labels_stable() {
    for (v, l) in &[
        (&EbpfReaderLabNextArcFreezeReviewPackStatus::Draft, "draft"),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::Incomplete,
            "incomplete",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::Blocked,
            "blocked",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady,
            "review_ready",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewRejected,
            "review_rejected",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::ExperimentalOnly,
            "experimental_only",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewPackStatus::ReleaseForbidden,
            "release_forbidden",
        ),
    ] {
        assert_eq!(reader_lab_next_arc_freeze_review_pack_status_label(**v), *l);
    }
}
#[test]
fn i30_decision_labels_stable() {
    for (v, l) in &[
        (&EbpfReaderLabNextArcFreezeReviewDecision::Stop, "stop"),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::KeepExperimental,
            "keep_experimental",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenFixtureOnlyArc,
            "review_frozen_fixture_only_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenStaticPolicyArc,
            "review_frozen_static_policy_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenManualReaderSpikeChecklistArc,
            "review_frozen_manual_reader_spike_checklist_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenReaderSpikeReviewArc,
            "review_frozen_reader_spike_review_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::RejectLiveReaderArc,
            "reject_live_reader_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::RejectPublicCliArc,
            "reject_public_cli_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::RejectReleaseArc,
            "reject_release_arc",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewDecision::RejectEnforcementArc,
            "reject_enforcement_arc",
        ),
    ] {
        assert_eq!(reader_lab_next_arc_freeze_review_decision_label(**v), *l);
    }
}
#[test]
fn i30_finding_kind_labels_stable() {
    for (v, l) in &[
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcEntryGate,
            "next_arc_entry_gate",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcReviewPack,
            "next_arc_review_pack",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcStaticFreeze,
            "next_arc_static_freeze",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::ReleaseInvariant,
            "release_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant,
            "cli_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::SchemaInvariant,
            "schema_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::RuntimeInvariant,
            "runtime_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::KernelInvariant,
            "kernel_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::MutationInvariant,
            "mutation_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::FakeEvidenceInvariant,
            "fake_evidence_invariant",
        ),
        (
            &EbpfReaderLabNextArcFreezeReviewFindingKind::ReviewInvariant,
            "review_invariant",
        ),
    ] {
        assert_eq!(
            reader_lab_next_arc_freeze_review_finding_kind_label(**v),
            *l
        );
    }
}
#[test]
fn i30_safety_invariants() {
    let r = sdef();
    assert!(
        !r.release_allowed
            && r.must_remain_experimental
            && !r.review_ready
            && !r.live_reader_arc_allowed
            && !r.public_cli_arc_allowed
            && !r.release_arc_allowed
            && !r.enforcement_arc_allowed
    );
}
#[test]
fn i30_all_fake_flags_false() {
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
            && !r.fake_next_arc_freeze_review_success_detected
    );
}
#[test]
fn i30_default_not_review_ready() {
    let r = sdef();
    assert!(!r.review_ready && !r.findings.is_empty());
    assert_eq!(
        r.status,
        EbpfReaderLabNextArcFreezeReviewPackStatus::ExperimentalOnly
    );
}
// ReviewReady
#[test]
fn i30_review_ready_with_frozen_fixture() {
    let r = build_reader_lab_next_arc_freeze_review_pack(&sf());
    assert!(
        r.review_ready
            && r.must_remain_experimental
            && !r.release_allowed
            && r.frozen_fixture_only_arc
            && !r.live_reader_arc_allowed
            && !r.public_cli_arc_allowed
            && !r.release_arc_allowed
            && !r.enforcement_arc_allowed
    );
    assert_eq!(
        r.decision,
        EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenFixtureOnlyArc
    );
}
// 11-13: Evidence validation
#[test]
fn i30_requires_eg_valid() {
    let mut eg = me(|_| {});
    eg.phase = String::new();
    let mut i = sf();
    i.next_arc_entry_gate_report = eg;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-EG-INVALID"));
}
#[test]
fn i30_requires_rp_valid() {
    let mut rp = mr(|_| {});
    rp.phase = String::new();
    let mut i = sf();
    i.next_arc_review_pack = rp;
    assert!(!build_reader_lab_next_arc_freeze_review_pack(&i).review_ready);
}
#[test]
fn i30_requires_sf_valid() {
    let mut s = msf(|_| {});
    s.phase = String::new();
    let mut i = sf();
    i.next_arc_static_freeze_record = s;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-SF-INVALID"));
}
// 15-17: Require flags
#[test]
fn i30_require_entry_ready_blocks() {
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = false;
    let eg = build_reader_lab_next_arc_entry_gate_report(&gi);
    assert!(!eg.entry_ready);
    let mut i = sf();
    i.require_next_arc_entry_ready = true;
    i.next_arc_entry_gate_report = eg;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-EG-NOT-READY"));
}
#[test]
fn i30_require_review_ready_blocks() {
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = false;
    let rp = build_reader_lab_next_arc_review_pack(&ri);
    assert!(!rp.review_ready);
    let mut i = sf();
    i.require_next_arc_review_ready = true;
    i.next_arc_review_pack = rp;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-RP-NOT-READY"));
}
#[test]
fn i30_require_freeze_passed_blocks() {
    let mut fi = default_reader_lab_next_arc_static_freeze_input();
    fi.require_experimental_only = false;
    let s = build_reader_lab_next_arc_static_freeze_record(&fi);
    assert!(!s.freeze_passed);
    let mut i = sf();
    i.require_next_arc_static_freeze_passed = true;
    i.next_arc_static_freeze_record = s;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-SF-NOT-PASSED"));
}
#[test]
fn i30_experimental_only_not_confirmed() {
    let mut i = sf();
    i.require_experimental_only = false;
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert_eq!(
        r.status,
        EbpfReaderLabNextArcFreezeReviewPackStatus::ExperimentalOnly
    );
}
// 19-22: Priority
#[test]
fn i30_priority_static_policy() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| {
        r.frozen_static_policy_arc = true;
        r.frozen_fixture_only_arc = true;
    });
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenStaticPolicyArc
    );
}
#[test]
fn i30_priority_fixture() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| r.frozen_fixture_only_arc = true);
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenFixtureOnlyArc
    );
}
#[test]
fn i30_priority_manual_checklist() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| {
        r.frozen_manual_reader_spike_checklist_arc = true;
        r.frozen_fixture_only_arc = false;
        r.frozen_static_policy_arc = false;
    });
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenManualReaderSpikeChecklistArc
    );
}
#[test]
fn i30_priority_reader_spike_review() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| {
        r.frozen_reader_spike_review_arc = true;
        r.frozen_fixture_only_arc = false;
        r.frozen_static_policy_arc = false;
        r.frozen_manual_reader_spike_checklist_arc = false;
    });
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenReaderSpikeReviewArc
    );
}
// 23-26: EG forbidden arcs
#[test]
fn i30_eg_reject_live_reader() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.live_reader_arc_allowed = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert_eq!(
        r.decision,
        EbpfReaderLabNextArcFreezeReviewDecision::RejectLiveReaderArc
    );
    assert!(!r.review_ready);
}
#[test]
fn i30_eg_reject_public_cli() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.public_cli_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::RejectPublicCliArc
    );
}
#[test]
fn i30_eg_reject_release() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.release_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::RejectReleaseArc
    );
}
#[test]
fn i30_eg_reject_enforcement() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.enforcement_arc_allowed = true);
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::RejectEnforcementArc
    );
}
// 27-29: Schema/CLI
#[test]
fn i30_cli_exposed_blocked() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.public_cli_exposed = true);
    assert!(!build_reader_lab_next_arc_freeze_review_pack(&i).review_ready);
}
#[test]
fn i30_schema_changes_blocked() {
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
        assert!(!build_reader_lab_next_arc_freeze_review_pack(&i).review_ready);
    }
}
// 30-34: Release invariants
#[test]
fn i30_release_invariants() {
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
        let r = build_reader_lab_next_arc_freeze_review_pack(&i);
        assert!(
            !r.review_ready
                && r.status == EbpfReaderLabNextArcFreezeReviewPackStatus::ReleaseForbidden
        );
    }
}
// 35-41: Operation flags
#[test]
fn i30_ring_buffer_opened() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.ring_buffer_opened = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(r.ring_buffer_opened && !r.review_ready && has(&r, "NAFRP-OP-FLAGS-TRUE"));
}
#[test]
fn i30_operation_flags_cycle() {
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
        let r = build_reader_lab_next_arc_freeze_review_pack(&i);
        assert!(!r.review_ready && r.findings.iter().any(|f| f.blocking));
    }
}
// 42-53: Fake evidence
#[test]
fn i30_fake_from_eg() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.fake_reader_success_detected = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && r.fake_reader_success_detected && has(&r, "NAFRP-FAKE-READER"));
}
#[test]
fn i30_fake_from_rp() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.fake_planning_success_detected = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && r.fake_planning_success_detected && has(&r, "NAFRP-FAKE-PLANNING"));
}
#[test]
fn i30_fake_from_sf() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| r.fake_policy_hardening_success_detected = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && r.fake_policy_hardening_success_detected);
}
#[test]
fn i30_fake_flags_cycle() {
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
        "NAFRP-FAKE-READER",
        "NAFRP-FAKE-EVENTS",
        "NAFRP-FAKE-RELEASE",
        "NAFRP-FAKE-PLANNING",
        "NAFRP-FAKE-POLICY-FREEZE",
        "NAFRP-FAKE-REVIEW",
        "NAFRP-FAKE-HARDENING",
        "NAFRP-FAKE-COMPLETION",
        "NAFRP-FAKE-COMPLETION-REVIEW",
        "NAFRP-FAKE-ENTRY",
    ];
    for (s, c) in setters.iter().zip(codes.iter()) {
        let mut i = sf();
        i.next_arc_entry_gate_report = me(*s);
        let r = build_reader_lab_next_arc_freeze_review_pack(&i);
        assert!(!r.review_ready && has(&r, c));
    }
}
#[test]
fn i30_fake_review_pack() {
    let mut i = sf();
    i.next_arc_review_pack = mr(|r| r.fake_next_arc_review_success_detected = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-FAKE-REVIEW-PACK"));
}
#[test]
fn i30_fake_static_freeze() {
    let mut i = sf();
    i.next_arc_static_freeze_record =
        msf(|r| r.fake_next_arc_static_freeze_success_detected = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-FAKE-STATIC-FREEZE"));
}
// Validation
#[test]
fn i30_validate_safe_default() {
    assert!(validate_reader_lab_next_arc_freeze_review_pack(&sdef()).is_ok());
}
#[test]
fn i30_validate_rejects_review_ready_rejected() {
    let mut r = sdef();
    r.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewRejected;
    r.review_ready = true;
    assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
}
#[test]
fn i30_validate_rejects_release_allowed() {
    let mut r = sdef();
    r.release_allowed = true;
    assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
}
#[test]
fn i30_validate_rejects_not_experimental() {
    let mut r = sdef();
    r.must_remain_experimental = false;
    assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
}
#[test]
fn i30_validate_rejects_arc_flags() {
    for f in &[
        "live_reader_arc_allowed",
        "public_cli_arc_allowed",
        "release_arc_allowed",
        "enforcement_arc_allowed",
    ] {
        let mut r = sdef();
        match *f {
            "live_reader_arc_allowed" => r.live_reader_arc_allowed = true,
            "public_cli_arc_allowed" => r.public_cli_arc_allowed = true,
            "release_arc_allowed" => r.release_arc_allowed = true,
            _ => r.enforcement_arc_allowed = true,
        }
        assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
    }
}
#[test]
fn i30_validate_rejects_op_flags() {
    for f in &[
        "ring_buffer_opened",
        "live_event_stream_read",
        "map_pin_performed",
        "enforcement_performed",
        "packet_drop_performed",
        "mutation_performed",
        "persistence_performed",
    ] {
        let mut r = sdef();
        match *f {
            "ring_buffer_opened" => r.ring_buffer_opened = true,
            "live_event_stream_read" => r.live_event_stream_read = true,
            "map_pin_performed" => r.map_pin_performed = true,
            "enforcement_performed" => r.enforcement_performed = true,
            "packet_drop_performed" => r.packet_drop_performed = true,
            "mutation_performed" => r.mutation_performed = true,
            _ => r.persistence_performed = true,
        }
        assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
    }
}
#[test]
fn i30_validate_rejects_schema_flags() {
    for f in &[
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
        match *f {
            "public_cli_exposed" => r.public_cli_exposed = true,
            "usage_schema_changed" => r.usage_schema_changed = true,
            "ledger_schema_changed" => r.ledger_schema_changed = true,
            "stable_release_requested" => r.stable_release_requested = true,
            "tag_requested" => r.tag_requested = true,
            "publish_requested" => r.publish_requested = true,
            "version_bump_requested" => r.version_bump_requested = true,
            _ => r.main_merge_requested = true,
        }
        assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
    }
}
#[test]
fn i30_validate_rejects_all_fake_flags() {
    for f in &[
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
        "fake_next_arc_freeze_review_success_detected",
    ] {
        let mut r = sdef();
        match *f {
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
            "fake_next_arc_static_freeze_success_detected" => {
                r.fake_next_arc_static_freeze_success_detected = true
            }
            _ => r.fake_next_arc_freeze_review_success_detected = true,
        }
        assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
    }
}
#[test]
fn i30_validate_empty_phase() {
    let mut r = sdef();
    r.phase = String::new();
    assert!(validate_reader_lab_next_arc_freeze_review_pack(&r).is_err());
}
// 97-98: Blocked finding + deterministic
#[test]
fn i30_blocked_has_finding() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert!(build_reader_lab_next_arc_freeze_review_pack(&i)
        .findings
        .iter()
        .any(|f| f.blocking));
}
#[test]
fn i30_deterministic() {
    let r1 = build_reader_lab_next_arc_freeze_review_pack(&sf());
    let r2 = build_reader_lab_next_arc_freeze_review_pack(&sf());
    assert_eq!(r1, r2);
}
// Source integrity
#[test]
fn i30_copyright_header() {
    let s = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_freeze_review_pack.rs");
    assert!(
        s.starts_with("// Copyright (C) 2026 rezky_nightky")
            && s.contains("SPDX-License-Identifier: GPL-3.0-only")
    );
}
#[test]
fn i30_no_forbidden_patterns() {
    let nc: String =
        include_str!("backends/ebpf/event_stream_reader_lab_next_arc_freeze_review_pack.rs")
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    assert!(!nc.contains("nftables") && !nc.contains("tc qdisc") && !nc.contains("/drop"));
}
#[test]
fn i30_cargo_toml() {
    assert!(include_str!("../../Cargo.toml").contains("name = \"zelynic\""));
}
#[test]
fn i30_doc_exists() {
    assert!(!include_str!(
        "../../docs/intergalaxion/I-30-reader-lab-next-arc-freeze-review-pack.md"
    )
    .is_empty());
}
#[test]
fn i30_no_cli() {
    let nc: String =
        include_str!("backends/ebpf/event_stream_reader_lab_next_arc_freeze_review_pack.rs")
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    assert!(!nc.contains("clap") && !nc.contains("Command"));
}
// Cross-evidence
#[test]
fn i30_experimental_cross() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.must_remain_experimental = false);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-NOT-EXPERIMENTAL"));
}
#[test]
fn i30_release_cross() {
    let mut i = sf();
    i.next_arc_entry_gate_report = me(|r| r.release_allowed = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-CONTRADICTION-RELEASE"));
}
#[test]
fn i30_sf_arc_allowed() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| r.arc_allowed_live_reader = true);
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-SF-LIVE-READER-ARC"));
}
#[test]
fn i30_no_safe_arc() {
    let mut i = sf();
    i.next_arc_static_freeze_record = msf(|r| {
        r.frozen_fixture_only_arc = false;
        r.frozen_static_policy_arc = false;
        r.frozen_manual_reader_spike_checklist_arc = false;
        r.frozen_reader_spike_review_arc = false;
    });
    let r = build_reader_lab_next_arc_freeze_review_pack(&i);
    assert!(!r.review_ready && has(&r, "NAFRP-NO-SAFE-ARC"));
}
#[test]
fn i30_multi_findings() {
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
        build_reader_lab_next_arc_freeze_review_pack(&i)
            .findings
            .len()
            >= 3
    );
}
#[test]
fn i30_release_forbidden_decision() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert_eq!(
        build_reader_lab_next_arc_freeze_review_pack(&i).decision,
        EbpfReaderLabNextArcFreezeReviewDecision::RejectReleaseArc
    );
}
#[test]
fn i30_propagation() {
    let r = build_reader_lab_next_arc_freeze_review_pack(&sf());
    assert_eq!(
        r.next_arc_entry_ready,
        sf().next_arc_entry_gate_report.entry_ready
    );
    assert_eq!(
        r.next_arc_review_ready,
        sf().next_arc_review_pack.review_ready
    );
    assert_eq!(
        r.next_arc_static_freeze_passed,
        sf().next_arc_static_freeze_record.freeze_passed
    );
}
#[test]
fn i30_enum_equality() {
    assert_eq!(
        EbpfReaderLabNextArcFreezeReviewPackStatus::Draft,
        EbpfReaderLabNextArcFreezeReviewPackStatus::Draft
    );
    assert_eq!(
        EbpfReaderLabNextArcFreezeReviewDecision::Stop,
        EbpfReaderLabNextArcFreezeReviewDecision::Stop
    );
    assert_eq!(
        EbpfReaderLabNextArcFreezeReviewFindingKind::ReviewInvariant,
        EbpfReaderLabNextArcFreezeReviewFindingKind::ReviewInvariant
    );
}
#[test]
fn i30_clone_debug() {
    let r = sdef();
    assert_eq!(r, r.clone());
    assert!(format!("{:?}", r).contains("I-30"));
}
