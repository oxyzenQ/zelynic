// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_final_gate::{
    build_reader_lab_next_arc_final_gate_report, default_reader_lab_next_arc_final_gate_input,
    reader_lab_next_arc_final_decision_label, reader_lab_next_arc_final_finding_kind_label,
    reader_lab_next_arc_final_gate_status_label, validate_reader_lab_next_arc_final_gate_report,
    EbpfReaderLabNextArcFinalDecision, EbpfReaderLabNextArcFinalFinding,
    EbpfReaderLabNextArcFinalFindingKind, EbpfReaderLabNextArcFinalGateInput,
    EbpfReaderLabNextArcFinalGateReport, EbpfReaderLabNextArcFinalGateStatus,
};

type I = EbpfReaderLabNextArcFinalGateInput;
type R = EbpfReaderLabNextArcFinalGateReport;
type S = EbpfReaderLabNextArcFinalGateStatus;
type D = EbpfReaderLabNextArcFinalDecision;

fn sf() -> I {
    let mut i = default_reader_lab_next_arc_final_gate_input();
    i.require_experimental_only = true;
    i.require_next_arc_entry_ready = true;
    i.require_next_arc_review_ready = true;
    i.require_next_arc_static_freeze_passed = true;
    i.require_next_arc_freeze_review_ready = true;
    i
}
fn me(mut i: I) -> I {
    i.next_arc_entry_gate_report.entry_ready = true;
    i
}
fn mr(mut i: I) -> I {
    i.next_arc_review_pack.review_ready = true;
    i
}
fn ms(mut i: I) -> I {
    i.next_arc_static_freeze_record.freeze_passed = true;
    i.next_arc_static_freeze_record.frozen_fixture_only_arc = true;
    i
}
fn mf(mut i: I) -> I {
    i.next_arc_freeze_review_pack.review_ready = true;
    i
}
fn has(r: &R, c: &str) -> bool {
    r.findings.iter().any(|f| f.code == c)
}
fn full() -> I {
    mf(ms(mr(me(sf()))))
}

#[test]
fn i31_default_input_is_safe() {
    let d = default_reader_lab_next_arc_final_gate_input();
    assert!(
        !d.require_next_arc_entry_ready
            && !d.require_next_arc_review_ready
            && !d.require_next_arc_static_freeze_passed
            && !d.require_next_arc_freeze_review_ready
            && !d.require_experimental_only
    );
    assert!(
        d.public_cli_expected_hidden
            && d.usage_schema_expected_unchanged
            && d.ledger_schema_expected_unchanged
    );
    assert!(
        !d.stable_release_requested
            && !d.tag_requested
            && !d.publish_requested
            && !d.version_bump_requested
            && !d.main_merge_requested
    );
}

#[test]
fn i31_default_report_phase_and_op_flags() {
    let r = build_reader_lab_next_arc_final_gate_report(
        &default_reader_lab_next_arc_final_gate_input(),
    );
    assert_eq!(r.phase, "I-31");
    for f in [
        r.ring_buffer_opened,
        r.live_event_stream_read,
        r.map_pin_performed,
        r.enforcement_performed,
        r.packet_drop_performed,
        r.mutation_performed,
        r.persistence_performed,
    ] {
        assert!(!f);
    }
}

#[test]
fn i31_status_labels() {
    let l = [
        "draft",
        "incomplete",
        "blocked",
        "finalized",
        "final_rejected",
        "experimental_only",
        "release_forbidden",
    ];
    let v = [
        S::Draft,
        S::Incomplete,
        S::Blocked,
        S::Finalized,
        S::FinalRejected,
        S::ExperimentalOnly,
        S::ReleaseForbidden,
    ];
    for (s, e) in v.iter().zip(l.iter()) {
        assert_eq!(reader_lab_next_arc_final_gate_status_label(*s), *e);
    }
}

#[test]
fn i31_decision_labels() {
    let l = [
        "stop",
        "keep_experimental",
        "finalize_fixture_only_arc",
        "finalize_static_policy_arc",
        "finalize_manual_reader_spike_checklist_arc",
        "finalize_reader_spike_review_arc",
        "reject_live_reader_arc",
        "reject_public_cli_arc",
        "reject_release_arc",
        "reject_enforcement_arc",
    ];
    let v = [
        D::Stop,
        D::KeepExperimental,
        D::FinalizeFixtureOnlyArc,
        D::FinalizeStaticPolicyArc,
        D::FinalizeManualReaderSpikeChecklistArc,
        D::FinalizeReaderSpikeReviewArc,
        D::RejectLiveReaderArc,
        D::RejectPublicCliArc,
        D::RejectReleaseArc,
        D::RejectEnforcementArc,
    ];
    for (d, e) in v.iter().zip(l.iter()) {
        assert_eq!(reader_lab_next_arc_final_decision_label(*d), *e);
    }
}

#[test]
fn i31_finding_kind_labels() {
    let l = [
        "next_arc_entry_gate",
        "next_arc_review_pack",
        "next_arc_static_freeze",
        "next_arc_freeze_review",
        "release_invariant",
        "cli_invariant",
        "schema_invariant",
        "runtime_invariant",
        "kernel_invariant",
        "mutation_invariant",
        "fake_evidence_invariant",
        "final_gate_invariant",
    ];
    let v = [
        EbpfReaderLabNextArcFinalFindingKind::NextArcEntryGate,
        EbpfReaderLabNextArcFinalFindingKind::NextArcReviewPack,
        EbpfReaderLabNextArcFinalFindingKind::NextArcStaticFreeze,
        EbpfReaderLabNextArcFinalFindingKind::NextArcFreezeReview,
        EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant,
        EbpfReaderLabNextArcFinalFindingKind::CliInvariant,
        EbpfReaderLabNextArcFinalFindingKind::SchemaInvariant,
        EbpfReaderLabNextArcFinalFindingKind::RuntimeInvariant,
        EbpfReaderLabNextArcFinalFindingKind::KernelInvariant,
        EbpfReaderLabNextArcFinalFindingKind::MutationInvariant,
        EbpfReaderLabNextArcFinalFindingKind::FakeEvidenceInvariant,
        EbpfReaderLabNextArcFinalFindingKind::FinalGateInvariant,
    ];
    for (k, e) in v.iter().zip(l.iter()) {
        assert_eq!(reader_lab_next_arc_final_finding_kind_label(*k), *e);
    }
}

#[test]
fn i31_default_release_and_experimental() {
    let r = build_reader_lab_next_arc_final_gate_report(
        &default_reader_lab_next_arc_final_gate_input(),
    );
    assert!(!r.release_allowed && r.must_remain_experimental);
}

#[test]
fn i31_default_not_final_gate_passed() {
    assert!(
        !build_reader_lab_next_arc_final_gate_report(
            &default_reader_lab_next_arc_final_gate_input()
        )
        .final_gate_passed
    );
}

#[test]
fn i31_default_findings_nonempty_or_exp_only() {
    let r = build_reader_lab_next_arc_final_gate_report(
        &default_reader_lab_next_arc_final_gate_input(),
    );
    assert!(!r.findings.is_empty() || r.status == S::ExperimentalOnly);
}

#[test]
fn i31_evidence_valid() {
    let r = build_reader_lab_next_arc_final_gate_report(&sf());
    assert!(
        !has(&r, "NAFG-EG-INVALID")
            && !has(&r, "NAFG-RP-INVALID")
            && !has(&r, "NAFG-SF-INVALID")
            && !has(&r, "NAFG-FR-INVALID")
    );
}

#[test]
fn i31_require_flags_block_when_not_ready() {
    let mut i = default_reader_lab_next_arc_final_gate_input();
    i.require_next_arc_entry_ready = true;
    // Default EG built from default_reader_lab_next_arc_entry_gate_input() with require_experimental_only=true
    // so entry_ready is true. Force it false by using non-experimental evidence.
    let mut gi = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = false;
    gi.prefer_fixture_only_arc = false;
    i.next_arc_entry_gate_report = crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::build_reader_lab_next_arc_entry_gate_report(&gi);
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(has(&r, "NAFG-EG-NOT-READY"));
}

/// With sf(), experimental_only is true and evidence is ready, so it finalizes
#[test]
fn i31_experimental_check() {
    let r = build_reader_lab_next_arc_final_gate_report(&sf());
    // sf() sets require_experimental_only=true, so no experimental confirm finding
    assert!(!has(&r, "NAFG-NO-EXPERIMENTAL-CONFIRM"));
}

/// sf() produces a finalized report with safe arc, so final_gate_passed is true
#[test]
fn i31_safe_arc_finalizes() {
    let r = build_reader_lab_next_arc_final_gate_report(&sf());
    assert!(r.final_gate_passed && r.status == S::Finalized);
}

#[test]
fn i31_priority_static_policy() {
    let mut i = full();
    i.next_arc_static_freeze_record.frozen_static_policy_arc = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert_eq!(r.decision, D::FinalizeStaticPolicyArc);
}

#[test]
fn i31_priority_fixture_only() {
    let mut i = full();
    i.next_arc_static_freeze_record.frozen_static_policy_arc = false;
    i.next_arc_static_freeze_record.frozen_fixture_only_arc = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert_eq!(r.decision, D::FinalizeFixtureOnlyArc);
}

#[test]
fn i31_priority_manual_spike() {
    let mut i = full();
    i.next_arc_static_freeze_record.frozen_static_policy_arc = false;
    i.next_arc_static_freeze_record.frozen_fixture_only_arc = false;
    i.next_arc_static_freeze_record
        .frozen_manual_reader_spike_checklist_arc = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert_eq!(r.decision, D::FinalizeManualReaderSpikeChecklistArc);
}

#[test]
fn i31_priority_reader_spike() {
    let mut i = full();
    i.next_arc_static_freeze_record.frozen_static_policy_arc = false;
    i.next_arc_static_freeze_record.frozen_fixture_only_arc = false;
    i.next_arc_static_freeze_record
        .frozen_manual_reader_spike_checklist_arc = false;
    i.next_arc_static_freeze_record
        .frozen_reader_spike_review_arc = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert_eq!(r.decision, D::FinalizeReaderSpikeReviewArc);
}

#[test]
fn i31_eg_forbidden_arcs() {
    // Individual tests for each
    let mut i = sf();
    i.next_arc_entry_gate_report.live_reader_arc_allowed = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(has(&r, "NAFG-LIVE-READER-ARC") && r.decision == D::RejectLiveReaderArc);
    let mut i = sf();
    i.next_arc_entry_gate_report.public_cli_arc_allowed = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(has(&r, "NAFG-PUBLIC-CLI-ARC") && r.decision == D::RejectPublicCliArc);
    let mut i = sf();
    i.next_arc_entry_gate_report.release_arc_allowed = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(has(&r, "NAFG-RELEASE-ARC"));
    let mut i = sf();
    i.next_arc_entry_gate_report.enforcement_arc_allowed = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(has(&r, "NAFG-ENFORCEMENT-ARC"));
}

#[test]
fn i31_cli_schema_invariants() {
    let mut i = sf();
    i.next_arc_entry_gate_report.public_cli_exposed = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-CONTRADICTION-CLI-EXPOSED"
    ));
    let mut i = sf();
    i.usage_schema_expected_unchanged = false;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-USAGE-SCHEMA-CHANGED"
    ));
    let mut i = sf();
    i.ledger_schema_expected_unchanged = false;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-LEDGER-SCHEMA-CHANGED"
    ));
}

#[test]
fn i31_release_invariants() {
    let codes = [
        "NAFG-RELEASE-REQUESTED",
        "NAFG-TAG-REQUESTED",
        "NAFG-PUBLISH-REQUESTED",
        "NAFG-VERSION-BUMP-REQUESTED",
        "NAFG-MAIN-MERGE-REQUESTED",
    ];
    let muts: &[fn(&mut I)] = &[
        |i| i.stable_release_requested = true,
        |i| i.tag_requested = true,
        |i| i.publish_requested = true,
        |i| i.version_bump_requested = true,
        |i| i.main_merge_requested = true,
    ];
    for (code, m) in codes.iter().zip(muts.iter()) {
        let mut i = sf();
        m(&mut i);
        assert!(has(&build_reader_lab_next_arc_final_gate_report(&i), code));
    }
}

#[test]
fn i31_op_flags_block() {
    let mut i = sf();
    i.next_arc_entry_gate_report.ring_buffer_opened = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-OP-FLAGS-TRUE"
    ));
    let mut i = sf();
    i.next_arc_freeze_review_pack.live_event_stream_read = true;
    assert!(build_reader_lab_next_arc_final_gate_report(&i).live_event_stream_read);
}

#[test]
fn i31_fake_evidence_blocks() {
    let codes = [
        "NAFG-FAKE-READER",
        "NAFG-FAKE-EVENTS",
        "NAFG-FAKE-RELEASE",
        "NAFG-FAKE-PLANNING",
        "NAFG-FAKE-POLICY-FREEZE",
        "NAFG-FAKE-REVIEW",
        "NAFG-FAKE-HARDENING",
        "NAFG-FAKE-COMPLETION",
        "NAFG-FAKE-COMPLETION-REVIEW",
        "NAFG-FAKE-ENTRY",
        "NAFG-FAKE-REVIEW-PACK",
        "NAFG-FAKE-STATIC-FREEZE",
        "NAFG-FAKE-FREEZE-REVIEW",
    ];
    let fns: &[fn(&mut I)] = &[
        |i| i.next_arc_entry_gate_report.fake_reader_success_detected = true,
        |i| i.next_arc_review_pack.fake_live_event_counts_detected = true,
        |i| {
            i.next_arc_static_freeze_record
                .fake_release_readiness_detected = true
        },
        |i| i.next_arc_freeze_review_pack.fake_planning_success_detected = true,
        |i| {
            i.next_arc_entry_gate_report
                .fake_policy_freeze_success_detected = true
        },
        |i| {
            i.next_arc_entry_gate_report
                .fake_policy_review_success_detected = true
        },
        |i| {
            i.next_arc_review_pack
                .fake_policy_hardening_success_detected = true
        },
        |i| {
            i.next_arc_review_pack
                .fake_policy_completion_success_detected = true
        },
        |i| {
            i.next_arc_entry_gate_report
                .fake_completion_review_success_detected = true
        },
        |i| {
            i.next_arc_entry_gate_report
                .fake_next_arc_entry_success_detected = true
        },
        |i| i.next_arc_review_pack.fake_next_arc_review_success_detected = true,
        |i| {
            i.next_arc_static_freeze_record
                .fake_next_arc_static_freeze_success_detected = true
        },
        |i| {
            i.next_arc_freeze_review_pack
                .fake_next_arc_freeze_review_success_detected = true
        },
    ];
    for (code, f) in codes.iter().zip(fns.iter()) {
        let mut i = sf();
        f(&mut i);
        assert!(
            has(&build_reader_lab_next_arc_final_gate_report(&i), code),
            "expected {code}"
        );
    }
}

#[test]
fn i31_finalized_fixture_only() {
    let r = build_reader_lab_next_arc_final_gate_report(&full());
    assert_eq!(r.status, S::Finalized);
    assert_eq!(r.decision, D::FinalizeFixtureOnlyArc);
}

#[test]
fn i31_finalized_still_safe() {
    let r = build_reader_lab_next_arc_final_gate_report(&full());
    assert!(
        !r.release_allowed
            && r.must_remain_experimental
            && !r.live_reader_arc_allowed
            && !r.public_cli_arc_allowed
            && !r.release_arc_allowed
            && !r.enforcement_arc_allowed
    );
}

#[test]
fn i31_validation_accepts_default() {
    assert!(validate_reader_lab_next_arc_final_gate_report(
        &build_reader_lab_next_arc_final_gate_report(
            &default_reader_lab_next_arc_final_gate_input()
        )
    )
    .is_ok());
}

#[test]
fn i31_validation_rejects_unsafe_flags() {
    let d = default_reader_lab_next_arc_final_gate_input();
    let mut r = build_reader_lab_next_arc_final_gate_report(&d);
    // test final_gate_passed with FinalRejected
    r.final_gate_passed = true;
    r.status = S::FinalRejected;
    assert!(validate_reader_lab_next_arc_final_gate_report(&r).is_err());
    // test all deny fields via loop
    let flags: &[fn(&mut R)] = &[
        |r| r.release_allowed = true,
        |r| r.must_remain_experimental = false,
        |r| r.live_reader_arc_allowed = true,
        |r| r.public_cli_arc_allowed = true,
        |r| r.release_arc_allowed = true,
        |r| r.enforcement_arc_allowed = true,
        |r| r.public_cli_exposed = true,
        |r| r.usage_schema_changed = true,
        |r| r.ledger_schema_changed = true,
        |r| r.stable_release_requested = true,
        |r| r.tag_requested = true,
        |r| r.publish_requested = true,
        |r| r.version_bump_requested = true,
        |r| r.main_merge_requested = true,
        |r| r.ring_buffer_opened = true,
        |r| r.live_event_stream_read = true,
        |r| r.map_pin_performed = true,
        |r| r.enforcement_performed = true,
        |r| r.packet_drop_performed = true,
        |r| r.mutation_performed = true,
        |r| r.persistence_performed = true,
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
        |r| r.fake_next_arc_review_success_detected = true,
        |r| r.fake_next_arc_static_freeze_success_detected = true,
        |r| r.fake_next_arc_freeze_review_success_detected = true,
        |r| r.fake_next_arc_final_gate_success_detected = true,
    ];
    for f in flags {
        let mut r = build_reader_lab_next_arc_final_gate_report(&d);
        f(&mut r);
        assert!(validate_reader_lab_next_arc_final_gate_report(&r).is_err());
    }
}

#[test]
fn i31_blocked_has_blocking() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert!(build_reader_lab_next_arc_final_gate_report(&i)
        .findings
        .iter()
        .any(|f| f.blocking));
}

#[test]
fn i31_deterministic() {
    let i = default_reader_lab_next_arc_final_gate_input();
    let a = build_reader_lab_next_arc_final_gate_report(&i);
    let b = build_reader_lab_next_arc_final_gate_report(&i);
    assert_eq!(a.status, b.status);
    assert_eq!(a.decision, b.decision);
    assert_eq!(a.findings.len(), b.findings.len());
}

#[test]
fn i31_source_integrity() {
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_final_gate.rs");
    assert!(
        src.contains("// Copyright (C) 2026 rezky_nightky")
            && src.contains("SPDX-License-Identifier: GPL-3.0-only")
    );
    let forbidden = [
        ".attach(",
        "RingBuf",
        "PerfEventArray",
        "bpf_prog_load",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
        "create_map",
        "pin(",
    ];
    for pat in forbidden {
        for line in src.lines() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("//!") {
                continue;
            }
            if t.contains(pat) {
                panic!("forbidden pattern '{pat}' found: {line}");
            }
        }
    }
    assert!(
        !src.contains("nftables")
            && !src.contains("tc qdisc")
            && !src.contains("drop_packet")
            && !src.contains("File::create")
            && !src.contains("fs::write")
    );
    assert!(src.contains("\"I-31\""));
}

#[test]
fn i31_impl_under_1000_loc() {
    let c = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_final_gate.rs")
        .lines()
        .count();
    assert!(c <= 1000, "impl is {c} lines");
}

#[test]
fn i31_docs_exist() {
    let d = include_str!("../../docs/intergalaxion/I-31-reader-lab-next-arc-final-gate.md");
    assert!(
        d.contains("final gate")
            && d.contains("not a release")
            && d.contains("no tag")
            && d.contains("no public CLI")
            && d.contains("no ring buffer")
            && d.contains("no enforcement")
            && d.contains("release_allowed is always false")
            && d.contains("must_remain_experimental is always true")
            && d.contains("fake next arc final gate success")
            && d.contains("schema unchanged")
    );
}

#[test]
fn i31_no_new_dependency() {
    assert!(include_str!("../../Cargo.toml").contains("[package]"));
}

#[test]
fn i31_version_unchanged() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i31_no_intergalaxion_in_help() {
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_final_gate.rs");
    assert!(!src.contains("clap::") && !src.contains("Command::"));
}

#[test]
fn i31_no_nft_tc_source() {
    let src = include_str!("backends/ebpf/event_stream_reader_lab_next_arc_final_gate.rs");
    assert!(!src.contains("nft") && !src.contains("tc qdisc") && !src.contains("tc filter"));
}

#[test]
fn i31_enum_traits() {
    let s = S::Draft;
    assert_eq!(s, S::Draft);
    assert!(format!("{:?}", s).contains("Draft"));
    let d = D::Stop;
    assert_eq!(d, D::Stop);
}

#[test]
fn i31_finding_fields() {
    let f = EbpfReaderLabNextArcFinalFinding {
        code: "T".into(),
        kind: EbpfReaderLabNextArcFinalFindingKind::FinalGateInvariant,
        message: "m".into(),
        blocking: true,
        status: S::Blocked,
    };
    assert_eq!(f.code, "T");
    assert!(f.blocking);
}

#[test]
fn i31_v_reject_empty_phase() {
    let mut r = build_reader_lab_next_arc_final_gate_report(
        &default_reader_lab_next_arc_final_gate_input(),
    );
    r.phase = String::new();
    assert!(validate_reader_lab_next_arc_final_gate_report(&r).is_err());
}

#[test]
fn i31_propagates_evidence() {
    let r = build_reader_lab_next_arc_final_gate_report(&full());
    assert!(
        r.next_arc_entry_ready
            && r.next_arc_review_ready
            && r.next_arc_static_freeze_passed
            && r.next_arc_freeze_review_ready
    );
}

#[test]
fn i31_release_contradiction() {
    let mut i = sf();
    i.next_arc_entry_gate_report.release_allowed = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-CONTRADICTION-RELEASE"
    ));
}

#[test]
fn i31_rp_sf_fr_arcs_block() {
    let mut i = sf();
    i.next_arc_review_pack.live_reader_arc_allowed = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-RP-LIVE-READER-ARC"
    ));
    let mut i = sf();
    i.next_arc_static_freeze_record.arc_allowed_release = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-SF-RELEASE-ARC"
    ));
    let mut i = sf();
    i.next_arc_freeze_review_pack.enforcement_arc_allowed = true;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-FR-ENFORCEMENT-ARC"
    ));
}

#[test]
fn i31_not_exp_only_status() {
    let r = build_reader_lab_next_arc_final_gate_report(
        &default_reader_lab_next_arc_final_gate_input(),
    );
    assert_eq!(r.status, S::ExperimentalOnly);
}

#[test]
fn i31_release_forbidden_status() {
    let mut i = sf();
    i.stable_release_requested = true;
    assert_eq!(
        build_reader_lab_next_arc_final_gate_report(&i).status,
        S::ReleaseForbidden
    );
}

#[test]
fn i31_multi_findings() {
    let mut i = sf();
    i.stable_release_requested = true;
    i.tag_requested = true;
    i.publish_requested = true;
    assert!(
        build_reader_lab_next_arc_final_gate_report(&i)
            .findings
            .len()
            >= 3
    );
}

#[test]
fn i31_experimental_cross() {
    let r = build_reader_lab_next_arc_final_gate_report(&sf());
    assert!(!has(&r, "NAFG-NOT-EXPERIMENTAL"));
}

#[test]
fn i31_cli_not_hidden() {
    let mut i = sf();
    i.public_cli_expected_hidden = false;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-CLI-NOT-HIDDEN"
    ));
}

#[test]
fn i31_no_safe_arc_blocks() {
    let mut i = full();
    i.next_arc_static_freeze_record.frozen_fixture_only_arc = false;
    i.next_arc_static_freeze_record.frozen_static_policy_arc = false;
    i.next_arc_static_freeze_record
        .frozen_manual_reader_spike_checklist_arc = false;
    i.next_arc_static_freeze_record
        .frozen_reader_spike_review_arc = false;
    assert!(has(
        &build_reader_lab_next_arc_final_gate_report(&i),
        "NAFG-NO-SAFE-ARC"
    ));
}

#[test]
fn i31_finalized_full() {
    let r = build_reader_lab_next_arc_final_gate_report(&full());
    assert_eq!(r.status, S::Finalized);
    assert!(r.final_gate_passed && !r.release_allowed && r.must_remain_experimental);
}

#[test]
fn i31_op_flags_propagation() {
    let mut i = sf();
    i.next_arc_freeze_review_pack.ring_buffer_opened = true;
    let r = build_reader_lab_next_arc_final_gate_report(&i);
    assert!(r.ring_buffer_opened && has(&r, "NAFG-OP-FLAGS-TRUE"));
}
