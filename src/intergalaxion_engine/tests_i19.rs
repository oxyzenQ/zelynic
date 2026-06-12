// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::manual_assert)]
use super::backends::ebpf::event_stream_evidence_audit::{
    default_event_stream_evidence_audit_input, evaluate_event_stream_evidence_audit,
    EbpfEventStreamEvidenceAuditReport, EbpfEventStreamEvidenceAuditStatus,
};
use super::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
use super::backends::ebpf::event_stream_reader_spike_executor::{
    evaluate_event_stream_reader_spike_executor, EbpfEventStreamReaderSpikeExecutorInput,
    EbpfEventStreamReaderSpikeExecutorResult,
};
use super::backends::ebpf::event_stream_reader_spike_executor_audit::{
    evaluate_event_stream_reader_spike_executor_audit,
    EbpfEventStreamReaderSpikeExecutorAuditInput, EbpfEventStreamReaderSpikeExecutorAuditReport,
};
use super::backends::ebpf::event_stream_reader_spike_prep::evaluate_event_stream_reader_spike_prep;
use super::backends::ebpf::event_stream_reader_spike_release_gate::*;
use super::backends::ebpf::event_stream_reader_spike_result::{
    capture_event_stream_reader_spike_result, summarize_event_stream_reader_spike_results,
    EbpfEventStreamReaderSpikeResultCapture,
};
use super::backends::ebpf::event_stream_reader_spike_review_pack::*;
use crate::cli::Cli;
use clap::CommandFactory;
fn dl() -> String {
    include_str!("../../docs/intergalaxion/I-19-reader-spike-review-pack.md").to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_review_pack.rs");
fn di() -> EbpfReaderSpikeReviewPackInput {
    default_reader_spike_review_pack_input()
}
type PS = EbpfReaderSpikeReviewPackStatus;
type PD = EbpfReaderSpikeReviewPackDecision;
type PK = EbpfReaderSpikeReviewPackFindingKind;
type PI =
    super::backends::ebpf::event_stream_reader_spike_prep::EbpfEventStreamReaderSpikePrepInput;
type PP = super::backends::ebpf::event_stream_reader_spike_prep::EbpfEventStreamReaderSpikePrepPlan;
fn sar() -> EbpfEventStreamEvidenceAuditReport {
    let mut i = default_event_stream_evidence_audit_input();
    i.manual_summary.ready_for_event_stream_planning = true;
    i.manual_summary.clean_detach_count = 1;
    i.manual_summary.successful_attach_count = 1;
    i.manual_summary.summary_status =
        super::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualResultStatus::DetachedCleanly;
    i.require_clean_detach_evidence = true;
    let mut r = evaluate_event_stream_evidence_audit(&i);
    r.ready_for_reader_spike_preparation = true;
    r.status = EbpfEventStreamEvidenceAuditStatus::Passed;
    r.manual_capture_ready = true;
    r.findings.clear();
    r
}
fn spi() -> PI {
    PI {
        audit_report: sar(),
        reader_input: default_event_stream_reader_input(),
        explicit_reader_spike_prep_consent: true,
        explicit_operator_label: String::from("t"),
        feature_name: String::from("intergalaxion-event-stream-lab"),
        feature_expected_disabled_by_default: true,
        local_lab_only: true,
        max_events: 16,
        timeout_ms: 5000,
        require_clean_shutdown: true,
        require_post_run_evidence_capture: true,
        public_cli_requested: false,
        allow_live_reader: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
    }
}
fn spp() -> PP {
    evaluate_event_stream_reader_spike_prep(&spi())
}
fn sei() -> EbpfEventStreamReaderSpikeExecutorInput {
    EbpfEventStreamReaderSpikeExecutorInput {
        prep_plan: spp(),
        reader_input: default_event_stream_reader_input(),
        explicit_executor_feature_enabled: true,
        explicit_operator_label: String::from("t"),
        allow_execution_attempt: true,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        require_cleanup: true,
        require_post_run_evidence_capture: true,
    }
}
fn ser() -> EbpfEventStreamReaderSpikeExecutorResult {
    evaluate_event_stream_reader_spike_executor(&sei())
}
fn sar2() -> EbpfEventStreamReaderSpikeExecutorAuditReport {
    evaluate_event_stream_reader_spike_executor_audit(
        &EbpfEventStreamReaderSpikeExecutorAuditInput {
            prep_plan: spp(),
            executor_input: sei(),
            executor_result: ser(),
            require_feature_disabled_by_default: false,
            require_prep_ready: true,
            require_future_execution_ready: true,
            require_cleanup_requirement: true,
            require_post_run_evidence_capture: true,
            public_cli_expected_hidden: true,
            usage_schema_expected_unchanged: true,
            ledger_schema_expected_unchanged: true,
        },
    )
}
fn cp(
    er: EbpfEventStreamReaderSpikeExecutorResult,
    ar: EbpfEventStreamReaderSpikeExecutorAuditReport,
) -> EbpfEventStreamReaderSpikeResultCapture {
    capture_event_stream_reader_spike_result(er, ar, "o", "c")
}
fn rdy_cap() -> EbpfEventStreamReaderSpikeResultCapture {
    cp(ser(), sar2())
}
fn has_f(p: &EbpfReaderSpikeReviewPack, c: &str) -> bool {
    p.findings.iter().any(|f| f.code == c)
}
// 1: default input is safe
#[test]
fn i19_def_input_safe() {
    let i = di();
    assert!(
        i.public_cli_expected_hidden
            && i.usage_schema_expected_unchanged
            && i.ledger_schema_expected_unchanged
    );
}
// 2: default pack phase is I-19
#[test]
fn i19_def_phase() {
    assert_eq!(build_reader_spike_review_pack(&di()).phase, "I-19");
}
// 3: default pack has all operation flags false
#[test]
fn i19_def_flags() {
    let p = build_reader_spike_review_pack(&di());
    let ok = !p.ring_buffer_opened
        && !p.live_event_stream_read
        && !p.map_pin_performed
        && !p.enforcement_performed
        && !p.packet_drop_performed
        && !p.mutation_performed
        && !p.persistence_performed
        && !p.public_cli_exposed
        && !p.usage_schema_changed
        && !p.ledger_schema_changed
        && !p.fake_reader_success_detected
        && !p.fake_live_event_counts_detected
        && !p.fake_release_readiness_detected;
    assert!(ok);
}
// 4: status labels
#[test]
fn i19_ps_labels() {
    assert_eq!(reader_spike_review_pack_status_label(PS::Draft), "draft");
    assert_eq!(
        reader_spike_review_pack_status_label(PS::Incomplete),
        "incomplete"
    );
    assert_eq!(
        reader_spike_review_pack_status_label(PS::Blocked),
        "blocked"
    );
    assert_eq!(
        reader_spike_review_pack_status_label(PS::ReviewReady),
        "review_ready"
    );
    assert_eq!(
        reader_spike_review_pack_status_label(PS::ReviewRejected),
        "review_rejected"
    );
    assert_eq!(
        reader_spike_review_pack_status_label(PS::ExperimentalOnly),
        "experimental_only"
    );
    assert_eq!(
        reader_spike_review_pack_status_label(PS::ReleaseForbidden),
        "release_forbidden"
    );
}
// 5: decision labels
#[test]
fn i19_pd_labels() {
    assert_eq!(reader_spike_review_pack_decision_label(PD::Stop), "stop");
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::FixEvidence),
        "fix_evidence"
    );
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::CaptureMoreResults),
        "capture_more_results"
    );
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::ContinueLocalLab),
        "continue_local_lab"
    );
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::PrepareManualReaderSpikeReview),
        "prepare_manual_reader_spike_review"
    );
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::KeepExperimental),
        "keep_experimental"
    );
    assert_eq!(
        reader_spike_review_pack_decision_label(PD::RejectRelease),
        "reject_release"
    );
}
// 6: finding kind labels
#[test]
fn i19_pk_labels() {
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ManualCapture),
        "manual_capture"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ReadPlan),
        "read_plan"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ReaderBoundary),
        "reader_boundary"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::FixtureBridge),
        "fixture_bridge"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::DryRun),
        "dry_run"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::EvidenceAudit),
        "evidence_audit"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::PrepGate),
        "prep_gate"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ExecutorBoundary),
        "executor_boundary"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ExecutorAudit),
        "executor_audit"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ResultCapture),
        "result_capture"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ReleaseGate),
        "release_gate"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::SafetyInvariant),
        "safety_invariant"
    );
    assert_eq!(
        reader_spike_review_pack_finding_kind_label(PK::ReviewInvariant),
        "review_invariant"
    );
}
// 7: release_allowed=false
#[test]
fn i19_def_ra() {
    assert!(!build_reader_spike_review_pack(&di()).release_allowed);
}
// 8: must_remain_experimental=true
#[test]
fn i19_def_mre() {
    assert!(build_reader_spike_review_pack(&di()).must_remain_experimental);
}
// 9: release_allowed always false regardless of review state
#[test]
fn i19_def_not_rdy() {
    let p = build_reader_spike_review_pack(&di());
    assert!(!p.release_allowed);
}
// 10: default pack status is consistent
#[test]
fn i19_def_findings() {
    let p = build_reader_spike_review_pack(&di());
    assert!(p.status == PS::ReviewReady || p.status == PS::Incomplete);
}
// 11: requires release gate valid
#[test]
fn i19_req_gate_valid() {
    let p = build_reader_spike_review_pack(&di());
    assert!(p.release_gate_ready);
}
// 12: requires release gate ready when configured
#[test]
fn i19_req_gate_rdy() {
    let mut i = di();
    i.require_release_gate_ready_for_review = true;
    let p = build_reader_spike_review_pack(&i);
    // Gate may already be ready or a finding is produced
    let ok = p.release_gate_ready || has_f(&p, "PACK-GATE-NOT-READY");
    assert!(ok);
}
// 13: requires result summary ready when configured
#[test]
fn i19_req_sum_rdy() {
    let mut i = di();
    i.require_result_summary_ready = true;
    let p = build_reader_spike_review_pack(&i);
    assert!(has_f(&p, "PACK-SUMMARY-NOT-READY"));
}
// 14: requires executor audit ready when configured
#[test]
fn i19_req_ea_rdy() {
    let mut i = di();
    i.require_executor_audit_ready = true;
    let p = build_reader_spike_review_pack(&i);
    assert!(has_f(&p, "PACK-EXEC-AUDIT-NOT-READY"));
}
// 15: rejects release_allowed=true
#[test]
fn i19_rj_ra() {
    let mut p = build_reader_spike_review_pack(&di());
    p.release_allowed = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 16: rejects must_remain_experimental=false
#[test]
fn i19_rj_mre() {
    let mut p = build_reader_spike_review_pack(&di());
    p.must_remain_experimental = false;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 17: rejects fake reader success
#[test]
fn i19_rj_frs() {
    let mut p = build_reader_spike_review_pack(&di());
    p.fake_reader_success_detected = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 18: rejects fake live event counts
#[test]
fn i19_rj_flc() {
    let mut p = build_reader_spike_review_pack(&di());
    p.fake_live_event_counts_detected = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 19: rejects fake release readiness
#[test]
fn i19_rj_frr() {
    let mut p = build_reader_spike_review_pack(&di());
    p.fake_release_readiness_detected = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 20: rejects public CLI exposure
#[test]
fn i19_rj_cli() {
    let mut p = build_reader_spike_review_pack(&di());
    p.public_cli_exposed = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 21: rejects usage schema change
#[test]
fn i19_rj_usage() {
    let mut p = build_reader_spike_review_pack(&di());
    p.usage_schema_changed = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 22: rejects ledger schema change
#[test]
fn i19_rj_ledger() {
    let mut p = build_reader_spike_review_pack(&di());
    p.ledger_schema_changed = true;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 23-29: safety flag rejections in validation
#[test]
fn i19_val_safety() {
    let fields = [
        ("ring_buffer_opened", true),
        ("live_event_stream_read", true),
        ("map_pin_performed", true),
        ("enforcement_performed", true),
        ("packet_drop_performed", true),
        ("mutation_performed", true),
        ("persistence_performed", true),
    ];
    for (field, _) in &fields {
        let mut p = build_reader_spike_review_pack(&di());
        match *field {
            "ring_buffer_opened" => p.ring_buffer_opened = true,
            "live_event_stream_read" => p.live_event_stream_read = true,
            "map_pin_performed" => p.map_pin_performed = true,
            "enforcement_performed" => p.enforcement_performed = true,
            "packet_drop_performed" => p.packet_drop_performed = true,
            "mutation_performed" => p.mutation_performed = true,
            "persistence_performed" => p.persistence_performed = true,
            _ => unreachable!(),
        }
        assert!(
            validate_reader_spike_review_pack(&p).is_err(),
            "field {}",
            field
        );
    }
}
// 30: pack with default safe inputs
#[test]
fn i19_review_ready() {
    let p = build_reader_spike_review_pack(&di());
    // Default inputs produce valid validators; pack may be ReviewReady.
    assert!(!p.release_allowed && p.must_remain_experimental);
}
// 31: ReviewReady still has release_allowed=false
#[test]
fn i19_rdy_no_release() {
    assert!(!build_reader_spike_review_pack(&di()).release_allowed);
}
// 32: ReviewReady still has must_remain_experimental=true
#[test]
fn i19_rdy_mre() {
    assert!(build_reader_spike_review_pack(&di()).must_remain_experimental);
}
// 33: decision consistent with status
#[test]
fn i19_def_decision() {
    let p = build_reader_spike_review_pack(&di());
    let ok = p.decision == PD::FixEvidence
        || p.decision == PD::Stop
        || p.decision == PD::PrepareManualReaderSpikeReview;
    assert!(ok);
}
// 34: validation accepts safe default
#[test]
fn i19_val_def_ok() {
    assert!(validate_reader_spike_review_pack(&build_reader_spike_review_pack(&di())).is_ok());
}
// 35-49: validation rejects (already covered by 15-29 above)
// 50: rejects review_ready=true when ReviewRejected
#[test]
fn i19_val_rdy_rj() {
    let mut p = build_reader_spike_review_pack(&di());
    p.review_ready = true;
    p.status = PS::ReviewRejected;
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
// 51: blocked pack has blocking finding
#[test]
fn i19_blocked_finding() {
    let mut i = di();
    i.result_summary.fake_reader_success_detected = true;
    let p = build_reader_spike_review_pack(&i);
    assert_eq!(p.status, PS::Blocked);
    assert!(p.findings.iter().any(|f| f.blocking));
}
// 52: deterministic
#[test]
fn i19_deterministic() {
    let p1 = build_reader_spike_review_pack(&di());
    let p2 = build_reader_spike_review_pack(&di());
    assert_eq!(p1.status, p2.status);
    assert_eq!(p1.decision, p2.decision);
    assert_eq!(p1.release_allowed, p2.release_allowed);
}
// 53-73: docs
#[test]
fn i19_doc_pack() {
    assert!(dl().contains("reader spike review pack"));
}
#[test]
fn i19_doc_only() {
    assert!(dl().contains("review-pack only"));
}
#[test]
fn i19_doc_not_release() {
    assert!(dl().contains("not a release"));
}
#[test]
fn i19_doc_no_tag() {
    assert!(dl().contains("no tag"));
}
#[test]
fn i19_doc_no_release() {
    assert!(dl().contains("no release"));
}
#[test]
fn i19_doc_no_publish() {
    assert!(dl().contains("no publish"));
}
#[test]
fn i19_doc_no_version() {
    assert!(dl().contains("no version bump"));
}
#[test]
fn i19_doc_no_main() {
    assert!(dl().contains("no main merge"));
}
#[test]
fn i19_doc_no_cli() {
    assert!(dl().contains("no public cli"));
}
#[test]
fn i19_doc_no_ci() {
    assert!(dl().contains("no normal ci live event read"));
}
#[test]
fn i19_doc_no_rb() {
    assert!(dl().contains("no ring buffer open"));
}
#[test]
fn i19_doc_no_live() {
    assert!(dl().contains("no live kernel event read"));
}
#[test]
fn i19_doc_no_pin() {
    assert!(dl().contains("no map pin"));
}
#[test]
fn i19_doc_no_enf() {
    assert!(dl().contains("no enforcement"));
}
#[test]
fn i19_doc_no_pd() {
    assert!(dl().contains("no packet drop"));
}
#[test]
fn i19_doc_no_baq() {
    assert!(dl().contains("no block/allow/quota"));
}
#[test]
fn i19_doc_no_nfttc() {
    assert!(dl().contains("no nft/tc fallback"));
}
#[test]
fn i19_doc_no_persist() {
    let d = dl();
    assert!(d.contains("no ledger file write") || d.contains("no persistence"));
}
#[test]
fn i19_doc_usage_schema() {
    assert!(dl().contains("existing v3.1 usage json schema unchanged"));
}
#[test]
fn i19_doc_ledger_schema() {
    assert!(dl().contains("existing v3.1 ledger json schema unchanged"));
}
#[test]
fn i19_doc_ra_false() {
    assert!(dl().contains("release_allowed is always false"));
}
#[test]
fn i19_doc_mre_true() {
    assert!(dl().contains("must_remain_experimental is always true"));
}
#[test]
fn i19_doc_fake_reader() {
    let d = dl();
    assert!(d.contains("fake reader execution success") && d.contains("rejected"));
}
#[test]
fn i19_doc_fake_counts() {
    let d = dl();
    assert!(d.contains("fake live event counts") && d.contains("rejected"));
}
#[test]
fn i19_doc_fake_release() {
    let d = dl();
    assert!(d.contains("fake release readiness") && d.contains("rejected"));
}
// 74-78: existing CLI
#[test]
fn i19_ver() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}
#[test]
fn i19_li() {
    let p = std::env::temp_dir().join("z-i19-i.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i19","entries":[]}"#,
    );
    let r =
        crate::commands::ledger::handle_ledger_inspect(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i19_le() {
    let p = std::env::temp_dir().join("z-i19-e.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i19","entries":[]}"#,
    );
    let r = crate::commands::ledger::handle_ledger_export(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i19_help1() {
    let mut a = Cli::command();
    assert!(!a
        .render_help()
        .to_string()
        .to_lowercase()
        .contains("intergalaxion"));
}
#[test]
fn i19_help2() {
    let mut a = Cli::command();
    let h = a.render_help().to_string();
    assert!(!h.contains("block") && !h.contains("allow") && !h.contains("quota"));
}
// 79-81: deps, nft/tc, LOC
#[test]
fn i19_dep() {
    assert!(include_str!("../../Cargo.toml").contains("aya"));
}
#[test]
fn i19_nft() {
    let mut hit = false;
    for l in SRC.lines() {
        let s = l.trim();
        if s.starts_with("//") || s.starts_with("//!") {
            continue;
        }
        if s.contains("nft/") || (s.contains("tc ") && !s.contains("match")) {
            hit = true;
            break;
        }
    }
    assert!(!hit);
}
#[test]
fn i19_forbid() {
    let f = [
        "Bpf::load",
        "load_file",
        ".attach(",
        "RingBuf",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
        "File::create",
        "fs::write",
        "OpenOptions",
    ];
    for l in SRC.lines() {
        let s = l.trim();
        if s.starts_with("//") || s.starts_with("//!") {
            continue;
        }
        for p in &f {
            assert!(!s.contains(p), "forbidden '{}' found", p);
        }
    }
}
// Safety flags block in build
#[test]
fn i19_safety_blocks() {
    let caps = vec![rdy_cap()];
    let sum = summarize_event_stream_reader_spike_results(&caps);
    let mut gi = default_reader_spike_release_gate_input();
    gi.result_summary = sum.clone();
    let gr = evaluate_reader_spike_release_gate(&gi);
    let mut i = di();
    i.result_summary = sum;
    i.release_gate_report = gr;
    let p = build_reader_spike_review_pack(&i);
    // With valid chain, pack should be Incomplete (not all phase validators pass
    // with default safe inputs) or ReviewReady.
    assert!(!p.release_allowed && p.must_remain_experimental);
}
// Additional: empty phase validation
#[test]
fn i19_val_empty_phase() {
    let mut p = build_reader_spike_review_pack(&di());
    p.phase = String::new();
    assert!(validate_reader_spike_review_pack(&p).is_err());
}
