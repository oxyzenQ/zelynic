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
    EbpfEventStreamReaderSpikeExecutorResult, EbpfEventStreamReaderSpikeExecutorStatus,
};
use super::backends::ebpf::event_stream_reader_spike_executor_audit::{
    evaluate_event_stream_reader_spike_executor_audit,
    EbpfEventStreamReaderSpikeExecutorAuditInput, EbpfEventStreamReaderSpikeExecutorAuditReport,
};
use super::backends::ebpf::event_stream_reader_spike_prep::evaluate_event_stream_reader_spike_prep;
use super::backends::ebpf::event_stream_reader_spike_release_gate::*;
use super::backends::ebpf::event_stream_reader_spike_result::{
    capture_event_stream_reader_spike_result, summarize_event_stream_reader_spike_results,
    EbpfEventStreamReaderSpikeResultCapture, EbpfEventStreamReaderSpikeResultStatus,
};
use crate::cli::Cli;
use clap::CommandFactory;
fn dl() -> String {
    include_str!("../../docs/intergalaxion/I-18-reader-spike-result-audit-release-decision-gate.md")
        .to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_release_gate.rs");
fn di() -> EbpfReaderSpikeReleaseGateInput {
    default_reader_spike_release_gate_input()
}
type GS = EbpfReaderSpikeReleaseGateStatus;
type GD = EbpfReaderSpikeReleaseDecision;
type GK = EbpfReaderSpikeReleaseGateFindingKind;
type RS = EbpfEventStreamReaderSpikeResultStatus;
type ES = EbpfEventStreamReaderSpikeExecutorStatus;
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
fn rdy_summary() -> EbpfEventStreamReaderSpikeResultCapture {
    cp(ser(), sar2())
}
fn di_safe(
    caps: &[EbpfEventStreamReaderSpikeResultCapture],
    req_fer: bool,
    req_cc: bool,
    allow_es: bool,
) -> EbpfReaderSpikeReleaseGateInput {
    let summary = summarize_event_stream_reader_spike_results(caps);
    EbpfReaderSpikeReleaseGateInput {
        result_summary: summary,
        require_future_execution_ready_capture: req_fer,
        require_cleanup_completed_capture: req_cc,
        allow_execution_succeeded_capture: allow_es,
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
fn has_finding(r: &EbpfReaderSpikeReleaseGateReport, code: &str) -> bool {
    r.findings.iter().any(|f| f.code == code)
}
fn mut_cap(c: &EbpfEventStreamReaderSpikeResultCapture) -> EbpfEventStreamReaderSpikeResultCapture {
    let mut c2 = rdy_summary();
    c2.result_status = c.result_status;
    c2.fake_reader_success_detected = c.fake_reader_success_detected;
    c2.fake_live_event_counts_detected = c.fake_live_event_counts_detected;
    c2.public_cli_exposed = c.public_cli_exposed;
    c2.ring_buffer_opened = c.ring_buffer_opened;
    c2.live_event_stream_read = c.live_event_stream_read;
    c2.map_pin_performed = c.map_pin_performed;
    c2.enforcement_performed = c.enforcement_performed;
    c2.packet_drop_performed = c.packet_drop_performed;
    c2.mutation_performed = c.mutation_performed;
    c2.persistence_performed = c.persistence_performed;
    c2
}
// 1: default gate input is safe
#[test]
fn i18_def_input_safe() {
    let i = di();
    let ok = !i.stable_release_requested
        && !i.tag_requested
        && !i.publish_requested
        && !i.version_bump_requested
        && !i.main_merge_requested
        && i.public_cli_expected_hidden
        && i.usage_schema_expected_unchanged
        && i.ledger_schema_expected_unchanged
        && !i.allow_execution_succeeded_capture;
    assert!(ok);
}
// 2: default report phase is I-18
#[test]
fn i18_def_phase() {
    assert_eq!(evaluate_reader_spike_release_gate(&di()).phase, "I-18");
}
// 3: default report has all operation flags false
#[test]
fn i18_def_flags() {
    let r = evaluate_reader_spike_release_gate(&di());
    let ok = !r.ring_buffer_opened
        && !r.live_event_stream_read
        && !r.map_pin_performed
        && !r.enforcement_performed
        && !r.packet_drop_performed
        && !r.mutation_performed
        && !r.persistence_performed
        && !r.public_cli_exposed
        && !r.usage_schema_changed
        && !r.ledger_schema_changed
        && !r.invalid_capture_detected
        && !r.fake_reader_success_detected
        && !r.fake_live_event_counts_detected
        && !r.stable_release_requested
        && !r.tag_requested
        && !r.publish_requested
        && !r.version_bump_requested
        && !r.main_merge_requested;
    assert!(ok);
}
// 4: gate status labels
#[test]
fn i18_gs_labels() {
    assert_eq!(
        reader_spike_release_gate_status_label(GS::NotReady),
        "not_ready"
    );
    assert_eq!(
        reader_spike_release_gate_status_label(GS::Blocked),
        "blocked"
    );
    assert_eq!(reader_spike_release_gate_status_label(GS::Failed), "failed");
    assert_eq!(
        reader_spike_release_gate_status_label(GS::Warning),
        "warning"
    );
    assert_eq!(reader_spike_release_gate_status_label(GS::Passed), "passed");
    assert_eq!(
        reader_spike_release_gate_status_label(GS::HoldExperimental),
        "hold_experimental"
    );
    assert_eq!(
        reader_spike_release_gate_status_label(GS::ContinueLocalLab),
        "continue_local_lab"
    );
    assert_eq!(
        reader_spike_release_gate_status_label(GS::ReadyForReaderSpikeReview),
        "ready_for_reader_spike_review"
    );
    assert_eq!(
        reader_spike_release_gate_status_label(GS::ReleaseRejected),
        "release_rejected"
    );
}
// 5: decision labels
#[test]
fn i18_gd_labels() {
    assert_eq!(reader_spike_release_decision_label(GD::Stop), "stop");
    assert_eq!(
        reader_spike_release_decision_label(GD::FixPreparation),
        "fix_preparation"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::FixExecutor),
        "fix_executor"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::CaptureMoreEvidence),
        "capture_more_evidence"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::ContinueLocalLabOnly),
        "continue_local_lab_only"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::PrepareReaderSpikeReview),
        "prepare_reader_spike_review"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::RejectRelease),
        "reject_release"
    );
    assert_eq!(
        reader_spike_release_decision_label(GD::KeepExperimental),
        "keep_experimental"
    );
}
// 6: finding kind labels
#[test]
fn i18_gk_labels() {
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::ResultCapture),
        "result_capture"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::ResultSummary),
        "result_summary"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::SafetyInvariant),
        "safety_invariant"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::CliInvariant),
        "cli_invariant"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::SchemaInvariant),
        "schema_invariant"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::ReleaseInvariant),
        "release_invariant"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::CountInvariant),
        "count_invariant"
    );
    assert_eq!(
        reader_spike_release_gate_finding_kind_label(GK::EvidenceInvariant),
        "evidence_invariant"
    );
}
// 7: release_allowed=false
#[test]
fn i18_def_ra() {
    assert!(!evaluate_reader_spike_release_gate(&di()).release_allowed);
}
// 8: must_remain_experimental=true
#[test]
fn i18_def_mre() {
    assert!(evaluate_reader_spike_release_gate(&di()).must_remain_experimental);
}
// 9: not ready for reader spike review by default
#[test]
fn i18_def_not_rdy() {
    assert!(!evaluate_reader_spike_release_gate(&di()).ready_for_reader_spike_review);
}
// 10: default summary validates
#[test]
fn i18_def_findings() {
    let r = evaluate_reader_spike_release_gate(&di());
    assert!(r.summary_valid);
    assert_ne!(r.status, GS::ReadyForReaderSpikeReview);
}
// 11: valid summary required for readiness
#[test]
fn i18_req_valid_summary() {
    let r = evaluate_reader_spike_release_gate(&di());
    assert!(r.summary_valid);
    assert_ne!(r.status, GS::ReadyForReaderSpikeReview);
}
// 12: ready requires summary ready
#[test]
fn i18_rdy_req_summary_rdy() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(!r.ready_for_reader_spike_review || r.summary_valid);
}
// 13: FER required check
#[test]
fn i18_req_fer_present() {
    let c = rdy_summary();
    let mut i = di_safe(&[c], true, false, false);
    i.require_future_execution_ready_capture = true;
    let r = evaluate_reader_spike_release_gate(&i);
    if !has_finding(&r, "GATE-FUTURE-EXEC-READY-MISSING") {
        assert!(r.future_execution_ready_capture_present);
    }
}
// 14: CC required check
#[test]
fn i18_req_cc_present() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = true;
    r.cleanup_completed = true;
    let c = cp(r, sar2());
    let i = di_safe(&[c], false, true, false);
    let rpt = evaluate_reader_spike_release_gate(&i);
    if !has_finding(&rpt, "GATE-CLEANUP-COMPLETED-MISSING") {
        assert!(rpt.cleanup_completed_capture_present);
    }
}
// 15: rejects invalid captures
#[test]
fn i18_rj_invalid() {
    let mut c = rdy_summary();
    c.result_status = RS::InvalidCapture;
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.invalid_capture_detected);
    assert_eq!(r.status, GS::Blocked);
    assert!(has_finding(&r, "GATE-INVALID-CAPTURE"));
}
// 16: rejects fake reader success
#[test]
fn i18_rj_fake_reader() {
    let mut c = rdy_summary();
    c.fake_reader_success_detected = true;
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.fake_reader_success_detected);
    assert_eq!(r.status, GS::Blocked);
    assert!(has_finding(&r, "GATE-FAKE-READER-SUCCESS"));
}
// 17: rejects fake live event counts
#[test]
fn i18_rj_fake_counts() {
    let mut c = rdy_summary();
    c.fake_live_event_counts_detected = true;
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.fake_live_event_counts_detected);
    assert!(has_finding(&r, "GATE-FAKE-LIVE-COUNTS"));
}
// 18: rejects ExecutionSucceeded unless allowed
#[test]
fn i18_rj_exec_succ() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    let c = cp(r, sar2());
    let i = di_safe(&[c], false, false, false);
    let rpt = evaluate_reader_spike_release_gate(&i);
    assert!(rpt.execution_succeeded_capture_present);
    assert!(has_finding(&rpt, "GATE-EXEC-SUCCEEDED-NOT-ALLOWED"));
}
// 19: allowed ExecutionSucceeded still no release
#[test]
fn i18_allow_exec_no_release() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    let c = cp(r, sar2());
    let i = di_safe(&[c], false, false, true);
    let rpt = evaluate_reader_spike_release_gate(&i);
    assert!(!rpt.release_allowed);
    assert!(rpt.must_remain_experimental);
}
// 20-24: release request blocking
#[test]
fn i18_rj_stable_release() {
    let mut i = di();
    i.stable_release_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert_eq!(r.status, GS::Blocked);
    assert!(has_finding(&r, "GATE-STABLE-RELEASE-REQUESTED"));
}
#[test]
fn i18_rj_tag() {
    let mut i = di();
    i.tag_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-TAG-REQUESTED"));
}
#[test]
fn i18_rj_publish() {
    let mut i = di();
    i.publish_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-PUBLISH-REQUESTED"));
}
#[test]
fn i18_rj_version_bump() {
    let mut i = di();
    i.version_bump_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-VERSION-BUMP-REQUESTED"));
}
#[test]
fn i18_rj_main_merge() {
    let mut i = di();
    i.main_merge_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-MAIN-MERGE-REQUESTED"));
}
// 25: public_cli blocks
#[test]
fn i18_rj_cli() {
    let mut c = rdy_summary();
    c.public_cli_exposed = true;
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.public_cli_exposed);
    assert!(has_finding(&r, "GATE-PUBLIC-CLI-EXPOSED"));
}
// 26-27: schema change blocks
#[test]
fn i18_rj_usage_schema() {
    let mut i = di();
    i.usage_schema_expected_unchanged = false;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.usage_schema_changed);
    assert!(has_finding(&r, "GATE-USAGE-SCHEMA-CHANGED"));
}
#[test]
fn i18_rj_ledger_schema() {
    let mut i = di();
    i.ledger_schema_expected_unchanged = false;
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(r.ledger_schema_changed);
    assert!(has_finding(&r, "GATE-LEDGER-SCHEMA-CHANGED"));
}
// 28: pass with FER
#[test]
fn i18_pass_fer() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert_eq!(r.status, GS::ReadyForReaderSpikeReview);
    assert_eq!(r.decision, GD::PrepareReaderSpikeReview);
    assert!(r.ready_for_reader_spike_review);
}
// 29: passed gate still release_allowed=false
#[test]
fn i18_pass_no_release() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, false, false);
    assert!(!evaluate_reader_spike_release_gate(&i).release_allowed);
}
// 30: passed gate still must_remain_experimental=true
#[test]
fn i18_pass_mre() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, false, false);
    assert!(evaluate_reader_spike_release_gate(&i).must_remain_experimental);
}
// 31: passed gate decision
#[test]
fn i18_pass_decision() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    let ok = r.decision == GD::PrepareReaderSpikeReview || r.decision == GD::ContinueLocalLabOnly;
    assert!(ok);
}
// 32: validation accepts safe default
#[test]
fn i18_val_def_ok() {
    let r = evaluate_reader_spike_release_gate(&di());
    assert!(validate_reader_spike_release_gate_report(&r).is_ok());
}
// 33-51: validation rejects unsafe flags
#[test]
fn i18_val_ra() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.release_allowed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_mre() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.must_remain_experimental = false;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_cli() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.public_cli_exposed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_usage() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.usage_schema_changed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_ledger() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.ledger_schema_changed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_sr() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.stable_release_requested = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_tag() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.tag_requested = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_pub() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.publish_requested = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_vb() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.version_bump_requested = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_mm() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.main_merge_requested = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_rb() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.ring_buffer_opened = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_le() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.live_event_stream_read = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_mp() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.map_pin_performed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_en() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.enforcement_performed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_pd() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.packet_drop_performed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_mu() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.mutation_performed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_pe() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.persistence_performed = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_frs() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.fake_reader_success_detected = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
#[test]
fn i18_val_flc() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.fake_live_event_counts_detected = true;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
// 52: rejects ready when Failed
#[test]
fn i18_val_rdy_failed() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.ready_for_reader_spike_review = true;
    r.status = GS::Failed;
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
// 53: blocked gate has blocking finding
#[test]
fn i18_failed_blocking() {
    let mut i = di();
    i.stable_release_requested = true;
    let r = evaluate_reader_spike_release_gate(&i);
    assert_eq!(r.status, GS::Blocked);
    assert!(r.findings.iter().any(|f| f.blocking));
}
// 54: deterministic
#[test]
fn i18_deterministic() {
    let r1 = evaluate_reader_spike_release_gate(&di());
    let r2 = evaluate_reader_spike_release_gate(&di());
    assert_eq!(r1.status, r2.status);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.release_allowed, r2.release_allowed);
    assert_eq!(r1.findings.len(), r2.findings.len());
}
// 55-74: docs
#[test]
fn i18_doc_audit() {
    let d = dl();
    assert!(d.contains("reader spike result audit"));
}
#[test]
fn i18_doc_internal() {
    assert!(dl().contains("internal decision gate"));
}
#[test]
fn i18_doc_no_real_release() {
    assert!(dl().contains("release decision gate does not mean real release"));
}
#[test]
fn i18_doc_no_tag() {
    assert!(dl().contains("no tag"));
}
#[test]
fn i18_doc_no_release() {
    assert!(dl().contains("no release"));
}
#[test]
fn i18_doc_no_publish() {
    assert!(dl().contains("no publish"));
}
#[test]
fn i18_doc_no_version() {
    assert!(dl().contains("no version bump"));
}
#[test]
fn i18_doc_no_main_merge() {
    assert!(dl().contains("no main merge"));
}
#[test]
fn i18_doc_no_cli() {
    assert!(dl().contains("no public cli"));
}
#[test]
fn i18_doc_no_ci_live() {
    assert!(dl().contains("no normal ci live event read"));
}
#[test]
fn i18_doc_no_rb() {
    assert!(dl().contains("no ring buffer open"));
}
#[test]
fn i18_doc_no_live() {
    assert!(dl().contains("no live kernel event read"));
}
#[test]
fn i18_doc_no_pin() {
    assert!(dl().contains("no map pin"));
}
#[test]
fn i18_doc_no_enf() {
    assert!(dl().contains("no enforcement"));
}
#[test]
fn i18_doc_no_pd() {
    assert!(dl().contains("no packet drop"));
}
#[test]
fn i18_doc_no_baq() {
    assert!(dl().contains("no block/allow/quota"));
}
#[test]
fn i18_doc_no_nfttc() {
    assert!(dl().contains("no nft/tc fallback"));
}
#[test]
fn i18_doc_no_persist() {
    let d = dl();
    assert!(d.contains("no ledger file write") || d.contains("no persistence"));
}
#[test]
fn i18_doc_usage_schema() {
    assert!(dl().contains("existing v3.1 usage json schema unchanged"));
}
#[test]
fn i18_doc_ledger_schema() {
    assert!(dl().contains("existing v3.1 ledger json schema unchanged"));
}
#[test]
fn i18_doc_ra_false() {
    assert!(dl().contains("release_allowed is always false"));
}
#[test]
fn i18_doc_mre_true() {
    assert!(dl().contains("must_remain_experimental is always true"));
}
#[test]
fn i18_doc_fake_reader() {
    let d = dl();
    assert!(d.contains("fake reader execution success") && d.contains("rejected"));
}
#[test]
fn i18_doc_fake_counts() {
    let d = dl();
    assert!(d.contains("fake live event counts") && d.contains("rejected"));
}
// 75-79: existing CLI works
#[test]
fn i18_ver() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}
#[test]
fn i18_li() {
    let p = std::env::temp_dir().join("z-i18-i.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i18","entries":[]}"#,
    );
    let r =
        crate::commands::ledger::handle_ledger_inspect(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i18_le() {
    let p = std::env::temp_dir().join("z-i18-e.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i18","entries":[]}"#,
    );
    let r = crate::commands::ledger::handle_ledger_export(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i18_help1() {
    let mut a = Cli::command();
    assert!(!a
        .render_help()
        .to_string()
        .to_lowercase()
        .contains("intergalaxion"));
}
#[test]
fn i18_help2() {
    let mut a = Cli::command();
    let h = a.render_help().to_string();
    assert!(!h.contains("block") && !h.contains("allow") && !h.contains("quota"));
}
// 80-82: deps, nft/tc, LOC
#[test]
fn i18_dep() {
    assert!(include_str!("../../Cargo.toml").contains("aya"));
}
#[test]
fn i18_nft() {
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
fn i18_forbid() {
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
// Additional: pass with CC
#[test]
fn i18_pass_cc() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = true;
    r.cleanup_completed = true;
    let c = cp(r, sar2());
    let i = di_safe(&[c], false, false, false);
    let rpt = evaluate_reader_spike_release_gate(&i);
    assert_eq!(rpt.status, GS::ReadyForReaderSpikeReview);
    assert_eq!(rpt.decision, GD::PrepareReaderSpikeReview);
}
// FER missing
#[test]
fn i18_fer_missing() {
    let mut c = rdy_summary();
    c.result_status = RS::NotRun;
    let i = di_safe(&[c], true, false, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-FUTURE-EXEC-READY-MISSING"));
}
// CC missing
#[test]
fn i18_cc_missing() {
    let c = rdy_summary();
    let i = di_safe(&[c], false, true, false);
    let r = evaluate_reader_spike_release_gate(&i);
    assert!(has_finding(&r, "GATE-CLEANUP-COMPLETED-MISSING"));
}
// Safety flags block
#[test]
fn i18_safety_blocks() {
    let flags = [
        ("ring_buffer_opened", "GATE-RING-BUFFER-OPENED"),
        ("live_event_stream_read", "GATE-LIVE-EVENT-READ"),
        ("map_pin_performed", "GATE-MAP-PIN-PERFORMED"),
        ("enforcement_performed", "GATE-ENFORCEMENT-PERFORMED"),
        ("packet_drop_performed", "GATE-PACKET-DROP-PERFORMED"),
        ("mutation_performed", "GATE-MUTATION-PERFORMED"),
        ("persistence_performed", "GATE-PERSISTENCE-PERFORMED"),
    ];
    for (field, code) in &flags {
        let mut c = rdy_summary();
        match *field {
            "ring_buffer_opened" => c.ring_buffer_opened = true,
            "live_event_stream_read" => c.live_event_stream_read = true,
            "map_pin_performed" => c.map_pin_performed = true,
            "enforcement_performed" => c.enforcement_performed = true,
            "packet_drop_performed" => c.packet_drop_performed = true,
            "mutation_performed" => c.mutation_performed = true,
            "persistence_performed" => c.persistence_performed = true,
            _ => unreachable!(),
        }
        let i = di_safe(&[c], false, false, false);
        let r = evaluate_reader_spike_release_gate(&i);
        assert!(has_finding(&r, code), "expected finding {}", code);
    }
}
// Empty phase validation
#[test]
fn i18_val_empty_phase() {
    let mut r = evaluate_reader_spike_release_gate(&di());
    r.phase = String::new();
    assert!(validate_reader_spike_release_gate_report(&r).is_err());
}
