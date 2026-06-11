// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::manual_assert)]
use super::backends::ebpf::event_stream_evidence_audit::{
    default_event_stream_evidence_audit_input, evaluate_event_stream_evidence_audit,
    EbpfEventStreamEvidenceAuditReport, EbpfEventStreamEvidenceAuditStatus,
};
use super::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
use super::backends::ebpf::event_stream_reader_spike_executor::{
    evaluate_event_stream_reader_spike_executor, EbpfEventStreamReaderSpikeExecutorResult,
    EbpfEventStreamReaderSpikeExecutorStatus,
};
use super::backends::ebpf::event_stream_reader_spike_executor_audit::{
    evaluate_event_stream_reader_spike_executor_audit,
    EbpfEventStreamReaderSpikeExecutorAuditInput, EbpfEventStreamReaderSpikeExecutorAuditReport,
};
use super::backends::ebpf::event_stream_reader_spike_prep::evaluate_event_stream_reader_spike_prep;
use super::backends::ebpf::event_stream_reader_spike_result::*;
use crate::cli::Cli;
use clap::CommandFactory;
fn dl() -> String {
    include_str!("../../docs/intergalaxion/I-17-local-reader-spike-result-capture.md")
        .to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_result.rs");
fn dc() -> EbpfEventStreamReaderSpikeResultCapture {
    default_event_stream_reader_spike_result_capture()
}
fn sar() -> EbpfEventStreamEvidenceAuditReport {
    let mut i = default_event_stream_evidence_audit_input();
    i.manual_summary.ready_for_event_stream_planning = true;
    i.manual_summary.clean_detach_count = 1;
    i.manual_summary.successful_attach_count = 1;
    i.manual_summary.summary_status = super::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualResultStatus::DetachedCleanly;
    i.require_clean_detach_evidence = true;
    let mut r = evaluate_event_stream_evidence_audit(&i);
    r.ready_for_reader_spike_preparation = true;
    r.status = EbpfEventStreamEvidenceAuditStatus::Passed;
    r.manual_capture_ready = true;
    r.findings.clear();
    r
}
type PI =
    super::backends::ebpf::event_stream_reader_spike_prep::EbpfEventStreamReaderSpikePrepInput;
type PP = super::backends::ebpf::event_stream_reader_spike_prep::EbpfEventStreamReaderSpikePrepPlan;
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
type EI = super::backends::ebpf::event_stream_reader_spike_executor::EbpfEventStreamReaderSpikeExecutorInput;
fn sei() -> EI {
    EI {
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
fn ser_fd() -> EbpfEventStreamReaderSpikeExecutorResult {
    evaluate_event_stream_reader_spike_executor(&super::backends::ebpf::event_stream_reader_spike_executor::default_event_stream_reader_spike_executor_input())
}
fn cp(
    er: EbpfEventStreamReaderSpikeExecutorResult,
    ar: EbpfEventStreamReaderSpikeExecutorAuditReport,
    l: &str,
    c: &str,
) -> EbpfEventStreamReaderSpikeResultCapture {
    capture_event_stream_reader_spike_result(er, ar, l, c)
}
type RS = EbpfEventStreamReaderSpikeResultStatus;
type R = EbpfEventStreamReaderSpikeRecommendation;
type ES = EbpfEventStreamReaderSpikeExecutorStatus;
type EL = EbpfEventStreamReaderSpikeEvidenceLevel;
#[test]
fn i17_default_phase() {
    assert_eq!(dc().phase, "I-17");
}
#[test]
fn i17_default_status() {
    assert_eq!(dc().result_status, RS::NotRun);
}
#[test]
fn i17_default_flags() {
    let c = dc();
    assert!(
        !c.attempted
            && !c.reader_started
            && !c.reader_completed
            && !c.cleanup_required
            && !c.cleanup_completed
            && !c.public_cli_exposed
            && !c.ring_buffer_opened
            && !c.live_event_stream_read
            && !c.map_pin_performed
            && !c.enforcement_performed
            && !c.packet_drop_performed
            && !c.mutation_performed
            && !c.persistence_performed
            && !c.fake_reader_success_detected
            && !c.fake_live_event_counts_detected
    );
}
#[test]
fn i17_status_labels() {
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::NotRun),
        "not_run"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::FeatureDisabled),
        "feature_disabled"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::PrepRejected),
        "prep_rejected"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::ExecutorDisabled),
        "executor_disabled"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::ReaderNotImplemented),
        "reader_not_implemented"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::FutureExecutionReady),
        "future_execution_ready"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::ExecutionAttempted),
        "execution_attempted"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::ExecutionSucceeded),
        "execution_succeeded"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::ExecutionFailed),
        "execution_failed"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::CleanupRequired),
        "cleanup_required"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::CleanupCompleted),
        "cleanup_completed"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::CleanupFailed),
        "cleanup_failed"
    );
    assert_eq!(
        event_stream_reader_spike_result_status_label(RS::InvalidCapture),
        "invalid_capture"
    );
}
#[test]
fn i17_ev_labels() {
    assert_eq!(
        event_stream_reader_spike_evidence_level_label(EL::None),
        "none"
    );
    assert_eq!(
        event_stream_reader_spike_evidence_level_label(EL::OperatorReported),
        "operator_reported"
    );
    assert_eq!(
        event_stream_reader_spike_evidence_level_label(EL::ExecutorResultCaptured),
        "executor_result_captured"
    );
    assert_eq!(
        event_stream_reader_spike_evidence_level_label(EL::CleanupEvidenceCaptured),
        "cleanup_evidence_captured"
    );
    assert_eq!(
        event_stream_reader_spike_evidence_level_label(EL::AuditReady),
        "audit_ready"
    );
}
#[test]
fn i17_rec_labels() {
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::Stop),
        "stop"
    );
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::FixPreparation),
        "fix_preparation"
    );
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::FixExecutor),
        "fix_executor"
    );
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::CaptureCleanupEvidence),
        "capture_cleanup_evidence"
    );
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::RetryLocalLab),
        "retry_local_lab"
    );
    assert_eq!(
        event_stream_reader_spike_recommendation_label(R::ReadyForReaderSpikeReview),
        "ready_for_reader_spike_review"
    );
}
#[test]
fn i17_cap_fd() {
    assert_eq!(
        cp(ser_fd(), sar2(), "o", "").result_status,
        RS::FeatureDisabled
    );
}
#[test]
fn i17_cap_pr() {
    let mut r = ser_fd();
    r.status = ES::PrepRejected;
    r.feature_enabled = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::PrepRejected);
}
#[test]
fn i17_cap_ed() {
    let mut r = ser_fd();
    r.status = ES::ExecutorDisabled;
    r.feature_enabled = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::ExecutorDisabled);
}
#[test]
fn i17_cap_rni() {
    let mut r = ser_fd();
    r.status = ES::ReaderNotImplemented;
    r.feature_enabled = true;
    assert_eq!(
        cp(r, sar2(), "o", "").result_status,
        RS::ReaderNotImplemented
    );
}
#[test]
fn i17_cap_fer() {
    assert_eq!(
        cp(ser(), sar2(), "o", "c").result_status,
        RS::FutureExecutionReady
    );
}
#[test]
fn i17_att_ok() {
    let mut r = ser();
    r.status = ES::ExecutionAttempted;
    r.attempted = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::ExecutionAttempted);
}
#[test]
fn i17_att_bad() {
    let mut r = ser();
    r.status = ES::ExecutionAttempted;
    r.attempted = false;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_reader_success_detected);
}
#[test]
fn i17_suc_na() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = false;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
}
#[test]
fn i17_suc_ns() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = false;
    r.reader_completed = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_fake_succ() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    r.events_read = 10;
    r.live_event_stream_read = false;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_live_event_counts_detected);
}
#[test]
fn i17_fake_cnt() {
    let mut r = ser();
    r.status = ES::FutureExecutionReady;
    r.events_read = 5;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_live_event_counts_detected);
}
#[test]
fn i17_fer_att() {
    let mut r = ser();
    r.attempted = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_fer_rs() {
    let mut r = ser();
    r.reader_started = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_fer_rc() {
    let mut r = ser();
    r.reader_completed = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_fer_ev() {
    let mut r = ser();
    r.events_read = 1;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_live_event_counts_detected);
}
#[test]
fn i17_fer_de() {
    let mut r = ser();
    r.decode_errors = 1;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_live_event_counts_detected);
}
#[test]
fn i17_fer_br() {
    let mut r = ser();
    r.bridge_records = 1;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::InvalidCapture);
    assert!(c.fake_live_event_counts_detected);
}
#[test]
fn i17_cc_ok() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = true;
    r.cleanup_completed = true;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::CleanupCompleted);
}
#[test]
fn i17_cc_bad() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = false;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_labels() {
    let c = cp(ser(), sar2(), "my-op", "run-v1");
    assert_eq!(c.operator_label, "my-op");
    assert_eq!(c.command_summary, "run-v1");
}
#[test]
fn i17_val_ok() {
    assert!(validate_event_stream_reader_spike_result_capture(&dc()).is_ok());
}
#[test]
fn i17_val_id() {
    let mut c = dc();
    c.capture_id = String::new();
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_ph() {
    let mut c = dc();
    c.phase = String::new();
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_lab() {
    let mut c = dc();
    c.local_lab_only = false;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_cli() {
    let mut c = dc();
    c.public_cli_exposed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_mp() {
    let mut c = dc();
    c.map_pin_performed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_en() {
    let mut c = dc();
    c.enforcement_performed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_pd() {
    let mut c = dc();
    c.packet_drop_performed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_mu() {
    let mut c = dc();
    c.mutation_performed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_pe() {
    let mut c = dc();
    c.persistence_performed = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_fr() {
    let mut c = dc();
    c.fake_reader_success_detected = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_fc() {
    let mut c = dc();
    c.fake_live_event_counts_detected = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_ev() {
    let mut c = dc();
    c.events_read = 1;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_de() {
    let mut c = dc();
    c.decode_errors = 1;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_val_br() {
    let mut c = dc();
    c.bridge_records = 1;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_sum_det() {
    let c1 = dc();
    let c2 = dc();
    let s1 = summarize_event_stream_reader_spike_results(&[c1.clone(), c2.clone()]);
    let s2 = summarize_event_stream_reader_spike_results(&[c2, c1]);
    assert_eq!(s1.total_captures, s2.total_captures);
    assert_eq!(s1.not_run_count, s2.not_run_count);
}
#[test]
fn i17_sum_tot() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[dc(), dc(), dc()]).total_captures,
        3
    );
}
#[test]
fn i17_sum_nr() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[dc(), dc()]).not_run_count,
        2
    );
}
#[test]
fn i17_sum_fd() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(ser_fd(), sar2(), "o", "")])
            .feature_disabled_count,
        1
    );
}
#[test]
fn i17_sum_pr() {
    let mut r = ser_fd();
    r.status = ES::PrepRejected;
    r.feature_enabled = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")]).prep_rejected_count,
        1
    );
}
#[test]
fn i17_sum_ed() {
    let mut r = ser_fd();
    r.status = ES::ExecutorDisabled;
    r.feature_enabled = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .executor_disabled_count,
        1
    );
}
#[test]
fn i17_sum_rni() {
    let mut r = ser_fd();
    r.status = ES::ReaderNotImplemented;
    r.feature_enabled = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .reader_not_implemented_count,
        1
    );
}
#[test]
fn i17_sum_fer() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(ser(), sar2(), "o", "")])
            .future_execution_ready_count,
        1
    );
}
#[test]
fn i17_sum_ea() {
    let mut r = ser();
    r.status = ES::ExecutionAttempted;
    r.attempted = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .execution_attempted_count,
        1
    );
}
#[test]
fn i17_sum_es() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .execution_succeeded_count,
        1
    );
}
#[test]
fn i17_sum_ef() {
    let mut r = ser();
    r.status = ES::ExecutionFailed;
    r.attempted = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .execution_failed_count,
        1
    );
}
#[test]
fn i17_sum_cr() {
    let mut r = ser();
    r.status = ES::CleanupRequired;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .cleanup_required_count,
        1
    );
}
#[test]
fn i17_sum_cc() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = true;
    r.cleanup_completed = true;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .cleanup_completed_count,
        1
    );
}
#[test]
fn i17_sum_cf() {
    let mut c = cp(ser(), sar2(), "o", "");
    c.result_status = RS::CleanupFailed;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[c]).cleanup_failed_count,
        1
    );
}
#[test]
fn i17_sum_ic() {
    let mut r = ser();
    r.events_read = 5;
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
            .invalid_capture_count,
        1
    );
}
#[test]
fn i17_nr_empty() {
    assert!(!summarize_event_stream_reader_spike_results(&[]).ready_for_reader_spike_review);
}
#[test]
fn i17_rdy_fer() {
    assert!(
        summarize_event_stream_reader_spike_results(&[cp(ser(), sar2(), "o", "c")])
            .ready_for_reader_spike_review
    );
}
#[test]
fn i17_rdy_cc() {
    let mut r = ser();
    r.status = ES::CleanupCompleted;
    r.cleanup_required = true;
    r.cleanup_completed = true;
    assert!(
        summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "c")])
            .ready_for_reader_spike_review
    );
}
#[test]
fn i17_nr_fr() {
    let mut c = cp(ser(), sar2(), "o", "c");
    c.fake_reader_success_detected = true;
    assert!(!summarize_event_stream_reader_spike_results(&[c]).ready_for_reader_spike_review);
}
#[test]
fn i17_nr_fc() {
    let mut c = cp(ser(), sar2(), "o", "c");
    c.fake_live_event_counts_detected = true;
    assert!(!summarize_event_stream_reader_spike_results(&[c]).ready_for_reader_spike_review);
}
#[test]
fn i17_sr_cli() {
    let mut c = dc();
    c.public_cli_exposed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(s.public_cli_exposed && validate_event_stream_reader_spike_result_summary(&s).is_err());
}
#[test]
fn i17_rb_ok() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    let mut c = cp(r, sar2(), "o", "");
    c.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_result_summary(
        &summarize_event_stream_reader_spike_results(&[c])
    )
    .is_ok());
}
#[test]
fn i17_rb_rj() {
    let mut s = summarize_event_stream_reader_spike_results(&[cp(ser(), sar2(), "o", "")]);
    s.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_result_summary(&s).is_err());
}
#[test]
fn i17_le_ok() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    r.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_result_summary(
        &summarize_event_stream_reader_spike_results(&[cp(r, sar2(), "o", "")])
    )
    .is_ok());
}
#[test]
fn i17_le_rj() {
    let mut s = summarize_event_stream_reader_spike_results(&[cp(ser(), sar2(), "o", "")]);
    s.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_result_summary(&s).is_err());
}
#[test]
fn i17_sr_mp() {
    let mut c = dc();
    c.map_pin_performed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(s.map_pin_performed && validate_event_stream_reader_spike_result_summary(&s).is_err());
}
#[test]
fn i17_sr_en() {
    let mut c = dc();
    c.enforcement_performed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(
        s.enforcement_performed && validate_event_stream_reader_spike_result_summary(&s).is_err()
    );
}
#[test]
fn i17_sr_pd() {
    let mut c = dc();
    c.packet_drop_performed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(
        s.packet_drop_performed && validate_event_stream_reader_spike_result_summary(&s).is_err()
    );
}
#[test]
fn i17_sr_mu() {
    let mut c = dc();
    c.mutation_performed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(s.mutation_performed && validate_event_stream_reader_spike_result_summary(&s).is_err());
}
#[test]
fn i17_sr_pe() {
    let mut c = dc();
    c.persistence_performed = true;
    let s = summarize_event_stream_reader_spike_results(&[c]);
    assert!(
        s.persistence_performed && validate_event_stream_reader_spike_result_summary(&s).is_err()
    );
}
#[test]
fn i17_doc_all() {
    let d = dl();
    assert!(
        d.contains("local reader spike result capture")
            && d.contains("capture-only")
            && d.contains("no public cli")
    );
    assert!(
        d.contains("no normal ci live event read")
            && d.contains("no automatic reader execution")
            && d.contains("no ring buffer open")
    );
    assert!(
        d.contains("no live kernel event read")
            && d.contains("no map pin")
            && d.contains("no enforcement")
    );
    assert!(
        d.contains("no packet drop")
            && d.contains("no block/allow/quota")
            && d.contains("no nft/tc fallback")
    );
    assert!(d.contains("no ledger file write") || d.contains("no persistence"));
    assert!(
        d.contains("existing v3.1 usage json schema unchanged")
            && d.contains("existing v3.1 ledger json schema unchanged")
    );
    assert!(d.contains("executionsucceeded is never produced"));
    assert!(
        d.contains("fake reader execution success rejected")
            && d.contains("fake live event counts rejected")
    );
}
#[test]
fn i17_ver() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}
#[test]
fn i17_li() {
    let p = std::env::temp_dir().join("z-i17-i.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i17","entries":[]}"#,
    );
    let r =
        crate::commands::ledger::handle_ledger_inspect(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i17_le() {
    let p = std::env::temp_dir().join("z-i17-e.json");
    let _ = std::fs::write(
        &p,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i17","entries":[]}"#,
    );
    let r = crate::commands::ledger::handle_ledger_export(true, Some(p.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(&p);
    assert!(r.is_ok());
}
#[test]
fn i17_help1() {
    let mut a = Cli::command();
    assert!(!a
        .render_help()
        .to_string()
        .to_lowercase()
        .contains("intergalaxion"));
}
#[test]
fn i17_help2() {
    let mut a = Cli::command();
    let h = a.render_help().to_string();
    assert!(!h.contains("block") && !h.contains("allow") && !h.contains("quota"));
}
#[test]
fn i17_dep() {
    assert!(include_str!("../../Cargo.toml").contains("aya"));
}
#[test]
fn i17_nft() {
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
fn i17_forbid() {
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
#[test]
fn i17_blk_inv() {
    let mut r = ser_fd();
    r.status = ES::Blocked;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_fail_na() {
    let mut r = ser();
    r.status = ES::ExecutionFailed;
    r.attempted = false;
    assert_eq!(cp(r, sar2(), "o", "").result_status, RS::InvalidCapture);
}
#[test]
fn i17_rec_stop() {
    let mut c = dc();
    c.public_cli_exposed = true;
    assert_eq!(c.recommendation, R::Stop);
}
#[test]
fn i17_rec_fp() {
    let mut r = ser_fd();
    r.status = ES::PrepRejected;
    r.feature_enabled = true;
    assert_eq!(cp(r, sar2(), "o", "").recommendation, R::FixPreparation);
}
#[test]
fn i17_rec_fe() {
    let mut r = ser_fd();
    r.status = ES::ExecutorDisabled;
    r.feature_enabled = true;
    assert_eq!(cp(r, sar2(), "o", "").recommendation, R::FixExecutor);
}
#[test]
fn i17_rec_rdy() {
    assert_eq!(
        cp(ser(), sar2(), "o", "c").recommendation,
        R::ReadyForReaderSpikeReview
    );
}
#[test]
fn i17_srec_stop() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[]).recommendation,
        R::Stop
    );
}
#[test]
fn i17_def_ev() {
    assert_eq!(dc().evidence_level, EL::None);
}
#[test]
fn i17_def_rec() {
    assert_eq!(dc().recommendation, R::Stop);
}
#[test]
fn i17_succ_live() {
    let mut r = ser();
    r.status = ES::ExecutionSucceeded;
    r.attempted = true;
    r.reader_started = true;
    r.reader_completed = true;
    r.events_read = 5;
    r.live_event_stream_read = true;
    let c = cp(r, sar2(), "o", "");
    assert_eq!(c.result_status, RS::ExecutionSucceeded);
    assert!(!c.fake_live_event_counts_detected);
}
#[test]
fn i17_sum_ph() {
    assert_eq!(
        summarize_event_stream_reader_spike_results(&[]).phase,
        "I-17"
    );
}
#[test]
fn i17_fn() {
    assert_eq!(dc().feature_name, "intergalaxion-event-stream-lab");
}
#[test]
fn i17_vrb() {
    let mut c = dc();
    c.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
#[test]
fn i17_vle() {
    let mut c = dc();
    c.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_result_capture(&c).is_err());
}
