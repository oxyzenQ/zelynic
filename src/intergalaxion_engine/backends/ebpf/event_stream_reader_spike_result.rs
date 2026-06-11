// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Local reader spike result capture model for the Intergalaxion Engine.
//!
//! Phase I-17 defines the result capture layer for a future local reader spike.
//! This phase is NOT the real live event stream reader. It is NOT a ring buffer
//! reader. It is NOT a kernel event consumer. It captures and validates the
//! result of a future feature-gated local reader spike, consuming the I-16
//! executor result and I-16A executor audit report.
//!
//! # Design constraints (I-17)
//!
//! * Capture-only — not a live reader, not a ring buffer reader.
//! * Disabled by default — no capture possible without the
//!   `intergalaxion-event-stream-lab` Cargo feature.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake reader success.
//! * No fake live event counts.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.
//! * ExecutionSucceeded is never produced by normal build evaluation.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::{
    EbpfEventStreamReaderSpikeExecutorResult, EbpfEventStreamReaderSpikeExecutorStatus,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::EbpfEventStreamReaderSpikeExecutorAuditReport;

/// Status of the reader spike result capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeResultStatus {
    /// The reader spike was not run.
    NotRun,
    /// The feature is disabled.
    FeatureDisabled,
    /// Preparation was rejected.
    PrepRejected,
    /// The executor is disabled.
    ExecutorDisabled,
    /// The reader is not yet implemented.
    ReaderNotImplemented,
    /// All gates pass; future execution is ready.
    FutureExecutionReady,
    /// An execution was attempted.
    ExecutionAttempted,
    /// An execution succeeded (never reachable in I-17 normal build).
    ExecutionSucceeded,
    /// An execution failed.
    ExecutionFailed,
    /// Cleanup is required before next execution.
    CleanupRequired,
    /// Cleanup has been completed.
    CleanupCompleted,
    /// Cleanup failed.
    CleanupFailed,
    /// The capture is invalid or inconsistent.
    InvalidCapture,
}

impl EbpfEventStreamReaderSpikeResultStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::FeatureDisabled => "feature_disabled",
            Self::PrepRejected => "prep_rejected",
            Self::ExecutorDisabled => "executor_disabled",
            Self::ReaderNotImplemented => "reader_not_implemented",
            Self::FutureExecutionReady => "future_execution_ready",
            Self::ExecutionAttempted => "execution_attempted",
            Self::ExecutionSucceeded => "execution_succeeded",
            Self::ExecutionFailed => "execution_failed",
            Self::CleanupRequired => "cleanup_required",
            Self::CleanupCompleted => "cleanup_completed",
            Self::CleanupFailed => "cleanup_failed",
            Self::InvalidCapture => "invalid_capture",
        }
    }
}

/// Evidence level of the reader spike result capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeEvidenceLevel {
    /// No evidence captured.
    None,
    /// Operator-reported evidence only.
    OperatorReported,
    /// Executor result captured.
    ExecutorResultCaptured,
    /// Cleanup evidence captured.
    CleanupEvidenceCaptured,
    /// Full audit-ready evidence.
    AuditReady,
}

impl EbpfEventStreamReaderSpikeEvidenceLevel {
    /// Stable lowercase label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OperatorReported => "operator_reported",
            Self::ExecutorResultCaptured => "executor_result_captured",
            Self::CleanupEvidenceCaptured => "cleanup_evidence_captured",
            Self::AuditReady => "audit_ready",
        }
    }
}

/// Recommendation for the reader spike result capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeRecommendation {
    /// Stop and do not proceed.
    Stop,
    /// Fix preparation before proceeding.
    FixPreparation,
    /// Fix executor before proceeding.
    FixExecutor,
    /// Capture cleanup evidence.
    CaptureCleanupEvidence,
    /// Retry the local lab run.
    RetryLocalLab,
    /// Ready for reader spike review.
    ReadyForReaderSpikeReview,
}

impl EbpfEventStreamReaderSpikeRecommendation {
    /// Stable lowercase label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixPreparation => "fix_preparation",
            Self::FixExecutor => "fix_executor",
            Self::CaptureCleanupEvidence => "capture_cleanup_evidence",
            Self::RetryLocalLab => "retry_local_lab",
            Self::ReadyForReaderSpikeReview => "ready_for_reader_spike_review",
        }
    }
}

/// Captured result of a local reader spike.
///
/// Combines the I-16 executor result, I-16A audit report, operator labels,
/// safety flags, evidence level, and recommendation. The capture is pure
/// and deterministic. No live operations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeResultCapture {
    /// Unique capture identifier.
    pub capture_id: String,
    /// The phase this capture covers.
    pub phase: String,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// Feature name that was evaluated.
    pub feature_name: String,
    /// Whether the feature is enabled.
    pub feature_enabled: bool,
    /// Whether this is local lab only.
    pub local_lab_only: bool,
    /// The I-16 executor result.
    pub executor_result: EbpfEventStreamReaderSpikeExecutorResult,
    /// The I-16A executor audit report.
    pub executor_audit_report: EbpfEventStreamReaderSpikeExecutorAuditReport,
    /// The determined result status.
    pub result_status: EbpfEventStreamReaderSpikeResultStatus,
    /// The evidence level of this capture.
    pub evidence_level: EbpfEventStreamReaderSpikeEvidenceLevel,
    /// Command summary from operator.
    pub command_summary: String,
    /// Standard output summary.
    pub stdout_summary: String,
    /// Standard error summary.
    pub stderr_summary: String,
    /// Reason explaining the capture decision.
    pub reason: String,
    /// Whether an execution was attempted (always false in I-17 normal build).
    pub attempted: bool,
    /// Whether a reader was started (always false in I-17 normal build).
    pub reader_started: bool,
    /// Whether a reader completed (always false in I-17 normal build).
    pub reader_completed: bool,
    /// Whether cleanup is required.
    pub cleanup_required: bool,
    /// Whether cleanup has been completed.
    pub cleanup_completed: bool,
    /// Whether post-run evidence capture is required.
    pub post_run_evidence_required: bool,
    /// Whether post-run evidence was captured.
    pub post_run_evidence_captured: bool,
    /// Number of events read (always 0 in I-17 normal build).
    pub events_read: usize,
    /// Number of decode errors (always 0 in I-17 normal build).
    pub decode_errors: usize,
    /// Number of bridge records (always 0 in I-17 normal build).
    pub bridge_records: usize,
    /// Duration in milliseconds (None if not run).
    pub duration_ms: Option<u64>,
    /// Safety notes for this capture.
    pub safety_notes: Vec<String>,
    /// Recommendation for next steps.
    pub recommendation: EbpfEventStreamReaderSpikeRecommendation,
    /// Whether public CLI was exposed (always false in I-17).
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened (always false in I-17).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-17).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-17).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-17).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false in I-17).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false in I-17).
    pub mutation_performed: bool,
    /// Whether file write was performed (always false in I-17).
    pub persistence_performed: bool,
    /// Whether fake reader success was detected.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected.
    pub fake_live_event_counts_detected: bool,
}

/// Summary of multiple reader spike result captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeResultSummary {
    /// The phase this summary covers.
    pub phase: String,
    /// The individual captures.
    pub captures: Vec<EbpfEventStreamReaderSpikeResultCapture>,
    /// Total number of captures.
    pub total_captures: usize,
    /// Count of NotRun captures.
    pub not_run_count: usize,
    /// Count of FeatureDisabled captures.
    pub feature_disabled_count: usize,
    /// Count of PrepRejected captures.
    pub prep_rejected_count: usize,
    /// Count of ExecutorDisabled captures.
    pub executor_disabled_count: usize,
    /// Count of ReaderNotImplemented captures.
    pub reader_not_implemented_count: usize,
    /// Count of FutureExecutionReady captures.
    pub future_execution_ready_count: usize,
    /// Count of ExecutionAttempted captures.
    pub execution_attempted_count: usize,
    /// Count of ExecutionSucceeded captures.
    pub execution_succeeded_count: usize,
    /// Count of ExecutionFailed captures.
    pub execution_failed_count: usize,
    /// Count of CleanupRequired captures.
    pub cleanup_required_count: usize,
    /// Count of CleanupCompleted captures.
    pub cleanup_completed_count: usize,
    /// Count of CleanupFailed captures.
    pub cleanup_failed_count: usize,
    /// Count of InvalidCapture captures.
    pub invalid_capture_count: usize,
    /// Whether ready for reader spike review.
    pub ready_for_reader_spike_review: bool,
    /// Summary-level status (dominant or most significant).
    pub summary_status: EbpfEventStreamReaderSpikeResultStatus,
    /// Summary-level recommendation.
    pub recommendation: EbpfEventStreamReaderSpikeRecommendation,
    /// Whether public CLI was exposed in any capture.
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened in any capture.
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read in any capture.
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed in any capture.
    pub map_pin_performed: bool,
    /// Whether enforcement was performed in any capture.
    pub enforcement_performed: bool,
    /// Whether packet drop was performed in any capture.
    pub packet_drop_performed: bool,
    /// Whether mutation was performed in any capture.
    pub mutation_performed: bool,
    /// Whether file write was performed in any capture.
    pub persistence_performed: bool,
    /// Whether fake reader success was detected in any capture.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected in any capture.
    pub fake_live_event_counts_detected: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

fn safe_base_capture() -> EbpfEventStreamReaderSpikeResultCapture {
    let exec_res =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::evaluate_event_stream_reader_spike_executor(
            &crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::default_event_stream_reader_spike_executor_input(),
        );
    let audit_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::default_event_stream_reader_spike_executor_audit_input();
    let audit_report =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::evaluate_event_stream_reader_spike_executor_audit(&audit_input);
    EbpfEventStreamReaderSpikeResultCapture {
        capture_id: String::from("i17-default"),
        phase: String::from("I-17"),
        operator_label: String::new(),
        feature_name: String::from("intergalaxion-event-stream-lab"),
        feature_enabled: false,
        local_lab_only: true,
        executor_result: exec_res,
        executor_audit_report: audit_report,
        result_status: EbpfEventStreamReaderSpikeResultStatus::NotRun,
        evidence_level: EbpfEventStreamReaderSpikeEvidenceLevel::None,
        command_summary: String::new(),
        stdout_summary: String::new(),
        stderr_summary: String::new(),
        reason: String::from("default capture is not run"),
        attempted: false,
        reader_started: false,
        reader_completed: false,
        cleanup_required: false,
        cleanup_completed: false,
        post_run_evidence_required: false,
        post_run_evidence_captured: false,
        events_read: 0,
        decode_errors: 0,
        bridge_records: 0,
        duration_ms: None,
        safety_notes: Vec::new(),
        recommendation: EbpfEventStreamReaderSpikeRecommendation::Stop,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        fake_reader_success_detected: false,
        fake_live_event_counts_detected: false,
    }
}

/// Create the default reader spike result capture.
///
/// Phase is I-17. Status is NotRun. All operation flags are false.
/// Evidence level is None. Recommendation is Stop.
pub fn default_event_stream_reader_spike_result_capture() -> EbpfEventStreamReaderSpikeResultCapture
{
    safe_base_capture()
}

/// Capture the result of a local reader spike from executor result and audit.
///
/// Maps the executor status to the appropriate result capture status.
/// Detects inconsistencies, fake reader success, fake live event counts,
/// and sets recommendation accordingly.
pub fn capture_event_stream_reader_spike_result(
    executor_result: EbpfEventStreamReaderSpikeExecutorResult,
    executor_audit_report: EbpfEventStreamReaderSpikeExecutorAuditReport,
    operator_label: &str,
    command_summary: &str,
) -> EbpfEventStreamReaderSpikeResultCapture {
    let mut capture = safe_base_capture();
    capture.executor_result = executor_result.clone();
    capture.executor_audit_report = executor_audit_report.clone();
    capture.operator_label = String::from(operator_label);
    capture.command_summary = String::from(command_summary);
    capture.feature_enabled = executor_result.feature_enabled;
    capture.attempted = executor_result.attempted;
    capture.reader_started = executor_result.reader_started;
    capture.reader_completed = executor_result.reader_completed;
    capture.cleanup_required = executor_result.cleanup_required;
    capture.cleanup_completed = executor_result.cleanup_completed;
    capture.post_run_evidence_required = executor_result.post_run_evidence_required;
    capture.post_run_evidence_captured = executor_result.post_run_evidence_captured;
    capture.events_read = executor_result.events_read;
    capture.decode_errors = executor_result.decode_errors;
    capture.bridge_records = executor_result.bridge_records;
    capture.public_cli_exposed =
        executor_result.public_cli_exposed || executor_audit_report.public_cli_exposed;
    capture.ring_buffer_opened =
        executor_result.ring_buffer_opened || executor_audit_report.ring_buffer_opened;
    capture.live_event_stream_read =
        executor_result.live_event_stream_read || executor_audit_report.live_event_stream_read;
    capture.map_pin_performed =
        executor_result.map_pin_performed || executor_audit_report.map_pin_performed;
    capture.enforcement_performed =
        executor_result.enforcement_performed || executor_audit_report.enforcement_performed;
    capture.packet_drop_performed =
        executor_result.packet_drop_performed || executor_audit_report.packet_drop_performed;
    capture.mutation_performed =
        executor_result.mutation_performed || executor_audit_report.mutation_performed;
    capture.persistence_performed =
        executor_result.persistence_performed || executor_audit_report.persistence_performed;
    capture.fake_reader_success_detected = executor_audit_report.fake_reader_success_detected;
    capture.fake_live_event_counts_detected = executor_audit_report.fake_live_event_counts_detected;

    // Determine result_status from executor status
    capture.result_status = map_executor_to_capture_status(&executor_result, &mut capture);

    // Set evidence level
    capture.evidence_level = determine_evidence_level(&capture);

    // Set recommendation
    capture.recommendation = determine_recommendation(&capture);

    capture
}

fn map_executor_to_capture_status(
    er: &EbpfEventStreamReaderSpikeExecutorResult,
    capture: &mut EbpfEventStreamReaderSpikeResultCapture,
) -> EbpfEventStreamReaderSpikeResultStatus {
    match er.status {
        EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled => {
            capture.reason = String::from("feature is disabled");
            EbpfEventStreamReaderSpikeResultStatus::FeatureDisabled
        }
        EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected => {
            capture.reason = String::from("preparation was rejected");
            EbpfEventStreamReaderSpikeResultStatus::PrepRejected
        }
        EbpfEventStreamReaderSpikeExecutorStatus::ExecutorDisabled => {
            capture.reason = String::from("executor is disabled");
            EbpfEventStreamReaderSpikeResultStatus::ExecutorDisabled
        }
        EbpfEventStreamReaderSpikeExecutorStatus::ReaderNotImplemented => {
            capture.reason = String::from("reader is not implemented");
            EbpfEventStreamReaderSpikeResultStatus::ReaderNotImplemented
        }
        EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady => {
            // Validate: must not have execution flags
            if er.attempted {
                capture.fake_reader_success_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with attempted=true is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.reader_started {
                capture.fake_reader_success_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with reader_started=true is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.reader_completed {
                capture.fake_reader_success_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with reader_completed=true is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.events_read > 0 {
                capture.fake_live_event_counts_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with events_read>0 is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.decode_errors > 0 {
                capture.fake_live_event_counts_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with decode_errors>0 is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.bridge_records > 0 {
                capture.fake_live_event_counts_detected = true;
                capture.reason =
                    String::from("FutureExecutionReady with bridge_records>0 is inconsistent");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            capture.reason = String::from("all gates pass; future execution is ready");
            EbpfEventStreamReaderSpikeResultStatus::FutureExecutionReady
        }
        EbpfEventStreamReaderSpikeExecutorStatus::ExecutionAttempted => {
            if !er.attempted {
                capture.fake_reader_success_detected = true;
                capture.reason = String::from("ExecutionAttempted requires attempted=true");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            capture.reason = String::from("execution was attempted");
            EbpfEventStreamReaderSpikeResultStatus::ExecutionAttempted
        }
        EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded => {
            // Must be internally consistent
            if !er.attempted || !er.reader_started || !er.reader_completed {
                capture.fake_reader_success_detected = true;
                capture.reason = String::from(
                    "ExecutionSucceeded requires attempted, reader_started, and reader_completed",
                );
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            if er.events_read > 0 && !er.live_event_stream_read {
                capture.fake_live_event_counts_detected = true;
                capture.reason = String::from(
                    "ExecutionSucceeded with events_read>0 requires live_event_stream_read=true",
                );
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            capture.reason = String::from("execution succeeded (captured status only)");
            EbpfEventStreamReaderSpikeResultStatus::ExecutionSucceeded
        }
        EbpfEventStreamReaderSpikeExecutorStatus::ExecutionFailed => {
            if !er.attempted {
                capture.fake_reader_success_detected = true;
                capture.reason = String::from("ExecutionFailed requires attempted=true");
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            capture.reason = String::from("execution failed");
            EbpfEventStreamReaderSpikeResultStatus::ExecutionFailed
        }
        EbpfEventStreamReaderSpikeExecutorStatus::CleanupRequired => {
            capture.reason = String::from("cleanup is required");
            EbpfEventStreamReaderSpikeResultStatus::CleanupRequired
        }
        EbpfEventStreamReaderSpikeExecutorStatus::CleanupCompleted => {
            if !er.cleanup_required || !er.cleanup_completed {
                capture.reason = String::from(
                    "CleanupCompleted requires cleanup_required and cleanup_completed",
                );
                return EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
            }
            capture.reason = String::from("cleanup completed");
            EbpfEventStreamReaderSpikeResultStatus::CleanupCompleted
        }
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked => {
            capture.reason = String::from("executor was blocked by a hard safety gate");
            EbpfEventStreamReaderSpikeResultStatus::InvalidCapture
        }
    }
}

fn determine_evidence_level(
    c: &EbpfEventStreamReaderSpikeResultCapture,
) -> EbpfEventStreamReaderSpikeEvidenceLevel {
    if c.fake_reader_success_detected || c.fake_live_event_counts_detected {
        return EbpfEventStreamReaderSpikeEvidenceLevel::None;
    }
    if c.public_cli_exposed
        || c.enforcement_performed
        || c.packet_drop_performed
        || c.mutation_performed
        || c.persistence_performed
        || c.map_pin_performed
    {
        return EbpfEventStreamReaderSpikeEvidenceLevel::None;
    }
    if !c.command_summary.is_empty()
        && c.evidence_level == EbpfEventStreamReaderSpikeEvidenceLevel::None
    {
        return EbpfEventStreamReaderSpikeEvidenceLevel::OperatorReported;
    }
    if c.post_run_evidence_captured && c.cleanup_completed {
        return EbpfEventStreamReaderSpikeEvidenceLevel::CleanupEvidenceCaptured;
    }
    if !c.executor_result.reason.is_empty() {
        return EbpfEventStreamReaderSpikeEvidenceLevel::ExecutorResultCaptured;
    }
    EbpfEventStreamReaderSpikeEvidenceLevel::None
}

fn determine_recommendation(
    c: &EbpfEventStreamReaderSpikeResultCapture,
) -> EbpfEventStreamReaderSpikeRecommendation {
    if c.fake_reader_success_detected
        || c.fake_live_event_counts_detected
        || c.public_cli_exposed
        || c.enforcement_performed
        || c.packet_drop_performed
        || c.mutation_performed
        || c.persistence_performed
        || c.map_pin_performed
    {
        return EbpfEventStreamReaderSpikeRecommendation::Stop;
    }
    match c.result_status {
        EbpfEventStreamReaderSpikeResultStatus::InvalidCapture => {
            EbpfEventStreamReaderSpikeRecommendation::FixExecutor
        }
        EbpfEventStreamReaderSpikeResultStatus::NotRun => {
            EbpfEventStreamReaderSpikeRecommendation::Stop
        }
        EbpfEventStreamReaderSpikeResultStatus::FeatureDisabled => {
            EbpfEventStreamReaderSpikeRecommendation::Stop
        }
        EbpfEventStreamReaderSpikeResultStatus::PrepRejected => {
            EbpfEventStreamReaderSpikeRecommendation::FixPreparation
        }
        EbpfEventStreamReaderSpikeResultStatus::ExecutorDisabled => {
            EbpfEventStreamReaderSpikeRecommendation::FixExecutor
        }
        EbpfEventStreamReaderSpikeResultStatus::ReaderNotImplemented => {
            EbpfEventStreamReaderSpikeRecommendation::FixExecutor
        }
        EbpfEventStreamReaderSpikeResultStatus::FutureExecutionReady => {
            EbpfEventStreamReaderSpikeRecommendation::ReadyForReaderSpikeReview
        }
        EbpfEventStreamReaderSpikeResultStatus::ExecutionAttempted => {
            EbpfEventStreamReaderSpikeRecommendation::CaptureCleanupEvidence
        }
        EbpfEventStreamReaderSpikeResultStatus::ExecutionSucceeded => {
            EbpfEventStreamReaderSpikeRecommendation::CaptureCleanupEvidence
        }
        EbpfEventStreamReaderSpikeResultStatus::ExecutionFailed => {
            EbpfEventStreamReaderSpikeRecommendation::RetryLocalLab
        }
        EbpfEventStreamReaderSpikeResultStatus::CleanupRequired => {
            EbpfEventStreamReaderSpikeRecommendation::CaptureCleanupEvidence
        }
        EbpfEventStreamReaderSpikeResultStatus::CleanupCompleted => {
            EbpfEventStreamReaderSpikeRecommendation::ReadyForReaderSpikeReview
        }
        EbpfEventStreamReaderSpikeResultStatus::CleanupFailed => {
            EbpfEventStreamReaderSpikeRecommendation::RetryLocalLab
        }
    }
}

/// Summarize multiple reader spike result captures.
///
/// Counts statuses deterministically and computes the summary-level status
/// and recommendation.
pub fn summarize_event_stream_reader_spike_results(
    captures: &[EbpfEventStreamReaderSpikeResultCapture],
) -> EbpfEventStreamReaderSpikeResultSummary {
    let mut summary = EbpfEventStreamReaderSpikeResultSummary {
        phase: String::from("I-17"),
        captures: captures.to_vec(),
        total_captures: captures.len(),
        not_run_count: 0,
        feature_disabled_count: 0,
        prep_rejected_count: 0,
        executor_disabled_count: 0,
        reader_not_implemented_count: 0,
        future_execution_ready_count: 0,
        execution_attempted_count: 0,
        execution_succeeded_count: 0,
        execution_failed_count: 0,
        cleanup_required_count: 0,
        cleanup_completed_count: 0,
        cleanup_failed_count: 0,
        invalid_capture_count: 0,
        ready_for_reader_spike_review: false,
        summary_status: EbpfEventStreamReaderSpikeResultStatus::NotRun,
        recommendation: EbpfEventStreamReaderSpikeRecommendation::Stop,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        fake_reader_success_detected: false,
        fake_live_event_counts_detected: false,
    };
    for c in captures {
        match c.result_status {
            EbpfEventStreamReaderSpikeResultStatus::NotRun => summary.not_run_count += 1,
            EbpfEventStreamReaderSpikeResultStatus::FeatureDisabled => {
                summary.feature_disabled_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::PrepRejected => {
                summary.prep_rejected_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::ExecutorDisabled => {
                summary.executor_disabled_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::ReaderNotImplemented => {
                summary.reader_not_implemented_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::FutureExecutionReady => {
                summary.future_execution_ready_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::ExecutionAttempted => {
                summary.execution_attempted_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::ExecutionSucceeded => {
                summary.execution_succeeded_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::ExecutionFailed => {
                summary.execution_failed_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::CleanupRequired => {
                summary.cleanup_required_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::CleanupCompleted => {
                summary.cleanup_completed_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::CleanupFailed => {
                summary.cleanup_failed_count += 1
            }
            EbpfEventStreamReaderSpikeResultStatus::InvalidCapture => {
                summary.invalid_capture_count += 1
            }
        }
        // Aggregate safety flags
        if c.public_cli_exposed {
            summary.public_cli_exposed = true;
        }
        if c.ring_buffer_opened {
            summary.ring_buffer_opened = true;
        }
        if c.live_event_stream_read {
            summary.live_event_stream_read = true;
        }
        if c.map_pin_performed {
            summary.map_pin_performed = true;
        }
        if c.enforcement_performed {
            summary.enforcement_performed = true;
        }
        if c.packet_drop_performed {
            summary.packet_drop_performed = true;
        }
        if c.mutation_performed {
            summary.mutation_performed = true;
        }
        if c.persistence_performed {
            summary.persistence_performed = true;
        }
        if c.fake_reader_success_detected {
            summary.fake_reader_success_detected = true;
        }
        if c.fake_live_event_counts_detected {
            summary.fake_live_event_counts_detected = true;
        }
    }

    // Determine summary_status: most significant status present
    if summary.invalid_capture_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::InvalidCapture;
    } else if summary.execution_failed_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::ExecutionFailed;
    } else if summary.cleanup_required_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::CleanupRequired;
    } else if summary.cleanup_completed_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::CleanupCompleted;
    } else if summary.future_execution_ready_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::FutureExecutionReady;
    } else if summary.prep_rejected_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::PrepRejected;
    } else if summary.executor_disabled_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::ExecutorDisabled;
    } else if summary.feature_disabled_count > 0 {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::FeatureDisabled;
    } else {
        summary.summary_status = EbpfEventStreamReaderSpikeResultStatus::NotRun;
    }

    // Determine recommendation
    if summary.fake_reader_success_detected
        || summary.fake_live_event_counts_detected
        || summary.public_cli_exposed
        || summary.enforcement_performed
        || summary.packet_drop_performed
        || summary.mutation_performed
        || summary.persistence_performed
        || summary.map_pin_performed
    {
        summary.recommendation = EbpfEventStreamReaderSpikeRecommendation::Stop;
    } else if summary.invalid_capture_count > 0 {
        summary.recommendation = EbpfEventStreamReaderSpikeRecommendation::FixExecutor;
    } else if summary.prep_rejected_count > 0 {
        summary.recommendation = EbpfEventStreamReaderSpikeRecommendation::FixPreparation;
    } else {
        summary.recommendation = EbpfEventStreamReaderSpikeRecommendation::Stop;
    }

    // ready_for_reader_spike_review: at least one FutureExecutionReady or
    // CleanupCompleted and no invalid/fake/safety flags
    summary.ready_for_reader_spike_review = (summary.future_execution_ready_count > 0
        || summary.cleanup_completed_count > 0)
        && summary.invalid_capture_count == 0
        && !summary.fake_reader_success_detected
        && !summary.fake_live_event_counts_detected
        && !summary.public_cli_exposed
        && !summary.enforcement_performed
        && !summary.packet_drop_performed
        && !summary.mutation_performed
        && !summary.persistence_performed
        && !summary.map_pin_performed;

    summary
}

/// Validate that a reader spike result capture does not have any unsafe
/// or inconsistent flags.
///
/// Returns `Ok(())` if the capture is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_reader_spike_result_capture(
    capture: &EbpfEventStreamReaderSpikeResultCapture,
) -> Result<(), String> {
    if capture.capture_id.is_empty() {
        return Err("capture_id must not be empty".to_string());
    }
    if capture.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if !capture.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    if capture.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if capture.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if capture.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if capture.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if capture.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if capture.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if capture.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if capture.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if capture.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if capture.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if capture.events_read > 0 && !capture.live_event_stream_read {
        return Err("events_read>0 requires live_event_stream_read=true".to_string());
    }
    if capture.decode_errors > 0 && !capture.attempted {
        return Err("decode_errors>0 requires attempted=true".to_string());
    }
    if capture.bridge_records > 0 && !capture.attempted {
        return Err("bridge_records>0 requires attempted=true".to_string());
    }
    Ok(())
}

/// Validate that a reader spike result summary does not have any unsafe
/// or inconsistent state.
///
/// Returns `Ok(())` if the summary is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_reader_spike_result_summary(
    summary: &EbpfEventStreamReaderSpikeResultSummary,
) -> Result<(), String> {
    if summary.public_cli_exposed {
        return Err("summary public_cli_exposed must be false".to_string());
    }
    if summary.map_pin_performed {
        return Err("summary map_pin_performed must be false".to_string());
    }
    if summary.enforcement_performed {
        return Err("summary enforcement_performed must be false".to_string());
    }
    if summary.packet_drop_performed {
        return Err("summary packet_drop_performed must be false".to_string());
    }
    if summary.mutation_performed {
        return Err("summary mutation_performed must be false".to_string());
    }
    if summary.persistence_performed {
        return Err("summary persistence_performed must be false".to_string());
    }
    // Ring buffer and live event read only valid if a capture is
    // ExecutionSucceeded with attempted=true
    if summary.ring_buffer_opened {
        let valid = summary.captures.iter().any(|c| {
            c.result_status == EbpfEventStreamReaderSpikeResultStatus::ExecutionSucceeded
                && c.attempted
        });
        if !valid {
            return Err(
                "summary ring_buffer_opened requires ExecutionSucceeded with attempted=true"
                    .to_string(),
            );
        }
    }
    if summary.live_event_stream_read {
        let valid = summary.captures.iter().any(|c| {
            c.result_status == EbpfEventStreamReaderSpikeResultStatus::ExecutionSucceeded
                && c.attempted
        });
        if !valid {
            return Err(
                "summary live_event_stream_read requires ExecutionSucceeded with attempted=true"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Map a reader spike result status to a stable human-readable label.
pub fn event_stream_reader_spike_result_status_label(
    status: EbpfEventStreamReaderSpikeResultStatus,
) -> &'static str {
    status.as_str()
}

/// Map a reader spike evidence level to a stable human-readable label.
pub fn event_stream_reader_spike_evidence_level_label(
    level: EbpfEventStreamReaderSpikeEvidenceLevel,
) -> &'static str {
    level.as_str()
}

/// Map a reader spike recommendation to a stable human-readable label.
pub fn event_stream_reader_spike_recommendation_label(
    recommendation: EbpfEventStreamReaderSpikeRecommendation,
) -> &'static str {
    recommendation.as_str()
}
