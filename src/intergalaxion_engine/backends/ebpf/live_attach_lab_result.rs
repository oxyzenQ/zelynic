// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Manual lab result capture for the Intergalaxion Engine.
//!
//! Phase I-10F adds a pure capture-and-validation model for recording the
//! outcome of manually-run local lab attempts. This phase does NOT execute
//! live attach, detach, event reads, ring buffer opens, map pins, or any
//! kernel mutation. It captures what happened as structured data and
//! validates internal consistency of that data.
//!
//! # Design constraints (I-10F)
//!
//! * No actual attach or detach execution.
//! * No ring buffer open.
//! * No live event stream read.
//! * No map pin.
//! * No enforcement or packet drop.
//! * No persistence or ledger file writes.
//! * No public CLI exposure.
//! * No fake attach or detach success.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live attach.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind;
use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::{
    EbpfLiveAttachArtifactContract, EbpfLocalAttachSmokeRecipe,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab::{
    EbpfLiveAttachLabExecutionInput, EbpfLiveAttachLabExecutionResult, EbpfLiveAttachLabStatus,
};

/// Status of a manually-captured local lab result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachManualResultStatus {
    /// No lab run was performed.
    NotRun,
    /// The intergalaxion-live-attach-lab feature was not enabled.
    FeatureDisabled,
    /// The eBPF artifact is missing or unavailable.
    ArtifactMissing,
    /// The attach target kind is not supported.
    UnsupportedTarget,
    /// Gate validation rejected the attempt.
    GateRejected,
    /// Live attach is not yet implemented.
    AttachNotImplemented,
    /// A live attach was attempted.
    AttachAttempted,
    /// A live attach succeeded.
    AttachSucceeded,
    /// A live attach failed.
    AttachFailed,
    /// A detach was attempted.
    DetachAttempted,
    /// Programs were detached cleanly.
    DetachedCleanly,
    /// Detach failed.
    DetachFailed,
    /// The captured data is internally inconsistent.
    InvalidCapture,
}

impl EbpfLiveAttachManualResultStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::FeatureDisabled => "feature_disabled",
            Self::ArtifactMissing => "artifact_missing",
            Self::UnsupportedTarget => "unsupported_target",
            Self::GateRejected => "gate_rejected",
            Self::AttachNotImplemented => "attach_not_implemented",
            Self::AttachAttempted => "attach_attempted",
            Self::AttachSucceeded => "attach_succeeded",
            Self::AttachFailed => "attach_failed",
            Self::DetachAttempted => "detach_attempted",
            Self::DetachedCleanly => "detached_cleanly",
            Self::DetachFailed => "detach_failed",
            Self::InvalidCapture => "invalid_capture",
        }
    }
}

/// Evidence level of a manual lab capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachManualEvidenceLevel {
    /// No evidence captured.
    None,
    /// Operator reported results verbally or in notes.
    OperatorReported,
    /// Command output (stdout/stderr) was captured.
    CommandOutputCaptured,
    /// Detach proof was explicitly captured.
    DetachProofCaptured,
    /// Capture is complete enough for audit review.
    AuditReady,
}

impl EbpfLiveAttachManualEvidenceLevel {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OperatorReported => "operator_reported",
            Self::CommandOutputCaptured => "command_output_captured",
            Self::DetachProofCaptured => "detach_proof_captured",
            Self::AuditReady => "audit_ready",
        }
    }
}

/// Recommendation for next action after a manual lab capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachManualRecommendation {
    /// Stop; do not proceed further.
    Stop,
    /// Fix the artifact before retrying.
    FixArtifact,
    /// Fix gate issues before retrying.
    FixGate,
    /// Retry the local lab.
    RetryLocalLab,
    /// Capture detach proof before proceeding.
    CaptureDetachProof,
    /// Ready to plan event stream reads.
    ReadyForEventStreamPlanning,
}

impl EbpfLiveAttachManualRecommendation {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixArtifact => "fix_artifact",
            Self::FixGate => "fix_gate",
            Self::RetryLocalLab => "retry_local_lab",
            Self::CaptureDetachProof => "capture_detach_proof",
            Self::ReadyForEventStreamPlanning => "ready_for_event_stream_planning",
        }
    }
}

/// Captured result of a manual local lab attach attempt.
///
/// Records operator label, feature state, artifact status, target kind,
/// attach/detach outcomes, evidence, and safety flags. The capture is
/// purely data — it does not execute any live kernel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachManualLabCapture {
    /// Unique identifier for this capture.
    pub capture_id: String,
    /// Phase label for this capture.
    pub phase: String,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// The Cargo feature name.
    pub feature_name: String,
    /// Whether the feature is enabled.
    pub feature_enabled: bool,
    /// Whether this capture is local-lab-only.
    pub local_lab_only: bool,
    /// The attach target kind.
    pub target_kind: EbpfAttachTargetKind,
    /// The artifact contract.
    pub artifact_contract: EbpfLiveAttachArtifactContract,
    /// The smoke recipe.
    pub smoke_recipe: EbpfLocalAttachSmokeRecipe,
    /// The lab execution input.
    pub lab_input: EbpfLiveAttachLabExecutionInput,
    /// The lab execution result.
    pub lab_result: EbpfLiveAttachLabExecutionResult,
    /// The manually-determined result status.
    pub manual_status: EbpfLiveAttachManualResultStatus,
    /// Evidence level of this capture.
    pub evidence_level: EbpfLiveAttachManualEvidenceLevel,
    /// Summary of command output.
    pub command_summary: String,
    /// Summary of stderr output.
    pub stderr_summary: String,
    /// Summary of stdout output.
    pub stdout_summary: String,
    /// Whether attach was attempted.
    pub attach_attempted: bool,
    /// Whether attach succeeded.
    pub attach_succeeded: bool,
    /// Whether detach was attempted.
    pub detach_attempted: bool,
    /// Whether detach was clean.
    pub detached_cleanly: bool,
    /// Duration of the lab attempt in milliseconds.
    pub duration_ms: Option<u64>,
    /// Summary of any errors.
    pub error_summary: String,
    /// Safety notes.
    pub safety_notes: Vec<String>,
    /// Recommendation for next action.
    pub recommendation: EbpfLiveAttachManualRecommendation,
    /// Whether public CLI was exposed.
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened.
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read.
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed.
    pub map_pin_performed: bool,
    /// Whether enforcement was performed.
    pub enforcement_performed: bool,
    /// Whether packet drop was performed.
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed.
    pub mutation_performed: bool,
    /// Whether persistence was performed.
    pub persistence_performed: bool,
}

/// Summary of multiple manual lab captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachManualLabSummary {
    /// Phase label.
    pub phase: String,
    /// All captures in this summary.
    pub captures: Vec<EbpfLiveAttachManualLabCapture>,
    /// Total number of captures.
    pub total_captures: usize,
    /// Number of captures with successful attach.
    pub successful_attach_count: usize,
    /// Number of captures with clean detach.
    pub clean_detach_count: usize,
    /// Number of captures with failed attach.
    pub failed_attach_count: usize,
    /// Number of captures with failed detach.
    pub failed_detach_count: usize,
    /// Number of captures that were not run.
    pub not_run_count: usize,
    /// Whether the lab is ready for event stream planning.
    pub ready_for_event_stream_planning: bool,
    /// Summary-level status.
    pub summary_status: EbpfLiveAttachManualResultStatus,
    /// Summary-level recommendation.
    pub recommendation: EbpfLiveAttachManualRecommendation,
    /// Whether public CLI was exposed.
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened.
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read.
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed.
    pub map_pin_performed: bool,
    /// Whether enforcement was performed.
    pub enforcement_performed: bool,
    /// Whether packet drop was performed.
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed.
    pub mutation_performed: bool,
    /// Whether persistence was performed.
    pub persistence_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default manual lab capture.
///
/// The default capture is NotRun, phase I-10F, local_lab_only=true,
/// with all safety flags false and recommendation Stop.
pub fn default_manual_lab_capture() -> EbpfLiveAttachManualLabCapture {
    use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_live_attach_artifact_contract;
    use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_local_attach_smoke_recipe;
    use crate::intergalaxion_engine::backends::ebpf::live_attach_lab::default_live_attach_lab_execution_input;
    EbpfLiveAttachManualLabCapture {
        capture_id: String::from("default-i10f-capture"),
        phase: String::from("I-10F"),
        operator_label: String::new(),
        feature_name: String::from("intergalaxion-live-attach-lab"),
        feature_enabled: false,
        local_lab_only: true,
        target_kind: EbpfAttachTargetKind::default(),
        artifact_contract: default_live_attach_artifact_contract(),
        smoke_recipe: default_local_attach_smoke_recipe(),
        lab_input: default_live_attach_lab_execution_input(),
        lab_result:
            crate::intergalaxion_engine::backends::ebpf::live_attach_lab::safe_base_result_internal(
            ),
        manual_status: EbpfLiveAttachManualResultStatus::NotRun,
        evidence_level: EbpfLiveAttachManualEvidenceLevel::None,
        command_summary: String::new(),
        stderr_summary: String::new(),
        stdout_summary: String::new(),
        attach_attempted: false,
        attach_succeeded: false,
        detach_attempted: false,
        detached_cleanly: false,
        duration_ms: None,
        error_summary: String::new(),
        safety_notes: Vec::new(),
        recommendation: EbpfLiveAttachManualRecommendation::Stop,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
    }
}

/// Capture a manual lab result from a lab execution result.
///
/// Translates the lab execution result status into a manual capture with
/// the given operator label and command summary. The capture records
/// what happened without performing any live kernel operations.
pub fn capture_manual_lab_result(
    lab_result: EbpfLiveAttachLabExecutionResult,
    operator_label: &str,
    command_summary: &str,
) -> EbpfLiveAttachManualLabCapture {
    use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_live_attach_artifact_contract;
    use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_local_attach_smoke_recipe;
    use crate::intergalaxion_engine::backends::ebpf::live_attach_lab::default_live_attach_lab_execution_input;
    let manual_status = match lab_result.status {
        EbpfLiveAttachLabStatus::FeatureDisabled => {
            EbpfLiveAttachManualResultStatus::FeatureDisabled
        }
        EbpfLiveAttachLabStatus::ArtifactMissing => {
            EbpfLiveAttachManualResultStatus::ArtifactMissing
        }
        EbpfLiveAttachLabStatus::UnsupportedTarget => {
            EbpfLiveAttachManualResultStatus::UnsupportedTarget
        }
        EbpfLiveAttachLabStatus::LabGateRejected => EbpfLiveAttachManualResultStatus::GateRejected,
        EbpfLiveAttachLabStatus::AttachNotImplemented => {
            EbpfLiveAttachManualResultStatus::AttachNotImplemented
        }
        EbpfLiveAttachLabStatus::AttachAttempted => {
            EbpfLiveAttachManualResultStatus::AttachAttempted
        }
        EbpfLiveAttachLabStatus::AttachSucceeded => {
            EbpfLiveAttachManualResultStatus::AttachSucceeded
        }
        EbpfLiveAttachLabStatus::AttachFailed => EbpfLiveAttachManualResultStatus::AttachFailed,
        EbpfLiveAttachLabStatus::DetachedCleanly => {
            EbpfLiveAttachManualResultStatus::DetachedCleanly
        }
        EbpfLiveAttachLabStatus::DetachFailed => EbpfLiveAttachManualResultStatus::DetachFailed,
    };
    let recommendation = match manual_status {
        EbpfLiveAttachManualResultStatus::NotRun => EbpfLiveAttachManualRecommendation::Stop,
        EbpfLiveAttachManualResultStatus::FeatureDisabled => {
            EbpfLiveAttachManualRecommendation::Stop
        }
        EbpfLiveAttachManualResultStatus::ArtifactMissing => {
            EbpfLiveAttachManualRecommendation::FixArtifact
        }
        EbpfLiveAttachManualResultStatus::UnsupportedTarget => {
            EbpfLiveAttachManualRecommendation::Stop
        }
        EbpfLiveAttachManualResultStatus::GateRejected => {
            EbpfLiveAttachManualRecommendation::FixGate
        }
        EbpfLiveAttachManualResultStatus::AttachNotImplemented => {
            EbpfLiveAttachManualRecommendation::Stop
        }
        EbpfLiveAttachManualResultStatus::AttachAttempted => {
            EbpfLiveAttachManualRecommendation::CaptureDetachProof
        }
        EbpfLiveAttachManualResultStatus::AttachSucceeded => {
            EbpfLiveAttachManualRecommendation::CaptureDetachProof
        }
        EbpfLiveAttachManualResultStatus::AttachFailed => {
            EbpfLiveAttachManualRecommendation::RetryLocalLab
        }
        EbpfLiveAttachManualResultStatus::DetachAttempted => {
            EbpfLiveAttachManualRecommendation::CaptureDetachProof
        }
        EbpfLiveAttachManualResultStatus::DetachedCleanly => {
            EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning
        }
        EbpfLiveAttachManualResultStatus::DetachFailed => {
            EbpfLiveAttachManualRecommendation::RetryLocalLab
        }
        EbpfLiveAttachManualResultStatus::InvalidCapture => {
            EbpfLiveAttachManualRecommendation::Stop
        }
    };
    EbpfLiveAttachManualLabCapture {
        capture_id: format!("capture-{}", operator_label),
        phase: String::from("I-10F"),
        operator_label: String::from(operator_label),
        feature_name: String::from("intergalaxion-live-attach-lab"),
        feature_enabled: lab_result.feature_enabled,
        local_lab_only: lab_result.local_lab_only,
        target_kind: EbpfAttachTargetKind::default(),
        artifact_contract: default_live_attach_artifact_contract(),
        smoke_recipe: default_local_attach_smoke_recipe(),
        lab_input: default_live_attach_lab_execution_input(),
        lab_result,
        manual_status,
        evidence_level: EbpfLiveAttachManualEvidenceLevel::OperatorReported,
        command_summary: String::from(command_summary),
        stderr_summary: String::new(),
        stdout_summary: String::new(),
        attach_attempted: false,
        attach_succeeded: false,
        detach_attempted: false,
        detached_cleanly: false,
        duration_ms: None,
        error_summary: String::new(),
        safety_notes: Vec::new(),
        recommendation,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
    }
}

/// Summarize a list of manual lab captures into an aggregate summary.
///
/// The summary counts outcomes, checks for unsafe flags, and determines
/// whether the lab is ready for event stream planning. The summary is
/// deterministic: identical inputs always produce identical outputs.
pub fn summarize_manual_lab_captures(
    captures: &[EbpfLiveAttachManualLabCapture],
) -> EbpfLiveAttachManualLabSummary {
    let total_captures = captures.len();
    let mut successful_attach_count = 0usize;
    let mut clean_detach_count = 0usize;
    let mut failed_attach_count = 0usize;
    let mut failed_detach_count = 0usize;
    let mut not_run_count = 0usize;
    let mut any_unsafe = false;
    let mut best_status = EbpfLiveAttachManualResultStatus::NotRun;
    for c in captures {
        if c.attach_succeeded {
            successful_attach_count += 1;
        }
        if c.detached_cleanly {
            clean_detach_count += 1;
        }
        if c.manual_status == EbpfLiveAttachManualResultStatus::AttachFailed {
            failed_attach_count += 1;
        }
        if c.manual_status == EbpfLiveAttachManualResultStatus::DetachFailed {
            failed_detach_count += 1;
        }
        if c.manual_status == EbpfLiveAttachManualResultStatus::NotRun {
            not_run_count += 1;
        }
        if c.public_cli_exposed
            || c.ring_buffer_opened
            || c.live_event_stream_read
            || c.map_pin_performed
            || c.enforcement_performed
            || c.packet_drop_performed
            || c.mutation_performed
            || c.persistence_performed
        {
            any_unsafe = true;
        }
        // Track the "best" status for summary_status
        if matches!(
            c.manual_status,
            EbpfLiveAttachManualResultStatus::DetachedCleanly
        ) {
            best_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
        } else if best_status == EbpfLiveAttachManualResultStatus::NotRun
            && !matches!(
                c.manual_status,
                EbpfLiveAttachManualResultStatus::NotRun
                    | EbpfLiveAttachManualResultStatus::InvalidCapture
            )
        {
            best_status = c.manual_status;
        }
    }
    let has_clean_detach = clean_detach_count > 0;
    let no_failures = failed_attach_count == 0 && failed_detach_count == 0;
    let ready_for_event_stream_planning = has_clean_detach && no_failures && !any_unsafe;
    let recommendation = if ready_for_event_stream_planning {
        EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning
    } else if any_unsafe || total_captures == 0 {
        EbpfLiveAttachManualRecommendation::Stop
    } else {
        EbpfLiveAttachManualRecommendation::RetryLocalLab
    };
    EbpfLiveAttachManualLabSummary {
        phase: String::from("I-10F"),
        captures: captures.to_vec(),
        total_captures,
        successful_attach_count,
        clean_detach_count,
        failed_attach_count,
        failed_detach_count,
        not_run_count,
        ready_for_event_stream_planning,
        summary_status: best_status,
        recommendation,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
    }
}

/// Validate that a manual lab capture does not have any unsafe or
/// inconsistent flags.
///
/// Returns `Ok(())` if the capture is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_manual_lab_capture(capture: &EbpfLiveAttachManualLabCapture) -> Result<(), String> {
    // Identity and phase checks
    if capture.capture_id.is_empty() {
        return Err("capture_id must not be empty".to_string());
    }
    if capture.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    // Operator label required for non-NotRun captures
    if capture.manual_status != EbpfLiveAttachManualResultStatus::NotRun
        && capture.operator_label.is_empty()
    {
        return Err("operator_label must not be empty for non-NotRun captures".to_string());
    }
    // Local lab only
    if !capture.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    // Unsafe flag checks
    if capture.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if capture.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-10F".to_string());
    }
    if capture.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-10F".to_string());
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
    // Attach/detach consistency
    if capture.manual_status == EbpfLiveAttachManualResultStatus::AttachSucceeded {
        if !capture.attach_attempted {
            return Err("AttachSucceeded requires attach_attempted=true".to_string());
        }
        if !capture.attach_succeeded {
            return Err("AttachSucceeded requires attach_succeeded=true".to_string());
        }
    }
    if capture.manual_status == EbpfLiveAttachManualResultStatus::DetachedCleanly {
        if !capture.attach_succeeded {
            return Err("DetachedCleanly requires attach_succeeded=true".to_string());
        }
        if !capture.detach_attempted {
            return Err("DetachedCleanly requires detach_attempted=true".to_string());
        }
        if !capture.detached_cleanly {
            return Err("DetachedCleanly requires detached_cleanly=true".to_string());
        }
    }
    // ReadyForEventStreamPlanning requires DetachedCleanly and no unsafe flags
    if capture.recommendation == EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning {
        if !capture.detached_cleanly {
            return Err("ReadyForEventStreamPlanning requires detached_cleanly=true".to_string());
        }
        if capture.public_cli_exposed
            || capture.ring_buffer_opened
            || capture.live_event_stream_read
            || capture.map_pin_performed
            || capture.enforcement_performed
            || capture.packet_drop_performed
            || capture.mutation_performed
            || capture.persistence_performed
        {
            return Err("ReadyForEventStreamPlanning requires all unsafe flags false".to_string());
        }
    }
    Ok(())
}

/// Validate that a manual lab summary does not have any unsafe or
/// inconsistent flags.
///
/// Returns `Ok(())` if the summary is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_manual_lab_summary(summary: &EbpfLiveAttachManualLabSummary) -> Result<(), String> {
    // Unsafe flag checks
    if summary.public_cli_exposed {
        return Err("summary public_cli_exposed must be false".to_string());
    }
    if summary.ring_buffer_opened {
        return Err("summary ring_buffer_opened must be false".to_string());
    }
    if summary.live_event_stream_read {
        return Err("summary live_event_stream_read must be false".to_string());
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
    // Consistency: counts must match captures
    if summary.total_captures != summary.captures.len() {
        return Err("total_captures must match captures.len()".to_string());
    }
    // Ready must not be claimed from unsafe states
    if summary.ready_for_event_stream_planning {
        if summary.clean_detach_count == 0 {
            return Err(
                "ready_for_event_stream_planning requires at least one clean detach".to_string(),
            );
        }
        if summary.failed_attach_count > 0 {
            return Err("ready_for_event_stream_planning conflicts with failed attach".to_string());
        }
        if summary.failed_detach_count > 0 {
            return Err("ready_for_event_stream_planning conflicts with failed detach".to_string());
        }
    }
    // Validate individual captures
    for (i, c) in summary.captures.iter().enumerate() {
        if let Err(e) = validate_manual_lab_capture(c) {
            return Err(format!("capture[{}] invalid: {}", i, e));
        }
    }
    Ok(())
}

/// Map a manual result status to a stable human-readable label.
pub fn manual_result_status_label(status: EbpfLiveAttachManualResultStatus) -> &'static str {
    status.as_str()
}

/// Map an evidence level to a stable human-readable label.
pub fn manual_evidence_level_label(level: EbpfLiveAttachManualEvidenceLevel) -> &'static str {
    level.as_str()
}

/// Map a recommendation to a stable human-readable label.
pub fn manual_recommendation_label(
    recommendation: EbpfLiveAttachManualRecommendation,
) -> &'static str {
    recommendation.as_str()
}
