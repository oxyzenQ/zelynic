// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Feature-gated local reader spike preparation for the Intergalaxion Engine.
//!
//! Phase I-15A adds a preparation-only model for a future local reader spike.
//! This phase does NOT open ring buffers, NOT read live kernel events, NOT
//! start the event stream reader, NOT expose public CLI, NOT add enforcement,
//! NOT fake reader readiness. It defines the preparation contract, operator
//! checklist, abort conditions, timeout/event limits, and evidence requirements
//! needed before a future feature-gated event stream reader spike.
//!
//! # Design constraints (I-15A)
//!
//! * Preparation-only — not a live reader, not a ring buffer reader.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake preparation readiness.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.
//! * Audit readiness from I-15 evidence audit is required.

use crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::{
    validate_event_stream_evidence_audit_report, EbpfEventStreamEvidenceAuditReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderInput;

/// Status of the event stream reader spike preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikePrepStatus {
    /// Preparation is disabled.
    Disabled,
    /// I-15 evidence audit is not ready.
    AuditNotReady,
    /// Operator consent is missing.
    MissingOperatorConsent,
    /// Event/timeout limits are invalid.
    InvalidLimits,
    /// All preparation gates pass; ready for future spike.
    PrepReady,
    /// Preparation was rejected due to unsafe configuration.
    PrepRejected,
    /// Live reader is not supported in I-15A.
    LiveReaderUnsupported,
    /// Preparation is blocked by a hard safety gate.
    Blocked,
}

impl EbpfEventStreamReaderSpikePrepStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AuditNotReady => "audit_not_ready",
            Self::MissingOperatorConsent => "missing_operator_consent",
            Self::InvalidLimits => "invalid_limits",
            Self::PrepReady => "prep_ready",
            Self::PrepRejected => "prep_rejected",
            Self::LiveReaderUnsupported => "live_reader_unsupported",
            Self::Blocked => "blocked",
        }
    }
}

/// Kind of preparation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikePrepStepKind {
    /// Review I-15 evidence audit report.
    AuditReview,
    /// Obtain operator consent.
    OperatorConsent,
    /// Verify Cargo feature gate.
    FeatureGateCheck,
    /// Review reader target configuration.
    ReaderTargetReview,
    /// Review event/timeout limits.
    LimitReview,
    /// Review abort conditions.
    AbortConditionReview,
    /// Review cleanup plan.
    CleanupReview,
    /// Plan post-run evidence capture.
    PostRunEvidencePlan,
}

impl EbpfEventStreamReaderSpikePrepStepKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditReview => "audit_review",
            Self::OperatorConsent => "operator_consent",
            Self::FeatureGateCheck => "feature_gate_check",
            Self::ReaderTargetReview => "reader_target_review",
            Self::LimitReview => "limit_review",
            Self::AbortConditionReview => "abort_condition_review",
            Self::CleanupReview => "cleanup_review",
            Self::PostRunEvidencePlan => "post_run_evidence_plan",
        }
    }
}

/// A single preparation step in the reader spike checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikePrepStep {
    /// Unique step identifier.
    pub step_id: String,
    /// The kind of preparation step.
    pub kind: EbpfEventStreamReaderSpikePrepStepKind,
    /// Human-readable step title.
    pub title: String,
    /// Whether this step is required.
    pub required: bool,
    /// Whether this step was completed.
    pub completed: bool,
    /// Whether this step is manual-only.
    pub manual_only: bool,
    /// Human-readable step description.
    pub description: String,
}

/// An abort condition for the reader spike preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikePrepAbortCondition {
    /// Machine-readable abort condition code.
    pub code: String,
    /// Human-readable abort condition description.
    pub description: String,
    /// Whether this condition is blocking.
    pub blocking: bool,
}

/// Input to the reader spike preparation evaluation.
///
/// Combines the I-15 evidence audit report, I-12 reader input, explicit
/// consent, operator label, feature gate, and safety flags. The evaluator
/// is pure and deterministic — no live kernel operations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikePrepInput {
    /// The I-15 evidence audit report.
    pub audit_report: EbpfEventStreamEvidenceAuditReport,
    /// The I-12 event stream reader input (informational).
    pub reader_input: EbpfEventStreamReaderInput,
    /// Whether explicit reader spike prep consent is given.
    pub explicit_reader_spike_prep_consent: bool,
    /// Operator label for audit trail.
    pub explicit_operator_label: String,
    /// The Cargo feature name for the spike.
    pub feature_name: String,
    /// Whether the feature is expected to be disabled by default.
    pub feature_expected_disabled_by_default: bool,
    /// Whether this is local lab only.
    pub local_lab_only: bool,
    /// Maximum events to read in the future spike.
    pub max_events: usize,
    /// Timeout in milliseconds for the future spike.
    pub timeout_ms: u64,
    /// Whether clean shutdown is required.
    pub require_clean_shutdown: bool,
    /// Whether post-run evidence capture is required.
    pub require_post_run_evidence_capture: bool,
    /// Whether public CLI is requested (must be false).
    pub public_cli_requested: bool,
    /// Whether live reader is allowed (must be false in I-15A).
    pub allow_live_reader: bool,
    /// Whether ring buffer open is allowed (must be false in I-15A).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is allowed (must be false in I-15A).
    pub allow_live_event_read: bool,
    /// Whether map pin is allowed (must be false).
    pub allow_map_pin: bool,
    /// Whether file write is allowed (must be false).
    pub allow_persistence: bool,
    /// Whether enforcement is allowed (must be false).
    pub allow_enforcement: bool,
    /// Whether packet drop is allowed (must be false).
    pub allow_packet_drop: bool,
}

/// Plan produced by the reader spike preparation evaluation.
///
/// All operation flags are always false in I-15A. The plan is pure and
/// deterministic. No ring buffer is opened, no live events are read,
/// no maps are pinned, no enforcement occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikePrepPlan {
    /// The determined preparation status.
    pub status: EbpfEventStreamReaderSpikePrepStatus,
    /// The phase this plan covers.
    pub phase: String,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// The Cargo feature name.
    pub feature_name: String,
    /// Whether this is local lab only.
    pub local_lab_only: bool,
    /// Whether all preparation gates pass.
    pub prep_ready: bool,
    /// The preparation checklist steps.
    pub steps: Vec<EbpfEventStreamReaderSpikePrepStep>,
    /// The abort conditions.
    pub abort_conditions: Vec<EbpfEventStreamReaderSpikePrepAbortCondition>,
    /// Maximum events for the future spike.
    pub max_events: usize,
    /// Timeout in milliseconds for the future spike.
    pub timeout_ms: u64,
    /// Whether clean shutdown is required.
    pub require_clean_shutdown: bool,
    /// Whether post-run evidence capture is required.
    pub require_post_run_evidence_capture: bool,
    /// Reason explaining the preparation decision.
    pub reason: String,
    /// Whether public CLI was exposed (always false in I-15A).
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened (always false in I-15A).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-15A).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-15A).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-15A).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false in I-15A).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false in I-15A).
    pub mutation_performed: bool,
    /// Whether file write was performed (always false in I-15A).
    pub persistence_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default reader spike preparation input.
///
/// All fields are in their safest configuration: audit report from
/// defaults, no consent, no unsafe flags set. The default input
/// is safe but not ready for preparation.
pub fn default_event_stream_reader_spike_prep_input() -> EbpfEventStreamReaderSpikePrepInput {
    let audit_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::default_event_stream_evidence_audit_input();
    let audit_report =
        crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::evaluate_event_stream_evidence_audit(&audit_input);
    let reader_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    EbpfEventStreamReaderSpikePrepInput {
        audit_report,
        reader_input,
        explicit_reader_spike_prep_consent: false,
        explicit_operator_label: String::new(),
        feature_name: String::new(),
        feature_expected_disabled_by_default: true,
        local_lab_only: true,
        max_events: 0,
        timeout_ms: 0,
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

/// Build deterministic required preparation steps.
fn build_required_steps() -> Vec<EbpfEventStreamReaderSpikePrepStep> {
    vec![
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-1-audit-review"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::AuditReview,
            title: String::from("Review I-15 Evidence Audit"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Verify that the I-15 evidence audit report indicates readiness for reader spike preparation",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-2-operator-consent"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::OperatorConsent,
            title: String::from("Obtain Operator Consent"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Confirm explicit operator consent with a non-empty label for the reader spike",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-3-feature-gate-check"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::FeatureGateCheck,
            title: String::from("Verify Feature Gate"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Confirm the Cargo feature is named, non-empty, and disabled by default",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-4-reader-target-review"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::ReaderTargetReview,
            title: String::from("Review Reader Target"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Review the reader target configuration and ensure it is consistent with the read plan",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-5-limit-review"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::LimitReview,
            title: String::from("Review Event and Timeout Limits"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Confirm max_events is in range [1, 1024] and timeout_ms is in range [1, 60000]",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-6-abort-condition-review"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::AbortConditionReview,
            title: String::from("Review Abort Conditions"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Review and acknowledge all blocking abort conditions for the reader spike",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-7-cleanup-review"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::CleanupReview,
            title: String::from("Review Cleanup Plan"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Confirm clean shutdown is required and no residual state will remain after the spike",
            ),
        },
        EbpfEventStreamReaderSpikePrepStep {
            step_id: String::from("step-8-evidence-plan"),
            kind: EbpfEventStreamReaderSpikePrepStepKind::PostRunEvidencePlan,
            title: String::from("Plan Post-Run Evidence Capture"),
            required: true,
            completed: false,
            manual_only: true,
            description: String::from(
                "Plan how post-run evidence will be captured and validated after the spike completes",
            ),
        },
    ]
}

/// Build deterministic blocking abort conditions.
fn build_abort_conditions() -> Vec<EbpfEventStreamReaderSpikePrepAbortCondition> {
    vec![
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-ring-buffer-open"),
            description: String::from("ring buffer must not be opened during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-live-event-read"),
            description: String::from("live kernel event read must not occur during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-map-pin"),
            description: String::from("map pin must not be performed during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-enforcement"),
            description: String::from("enforcement must not be performed during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-packet-drop"),
            description: String::from("packet drop must not be performed during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-public-cli"),
            description: String::from("public CLI must not be exposed during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-mutation"),
            description: String::from("kernel mutation must not occur during the spike"),
            blocking: true,
        },
        EbpfEventStreamReaderSpikePrepAbortCondition {
            code: String::from("abort-persistence"),
            description: String::from("file write or storage must not occur during the spike"),
            blocking: true,
        },
    ]
}

/// Build a safe base plan with all operation flags false.
fn safe_base_plan() -> EbpfEventStreamReaderSpikePrepPlan {
    EbpfEventStreamReaderSpikePrepPlan {
        status: EbpfEventStreamReaderSpikePrepStatus::Disabled,
        phase: String::from("I-15A"),
        operator_label: String::new(),
        feature_name: String::new(),
        local_lab_only: true,
        prep_ready: false,
        steps: build_required_steps(),
        abort_conditions: build_abort_conditions(),
        max_events: 0,
        timeout_ms: 0,
        require_clean_shutdown: true,
        require_post_run_evidence_capture: true,
        reason: String::from("reader spike preparation is disabled by default"),
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

/// Evaluate the reader spike preparation from input.
///
/// This function is pure and deterministic. It checks the I-15 evidence
/// audit report, operator consent, feature gate, limits, and safety flags
/// to determine whether preparation for a future reader spike can proceed.
///
/// # Evaluation logic
///
/// 1. **Audit readiness**: `audit_report.ready_for_reader_spike_preparation=false`
///    forces `AuditNotReady`. Also validates the audit report itself.
/// 2. **Explicit consent**: `explicit_reader_spike_prep_consent=false`
///    forces `MissingOperatorConsent`.
/// 3. **Operator label**: Empty label forces `MissingOperatorConsent`.
/// 4. **Feature name**: Empty feature name forces `PrepRejected`.
/// 5. **Feature disabled by default**: `feature_expected_disabled_by_default=false`
///    forces `PrepRejected`.
/// 6. **Local lab only**: `local_lab_only=false` forces `PrepRejected`.
/// 7. **Limit validation**: `max_events=0`, `max_events>1024`,
///    `timeout_ms=0`, `timeout_ms>60000` force `InvalidLimits`.
/// 8. **Clean shutdown**: `require_clean_shutdown=false` forces `PrepRejected`.
/// 9. **Post-run evidence**: `require_post_run_evidence_capture=false`
///    forces `PrepRejected`.
/// 10. **Public CLI**: `public_cli_requested=true` forces `PrepRejected`.
/// 11. **Forbidden flags**: `allow_live_reader=true`, `allow_ring_buffer_open=true`,
///     `allow_live_event_read=true`, `allow_map_pin=true`,
///     `allow_persistence=true`, `allow_enforcement=true`,
///     `allow_packet_drop=true` all force `PrepRejected` or `Blocked`.
/// 12. **PrepReady**: All gates pass. Plan has all operation flags false.
pub fn evaluate_event_stream_reader_spike_prep(
    input: &EbpfEventStreamReaderSpikePrepInput,
) -> EbpfEventStreamReaderSpikePrepPlan {
    let base = safe_base_plan();

    // ── 1. Audit readiness ──────────────────────────────────────────
    if !input.audit_report.ready_for_reader_spike_preparation {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::AuditNotReady,
            reason: String::from(
                "I-15 evidence audit does not indicate readiness for reader spike preparation",
            ),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if validate_event_stream_evidence_audit_report(&input.audit_report).is_err() {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::AuditNotReady,
            reason: String::from("I-15 evidence audit report failed validation"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 2. Explicit consent ─────────────────────────────────────────
    if !input.explicit_reader_spike_prep_consent {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::MissingOperatorConsent,
            reason: String::from("explicit reader spike preparation consent not given"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 3. Operator label required ──────────────────────────────────
    if input.explicit_operator_label.is_empty() {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::MissingOperatorConsent,
            reason: String::from("operator label must not be empty"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 4. Feature name required ───────────────────────────────────
    if input.feature_name.is_empty() {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("feature name must not be empty"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 5. Feature must be disabled by default ─────────────────────
    if !input.feature_expected_disabled_by_default {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("feature must be disabled by default"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 6. Local lab only required ─────────────────────────────────
    if !input.local_lab_only {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("reader spike must be local lab only"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 7. Limit validation ─────────────────────────────────────────
    if input.max_events == 0 {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::InvalidLimits,
            reason: String::from("max_events must be greater than 0"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.max_events > 1024 {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::InvalidLimits,
            reason: String::from("max_events must not exceed 1024"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.timeout_ms == 0 {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::InvalidLimits,
            reason: String::from("timeout_ms must be greater than 0"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.timeout_ms > 60000 {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::InvalidLimits,
            reason: String::from("timeout_ms must not exceed 60000"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 8. Clean shutdown required ───────────────────────────────────
    if !input.require_clean_shutdown {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("clean shutdown is required for reader spike"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 9. Post-run evidence capture required ──────────────────────
    if !input.require_post_run_evidence_capture {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("post-run evidence capture is required for reader spike"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 10. Public CLI rejected ───────────────────────────────────
    if input.public_cli_requested {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::PrepRejected,
            reason: String::from("public CLI must not be exposed in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 11. Forbidden flags (I-15A hard blocks) ────────────────────
    if input.allow_live_reader {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::LiveReaderUnsupported,
            reason: String::from("live reader is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_ring_buffer_open {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("ring buffer open is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_live_event_read {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("live event read is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_map_pin {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("map pin is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_persistence {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("file write is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_enforcement {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("enforcement is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }
    if input.allow_packet_drop {
        return EbpfEventStreamReaderSpikePrepPlan {
            status: EbpfEventStreamReaderSpikePrepStatus::Blocked,
            reason: String::from("packet drop is not supported in I-15A"),
            operator_label: input.explicit_operator_label.clone(),
            feature_name: input.feature_name.clone(),
            local_lab_only: input.local_lab_only,
            ..base
        };
    }

    // ── 12. PrepReady ──────────────────────────────────────────────
    EbpfEventStreamReaderSpikePrepPlan {
        status: EbpfEventStreamReaderSpikePrepStatus::PrepReady,
        phase: String::from("I-15A"),
        operator_label: input.explicit_operator_label.clone(),
        feature_name: input.feature_name.clone(),
        local_lab_only: input.local_lab_only,
        prep_ready: true,
        steps: build_required_steps(),
        abort_conditions: build_abort_conditions(),
        max_events: input.max_events,
        timeout_ms: input.timeout_ms,
        require_clean_shutdown: input.require_clean_shutdown,
        require_post_run_evidence_capture: input.require_post_run_evidence_capture,
        reason: String::from(
            "all preparation gates pass; reader spike is ready for future execution",
        ),
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

/// Validate that a reader spike preparation plan does not have any unsafe
/// or inconsistent flags.
///
/// Returns `Ok(())` if the plan is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
///
/// # Validation rules (I-15A)
///
/// * All safety flags must be false.
/// * `prep_ready=true` requires status `PrepReady`.
/// * Phase must not be empty.
/// * `local_lab_only` must be true.
/// * Steps must not be empty.
/// * Abort conditions must not be empty.
/// * Required steps must have non-empty title and description.
/// * Abort conditions must have non-empty code and description.
pub fn validate_event_stream_reader_spike_prep_plan(
    plan: &EbpfEventStreamReaderSpikePrepPlan,
) -> Result<(), String> {
    // Safety flag checks
    if plan.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-15A".to_string());
    }
    if plan.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-15A".to_string());
    }
    if plan.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-15A".to_string());
    }
    if plan.map_pin_performed {
        return Err("map_pin_performed must be false in I-15A".to_string());
    }
    if plan.enforcement_performed {
        return Err("enforcement_performed must be false in I-15A".to_string());
    }
    if plan.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-15A".to_string());
    }
    if plan.mutation_performed {
        return Err("mutation_performed must be false in I-15A".to_string());
    }
    if plan.persistence_performed {
        return Err("persistence_performed must be false in I-15A".to_string());
    }
    // Structural consistency
    if plan.prep_ready && plan.status != EbpfEventStreamReaderSpikePrepStatus::PrepReady {
        return Err("prep_ready=true requires status PrepReady".to_string());
    }
    if plan.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if !plan.local_lab_only {
        return Err("local_lab_only must be true in I-15A".to_string());
    }
    if plan.steps.is_empty() {
        return Err("steps must not be empty".to_string());
    }
    if plan.abort_conditions.is_empty() {
        return Err("abort_conditions must not be empty".to_string());
    }
    for step in &plan.steps {
        if step.required && step.title.is_empty() {
            return Err("required step must have non-empty title".to_string());
        }
        if step.required && step.description.is_empty() {
            return Err("required step must have non-empty description".to_string());
        }
    }
    for cond in &plan.abort_conditions {
        if cond.code.is_empty() {
            return Err("abort condition must have non-empty code".to_string());
        }
        if cond.description.is_empty() {
            return Err("abort condition must have non-empty description".to_string());
        }
    }
    Ok(())
}

/// Map a reader spike preparation status to a stable human-readable label.
pub fn event_stream_reader_spike_prep_status_label(
    status: EbpfEventStreamReaderSpikePrepStatus,
) -> &'static str {
    status.as_str()
}

/// Map a reader spike preparation step kind to a stable human-readable label.
pub fn event_stream_reader_spike_prep_step_kind_label(
    kind: EbpfEventStreamReaderSpikePrepStepKind,
) -> &'static str {
    kind.as_str()
}
