// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Event stream read planning for the Intergalaxion Engine.
//!
//! Phase I-11 adds a pure planning model for how a future event stream
//! reader would be allowed, validated, and refused. This phase does NOT
//! open ring buffers, NOT read live kernel events, NOT decode a live
//! event stream, NOT expose public CLI, NOT persist anything, and NOT
//! add enforcement. It is planning only — the reader remains not
//! implemented.
//!
//! # Design constraints (I-11)
//!
//! * Planning only — no ring buffer open.
//! * No live kernel event read.
//! * No public CLI exposure.
//! * No enforcement, no packet drop, no block/allow/quota.
//! * No nft/tc backend.
//! * No map pin.
//! * No ledger file write.
//! * No persistence.
//! * Normal tests remain rootless.
//! * No fake event stream readiness from missing/failed evidence.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind;
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::{
    summarize_manual_lab_captures, EbpfLiveAttachManualLabSummary, EbpfLiveAttachManualResultStatus,
};

/// Status of the event stream read plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReadPlanStatus {
    /// Event stream read planning is disabled.
    Disabled,
    /// Manual capture is not yet ready for event stream planning.
    ManualCaptureNotReady,
    /// Missing clean detach evidence prevents readiness.
    MissingCleanDetachEvidence,
    /// Plan is in planning-only mode; no reader exists yet.
    PlanOnly,
    /// All model gates pass; candidate for future read implementation.
    FutureReadCandidate,
    /// Planning was rejected due to unsafe configuration.
    Rejected,
    /// The attach target kind is not supported.
    UnsupportedTarget,
    /// The event stream reader is not yet implemented.
    ReaderNotImplemented,
}

impl EbpfEventStreamReadPlanStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ManualCaptureNotReady => "manual_capture_not_ready",
            Self::MissingCleanDetachEvidence => "missing_clean_detach_evidence",
            Self::PlanOnly => "plan_only",
            Self::FutureReadCandidate => "future_read_candidate",
            Self::Rejected => "rejected",
            Self::UnsupportedTarget => "unsupported_target",
            Self::ReaderNotImplemented => "reader_not_implemented",
        }
    }
}

/// Mode of the event stream read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReadMode {
    /// Planning only; no actual reading occurs.
    PlanningOnly,
    /// Future ring buffer read mode (not implemented).
    FutureRingBufferRead,
    /// Future perf event read mode (not implemented).
    FuturePerfEventRead,
    /// Unsupported read mode.
    Unsupported,
}

impl EbpfEventStreamReadMode {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanningOnly => "planning_only",
            Self::FutureRingBufferRead => "future_ring_buffer_read",
            Self::FuturePerfEventRead => "future_perf_event_read",
            Self::Unsupported => "unsupported",
        }
    }
}

/// A reason code and message explaining a planning decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReadPlanReason {
    /// Machine-readable reason code.
    pub code: String,
    /// Human-readable reason message.
    pub message: String,
    /// Whether this reason is blocking.
    pub blocking: bool,
}

/// Input to the event stream read plan evaluation.
///
/// Combines the I-10F manual lab summary, required capture status,
/// read mode, target kind, and explicit safety flags. The evaluator
/// is pure and deterministic — no live kernel operations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReadPlanInput {
    /// The I-10F manual lab summary.
    pub manual_summary: EbpfLiveAttachManualLabSummary,
    /// The required capture status for event stream planning.
    pub required_capture_status: EbpfLiveAttachManualResultStatus,
    /// The desired read mode.
    pub read_mode: EbpfEventStreamReadMode,
    /// The attach target kind.
    pub target_kind: EbpfAttachTargetKind,
    /// Whether explicit event stream planning consent is given.
    pub explicit_event_stream_planning_consent: bool,
    /// Whether public CLI is requested (must be false).
    pub public_cli_requested: bool,
    /// Whether ring buffer open is allowed (must be false in I-11).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is allowed (must be false in I-11).
    pub allow_live_event_read: bool,
    /// Whether map pin is allowed (must be false).
    pub allow_map_pin: bool,
    /// Whether enforcement is allowed (must be false).
    pub allow_enforcement: bool,
    /// Whether packet drop is allowed (must be false).
    pub allow_packet_drop: bool,
    /// Whether persistence is allowed (must be false).
    pub allow_persistence: bool,
}

/// Result of evaluating the event stream read plan.
///
/// All operation flags are always false in I-11. The evaluation is
/// pure and deterministic. No ring buffer is opened, no live events
/// are read, no maps are pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReadPlan {
    /// The determined plan status.
    pub status: EbpfEventStreamReadPlanStatus,
    /// The read mode.
    pub mode: EbpfEventStreamReadMode,
    /// The attach target kind.
    pub target_kind: EbpfAttachTargetKind,
    /// Whether this is a candidate for future read implementation.
    pub future_read_candidate: bool,
    /// Whether the reader is implemented (always false in I-11).
    pub reader_implemented: bool,
    /// Reason codes explaining the planning decision.
    pub reasons: Vec<EbpfEventStreamReadPlanReason>,
    /// Whether the manual summary indicates readiness.
    pub manual_summary_ready: bool,
    /// Whether clean detach is required.
    pub clean_detach_required: bool,
    /// Whether clean detach is confirmed from evidence.
    pub clean_detach_confirmed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened (always false in I-11).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-11).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default event stream read plan input.
///
/// All fields are in their safest configuration: manual summary empty,
/// planning-only mode, no consent, no unsafe flags set.
pub fn default_event_stream_read_plan_input() -> EbpfEventStreamReadPlanInput {
    let empty_summary = summarize_manual_lab_captures(&[]);
    EbpfEventStreamReadPlanInput {
        manual_summary: empty_summary,
        required_capture_status: EbpfLiveAttachManualResultStatus::DetachedCleanly,
        read_mode: EbpfEventStreamReadMode::PlanningOnly,
        target_kind: EbpfAttachTargetKind::default(),
        explicit_event_stream_planning_consent: false,
        public_cli_requested: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

/// Build a safe base plan with all operation flags false.
fn safe_base_plan() -> EbpfEventStreamReadPlan {
    EbpfEventStreamReadPlan {
        status: EbpfEventStreamReadPlanStatus::Disabled,
        mode: EbpfEventStreamReadMode::PlanningOnly,
        target_kind: EbpfAttachTargetKind::default(),
        future_read_candidate: false,
        reader_implemented: false,
        reasons: vec![EbpfEventStreamReadPlanReason {
            code: String::from("disabled"),
            message: String::from("event stream read planning is disabled by default"),
            blocking: true,
        }],
        manual_summary_ready: false,
        clean_detach_required: true,
        clean_detach_confirmed: false,
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

/// Evaluate the event stream read plan from input.
///
/// This function is pure and deterministic. It checks the manual lab
/// summary, required capture status, consent, and safety flags to
/// determine whether event stream read planning can proceed.
///
/// # Evaluation logic
///
/// 1. **Manual summary readiness**: `ready_for_event_stream_planning=false`
///    forces `ManualCaptureNotReady`.
/// 2. **Clean detach evidence**: Summary must have `clean_detach_count > 0`
///    and no failures; otherwise `MissingCleanDetachEvidence`.
/// 3. **Summary status check**: Certain statuses (NotRun, FeatureDisabled,
///    ArtifactMissing, GateRejected, InvalidCapture) block readiness.
/// 4. **Required capture status**: Must be `DetachedCleanly` for readiness.
/// 5. **Explicit consent**: `explicit_event_stream_planning_consent=false`
///    forces `PlanOnly`.
/// 6. **Public CLI**: `public_cli_requested=true` forces `Rejected`.
/// 7. **Forbidden flags**: Any true `allow_*` flag forces `Rejected`.
/// 8. **Target support**: Currently all targets are supported.
/// 9. **Reader not implemented**: Even if all gates pass, the reader is
///    not implemented in I-11, so `ReaderNotImplemented` is returned
///    with `future_read_candidate=true`.
pub fn evaluate_event_stream_read_plan(
    input: &EbpfEventStreamReadPlanInput,
) -> EbpfEventStreamReadPlan {
    let base = safe_base_plan();

    // ── 1. Manual summary readiness ────────────────────────────────

    if !input.manual_summary.ready_for_event_stream_planning {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::ManualCaptureNotReady,
            manual_summary_ready: false,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("manual_capture_not_ready"),
                message: String::from(
                    "manual summary does not indicate readiness for event stream planning",
                ),
                blocking: true,
            }],
            ..base
        };
    }

    let ready_base = EbpfEventStreamReadPlan {
        manual_summary_ready: true,
        reasons: vec![],
        ..base
    };

    // ── 2. Clean detach evidence ────────────────────────────────────

    if input.manual_summary.clean_detach_count == 0 {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::MissingCleanDetachEvidence,
            clean_detach_confirmed: false,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("missing_clean_detach"),
                message: String::from("no clean detach evidence in manual summary"),
                blocking: true,
            }],
            ..ready_base
        };
    }

    if input.manual_summary.failed_attach_count > 0 || input.manual_summary.failed_detach_count > 0
    {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::MissingCleanDetachEvidence,
            clean_detach_confirmed: false,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("has_failures"),
                message: String::from("manual summary has failed attach or detach captures"),
                blocking: true,
            }],
            ..ready_base
        };
    }

    let detach_base = EbpfEventStreamReadPlan {
        clean_detach_confirmed: true,
        ..ready_base
    };

    // ── 3. Summary status check ────────────────────────────────────

    let blocking_statuses = [
        EbpfLiveAttachManualResultStatus::NotRun,
        EbpfLiveAttachManualResultStatus::FeatureDisabled,
        EbpfLiveAttachManualResultStatus::ArtifactMissing,
        EbpfLiveAttachManualResultStatus::GateRejected,
        EbpfLiveAttachManualResultStatus::InvalidCapture,
    ];
    if blocking_statuses.contains(&input.manual_summary.summary_status) {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::ManualCaptureNotReady,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("blocking_summary_status"),
                message: format!(
                    "summary status {:?} blocks event stream planning",
                    input.manual_summary.summary_status
                ),
                blocking: true,
            }],
            ..detach_base
        };
    }

    // Also block on AttachNotImplemented, AttachFailed, DetachFailed
    let failure_statuses = [
        EbpfLiveAttachManualResultStatus::AttachNotImplemented,
        EbpfLiveAttachManualResultStatus::AttachFailed,
        EbpfLiveAttachManualResultStatus::DetachFailed,
    ];
    if failure_statuses.contains(&input.manual_summary.summary_status) {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::MissingCleanDetachEvidence,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("failure_status"),
                message: format!(
                    "summary status {:?} indicates prior failure",
                    input.manual_summary.summary_status
                ),
                blocking: true,
            }],
            ..detach_base
        };
    }

    // ── 4. Required capture status ─────────────────────────────────

    if input.required_capture_status != EbpfLiveAttachManualResultStatus::DetachedCleanly {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::ManualCaptureNotReady,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("wrong_required_status"),
                message: String::from("required_capture_status must be DetachedCleanly"),
                blocking: true,
            }],
            ..detach_base
        };
    }

    let consent_base = EbpfEventStreamReadPlan {
        mode: input.read_mode,
        target_kind: input.target_kind,
        ..detach_base
    };

    // ── 5. Explicit consent ───────────────────────────────────────

    if !input.explicit_event_stream_planning_consent {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::PlanOnly,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("no_consent"),
                message: String::from("explicit event stream planning consent not given"),
                blocking: true,
            }],
            ..consent_base
        };
    }

    // ── 6. Public CLI check ─────────────────────────────────────────

    if input.public_cli_requested {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("public_cli_requested"),
                message: String::from("public CLI requested; event stream read must remain hidden"),
                blocking: true,
            }],
            ..consent_base
        };
    }

    // ── 7. Forbidden flags check ───────────────────────────────────

    if input.allow_ring_buffer_open {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_ring_buffer_open"),
                message: String::from("allow_ring_buffer_open must be false in I-11"),
                blocking: true,
            }],
            ..consent_base
        };
    }
    if input.allow_live_event_read {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_live_event_read"),
                message: String::from("allow_live_event_read must be false in I-11"),
                blocking: true,
            }],
            ..consent_base
        };
    }
    if input.allow_map_pin {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_map_pin"),
                message: String::from("allow_map_pin must be false"),
                blocking: true,
            }],
            ..consent_base
        };
    }
    if input.allow_enforcement {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_enforcement"),
                message: String::from("allow_enforcement must be false"),
                blocking: true,
            }],
            ..consent_base
        };
    }
    if input.allow_packet_drop {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_packet_drop"),
                message: String::from("allow_packet_drop must be false"),
                blocking: true,
            }],
            ..consent_base
        };
    }
    if input.allow_persistence {
        return EbpfEventStreamReadPlan {
            status: EbpfEventStreamReadPlanStatus::Rejected,
            reasons: vec![EbpfEventStreamReadPlanReason {
                code: String::from("allow_persistence"),
                message: String::from("allow_persistence must be false"),
                blocking: true,
            }],
            ..consent_base
        };
    }

    // ── 8. Target support check ────────────────────────────────────

    match input.target_kind {
        EbpfAttachTargetKind::SocketFilter
        | EbpfAttachTargetKind::CgroupSkb
        | EbpfAttachTargetKind::Tracepoint => {
            // Supported — continue.
        }
    }

    // ── 9. Reader not implemented ──────────────────────────────────

    // All model gates pass. In I-11, the event stream reader is not
    // yet implemented. The future-read-candidate flag is set so that
    // a future phase (I-12) can pick up from here.
    EbpfEventStreamReadPlan {
        status: EbpfEventStreamReadPlanStatus::ReaderNotImplemented,
        future_read_candidate: true,
        reasons: vec![EbpfEventStreamReadPlanReason {
            code: String::from("reader_not_implemented"),
            message: String::from(
                "all model gates pass; event stream reader not implemented in I-11",
            ),
            blocking: false,
        }],
        ..consent_base
    }
}

/// Validate that an event stream read plan does not have any unsafe or
/// inconsistent flags.
///
/// Returns `Ok(())` if the plan is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_read_plan(plan: &EbpfEventStreamReadPlan) -> Result<(), String> {
    if plan.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if plan.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-11".to_string());
    }
    if plan.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-11".to_string());
    }
    if plan.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if plan.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if plan.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if plan.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if plan.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if plan.reader_implemented {
        return Err("reader_implemented must be false in I-11".to_string());
    }
    if plan.future_read_candidate && plan.ring_buffer_opened {
        return Err("future_read_candidate must not have ring_buffer_opened".to_string());
    }
    if plan.future_read_candidate && plan.live_event_stream_read {
        return Err("future_read_candidate must not have live_event_stream_read".to_string());
    }
    Ok(())
}

/// Map an event stream read plan status to a stable human-readable label.
pub fn event_stream_read_plan_status_label(status: EbpfEventStreamReadPlanStatus) -> &'static str {
    status.as_str()
}

/// Map an event stream read mode to a stable human-readable label.
pub fn event_stream_read_mode_label(mode: EbpfEventStreamReadMode) -> &'static str {
    mode.as_str()
}
