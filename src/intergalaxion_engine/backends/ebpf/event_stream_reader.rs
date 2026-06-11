// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Event stream reader boundary for the Intergalaxion Engine.
//!
//! Phase I-12 adds a disabled-by-default event stream reader executor seam.
//! This phase is NOT the real event stream reader implementation. It defines
//! feature-gated reader input/result models and validation, plus an executor
//! function that refuses safely by default. The normal build/test/CI remains
//! rootless and inert.
//!
//! # Design constraints (I-12)
//!
//! * Reader boundary only — no real event stream reading.
//! * Disabled by default — no reader possible without the
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
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind;
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::{
    validate_event_stream_read_plan, EbpfEventStreamReadMode, EbpfEventStreamReadPlan,
    EbpfEventStreamReadPlanStatus,
};

/// Status of the event stream reader boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderStatus {
    /// The intergalaxion-event-stream-lab feature is not enabled.
    FeatureDisabled,
    /// The read plan was rejected (not a future read candidate or validation failed).
    PlanRejected,
    /// Manual lab evidence is missing or insufficient.
    ManualEvidenceMissing,
    /// The read mode is not supported.
    UnsupportedMode,
    /// The attach target kind is not supported.
    UnsupportedTarget,
    /// The event stream reader is not yet implemented.
    ReaderNotImplemented,
    /// All gates pass; future reader is ready (but not started).
    FutureReaderReady,
    /// A reader was attempted (only behind feature gate in a future phase).
    ReaderAttempted,
    /// A reader succeeded (never reachable in I-12 normal build).
    ReaderSucceeded,
    /// A reader failed (only behind feature gate in a future phase).
    ReaderFailed,
}

impl EbpfEventStreamReaderStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::PlanRejected => "plan_rejected",
            Self::ManualEvidenceMissing => "manual_evidence_missing",
            Self::UnsupportedMode => "unsupported_mode",
            Self::UnsupportedTarget => "unsupported_target",
            Self::ReaderNotImplemented => "reader_not_implemented",
            Self::FutureReaderReady => "future_reader_ready",
            Self::ReaderAttempted => "reader_attempted",
            Self::ReaderSucceeded => "reader_succeeded",
            Self::ReaderFailed => "reader_failed",
        }
    }
}

/// Input to the event stream reader boundary evaluation.
///
/// Combines the I-11 read plan, feature flag, operator label, and explicit
/// safety flags. The evaluator is pure and deterministic — no live kernel
/// operations occur in any build configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderInput {
    /// The I-11 event stream read plan.
    pub read_plan: EbpfEventStreamReadPlan,
    /// Whether the intergalaxion-event-stream-lab feature is enabled.
    pub explicit_event_stream_lab_feature_enabled: bool,
    /// Operator label for audit trail.
    pub explicit_operator_label: String,
    /// Whether the reader attempt is allowed.
    pub allow_reader_attempt: bool,
    /// Whether ring buffer open is allowed (must be false in I-12).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is allowed (must be false in I-12).
    pub allow_live_event_read: bool,
    /// Whether map pin is allowed (must be false in I-12).
    pub allow_map_pin: bool,
    /// Whether persistence is allowed (must be false in I-12).
    pub allow_persistence: bool,
    /// Maximum events to read (informational only in I-12).
    pub max_events: usize,
    /// Timeout in milliseconds (informational only in I-12).
    pub timeout_ms: u64,
}

/// Result of evaluating the event stream reader boundary.
///
/// All operation flags are always false in I-12. The evaluation is
/// pure and deterministic. No ring buffer is opened, no live events
/// are read, no maps are pinned, no persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderResult {
    /// The determined reader status.
    pub status: EbpfEventStreamReaderStatus,
    /// Whether a reader was attempted (always false in I-12).
    pub attempted: bool,
    /// Whether a reader was started (always false in I-12).
    pub reader_started: bool,
    /// Whether a reader completed (always false in I-12).
    pub reader_completed: bool,
    /// Whether the event stream lab feature is enabled.
    pub feature_enabled: bool,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// The read mode from the plan.
    pub mode: EbpfEventStreamReadMode,
    /// The attach target kind from the plan.
    pub target_kind: EbpfAttachTargetKind,
    /// Maximum events to read (informational only).
    pub max_events: usize,
    /// Timeout in milliseconds (informational only).
    pub timeout_ms: u64,
    /// Reason explaining the reader decision.
    pub reason: String,
    /// Number of events read (always 0 in I-12).
    pub events_read: usize,
    /// Number of decode errors (always 0 in I-12).
    pub decode_errors: usize,
    /// Whether a ring buffer was opened (always false in I-12).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-12).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-12).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default event stream reader input.
///
/// All fields are in their safest configuration: feature disabled,
/// empty operator label, no unsafe flags set.
pub fn default_event_stream_reader_input() -> EbpfEventStreamReaderInput {
    let default_plan = crate::intergalaxion_engine::backends::ebpf::event_stream_plan::default_event_stream_read_plan_input();
    let read_plan = crate::intergalaxion_engine::backends::ebpf::event_stream_plan::evaluate_event_stream_read_plan(&default_plan);
    EbpfEventStreamReaderInput {
        read_plan,
        explicit_event_stream_lab_feature_enabled: false,
        explicit_operator_label: String::new(),
        allow_reader_attempt: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        max_events: 0,
        timeout_ms: 0,
    }
}

/// Build a safe base result with all operation flags false.
fn safe_base_result(feature_enabled: bool, operator_label: String) -> EbpfEventStreamReaderResult {
    EbpfEventStreamReaderResult {
        status: EbpfEventStreamReaderStatus::FeatureDisabled,
        attempted: false,
        reader_started: false,
        reader_completed: false,
        feature_enabled,
        operator_label,
        mode: EbpfEventStreamReadMode::PlanningOnly,
        target_kind: EbpfAttachTargetKind::default(),
        max_events: 0,
        timeout_ms: 0,
        reason: String::from("event stream reader is disabled by default"),
        events_read: 0,
        decode_errors: 0,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    }
}

/// Evaluate the event stream reader boundary from input.
///
/// This function is pure and deterministic. It checks the feature flag,
/// read plan, operator label, and safety flags to determine whether
/// the event stream reader boundary can proceed.
///
/// # Evaluation logic
///
/// 1. **Feature disabled**: `explicit_event_stream_lab_feature_enabled=false`
///    always returns `FeatureDisabled`.
/// 2. **Plan validation**: If the read plan itself fails validation,
///    returns `PlanRejected`.
/// 3. **Plan not a future read candidate**: If plan status is not
///    `FutureReadCandidate` or `ReaderNotImplemented` with
///    `future_read_candidate=true`, returns `PlanRejected`.
/// 4. **Operator label**: Empty operator label blocks the reader.
/// 5. **Reader attempt flag**: `allow_reader_attempt=false` blocks.
/// 6. **Forbidden flags in I-12**: `allow_ring_buffer_open=true`,
///    `allow_live_event_read=true`, `allow_map_pin=true`,
///    `allow_persistence=true` all block.
/// 7. **Unsupported mode**: `Unsupported` read mode blocks.
/// 8. **Unsupported target**: Currently all targets are supported.
/// 9. **Reader not implemented**: Even if all gates pass, the real
///    reader is not implemented in I-12, so `FutureReaderReady` is
///    returned with all operation flags false.
pub fn evaluate_event_stream_reader(
    input: &EbpfEventStreamReaderInput,
) -> EbpfEventStreamReaderResult {
    // ── 1. Feature disabled ─────────────────────────────────────────
    if !input.explicit_event_stream_lab_feature_enabled {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::FeatureDisabled,
            reason: String::from("intergalaxion-event-stream-lab feature is disabled"),
            ..safe_base_result(false, input.explicit_operator_label.clone())
        };
    }

    let feature_base = safe_base_result(true, input.explicit_operator_label.clone());

    // ── 2. Plan validation ──────────────────────────────────────────
    if validate_event_stream_read_plan(&input.read_plan).is_err() {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::PlanRejected,
            reason: String::from("read plan failed validation"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 3. Plan must be future read candidate ───────────────────────
    let is_future_candidate = input.read_plan.future_read_candidate
        && (input.read_plan.status == EbpfEventStreamReadPlanStatus::FutureReadCandidate
            || input.read_plan.status == EbpfEventStreamReadPlanStatus::ReaderNotImplemented);

    if !is_future_candidate {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::PlanRejected,
            reason: String::from("read plan is not a future read candidate"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 4. Operator label required ────────────────────────────────────
    if input.explicit_operator_label.is_empty() {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::ManualEvidenceMissing,
            reason: String::from("operator label must not be empty"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 5. Reader attempt flag ───────────────────────────────────────
    if !input.allow_reader_attempt {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::ReaderNotImplemented,
            reason: String::from("allow_reader_attempt is false; reader not attempted"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 6. Forbidden flags (I-12 hard blocks) ─────────────────────
    if input.allow_ring_buffer_open {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::UnsupportedMode,
            reason: String::from("allow_ring_buffer_open must be false in I-12"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }
    if input.allow_live_event_read {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::UnsupportedMode,
            reason: String::from("allow_live_event_read must be false in I-12"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }
    if input.allow_map_pin {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::UnsupportedTarget,
            reason: String::from("allow_map_pin must be false in I-12"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }
    if input.allow_persistence {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::UnsupportedTarget,
            reason: String::from("allow_persistence must be false in I-12"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 7. Unsupported mode check ────────────────────────────────────
    if input.read_plan.mode == EbpfEventStreamReadMode::Unsupported {
        return EbpfEventStreamReaderResult {
            status: EbpfEventStreamReaderStatus::UnsupportedMode,
            reason: String::from("read mode is unsupported"),
            mode: input.read_plan.mode,
            target_kind: input.read_plan.target_kind,
            ..feature_base
        };
    }

    // ── 8. Unsupported target check ─────────────────────────────────
    // All current target kinds are supported (SocketFilter, CgroupSkb, Tracepoint).

    // ── 9. Reader not implemented in I-12 ────────────────────────────
    // All model gates pass. In I-12, the real event stream reader is
    // not implemented. Return FutureReaderReady with all operation
    // flags false.
    EbpfEventStreamReaderResult {
        status: EbpfEventStreamReaderStatus::FutureReaderReady,
        reason: String::from("all reader gates pass; event stream reader not implemented in I-12"),
        mode: input.read_plan.mode,
        target_kind: input.read_plan.target_kind,
        max_events: input.max_events,
        timeout_ms: input.timeout_ms,
        ..feature_base
    }
}

/// Validate that an event stream reader result does not have any unsafe
/// or inconsistent flags.
///
/// Returns `Ok(())` if the result is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
///
/// # Validation rules (I-12)
///
/// * All safety flags must be false (ring_buffer_opened, live_event_stream_read,
///   map_pin_performed, enforcement_performed, packet_drop_performed,
///   mutation_performed, persistence_performed, public_cli_exposed).
/// * `reader_started` requires `attempted=true`.
/// * `reader_completed` requires `reader_started=true`.
/// * `events_read > 0` requires `live_event_stream_read=true`.
/// * `decode_errors > 0` requires `attempted=true`.
/// * `ReaderSucceeded` is never reachable in I-12 normal build.
pub fn validate_event_stream_reader_result(
    result: &EbpfEventStreamReaderResult,
) -> Result<(), String> {
    // Safety flag checks
    if result.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-12".to_string());
    }
    if result.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-12".to_string());
    }
    if result.map_pin_performed {
        return Err("map_pin_performed must be false in I-12".to_string());
    }
    if result.enforcement_performed {
        return Err("enforcement_performed must be false in I-12".to_string());
    }
    if result.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-12".to_string());
    }
    if result.mutation_performed {
        return Err("mutation_performed must be false in I-12".to_string());
    }
    if result.persistence_performed {
        return Err("persistence_performed must be false in I-12".to_string());
    }
    if result.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-12".to_string());
    }
    // Structural consistency
    if result.reader_started && !result.attempted {
        return Err("reader_started requires attempted=true".to_string());
    }
    if result.reader_completed && !result.reader_started {
        return Err("reader_completed requires reader_started=true".to_string());
    }
    if result.events_read > 0 && !result.live_event_stream_read {
        return Err("events_read>0 requires live_event_stream_read=true".to_string());
    }
    if result.decode_errors > 0 && !result.attempted {
        return Err("decode_errors>0 requires attempted=true".to_string());
    }
    // I-12 boundary: ReaderSucceeded is not reachable
    if result.status == EbpfEventStreamReaderStatus::ReaderSucceeded {
        return Err("ReaderSucceeded is not reachable in I-12 normal build".to_string());
    }
    // FeatureDisabled must not have attempted=true
    if result.status == EbpfEventStreamReaderStatus::FeatureDisabled && result.attempted {
        return Err("FeatureDisabled must not have attempted=true".to_string());
    }
    Ok(())
}

/// Map an event stream reader status to a stable human-readable label.
pub fn event_stream_reader_status_label(status: EbpfEventStreamReaderStatus) -> &'static str {
    status.as_str()
}

/// Execute the event stream reader with feature-gate awareness.
///
/// This function is pure and deterministic. In I-12 it delegates to
/// `evaluate_event_stream_reader`. A future phase may add real
/// ring buffer handling behind the feature gate.
#[cfg(feature = "intergalaxion-event-stream-lab")]
pub fn execute_event_stream_reader_feature_gated(
    input: &EbpfEventStreamReaderInput,
) -> EbpfEventStreamReaderResult {
    evaluate_event_stream_reader(input)
}

/// Execute the event stream reader with feature-gate awareness (disabled path).
///
/// When the feature is not enabled, always returns FeatureDisabled.
#[cfg(not(feature = "intergalaxion-event-stream-lab"))]
pub fn execute_event_stream_reader_feature_gated(
    input: &EbpfEventStreamReaderInput,
) -> EbpfEventStreamReaderResult {
    let _ = input;
    EbpfEventStreamReaderResult {
        status: EbpfEventStreamReaderStatus::FeatureDisabled,
        attempted: false,
        reader_started: false,
        reader_completed: false,
        feature_enabled: false,
        operator_label: String::new(),
        mode: EbpfEventStreamReadMode::PlanningOnly,
        target_kind: EbpfAttachTargetKind::default(),
        max_events: 0,
        timeout_ms: 0,
        reason: String::from("intergalaxion-event-stream-lab feature is not enabled"),
        events_read: 0,
        decode_errors: 0,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    }
}
