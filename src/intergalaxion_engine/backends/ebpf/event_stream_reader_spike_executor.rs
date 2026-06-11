// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Feature-gated local reader spike executor boundary for the Intergalaxion Engine.
//!
//! Phase I-16 defines the final executor seam for a future local reader spike.
//! This phase is NOT the real live event stream reader. It is NOT a ring buffer
//! reader. It is NOT a kernel event consumer. It defines feature-gated executor
//! input/result models and validation, plus an executor function that refuses
//! safely by default. The normal build/test/CI remains rootless and inert.
//!
//! # Design constraints (I-16)
//!
//! * Executor-boundary only — not a live reader, not a ring buffer reader.
//! * Disabled by default — no execution possible without the
//!   `intergalaxion-event-stream-lab` Cargo feature.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake reader execution success.
//! * No fake live event counts.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.
//! * I-15A preparation readiness is required.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderInput;
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::{
    validate_event_stream_reader_spike_prep_plan, EbpfEventStreamReaderSpikePrepPlan,
    EbpfEventStreamReaderSpikePrepStatus,
};

/// Status of the event stream reader spike executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeExecutorStatus {
    /// The feature is disabled.
    FeatureDisabled,
    /// The I-15A preparation plan is not ready.
    PrepRejected,
    /// The executor is disabled (allow_execution_attempt=false).
    ExecutorDisabled,
    /// The reader is not yet implemented.
    ReaderNotImplemented,
    /// All gates pass; future execution is ready (but not attempted).
    FutureExecutionReady,
    /// An execution was attempted (only behind feature gate in a future phase).
    ExecutionAttempted,
    /// An execution succeeded (never reachable in I-16 normal build).
    ExecutionSucceeded,
    /// An execution failed (only behind feature gate in a future phase).
    ExecutionFailed,
    /// Cleanup is required before next execution.
    CleanupRequired,
    /// Cleanup has been completed.
    CleanupCompleted,
    /// Executor is blocked by a hard safety gate.
    Blocked,
}

impl EbpfEventStreamReaderSpikeExecutorStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
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
            Self::Blocked => "blocked",
        }
    }
}

/// Input to the event stream reader spike executor boundary.
///
/// Combines the I-15A preparation plan, I-12 reader input, explicit feature
/// flag, operator label, and safety flags. The evaluator is pure and
/// deterministic — no live kernel operations occur in any build configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeExecutorInput {
    /// The I-15A preparation plan.
    pub prep_plan: EbpfEventStreamReaderSpikePrepPlan,
    /// The I-12 event stream reader input (informational).
    pub reader_input: EbpfEventStreamReaderInput,
    /// Whether the executor feature is explicitly enabled.
    pub explicit_executor_feature_enabled: bool,
    /// Operator label for audit trail.
    pub explicit_operator_label: String,
    /// Whether an execution attempt is allowed.
    pub allow_execution_attempt: bool,
    /// Whether ring buffer open is allowed (must be false in I-16).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is allowed (must be false in I-16).
    pub allow_live_event_read: bool,
    /// Whether map pin is allowed (must be false in I-16).
    pub allow_map_pin: bool,
    /// Whether file write is allowed (must be false in I-16).
    pub allow_persistence: bool,
    /// Whether enforcement is allowed (must be false in I-16).
    pub allow_enforcement: bool,
    /// Whether packet drop is allowed (must be false in I-16).
    pub allow_packet_drop: bool,
    /// Whether cleanup is required after execution.
    pub require_cleanup: bool,
    /// Whether post-run evidence capture is required.
    pub require_post_run_evidence_capture: bool,
}

/// Result of evaluating the event stream reader spike executor boundary.
///
/// All operation flags are always false in I-16. The evaluation is pure and
/// deterministic. No ring buffer is opened, no live events are read, no maps
/// are pinned, no enforcement occurs, no persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeExecutorResult {
    /// The determined executor status.
    pub status: EbpfEventStreamReaderSpikeExecutorStatus,
    /// The phase this result covers.
    pub phase: String,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// Whether the executor feature is enabled.
    pub feature_enabled: bool,
    /// Whether execution is ready (all gates pass, but not attempted).
    pub execution_ready: bool,
    /// Whether an execution was attempted (always false in I-16).
    pub attempted: bool,
    /// Whether a reader was started (always false in I-16).
    pub reader_started: bool,
    /// Whether a reader completed (always false in I-16).
    pub reader_completed: bool,
    /// Whether cleanup is required.
    pub cleanup_required: bool,
    /// Whether cleanup has been completed (always false in I-16).
    pub cleanup_completed: bool,
    /// Whether post-run evidence capture is required.
    pub post_run_evidence_required: bool,
    /// Whether post-run evidence was captured (always false in I-16).
    pub post_run_evidence_captured: bool,
    /// Maximum events for the spike.
    pub max_events: usize,
    /// Timeout in milliseconds for the spike.
    pub timeout_ms: u64,
    /// Number of events read (always 0 in I-16).
    pub events_read: usize,
    /// Number of decode errors (always 0 in I-16).
    pub decode_errors: usize,
    /// Number of bridge records (always 0 in I-16).
    pub bridge_records: usize,
    /// Reason explaining the executor decision.
    pub reason: String,
    /// Whether public CLI was exposed (always false in I-16).
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened (always false in I-16).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-16).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-16).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-16).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false in I-16).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false in I-16).
    pub mutation_performed: bool,
    /// Whether file write was performed (always false in I-16).
    pub persistence_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default reader spike executor input.
///
/// All fields are in their safest configuration: default I-15A prep plan
/// (not PrepReady), no feature enabled, no unsafe flags set. The default
/// input is safe but not ready for execution.
pub fn default_event_stream_reader_spike_executor_input() -> EbpfEventStreamReaderSpikeExecutorInput
{
    let prep_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::default_event_stream_reader_spike_prep_input();
    let prep_plan =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::evaluate_event_stream_reader_spike_prep(&prep_input);
    let reader_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    EbpfEventStreamReaderSpikeExecutorInput {
        prep_plan,
        reader_input,
        explicit_executor_feature_enabled: false,
        explicit_operator_label: String::new(),
        allow_execution_attempt: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        require_cleanup: false,
        require_post_run_evidence_capture: false,
    }
}

/// Build a safe base result with all operation flags false.
fn safe_base_result() -> EbpfEventStreamReaderSpikeExecutorResult {
    EbpfEventStreamReaderSpikeExecutorResult {
        status: EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled,
        phase: String::from("I-16"),
        operator_label: String::new(),
        feature_enabled: false,
        execution_ready: false,
        attempted: false,
        reader_started: false,
        reader_completed: false,
        cleanup_required: false,
        cleanup_completed: false,
        post_run_evidence_required: false,
        post_run_evidence_captured: false,
        max_events: 0,
        timeout_ms: 0,
        events_read: 0,
        decode_errors: 0,
        bridge_records: 0,
        reason: String::from("reader spike executor is disabled by default"),
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

/// Evaluate the reader spike executor from input.
///
/// This function is pure and deterministic. It checks the I-15A preparation
/// plan, feature flag, operator label, execution flags, and safety flags to
/// determine whether the executor can represent future execution readiness.
///
/// # Evaluation logic
///
/// 1. **Feature disabled**: `explicit_executor_feature_enabled=false`
///    forces `FeatureDisabled`.
/// 2. **Prep plan validation**: `validate_event_stream_reader_spike_prep_plan()`
///    failure forces `PrepRejected`.
/// 3. **Prep plan status**: Status not `PrepReady` forces `PrepRejected`.
/// 4. **Operator label**: Empty label forces `PrepRejected`.
/// 5. **Execution attempt**: `allow_execution_attempt=false`
///    forces `ExecutorDisabled`.
/// 6. **Forbidden flags**: `allow_ring_buffer_open=true`,
///    `allow_live_event_read=true`, `allow_map_pin=true`,
///    `allow_persistence=true`, `allow_enforcement=true`,
///    `allow_packet_drop=true` all force `Blocked`.
/// 7. **Cleanup required**: `require_cleanup=false` forces `Blocked`.
/// 8. **Post-run evidence**: `require_post_run_evidence_capture=false`
///    forces `Blocked`.
/// 9. **FutureExecutionReady**: All gates pass, but `attempted=false`,
///    `reader_started=false`, `reader_completed=false`, all counts 0.
pub fn evaluate_event_stream_reader_spike_executor(
    input: &EbpfEventStreamReaderSpikeExecutorInput,
) -> EbpfEventStreamReaderSpikeExecutorResult {
    // ── 1. Feature disabled ──────────────────────────────────────────
    if !input.explicit_executor_feature_enabled {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled,
            feature_enabled: false,
            reason: String::from("executor feature is disabled"),
            operator_label: input.explicit_operator_label.clone(),
            ..safe_base_result()
        };
    }

    // ── 2. Prep plan validation ────────────────────────────────────
    if validate_event_stream_reader_spike_prep_plan(&input.prep_plan).is_err() {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected,
            feature_enabled: true,
            reason: String::from("I-15A preparation plan failed validation"),
            operator_label: input.explicit_operator_label.clone(),
            ..safe_base_result()
        };
    }

    // ── 3. Prep plan must be PrepReady ──────────────────────────────
    if input.prep_plan.status != EbpfEventStreamReaderSpikePrepStatus::PrepReady {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected,
            feature_enabled: true,
            reason: String::from("I-15A preparation plan is not PrepReady"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            ..safe_base_result()
        };
    }

    // ── 4. Operator label required ─────────────────────────────────
    if input.explicit_operator_label.is_empty() {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected,
            feature_enabled: true,
            reason: String::from("operator label must not be empty"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            ..safe_base_result()
        };
    }

    // ── 5. Execution attempt required ───────────────────────────────
    if !input.allow_execution_attempt {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::ExecutorDisabled,
            feature_enabled: true,
            execution_ready: false,
            reason: String::from("execution attempt is not enabled"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }

    // ── 6. Forbidden flags (I-16 hard blocks) ────────────────────
    if input.allow_ring_buffer_open {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("ring buffer open is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }
    if input.allow_live_event_read {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("live event read is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }
    if input.allow_map_pin {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("map pin is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }
    if input.allow_persistence {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("file write is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }
    if input.allow_enforcement {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("enforcement is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }
    if input.allow_packet_drop {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("packet drop is not supported in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            post_run_evidence_required: input.require_post_run_evidence_capture,
            ..safe_base_result()
        };
    }

    // ── 7. Cleanup required ──────────────────────────────────────────
    if !input.require_cleanup {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("cleanup is required in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            ..safe_base_result()
        };
    }

    // ── 8. Post-run evidence capture required ────────────────────────
    if !input.require_post_run_evidence_capture {
        return EbpfEventStreamReaderSpikeExecutorResult {
            status: EbpfEventStreamReaderSpikeExecutorStatus::Blocked,
            feature_enabled: true,
            reason: String::from("post-run evidence capture is required in I-16"),
            operator_label: input.explicit_operator_label.clone(),
            max_events: input.prep_plan.max_events,
            timeout_ms: input.prep_plan.timeout_ms,
            cleanup_required: input.require_cleanup,
            ..safe_base_result()
        };
    }

    // ── 9. FutureExecutionReady ──────────────────────────────────────
    EbpfEventStreamReaderSpikeExecutorResult {
        status: EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady,
        phase: String::from("I-16"),
        operator_label: input.explicit_operator_label.clone(),
        feature_enabled: true,
        execution_ready: true,
        attempted: false,
        reader_started: false,
        reader_completed: false,
        cleanup_required: true,
        cleanup_completed: false,
        post_run_evidence_required: true,
        post_run_evidence_captured: false,
        max_events: input.prep_plan.max_events,
        timeout_ms: input.prep_plan.timeout_ms,
        events_read: 0,
        decode_errors: 0,
        bridge_records: 0,
        reason: String::from(
            "all executor gates pass; future execution is ready but not attempted",
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

/// Feature-gated executor function that refuses safely by default.
///
/// In the normal build (feature disabled), this always returns
/// `FeatureDisabled`. When the feature is enabled, it delegates to
/// `evaluate_event_stream_reader_spike_executor`.
pub fn execute_event_stream_reader_spike_feature_gated(
    input: &EbpfEventStreamReaderSpikeExecutorInput,
) -> EbpfEventStreamReaderSpikeExecutorResult {
    evaluate_event_stream_reader_spike_executor(input)
}

/// Validate that a reader spike executor result does not have any unsafe
/// or inconsistent flags.
///
/// Returns `Ok(())` if the result is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
///
/// # Validation rules (I-16)
///
/// * All safety operation flags must be false.
/// * `execution_ready=true` requires status `FutureExecutionReady`.
/// * `attempted=true` requires status not `FeatureDisabled`.
/// * `reader_started=true` requires `attempted=true`.
/// * `reader_completed=true` requires `reader_started=true`.
/// * `ExecutionSucceeded` is never reachable in I-16 normal build.
/// * `events_read>0` requires `live_event_stream_read=true`.
/// * `decode_errors>0` requires `attempted=true`.
/// * `bridge_records>0` requires `attempted=true`.
/// * `cleanup_completed=true` requires `cleanup_required=true`.
pub fn validate_event_stream_reader_spike_executor_result(
    result: &EbpfEventStreamReaderSpikeExecutorResult,
) -> Result<(), String> {
    // Safety flag checks
    if result.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-16".to_string());
    }
    if result.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-16".to_string());
    }
    if result.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-16".to_string());
    }
    if result.map_pin_performed {
        return Err("map_pin_performed must be false in I-16".to_string());
    }
    if result.enforcement_performed {
        return Err("enforcement_performed must be false in I-16".to_string());
    }
    if result.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-16".to_string());
    }
    if result.mutation_performed {
        return Err("mutation_performed must be false in I-16".to_string());
    }
    if result.persistence_performed {
        return Err("persistence_performed must be false in I-16".to_string());
    }
    // Structural consistency
    if result.execution_ready
        && result.status != EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady
    {
        return Err("execution_ready=true requires status FutureExecutionReady".to_string());
    }
    if result.attempted
        && result.status == EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled
    {
        return Err("attempted=true requires status not FeatureDisabled".to_string());
    }
    if result.reader_started && !result.attempted {
        return Err("reader_started=true requires attempted=true".to_string());
    }
    if result.reader_completed && !result.reader_started {
        return Err("reader_completed=true requires reader_started=true".to_string());
    }
    if result.status == EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded {
        return Err("ExecutionSucceeded must not be reachable in I-16".to_string());
    }
    if result.events_read > 0 && !result.live_event_stream_read {
        return Err("events_read>0 requires live_event_stream_read=true".to_string());
    }
    if result.decode_errors > 0 && !result.attempted {
        return Err("decode_errors>0 requires attempted=true".to_string());
    }
    if result.bridge_records > 0 && !result.attempted {
        return Err("bridge_records>0 requires attempted=true".to_string());
    }
    if result.cleanup_completed && !result.cleanup_required {
        return Err("cleanup_completed=true requires cleanup_required=true".to_string());
    }
    Ok(())
}

/// Map a reader spike executor status to a stable human-readable label.
pub fn event_stream_reader_spike_executor_status_label(
    status: EbpfEventStreamReaderSpikeExecutorStatus,
) -> &'static str {
    status.as_str()
}
