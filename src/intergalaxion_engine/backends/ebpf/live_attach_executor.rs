// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Minimal live attach executor spike for the Intergalaxion Engine.
//!
//! Phase I-10C adds the first narrow live attach executor spike boundary.
//! This phase is hard-gated, feature-gated, observer-only, local-lab-only,
//! and hidden from public CLI. The executor must remain disabled by default
//! and must not run in normal tests or normal CI.
//!
//! # Design constraints (I-10C)
//!
//! * Disabled by default — no live attach without the
//!   `intergalaxion-live-attach-lab` Cargo feature.
//! * No public CLI exposure.
//! * No enforcement, no packet drop, no block/allow/quota.
//! * No nft/tc backend.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No ledger file write.
//! * No persistence.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live attach.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind;
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::EbpfLiveAttachGateDecision;
use crate::intergalaxion_engine::live_attach_runbook::{
    validate_live_attach_runbook, IntergalaxionLiveAttachRunbook,
};

/// Status of the live attach executor spike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachExecutorStatus {
    /// The intergalaxion-live-attach-lab feature is not enabled.
    FeatureDisabled,
    /// Gate decision or runbook validation rejected the attempt.
    GateRejected,
    /// Object source is declared but no object bytes are available.
    ObjectSourceMissing,
    /// The attach target kind is not supported.
    UnsupportedTarget,
    /// Attach was not attempted (safe default).
    AttachNotAttempted,
    /// Future attach could proceed but is not executed in default build.
    FutureAttachReady,
    /// A live attach was attempted (only behind feature gate).
    LiveAttachAttempted,
    /// A live attach succeeded (only behind feature gate).
    LiveAttachSucceeded,
    /// A live attach failed (only behind feature gate).
    LiveAttachFailed,
    /// Programs were detached cleanly after attach (only behind feature gate).
    DetachedCleanly,
}

impl EbpfLiveAttachExecutorStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::GateRejected => "gate_rejected",
            Self::ObjectSourceMissing => "object_source_missing",
            Self::UnsupportedTarget => "unsupported_target",
            Self::AttachNotAttempted => "attach_not_attempted",
            Self::FutureAttachReady => "future_attach_ready",
            Self::LiveAttachAttempted => "live_attach_attempted",
            Self::LiveAttachSucceeded => "live_attach_succeeded",
            Self::LiveAttachFailed => "live_attach_failed",
            Self::DetachedCleanly => "detached_cleanly",
        }
    }
}

/// Input to the live attach executor spike evaluation.
///
/// Combines the I-9 gate decision, I-10B runbook, and explicit lab
/// parameters. The evaluator is pure and deterministic — it inspects
/// these models but does NOT perform any live kernel operations in
/// the default build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachLabInput {
    /// I-9 gate decision result.
    pub gate_decision: EbpfLiveAttachGateDecision,
    /// I-10B runbook contract.
    pub runbook: IntergalaxionLiveAttachRunbook,
    /// Whether an object source is declared.
    pub object_source_declared: bool,
    /// Whether actual object bytes are available.
    pub object_bytes_available: bool,
    /// The attach target kind.
    pub target_kind: EbpfAttachTargetKind,
    /// Whether the local lab feature is explicitly enabled.
    pub explicit_local_lab_feature_enabled: bool,
    /// Operator label for audit trail.
    pub explicit_operator_label: String,
    /// Whether explicit detach is required.
    pub explicit_detach_required: bool,
    /// Whether a live attempt is explicitly allowed.
    pub allow_live_attempt: bool,
}

/// Result of evaluating the live attach executor spike.
///
/// All operation flags are always false in the default build. The
/// evaluation is pure and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachExecutorAttempt {
    /// The determined executor status.
    pub status: EbpfLiveAttachExecutorStatus,
    /// Whether an attach was attempted (always false in default build).
    pub attempted: bool,
    /// Whether a program was attached (always false in default build).
    pub attached: bool,
    /// Whether a program was detached (always false in default build).
    pub detached: bool,
    /// Whether this is observer-only (always true).
    pub observer_only: bool,
    /// Whether the feature is enabled.
    pub feature_enabled: bool,
    /// Whether this is local-lab-only (always true).
    pub local_lab_only: bool,
    /// Whether object source was declared.
    pub object_source_declared: bool,
    /// Whether object bytes were available.
    pub object_bytes_available: bool,
    /// Human-readable reason for the status.
    pub reason: String,
    /// Whether a program load was attempted (always false in default build).
    pub program_load_attempted: bool,
    /// Whether an attach was attempted (always false in default build).
    pub attach_attempted: bool,
    /// Whether a map create was attempted (always false in default build).
    pub map_create_attempted: bool,
    /// Whether a ring buffer was opened (always false in I-10C).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-10C).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-10C).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether a packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether mutation was performed (always false in default build).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default live attach lab input.
///
/// All fields are in their safest configuration: feature disabled, no
/// object source, no operator label, no detach required, no live
/// attempt allowed.
pub fn default_live_attach_lab_input() -> EbpfLiveAttachLabInput {
    EbpfLiveAttachLabInput {
        gate_decision: EbpfLiveAttachGateDecision::default(),
        runbook: crate::intergalaxion_engine::live_attach_runbook::default_live_attach_runbook(),
        object_source_declared: false,
        object_bytes_available: false,
        target_kind: EbpfAttachTargetKind::default(),
        explicit_local_lab_feature_enabled: false,
        explicit_operator_label: String::new(),
        explicit_detach_required: false,
        allow_live_attempt: false,
    }
}

/// Evaluate the live attach executor spike from lab input.
///
/// This function is pure and deterministic. It inspects the provided
/// input models but does NOT perform any live kernel operations, file
/// I/O, or process mutation. In the default build (feature disabled),
/// it always returns a safe result with all operation flags false.
///
/// # Evaluation logic
///
/// 1. **Feature gate**: `explicit_local_lab_feature_enabled=false` forces
///    `FeatureDisabled`.
/// 2. **Runbook validation**: Unsafe runbook forces `GateRejected`.
/// 3. **Gate decision validation**: Unsafe gate decision forces
///    `GateRejected`.
/// 4. **Future candidate check**: Gate decision must have
///    `future_live_attach_candidate=true`.
/// 5. **Operator label**: Must be nonempty.
/// 6. **Detach required**: Must be true.
/// 7. **Allow live attempt**: Must be true.
/// 8. **Object source**: `object_source_declared=false` or
///    `object_bytes_available=false` forces `ObjectSourceMissing`.
/// 9. **Target support**: Unsupported target kind forces
///    `UnsupportedTarget`.
/// 10. **Future attach ready**: If all model gates pass but real attach
///     is not executed in default build, status is `FutureAttachReady`.
pub fn evaluate_live_attach_lab_attempt(
    input: &EbpfLiveAttachLabInput,
) -> EbpfLiveAttachExecutorAttempt {
    let safe_attempt = EbpfLiveAttachExecutorAttempt {
        status: EbpfLiveAttachExecutorStatus::AttachNotAttempted,
        attempted: false,
        attached: false,
        detached: false,
        observer_only: true,
        feature_enabled: false,
        local_lab_only: true,
        object_source_declared: input.object_source_declared,
        object_bytes_available: input.object_bytes_available,
        reason: String::new(),
        program_load_attempted: false,
        attach_attempted: false,
        map_create_attempted: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    };

    // ── 1. Feature gate check ────────────────────────────────────────

    if !input.explicit_local_lab_feature_enabled {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::FeatureDisabled,
            reason: String::from("intergalaxion-live-attach-lab feature is not enabled"),
            ..safe_attempt
        };
    }

    // ── 2. Runbook validation check ───────────────────────────────────

    if validate_live_attach_runbook(&input.runbook).is_err() {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::GateRejected,
            feature_enabled: true,
            reason: String::from("runbook validation failed"),
            ..safe_attempt
        };
    }

    // ── 3. Gate decision validation check ──────────────────────────────

    if crate::intergalaxion_engine::backends::ebpf::live_attach_gate::validate_live_attach_gate_decision(&input.gate_decision).is_err() {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::GateRejected,
            feature_enabled: true,
            reason: String::from("gate decision validation failed"),
            ..safe_attempt
        };
    }

    // ── 4. Future candidate check ──────────────────────────────────────

    if !input.gate_decision.future_live_attach_candidate {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::GateRejected,
            feature_enabled: true,
            reason: String::from("gate decision is not a future live attach candidate"),
            ..safe_attempt
        };
    }

    // ── 5. Operator label check ───────────────────────────────────────

    if input.explicit_operator_label.is_empty() {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::GateRejected,
            feature_enabled: true,
            reason: String::from("explicit operator label is empty"),
            ..safe_attempt
        };
    }

    // ── 6. Detach required check ──────────────────────────────────────

    if !input.explicit_detach_required {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::GateRejected,
            feature_enabled: true,
            reason: String::from("explicit detach is not required"),
            ..safe_attempt
        };
    }

    // ── 7. Allow live attempt check ──────────────────────────────────

    if !input.allow_live_attempt {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::AttachNotAttempted,
            feature_enabled: true,
            reason: String::from("live attempt not explicitly allowed"),
            ..safe_attempt
        };
    }

    // ── 8. Object source check ─────────────────────────────────────────

    if !input.object_source_declared {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::ObjectSourceMissing,
            feature_enabled: true,
            reason: String::from("object source is not declared"),
            ..safe_attempt
        };
    }

    if !input.object_bytes_available {
        return EbpfLiveAttachExecutorAttempt {
            status: EbpfLiveAttachExecutorStatus::ObjectSourceMissing,
            feature_enabled: true,
            reason: String::from("object bytes are not available"),
            ..safe_attempt
        };
    }

    // ── 9. Target support check ───────────────────────────────────────

    match input.target_kind {
        EbpfAttachTargetKind::SocketFilter
        | EbpfAttachTargetKind::CgroupSkb
        | EbpfAttachTargetKind::Tracepoint => {
            // Supported targets — continue.
        }
    }

    // ── 10. Future attach ready ───────────────────────────────────────

    // All model gates pass. In the default build, real attach is not
    // executed. The feature-gated code path would go here, but in
    // the current phase it remains stubbed.
    EbpfLiveAttachExecutorAttempt {
        status: EbpfLiveAttachExecutorStatus::FutureAttachReady,
        feature_enabled: true,
        reason: String::from("all model gates pass; real attach is stubbed in default build"),
        ..safe_attempt
    }
}

/// Validate that a live attach executor attempt does not have any unsafe
/// flags.
///
/// Returns `Ok(())` if the attempt is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `attached` is `true` when `attempted` is `false`
/// * `detached` is `true` when `attached` is `false`
/// * `observer_only` is `false`
/// * `local_lab_only` is `false`
/// * `program_load_attempted` is `true` unless status is
///   `LiveAttachAttempted`, `LiveAttachSucceeded`, or `LiveAttachFailed`
/// * `attach_attempted` is `true` unless status is
///   `LiveAttachAttempted`, `LiveAttachSucceeded`, or `LiveAttachFailed`
/// * `map_create_attempted` is `true`
/// * `ring_buffer_opened` is `true`
/// * `live_kernel_read_performed` is `true`
/// * `map_pin_performed` is `true`
/// * `enforcement_performed` is `true`
/// * `packet_drop_performed` is `true`
/// * `mutation_performed` is `true`
/// * `persistence_performed` is `true`
/// * `public_cli_exposed` is `true`
pub fn validate_live_attach_executor_attempt(
    attempt: &EbpfLiveAttachExecutorAttempt,
) -> Result<(), String> {
    if attempt.attached && !attempt.attempted {
        return Err("attached=true requires attempted=true".to_string());
    }
    if attempt.detached && !attempt.attached {
        return Err("detached=true requires attached=true".to_string());
    }
    if !attempt.observer_only {
        return Err("observer_only must be true".to_string());
    }
    if !attempt.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    let live_statuses = [
        EbpfLiveAttachExecutorStatus::LiveAttachAttempted,
        EbpfLiveAttachExecutorStatus::LiveAttachSucceeded,
        EbpfLiveAttachExecutorStatus::LiveAttachFailed,
    ];
    if attempt.program_load_attempted && !live_statuses.contains(&attempt.status) {
        return Err("program_load_attempted=true requires live attach status".to_string());
    }
    if attempt.attach_attempted && !live_statuses.contains(&attempt.status) {
        return Err("attach_attempted=true requires live attach status".to_string());
    }
    if attempt.map_create_attempted {
        return Err("map_create_attempted must be false".to_string());
    }
    if attempt.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if attempt.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if attempt.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if attempt.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if attempt.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if attempt.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if attempt.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if attempt.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    Ok(())
}

/// Map a live attach executor status to a stable human-readable label.
pub fn live_attach_executor_status_label(status: EbpfLiveAttachExecutorStatus) -> &'static str {
    status.as_str()
}
