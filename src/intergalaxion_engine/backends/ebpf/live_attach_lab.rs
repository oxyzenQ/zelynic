// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Feature-gated local live attach lab execution for the Intergalaxion Engine.
//!
//! Phase I-10E adds the first minimal feature-gated local live attach lab
//! execution path. This phase introduces a private lab executor seam that
//! is reachable ONLY behind the `intergalaxion-live-attach-lab` Cargo
//! feature (disabled by default). In the default build, all evaluation
//! paths return safe, inert results with no live kernel operations.
//!
//! # Design constraints (I-10E)
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
//! * Artifact absence must be reported honestly.
//! * Detach proof must not fake success.
//! * Any attach success must require detach before result is accepted.

use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::{
    default_detach_proof, default_live_attach_artifact_contract, default_local_attach_smoke_recipe,
    validate_live_attach_artifact_contract, validate_local_attach_smoke_recipe, EbpfDetachProof,
    EbpfLiveAttachArtifactContract, EbpfLiveAttachArtifactStatus, EbpfLocalAttachSmokeRecipe,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_executor::{
    default_live_attach_lab_input, evaluate_live_attach_lab_attempt, EbpfLiveAttachLabInput,
};

/// Status of the live attach lab execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachLabStatus {
    /// The intergalaxion-live-attach-lab feature is not enabled.
    FeatureDisabled,
    /// Lab gate validation rejected the execution.
    LabGateRejected,
    /// The eBPF artifact is missing or unavailable.
    ArtifactMissing,
    /// The attach target kind is not supported.
    UnsupportedTarget,
    /// Live attach is not yet implemented for this target.
    AttachNotImplemented,
    /// A live attach was attempted.
    AttachAttempted,
    /// A live attach succeeded.
    AttachSucceeded,
    /// A live attach failed.
    AttachFailed,
    /// Programs were detached cleanly after attach.
    DetachedCleanly,
    /// Detach failed after attach.
    DetachFailed,
}

impl EbpfLiveAttachLabStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::LabGateRejected => "lab_gate_rejected",
            Self::ArtifactMissing => "artifact_missing",
            Self::UnsupportedTarget => "unsupported_target",
            Self::AttachNotImplemented => "attach_not_implemented",
            Self::AttachAttempted => "attach_attempted",
            Self::AttachSucceeded => "attach_succeeded",
            Self::AttachFailed => "attach_failed",
            Self::DetachedCleanly => "detached_cleanly",
            Self::DetachFailed => "detach_failed",
        }
    }
}

/// Input to the live attach lab execution evaluation.
///
/// Combines the I-10C lab input, I-10D artifact contract, smoke recipe,
/// and explicit safety flags. The evaluator is pure and deterministic
/// in the default build — no live kernel operations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachLabExecutionInput {
    /// The I-10C lab input (gate decision, runbook, etc.).
    pub lab_input: EbpfLiveAttachLabInput,
    /// The I-10D artifact contract.
    pub artifact_contract: EbpfLiveAttachArtifactContract,
    /// The I-10D local smoke recipe.
    pub smoke_recipe: EbpfLocalAttachSmokeRecipe,
    /// Whether immediate detach is required after attach (must be true).
    pub require_immediate_detach: bool,
    /// Whether ring buffer open is allowed (must be false in I-10E).
    pub allow_ring_buffer_open: bool,
    /// Whether live event stream read is allowed (must be false in I-10E).
    pub allow_event_stream_read: bool,
    /// Whether map pin is allowed (must be false in I-10E).
    pub allow_map_pin: bool,
    /// Whether enforcement is allowed (must be false).
    pub allow_enforcement: bool,
    /// Whether packet drop is allowed (must be false).
    pub allow_packet_drop: bool,
    /// Whether persistence is allowed (must be false).
    pub allow_persistence: bool,
}

/// Result of evaluating the live attach lab execution.
///
/// All operation flags are always false in the default build. The
/// evaluation is pure and deterministic. An embedded detach proof
/// tracks cleanup state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachLabExecutionResult {
    /// The determined lab execution status.
    pub status: EbpfLiveAttachLabStatus,
    /// Whether an attach was attempted.
    pub attempted: bool,
    /// Whether a program was attached.
    pub attached: bool,
    /// Whether a program was detached.
    pub detached: bool,
    /// Whether this is observer-only (always true).
    pub observer_only: bool,
    /// Whether the feature is enabled.
    pub feature_enabled: bool,
    /// Whether this is local-lab-only (always true).
    pub local_lab_only: bool,
    /// Human-readable reason for the status.
    pub reason: String,
    /// The detach proof model.
    pub detach_proof: EbpfDetachProof,
    /// Whether a program load was attempted.
    pub program_load_attempted: bool,
    /// Whether an attach was attempted.
    pub attach_attempted: bool,
    /// Whether a map create was attempted.
    pub map_create_attempted: bool,
    /// Whether a ring buffer was opened.
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed.
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed.
    pub map_pin_performed: bool,
    /// Whether enforcement was performed.
    pub enforcement_performed: bool,
    /// Whether a packet drop was performed.
    pub packet_drop_performed: bool,
    /// Whether mutation was performed.
    pub mutation_performed: bool,
    /// Whether persistence was performed.
    pub persistence_performed: bool,
    /// Whether public CLI was exposed.
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default live attach lab execution input.
///
/// All fields are in their safest configuration: feature disabled,
/// artifact missing, no unsafe flags set.
pub fn default_live_attach_lab_execution_input() -> EbpfLiveAttachLabExecutionInput {
    EbpfLiveAttachLabExecutionInput {
        lab_input: default_live_attach_lab_input(),
        artifact_contract: default_live_attach_artifact_contract(),
        smoke_recipe: default_local_attach_smoke_recipe(),
        require_immediate_detach: true,
        allow_ring_buffer_open: false,
        allow_event_stream_read: false,
        allow_map_pin: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

/// Build a safe base result with all operation flags false.
pub(crate) fn safe_base_result_internal() -> EbpfLiveAttachLabExecutionResult {
    EbpfLiveAttachLabExecutionResult {
        status: EbpfLiveAttachLabStatus::FeatureDisabled,
        attempted: false,
        attached: false,
        detached: false,
        observer_only: true,
        feature_enabled: false,
        local_lab_only: true,
        reason: String::new(),
        detach_proof: default_detach_proof(),
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
    }
}

/// Evaluate the live attach lab execution from input.
///
/// This function is pure and deterministic. In the default build
/// (feature disabled), it always returns a safe result. The evaluation
/// chain checks feature gate, lab input safety, artifact contract,
/// smoke recipe, and explicit safety flags before determining whether
/// a future attach could proceed.
///
/// # Evaluation logic
///
/// 1. **Feature gate**: Feature disabled forces `FeatureDisabled`.
/// 2. **Immediate detach**: `require_immediate_detach=false` is rejected.
/// 3. **Forbidden flags**: Any unsafe allow_* flag forces
///    `LabGateRejected`.
/// 4. **Smoke recipe validation**: Unsafe recipe forces `LabGateRejected`.
/// 5. **Artifact contract validation**: Unsafe contract forces
///    `LabGateRejected`.
/// 6. **Executor evaluation**: Delegates to I-10C executor; unsafe
///    result forces corresponding lab status.
/// 7. **Artifact check**: `MissingArtifact` or unavailable bytes forces
///    `ArtifactMissing`.
/// 8. **Target support**: Currently all targets are supported but
///    attach is not yet implemented, so `AttachNotImplemented` is
///    returned when all gates pass.
pub fn evaluate_live_attach_lab_execution(
    input: &EbpfLiveAttachLabExecutionInput,
) -> EbpfLiveAttachLabExecutionResult {
    let base = safe_base_result_internal();

    // ── 1. Feature gate check ────────────────────────────────────────

    if !input.lab_input.explicit_local_lab_feature_enabled {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::FeatureDisabled,
            reason: String::from("intergalaxion-live-attach-lab feature is not enabled"),
            ..base
        };
    }

    let feature_base = EbpfLiveAttachLabExecutionResult {
        feature_enabled: true,
        ..base
    };

    // ── 2. Immediate detach required ────────────────────────────────

    if !input.require_immediate_detach {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("require_immediate_detach must be true"),
            ..feature_base
        };
    }

    // ── 3. Forbidden flags check ────────────────────────────────────

    if input.allow_ring_buffer_open {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_ring_buffer_open must be false in I-10E"),
            ..feature_base
        };
    }
    if input.allow_event_stream_read {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_event_stream_read must be false in I-10E"),
            ..feature_base
        };
    }
    if input.allow_map_pin {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_map_pin must be false in I-10E"),
            ..feature_base
        };
    }
    if input.allow_enforcement {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_enforcement must be false"),
            ..feature_base
        };
    }
    if input.allow_packet_drop {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_packet_drop must be false"),
            ..feature_base
        };
    }
    if input.allow_persistence {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("allow_persistence must be false"),
            ..feature_base
        };
    }

    // ── 4. Smoke recipe validation ──────────────────────────────────

    if validate_local_attach_smoke_recipe(&input.smoke_recipe).is_err() {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("smoke recipe validation failed"),
            ..feature_base
        };
    }

    // ── 5. Artifact contract validation ──────────────────────────────

    if validate_live_attach_artifact_contract(&input.artifact_contract).is_err() {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::LabGateRejected,
            reason: String::from("artifact contract validation failed"),
            ..feature_base
        };
    }

    // ── 6. Executor evaluation (I-10C delegate) ────────────────────

    let executor_attempt = evaluate_live_attach_lab_attempt(&input.lab_input);
    match executor_attempt.status {
        crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachExecutorStatus::FeatureDisabled => {
            return EbpfLiveAttachLabExecutionResult {
                status: EbpfLiveAttachLabStatus::FeatureDisabled,
                reason: String::from("executor feature gate blocked"),
                ..feature_base
            };
        }
        crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachExecutorStatus::GateRejected => {
            return EbpfLiveAttachLabExecutionResult {
                status: EbpfLiveAttachLabStatus::LabGateRejected,
                reason: String::from("executor gate rejected"),
                ..feature_base
            };
        }
        crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachExecutorStatus::UnsupportedTarget => {
            return EbpfLiveAttachLabExecutionResult {
                status: EbpfLiveAttachLabStatus::UnsupportedTarget,
                reason: String::from("attach target is unsupported"),
                ..feature_base
            };
        }
        crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachExecutorStatus::ObjectSourceMissing => {
            return EbpfLiveAttachLabExecutionResult {
                status: EbpfLiveAttachLabStatus::ArtifactMissing,
                reason: String::from("executor object source missing"),
                ..feature_base
            };
        }
        _ => {
            // Executor passed — continue to artifact checks.
        }
    }

    // ── 7. Artifact availability check ──────────────────────────────

    if input.artifact_contract.artifact_status == EbpfLiveAttachArtifactStatus::MissingArtifact {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::ArtifactMissing,
            reason: String::from("artifact status is MissingArtifact"),
            ..feature_base
        };
    }
    if input.artifact_contract.artifact_status == EbpfLiveAttachArtifactStatus::Unsupported {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::UnsupportedTarget,
            reason: String::from("artifact status is Unsupported"),
            ..feature_base
        };
    }
    if !input.lab_input.object_bytes_available {
        return EbpfLiveAttachLabExecutionResult {
            status: EbpfLiveAttachLabStatus::ArtifactMissing,
            reason: String::from("object bytes are not available"),
            ..feature_base
        };
    }

    // ── 8. Attach not yet implemented ────────────────────────────────

    // All model gates pass. In I-10E, the real attach code path is not
    // yet implemented. The feature-gated seam exists but returns
    // AttachNotImplemented honestly. A future phase would attempt
    // actual BPF load/attach here.
    EbpfLiveAttachLabExecutionResult {
        status: EbpfLiveAttachLabStatus::AttachNotImplemented,
        reason: String::from("all model gates pass; live attach not yet implemented in I-10E"),
        ..feature_base
    }
}

/// Validate that a live attach lab execution result does not have any
/// unsafe flags.
///
/// Returns `Ok(())` if the result is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
pub fn validate_live_attach_lab_execution_result(
    result: &EbpfLiveAttachLabExecutionResult,
) -> Result<(), String> {
    if result.attached && !result.attempted {
        return Err("attached=true requires attempted=true".to_string());
    }
    if result.detached && !result.attached {
        return Err("detached=true requires attached=true".to_string());
    }
    if matches!(result.status, EbpfLiveAttachLabStatus::AttachSucceeded) && !result.detached {
        return Err("AttachSucceeded requires detached=true".to_string());
    }
    if !result.observer_only {
        return Err("observer_only must be true".to_string());
    }
    if !result.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    if result.map_create_attempted {
        return Err("map_create_attempted must be false".to_string());
    }
    if result.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if result.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if result.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if result.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if result.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if result.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if result.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    // Reject fake detach success: detach_proof should not claim
    // DetachedCleanly if attach was not attempted.
    if matches!(
        result.detach_proof.status,
        EbpfDetachProofStatus::DetachedCleanly
    ) && !result.attempted
    {
        return Err("fake detach success: attach was not attempted".to_string());
    }
    Ok(())
}

/// Map a live attach lab status to a stable human-readable label.
pub fn live_attach_lab_status_label(status: EbpfLiveAttachLabStatus) -> &'static str {
    status.as_str()
}

// Re-export for convenience in this module.
use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::EbpfDetachProofStatus;
