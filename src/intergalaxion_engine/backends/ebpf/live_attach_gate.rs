// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Live observer attach gate and disabled executor for the Intergalaxion
//! Engine.
//!
//! Phase I-9 adds the final explicit gate and disabled executor seam
//! before any real live observer attach. This phase defines the exact
//! consent bundle, preflight result, and executor refusal model that would
//! be required before a future live observer attach. It must still perform
//! no attach, no BPF load, no map creation, no ring buffer open, no live
//! kernel read, no map pin, no enforcement, and no packet drop.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    validate_attach_plan, EbpfAttachPlan,
};
use crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilityReport;
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::{
    validate_loader_boundary_plan, EbpfLoaderBoundaryPlan,
};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    validate_program_skeleton_set, EbpfProgramSkeletonSet,
};

/// Status of the live observer attach gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfLiveAttachGateStatus {
    /// Gate is explicitly disabled (default in I-9).
    #[default]
    Disabled,
    /// One or more consent flags are missing.
    MissingConsent,
    /// Preflight checks failed with a blocking reason.
    PreflightBlocked,
    /// All conditions met for future live attach consideration.
    FutureLiveAttachCandidate,
    /// Gate passed but the executor is explicitly disabled.
    ExecutorDisabled,
}

impl EbpfLiveAttachGateStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MissingConsent => "missing_consent",
            Self::PreflightBlocked => "preflight_blocked",
            Self::FutureLiveAttachCandidate => "future_live_attach_candidate",
            Self::ExecutorDisabled => "executor_disabled",
        }
    }
}

/// Explicit consent bundle for live observer attach.
///
/// Every field must be true for a future live attach to be considered.
/// Missing any consent flag prevents live attach candidacy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfLiveAttachConsent {
    /// Operator explicitly consents to live observer attach.
    pub explicit_live_observer_attach: bool,
    /// Operator acknowledges that root is required.
    pub explicit_root_acknowledgement: bool,
    /// Operator acknowledges that no enforcement will occur.
    pub explicit_no_enforcement_acknowledgement: bool,
    /// Operator acknowledges that no packet drop will occur.
    pub explicit_no_packet_drop_acknowledgement: bool,
    /// Operator acknowledges cleanup responsibility.
    pub explicit_cleanup_acknowledgement: bool,
    /// Whether rollback capability is required.
    pub rollback_required: bool,
    /// Operator label for audit trail.
    pub operator_label: String,
}

// Default for EbpfLiveAttachConsent is #[derive(Default)] above.

/// Preflight input combining all prior phase models and the consent
/// bundle for the live observer attach gate evaluation.
#[derive(Debug, Clone, Default)]
pub struct EbpfLiveAttachPreflight {
    /// I-8 attach plan evaluation result.
    pub attach_plan: EbpfAttachPlan,
    /// I-1 capability report.
    pub capability_report: EbpfCapabilityReport,
    /// I-7 loader boundary plan.
    pub loader_plan: EbpfLoaderBoundaryPlan,
    /// I-6 program skeleton set.
    pub skeleton_set: EbpfProgramSkeletonSet,
    /// Consent bundle.
    pub consent: EbpfLiveAttachConsent,
    /// Whether public CLI exposure was requested (must be false).
    pub public_cli_requested: bool,
}

// Default for EbpfLiveAttachPreflight is #[derive(Default)] above.

/// A single reason contributing to the live attach gate decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachGateReason {
    /// Machine-readable reason code.
    pub code: String,
    /// Human-readable reason message.
    pub message: String,
    /// Whether this reason is blocking.
    pub blocking: bool,
}

/// Output of the live attach gate evaluation.
///
/// All operation flags are always false — the gate only evaluates
/// model state, it never performs live operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfLiveAttachGateDecision {
    /// The determined gate status.
    pub status: EbpfLiveAttachGateStatus,
    /// Whether this decision is a future live attach candidate.
    pub future_live_attach_candidate: bool,
    /// Whether the executor is disabled (always true in I-9).
    pub executor_disabled: bool,
    /// Reasons contributing to the gate decision.
    pub reasons: Vec<EbpfLiveAttachGateReason>,
    /// Whether a program load was performed (always false in I-9).
    pub program_load_performed: bool,
    /// Whether an attach was performed (always false in I-9).
    pub attach_performed: bool,
    /// Whether a map create was performed (always false in I-9).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-9).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-9).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-9).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-9).
    pub enforcement_performed: bool,
    /// Whether a packet drop was performed (always false in I-9).
    pub packet_drop_performed: bool,
    /// Whether mutation was performed (always false in I-9).
    pub mutation_performed: bool,
    /// Whether public CLI was exposed (always false in I-9).
    pub public_cli_exposed: bool,
}

/// Result of the disabled live attach executor.
///
/// The executor is always disabled in I-9. It always refuses and never
/// performs any live operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachExecutorResult {
    /// Whether an attach was attempted (always false in I-9).
    pub attempted: bool,
    /// Whether the executor refused (always true in I-9).
    pub refused: bool,
    /// Reason for refusal.
    pub reason: String,
    /// The gate decision that led to this executor result.
    pub decision: EbpfLiveAttachGateDecision,
    /// Whether a program load was performed (always false in I-9).
    pub program_load_performed: bool,
    /// Whether an attach was performed (always false in I-9).
    pub attach_performed: bool,
    /// Whether a map create was performed (always false in I-9).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-9).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-9).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-9).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-9).
    pub enforcement_performed: bool,
    /// Whether a packet drop was performed (always false in I-9).
    pub packet_drop_performed: bool,
    /// Whether mutation was performed (always false in I-9).
    pub mutation_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default consent bundle (all flags false, no label).
pub fn default_live_attach_consent() -> EbpfLiveAttachConsent {
    EbpfLiveAttachConsent::default()
}

/// Create a default preflight input (all safe defaults).
///
/// Uses default values from all prior phase models, empty consent,
/// no public CLI.
pub fn default_live_attach_preflight() -> EbpfLiveAttachPreflight {
    EbpfLiveAttachPreflight::default()
}

/// Evaluate the live observer attach gate from preflight models.
///
/// This function is pure and deterministic. It inspects the provided
/// preflight models but does NOT perform any live kernel operations,
/// file I/O, or process mutation.
///
/// # Evaluation logic
///
/// 1. **Public CLI check**: `public_cli_requested=true` forces
///    `PreflightBlocked`.
/// 2. **Consent check**: Missing any consent flag forces
///    `MissingConsent`.
/// 3. **Preflight checks**: Unsafe attach plan, unsafe loader plan,
///    unsafe skeleton set, or insufficient capability report forces
///    `PreflightBlocked`.
/// 4. **Future live attach candidate**: Requires all preflight checks
///    pass, all consent flags true, and nonempty operator label. Even
///    with all conditions met, the executor remains disabled.
/// 5. **Default**: If no conditions are met, the gate remains
///    `Disabled`.
pub fn evaluate_live_attach_gate(
    preflight: &EbpfLiveAttachPreflight,
) -> EbpfLiveAttachGateDecision {
    let mut reasons: Vec<EbpfLiveAttachGateReason> = Vec::new();

    let mut decision_flags = EbpfLiveAttachGateDecision {
        status: EbpfLiveAttachGateStatus::Disabled,
        future_live_attach_candidate: false,
        executor_disabled: true,
        reasons: Vec::new(),
        program_load_performed: false,
        attach_performed: false,
        map_create_performed: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        public_cli_exposed: false,
    };

    // ── Public CLI check ──────────────────────────────────────────────

    if preflight.public_cli_requested {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("public_cli_requested"),
            message: String::from("public CLI exposure is not permitted in live attach gate"),
            blocking: true,
        });
        decision_flags.status = EbpfLiveAttachGateStatus::PreflightBlocked;
        decision_flags.reasons = reasons;
        return decision_flags;
    }

    // ── Consent check ─────────────────────────────────────────────────

    let c = &preflight.consent;
    if !c.explicit_live_observer_attach {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_live_observer_attach"),
            message: String::from("explicit live observer attach consent is missing"),
            blocking: false,
        });
    }
    if !c.explicit_root_acknowledgement {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_root_acknowledgement"),
            message: String::from("explicit root acknowledgement is missing"),
            blocking: false,
        });
    }
    if !c.explicit_no_enforcement_acknowledgement {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_no_enforcement"),
            message: String::from("explicit no-enforcement acknowledgement is missing"),
            blocking: false,
        });
    }
    if !c.explicit_no_packet_drop_acknowledgement {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_no_packet_drop"),
            message: String::from("explicit no-packet-drop acknowledgement is missing"),
            blocking: false,
        });
    }
    if !c.explicit_cleanup_acknowledgement {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_cleanup"),
            message: String::from("explicit cleanup acknowledgement is missing"),
            blocking: false,
        });
    }
    if !c.rollback_required {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_rollback"),
            message: String::from("rollback required flag is not set"),
            blocking: false,
        });
    }
    if c.operator_label.is_empty() {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("consent_operator_label"),
            message: String::from("operator label is empty"),
            blocking: false,
        });
    }

    let has_missing_consent = reasons.iter().any(|r| !r.blocking);
    if has_missing_consent {
        decision_flags.status = EbpfLiveAttachGateStatus::MissingConsent;
        decision_flags.reasons = reasons;
        return decision_flags;
    }

    // ── Preflight safety checks ──────────────────────────────────────

    if validate_attach_plan(&preflight.attach_plan).is_err() {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("unsafe_attach_plan"),
            message: String::from("attach plan has unsafe operation flags"),
            blocking: true,
        });
    }
    if validate_loader_boundary_plan(&preflight.loader_plan).is_err() {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("unsafe_loader_plan"),
            message: String::from("loader boundary plan has unsafe flags"),
            blocking: true,
        });
    }
    if validate_program_skeleton_set(&preflight.skeleton_set).is_err() {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("unsafe_skeleton_set"),
            message: String::from("skeleton set has unsafe operation flags"),
            blocking: true,
        });
    }
    if !preflight.capability_report.observer_ready && !preflight.capability_report.attach_candidate
    {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("insufficient_capability"),
            message: String::from("capability report is not observer-ready or attach-candidate"),
            blocking: true,
        });
    }

    let has_blocking = reasons.iter().any(|r| r.blocking);
    if has_blocking {
        decision_flags.status = EbpfLiveAttachGateStatus::PreflightBlocked;
        decision_flags.reasons = reasons;
        return decision_flags;
    }

    // ── Future live attach candidate check ────────────────────────────

    let attach_ready = preflight.attach_plan.future_attach_candidate;
    let attach_valid = validate_attach_plan(&preflight.attach_plan).is_ok();
    let loader_valid = validate_loader_boundary_plan(&preflight.loader_plan).is_ok();
    let skeleton_safe = validate_program_skeleton_set(&preflight.skeleton_set).is_ok();
    let cap_sufficient =
        preflight.capability_report.observer_ready || preflight.capability_report.attach_candidate;

    if attach_ready && attach_valid && loader_valid && skeleton_safe && cap_sufficient {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("future_live_attach_candidate"),
            message: String::from(
                "all conditions met for future live attach candidate; executor remains disabled",
            ),
            blocking: false,
        });
        decision_flags.status = EbpfLiveAttachGateStatus::FutureLiveAttachCandidate;
        decision_flags.future_live_attach_candidate = true;
        decision_flags.reasons = reasons;
        return decision_flags;
    }

    if !attach_ready {
        reasons.push(EbpfLiveAttachGateReason {
            code: String::from("attach_plan_not_candidate"),
            message: String::from("attach plan is not a future attach candidate"),
            blocking: false,
        });
    }

    decision_flags.status = EbpfLiveAttachGateStatus::Disabled;
    decision_flags.reasons = reasons;
    decision_flags
}

/// Execute a disabled live attach operation.
///
/// The executor is always disabled in I-9. It always refuses and never
/// performs any live operation regardless of the gate decision.
pub fn execute_live_attach_disabled(
    decision: &EbpfLiveAttachGateDecision,
) -> EbpfLiveAttachExecutorResult {
    EbpfLiveAttachExecutorResult {
        attempted: false,
        refused: true,
        reason: String::from("executor is disabled in I-9; no live attach performed"),
        decision: decision.clone(),
        program_load_performed: false,
        attach_performed: false,
        map_create_performed: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
    }
}

/// Validate that a live attach gate decision does not have any unsafe
/// flags.
///
/// Returns `Ok(())` if the decision is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `program_load_performed` is `true`
/// * `attach_performed` is `true`
/// * `map_create_performed` is `true`
/// * `ring_buffer_opened` is `true`
/// * `live_kernel_read_performed` is `true`
/// * `map_pin_performed` is `true`
/// * `enforcement_performed` is `true`
/// * `packet_drop_performed` is `true`
/// * `mutation_performed` is `true`
/// * `public_cli_exposed` is `true`
pub fn validate_live_attach_gate_decision(
    decision: &EbpfLiveAttachGateDecision,
) -> Result<(), String> {
    if decision.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if decision.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if decision.map_create_performed {
        return Err("map_create_performed must be false".to_string());
    }
    if decision.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if decision.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if decision.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if decision.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if decision.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if decision.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if decision.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    Ok(())
}

/// Validate that a live attach executor result does not have any unsafe
/// flags.
///
/// Returns `Ok(())` if the result is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `attempted` is `true`
/// * `refused` is `false`
/// * Any operation flag is `true`
pub fn validate_live_attach_executor_result(
    result: &EbpfLiveAttachExecutorResult,
) -> Result<(), String> {
    if result.attempted {
        return Err("attempted must be false".to_string());
    }
    if !result.refused {
        return Err("refused must be true".to_string());
    }
    if result.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if result.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if result.map_create_performed {
        return Err("map_create_performed must be false".to_string());
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
    if result.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    Ok(())
}

/// Map a live attach gate status to a stable human-readable label.
pub fn live_attach_gate_status_label(status: EbpfLiveAttachGateStatus) -> &'static str {
    status.as_str()
}
