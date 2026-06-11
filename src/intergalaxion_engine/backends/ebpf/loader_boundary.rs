// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF loader boundary model for the Intergalaxion Engine.
//!
//! Phase I-7 adds a pure model-only loader boundary that defines what a
//! future loader would require, what it would refuse, and how it reports
//! disabled state. This phase must NOT load anything, NOT call BPF load
//! APIs, NOT attach programs, NOT create maps, NOT open ring buffers,
//! NOT read live kernel events, NOT pin maps/programs, NOT require root
//! for tests, NOT expose public CLI, and NOT add enforcement.

use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    validate_program_skeleton_set, EbpfProgramSkeletonSet,
};
use crate::intergalaxion_engine::live_readiness::{
    IntergalaxionReadinessGate, IntergalaxionReadinessLevel,
};

/// Status of the eBPF loader boundary.
///
/// The loader boundary is always disabled in I-7. No userspace loader
/// implementation exists. No BPF program loading occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfLoaderBoundaryStatus {
    /// Loader is explicitly disabled (default and only state in I-7).
    #[default]
    Disabled,
    /// Loader boundary exists as a model-only construct.
    ModelOnly,
    /// Loader boundary would be ready but is blocked by safety constraints.
    FutureReadyBlocked,
    /// Kernel loading is not supported in this phase.
    KernelLoadUnsupported,
}

impl EbpfLoaderBoundaryStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ModelOnly => "model_only",
            Self::FutureReadyBlocked => "future_ready_blocked",
            Self::KernelLoadUnsupported => "kernel_load_unsupported",
        }
    }
}

/// A single reason contributing to the loader boundary decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLoaderBoundaryReason {
    /// Machine-readable reason code.
    pub code: String,
    /// Human-readable reason message.
    pub message: String,
    /// Whether this reason is blocking.
    pub blocking: bool,
}

/// Input to the loader boundary evaluation.
///
/// Combines the I-5 readiness gate and I-6 skeleton set to determine
/// whether a future loader could be considered. The evaluator inspects
/// these models but does NOT perform any live kernel operations.
#[derive(Debug, Clone, Default)]
pub struct EbpfLoaderBoundaryInput {
    /// I-5 readiness gate evaluation result.
    pub readiness_gate: IntergalaxionReadinessGate,
    /// I-6 program skeleton set.
    pub skeleton_set: EbpfProgramSkeletonSet,
    /// Whether the operator has explicitly consented to loader activation.
    pub explicit_loader_consent: bool,
    /// Whether an object source has been declared for future compilation.
    pub object_source_declared: bool,
    /// Whether public CLI exposure was requested (must be false).
    pub public_cli_requested: bool,
    /// Whether root is required for future load (informational in I-7).
    pub root_required_for_future_load: bool,
}

/// Output of the loader boundary evaluation.
///
/// All operation flags are always false — the loader boundary only
/// evaluates model state, it never performs live operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfLoaderBoundaryPlan {
    /// The determined loader boundary status.
    pub status: EbpfLoaderBoundaryStatus,
    /// Whether the loader is available (always false in I-7).
    pub loader_available: bool,
    /// Whether the loader is disabled (always true in I-7).
    pub loader_disabled: bool,
    /// Whether an object source is declared.
    pub object_source_declared: bool,
    /// Whether the plan is a candidate for future loading (model only).
    pub future_load_candidate: bool,
    /// Reasons contributing to the loader boundary decision.
    pub reasons: Vec<EbpfLoaderBoundaryReason>,
    /// Whether a program load was performed (always false in I-7).
    pub program_load_performed: bool,
    /// Whether an attach was performed (always false in I-7).
    pub attach_performed: bool,
    /// Whether a map create was performed (always false in I-7).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-7).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-7).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-7).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-7).
    pub enforcement_performed: bool,
    /// Whether mutation was performed (always false in I-7).
    pub mutation_performed: bool,
    /// Whether public CLI was exposed (always false in I-7).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default loader boundary input (all safe defaults).
///
/// The default input uses safe defaults: an empty readiness gate
/// (which defaults to ModelOnly with no consent), an empty skeleton
/// set, no loader consent, no object source declared, no public CLI,
/// root not required for future load.
pub fn default_loader_boundary_input() -> EbpfLoaderBoundaryInput {
    EbpfLoaderBoundaryInput::default()
}

/// Evaluate loader boundary from readiness gate and skeleton set.
///
/// This function is pure and deterministic. It inspects the provided
/// input models but does NOT perform any live kernel operations, file
/// I/O, or process mutation.
///
/// # Evaluation logic
///
/// 1. **Blocking checks**: Any unsafe condition (public CLI requested,
///    unsafe readiness gate level, unsafe skeleton set) forces a
///    disabled or blocked status.
/// 2. **Future load candidate**: Requires readiness gate at
///    `FutureAttachPlanningCandidate`, skeleton set validates safe,
///    explicit loader consent, object source declared, and public
///    CLI not requested. Even with all conditions met, no actual
///    loading occurs.
/// 3. **Default**: If no conditions for future load candidate are met,
///    the boundary remains `Disabled`.
pub fn evaluate_loader_boundary(input: &EbpfLoaderBoundaryInput) -> EbpfLoaderBoundaryPlan {
    let mut reasons: Vec<EbpfLoaderBoundaryReason> = Vec::new();

    // ── Blocking checks ──────────────────────────────────────────────

    if input.public_cli_requested {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("public_cli_requested"),
            message: String::from("public CLI exposure is not permitted in loader boundary"),
            blocking: true,
        });
    }

    if input.readiness_gate.level == IntergalaxionReadinessLevel::Blocked {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("readiness_gate_blocked"),
            message: String::from("readiness gate is in blocked state"),
            blocking: true,
        });
    }

    if validate_program_skeleton_set(&input.skeleton_set).is_err() {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("unsafe_skeleton_set"),
            message: String::from("skeleton set has unsafe operation flags"),
            blocking: true,
        });
    }

    // ── Determine status ─────────────────────────────────────────────

    let has_blocking = reasons.iter().any(|r| r.blocking);

    if has_blocking {
        return EbpfLoaderBoundaryPlan {
            status: EbpfLoaderBoundaryStatus::Disabled,
            loader_available: false,
            loader_disabled: true,
            object_source_declared: false,
            future_load_candidate: false,
            reasons,
            // All operation flags remain false — the boundary never
            // performs live actions.
            program_load_performed: false,
            attach_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            public_cli_exposed: false,
        };
    }

    // No blocking reasons — check for future load candidate conditions.

    let gate_ready =
        input.readiness_gate.level == IntergalaxionReadinessLevel::FutureAttachPlanningCandidate;
    let skeleton_safe = validate_program_skeleton_set(&input.skeleton_set).is_ok();
    let consent = input.explicit_loader_consent;
    let obj_source = input.object_source_declared;
    let no_public_cli = !input.public_cli_requested;

    if gate_ready && skeleton_safe && consent && obj_source && no_public_cli {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("future_load_candidate"),
            message: String::from(
                "all conditions met for future load candidate; no actual load performed",
            ),
            blocking: false,
        });
        return EbpfLoaderBoundaryPlan {
            status: EbpfLoaderBoundaryStatus::ModelOnly,
            loader_available: false,
            loader_disabled: true,
            object_source_declared: true,
            future_load_candidate: true,
            reasons,
            program_load_performed: false,
            attach_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            public_cli_exposed: false,
        };
    }

    // Conditions not fully met — remain disabled.
    if !gate_ready {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("readiness_gate_not_future_attach"),
            message: String::from(
                "readiness gate is not at future attach planning candidate level",
            ),
            blocking: false,
        });
    }
    if !consent {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("loader_consent_missing"),
            message: String::from("explicit loader consent is not granted"),
            blocking: false,
        });
    }
    if !obj_source {
        reasons.push(EbpfLoaderBoundaryReason {
            code: String::from("object_source_not_declared"),
            message: String::from("object source is not declared"),
            blocking: false,
        });
    }

    EbpfLoaderBoundaryPlan {
        status: EbpfLoaderBoundaryStatus::Disabled,
        loader_available: false,
        loader_disabled: true,
        object_source_declared: false,
        future_load_candidate: false,
        reasons,
        program_load_performed: false,
        attach_performed: false,
        map_create_performed: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        mutation_performed: false,
        public_cli_exposed: false,
    }
}

/// Validate that a loader boundary plan does not have any unsafe flags.
///
/// Returns `Ok(())` if the plan is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `loader_available` is `true`
/// * `loader_disabled` is `false`
/// * `program_load_performed` is `true`
/// * `attach_performed` is `true`
/// * `map_create_performed` is `true`
/// * `ring_buffer_opened` is `true`
/// * `live_kernel_read_performed` is `true`
/// * `map_pin_performed` is `true`
/// * `enforcement_performed` is `true`
/// * `mutation_performed` is `true`
/// * `public_cli_exposed` is `true`
pub fn validate_loader_boundary_plan(plan: &EbpfLoaderBoundaryPlan) -> Result<(), String> {
    if plan.loader_available {
        return Err("loader_available must be false".to_string());
    }
    if !plan.loader_disabled {
        return Err("loader_disabled must be true".to_string());
    }
    if plan.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if plan.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if plan.map_create_performed {
        return Err("map_create_performed must be false".to_string());
    }
    if plan.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if plan.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if plan.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if plan.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if plan.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if plan.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    Ok(())
}

/// Map a loader boundary status to a stable human-readable label.
pub fn loader_boundary_status_label(status: EbpfLoaderBoundaryStatus) -> &'static str {
    status.as_str()
}
