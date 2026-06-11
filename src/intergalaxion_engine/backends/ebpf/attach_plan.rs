// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Safe attach plan model for the Intergalaxion Engine.
//!
//! Phase I-8 adds a pure model-only attach planning layer that defines
//! how a future attach operation would be planned and audited. This phase
//! must NOT attach anything, NOT call BPF load APIs, NOT call attach
//! APIs, NOT create maps, NOT open ring buffers, NOT read live kernel
//! events, NOT pin maps/programs, NOT require root for tests, NOT
//! expose public CLI, and NOT add enforcement.

use crate::intergalaxion_engine::backends::ebpf::loader_boundary::{
    validate_loader_boundary_plan, EbpfLoaderBoundaryPlan,
};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    validate_program_skeleton_set, EbpfProgramSkeletonSet,
};

/// The kind of eBPF attach target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfAttachTargetKind {
    /// Socket filter observer (passive byte counting on a socket).
    #[default]
    SocketFilter,
    /// cgroup skb observer (reads traffic at a cgroup boundary).
    CgroupSkb,
    /// Tracepoint observer (hooks into kernel tracepoints).
    Tracepoint,
}

impl EbpfAttachTargetKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SocketFilter => "socket_filter",
            Self::CgroupSkb => "cgroup_skb",
            Self::Tracepoint => "tracepoint",
        }
    }
}

/// Status of an attach plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfAttachPlanStatus {
    /// Attach is explicitly disabled (default in I-8).
    #[default]
    Disabled,
    /// Plan exists as a model-only construct.
    PlanOnly,
    /// All conditions are met for future attach consideration.
    FutureAttachCandidate,
    /// Attach plan is rejected due to safety violations.
    Rejected,
}

impl EbpfAttachPlanStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::PlanOnly => "plan_only",
            Self::FutureAttachCandidate => "future_attach_candidate",
            Self::Rejected => "rejected",
        }
    }
}

/// A single reason contributing to the attach plan decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfAttachPlanReason {
    /// Machine-readable reason code.
    pub code: String,
    /// Human-readable reason message.
    pub message: String,
    /// Whether this reason is blocking.
    pub blocking: bool,
}

/// A target descriptor for a future eBPF attach operation.
///
/// Describes what would be attached, where, and how. In I-8 this is
/// a planning model only — no actual attach occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfAttachTarget {
    /// Unique identifier for this attach target.
    pub target_id: String,
    /// The kind of attach target.
    pub kind: EbpfAttachTargetKind,
    /// ELF section name for the program entry point.
    pub section_name: String,
    /// Network interface name (required for SocketFilter).
    pub interface_name: Option<String>,
    /// cgroup path (required for CgroupSkb).
    pub cgroup_path: Option<String>,
    /// Tracepoint category (required for Tracepoint).
    pub tracepoint_category: Option<String>,
    /// Tracepoint name (required for Tracepoint).
    pub tracepoint_name: Option<String>,
    /// Human-readable description of this target.
    pub target_description: String,
}

impl Default for EbpfAttachTarget {
    fn default() -> Self {
        Self {
            target_id: String::from("default_attach_target"),
            kind: EbpfAttachTargetKind::SocketFilter,
            section_name: String::from("socket/observer"),
            interface_name: Some(String::from("eth0")),
            cgroup_path: None,
            tracepoint_category: None,
            tracepoint_name: None,
            target_description: String::from(
                "Default socket filter attach target for planning purposes",
            ),
        }
    }
}

/// Input to the attach plan evaluation.
///
/// Combines the I-7 loader boundary plan, I-6 skeleton set, and an
/// attach target to determine whether future attach could be planned.
/// The evaluator inspects these models but does NOT perform any live
/// kernel operations.
#[derive(Debug, Clone, Default)]
pub struct EbpfAttachPlanInput {
    /// I-7 loader boundary plan.
    pub loader_plan: EbpfLoaderBoundaryPlan,
    /// I-6 program skeleton set.
    pub skeleton_set: EbpfProgramSkeletonSet,
    /// The attach target descriptor.
    pub target: EbpfAttachTarget,
    /// Whether the operator has explicitly consented to attach planning.
    pub explicit_attach_consent: bool,
    /// Whether rollback capability is required (must be true).
    pub rollback_required: bool,
    /// Whether public CLI exposure was requested (must be false).
    pub public_cli_requested: bool,
    /// Whether root is required for future attach (informational in I-8).
    pub root_required_for_future_attach: bool,
}

/// Output of the attach plan evaluation.
///
/// All operation flags are always false — the attach plan only evaluates
/// model state, it never performs live operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfAttachPlan {
    /// The determined attach plan status.
    pub status: EbpfAttachPlanStatus,
    /// The attach target descriptor.
    pub target: EbpfAttachTarget,
    /// Whether this plan is a candidate for future attach (model only).
    pub future_attach_candidate: bool,
    /// Reasons contributing to the attach plan decision.
    pub reasons: Vec<EbpfAttachPlanReason>,
    /// Whether an attach was performed (always false in I-8).
    pub attach_performed: bool,
    /// Whether a program load was performed (always false in I-8).
    pub program_load_performed: bool,
    /// Whether a map create was performed (always false in I-8).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-8).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-8).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-8).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-8).
    pub enforcement_performed: bool,
    /// Whether mutation was performed (always false in I-8).
    pub mutation_performed: bool,
    /// Whether a packet drop was performed (always false in I-8).
    pub packet_drop_performed: bool,
    /// Whether public CLI was exposed (always false in I-8).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default attach target (socket filter on eth0).
///
/// The default target is the safest configuration for planning:
/// socket filter on eth0, no cgroup path, no tracepoint.
pub fn default_attach_target() -> EbpfAttachTarget {
    EbpfAttachTarget::default()
}

/// Create a socket filter attach target with the given interface name.
pub fn socket_filter_attach_target(interface_name: &str) -> EbpfAttachTarget {
    EbpfAttachTarget {
        target_id: format!("socket_filter_{interface_name}"),
        kind: EbpfAttachTargetKind::SocketFilter,
        section_name: String::from("socket/observer"),
        interface_name: Some(String::from(interface_name)),
        cgroup_path: None,
        tracepoint_category: None,
        tracepoint_name: None,
        target_description: format!("Socket filter attach target on interface {interface_name}"),
    }
}

/// Create a cgroup skb attach target with the given cgroup path.
pub fn cgroup_skb_attach_target(cgroup_path: &str) -> EbpfAttachTarget {
    EbpfAttachTarget {
        target_id: format!("cgroup_skb_{cgroup_path}"),
        kind: EbpfAttachTargetKind::CgroupSkb,
        section_name: String::from("cgroup/skb/observer"),
        interface_name: None,
        cgroup_path: Some(String::from(cgroup_path)),
        tracepoint_category: None,
        tracepoint_name: None,
        target_description: format!("cgroup skb attach target at {cgroup_path}"),
    }
}

/// Create a tracepoint attach target with the given category and name.
pub fn tracepoint_attach_target(category: &str, name: &str) -> EbpfAttachTarget {
    EbpfAttachTarget {
        target_id: format!("tracepoint_{category}_{name}"),
        kind: EbpfAttachTargetKind::Tracepoint,
        section_name: String::from("tracepoint/observer"),
        interface_name: None,
        cgroup_path: None,
        tracepoint_category: Some(String::from(category)),
        tracepoint_name: Some(String::from(name)),
        target_description: format!("Tracepoint attach target at {category}/{name}"),
    }
}

/// Create a default attach plan input (all safe defaults).
///
/// The default input uses safe defaults: a default loader boundary
/// plan (disabled), an empty skeleton set, a default socket filter
/// target, no attach consent, rollback not required, no public CLI.
pub fn default_attach_plan_input() -> EbpfAttachPlanInput {
    EbpfAttachPlanInput::default()
}

/// Evaluate attach plan from loader boundary plan, skeleton set, and
/// target.
///
/// This function is pure and deterministic. It inspects the provided
/// input models but does NOT perform any live kernel operations, file
/// I/O, or process mutation.
///
/// # Evaluation logic
///
/// 1. **Blocking checks**: Any unsafe condition (public CLI requested,
///    unsafe target, unsafe skeleton set, unsafe loader plan) forces
///    a rejected or disabled status.
/// 2. **Future attach candidate**: Requires loader plan with
///    `future_load_candidate=true`, skeleton set validates safe, target
///    validates safe, explicit attach consent, rollback required, and
///    public CLI not requested. Even with all conditions met, no actual
///    attach occurs.
/// 3. **Default**: If no conditions for future attach candidate are met,
///    the plan remains `Disabled`.
pub fn evaluate_attach_plan(input: &EbpfAttachPlanInput) -> EbpfAttachPlan {
    let mut reasons: Vec<EbpfAttachPlanReason> = Vec::new();

    // ── Blocking checks ──────────────────────────────────────────────

    if input.public_cli_requested {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("public_cli_requested"),
            message: String::from("public CLI exposure is not permitted in attach plan"),
            blocking: true,
        });
    }

    if validate_attach_target(&input.target).is_err() {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("unsafe_target"),
            message: String::from("attach target has validation errors"),
            blocking: true,
        });
    }

    if validate_program_skeleton_set(&input.skeleton_set).is_err() {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("unsafe_skeleton_set"),
            message: String::from("skeleton set has unsafe operation flags"),
            blocking: true,
        });
    }

    if validate_loader_boundary_plan(&input.loader_plan).is_err() {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("unsafe_loader_plan"),
            message: String::from("loader boundary plan has unsafe flags"),
            blocking: true,
        });
    }

    // ── Determine status ─────────────────────────────────────────────

    let has_blocking = reasons.iter().any(|r| r.blocking);

    if has_blocking {
        return EbpfAttachPlan {
            status: EbpfAttachPlanStatus::Rejected,
            target: input.target.clone(),
            future_attach_candidate: false,
            reasons,
            // All operation flags remain false — the plan never
            // performs live actions.
            attach_performed: false,
            program_load_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            packet_drop_performed: false,
            public_cli_exposed: false,
        };
    }

    // No blocking reasons — check for future attach candidate conditions.

    let loader_ready = input.loader_plan.future_load_candidate;
    let loader_valid = validate_loader_boundary_plan(&input.loader_plan).is_ok();
    let skeleton_safe = validate_program_skeleton_set(&input.skeleton_set).is_ok();
    let target_valid = validate_attach_target(&input.target).is_ok();
    let consent = input.explicit_attach_consent;
    let rollback = input.rollback_required;
    let no_public_cli = !input.public_cli_requested;

    if loader_ready
        && loader_valid
        && skeleton_safe
        && target_valid
        && consent
        && rollback
        && no_public_cli
    {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("future_attach_candidate"),
            message: String::from(
                "all conditions met for future attach candidate; no actual attach performed",
            ),
            blocking: false,
        });
        return EbpfAttachPlan {
            status: EbpfAttachPlanStatus::FutureAttachCandidate,
            target: input.target.clone(),
            future_attach_candidate: true,
            reasons,
            attach_performed: false,
            program_load_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            packet_drop_performed: false,
            public_cli_exposed: false,
        };
    }

    // Conditions not fully met — remain disabled.
    if !loader_ready {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("loader_not_future_load_candidate"),
            message: String::from("loader boundary plan is not a future load candidate"),
            blocking: false,
        });
    }
    if !consent {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("attach_consent_missing"),
            message: String::from("explicit attach consent is not granted"),
            blocking: false,
        });
    }
    if !rollback {
        reasons.push(EbpfAttachPlanReason {
            code: String::from("rollback_not_required"),
            message: String::from("rollback capability is not required"),
            blocking: false,
        });
    }

    EbpfAttachPlan {
        status: EbpfAttachPlanStatus::Disabled,
        target: input.target.clone(),
        future_attach_candidate: false,
        reasons,
        attach_performed: false,
        program_load_performed: false,
        map_create_performed: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        mutation_performed: false,
        packet_drop_performed: false,
        public_cli_exposed: false,
    }
}

/// Validate that an attach target has all required fields for its kind.
///
/// Returns `Ok(())` if the target is valid. Returns `Err(description)`
/// if any validation error is detected.
///
/// # Validation rules
///
/// * `target_id` must not be empty.
/// * `section_name` must not be empty.
/// * `SocketFilter` requires `interface_name` to be `Some`.
/// * `CgroupSkb` requires `cgroup_path` to be `Some`.
/// * `Tracepoint` requires both `tracepoint_category` and `tracepoint_name`
///   to be `Some`.
/// * `CgroupSkb` cgroup path must not contain parent traversal (`..`).
pub fn validate_attach_target(target: &EbpfAttachTarget) -> Result<(), String> {
    if target.target_id.is_empty() {
        return Err("target_id must not be empty".to_string());
    }
    if target.section_name.is_empty() {
        return Err("section_name must not be empty".to_string());
    }
    match target.kind {
        EbpfAttachTargetKind::SocketFilter => {
            if target.interface_name.is_none() {
                return Err("socket filter target requires interface_name".to_string());
            }
        }
        EbpfAttachTargetKind::CgroupSkb => {
            if target.cgroup_path.is_none() {
                return Err("cgroup skb target requires cgroup_path".to_string());
            }
            let path = target.cgroup_path.as_deref().unwrap_or("");
            if path.contains("..") {
                return Err("cgroup path must not contain parent traversal".to_string());
            }
        }
        EbpfAttachTargetKind::Tracepoint => {
            if target.tracepoint_category.is_none() {
                return Err("tracepoint target requires tracepoint_category".to_string());
            }
            if target.tracepoint_name.is_none() {
                return Err("tracepoint target requires tracepoint_name".to_string());
            }
        }
    }
    Ok(())
}

/// Validate that an attach plan does not have any unsafe flags.
///
/// Returns `Ok(())` if the plan is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `attach_performed` is `true`
/// * `program_load_performed` is `true`
/// * `map_create_performed` is `true`
/// * `ring_buffer_opened` is `true`
/// * `live_kernel_read_performed` is `true`
/// * `map_pin_performed` is `true`
/// * `enforcement_performed` is `true`
/// * `mutation_performed` is `true`
/// * `packet_drop_performed` is `true`
/// * `public_cli_exposed` is `true`
pub fn validate_attach_plan(plan: &EbpfAttachPlan) -> Result<(), String> {
    if plan.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if plan.program_load_performed {
        return Err("program_load_performed must be false".to_string());
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
    if plan.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if plan.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    Ok(())
}

/// Map an attach target kind to a stable human-readable label.
pub fn attach_target_kind_label(kind: EbpfAttachTargetKind) -> &'static str {
    kind.as_str()
}

/// Map an attach plan status to a stable human-readable label.
pub fn attach_plan_status_label(status: EbpfAttachPlanStatus) -> &'static str {
    status.as_str()
}
