// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Live attach spike runbook and hard gate contract for the Intergalaxion
//! Engine.
//!
//! Phase I-10B adds a deterministic runbook and hard gate contract that
//! freezes the exact human/operator checklist for a future live attach
//! spike. This phase must NOT implement real live attach, NOT call BPF
//! load APIs, NOT attach programs, NOT create maps, NOT open ring
//! buffers, NOT read live kernel events, NOT pin maps, NOT enforce, NOT
//! mutate, and NOT expose public CLI. The runbook is a pure model that
//! defines what conditions and steps would be required before a future
//! local-lab-only attach spike could proceed.

/// Status of the live attach spike runbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntergalaxionLiveAttachRunbookStatus {
    /// Runbook is in draft (initial state).
    #[default]
    Draft,
    /// Runbook is frozen and ready for review.
    Frozen,
    /// Runbook was rejected due to safety violations.
    Rejected,
}

impl IntergalaxionLiveAttachRunbookStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Frozen => "frozen",
            Self::Rejected => "rejected",
        }
    }
}

/// The kind of a runbook step in the live attach spike procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntergalaxionLiveAttachRunbookStepKind {
    /// Preflight safety checks before any attach consideration.
    Preflight,
    /// Explicit operator consent collection.
    OperatorConsent,
    /// Build integrity verification.
    BuildCheck,
    /// Host capability verification.
    CapabilityCheck,
    /// The attach window in which a future attach would occur.
    AttachWindow,
    /// Post-attach cleanup verification.
    Cleanup,
    /// Abort condition evaluation step.
    AbortCondition,
    /// Post-run audit verification.
    PostRunAudit,
}

impl IntergalaxionLiveAttachRunbookStepKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::OperatorConsent => "operator_consent",
            Self::BuildCheck => "build_check",
            Self::CapabilityCheck => "capability_check",
            Self::AttachWindow => "attach_window",
            Self::Cleanup => "cleanup",
            Self::AbortCondition => "abort_condition",
            Self::PostRunAudit => "post_run_audit",
        }
    }
}

/// A single step in the live attach spike runbook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionLiveAttachRunbookStep {
    /// Unique step identifier.
    pub step_id: String,
    /// The kind of step.
    pub kind: IntergalaxionLiveAttachRunbookStepKind,
    /// Human-readable step title.
    pub title: String,
    /// Whether this step is required.
    pub required: bool,
    /// Whether this step must be performed manually by an operator.
    pub must_be_manual: bool,
    /// Whether this step is allowed to mutate system state (always false
    /// in I-10B).
    pub can_mutate_system: bool,
    /// Human-readable step description.
    pub description: String,
}

/// A single abort condition in the live attach spike runbook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionLiveAttachAbortCondition {
    /// Machine-readable abort condition code.
    pub code: String,
    /// Human-readable abort condition description.
    pub description: String,
    /// Whether this condition is blocking (forces immediate abort).
    pub blocking: bool,
}

/// The live attach spike runbook and hard gate contract.
///
/// This model defines the exact checklist and conditions that must be
/// satisfied before a future local-lab-only live attach spike could
/// proceed. In I-10B the runbook is model-only: no actual attach
/// occurs, no BPF programs are loaded, no maps are created, and no
/// ring buffers are opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionLiveAttachRunbook {
    /// The phase label for this runbook (always "I-10B").
    pub phase: String,
    /// The current runbook status.
    pub status: IntergalaxionLiveAttachRunbookStatus,
    /// Whether this runbook is restricted to local lab only.
    pub local_lab_only: bool,
    /// Whether public CLI is allowed (always false in I-10B).
    pub public_cli_allowed: bool,
    /// Whether enforcement is allowed (always false in I-10B).
    pub enforcement_allowed: bool,
    /// Whether packet drop is allowed (always false in I-10B).
    pub packet_drop_allowed: bool,
    /// Whether persistence is allowed (always false in I-10B).
    pub persistence_allowed: bool,
    /// Whether root acknowledgement is required (always true).
    pub requires_root_acknowledgement: bool,
    /// Whether an explicit operator label is required (always true).
    pub requires_explicit_operator_label: bool,
    /// Whether a cleanup plan is required (always true).
    pub requires_cleanup_plan: bool,
    /// Ordered list of runbook steps.
    pub steps: Vec<IntergalaxionLiveAttachRunbookStep>,
    /// List of abort conditions.
    pub abort_conditions: Vec<IntergalaxionLiveAttachAbortCondition>,
    /// Whether a program load was performed (always false in I-10B).
    pub program_load_performed: bool,
    /// Whether an attach was performed (always false in I-10B).
    pub attach_performed: bool,
    /// Whether a map create was performed (always false in I-10B).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-10B).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-10B).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-10B).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-10B).
    pub enforcement_performed: bool,
    /// Whether a packet drop was performed (always false in I-10B).
    pub packet_drop_performed: bool,
    /// Whether mutation was performed (always false in I-10B).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false in I-10B).
    pub persistence_performed: bool,
    /// Whether public CLI was exposed (always false in I-10B).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default live attach spike runbook.
///
/// The default runbook contains all required steps, deterministic abort
/// conditions, and all safety flags in their safest configuration.
pub fn default_live_attach_runbook() -> IntergalaxionLiveAttachRunbook {
    IntergalaxionLiveAttachRunbook {
        phase: String::from("I-10B"),
        status: IntergalaxionLiveAttachRunbookStatus::Draft,
        local_lab_only: true,
        public_cli_allowed: false,
        enforcement_allowed: false,
        packet_drop_allowed: false,
        persistence_allowed: false,
        requires_root_acknowledgement: true,
        requires_explicit_operator_label: true,
        requires_cleanup_plan: true,
        steps: default_runbook_steps(),
        abort_conditions: default_abort_conditions(),
        program_load_performed: false,
        attach_performed: false,
        map_create_performed: false,
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

/// Create the default ordered runbook steps.
fn default_runbook_steps() -> Vec<IntergalaxionLiveAttachRunbookStep> {
    vec![
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("preflight-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::Preflight,
            title: String::from("Preflight Safety Verification"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Verify all I-0 through I-10A models are safe and no operation flags are set",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("consent-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::OperatorConsent,
            title: String::from("Explicit Operator Consent"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Collect explicit operator consent for local-lab-only live attach spike",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("build-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::BuildCheck,
            title: String::from("Build Integrity Check"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Verify release build passes all checks with no forbidden source patterns",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("capability-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::CapabilityCheck,
            title: String::from("Host Capability Verification"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Verify host has BTF, bpffs, CAP_BPF available for observer-only attach",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("attach-window-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::AttachWindow,
            title: String::from("Live Attach Window"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Operator-initiated attach window for observer-only spike in local lab",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("cleanup-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::Cleanup,
            title: String::from("Cleanup Verification"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Verify all programs detached, maps removed, ring buffers closed after spike",
            ),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("abort-cond-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::AbortCondition,
            title: String::from("Abort Condition Evaluation"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from("Evaluate all abort conditions before proceeding to attach"),
        },
        IntergalaxionLiveAttachRunbookStep {
            step_id: String::from("post-audit-01"),
            kind: IntergalaxionLiveAttachRunbookStepKind::PostRunAudit,
            title: String::from("Post-Run Audit"),
            required: true,
            must_be_manual: true,
            can_mutate_system: false,
            description: String::from(
                "Run static audit to verify no operation flags were set during spike",
            ),
        },
    ]
}

/// Create the default abort conditions.
fn default_abort_conditions() -> Vec<IntergalaxionLiveAttachAbortCondition> {
    vec![
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("public_cli_exposed"),
            description: String::from("public CLI was exposed during runbook execution"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("enforcement_detected"),
            description: String::from("enforcement was detected during runbook execution"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("packet_drop_detected"),
            description: String::from("packet drop was detected during runbook execution"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("mutation_detected"),
            description: String::from("kernel mutation was detected during runbook execution"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("persistence_detected"),
            description: String::from("persistence was detected during runbook execution"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("not_local_lab"),
            description: String::from("runbook is being executed outside local lab environment"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("missing_operator_label"),
            description: String::from("explicit operator label is missing"),
            blocking: true,
        },
        IntergalaxionLiveAttachAbortCondition {
            code: String::from("missing_cleanup_plan"),
            description: String::from("cleanup plan is missing or incomplete"),
            blocking: true,
        },
    ]
}

/// Validate that a live attach spike runbook does not have any unsafe
/// configuration or flags.
///
/// Returns `Ok(())` if the runbook is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `local_lab_only` is `false`
/// * `public_cli_allowed` is `true`
/// * `enforcement_allowed` is `true`
/// * `packet_drop_allowed` is `true`
/// * `persistence_allowed` is `true`
/// * `requires_root_acknowledgement` is `false`
/// * `requires_explicit_operator_label` is `false`
/// * `requires_cleanup_plan` is `false`
/// * Any operation flag is `true`
/// * `steps` is empty
/// * `abort_conditions` is empty
/// * Any required step has empty `title` or `description`
/// * Any abort condition has empty `code` or `description`
pub fn validate_live_attach_runbook(
    runbook: &IntergalaxionLiveAttachRunbook,
) -> Result<(), String> {
    if !runbook.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    if runbook.public_cli_allowed {
        return Err("public_cli_allowed must be false".to_string());
    }
    if runbook.enforcement_allowed {
        return Err("enforcement_allowed must be false".to_string());
    }
    if runbook.packet_drop_allowed {
        return Err("packet_drop_allowed must be false".to_string());
    }
    if runbook.persistence_allowed {
        return Err("persistence_allowed must be false".to_string());
    }
    if !runbook.requires_root_acknowledgement {
        return Err("requires_root_acknowledgement must be true".to_string());
    }
    if !runbook.requires_explicit_operator_label {
        return Err("requires_explicit_operator_label must be true".to_string());
    }
    if !runbook.requires_cleanup_plan {
        return Err("requires_cleanup_plan must be true".to_string());
    }
    if runbook.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if runbook.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if runbook.map_create_performed {
        return Err("map_create_performed must be false".to_string());
    }
    if runbook.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if runbook.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if runbook.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if runbook.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if runbook.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if runbook.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if runbook.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if runbook.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if runbook.steps.is_empty() {
        return Err("steps must not be empty".to_string());
    }
    if runbook.abort_conditions.is_empty() {
        return Err("abort_conditions must not be empty".to_string());
    }
    for step in &runbook.steps {
        if step.required && step.title.is_empty() {
            return Err(format!("required step {} has empty title", step.step_id));
        }
        if step.required && step.description.is_empty() {
            return Err(format!(
                "required step {} has empty description",
                step.step_id
            ));
        }
    }
    for cond in &runbook.abort_conditions {
        if cond.code.is_empty() {
            return Err("abort condition has empty code".to_string());
        }
        if cond.description.is_empty() {
            return Err("abort condition has empty description".to_string());
        }
    }
    Ok(())
}

/// Map a live attach runbook status to a stable human-readable label.
pub fn live_attach_runbook_status_label(
    status: IntergalaxionLiveAttachRunbookStatus,
) -> &'static str {
    status.as_str()
}

/// Map a live attach runbook step kind to a stable human-readable label.
pub fn live_attach_runbook_step_kind_label(
    kind: IntergalaxionLiveAttachRunbookStepKind,
) -> &'static str {
    kind.as_str()
}
