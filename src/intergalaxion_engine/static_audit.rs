// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Final static safety audit model for the Intergalaxion Engine.
//!
//! Phase I-10A adds a final audit-only model that verifies I-0 through I-9
//! remain safe, inert, hidden, and model-only. This phase must NOT load
//! eBPF programs, attach them, create maps, open ring buffers, read live
//! kernel events, pin maps, enforce, mutate, or expose public CLI. The
//! audit is pure and deterministic: it inspects prior phase models but
//! performs no I/O, no kernel operations, and no process mutation.

use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    validate_attach_plan, EbpfAttachPlan,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::{
    execute_live_attach_disabled, validate_live_attach_executor_result,
    validate_live_attach_gate_decision, EbpfLiveAttachExecutorResult, EbpfLiveAttachGateDecision,
};
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::{
    validate_loader_boundary_plan, EbpfLoaderBoundaryPlan,
};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    validate_program_skeleton_set, EbpfProgramSkeletonSet,
};
use crate::intergalaxion_engine::live_readiness::{
    validate_readiness_gate, IntergalaxionReadinessGate, IntergalaxionReadinessLevel,
};

/// Status of the final static safety audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntergalaxionStaticAuditStatus {
    /// All checks passed — the branch is safe for future attach spike.
    #[default]
    Passed,
    /// One or more blocking violations detected.
    Failed,
    /// Non-blocking issues detected; audit not fully clean.
    Warning,
}

impl IntergalaxionStaticAuditStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Warning => "warning",
        }
    }
}

/// A single finding from the static safety audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionStaticAuditFinding {
    /// Machine-readable finding code.
    pub code: String,
    /// Human-readable finding message.
    pub message: String,
    /// The status this finding contributes.
    pub status: IntergalaxionStaticAuditStatus,
    /// Whether this finding is blocking (forces Failed).
    pub blocking: bool,
}

/// Input to the static safety audit evaluation.
///
/// Combines all prior phase models (I-0 through I-9) into a single
/// struct for the final audit. The evaluator inspects these models
/// but does NOT perform any live kernel operations, file I/O, or
/// process mutation.
#[derive(Debug, Clone)]
pub struct IntergalaxionStaticAuditInput {
    /// I-5 readiness gate.
    pub readiness_gate: IntergalaxionReadinessGate,
    /// I-6 program skeleton set.
    pub program_skeleton_set: EbpfProgramSkeletonSet,
    /// I-7 loader boundary plan.
    pub loader_plan: EbpfLoaderBoundaryPlan,
    /// I-8 attach plan.
    pub attach_plan: EbpfAttachPlan,
    /// I-9 live attach gate decision.
    pub live_attach_decision: EbpfLiveAttachGateDecision,
    /// I-9 executor result.
    pub executor_result: EbpfLiveAttachExecutorResult,
    /// Whether the public CLI is expected to be hidden (must be true).
    pub public_cli_expected_hidden: bool,
    /// Whether the stable CLI is expected unchanged (must be true).
    pub stable_cli_expected_unchanged: bool,
    /// Whether the usage JSON schema is expected unchanged (must be true).
    pub usage_schema_expected_unchanged: bool,
    /// Whether the ledger JSON schema is expected unchanged (must be true).
    pub ledger_schema_expected_unchanged: bool,
}

/// Output of the static safety audit evaluation.
///
/// All operation flags default to false. The audit never performs live
/// operations — it only inspects prior phase models and verifies invariants.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntergalaxionStaticAuditReport {
    /// The phase label for this audit (always "I-10A").
    pub phase: String,
    /// Whether phases I-0 through I-9 were audited.
    pub audited_i0_to_i9: bool,
    /// Whether the branch is ready for a future real attach spike.
    pub ready_for_real_attach_spike: bool,
    /// The overall audit status.
    pub status: IntergalaxionStaticAuditStatus,
    /// Individual findings from the audit.
    pub findings: Vec<IntergalaxionStaticAuditFinding>,
    /// Whether a public CLI is exposed.
    pub public_cli_exposed: bool,
    /// Whether the stable CLI was changed.
    pub stable_cli_changed: bool,
    /// Whether the usage JSON schema was changed.
    pub usage_schema_changed: bool,
    /// Whether the ledger JSON schema was changed.
    pub ledger_schema_changed: bool,
    /// Whether a program load was performed.
    pub program_load_performed: bool,
    /// Whether an attach was performed.
    pub attach_performed: bool,
    /// Whether a map create was performed.
    pub map_create_performed: bool,
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
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default static audit input.
///
/// All fields use their safest defaults: empty models, hidden public
/// CLI, unchanged schemas. The executor result is constructed from
/// a disabled decision to ensure safe defaults.
pub fn default_static_audit_input() -> IntergalaxionStaticAuditInput {
    IntergalaxionStaticAuditInput {
        readiness_gate: IntergalaxionReadinessGate::default(),
        program_skeleton_set: EbpfProgramSkeletonSet::default(),
        loader_plan: EbpfLoaderBoundaryPlan::default(),
        attach_plan: EbpfAttachPlan::default(),
        live_attach_decision: EbpfLiveAttachGateDecision::default(),
        executor_result: execute_live_attach_disabled(&EbpfLiveAttachGateDecision::default()),
        public_cli_expected_hidden: true,
        stable_cli_expected_unchanged: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

/// Evaluate the final static safety audit from accumulated phase
/// models.
///
/// This function is pure and deterministic. It inspects the provided
/// input models but does NOT perform any live kernel operations, file
/// I/O, or process mutation. It never calls BPF load APIs, attach APIs,
/// map creation APIs, ring buffer APIs, or any kernel mutation APIs.
///
/// # Evaluation logic
///
/// 1. **Phase label**: Always "I-10A".
/// 2. **Scope**: `audited_i0_to_i9` always true.
/// 3. **Operation flag checks**: Any true operation flag in the decision
///    or executor result produces a blocking finding and Failed status.
/// 4. **Schema invariant checks**: Any expected-hidden/unchanged flag
///    that is false produces a blocking finding.
/// 5. **Model safety checks**: Unsafe loader plan, unsafe skeleton set,
///    or unsafe attach plan produces a blocking finding.
/// 6. **Executor check**: Executor attempted=true or refused=false
///    produces a blocking finding.
/// 7. **Ready for attach spike**: Requires Passed status with executor
///    disabled, all model validations passing, and all schema invariants
///    intact.
pub fn evaluate_static_audit(
    input: &IntergalaxionStaticAuditInput,
) -> IntergalaxionStaticAuditReport {
    let mut findings: Vec<IntergalaxionStaticAuditFinding> = Vec::new();
    let mut has_blocking = false;

    // ── Operation flag checks from live attach gate decision ───────────

    if input.live_attach_decision.program_load_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_program_load_performed"),
            message: String::from("live attach decision reports program load was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.attach_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_attach_performed"),
            message: String::from("live attach decision reports attach was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.map_create_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_map_create_performed"),
            message: String::from("live attach decision reports map create was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.ring_buffer_opened {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_ring_buffer_opened"),
            message: String::from("live attach decision reports ring buffer was opened"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.live_kernel_read_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_live_kernel_read_performed"),
            message: String::from("live attach decision reports live kernel read was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.map_pin_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_map_pin_performed"),
            message: String::from("live attach decision reports map pin was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.enforcement_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_enforcement_performed"),
            message: String::from("live attach decision reports enforcement was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.packet_drop_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_packet_drop_performed"),
            message: String::from("live attach decision reports packet drop was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.mutation_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_mutation_performed"),
            message: String::from("live attach decision reports mutation was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.live_attach_decision.public_cli_exposed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("decision_public_cli_exposed"),
            message: String::from("live attach decision reports public CLI was exposed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }

    // ── Executor result checks ──────────────────────────────────────────

    if input.executor_result.attempted {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_attempted"),
            message: String::from("executor result reports an attach was attempted"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if !input.executor_result.refused {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_not_refused"),
            message: String::from("executor result reports attach was not refused"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.program_load_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_program_load_performed"),
            message: String::from("executor result reports program load was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.attach_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_attach_performed"),
            message: String::from("executor result reports attach was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.map_create_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_map_create_performed"),
            message: String::from("executor result reports map create was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.ring_buffer_opened {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_ring_buffer_opened"),
            message: String::from("executor result reports ring buffer was opened"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.live_kernel_read_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_live_kernel_read_performed"),
            message: String::from("executor result reports live kernel read was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.map_pin_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_map_pin_performed"),
            message: String::from("executor result reports map pin was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.enforcement_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_enforcement_performed"),
            message: String::from("executor result reports enforcement was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.packet_drop_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_packet_drop_performed"),
            message: String::from("executor result reports packet drop was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.executor_result.mutation_performed {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("executor_mutation_performed"),
            message: String::from("executor result reports mutation was performed"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }

    // ── Schema invariant checks ───────────────────────────────────────

    if !input.public_cli_expected_hidden {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("public_cli_not_hidden"),
            message: String::from("public CLI is not expected to be hidden"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if !input.stable_cli_expected_unchanged {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("stable_cli_changed"),
            message: String::from("stable CLI is expected to be unchanged but is not"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if !input.usage_schema_expected_unchanged {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("usage_schema_changed"),
            message: String::from("usage JSON schema is expected to be unchanged but is not"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("ledger_schema_changed"),
            message: String::from("ledger JSON schema is expected to be unchanged but is not"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }

    // ── Model safety checks ──────────────────────────────────────────

    if validate_loader_boundary_plan(&input.loader_plan).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_loader_plan"),
            message: String::from("loader boundary plan has unsafe flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if validate_program_skeleton_set(&input.program_skeleton_set).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_skeleton_set"),
            message: String::from("program skeleton set has unsafe flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if validate_attach_plan(&input.attach_plan).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_attach_plan"),
            message: String::from("attach plan has unsafe operation flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if validate_live_attach_gate_decision(&input.live_attach_decision).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_live_attach_decision"),
            message: String::from("live attach gate decision has unsafe flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if validate_live_attach_executor_result(&input.executor_result).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_executor_result"),
            message: String::from("live attach executor result has unsafe flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }

    // ── Readiness gate safety check ─────────────────────────────────────

    if validate_readiness_gate(&input.readiness_gate).is_err() {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("unsafe_readiness_gate"),
            message: String::from("readiness gate has unsafe operation flags"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }
    if input.readiness_gate.level == IntergalaxionReadinessLevel::Blocked {
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("readiness_gate_blocked"),
            message: String::from("readiness gate is in blocked state"),
            status: IntergalaxionStaticAuditStatus::Failed,
            blocking: true,
        });
        has_blocking = true;
    }

    // ── Determine status ──────────────────────────────────────────────

    let status = if has_blocking {
        IntergalaxionStaticAuditStatus::Failed
    } else {
        // Warning path reserved for future non-blocking findings.
        findings.push(IntergalaxionStaticAuditFinding {
            code: String::from("audit_passed"),
            message: String::from("I-0 through I-9 audited successfully; all invariants hold"),
            status: IntergalaxionStaticAuditStatus::Passed,
            blocking: false,
        });
        IntergalaxionStaticAuditStatus::Passed
    };

    // ── Determine ready_for_real_attach_spike ──────────────────────────

    let executor_disabled = input.live_attach_decision.executor_disabled;
    let gate_safe = validate_readiness_gate(&input.readiness_gate).is_ok()
        && input.readiness_gate.level != IntergalaxionReadinessLevel::Blocked;
    let loader_safe = validate_loader_boundary_plan(&input.loader_plan).is_ok();
    let skeleton_safe = validate_program_skeleton_set(&input.program_skeleton_set).is_ok();
    let attach_safe = validate_attach_plan(&input.attach_plan).is_ok();
    let decision_safe = validate_live_attach_gate_decision(&input.live_attach_decision).is_ok();
    let executor_safe = validate_live_attach_executor_result(&input.executor_result).is_ok();

    let ready_for_real_attach_spike = status == IntergalaxionStaticAuditStatus::Passed
        && executor_disabled
        && gate_safe
        && loader_safe
        && skeleton_safe
        && attach_safe
        && decision_safe
        && executor_safe
        && input.public_cli_expected_hidden
        && input.stable_cli_expected_unchanged
        && input.usage_schema_expected_unchanged
        && input.ledger_schema_expected_unchanged;

    // ── Build operation flags from combined inputs ────────────────────

    let program_load_performed = input.live_attach_decision.program_load_performed
        || input.executor_result.program_load_performed;
    let attach_performed =
        input.live_attach_decision.attach_performed || input.executor_result.attach_performed;
    let map_create_performed = input.live_attach_decision.map_create_performed
        || input.executor_result.map_create_performed;
    let ring_buffer_opened =
        input.live_attach_decision.ring_buffer_opened || input.executor_result.ring_buffer_opened;
    let live_kernel_read_performed = input.live_attach_decision.live_kernel_read_performed
        || input.executor_result.live_kernel_read_performed;
    let map_pin_performed =
        input.live_attach_decision.map_pin_performed || input.executor_result.map_pin_performed;
    let enforcement_performed = input.live_attach_decision.enforcement_performed
        || input.executor_result.enforcement_performed;
    let packet_drop_performed = input.live_attach_decision.packet_drop_performed
        || input.executor_result.packet_drop_performed;
    let mutation_performed =
        input.live_attach_decision.mutation_performed || input.executor_result.mutation_performed;
    let persistence_performed = false; // persistence is never performed in I-0..I-9

    IntergalaxionStaticAuditReport {
        phase: String::from("I-10A"),
        audited_i0_to_i9: true,
        ready_for_real_attach_spike,
        status,
        findings,
        public_cli_exposed: input.live_attach_decision.public_cli_exposed,
        stable_cli_changed: !input.stable_cli_expected_unchanged,
        usage_schema_changed: !input.usage_schema_expected_unchanged,
        ledger_schema_changed: !input.ledger_schema_expected_unchanged,
        program_load_performed,
        attach_performed,
        map_create_performed,
        ring_buffer_opened,
        live_kernel_read_performed,
        map_pin_performed,
        enforcement_performed,
        packet_drop_performed,
        mutation_performed,
        persistence_performed,
    }
}

/// Validate that a static audit report does not have any unsafe flags.
///
/// Returns `Ok(())` if the report is safe. Returns `Err(description)`
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
/// * `persistence_performed` is `true`
/// * `public_cli_exposed` is `true`
/// * `stable_cli_changed` is `true`
/// * `usage_schema_changed` is `true`
/// * `ledger_schema_changed` is `true`
pub fn validate_static_audit_report(report: &IntergalaxionStaticAuditReport) -> Result<(), String> {
    if report.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if report.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if report.map_create_performed {
        return Err("map_create_performed must be false".to_string());
    }
    if report.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if report.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if report.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if report.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if report.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if report.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if report.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if report.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if report.stable_cli_changed {
        return Err("stable_cli_changed must be false".to_string());
    }
    if report.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if report.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    Ok(())
}

/// Map a static audit status to a stable human-readable label.
pub fn static_audit_status_label(status: IntergalaxionStaticAuditStatus) -> &'static str {
    status.as_str()
}
