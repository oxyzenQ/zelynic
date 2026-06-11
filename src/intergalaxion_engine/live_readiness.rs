// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Live-readiness gate model for the Intergalaxion Engine.
//!
//! Phase I-5 adds a pure model-only readiness gate that combines I-1
//! capability detection, I-2 probe plan safety, I-3 event/ring-buffer
//! model safety, and I-4 decoder/ledger bridge safety. This phase
//! decides whether a future observer attach could be planned later,
//! but it must NOT perform attach, load programs, create maps, open ring
//! buffers, read live kernel events, pin maps, enforce, mutate, or
//! expose CLI.

use crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilityReport;
use crate::intergalaxion_engine::backends::ebpf::capability::EbpfReadinessLevel as EbpfCapReadiness;
use crate::intergalaxion_engine::backends::ebpf::decoder::EbpfDecodeReport;
use crate::intergalaxion_engine::backends::ebpf::probe_plan::{
    validate_probe_plan_safety, EbpfProbePlan,
};
use crate::intergalaxion_engine::backends::ebpf::ringbuf::{
    validate_ring_buffer_plan, EbpfRingBufferPlan,
};
use crate::intergalaxion_engine::ledger_bridge::event_bridge::IntergalaxionLedgerBridgeBatch;

/// Overall readiness level for the Intergalaxion Engine.
///
/// The readiness gate evaluates accumulated phase models (I-1 through
/// I-4) to determine whether the engine is in a position where future
/// observer attach planning could be considered. All levels are
/// model-only — no live kernel operations are performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntergalaxionReadinessLevel {
    /// One or more hard blocks prevent any further readiness.
    Blocked,
    /// The model layer exists but observer capabilities are incomplete.
    #[default]
    ModelOnly,
    /// Observer capabilities are present but future attach planning is
    /// not yet consented or conditions are not fully met.
    ObserverCandidate,
    /// All conditions are met for future attach planning consideration.
    /// This does NOT mean attach has been or will be performed.
    FutureAttachPlanningCandidate,
}

impl IntergalaxionReadinessLevel {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::ModelOnly => "model_only",
            Self::ObserverCandidate => "observer_candidate",
            Self::FutureAttachPlanningCandidate => "future_attach_planning_candidate",
        }
    }
}

/// A single reason contributing to the readiness gate decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionReadinessReason {
    /// Machine-readable reason code.
    pub code: String,
    /// Human-readable reason message.
    pub message: String,
    /// Whether this reason is blocking (forces Blocked level).
    pub blocking: bool,
}

/// Input to the readiness gate evaluation.
///
/// Combines reports and plans from all prior Intergalaxion phases.
/// The evaluator inspects these models but does NOT perform any live
/// kernel operations.
#[derive(Debug, Clone, Default)]
pub struct IntergalaxionReadinessInput {
    /// I-1 capability detection report.
    pub capability_report: EbpfCapabilityReport,
    /// I-2 probe plan.
    pub probe_plan: EbpfProbePlan,
    /// I-3 ring buffer plan.
    pub ring_buffer_plan: EbpfRingBufferPlan,
    /// I-4 decoder report.
    pub decode_report: EbpfDecodeReport,
    /// I-4 ledger bridge batch.
    pub bridge_batch: IntergalaxionLedgerBridgeBatch,
    /// Whether the operator has explicitly consented to future attach
    /// planning.
    pub explicit_future_attach_consent: bool,
    /// Whether root is required for future attach (informational in I-5).
    pub root_required_for_future_attach: bool,
    /// Whether public CLI exposure was requested (must be false).
    pub public_cli_requested: bool,
}

/// Output of the readiness gate evaluation.
///
/// All operation flags are always false — the gate only evaluates
/// model state, it never performs live operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntergalaxionReadinessGate {
    /// The determined readiness level.
    pub level: IntergalaxionReadinessLevel,
    /// Whether the engine is an observer candidate.
    pub observer_candidate: bool,
    /// Whether the engine is a future attach planning candidate.
    pub future_attach_planning_candidate: bool,
    /// Reasons contributing to the readiness decision.
    pub reasons: Vec<IntergalaxionReadinessReason>,
    /// Whether an attach was performed (always false in I-5).
    pub attach_performed: bool,
    /// Whether a program load was performed (always false in I-5).
    pub program_load_performed: bool,
    /// Whether a map create was performed (always false in I-5).
    pub map_create_performed: bool,
    /// Whether a ring buffer was opened (always false in I-5).
    pub ring_buffer_opened: bool,
    /// Whether a live kernel read was performed (always false in I-5).
    pub live_kernel_read_performed: bool,
    /// Whether a map pin was performed (always false in I-5).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-5).
    pub enforcement_performed: bool,
    /// Whether mutation was performed (always false in I-5).
    pub mutation_performed: bool,
    /// Whether public CLI was exposed (always false in I-5).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default readiness input (all safe defaults, no consent).
///
/// The default input uses safe defaults from all prior phases:
/// capability report with all facts unknown (→ Unavailable → Blocked),
/// safe probe plan, safe ring buffer plan, empty decode report,
/// empty bridge batch, no consent, no public CLI.
pub fn default_readiness_input() -> IntergalaxionReadinessInput {
    IntergalaxionReadinessInput::default()
}

/// Evaluate readiness gate from accumulated phase models.
///
/// This function is pure and deterministic. It inspects the provided
/// input models but does NOT perform any live kernel operations, file
/// I/O, or process mutation.
///
/// # Evaluation logic
///
/// 1. **Blocking checks**: Any unsafe condition (public CLI requested,
///    unavailable capabilities, unsafe probe/ring-buffer/decode/bridge
///    models) forces `Blocked`.
/// 2. **Observer candidate**: If no blocks and capability report says
///    observer-ready → `ObserverCandidate`.
/// 3. **Future attach planning candidate**: If observer-ready and
///    explicit consent is granted → `FutureAttachPlanningCandidate`.
/// 4. **Model only**: If no blocks but observer capabilities are
///    incomplete → `ModelOnly`.
pub fn evaluate_intergalaxion_readiness(
    input: &IntergalaxionReadinessInput,
) -> IntergalaxionReadinessGate {
    let mut reasons: Vec<IntergalaxionReadinessReason> = Vec::new();

    // ── Blocking checks ──────────────────────────────────────────────

    if input.public_cli_requested {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("public_cli_requested"),
            message: String::from("public CLI exposure is not permitted in this phase"),
            blocking: true,
        });
    }

    if input.capability_report.readiness == EbpfCapReadiness::Unavailable {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("capability_unavailable"),
            message: String::from("eBPF capabilities are unavailable"),
            blocking: true,
        });
    }

    if validate_probe_plan_safety(&input.probe_plan).is_err() {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("unsafe_probe_plan"),
            message: String::from("probe plan has unsafe operation flags enabled"),
            blocking: true,
        });
    }

    if validate_ring_buffer_plan(&input.ring_buffer_plan).is_err() {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("unsafe_ring_buffer_plan"),
            message: String::from("ring buffer plan has unsafe operation flags enabled"),
            blocking: true,
        });
    }

    if input.decode_report.live_kernel_read_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("decode_live_kernel_read"),
            message: String::from("decoder report indicates live kernel read was performed"),
            blocking: true,
        });
    }

    if input.decode_report.ring_buffer_opened {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("decode_ring_buffer_opened"),
            message: String::from("decoder report indicates ring buffer was opened"),
            blocking: true,
        });
    }

    if input.decode_report.mutation_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("decode_mutation"),
            message: String::from("decoder report indicates mutation was performed"),
            blocking: true,
        });
    }

    if input.bridge_batch.filesystem_write_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("bridge_filesystem_write"),
            message: String::from("bridge batch indicates filesystem write was performed"),
            blocking: true,
        });
    }

    if input.bridge_batch.persistence_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("bridge_persistence"),
            message: String::from("bridge batch indicates persistence was performed"),
            blocking: true,
        });
    }

    if input.bridge_batch.enforcement_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("bridge_enforcement"),
            message: String::from("bridge batch indicates enforcement was performed"),
            blocking: true,
        });
    }

    if input.bridge_batch.mutation_performed {
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("bridge_mutation"),
            message: String::from("bridge batch indicates mutation was performed"),
            blocking: true,
        });
    }

    // ── Determine level ─────────────────────────────────────────────

    let has_blocking = reasons.iter().any(|r| r.blocking);

    if has_blocking {
        return IntergalaxionReadinessGate {
            level: IntergalaxionReadinessLevel::Blocked,
            observer_candidate: false,
            future_attach_planning_candidate: false,
            reasons,
            // All operation flags remain false — the gate never performs
            // live actions.
            attach_performed: false,
            program_load_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            public_cli_exposed: false,
        };
    }

    // No blocking reasons — determine non-blocked level.

    if input.capability_report.observer_ready {
        if input.explicit_future_attach_consent {
            reasons.push(IntergalaxionReadinessReason {
                code: String::from("future_attach_consent_granted"),
                message: String::from(
                    "explicit future attach consent granted; all sub-models safe",
                ),
                blocking: false,
            });
            return IntergalaxionReadinessGate {
                level: IntergalaxionReadinessLevel::FutureAttachPlanningCandidate,
                observer_candidate: true,
                future_attach_planning_candidate: true,
                reasons,
                attach_performed: false,
                program_load_performed: false,
                map_create_performed: false,
                ring_buffer_opened: false,
                live_kernel_read_performed: false,
                map_pin_performed: false,
                enforcement_performed: false,
                mutation_performed: false,
                public_cli_exposed: false,
            };
        }
        reasons.push(IntergalaxionReadinessReason {
            code: String::from("observer_ready"),
            message: String::from(
                "observer capabilities are available but future attach consent not granted",
            ),
            blocking: false,
        });
        return IntergalaxionReadinessGate {
            level: IntergalaxionReadinessLevel::ObserverCandidate,
            observer_candidate: true,
            future_attach_planning_candidate: false,
            reasons,
            attach_performed: false,
            program_load_performed: false,
            map_create_performed: false,
            ring_buffer_opened: false,
            live_kernel_read_performed: false,
            map_pin_performed: false,
            enforcement_performed: false,
            mutation_performed: false,
            public_cli_exposed: false,
        };
    }

    // Capabilities are present but observer-ready criteria not met.
    reasons.push(IntergalaxionReadinessReason {
        code: String::from("model_only"),
        message: String::from("model layer exists but observer capabilities are incomplete"),
        blocking: false,
    });
    IntergalaxionReadinessGate {
        level: IntergalaxionReadinessLevel::ModelOnly,
        observer_candidate: false,
        future_attach_planning_candidate: false,
        reasons,
        attach_performed: false,
        program_load_performed: false,
        map_create_performed: false,
        ring_buffer_opened: false,
        live_kernel_read_performed: false,
        map_pin_performed: false,
        enforcement_performed: false,
        mutation_performed: false,
        public_cli_exposed: false,
    }
}

/// Validate that a readiness gate does not have any operation flags set.
///
/// Returns `Ok(())` if all operation flags are false. Returns
/// `Err(description)` if any operation flag is true.
///
/// # Rejected flags
///
/// * `attach_performed`
/// * `program_load_performed`
/// * `map_create_performed`
/// * `ring_buffer_opened`
/// * `live_kernel_read_performed`
/// * `map_pin_performed`
/// * `enforcement_performed`
/// * `mutation_performed`
/// * `public_cli_exposed`
pub fn validate_readiness_gate(gate: &IntergalaxionReadinessGate) -> Result<(), String> {
    if gate.attach_performed {
        return Err("attach_performed must be false".to_string());
    }
    if gate.program_load_performed {
        return Err("program_load_performed must be false".to_string());
    }
    if gate.map_create_performed {
        return Err("map_create_performed must be false".to_string());
    }
    if gate.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if gate.live_kernel_read_performed {
        return Err("live_kernel_read_performed must be false".to_string());
    }
    if gate.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if gate.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if gate.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if gate.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    Ok(())
}

/// Map a readiness level to a stable human-readable label.
pub fn readiness_level_label(level: IntergalaxionReadinessLevel) -> &'static str {
    level.as_str()
}
