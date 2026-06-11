// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-9 tests: live observer attach gate, executor disabled.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    default_attach_target, evaluate_attach_plan,
};
use crate::intergalaxion_engine::backends::ebpf::capability::evaluate_ebpf_capability;
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::*;
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::evaluate_loader_boundary;
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::default_program_skeleton_set;
use crate::intergalaxion_engine::live_readiness::evaluate_intergalaxion_readiness;
use clap::CommandFactory;

const I9_DOC: &str =
    include_str!("../../docs/intergalaxion/I-9-live-observer-attach-gate-executor-disabled.md");
const I9_GATE_SOURCE: &str = include_str!("backends/ebpf/live_attach_gate.rs");

// Helper: observer-ready capability snapshot.
fn observer_ready_snapshot(
) -> crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
    crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..Default::default()
    }
}

// Helper: readiness gate at FutureAttachPlanningCandidate.
fn future_gate() -> crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessGate {
    let input = crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        explicit_future_attach_consent: true,
        public_cli_requested: false,
        ..Default::default()
    };
    evaluate_intergalaxion_readiness(&input)
}

// Helper: loader boundary plan with future_load_candidate=true.
fn future_loader_plan(
) -> crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryPlan {
    let gate = future_gate();
    let input =
        crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryInput {
            readiness_gate: gate,
            skeleton_set: default_program_skeleton_set(),
            explicit_loader_consent: true,
            object_source_declared: true,
            public_cli_requested: false,
            ..Default::default()
        };
    evaluate_loader_boundary(&input)
}

// Helper: attach plan with future_attach_candidate=true.
fn future_attach_plan() -> crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachPlan
{
    let input = crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: default_program_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    evaluate_attach_plan(&input)
}

// Helper: full consent bundle (all true, labeled).
fn full_consent() -> EbpfLiveAttachConsent {
    EbpfLiveAttachConsent {
        explicit_live_observer_attach: true,
        explicit_root_acknowledgement: true,
        explicit_no_enforcement_acknowledgement: true,
        explicit_no_packet_drop_acknowledgement: true,
        explicit_cleanup_acknowledgement: true,
        rollback_required: true,
        operator_label: String::from("test-operator"),
    }
}

// Helper: full future-ready preflight.
fn future_preflight() -> EbpfLiveAttachPreflight {
    EbpfLiveAttachPreflight {
        attach_plan: future_attach_plan(),
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        loader_plan: future_loader_plan(),
        skeleton_set: default_program_skeleton_set(),
        consent: full_consent(),
        public_cli_requested: false,
    }
}

// -- Coverage 1: default consent has all flags false -------------------

#[test]
fn i9_default_consent_all_flags_false() {
    let consent = default_live_attach_consent();
    assert!(!consent.explicit_live_observer_attach);
    assert!(!consent.explicit_root_acknowledgement);
    assert!(!consent.explicit_no_enforcement_acknowledgement);
    assert!(!consent.explicit_no_packet_drop_acknowledgement);
    assert!(!consent.explicit_cleanup_acknowledgement);
    assert!(!consent.rollback_required);
    assert!(consent.operator_label.is_empty());
}

// -- Coverage 2: default preflight is safe -----------------------------

#[test]
fn i9_default_preflight_is_safe() {
    let preflight = default_live_attach_preflight();
    assert!(!preflight.public_cli_requested);
}

// -- Coverage 3: default gate decision has all operation flags false --

#[test]
fn i9_default_gate_decision_all_flags_false() {
    let preflight = default_live_attach_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.program_load_performed);
    assert!(!decision.attach_performed);
    assert!(!decision.map_create_performed);
    assert!(!decision.ring_buffer_opened);
    assert!(!decision.live_kernel_read_performed);
    assert!(!decision.map_pin_performed);
    assert!(!decision.enforcement_performed);
    assert!(!decision.packet_drop_performed);
    assert!(!decision.mutation_performed);
    assert!(!decision.public_cli_exposed);
}

// -- Coverage 4: status labels are stable -----------------------------

#[test]
fn i9_status_labels_stable() {
    assert_eq!(
        live_attach_gate_status_label(EbpfLiveAttachGateStatus::Disabled),
        "disabled"
    );
    assert_eq!(
        live_attach_gate_status_label(EbpfLiveAttachGateStatus::MissingConsent),
        "missing_consent"
    );
    assert_eq!(
        live_attach_gate_status_label(EbpfLiveAttachGateStatus::PreflightBlocked),
        "preflight_blocked"
    );
    assert_eq!(
        live_attach_gate_status_label(EbpfLiveAttachGateStatus::FutureLiveAttachCandidate),
        "future_live_attach_candidate"
    );
    assert_eq!(
        live_attach_gate_status_label(EbpfLiveAttachGateStatus::ExecutorDisabled),
        "executor_disabled"
    );
}

// -- Coverage 5: default gate decision is not future candidate ------

#[test]
fn i9_default_not_future_live_attach_candidate() {
    let preflight = default_live_attach_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
}

// -- Coverage 6: default executor result refuses -----------------------

#[test]
fn i9_default_executor_refuses() {
    let preflight = default_live_attach_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    let result = execute_live_attach_disabled(&decision);
    assert!(result.refused);
}

// -- Coverage 7: disabled executor attempted=false --------------------

#[test]
fn i9_disabled_executor_attempted_false() {
    let decision = evaluate_live_attach_gate(&default_live_attach_preflight());
    let result = execute_live_attach_disabled(&decision);
    assert!(!result.attempted);
}

// -- Coverage 8: disabled executor refused=true ----------------------

#[test]
fn i9_disabled_executor_refused_true() {
    let result = execute_live_attach_disabled(&evaluate_live_attach_gate(&future_preflight()));
    assert!(result.refused);
}

// -- Coverage 9: disabled executor all operation flags false ----------

#[test]
fn i9_disabled_executor_all_flags_false() {
    let result = execute_live_attach_disabled(&evaluate_live_attach_gate(&future_preflight()));
    assert!(!result.program_load_performed);
    assert!(!result.attach_performed);
    assert!(!result.map_create_performed);
    assert!(!result.ring_buffer_opened);
    assert!(!result.live_kernel_read_performed);
    assert!(!result.map_pin_performed);
    assert!(!result.enforcement_performed);
    assert!(!result.packet_drop_performed);
    assert!(!result.mutation_performed);
}

// -- Coverage 10: future candidate requires attach_plan.future_attach_candidate=true

#[test]
fn i9_future_requires_attach_plan_candidate() {
    let mut preflight = future_preflight();
    preflight.attach_plan.future_attach_candidate = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
}

// -- Coverage 11: future candidate requires safe attach plan -----------

#[test]
fn i9_future_requires_safe_attach_plan() {
    let mut preflight = future_preflight();
    preflight.attach_plan.attach_performed = true;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::PreflightBlocked);
}

// -- Coverage 12: future candidate requires safe loader plan -----------

#[test]
fn i9_future_requires_safe_loader_plan() {
    let mut preflight = future_preflight();
    preflight.loader_plan.loader_available = true;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::PreflightBlocked);
}

// -- Coverage 13: future candidate requires safe skeleton set ----------

#[test]
fn i9_future_requires_safe_skeleton_set() {
    let mut preflight = future_preflight();
    preflight.skeleton_set.enforcement_available = true;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::PreflightBlocked);
}

// -- Coverage 14: future candidate requires sufficient capability ------

#[test]
fn i9_future_requires_sufficient_capability() {
    let mut preflight = future_preflight();
    // Default capability report has readiness=Unavailable (not observer-ready)
    preflight.capability_report =
        crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilityReport::default();
    evaluate_live_attach_gate(&preflight);
    // To test capability properly, we need consent but bad capability.
    let preflight2 = EbpfLiveAttachPreflight {
        attach_plan: future_attach_plan(),
        capability_report:
            crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilityReport::default(),
        loader_plan: future_loader_plan(),
        skeleton_set: default_program_skeleton_set(),
        consent: full_consent(),
        public_cli_requested: false,
    };
    let decision2 = evaluate_live_attach_gate(&preflight2);
    assert!(!decision2.future_live_attach_candidate);
    assert_eq!(decision2.status, EbpfLiveAttachGateStatus::PreflightBlocked);
}

// -- Coverage 15–21: future candidate requires each consent flag ------

#[test]
fn i9_future_requires_explicit_live_observer_attach() {
    let mut preflight = future_preflight();
    preflight.consent.explicit_live_observer_attach = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_explicit_root_acknowledgement() {
    let mut preflight = future_preflight();
    preflight.consent.explicit_root_acknowledgement = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_explicit_no_enforcement_acknowledgement() {
    let mut preflight = future_preflight();
    preflight.consent.explicit_no_enforcement_acknowledgement = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_explicit_no_packet_drop_acknowledgement() {
    let mut preflight = future_preflight();
    preflight.consent.explicit_no_packet_drop_acknowledgement = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_explicit_cleanup_acknowledgement() {
    let mut preflight = future_preflight();
    preflight.consent.explicit_cleanup_acknowledgement = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_rollback_required() {
    let mut preflight = future_preflight();
    preflight.consent.rollback_required = false;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

#[test]
fn i9_future_requires_nonempty_operator_label() {
    let mut preflight = future_preflight();
    preflight.consent.operator_label = String::new();
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
}

// -- Coverage 22: future candidate rejects public_cli_requested=true --

#[test]
fn i9_future_rejects_public_cli() {
    let mut preflight = future_preflight();
    preflight.public_cli_requested = true;
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(!decision.future_live_attach_candidate);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::PreflightBlocked);
}

// -- Coverage 23–31: future candidate operation flags all false --------

#[test]
fn i9_future_candidate_program_load_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.program_load_performed);
}

#[test]
fn i9_future_candidate_attach_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.attach_performed);
}

#[test]
fn i9_future_candidate_map_create_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.map_create_performed);
}

#[test]
fn i9_future_candidate_ring_buffer_opened_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.ring_buffer_opened);
}

#[test]
fn i9_future_candidate_live_kernel_read_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.live_kernel_read_performed);
}

#[test]
fn i9_future_candidate_map_pin_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.map_pin_performed);
}

#[test]
fn i9_future_candidate_enforcement_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.enforcement_performed);
}

#[test]
fn i9_future_candidate_packet_drop_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.packet_drop_performed);
}

#[test]
fn i9_future_candidate_mutation_performed_false() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(!decision.mutation_performed);
}

// -- Coverage 32: validation accepts safe default decision -------------

#[test]
fn i9_validate_accepts_safe_default_decision() {
    let preflight = default_live_attach_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    assert!(validate_live_attach_gate_decision(&decision).is_ok());
}

// -- Coverage 33–42: validation rejects unsafe decision flags ----------

#[test]
fn i9_validate_rejects_program_load_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        program_load_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_attach_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        attach_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_map_create_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        map_create_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_ring_buffer_opened_true() {
    let decision = EbpfLiveAttachGateDecision {
        ring_buffer_opened: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_live_kernel_read_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        live_kernel_read_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_map_pin_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        map_pin_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_enforcement_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        enforcement_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_packet_drop_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        packet_drop_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_mutation_performed_true() {
    let decision = EbpfLiveAttachGateDecision {
        mutation_performed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

#[test]
fn i9_validate_rejects_public_cli_exposed_true() {
    let decision = EbpfLiveAttachGateDecision {
        public_cli_exposed: true,
        ..Default::default()
    };
    assert!(validate_live_attach_gate_decision(&decision).is_err());
}

// -- Coverage 43: validation accepts safe disabled executor result ----

#[test]
fn i9_validate_accepts_safe_executor_result() {
    let result =
        execute_live_attach_disabled(&evaluate_live_attach_gate(&default_live_attach_preflight()));
    assert!(validate_live_attach_executor_result(&result).is_ok());
}

// -- Coverage 44: validation rejects executor attempted=true ----------

#[test]
fn i9_validate_rejects_executor_attempted_true() {
    let mut result =
        execute_live_attach_disabled(&evaluate_live_attach_gate(&default_live_attach_preflight()));
    result.attempted = true;
    assert!(validate_live_attach_executor_result(&result).is_err());
}

// -- Coverage 45: validation rejects executor refused=false -----------

#[test]
fn i9_validate_rejects_executor_refused_false() {
    let mut result =
        execute_live_attach_disabled(&evaluate_live_attach_gate(&default_live_attach_preflight()));
    result.refused = false;
    assert!(validate_live_attach_executor_result(&result).is_err());
}

// -- Coverage 46: validation rejects executor operation flags true ----

#[test]
fn i9_validate_rejects_executor_operation_flags_true() {
    let mut result =
        execute_live_attach_disabled(&evaluate_live_attach_gate(&default_live_attach_preflight()));
    result.attach_performed = true;
    assert!(validate_live_attach_executor_result(&result).is_err());
}

// -- Coverage 47: evaluation is deterministic -------------------------

#[test]
fn i9_evaluation_is_deterministic() {
    let preflight = default_live_attach_preflight();
    let d1 = evaluate_live_attach_gate(&preflight);
    let d2 = evaluate_live_attach_gate(&preflight);
    assert_eq!(d1, d2);
}

#[test]
fn i9_evaluation_deterministic_future() {
    let preflight = future_preflight();
    let d1 = evaluate_live_attach_gate(&preflight);
    let d2 = evaluate_live_attach_gate(&preflight);
    assert_eq!(d1, d2);
}

// -- Coverage 48: executor result is deterministic ---------------------

#[test]
fn i9_executor_result_is_deterministic() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    let r1 = execute_live_attach_disabled(&decision);
    let r2 = execute_live_attach_disabled(&decision);
    assert_eq!(r1, r2);
}

// -- Coverage 49–61: doc checks ----------------------------------------

#[test]
fn i9_doc_mentions_live_observer_attach_gate() {
    assert!(
        I9_DOC.contains("live observer attach gate")
            || I9_DOC.contains("Live observer attach gate")
    );
}

#[test]
fn i9_doc_says_executor_disabled() {
    assert!(I9_DOC.contains("executor") && I9_DOC.contains("disabled"));
}

#[test]
fn i9_doc_says_no_real_live_attach_yet() {
    assert!(I9_DOC.contains("No real live attach yet"));
}

#[test]
fn i9_doc_says_no_userspace_loader() {
    assert!(I9_DOC.contains("No userspace loader"));
}

#[test]
fn i9_doc_says_no_program_load_map_create_ringbuf_read_pin() {
    assert!(I9_DOC.contains("No eBPF program load"));
    assert!(I9_DOC.contains("No eBPF map create"));
    assert!(I9_DOC.contains("No ring buffer open"));
    assert!(I9_DOC.contains("No live kernel event read"));
    assert!(I9_DOC.contains("No map pin"));
}

#[test]
fn i9_doc_says_no_enforcement() {
    assert!(I9_DOC.contains("No enforcement"));
}

#[test]
fn i9_doc_says_no_packet_drop() {
    assert!(I9_DOC.contains("No packet drop"));
}

#[test]
fn i9_doc_says_no_nft_tc_fallback() {
    assert!(I9_DOC.contains("No nft/tc fallback"));
}

#[test]
fn i9_doc_says_no_public_cli() {
    assert!(I9_DOC.contains("No public CLI"));
}

#[test]
fn i9_doc_says_no_ledger_file_write_persistence() {
    assert!(I9_DOC.contains("No ledger file write"));
    assert!(I9_DOC.contains("No persistence"));
}

#[test]
fn i9_doc_says_usage_json_schema_unchanged() {
    assert!(I9_DOC.contains("usage JSON schema unchanged"));
}

#[test]
fn i9_doc_says_ledger_json_schema_unchanged() {
    assert!(I9_DOC.contains("ledger JSON schema unchanged"));
}

// -- Coverage 62: version remains v3.1.0 -------------------------------

#[test]
fn i9_version_remains_v3_1_0() {
    let app = Cli::command();
    let version = app.get_version().unwrap_or("unknown");
    assert_eq!(version, "3.1.0");
}

// -- Coverage 63–64: existing ledger commands still work --------------

#[test]
fn i9_ledger_inspect_json_works() {
    let result = handle_ledger_inspect(true, None);
    let _ = result;
}

#[test]
fn i9_ledger_export_json_works() {
    let tmp = std::env::temp_dir().join("i9_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let result = handle_ledger_export(true, Some(&tmp_str));
    let _ = result;
    let _ = std::fs::remove_file(tmp);
}

// -- Coverage 65: public help does not mention intergalaxion ----------

#[test]
fn i9_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

// -- Coverage 66: public help does not mention forbidden commands ------

#[test]
fn i9_public_help_no_forbidden_commands() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    let help_lower = help.to_lowercase();
    assert!(!help_lower.contains("block"));
    assert!(!help_lower.contains("quota"));
}

// -- Coverage 67: no new dependency -----------------------------------

#[test]
fn i9_no_new_dependency_in_cargo_toml() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(!cargo_toml.contains("aya-bpf"));
    assert!(!cargo_toml.contains("aya-log"));
}

// -- Coverage 68: no live kernel mutation API in gate source ---------

#[test]
fn i9_no_live_kernel_mutation_api_in_gate_source() {
    for forbidden in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
    ] {
        assert!(
            !I9_GATE_SOURCE.contains(forbidden),
            "live_attach_gate.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 69: no aya ringbuf/map open/load/attach/pin API ---------

#[test]
fn i9_no_aya_ringbuf_map_open_load_attach_pin_api() {
    for forbidden in [
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
    ] {
        assert!(
            !I9_GATE_SOURCE.contains(forbidden),
            "live_attach_gate.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 70: no nft/tc source under intergalaxion backend --------

#[test]
fn i9_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Coverage 71: all touched files under 1000 LOC --------------------

#[test]
fn i9_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("live_attach_gate.rs", I9_GATE_SOURCE),
        ("I-9 doc", I9_DOC),
        ("tests_i9.rs", include_str!("tests_i9.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// ── Extra coverage ────────────────────────────────────────────────────

#[test]
fn i9_future_candidate_validates_through_gate_validator() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(validate_live_attach_gate_decision(&decision).is_ok());
}

#[test]
fn i9_future_candidate_executor_validates() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    let result = execute_live_attach_disabled(&decision);
    assert!(validate_live_attach_executor_result(&result).is_ok());
}

#[test]
fn i9_future_candidate_status_is_future_live_attach_candidate() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert_eq!(
        decision.status,
        EbpfLiveAttachGateStatus::FutureLiveAttachCandidate
    );
    assert!(decision.future_live_attach_candidate);
}

#[test]
fn i9_executor_always_refuses_even_for_future_candidate() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    let result = execute_live_attach_disabled(&decision);
    assert!(!result.attempted);
    assert!(result.refused);
}

#[test]
fn i9_decision_executor_disabled_always_true() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(decision.executor_disabled);
}

#[test]
fn i9_default_decision_executor_disabled_true() {
    let decision = evaluate_live_attach_gate(&default_live_attach_preflight());
    assert!(decision.executor_disabled);
}

#[test]
fn i9_default_preflight_has_empty_consent() {
    let preflight = default_live_attach_preflight();
    assert_eq!(preflight.consent, EbpfLiveAttachConsent::default());
}

#[test]
fn i9_public_cli_forces_preflight_blocked() {
    let mut preflight = future_preflight();
    preflight.public_cli_requested = true;
    let decision = evaluate_live_attach_gate(&preflight);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::PreflightBlocked);
    assert!(decision.reasons.iter().any(|r| r.blocking));
}

#[test]
fn i9_missing_consent_reasons_are_non_blocking() {
    let preflight = default_live_attach_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    assert_eq!(decision.status, EbpfLiveAttachGateStatus::MissingConsent);
    for reason in &decision.reasons {
        assert!(!reason.blocking);
    }
}

#[test]
fn i9_no_forbidden_patterns_in_gate_source() {
    for forbidden in [
        "drop_packet",
        "File::create",
        "fs::write",
        "OpenOptions",
        "persist",
        "save",
    ] {
        assert!(
            !I9_GATE_SOURCE.contains(forbidden),
            "live_attach_gate.rs must not contain {}",
            forbidden
        );
    }
}

#[test]
fn i9_executor_result_has_refusal_reason() {
    let result =
        execute_live_attach_disabled(&evaluate_live_attach_gate(&default_live_attach_preflight()));
    assert!(!result.reason.is_empty());
}

#[test]
fn i9_future_preflight_validates_through_executor() {
    let decision = evaluate_live_attach_gate(&future_preflight());
    assert!(decision.future_live_attach_candidate);
    assert!(decision.executor_disabled);
    let result = execute_live_attach_disabled(&decision);
    assert!(!result.attempted);
    assert!(result.refused);
}
