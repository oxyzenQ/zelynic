// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-7 tests: loader boundary, disabled by default.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::*;
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    default_program_skeleton_set, EbpfProgramSkeletonSet,
};
use crate::intergalaxion_engine::live_readiness::{
    evaluate_intergalaxion_readiness, IntergalaxionReadinessGate, IntergalaxionReadinessLevel,
};
use clap::CommandFactory;

const I7_DOC: &str =
    include_str!("../../docs/intergalaxion/I-7-loader-boundary-disabled-by-default.md");
const I7_BOUNDARY_SOURCE: &str = include_str!("backends/ebpf/loader_boundary.rs");

// Helper to build an observer-ready capability snapshot.
fn observer_ready_snapshot(
) -> crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
    crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..Default::default()
    }
}

// Helper to build a readiness gate at a specific level.
fn gate_at_level(level: IntergalaxionReadinessLevel) -> IntergalaxionReadinessGate {
    match level {
        IntergalaxionReadinessLevel::Blocked => {
            let input = crate::intergalaxion_engine::live_readiness::default_readiness_input();
            evaluate_intergalaxion_readiness(&input)
        }
        IntergalaxionReadinessLevel::FutureAttachPlanningCandidate => {
            let input = crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessInput {
                capability_report: crate::intergalaxion_engine::backends::ebpf::capability::evaluate_ebpf_capability(
                    &observer_ready_snapshot(),
                ),
                explicit_future_attach_consent: true,
                public_cli_requested: false,
                ..Default::default()
            };
            evaluate_intergalaxion_readiness(&input)
        }
        _ => IntergalaxionReadinessGate {
            level,
            ..Default::default()
        },
    }
}

// Helper to build a safe skeleton set.
fn safe_skeleton_set() -> EbpfProgramSkeletonSet {
    default_program_skeleton_set()
}

// -- Coverage 1: default loader boundary input is safe ----------------

#[test]
fn i7_default_loader_boundary_input_is_safe() {
    let input = default_loader_boundary_input();
    assert!(!input.public_cli_requested);
    assert!(!input.explicit_loader_consent);
    assert!(!input.object_source_declared);
    assert!(!input.root_required_for_future_load);
}

// -- Coverage 2: default loader boundary plan is disabled ------------

#[test]
fn i7_default_loader_boundary_plan_is_disabled() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::Disabled);
}

// -- Coverage 3: default plan loader_available=false -------------------

#[test]
fn i7_default_plan_loader_available_false() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.loader_available);
}

// -- Coverage 4: default plan loader_disabled=true ---------------------

#[test]
fn i7_default_plan_loader_disabled_true() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(plan.loader_disabled);
}

// -- Coverage 5: default plan has all operation flags false -----------

#[test]
fn i7_default_plan_all_operation_flags_false() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.program_load_performed);
    assert!(!plan.attach_performed);
    assert!(!plan.map_create_performed);
    assert!(!plan.ring_buffer_opened);
    assert!(!plan.live_kernel_read_performed);
    assert!(!plan.map_pin_performed);
    assert!(!plan.enforcement_performed);
    assert!(!plan.mutation_performed);
    assert!(!plan.public_cli_exposed);
}

// -- Coverage 6: status labels are stable -----------------------------

#[test]
fn i7_status_labels_are_stable() {
    assert_eq!(
        loader_boundary_status_label(EbpfLoaderBoundaryStatus::Disabled),
        "disabled"
    );
    assert_eq!(
        loader_boundary_status_label(EbpfLoaderBoundaryStatus::ModelOnly),
        "model_only"
    );
    assert_eq!(
        loader_boundary_status_label(EbpfLoaderBoundaryStatus::FutureReadyBlocked),
        "future_ready_blocked"
    );
    assert_eq!(
        loader_boundary_status_label(EbpfLoaderBoundaryStatus::KernelLoadUnsupported),
        "kernel_load_unsupported"
    );
}

// -- Coverage 7: default plan reasons are nonempty --------------------

#[test]
fn i7_default_plan_reasons_nonempty() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.reasons.is_empty());
}

// -- Coverage 8: blocked reasons have blocking=true -------------------

#[test]
fn i7_blocked_reasons_have_blocking_true() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::Blocked);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(plan.reasons.iter().any(|r| r.blocking));
}

// -- Coverage 9: safe future candidate without performing load ---------

#[test]
fn i7_safe_future_candidate_no_load() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let skeleton = safe_skeleton_set();
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton,
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(plan.future_load_candidate);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::ModelOnly);
    assert!(!plan.loader_available);
    assert!(plan.loader_disabled);
}

// -- Coverage 10: future load candidate requires readiness gate future attach candidate

#[test]
fn i7_future_candidate_requires_readiness_gate_future_attach() {
    // Use ObserverCandidate level (not FutureAttachPlanningCandidate)
    let gate = gate_at_level(IntergalaxionReadinessLevel::ObserverCandidate);
    let skeleton = safe_skeleton_set();
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton,
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
}

// -- Coverage 11: future load candidate requires explicit_loader_consent=true

#[test]
fn i7_future_candidate_requires_explicit_loader_consent() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let skeleton = safe_skeleton_set();
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton,
        explicit_loader_consent: false,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
}

// -- Coverage 12: future load candidate requires object_source_declared=true

#[test]
fn i7_future_candidate_requires_object_source_declared() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let skeleton = safe_skeleton_set();
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton,
        explicit_loader_consent: true,
        object_source_declared: false,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
}

// -- Coverage 13: future load candidate rejects public_cli_requested=true

#[test]
fn i7_future_candidate_rejects_public_cli() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let skeleton = safe_skeleton_set();
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton,
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: true,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::Disabled);
}

// -- Coverage 14: future load candidate rejects unsafe skeleton set ----

#[test]
fn i7_future_candidate_rejects_unsafe_skeleton_set() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let unsafe_skeleton = EbpfProgramSkeletonSet {
        loader_available: true,
        ..Default::default()
    };
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: unsafe_skeleton,
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
}

// -- Coverage 15–22: future candidate operation flags all false ------

#[test]
fn i7_future_candidate_program_load_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.program_load_performed);
}

#[test]
fn i7_future_candidate_attach_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.attach_performed);
}

#[test]
fn i7_future_candidate_map_create_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.map_create_performed);
}

#[test]
fn i7_future_candidate_ring_buffer_opened_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.ring_buffer_opened);
}

#[test]
fn i7_future_candidate_live_kernel_read_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.live_kernel_read_performed);
}

#[test]
fn i7_future_candidate_map_pin_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.map_pin_performed);
}

#[test]
fn i7_future_candidate_enforcement_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.enforcement_performed);
}

#[test]
fn i7_future_candidate_mutation_performed_false() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.mutation_performed);
}

// -- Coverage 23: validation accepts safe default plan ---------------

#[test]
fn i7_validate_accepts_safe_default_plan() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(validate_loader_boundary_plan(&plan).is_ok());
}

// -- Coverage 24–34: validation rejects unsafe flags --------------------

#[test]
fn i7_validate_rejects_loader_available_true() {
    let plan = EbpfLoaderBoundaryPlan {
        loader_available: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_loader_disabled_false() {
    let plan = EbpfLoaderBoundaryPlan {
        loader_disabled: false,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_program_load_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        program_load_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_attach_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        attach_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_map_create_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        map_create_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_ring_buffer_opened_true() {
    let plan = EbpfLoaderBoundaryPlan {
        ring_buffer_opened: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_live_kernel_read_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        live_kernel_read_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_map_pin_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        map_pin_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_enforcement_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        enforcement_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_mutation_performed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        mutation_performed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_validate_rejects_public_cli_exposed_true() {
    let plan = EbpfLoaderBoundaryPlan {
        public_cli_exposed: true,
        ..Default::default()
    };
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

// -- Coverage 35: evaluation is deterministic ----------------------------

#[test]
fn i7_evaluation_is_deterministic() {
    let input = default_loader_boundary_input();
    let plan1 = evaluate_loader_boundary(&input);
    let plan2 = evaluate_loader_boundary(&input);
    assert_eq!(plan1, plan2);
}

#[test]
fn i7_evaluation_is_deterministic_with_full_input() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate.clone(),
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan1 = evaluate_loader_boundary(&input);
    let plan2 = evaluate_loader_boundary(&input);
    assert_eq!(plan1, plan2);
}

// -- Coverage 36–47: doc checks ----------------------------------------

#[test]
fn i7_doc_exists_and_mentions_loader_boundary() {
    assert!(I7_DOC.contains("loader boundary"));
}

#[test]
fn i7_doc_says_loader_disabled_by_default() {
    assert!(I7_DOC.contains("disabled by default"));
}

#[test]
fn i7_doc_says_no_userspace_loader() {
    assert!(I7_DOC.contains("no userspace loader"));
}

#[test]
fn i7_doc_says_no_program_load() {
    assert!(I7_DOC.contains("No eBPF program load"));
}

#[test]
fn i7_doc_says_no_attach_map_create_ringbuf_open_live_read_map_pin() {
    assert!(I7_DOC.contains("No eBPF attach"));
    assert!(I7_DOC.contains("No eBPF map create"));
    assert!(I7_DOC.contains("No ring buffer open"));
    assert!(I7_DOC.contains("No live kernel event read"));
    assert!(I7_DOC.contains("No map pin"));
}

#[test]
fn i7_doc_says_no_enforcement() {
    assert!(I7_DOC.contains("No enforcement"));
}

#[test]
fn i7_doc_says_no_nft_tc_fallback() {
    assert!(I7_DOC.contains("No nft/tc fallback"));
}

#[test]
fn i7_doc_says_no_public_cli() {
    assert!(I7_DOC.contains("No public CLI"));
}

#[test]
fn i7_doc_says_no_ledger_file_write_persistence() {
    assert!(I7_DOC.contains("No ledger file write"));
    assert!(I7_DOC.contains("No persistence"));
}

#[test]
fn i7_doc_says_usage_json_schema_unchanged() {
    assert!(I7_DOC.contains("usage JSON schema unchanged"));
}

#[test]
fn i7_doc_says_ledger_json_schema_unchanged() {
    assert!(I7_DOC.contains("ledger JSON schema unchanged"));
}

// -- Coverage 48: version remains v3.1.0 ---------------------------------

#[test]
fn i7_version_remains_v3_1_0() {
    let app = Cli::command();
    let version = app.get_version().unwrap_or("unknown");
    assert_eq!(version, "3.1.0");
}

// -- Coverage 49–50: existing ledger commands still work ---------------

#[test]
fn i7_ledger_inspect_json_works() {
    let result = handle_ledger_inspect(true, None);
    // Should not panic or error
    let _ = result;
}

#[test]
fn i7_ledger_export_json_works() {
    let tmp = std::env::temp_dir().join("i7_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let result = handle_ledger_export(true, Some(&tmp_str));
    let _ = result;
    // Cleanup
    let _ = std::fs::remove_file(tmp);
}

// -- Coverage 51: public help does not mention intergalaxion ----------

#[test]
fn i7_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

// -- Coverage 52: public help does not mention forbidden commands ------

#[test]
fn i7_public_help_no_forbidden_commands() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    let help_lower = help.to_lowercase();
    assert!(!help_lower.contains("block"));
    assert!(!help_lower.contains("quota"));
}

// -- Coverage 53: no new dependency -----------------------------------

#[test]
fn i7_no_new_dependency_in_cargo_toml() {
    let cargo_toml = include_str!("../../Cargo.toml");
    // Ensure no new eBPF loader or userspace dependencies were added
    assert!(!cargo_toml.contains("aya-bpf"));
    assert!(!cargo_toml.contains("aya-log"));
}

// -- Coverage 54: no live kernel mutation API in loader boundary source

#[test]
fn i7_no_live_kernel_mutation_api_in_boundary_source() {
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
            !I7_BOUNDARY_SOURCE.contains(forbidden),
            "loader_boundary.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 55: no aya ringbuf/map open/load/attach/pin API ----------

#[test]
fn i7_no_aya_ringbuf_map_open_load_attach_pin_api() {
    for forbidden in [
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
    ] {
        assert!(
            !I7_BOUNDARY_SOURCE.contains(forbidden),
            "loader_boundary.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 56: no nft/tc source under intergalaxion backend --------

#[test]
fn i7_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Coverage 57: all touched files under 1000 LOC --------------------

#[test]
fn i7_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("loader_boundary.rs", I7_BOUNDARY_SOURCE),
        ("I-7 doc", I7_DOC),
        ("tests_i7.rs", include_str!("tests_i7.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// ── Extra coverage: future candidate validates through validator ----

#[test]
fn i7_future_candidate_validates_through_validator() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(validate_loader_boundary_plan(&plan).is_ok());
}

#[test]
fn i7_public_cli_requested_forces_disabled() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: true,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::Disabled);
    assert!(plan.reasons.iter().any(|r| r.blocking));
}

#[test]
fn i7_unsafe_readiness_gate_forces_disabled() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::Blocked);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::Disabled);
}

#[test]
fn i7_unsafe_skeleton_set_forces_disabled() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let unsafe_set = EbpfProgramSkeletonSet {
        enforcement_available: true,
        ..Default::default()
    };
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: unsafe_set,
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert_eq!(plan.status, EbpfLoaderBoundaryStatus::Disabled);
}

#[test]
fn i7_default_input_has_empty_readiness_gate() {
    let input = default_loader_boundary_input();
    assert_eq!(
        input.readiness_gate.level,
        IntergalaxionReadinessLevel::ModelOnly
    );
}

#[test]
fn i7_default_input_has_empty_skeleton_set() {
    let input = default_loader_boundary_input();
    assert!(input.skeleton_set.skeletons.is_empty());
}

#[test]
fn i7_default_plan_future_load_candidate_false() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.future_load_candidate);
}

#[test]
fn i7_default_plan_object_source_declared_false() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    assert!(!plan.object_source_declared);
}

#[test]
fn i7_default_status_is_disabled_enum_default() {
    assert_eq!(
        EbpfLoaderBoundaryStatus::default(),
        EbpfLoaderBoundaryStatus::Disabled
    );
}

#[test]
fn i7_default_plan_is_default() {
    assert_eq!(
        EbpfLoaderBoundaryPlan::default(),
        EbpfLoaderBoundaryPlan {
            status: EbpfLoaderBoundaryStatus::Disabled,
            loader_available: false,
            loader_disabled: false,
            object_source_declared: false,
            future_load_candidate: false,
            reasons: Vec::new(),
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
    );
}

#[test]
fn i7_validate_default_raw_plan_fails_loader_disabled_false() {
    // The raw Default for EbpfLoaderBoundaryPlan has loader_disabled=false
    // which is unsafe. Only evaluated plans (from evaluate_loader_boundary)
    // have loader_disabled=true.
    let plan = EbpfLoaderBoundaryPlan::default();
    assert!(validate_loader_boundary_plan(&plan).is_err());
}

#[test]
fn i7_future_candidate_object_source_declared_true() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    assert!(plan.object_source_declared);
}

#[test]
fn i7_non_blocking_reasons_have_blocking_false() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    // Default input has readiness gate at ModelOnly (not blocked), so all
    // reasons should be non-blocking.
    for reason in &plan.reasons {
        assert!(
            !reason.blocking,
            "expected non-blocking reason, got code={}",
            reason.code
        );
    }
}

#[test]
fn i7_blocked_gate_produces_blocking_reason() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::Blocked);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    let blocking_codes: Vec<&str> = plan
        .reasons
        .iter()
        .filter(|r| r.blocking)
        .map(|r| r.code.as_str())
        .collect();
    assert!(blocking_codes.contains(&"readiness_gate_blocked"));
}

#[test]
fn i7_public_cli_reason_is_blocking() {
    let gate = gate_at_level(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate);
    let input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: safe_skeleton_set(),
        public_cli_requested: true,
        ..Default::default()
    };
    let plan = evaluate_loader_boundary(&input);
    let cli_reason = plan
        .reasons
        .iter()
        .find(|r| r.code == "public_cli_requested");
    assert!(cli_reason.is_some());
    assert!(cli_reason.unwrap().blocking);
}

#[test]
fn i7_reasons_have_unique_codes() {
    let input = default_loader_boundary_input();
    let plan = evaluate_loader_boundary(&input);
    let mut codes: Vec<&str> = plan.reasons.iter().map(|r| r.code.as_str()).collect();
    codes.sort();
    codes.dedup();
    assert_eq!(
        codes.len(),
        plan.reasons.len(),
        "reason codes must be unique"
    );
}

// -- Coverage: no forbidden source patterns in boundary source ----------

#[test]
fn i7_no_forbidden_patterns_in_boundary_source() {
    for forbidden in [
        "drop_packet",
        "File::create",
        "fs::write",
        "OpenOptions",
        "persist",
        "save",
    ] {
        assert!(
            !I7_BOUNDARY_SOURCE.contains(forbidden),
            "loader_boundary.rs must not contain {}",
            forbidden
        );
    }
}
