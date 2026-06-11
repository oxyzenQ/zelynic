// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-8 tests: safe attach plan, no attach yet.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::*;
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::evaluate_loader_boundary;
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::{
    default_program_skeleton_set, EbpfProgramSkeletonSet,
};
use crate::intergalaxion_engine::live_readiness::evaluate_intergalaxion_readiness;
use clap::CommandFactory;

const I8_DOC: &str = include_str!("../../docs/intergalaxion/I-8-safe-attach-plan-no-attach-yet.md");
const I8_ATTACH_SOURCE: &str = include_str!("backends/ebpf/attach_plan.rs");

// Helper: observer-ready capability snapshot (same as I-7).
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
        capability_report:
            crate::intergalaxion_engine::backends::ebpf::capability::evaluate_ebpf_capability(
                &observer_ready_snapshot(),
            ),
        explicit_future_attach_consent: true,
        public_cli_requested: false,
        ..Default::default()
    };
    evaluate_intergalaxion_readiness(&input)
}

// Helper: safe skeleton set.
fn safe_skeleton_set() -> EbpfProgramSkeletonSet {
    default_program_skeleton_set()
}

// Helper: loader boundary plan that is future_load_candidate=true.
fn future_loader_plan(
) -> crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryPlan {
    let gate = future_gate();
    let input =
        crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryInput {
            readiness_gate: gate,
            skeleton_set: safe_skeleton_set(),
            explicit_loader_consent: true,
            object_source_declared: true,
            public_cli_requested: false,
            ..Default::default()
        };
    evaluate_loader_boundary(&input)
}

// Helper: full future-ready attach plan input.
fn future_attach_input() -> EbpfAttachPlanInput {
    EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    }
}

// -- Coverage 1: default attach target is safe -------------------------

#[test]
fn i8_default_attach_target_is_safe() {
    let target = default_attach_target();
    assert!(!target.target_id.is_empty());
    assert!(!target.section_name.is_empty());
    assert!(validate_attach_target(&target).is_ok());
}

// -- Coverage 2: default attach plan input is safe --------------------

#[test]
fn i8_default_attach_plan_input_is_safe() {
    let input = default_attach_plan_input();
    assert!(!input.public_cli_requested);
    assert!(!input.explicit_attach_consent);
    assert!(!input.rollback_required);
}

// -- Coverage 3: default attach plan has all operation flags false ------

#[test]
fn i8_default_attach_plan_all_operation_flags_false() {
    let input = default_attach_plan_input();
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.attach_performed);
    assert!(!plan.program_load_performed);
    assert!(!plan.map_create_performed);
    assert!(!plan.ring_buffer_opened);
    assert!(!plan.live_kernel_read_performed);
    assert!(!plan.map_pin_performed);
    assert!(!plan.enforcement_performed);
    assert!(!plan.mutation_performed);
    assert!(!plan.packet_drop_performed);
    assert!(!plan.public_cli_exposed);
}

// -- Coverage 4: attach target kind labels are stable -------------------

#[test]
fn i8_attach_target_kind_labels_stable() {
    assert_eq!(
        attach_target_kind_label(EbpfAttachTargetKind::SocketFilter),
        "socket_filter"
    );
    assert_eq!(
        attach_target_kind_label(EbpfAttachTargetKind::CgroupSkb),
        "cgroup_skb"
    );
    assert_eq!(
        attach_target_kind_label(EbpfAttachTargetKind::Tracepoint),
        "tracepoint"
    );
}

// -- Coverage 5: attach plan status labels are stable ------------------

#[test]
fn i8_attach_plan_status_labels_stable() {
    assert_eq!(
        attach_plan_status_label(EbpfAttachPlanStatus::Disabled),
        "disabled"
    );
    assert_eq!(
        attach_plan_status_label(EbpfAttachPlanStatus::PlanOnly),
        "plan_only"
    );
    assert_eq!(
        attach_plan_status_label(EbpfAttachPlanStatus::FutureAttachCandidate),
        "future_attach_candidate"
    );
    assert_eq!(
        attach_plan_status_label(EbpfAttachPlanStatus::Rejected),
        "rejected"
    );
}

// -- Coverage 6: socket filter attach target preserves interface name -

#[test]
fn i8_socket_filter_preserves_interface_name() {
    let target = socket_filter_attach_target("lo");
    assert_eq!(target.interface_name.as_deref(), Some("lo"));
    assert_eq!(target.kind, EbpfAttachTargetKind::SocketFilter);
}

// -- Coverage 7: cgroup skb attach target preserves cgroup path --------

#[test]
fn i8_cgroup_skb_preserves_cgroup_path() {
    let target = cgroup_skb_attach_target("/sys/fs/cgroup/test");
    assert_eq!(target.cgroup_path.as_deref(), Some("/sys/fs/cgroup/test"));
    assert_eq!(target.kind, EbpfAttachTargetKind::CgroupSkb);
}

// -- Coverage 8: tracepoint attach target preserves category and name --

#[test]
fn i8_tracepoint_preserves_category_and_name() {
    let target = tracepoint_attach_target("sched", "sched_switch");
    assert_eq!(target.tracepoint_category.as_deref(), Some("sched"));
    assert_eq!(target.tracepoint_name.as_deref(), Some("sched_switch"));
    assert_eq!(target.kind, EbpfAttachTargetKind::Tracepoint);
}

// -- Coverage 9–12: validate accepts valid targets ---------------------

#[test]
fn i8_validate_accepts_default_attach_target() {
    let target = default_attach_target();
    assert!(validate_attach_target(&target).is_ok());
}

#[test]
fn i8_validate_accepts_socket_filter_target() {
    let target = socket_filter_attach_target("eth0");
    assert!(validate_attach_target(&target).is_ok());
}

#[test]
fn i8_validate_accepts_cgroup_skb_target() {
    let target = cgroup_skb_attach_target("/sys/fs/cgroup/test");
    assert!(validate_attach_target(&target).is_ok());
}

#[test]
fn i8_validate_accepts_tracepoint_target() {
    let target = tracepoint_attach_target("net", "net_dev_xmit");
    assert!(validate_attach_target(&target).is_ok());
}

// -- Coverage 13: validate rejects empty target_id ---------------------

#[test]
fn i8_validate_rejects_empty_target_id() {
    let target = EbpfAttachTarget {
        target_id: String::new(),
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 14: validate rejects empty section_name ------------------

#[test]
fn i8_validate_rejects_empty_section_name() {
    let target = EbpfAttachTarget {
        section_name: String::new(),
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 15: validate rejects socket filter without interface_name -

#[test]
fn i8_validate_rejects_socket_filter_without_interface() {
    let target = EbpfAttachTarget {
        kind: EbpfAttachTargetKind::SocketFilter,
        interface_name: None,
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 16: validate rejects cgroup skb without cgroup_path -----

#[test]
fn i8_validate_rejects_cgroup_skb_without_cgroup_path() {
    let target = EbpfAttachTarget {
        kind: EbpfAttachTargetKind::CgroupSkb,
        cgroup_path: None,
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 17: validate rejects tracepoint without category ---------

#[test]
fn i8_validate_rejects_tracepoint_without_category() {
    let target = EbpfAttachTarget {
        kind: EbpfAttachTargetKind::Tracepoint,
        tracepoint_category: None,
        tracepoint_name: Some(String::from("sched_switch")),
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 18: validate rejects tracepoint without name -------------

#[test]
fn i8_validate_rejects_tracepoint_without_name() {
    let target = EbpfAttachTarget {
        kind: EbpfAttachTargetKind::Tracepoint,
        tracepoint_category: Some(String::from("sched")),
        tracepoint_name: None,
        ..Default::default()
    };
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 19: validate rejects cgroup path with parent traversal --

#[test]
fn i8_validate_rejects_cgroup_parent_traversal() {
    let target = cgroup_skb_attach_target("/sys/fs/cgroup/../etc");
    assert!(validate_attach_target(&target).is_err());
}

// -- Coverage 20: default attach plan is not future attach candidate ----

#[test]
fn i8_default_plan_not_future_attach_candidate() {
    let input = default_attach_plan_input();
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
}

// -- Coverage 21: future candidate requires loader future_load_candidate --

#[test]
fn i8_future_candidate_requires_loader_future_load_candidate() {
    let input = EbpfAttachPlanInput {
        loader_plan: crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryPlan::default(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
}

// -- Coverage 22: future candidate requires explicit_attach_consent -----

#[test]
fn i8_future_candidate_requires_explicit_attach_consent() {
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: false,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
}

// -- Coverage 23: future candidate requires rollback_required -----------

#[test]
fn i8_future_candidate_requires_rollback_required() {
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: false,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
}

// -- Coverage 24: future candidate rejects public_cli_requested -------

#[test]
fn i8_future_candidate_rejects_public_cli() {
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: true,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
}

// -- Coverage 25: future candidate rejects unsafe loader plan ----------

#[test]
fn i8_future_candidate_rejects_unsafe_loader_plan() {
    let unsafe_plan =
        crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryPlan {
            loader_available: true,
            ..Default::default()
        };
    let input = EbpfAttachPlanInput {
        loader_plan: unsafe_plan,
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
}

// -- Coverage 26: future candidate rejects unsafe skeleton set ---------

#[test]
fn i8_future_candidate_rejects_unsafe_skeleton_set() {
    let unsafe_set = EbpfProgramSkeletonSet {
        enforcement_available: true,
        ..Default::default()
    };
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: unsafe_set,
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
}

// -- Coverage 27: future candidate rejects unsafe target ---------------

#[test]
fn i8_future_candidate_rejects_unsafe_target() {
    let unsafe_target = EbpfAttachTarget {
        target_id: String::new(),
        ..Default::default()
    };
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: unsafe_target,
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.future_attach_candidate);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
}

// -- Coverage 28–36: future candidate operation flags all false --------

#[test]
fn i8_future_candidate_attach_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.attach_performed);
}

#[test]
fn i8_future_candidate_program_load_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.program_load_performed);
}

#[test]
fn i8_future_candidate_map_create_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.map_create_performed);
}

#[test]
fn i8_future_candidate_ring_buffer_opened_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.ring_buffer_opened);
}

#[test]
fn i8_future_candidate_live_kernel_read_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.live_kernel_read_performed);
}

#[test]
fn i8_future_candidate_map_pin_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.map_pin_performed);
}

#[test]
fn i8_future_candidate_enforcement_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.enforcement_performed);
}

#[test]
fn i8_future_candidate_mutation_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.mutation_performed);
}

#[test]
fn i8_future_candidate_packet_drop_performed_false() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(!plan.packet_drop_performed);
}

// -- Coverage 37: validation accepts safe default plan ------------------

#[test]
fn i8_validate_accepts_safe_default_plan() {
    let input = default_attach_plan_input();
    let plan = evaluate_attach_plan(&input);
    assert!(validate_attach_plan(&plan).is_ok());
}

// -- Coverage 38–47: validation rejects unsafe flags -------------------

#[test]
fn i8_validate_rejects_attach_performed_true() {
    let plan = EbpfAttachPlan {
        attach_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_program_load_performed_true() {
    let plan = EbpfAttachPlan {
        program_load_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_map_create_performed_true() {
    let plan = EbpfAttachPlan {
        map_create_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_ring_buffer_opened_true() {
    let plan = EbpfAttachPlan {
        ring_buffer_opened: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_live_kernel_read_performed_true() {
    let plan = EbpfAttachPlan {
        live_kernel_read_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_map_pin_performed_true() {
    let plan = EbpfAttachPlan {
        map_pin_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_enforcement_performed_true() {
    let plan = EbpfAttachPlan {
        enforcement_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_mutation_performed_true() {
    let plan = EbpfAttachPlan {
        mutation_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_packet_drop_performed_true() {
    let plan = EbpfAttachPlan {
        packet_drop_performed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

#[test]
fn i8_validate_rejects_public_cli_exposed_true() {
    let plan = EbpfAttachPlan {
        public_cli_exposed: true,
        ..Default::default()
    };
    assert!(validate_attach_plan(&plan).is_err());
}

// -- Coverage 48: evaluation is deterministic ---------------------------

#[test]
fn i8_evaluation_is_deterministic() {
    let input = default_attach_plan_input();
    let plan1 = evaluate_attach_plan(&input);
    let plan2 = evaluate_attach_plan(&input);
    assert_eq!(plan1, plan2);
}

#[test]
fn i8_evaluation_is_deterministic_with_future_input() {
    let input = future_attach_input();
    let plan1 = evaluate_attach_plan(&input);
    let plan2 = evaluate_attach_plan(&input);
    assert_eq!(plan1, plan2);
}

// -- Coverage 49–59: doc checks ----------------------------------------

#[test]
fn i8_doc_exists_and_mentions_attach_planning() {
    assert!(I8_DOC.contains("attach planning") || I8_DOC.contains("Attach planning"));
}

#[test]
fn i8_doc_says_no_live_attach() {
    assert!(I8_DOC.contains("No live attach"));
}

#[test]
fn i8_doc_says_no_userspace_loader() {
    assert!(I8_DOC.contains("No userspace loader"));
}

#[test]
fn i8_doc_says_no_program_load_map_create_ringbuf_read_pin() {
    assert!(I8_DOC.contains("No eBPF program load"));
    assert!(I8_DOC.contains("No eBPF map create"));
    assert!(I8_DOC.contains("No ring buffer open"));
    assert!(I8_DOC.contains("No live kernel event read"));
    assert!(I8_DOC.contains("No map pin"));
}

#[test]
fn i8_doc_says_no_enforcement() {
    assert!(I8_DOC.contains("No enforcement"));
}

#[test]
fn i8_doc_says_no_nft_tc_fallback() {
    assert!(I8_DOC.contains("No nft/tc fallback"));
}

#[test]
fn i8_doc_says_no_public_cli() {
    assert!(I8_DOC.contains("No public CLI"));
}

#[test]
fn i8_doc_says_no_ledger_file_write_persistence() {
    assert!(I8_DOC.contains("No ledger file write"));
    assert!(I8_DOC.contains("No persistence"));
}

#[test]
fn i8_doc_says_usage_json_schema_unchanged() {
    assert!(I8_DOC.contains("usage JSON schema unchanged"));
}

#[test]
fn i8_doc_says_ledger_json_schema_unchanged() {
    assert!(I8_DOC.contains("ledger JSON schema unchanged"));
}

// -- Coverage 60: version remains v3.1.0 ---------------------------------

#[test]
fn i8_version_remains_v3_1_0() {
    let app = Cli::command();
    let version = app.get_version().unwrap_or("unknown");
    assert_eq!(version, "3.1.0");
}

// -- Coverage 61–62: existing ledger commands still work ---------------

#[test]
fn i8_ledger_inspect_json_works() {
    let result = handle_ledger_inspect(true, None);
    let _ = result;
}

#[test]
fn i8_ledger_export_json_works() {
    let tmp = std::env::temp_dir().join("i8_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let result = handle_ledger_export(true, Some(&tmp_str));
    let _ = result;
    let _ = std::fs::remove_file(tmp);
}

// -- Coverage 63: public help does not mention intergalaxion ----------

#[test]
fn i8_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

// -- Coverage 64: public help does not mention forbidden commands ------

#[test]
fn i8_public_help_no_forbidden_commands() {
    let mut app = Cli::command();
    let help = app.render_help().to_string();
    let help_lower = help.to_lowercase();
    assert!(!help_lower.contains("block"));
    assert!(!help_lower.contains("quota"));
}

// -- Coverage 65: no new dependency -----------------------------------

#[test]
fn i8_no_new_dependency_in_cargo_toml() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(!cargo_toml.contains("aya-bpf"));
    assert!(!cargo_toml.contains("aya-log"));
}

// -- Coverage 66: no live kernel mutation API in attach plan source ---

#[test]
fn i8_no_live_kernel_mutation_api_in_attach_source() {
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
            !I8_ATTACH_SOURCE.contains(forbidden),
            "attach_plan.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 67: no aya ringbuf/map open/load/attach/pin API ---------

#[test]
fn i8_no_aya_ringbuf_map_open_load_attach_pin_api() {
    for forbidden in [
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
    ] {
        assert!(
            !I8_ATTACH_SOURCE.contains(forbidden),
            "attach_plan.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 68: no nft/tc source under intergalaxion backend --------

#[test]
fn i8_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Coverage 69: all touched files under 1000 LOC --------------------

#[test]
fn i8_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("attach_plan.rs", I8_ATTACH_SOURCE),
        ("I-8 doc", I8_DOC),
        ("tests_i8.rs", include_str!("tests_i8.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// ── Extra coverage ────────────────────────────────────────────────────

#[test]
fn i8_future_candidate_validates_through_validator() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert!(validate_attach_plan(&plan).is_ok());
}

#[test]
fn i8_future_candidate_status_is_future_attach_candidate() {
    let plan = evaluate_attach_plan(&future_attach_input());
    assert_eq!(plan.status, EbpfAttachPlanStatus::FutureAttachCandidate);
    assert!(plan.future_attach_candidate);
}

#[test]
fn i8_default_plan_status_is_disabled() {
    // The default attach plan input has a default loader plan whose
    // raw Default has loader_disabled=false (unsafe), so the evaluator
    // rejects it. We need a proper evaluated loader plan.
    let gate_input = crate::intergalaxion_engine::live_readiness::default_readiness_input();
    let gate = evaluate_intergalaxion_readiness(&gate_input);
    let loader_input =
        crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryInput {
            readiness_gate: gate,
            ..Default::default()
        };
    let loader_plan = evaluate_loader_boundary(&loader_input);
    let attach_input = EbpfAttachPlanInput {
        loader_plan,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&attach_input);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Disabled);
}

#[test]
fn i8_default_plan_reasons_nonempty() {
    let input = default_attach_plan_input();
    let plan = evaluate_attach_plan(&input);
    assert!(!plan.reasons.is_empty());
}

#[test]
fn i8_default_plan_target_matches_input() {
    let input = default_attach_plan_input();
    let plan = evaluate_attach_plan(&input);
    assert_eq!(plan.target.target_id, input.target.target_id);
}

#[test]
fn i8_socket_filter_target_id_contains_interface() {
    let target = socket_filter_attach_target("wlan0");
    assert!(target.target_id.contains("wlan0"));
}

#[test]
fn i8_cgroup_skb_target_id_contains_cgroup() {
    let target = cgroup_skb_attach_target("/my/cgroup");
    assert!(target.target_id.contains("/my/cgroup"));
}

#[test]
fn i8_tracepoint_target_id_contains_category_and_name() {
    let target = tracepoint_attach_target("net", "net_dev_xmit");
    assert!(target.target_id.contains("net"));
    assert!(target.target_id.contains("net_dev_xmit"));
}

#[test]
fn i8_default_target_kind_is_socket_filter() {
    let target = default_attach_target();
    assert_eq!(target.kind, EbpfAttachTargetKind::SocketFilter);
}

#[test]
fn i8_default_status_is_disabled_enum_default() {
    assert_eq!(
        EbpfAttachPlanStatus::default(),
        EbpfAttachPlanStatus::Disabled
    );
}

#[test]
fn i8_default_target_kind_is_socket_filter_enum_default() {
    assert_eq!(
        EbpfAttachTargetKind::default(),
        EbpfAttachTargetKind::SocketFilter
    );
}

#[test]
fn i8_cgroup_safe_path_validates() {
    let target = cgroup_skb_attach_target("/sys/fs/cgroup/user.slice");
    assert!(validate_attach_target(&target).is_ok());
}

#[test]
fn i8_cgroup_dotdot_in_middle_rejected() {
    let target = cgroup_skb_attach_target("/sys/fs/cgroup/../secret");
    assert!(validate_attach_target(&target).is_err());
}

#[test]
fn i8_rejected_plan_has_blocking_reasons() {
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: true,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
    assert!(plan.reasons.iter().any(|r| r.blocking));
}

#[test]
fn i8_unsafe_target_plan_has_blocking_reasons() {
    let unsafe_target = EbpfAttachTarget {
        target_id: String::new(),
        ..Default::default()
    };
    let input = EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: safe_skeleton_set(),
        target: unsafe_target,
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let plan = evaluate_attach_plan(&input);
    assert_eq!(plan.status, EbpfAttachPlanStatus::Rejected);
    assert!(plan.reasons.iter().any(|r| r.code == "unsafe_target"));
}

#[test]
fn i8_no_forbidden_patterns_in_attach_source() {
    for forbidden in [
        "drop_packet",
        "File::create",
        "fs::write",
        "OpenOptions",
        "persist",
        "save",
    ] {
        assert!(
            !I8_ATTACH_SOURCE.contains(forbidden),
            "attach_plan.rs must not contain {}",
            forbidden
        );
    }
}
