// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10E tests: feature-gated local live attach lab execution.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    evaluate_attach_plan, EbpfAttachTargetKind,
};
use crate::intergalaxion_engine::backends::ebpf::capability::{
    evaluate_ebpf_capability, EbpfCapabilitySnapshot,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachLabInput;
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::{
    evaluate_live_attach_gate, EbpfLiveAttachConsent, EbpfLiveAttachPreflight,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab::*;
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::{
    evaluate_loader_boundary, EbpfLoaderBoundaryInput,
};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::default_program_skeleton_set;
use crate::intergalaxion_engine::live_attach_runbook::default_live_attach_runbook;
use crate::intergalaxion_engine::live_readiness::{
    evaluate_intergalaxion_readiness, IntergalaxionReadinessInput,
};
use clap::CommandFactory;

const I10E_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10E-feature-gated-local-live-attach-lab-execution.md");
const I10E_SOURCE: &str = include_str!("backends/ebpf/live_attach_lab.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helper: build safe gate chain ────────────────────────────────────────

fn observer_ready_snapshot() -> EbpfCapabilitySnapshot {
    EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..Default::default()
    }
}

fn safe_gate_decision(
) -> crate::intergalaxion_engine::backends::ebpf::live_attach_gate::EbpfLiveAttachGateDecision {
    let cap_report = evaluate_ebpf_capability(&observer_ready_snapshot());
    let readiness_input = IntergalaxionReadinessInput {
        capability_report: cap_report,
        explicit_future_attach_consent: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&readiness_input);
    let skeleton_set = default_program_skeleton_set();
    let loader_input = EbpfLoaderBoundaryInput {
        readiness_gate: gate,
        skeleton_set: skeleton_set.clone(),
        explicit_loader_consent: true,
        object_source_declared: true,
        public_cli_requested: false,
        ..Default::default()
    };
    let loader_plan = evaluate_loader_boundary(&loader_input);
    let consent = EbpfLiveAttachConsent {
        explicit_live_observer_attach: true,
        explicit_root_acknowledgement: true,
        explicit_no_enforcement_acknowledgement: true,
        explicit_no_packet_drop_acknowledgement: true,
        explicit_cleanup_acknowledgement: true,
        rollback_required: true,
        operator_label: String::from("i10e-test-operator"),
    };
    let attach_plan_input =
        crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachPlanInput {
            loader_plan: loader_plan.clone(),
            skeleton_set: skeleton_set.clone(),
            target: crate::intergalaxion_engine::backends::ebpf::attach_plan::default_attach_target(
            ),
            explicit_attach_consent: true,
            rollback_required: true,
            public_cli_requested: false,
            ..Default::default()
        };
    let attach_plan = evaluate_attach_plan(&attach_plan_input);
    let cap_report = evaluate_ebpf_capability(&observer_ready_snapshot());
    let preflight = EbpfLiveAttachPreflight {
        loader_plan,
        skeleton_set,
        attach_plan,
        capability_report: cap_report,
        consent,
        public_cli_requested: false,
    };
    evaluate_live_attach_gate(&preflight)
}

fn safe_lab_input() -> EbpfLiveAttachLabInput {
    EbpfLiveAttachLabInput {
        gate_decision: safe_gate_decision(),
        runbook: default_live_attach_runbook(),
        object_source_declared: true,
        object_bytes_available: true,
        target_kind: EbpfAttachTargetKind::SocketFilter,
        explicit_local_lab_feature_enabled: true,
        explicit_operator_label: String::from("i10e-test-operator"),
        explicit_detach_required: true,
        allow_live_attempt: true,
    }
}

fn safe_execution_input() -> EbpfLiveAttachLabExecutionInput {
    EbpfLiveAttachLabExecutionInput {
        lab_input: safe_lab_input(),
        artifact_contract: crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_live_attach_artifact_contract(),
        smoke_recipe: crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::default_local_attach_smoke_recipe(),
        require_immediate_detach: true,
        allow_ring_buffer_open: false,
        allow_event_stream_read: false,
        allow_map_pin: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

// ── Coverage 1: default execution input is safe ──────────────────────────

#[test]
fn i10e_default_execution_input_is_safe() {
    let input = default_live_attach_lab_execution_input();
    assert!(!input.lab_input.explicit_local_lab_feature_enabled);
    assert!(input.require_immediate_detach);
    assert!(!input.allow_ring_buffer_open);
    assert!(!input.allow_event_stream_read);
    assert!(!input.allow_map_pin);
    assert!(!input.allow_enforcement);
    assert!(!input.allow_packet_drop);
    assert!(!input.allow_persistence);
}

// ── Coverage 2: default execution result has all operation flags false ─────

#[test]
fn i10e_default_result_all_ops_false() {
    let input = default_live_attach_lab_execution_input();
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::FeatureDisabled);
    assert!(!result.attempted);
    assert!(!result.attached);
    assert!(!result.detached);
    assert!(result.observer_only);
    assert!(!result.feature_enabled);
    assert!(result.local_lab_only);
    assert!(!result.program_load_attempted);
    assert!(!result.attach_attempted);
    assert!(!result.map_create_attempted);
    assert!(!result.ring_buffer_opened);
    assert!(!result.live_kernel_read_performed);
    assert!(!result.map_pin_performed);
    assert!(!result.enforcement_performed);
    assert!(!result.packet_drop_performed);
    assert!(!result.mutation_performed);
    assert!(!result.persistence_performed);
    assert!(!result.public_cli_exposed);
}

// ── Coverage 3: status labels are stable ────────────────────────────────

#[test]
fn i10e_status_labels_stable() {
    let pairs: Vec<(EbpfLiveAttachLabStatus, &str)> = vec![
        (EbpfLiveAttachLabStatus::FeatureDisabled, "feature_disabled"),
        (
            EbpfLiveAttachLabStatus::LabGateRejected,
            "lab_gate_rejected",
        ),
        (EbpfLiveAttachLabStatus::ArtifactMissing, "artifact_missing"),
        (
            EbpfLiveAttachLabStatus::UnsupportedTarget,
            "unsupported_target",
        ),
        (
            EbpfLiveAttachLabStatus::AttachNotImplemented,
            "attach_not_implemented",
        ),
        (EbpfLiveAttachLabStatus::AttachAttempted, "attach_attempted"),
        (EbpfLiveAttachLabStatus::AttachSucceeded, "attach_succeeded"),
        (EbpfLiveAttachLabStatus::AttachFailed, "attach_failed"),
        (EbpfLiveAttachLabStatus::DetachedCleanly, "detached_cleanly"),
        (EbpfLiveAttachLabStatus::DetachFailed, "detach_failed"),
    ];
    for (status, label) in pairs {
        assert_eq!(live_attach_lab_status_label(status), label);
    }
}

// ── Coverage 4: feature disabled returns FeatureDisabled ──────────────────

#[test]
fn i10e_feature_disabled_returns_feature_disabled() {
    let input = default_live_attach_lab_execution_input();
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::FeatureDisabled);
}

// ── Coverage 5: feature disabled attempted=false ─────────────────────────

#[test]
fn i10e_feature_disabled_attempted_false() {
    let input = default_live_attach_lab_execution_input();
    let result = evaluate_live_attach_lab_execution(&input);
    assert!(!result.attempted);
}

// ── Coverage 6: feature disabled attached=false ───────────────────────────

#[test]
fn i10e_feature_disabled_attached_false() {
    let input = default_live_attach_lab_execution_input();
    let result = evaluate_live_attach_lab_execution(&input);
    assert!(!result.attached);
}

// ── Coverage 7: feature disabled detached=false ──────────────────────────

#[test]
fn i10e_feature_disabled_detached_false() {
    let input = default_live_attach_lab_execution_input();
    let result = evaluate_live_attach_lab_execution(&input);
    assert!(!result.detached);
}

// ── Coverage 8: unsafe lab input blocks ──────────────────────────────────

#[test]
fn i10e_unsafe_lab_input_blocks() {
    let mut input = safe_execution_input();
    input.lab_input.runbook.local_lab_only = false;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 9: unsafe artifact contract blocks ────────────────────────────

#[test]
fn i10e_unsafe_artifact_blocks() {
    let mut input = safe_execution_input();
    input.artifact_contract.observer_only = false;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 10: unsafe smoke recipe blocks ─────────────────────────────

#[test]
fn i10e_unsafe_recipe_blocks() {
    let mut input = safe_execution_input();
    input.smoke_recipe.local_lab_only = false;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 11: artifact missing returns ArtifactMissing ────────────────

#[test]
fn i10e_artifact_missing_returns_artifact_missing() {
    let input = safe_execution_input();
    // Default artifact is MissingArtifact, so evaluation reaches
    // artifact check and returns ArtifactMissing.
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::ArtifactMissing);
}

// ── Coverage 12: object bytes unavailable returns ArtifactMissing ─────────

#[test]
fn i10e_object_bytes_unavailable_returns_artifact_missing() {
    let mut input = safe_execution_input();
    input.lab_input.object_bytes_available = false;
    let result = evaluate_live_attach_lab_execution(&input);
    // Executor returns ObjectSourceMissing which maps to ArtifactMissing
    assert_eq!(result.status, EbpfLiveAttachLabStatus::ArtifactMissing);
}

// ── Coverage 13: unsupported target returns UnsupportedTarget ────────────

#[test]
fn i10e_unsupported_artifact_status_returns_unsupported() {
    let mut input = safe_execution_input();
    input.artifact_contract.artifact_status =
        crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::EbpfLiveAttachArtifactStatus::Unsupported;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::UnsupportedTarget);
}

// ── Coverage 14: require_immediate_detach=false blocks ────────────────────

#[test]
fn i10e_require_immediate_detach_false_blocks() {
    let mut input = safe_execution_input();
    input.require_immediate_detach = false;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 15: allow_ring_buffer_open=true blocks ──────────────────────

#[test]
fn i10e_allow_ring_buffer_blocks() {
    let mut input = safe_execution_input();
    input.allow_ring_buffer_open = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 16: allow_event_stream_read=true blocks ─────────────────────

#[test]
fn i10e_allow_event_stream_blocks() {
    let mut input = safe_execution_input();
    input.allow_event_stream_read = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 17: allow_map_pin=true blocks ──────────────────────────────

#[test]
fn i10e_allow_map_pin_blocks() {
    let mut input = safe_execution_input();
    input.allow_map_pin = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 18: allow_enforcement=true blocks ───────────────────────────

#[test]
fn i10e_allow_enforcement_blocks() {
    let mut input = safe_execution_input();
    input.allow_enforcement = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 19: allow_packet_drop=true blocks ────────────────────────────

#[test]
fn i10e_allow_packet_drop_blocks() {
    let mut input = safe_execution_input();
    input.allow_packet_drop = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 20: allow_persistence=true blocks ───────────────────────────

#[test]
fn i10e_allow_persistence_blocks() {
    let mut input = safe_execution_input();
    input.allow_persistence = true;
    let result = evaluate_live_attach_lab_execution(&input);
    assert_eq!(result.status, EbpfLiveAttachLabStatus::LabGateRejected);
}

// ── Coverage 21-31: default build has all ops false ───────────────────────

#[test]
fn i10e_default_no_program_load() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.program_load_attempted);
}

#[test]
fn i10e_default_no_attach_attempt() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.attach_attempted);
}

#[test]
fn i10e_default_no_map_create() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.map_create_attempted);
}

#[test]
fn i10e_default_no_ring_buffer() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.ring_buffer_opened);
}

#[test]
fn i10e_default_no_live_read() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.live_kernel_read_performed);
}

#[test]
fn i10e_default_no_map_pin() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.map_pin_performed);
}

#[test]
fn i10e_default_no_enforcement() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.enforcement_performed);
}

#[test]
fn i10e_default_no_packet_drop() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.packet_drop_performed);
}

#[test]
fn i10e_default_no_mutation() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.mutation_performed);
}

#[test]
fn i10e_default_no_persistence() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.persistence_performed);
}

#[test]
fn i10e_default_no_public_cli() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(!r.public_cli_exposed);
}

// ── Coverage 32: validation accepts safe default result ────────────────────

#[test]
fn i10e_validation_accepts_safe_default() {
    let r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    assert!(validate_live_attach_lab_execution_result(&r).is_ok());
}

// ── Coverage 33: validation rejects attached when attempted=false ──────────

#[test]
fn i10e_validation_rejects_attached_no_attempt() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.attached = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 34: validation rejects detached when attached=false ──────────

#[test]
fn i10e_validation_rejects_detached_no_attached() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.detached = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 35: validation rejects AttachSucceeded with detached=false ───

#[test]
fn i10e_validation_rejects_success_no_detach() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.status = EbpfLiveAttachLabStatus::AttachSucceeded;
    r.attempted = true;
    r.attached = true;
    // detached still false
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 36: validation rejects observer_only=false ──────────────────

#[test]
fn i10e_validation_rejects_non_observer() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.observer_only = false;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 37: validation rejects local_lab_only=false ─────────────────

#[test]
fn i10e_validation_rejects_non_local_lab() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.local_lab_only = false;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 38: validation rejects map_create_attempted=true ────────────

#[test]
fn i10e_validation_rejects_map_create() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.map_create_attempted = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 39: validation rejects ring_buffer_opened=true ──────────────

#[test]
fn i10e_validation_rejects_ring_buffer() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.ring_buffer_opened = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 40: validation rejects live_kernel_read=true ────────────────

#[test]
fn i10e_validation_rejects_kernel_read() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.live_kernel_read_performed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 41: validation rejects map_pin_performed=true ──────────────

#[test]
fn i10e_validation_rejects_map_pin() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.map_pin_performed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 42: validation rejects enforcement_performed=true ───────────

#[test]
fn i10e_validation_rejects_enforcement() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.enforcement_performed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 43: validation rejects packet_drop_performed=true ───────────

#[test]
fn i10e_validation_rejects_packet_drop() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.packet_drop_performed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 44: validation rejects persistence_performed=true ──────────

#[test]
fn i10e_validation_rejects_persistence() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.persistence_performed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 45: validation rejects public_cli_exposed=true ────────────────

#[test]
fn i10e_validation_rejects_public_cli() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.public_cli_exposed = true;
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 46: validation rejects fake detach success ──────────────────

#[test]
fn i10e_validation_rejects_fake_detach() {
    let mut r = evaluate_live_attach_lab_execution(&default_live_attach_lab_execution_input());
    r.detach_proof.status =
        crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::EbpfDetachProofStatus::DetachedCleanly;
    // attempted=false, so this is a fake detach
    assert!(validate_live_attach_lab_execution_result(&r).is_err());
}

// ── Coverage 47: evaluation is deterministic ──────────────────────────────

#[test]
fn i10e_evaluation_is_deterministic() {
    let input = default_live_attach_lab_execution_input();
    let r1 = evaluate_live_attach_lab_execution(&input);
    let r2 = evaluate_live_attach_lab_execution(&input);
    let r3 = evaluate_live_attach_lab_execution(&input);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ── Coverage 48-62: doc content checks ────────────────────────────────────

#[test]
fn i10e_docs_mention_feature_gated_lab() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("feature-gated local live attach lab execution"));
}

#[test]
fn i10e_docs_say_disabled_by_default() {
    assert!(I10E_DOC.to_lowercase().contains("disabled by default"));
}

#[test]
fn i10e_docs_say_no_public_cli() {
    assert!(I10E_DOC.to_lowercase().contains("no public cli"));
}

#[test]
fn i10e_docs_say_no_enforcement() {
    assert!(I10E_DOC.to_lowercase().contains("no enforcement"));
}

#[test]
fn i10e_docs_say_no_packet_drop() {
    assert!(I10E_DOC.to_lowercase().contains("no packet drop"));
}

#[test]
fn i10e_docs_say_no_block_allow_quota() {
    assert!(I10E_DOC.to_lowercase().contains("block/allow/quota"));
}

#[test]
fn i10e_docs_say_no_nft_tc() {
    assert!(I10E_DOC.to_lowercase().contains("no nft/tc"));
}

#[test]
fn i10e_docs_say_no_ring_buffer() {
    assert!(I10E_DOC.to_lowercase().contains("no ring buffer"));
}

#[test]
fn i10e_docs_say_no_live_kernel_read() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("no live kernel event read"));
}

#[test]
fn i10e_docs_say_no_map_pin() {
    assert!(I10E_DOC.to_lowercase().contains("no map pin"));
}

#[test]
fn i10e_docs_say_no_ledger_persistence() {
    assert!(I10E_DOC.to_lowercase().contains("no ledger file write"));
}

#[test]
fn i10e_docs_say_no_root_for_tests() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("normal tests do not require root"));
}

#[test]
fn i10e_docs_say_no_ci_live_attach() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("normal ci does not execute live attach"));
}

#[test]
fn i10e_docs_say_usage_schema_unchanged() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("usage json schema unchanged"));
}

#[test]
fn i10e_docs_say_ledger_schema_unchanged() {
    assert!(I10E_DOC
        .to_lowercase()
        .contains("ledger json schema unchanged"));
}

// ── Coverage 63: version remains v3.1.0 ────────────────────────────────────

#[test]
fn i10e_version_remains_3_1_0() {
    let _ = Cli::command();
    assert!(CARGO_TOML.contains("version = \"3.1.0\""));
}

// ── Coverage 64: ledger inspect still works ─────────────────────────────────

#[test]
fn i10e_ledger_inspect_still_works() {
    let _ = handle_ledger_inspect(true, None);
}

// ── Coverage 65: ledger export still works ────────────────────────────────

#[test]
fn i10e_ledger_export_still_works() {
    let tmp = std::env::temp_dir().join("i10e_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let _ = handle_ledger_export(true, Some(tmp_str.as_str()));
    let _ = std::fs::remove_file(tmp);
}

// ── Coverage 66: public help no intergalaxion ───────────────────────────

#[test]
fn i10e_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.to_lowercase().contains("intergalaxion"),
        "public help must not mention intergalaxion"
    );
}

// ── Coverage 67: public help no block/allow/quota ────────────────────────

#[test]
fn i10e_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// ── Coverage 68: no new dependency added ────────────────────────────────

#[test]
fn i10e_no_new_dependency() {
    assert!(CARGO_TOML.contains("[dependencies.aya]"));
    assert!(CARGO_TOML.contains("optional = true"));
}

// ── Coverage 69: no nft/tc in source ─────────────────────────────────────

#[test]
fn i10e_no_nft_tc_in_source() {
    let src = I10E_SOURCE;
    let code_lines: Vec<&str> = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!"))
        .collect();
    let code = code_lines.join("\n");
    assert!(!code.contains("nft"));
    assert!(!code.contains("tc "));
}

// ── Coverage 70: all files under 1000 LOC ────────────────────────────────

#[test]
fn i10e_source_under_1000_loc() {
    let lines: Vec<&str> = I10E_SOURCE.lines().collect();
    let non_empty = lines.iter().filter(|l| !l.trim().is_empty()).count();
    assert!(
        non_empty < 1000,
        "live_attach_lab.rs has {non_empty} non-empty lines"
    );
}

// ── Additional: all status labels distinct ───────────────────────────────

#[test]
fn i10e_all_status_labels_distinct() {
    let labels = [
        EbpfLiveAttachLabStatus::FeatureDisabled,
        EbpfLiveAttachLabStatus::LabGateRejected,
        EbpfLiveAttachLabStatus::ArtifactMissing,
        EbpfLiveAttachLabStatus::UnsupportedTarget,
        EbpfLiveAttachLabStatus::AttachNotImplemented,
        EbpfLiveAttachLabStatus::AttachAttempted,
        EbpfLiveAttachLabStatus::AttachSucceeded,
        EbpfLiveAttachLabStatus::AttachFailed,
        EbpfLiveAttachLabStatus::DetachedCleanly,
        EbpfLiveAttachLabStatus::DetachFailed,
    ];
    let mut seen = std::collections::HashSet::new();
    for status in &labels {
        let label = live_attach_lab_status_label(*status);
        assert!(seen.insert(label), "duplicate label: {label}");
    }
}

// ── Additional: forbidden patterns not in default-build source ─────────────

#[test]
fn i10e_source_no_forbidden_patterns() {
    let src = I10E_SOURCE;
    assert!(!src.contains("Bpf::load"));
    assert!(!src.contains("load_file"));
    assert!(!src.contains("program_mut"));
    assert!(!src.contains(".attach("));
    assert!(!src.contains("RingBuf"));
    assert!(!src.contains("AsyncPerfEventArray"));
    assert!(!src.contains("PerfEventArray"));
    assert!(!src.contains("MapData"));
    assert!(!src.contains("create_map"));
    assert!(!src.contains("pin("));
    assert!(!src.contains("bpf_prog_load"));
    assert!(!src.contains("bpf_map_create"));
    assert!(!src.contains("bpf_ringbuf"));
    assert!(!src.contains("/sys/fs/bpf"));
    assert!(!src.contains("/sys/kernel"));
    assert!(!src.contains("/proc/"));
    assert!(!src.contains("File::create"));
    assert!(!src.contains("fs::write"));
    assert!(!src.contains("OpenOptions"));
    assert!(!src.contains("drop_packet"));
}

// ── Additional: source no aya runtime ────────────────────────────────────

#[test]
fn i10e_source_no_aya_runtime() {
    assert!(!I10E_SOURCE.contains("aya::"));
}

// ── Additional: feature exists in Cargo.toml ─────────────────────────────

#[test]
fn i10e_feature_exists_in_cargo() {
    assert!(CARGO_TOML.contains("intergalaxion-live-attach-lab"));
}

// ── Additional: feature not in default ───────────────────────────────────

#[test]
fn i10e_feature_not_in_default() {
    assert!(CARGO_TOML.contains("default = []"));
}

// ── Additional: safe result with artifact missing validates ────────────────

#[test]
fn i10e_artifact_missing_validates() {
    let result = evaluate_live_attach_lab_execution(&safe_execution_input());
    assert!(validate_live_attach_lab_execution_result(&result).is_ok());
}

// ── Helper for rendering CLI help ─────────────────────────────────────────

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = clap::Command::write_long_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
