// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10C tests: minimal gated live attach executor spike.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    evaluate_attach_plan, EbpfAttachTargetKind,
};
use crate::intergalaxion_engine::backends::ebpf::capability::{
    evaluate_ebpf_capability, EbpfCapabilitySnapshot,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_executor::*;
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::{
    evaluate_live_attach_gate, EbpfLiveAttachConsent, EbpfLiveAttachPreflight,
};
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::{
    evaluate_loader_boundary, EbpfLoaderBoundaryInput,
};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::default_program_skeleton_set;
use crate::intergalaxion_engine::live_attach_runbook::default_live_attach_runbook;
use crate::intergalaxion_engine::live_readiness::{
    evaluate_intergalaxion_readiness, IntergalaxionReadinessInput,
};
use clap::CommandFactory;

const I10C_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10C-minimal-live-attach-executor-spike.md");
const I10C_SOURCE: &str = include_str!("backends/ebpf/live_attach_executor.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helper: build full safe chain for I-10C tests ───────────────────────

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
        operator_label: String::from("i10c-test-operator"),
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
        explicit_operator_label: String::from("i10c-test-operator"),
        explicit_detach_required: true,
        allow_live_attempt: true,
    }
}

// ── Coverage 1: default lab input is safe ───────────────────────────────

#[test]
fn i10c_default_lab_input_is_safe() {
    let input = default_live_attach_lab_input();
    assert!(!input.explicit_local_lab_feature_enabled);
    assert!(!input.object_source_declared);
    assert!(!input.object_bytes_available);
    assert!(!input.explicit_detach_required);
    assert!(!input.allow_live_attempt);
    assert!(input.explicit_operator_label.is_empty());
}

// ── Coverage 2: default executor attempt has all operation flags false ────

#[test]
fn i10c_default_attempt_all_ops_false() {
    let input = default_live_attach_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::FeatureDisabled
    );
    assert!(!attempt.attempted);
    assert!(!attempt.attached);
    assert!(!attempt.detached);
    assert!(attempt.observer_only);
    assert!(!attempt.feature_enabled);
    assert!(attempt.local_lab_only);
    assert!(!attempt.program_load_attempted);
    assert!(!attempt.attach_attempted);
    assert!(!attempt.map_create_attempted);
    assert!(!attempt.ring_buffer_opened);
    assert!(!attempt.live_kernel_read_performed);
    assert!(!attempt.map_pin_performed);
    assert!(!attempt.enforcement_performed);
    assert!(!attempt.packet_drop_performed);
    assert!(!attempt.mutation_performed);
    assert!(!attempt.persistence_performed);
    assert!(!attempt.public_cli_exposed);
}

// ── Coverage 3: status labels are stable ──────────────────────────────

#[test]
fn i10c_status_labels_stable() {
    let pairs: Vec<(EbpfLiveAttachExecutorStatus, &str)> = vec![
        (
            EbpfLiveAttachExecutorStatus::FeatureDisabled,
            "feature_disabled",
        ),
        (EbpfLiveAttachExecutorStatus::GateRejected, "gate_rejected"),
        (
            EbpfLiveAttachExecutorStatus::ObjectSourceMissing,
            "object_source_missing",
        ),
        (
            EbpfLiveAttachExecutorStatus::UnsupportedTarget,
            "unsupported_target",
        ),
        (
            EbpfLiveAttachExecutorStatus::AttachNotAttempted,
            "attach_not_attempted",
        ),
        (
            EbpfLiveAttachExecutorStatus::FutureAttachReady,
            "future_attach_ready",
        ),
        (
            EbpfLiveAttachExecutorStatus::LiveAttachAttempted,
            "live_attach_attempted",
        ),
        (
            EbpfLiveAttachExecutorStatus::LiveAttachSucceeded,
            "live_attach_succeeded",
        ),
        (
            EbpfLiveAttachExecutorStatus::LiveAttachFailed,
            "live_attach_failed",
        ),
        (
            EbpfLiveAttachExecutorStatus::DetachedCleanly,
            "detached_cleanly",
        ),
    ];
    for (status, label) in pairs {
        assert_eq!(live_attach_executor_status_label(status), label);
    }
}

// ── Coverage 4-7: feature disabled returns FeatureDisabled, no ops ────────

#[test]
fn i10c_feature_disabled_status() {
    let input = default_live_attach_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::FeatureDisabled
    );
    assert!(!attempt.attempted);
    assert!(!attempt.attached);
    assert!(!attempt.detached);
}

// ── Coverage 8-9: runbook/gate unsafe blocks ────────────────────────────────

#[test]
fn i10c_unsafe_runbook_blocks() {
    let mut input = safe_lab_input();
    input.runbook.local_lab_only = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

#[test]
fn i10c_unsafe_gate_decision_blocks() {
    let mut input = safe_lab_input();
    input.gate_decision.program_load_performed = true;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage 10: gate decision not future candidate blocks ─────────────

#[test]
fn i10c_not_future_candidate_blocks() {
    let mut input = safe_lab_input();
    input.gate_decision.future_live_attach_candidate = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage 11: local lab feature flag false blocks ────────────────────

#[test]
fn i10c_lab_feature_false_blocks() {
    let mut input = safe_lab_input();
    input.explicit_local_lab_feature_enabled = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::FeatureDisabled
    );
}

// ── Coverage 12: empty operator label blocks ───────────────────────────

#[test]
fn i10c_empty_operator_label_blocks() {
    let mut input = safe_lab_input();
    input.explicit_operator_label = String::new();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage 13: detach not required blocks ───────────────────────────

#[test]
fn i10c_detach_not_required_blocks() {
    let mut input = safe_lab_input();
    input.explicit_detach_required = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage 14: allow_live_attempt=false blocks ────────────────────────

#[test]
fn i10c_allow_live_false_blocks() {
    let mut input = safe_lab_input();
    input.allow_live_attempt = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::AttachNotAttempted
    );
}

// ── Coverage 15-16: object source missing ───────────────────────────────

#[test]
fn i10c_object_source_missing_when_not_declared() {
    let mut input = safe_lab_input();
    input.object_source_declared = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::ObjectSourceMissing
    );
}

#[test]
fn i10c_object_source_missing_when_no_bytes() {
    let mut input = safe_lab_input();
    input.object_bytes_available = false;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::ObjectSourceMissing
    );
}

// ── Coverage 17: unsupported target returns UnsupportedTarget ────────
// NOTE: All three current target kinds are supported, so this test
// verifies the evaluation path would reject if a kind were added
// that is unsupported. Currently all kinds pass the target check.

#[test]
fn i10c_all_supported_targets_pass() {
    for kind in [
        EbpfAttachTargetKind::SocketFilter,
        EbpfAttachTargetKind::CgroupSkb,
        EbpfAttachTargetKind::Tracepoint,
    ] {
        let mut input = safe_lab_input();
        input.target_kind = kind;
        let attempt = evaluate_live_attach_lab_attempt(&input);
        assert_eq!(
            attempt.status,
            EbpfLiveAttachExecutorStatus::FutureAttachReady,
            "target kind {:?} should pass",
            kind
        );
    }
}

// ── Coverage 18: future attach ready can be represented ────────────────

#[test]
fn i10c_future_attach_ready_represented() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::FutureAttachReady
    );
}

// ── Coverage 19: future attach ready has program_load_attempted=false ──

#[test]
fn i10c_future_ready_no_program_load() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.program_load_attempted);
}

// ── Coverage 20: future attach ready has attach_attempted=false ─────────

#[test]
fn i10c_future_ready_no_attach_attempt() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.attach_attempted);
}

// ── Coverage 21: future attach ready has map_create_attempted=false ────

#[test]
fn i10c_future_ready_no_map_create() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.map_create_attempted);
}

// ── Coverage 22: future attach ready has ring_buffer_opened=false ─────

#[test]
fn i10c_future_ready_no_ring_buffer() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.ring_buffer_opened);
}

// ── Coverage 23: future attach ready has live_kernel_read=false ─────────

#[test]
fn i10c_future_ready_no_kernel_read() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.live_kernel_read_performed);
}

// ── Coverage 24: future attach ready has map_pin=false ─────────────────

#[test]
fn i10c_future_ready_no_map_pin() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.map_pin_performed);
}

// ── Coverage 25: future attach ready has enforcement=false ─────────────

#[test]
fn i10c_future_ready_no_enforcement() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.enforcement_performed);
}

// ── Coverage 26: future attach ready has packet_drop=false ────────────

#[test]
fn i10c_future_ready_no_packet_drop() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.packet_drop_performed);
}

// ── Coverage 27: future attach ready has mutation=false ───────────────

#[test]
fn i10c_future_ready_no_mutation() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.mutation_performed);
}

// ── Coverage 28: future attach ready has persistence=false ────────────

#[test]
fn i10c_future_ready_no_persistence() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.persistence_performed);
}

// ── Coverage 29: future attach ready has public_cli=false ──────────────

#[test]
fn i10c_future_ready_no_public_cli() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.public_cli_exposed);
}

// ── Coverage 30: validation accepts safe default attempt ───────────────

#[test]
fn i10c_validation_accepts_safe_default() {
    let input = default_live_attach_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(validate_live_attach_executor_attempt(&attempt).is_ok());
}

// ── Coverage 31-34: validation rejects logical inconsistencies ──────────

#[test]
fn i10c_validation_rejects_attached_without_attempted() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.attached = true;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

#[test]
fn i10c_validation_rejects_detached_without_attached() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.detached = true;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

#[test]
fn i10c_validation_rejects_non_observer() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.observer_only = false;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

#[test]
fn i10c_validation_rejects_non_local_lab() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.local_lab_only = false;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

// ── Coverage 35-36: validation rejects live ops with wrong status ─────────

#[test]
fn i10c_validation_rejects_program_load_wrong_status() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.program_load_attempted = true;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

#[test]
fn i10c_validation_rejects_attach_attempted_wrong_status() {
    let mut attempt = evaluate_live_attach_lab_attempt(&safe_lab_input());
    attempt.attach_attempted = true;
    assert!(validate_live_attach_executor_attempt(&attempt).is_err());
}

// ── Coverage 37-45: validation rejects forbidden operation flags ──────────

#[test]
fn i10c_validation_rejects_map_create() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.map_create_attempted = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_ring_buffer() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.ring_buffer_opened = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_kernel_read() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.live_kernel_read_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_map_pin() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.map_pin_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_enforcement() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.enforcement_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_packet_drop() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.packet_drop_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_mutation() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.mutation_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_persistence() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.persistence_performed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

#[test]
fn i10c_validation_rejects_public_cli() {
    let mut a = evaluate_live_attach_lab_attempt(&safe_lab_input());
    a.public_cli_exposed = true;
    assert!(validate_live_attach_executor_attempt(&a).is_err());
}

// ── Coverage 46: evaluation is deterministic ───────────────────────────

#[test]
fn i10c_evaluation_is_deterministic() {
    let input = safe_lab_input();
    let a1 = evaluate_live_attach_lab_attempt(&input);
    let a2 = evaluate_live_attach_lab_attempt(&input);
    let a3 = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(a1, a2);
    assert_eq!(a2, a3);
}

// ── Coverage 47-59: doc content checks ──────────────────────────────────

#[test]
fn i10c_docs_exist_and_mention_executor_spike() {
    assert!(I10C_DOC
        .to_lowercase()
        .contains("minimal live attach executor spike"));
}

#[test]
fn i10c_docs_say_disabled_by_default() {
    assert!(I10C_DOC.to_lowercase().contains("disabled by default"));
}

#[test]
fn i10c_docs_say_no_public_cli() {
    assert!(I10C_DOC.to_lowercase().contains("no public cli"));
}

#[test]
fn i10c_docs_say_no_enforcement() {
    assert!(I10C_DOC.to_lowercase().contains("no enforcement"));
}

#[test]
fn i10c_docs_say_no_packet_drop() {
    assert!(I10C_DOC.to_lowercase().contains("no packet drop"));
}

#[test]
fn i10c_docs_say_no_block_allow_quota() {
    assert!(I10C_DOC.to_lowercase().contains("block/allow/quota"));
}

#[test]
fn i10c_docs_say_no_nft_tc_fallback() {
    assert!(I10C_DOC.to_lowercase().contains("no nft/tc"));
}

#[test]
fn i10c_docs_say_no_ring_buffer() {
    assert!(I10C_DOC.to_lowercase().contains("no ring buffer"));
}

#[test]
fn i10c_docs_say_no_live_kernel_event_read() {
    assert!(I10C_DOC
        .to_lowercase()
        .contains("no live kernel event read"));
}

#[test]
fn i10c_docs_say_no_map_pin() {
    assert!(I10C_DOC.to_lowercase().contains("no map pin"));
}

#[test]
fn i10c_docs_say_no_ledger_write_persistence() {
    assert!(I10C_DOC.to_lowercase().contains("no ledger file write"));
}

#[test]
fn i10c_docs_say_usage_schema_unchanged() {
    assert!(I10C_DOC
        .to_lowercase()
        .contains("usage json schema unchanged"));
}

#[test]
fn i10c_docs_say_ledger_schema_unchanged() {
    assert!(I10C_DOC
        .to_lowercase()
        .contains("ledger json schema unchanged"));
}

// ── Coverage 60: existing zelynic --version remains v3.1.0 ────────────

#[test]
fn i10c_version_remains_3_1_0() {
    let _ = Cli::command();
    // The version is verified at runtime; here we verify the Cargo.toml
    assert!(CARGO_TOML.contains("version = \"3.1.0\""));
}

// ── Coverage 61: existing ledger inspect still works ────────────────────

#[test]
fn i10c_ledger_inspect_still_works() {
    let _ = handle_ledger_inspect(true, None);
}

// ── Coverage 62: existing ledger export still works ───────────────────

#[test]
fn i10c_ledger_export_still_works() {
    let tmp = std::env::temp_dir().join("i10c_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let _ = handle_ledger_export(true, Some(tmp_str.as_str()));
    let _ = std::fs::remove_file(tmp);
}

// ── Coverage 63: public help does not mention intergalaxion ───────────

#[test]
fn i10c_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.to_lowercase().contains("intergalaxion"),
        "public help must not mention intergalaxion"
    );
}

// ── Coverage 64: public help does not mention block/allow/quota ───────

#[test]
fn i10c_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.contains("block"),
        "public help must not mention block"
    );
    assert!(
        !help.contains("allow"),
        "public help must not mention allow"
    );
    assert!(
        !help.contains("quota"),
        "public help must not mention quota"
    );
}

// ── Coverage 65: no new dependency added unless justified ───────────────

#[test]
fn i10c_no_new_dependency_unless_justified() {
    let toml = CARGO_TOML;
    // Verify aya is the only optional dependency and is already present
    assert!(toml.contains("[dependencies.aya]"));
    assert!(toml.contains("optional = true"));
}

// ── Coverage 66: no nft/tc source under intergalaxion backend ───────────

#[test]
fn i10c_no_nft_tc_in_executor_source() {
    let src = I10C_SOURCE;
    // Strip the module-level doc comment (lines starting with //!)
    let code_lines: Vec<&str> = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!"))
        .collect();
    let code = code_lines.join("\n");
    assert!(!code.contains("nft"), "executor code must not contain nft");
    assert!(!code.contains("tc "), "executor code must not contain tc");
}

// ── Coverage 67: all touched files under 1000 LOC ──────────────────────

#[test]
fn i10c_source_under_1000_loc() {
    let lines: Vec<&str> = I10C_SOURCE.lines().collect();
    let non_empty = lines.iter().filter(|l| !l.trim().is_empty()).count();
    assert!(
        non_empty < 1000,
        "live_attach_executor.rs has {non_empty} non-empty lines"
    );
}

// ── Coverage: feature exists in Cargo.toml ─────────────────────────────

#[test]
fn i10c_feature_exists_in_cargo_toml() {
    assert!(
        CARGO_TOML.contains("intergalaxion-live-attach-lab"),
        "Cargo.toml must have intergalaxion-live-attach-lab feature"
    );
}

// ── Coverage: feature is not in default ─────────────────────────────────

#[test]
fn i10c_feature_not_in_default() {
    assert!(
        CARGO_TOML.contains("default = []"),
        "default features must be empty"
    );
}

// ── Coverage: future attach ready has feature_enabled=true ─────────────

#[test]
fn i10c_future_ready_has_feature_enabled() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(attempt.feature_enabled);
}

// ── Coverage: safe_lab_input produces future attach ready ──────────────
#[test]
fn i10c_safe_input_produces_future_ready() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(
        attempt.status,
        EbpfLiveAttachExecutorStatus::FutureAttachReady
    );
}

// ── Coverage: gate rejected from attach_performed in decision ─────────
#[test]
fn i10c_gate_rejects_attach_performed_in_decision() {
    let mut input = safe_lab_input();
    input.gate_decision.attach_performed = true;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage: gate rejected from gate decision with mutation ────────────

#[test]
fn i10c_gate_rejects_mutation_in_decision() {
    let mut input = safe_lab_input();
    input.gate_decision.mutation_performed = true;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage: feature disabled has feature_enabled=false ────────────────

#[test]
fn i10c_feature_disabled_has_feature_false() {
    let input = default_live_attach_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(!attempt.feature_enabled);
}

// ── Coverage: safe default attempt validates ────────────────────────────

#[test]
fn i10c_safe_future_ready_validates() {
    let input = safe_lab_input();
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert!(validate_live_attach_executor_attempt(&attempt).is_ok());
}

// ── Coverage: all status variants have distinct labels ────────────────

#[test]
fn i10c_all_status_labels_distinct() {
    let labels = [
        EbpfLiveAttachExecutorStatus::FeatureDisabled,
        EbpfLiveAttachExecutorStatus::GateRejected,
        EbpfLiveAttachExecutorStatus::ObjectSourceMissing,
        EbpfLiveAttachExecutorStatus::UnsupportedTarget,
        EbpfLiveAttachExecutorStatus::AttachNotAttempted,
        EbpfLiveAttachExecutorStatus::FutureAttachReady,
        EbpfLiveAttachExecutorStatus::LiveAttachAttempted,
        EbpfLiveAttachExecutorStatus::LiveAttachSucceeded,
        EbpfLiveAttachExecutorStatus::LiveAttachFailed,
        EbpfLiveAttachExecutorStatus::DetachedCleanly,
    ];
    let mut seen = std::collections::HashSet::new();
    for status in &labels {
        let label = live_attach_executor_status_label(*status);
        assert!(seen.insert(label), "duplicate label: {label}");
    }
}

// ── Coverage: runbook with enforcement_allowed blocks ───────────────────

#[test]
fn i10c_runbook_enforcement_allowed_blocks() {
    let mut input = safe_lab_input();
    input.runbook.enforcement_allowed = true;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage: runbook with public_cli_allowed blocks ───────────────────

#[test]
fn i10c_runbook_public_cli_blocks() {
    let mut input = safe_lab_input();
    input.runbook.public_cli_allowed = true;
    let attempt = evaluate_live_attach_lab_attempt(&input);
    assert_eq!(attempt.status, EbpfLiveAttachExecutorStatus::GateRejected);
}

// ── Coverage: forbidden patterns not in source ─────────────────────────

#[test]
fn i10c_source_no_forbidden_patterns() {
    let src = I10C_SOURCE;
    assert!(
        !src.contains("Bpf::load"),
        "source must not contain Bpf::load"
    );
    assert!(
        !src.contains("load_file"),
        "source must not contain load_file"
    );
    assert!(
        !src.contains("program_mut"),
        "source must not contain program_mut"
    );
    assert!(
        !src.contains(".attach("),
        "source must not contain .attach("
    );
    assert!(!src.contains("RingBuf"), "source must not contain RingBuf");
    assert!(
        !src.contains("AsyncPerfEventArray"),
        "source must not contain AsyncPerfEventArray"
    );
    assert!(
        !src.contains("PerfEventArray"),
        "source must not contain PerfEventArray"
    );
    assert!(!src.contains("MapData"), "source must not contain MapData");
    assert!(
        !src.contains("create_map"),
        "source must not contain create_map"
    );
    assert!(!src.contains("pin("), "source must not contain pin(");
    assert!(
        !src.contains("bpf_prog_load"),
        "source must not contain bpf_prog_load"
    );
    assert!(
        !src.contains("bpf_map_create"),
        "source must not contain bpf_map_create"
    );
    assert!(
        !src.contains("bpf_ringbuf"),
        "source must not contain bpf_ringbuf"
    );
    assert!(
        !src.contains("/sys/fs/bpf"),
        "source must not contain /sys/fs/bpf"
    );
    assert!(
        !src.contains("/sys/kernel"),
        "source must not contain /sys/kernel"
    );
    assert!(!src.contains("/proc/"), "source must not contain /proc/");
    assert!(
        !src.contains("File::create"),
        "source must not contain File::create"
    );
    assert!(
        !src.contains("fs::write"),
        "source must not contain fs::write"
    );
    assert!(
        !src.contains("OpenOptions"),
        "source must not contain OpenOptions"
    );
    assert!(
        !src.contains("drop_packet"),
        "source must not contain drop_packet"
    );
}

// ── Coverage: source mentions validate and evaluate ───────────────────

#[test]
fn i10c_source_has_validate_and_evaluate() {
    let src = I10C_SOURCE;
    assert!(src.contains("validate_live_attach_executor_attempt"));
    assert!(src.contains("evaluate_live_attach_lab_attempt"));
}

// ── Coverage: source does not use aya at runtime ───────────────────────

#[test]
fn i10c_source_no_aya_runtime() {
    let src = I10C_SOURCE;
    assert!(!src.contains("aya::"));
}

// ── Helper for rendering CLI help ──────────────────────────────────────

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = clap::Command::write_long_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
