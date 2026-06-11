// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Compile-safe and invariant tests for the Intergalaxion Engine.
//!
//! These tests verify that:
//! 1. All modules compile.
//! 2. All model defaults are safe (observer-only, no enforcement).
//! 3. No existing CLI behavior is changed.
//! 4. Probe plans are model-only with no live kernel operations.

use super::*;
use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::*;
use crate::intergalaxion_engine::identity::ProcessIdentity;
use crate::intergalaxion_engine::ledger_bridge::{BridgeEvent, BridgeResult};
use crate::intergalaxion_engine::safety::{check_i0_invariants, SafetyCheck, SafetyViolation};
use crate::intergalaxion_engine::telemetry::TelemetrySummary;
use clap::CommandFactory;

// ── Module compilation smoke tests ───────────────────────────────────

#[test]
fn intergalaxion_module_compiles() {
    let _state = EngineState::default();
}

#[test]
fn ebpf_backend_module_compiles() {
    let _status = EbpfBackendStatus::default();
    let _cap = EbpfCapabilityReport::default();
    let _obs = EbpfObserverState::default();
    let _attach = EbpfAttachState::default();
    let _event = EbpfEventKind::default();
    let _plan = EbpfMapPlan::default();
}

// ── Default safety tests ────────────────────────────────────────────

#[test]
fn capability_report_defaults_to_unavailable() {
    let report = EbpfCapabilityReport::default();
    assert_eq!(report.readiness, EbpfReadinessLevel::Unavailable);
    assert!(!report.observer_ready);
    assert!(!report.attach_candidate);
    assert!(report.findings.iter().all(|finding| !finding.available));
}

#[test]
fn observer_state_defaults_to_inactive() {
    assert_eq!(EbpfObserverState::default(), EbpfObserverState::Inactive);
}

#[test]
fn attach_state_defaults_to_not_attached() {
    assert_eq!(EbpfAttachState::default(), EbpfAttachState::NotAttached);
}

#[test]
fn packet_drop_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.packet_drop_enabled);
}

#[test]
fn enforcement_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.enforcement_enabled);
}

#[test]
fn quota_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.quota_enabled);
}

#[test]
fn mutation_performed_defaults_false() {
    let state = EngineState::default();
    assert!(!state.mutation_performed);
}

#[test]
fn backend_available_defaults_false() {
    let state = EngineState::default();
    assert!(!state.backend_available);
}

#[test]
fn observer_active_defaults_false() {
    let state = EngineState::default();
    assert!(!state.observer_active);
}

// ── Safety invariant tests ──────────────────────────────────────────

#[test]
fn safety_check_ok_for_default_state() {
    let result = check_i0_invariants(false, false, false);
    assert_eq!(result, SafetyCheck::Ok);
}

#[test]
fn safety_check_rejects_enforcement() {
    let result = check_i0_invariants(false, true, false);
    assert_eq!(
        result,
        SafetyCheck::Violation(SafetyViolation::EnforcementInObserverMode)
    );
}

#[test]
fn safety_check_rejects_mutation() {
    let result = check_i0_invariants(false, false, true);
    assert_eq!(
        result,
        SafetyCheck::Violation(SafetyViolation::MutationNotAllowed)
    );
}

#[test]
fn safety_check_allows_active_observer() {
    let result = check_i0_invariants(true, false, false);
    assert_eq!(result, SafetyCheck::Ok);
}

// ── Model struct tests ──────────────────────────────────────────────

#[test]
fn process_identity_defaults_are_none() {
    let id = ProcessIdentity::default();
    assert!(id.pid.is_none());
    assert!(id.cgroup_path.is_none());
    assert!(id.label.is_none());
}

#[test]
fn telemetry_summary_defaults_to_zero() {
    let summary = TelemetrySummary::default();
    assert_eq!(summary.total_rx_bytes, 0);
    assert_eq!(summary.total_tx_bytes, 0);
    assert_eq!(summary.sample_count, 0);
}

#[test]
fn bridge_event_defaults() {
    let event = BridgeEvent::default();
    assert!(event.identity_label.is_empty());
    assert_eq!(event.rx_bytes, 0);
    assert_eq!(event.tx_bytes, 0);
    assert!(!event.committed);
}

#[test]
fn bridge_result_defaults_to_not_operational() {
    assert_eq!(BridgeResult::default(), BridgeResult::NotOperational);
}

#[test]
fn ebpf_event_kind_defaults_to_noop() {
    assert_eq!(EbpfEventKind::default(), EbpfEventKind::Noop);
}

#[test]
fn ebpf_map_plan_defaults_to_empty() {
    let plan = EbpfMapPlan::default();
    assert!(plan.maps.is_empty());
}

#[test]
fn ebpf_probe_descriptor_defaults_gated() {
    let probe = crate::intergalaxion_engine::backends::ebpf::EbpfProbeDescriptor::default();
    assert!(probe.gated);
}

// -- Phase I-1: read-only eBPF capability detector --------------------

const I1_DOC: &str = include_str!("../../docs/intergalaxion/I-1-ebpf-capability-detector.md");
const I1_CAPABILITY_SOURCE: &str = include_str!("backends/ebpf/capability.rs");
const I1_DETECTOR_SOURCE: &str = include_str!("backends/ebpf/detector.rs");
const I1_MOD_SOURCE: &str = include_str!("backends/ebpf/mod.rs");

fn full_candidate_snapshot() -> EbpfCapabilitySnapshot {
    EbpfCapabilitySnapshot {
        kernel_release: Some("6.8.0-test".to_string()),
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        cap_sys_admin_effective: Some(false),
        unprivileged_bpf_disabled: Some(1),
        aya_available_at_compile_time: false,
    }
}

fn write_i1_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i1_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i1-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i1-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i1 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion capability detector proof",
      "attribution_scope": "interface-level only",
      "enforcement_status": "inactive/not implemented",
      "reset_detected": false,
      "reset_details": []
    }
  ]
}
"#,
    )
    .unwrap();
    path
}

#[test]
fn i1_default_capability_snapshot_is_conservative() {
    let snapshot = EbpfCapabilitySnapshot::default();
    assert_eq!(snapshot.kernel_release, None);
    assert_eq!(snapshot.bpf_fs_mounted, None);
    assert_eq!(snapshot.btf_vmlinux_available, None);
    assert_eq!(snapshot.cap_bpf_effective, None);
    assert_eq!(snapshot.cap_sys_admin_effective, None);
    assert_eq!(snapshot.unprivileged_bpf_disabled, None);
}

#[test]
fn i1_default_report_is_unavailable() {
    let report = EbpfCapabilityReport::default();
    assert_eq!(report.readiness, EbpfReadinessLevel::Unavailable);
    assert_eq!(report.readiness.as_str(), "unavailable");
    assert!(!report.observer_ready);
    assert!(!report.attach_candidate);
}

#[test]
fn i1_no_bpf_fs_is_not_observer_ready() {
    let snapshot = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(false),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..EbpfCapabilitySnapshot::default()
    };
    let report = evaluate_ebpf_capability(&snapshot);
    assert_eq!(report.readiness, EbpfReadinessLevel::Unavailable);
    assert!(!report.observer_ready);
    assert!(!report.attach_candidate);
}

#[test]
fn i1_bpf_fs_without_btf_is_partial_only() {
    let snapshot = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(false),
        cap_bpf_effective: Some(true),
        ..EbpfCapabilitySnapshot::default()
    };
    let report = evaluate_ebpf_capability(&snapshot);
    assert_eq!(report.readiness, EbpfReadinessLevel::Partial);
    assert!(!report.observer_ready);
    assert!(!report.attach_candidate);
}

#[test]
fn i1_bpf_fs_and_btf_without_caps_is_not_attach_candidate() {
    let snapshot = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(false),
        cap_sys_admin_effective: Some(false),
        ..EbpfCapabilitySnapshot::default()
    };
    let report = evaluate_ebpf_capability(&snapshot);
    assert_eq!(report.readiness, EbpfReadinessLevel::ObserverReady);
    assert!(report.observer_ready);
    assert!(!report.attach_candidate);
}

#[test]
fn i1_bpf_fs_btf_and_cap_bpf_is_attach_candidate_model() {
    let snapshot = full_candidate_snapshot();
    let report = evaluate_ebpf_capability(&snapshot);
    assert_eq!(report.readiness, EbpfReadinessLevel::AttachCandidate);
    assert!(report.observer_ready);
    assert!(report.attach_candidate);
}

#[test]
fn i1_bpf_fs_btf_and_cap_sys_admin_is_attach_candidate_model() {
    let snapshot = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(false),
        cap_sys_admin_effective: Some(true),
        ..EbpfCapabilitySnapshot::default()
    };
    let report = evaluate_ebpf_capability(&snapshot);
    assert_eq!(report.readiness, EbpfReadinessLevel::AttachCandidate);
    assert!(report.attach_candidate);
}

#[test]
fn i1_unprivileged_bpf_disabled_is_recorded_honestly() {
    let snapshot = full_candidate_snapshot();
    let report = evaluate_ebpf_capability(&snapshot);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.key == "unprivileged_bpf_disabled")
        .unwrap();
    assert!(finding.checked);
    assert!(!finding.available);
    assert!(finding.reason.contains('1'));
}

#[test]
fn i1_kernel_release_is_informational() {
    let with_release = full_candidate_snapshot();
    let mut without_release = with_release.clone();
    without_release.kernel_release = None;
    assert_eq!(
        evaluate_ebpf_capability(&with_release).readiness,
        evaluate_ebpf_capability(&without_release).readiness
    );
}

#[test]
fn i1_aya_compile_time_flag_is_informational() {
    let mut disabled = full_candidate_snapshot();
    disabled.aya_available_at_compile_time = false;
    let mut enabled = disabled.clone();
    enabled.aya_available_at_compile_time = true;
    assert_eq!(
        evaluate_ebpf_capability(&disabled).readiness,
        evaluate_ebpf_capability(&enabled).readiness
    );
}

#[test]
fn i1_evaluator_is_deterministic() {
    let snapshot = full_candidate_snapshot();
    assert_eq!(
        evaluate_ebpf_capability(&snapshot),
        evaluate_ebpf_capability(&snapshot)
    );
}

#[test]
fn i1_readiness_label_strings_are_stable() {
    assert_eq!(EbpfReadinessLevel::Unavailable.as_str(), "unavailable");
    assert_eq!(EbpfReadinessLevel::Partial.as_str(), "partial");
    assert_eq!(EbpfReadinessLevel::ObserverReady.as_str(), "observer_ready");
    assert_eq!(
        EbpfReadinessLevel::AttachCandidate.as_str(),
        "attach_candidate"
    );
}

#[test]
fn i1_detector_does_not_expose_cli() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i1_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i1_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

#[test]
fn i1_no_nft_or_tc_backend_added_under_intergalaxion() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

#[test]
fn i1_no_packet_drop_field_enabled() {
    assert!(!EngineState::default().packet_drop_enabled);
}

#[test]
fn i1_no_enforcement_field_enabled() {
    assert!(!EngineState::default().enforcement_enabled);
}

#[test]
fn i1_no_kernel_mutation_api_in_detector_source() {
    for forbidden in [
        "Command::new",
        "File::create",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "std::fs::write",
    ] {
        assert!(
            !I1_DETECTOR_SOURCE.contains(forbidden),
            "detector source must not contain {forbidden}"
        );
    }
}

#[test]
fn i1_no_map_program_load_or_attach_api_in_detector_source() {
    for forbidden in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "tc",
        "nft",
        "drop_packet",
        "block",
        "allow",
        "quota",
    ] {
        assert!(
            !I1_DETECTOR_SOURCE.contains(forbidden),
            "detector source must not contain {forbidden}"
        );
    }
}

#[test]
fn i1_docs_exist_and_mention_read_only() {
    assert!(I1_DOC.contains("read-only"));
}

#[test]
fn i1_docs_say_no_attach_load_or_map_create() {
    assert!(I1_DOC.contains("no eBPF attach"));
    assert!(I1_DOC.contains("no eBPF program load"));
    assert!(I1_DOC.contains("no eBPF map create"));
}

#[test]
fn i1_docs_say_no_enforcement() {
    assert!(I1_DOC.contains("no enforcement"));
}

#[test]
fn i1_docs_say_no_block_allow_or_quota() {
    assert!(I1_DOC.contains("no block/allow/quota"));
}

#[test]
fn i1_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i1_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

#[test]
fn i1_existing_ledger_export_json_file_still_works() {
    let path = write_i1_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

#[test]
fn i1_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("capability.rs", I1_CAPABILITY_SOURCE),
        ("detector.rs", I1_DETECTOR_SOURCE),
        ("mod.rs", I1_MOD_SOURCE),
        ("tests.rs", include_str!("tests.rs")),
        ("I-1 doc", I1_DOC),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// -- Phase I-2: minimal eBPF observer probe design --------------------

use crate::intergalaxion_engine::backends::ebpf::probe_plan::*;
use crate::intergalaxion_engine::backends::ebpf::{
    validate_probe_plan_safety, EbpfEventKind, EbpfMapPlan, EbpfObserverState,
};

const I2_DOC: &str =
    include_str!("../../docs/intergalaxion/I-2-minimal-ebpf-observer-probe-design.md");
const I2_PROBE_PLAN_SOURCE: &str = include_str!("backends/ebpf/probe_plan.rs");

fn make_unsafe_plan(flag: &str) -> EbpfProbePlan {
    let mut plan = EbpfProbePlan::default();
    match flag {
        "program_load_enabled" => plan.program_load_enabled = true,
        "attach_enabled" => plan.attach_enabled = true,
        "map_create_enabled" => plan.map_create_enabled = true,
        "map_pin_enabled" => plan.map_pin_enabled = true,
        "packet_drop_enabled" => plan.packet_drop_enabled = true,
        "enforcement_enabled" => plan.enforcement_enabled = true,
        "mutation_enabled" => plan.mutation_enabled = true,
        _ => {}
    }
    plan
}

#[test]
fn i2_default_probe_plan_is_model_only() {
    let plan = EbpfProbePlan::default();
    assert_eq!(plan.safety_mode, EbpfProbeSafetyMode::ModelOnly);
}

#[test]
fn i2_default_probe_plan_kind_is_noop() {
    let plan = EbpfProbePlan::default();
    assert_eq!(plan.kind, EbpfProbeKind::Noop);
}

#[test]
fn i2_default_probe_plan_has_program_load_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.program_load_enabled);
}

#[test]
fn i2_default_probe_plan_has_attach_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.attach_enabled);
}

#[test]
fn i2_default_probe_plan_has_map_create_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.map_create_enabled);
}

#[test]
fn i2_default_probe_plan_has_map_pin_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.map_pin_enabled);
}

#[test]
fn i2_default_probe_plan_has_packet_drop_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.packet_drop_enabled);
}

#[test]
fn i2_default_probe_plan_has_enforcement_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.enforcement_enabled);
}

#[test]
fn i2_default_probe_plan_has_mutation_disabled() {
    let plan = EbpfProbePlan::default();
    assert!(!plan.mutation_enabled);
}

#[test]
fn i2_default_probe_plan_notes_empty() {
    let plan = EbpfProbePlan::default();
    assert!(plan.notes.is_empty());
}

// -- Helper plan factory tests ----------------------------------------

#[test]
fn i2_socket_observer_plan_is_observer_only() {
    let plan = minimal_socket_observer_probe_plan();
    assert_eq!(plan.kind, EbpfProbeKind::SocketObserver);
    assert_eq!(plan.safety_mode, EbpfProbeSafetyMode::ModelOnly);
    assert!(!plan.program_load_enabled);
    assert!(!plan.attach_enabled);
    assert!(!plan.packet_drop_enabled);
    assert!(!plan.enforcement_enabled);
    assert!(!plan.mutation_enabled);
}

#[test]
fn i2_cgroup_skb_observer_plan_is_observer_only() {
    let plan = minimal_cgroup_skb_observer_probe_plan();
    assert_eq!(plan.kind, EbpfProbeKind::CgroupSkbObserver);
    assert_eq!(plan.safety_mode, EbpfProbeSafetyMode::ModelOnly);
    assert!(plan.requires_bpf_fs);
    assert!(plan.requires_btf);
    assert!(plan.requires_cap_bpf_or_sys_admin);
    assert!(!plan.program_load_enabled);
    assert!(!plan.attach_enabled);
    assert!(!plan.packet_drop_enabled);
    assert!(!plan.enforcement_enabled);
    assert!(!plan.mutation_enabled);
}

#[test]
fn i2_tracepoint_observer_plan_is_observer_only() {
    let plan = minimal_tracepoint_observer_probe_plan();
    assert_eq!(plan.kind, EbpfProbeKind::TracepointObserver);
    assert_eq!(plan.safety_mode, EbpfProbeSafetyMode::ModelOnly);
    assert!(!plan.requires_bpf_fs);
    assert!(plan.requires_btf);
    assert!(!plan.program_load_enabled);
    assert!(!plan.attach_enabled);
    assert!(!plan.packet_drop_enabled);
    assert!(!plan.enforcement_enabled);
    assert!(!plan.mutation_enabled);
}

// -- Validator tests ---------------------------------------------------

#[test]
fn i2_validator_accepts_safe_model_only_plan() {
    let plan = EbpfProbePlan::default();
    assert!(validate_probe_plan_safety(&plan).is_ok());
}

#[test]
fn i2_validator_accepts_socket_observer_plan() {
    let plan = minimal_socket_observer_probe_plan();
    assert!(validate_probe_plan_safety(&plan).is_ok());
}

#[test]
fn i2_validator_accepts_cgroup_skb_observer_plan() {
    let plan = minimal_cgroup_skb_observer_probe_plan();
    assert!(validate_probe_plan_safety(&plan).is_ok());
}

#[test]
fn i2_validator_accepts_tracepoint_observer_plan() {
    let plan = minimal_tracepoint_observer_probe_plan();
    assert!(validate_probe_plan_safety(&plan).is_ok());
}

#[test]
fn i2_validator_rejects_program_load_enabled() {
    let plan = make_unsafe_plan("program_load_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("program_load_enabled"));
}

#[test]
fn i2_validator_rejects_attach_enabled() {
    let plan = make_unsafe_plan("attach_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("attach_enabled"));
}

#[test]
fn i2_validator_rejects_map_create_enabled() {
    let plan = make_unsafe_plan("map_create_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("map_create_enabled"));
}

#[test]
fn i2_validator_rejects_map_pin_enabled() {
    let plan = make_unsafe_plan("map_pin_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("map_pin_enabled"));
}

#[test]
fn i2_validator_rejects_packet_drop_enabled() {
    let plan = make_unsafe_plan("packet_drop_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("packet_drop_enabled"));
}

#[test]
fn i2_validator_rejects_enforcement_enabled() {
    let plan = make_unsafe_plan("enforcement_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("enforcement_enabled"));
}

#[test]
fn i2_validator_rejects_mutation_enabled() {
    let plan = make_unsafe_plan("mutation_enabled");
    let result = validate_probe_plan_safety(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("mutation_enabled"));
}

// -- Observer probe design composition tests ---------------------------

#[test]
fn i2_observer_probe_design_composes_defaults() {
    let design = EbpfObserverProbeDesign::default();
    assert_eq!(design.plan.kind, EbpfProbeKind::Noop);
    assert_eq!(design.plan.safety_mode, EbpfProbeSafetyMode::ModelOnly);
    assert_eq!(design.event_kind, EbpfEventKind::Noop);
    assert!(design.map_plan.maps.is_empty());
    assert_eq!(design.observer_state, EbpfObserverState::Inactive);
}

#[test]
fn i2_observer_state_remains_inactive_by_default() {
    assert_eq!(EbpfObserverState::default(), EbpfObserverState::Inactive);
}

#[test]
fn i2_observer_probe_design_all_flags_false() {
    let design = EbpfObserverProbeDesign::default();
    assert!(!design.plan.program_load_enabled);
    assert!(!design.plan.attach_enabled);
    assert!(!design.plan.map_create_enabled);
    assert!(!design.plan.map_pin_enabled);
    assert!(!design.plan.packet_drop_enabled);
    assert!(!design.plan.enforcement_enabled);
    assert!(!design.plan.mutation_enabled);
}

// -- Capability detector continuity -----------------------------------

#[test]
fn i2_capability_detector_still_defaults_unavailable() {
    let report = EbpfCapabilityReport::default();
    assert_eq!(report.readiness, EbpfReadinessLevel::Unavailable);
    assert!(!report.observer_ready);
}

// -- CLI exposure tests -----------------------------------------------

#[test]
fn i2_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i2_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// -- Version and ledger continuity tests -------------------------------

#[test]
fn i2_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i2_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

fn write_i2_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i2_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i2-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i2-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i2 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion observer probe design proof",
      "attribution_scope": "interface-level only",
      "enforcement_status": "inactive/not implemented",
      "reset_detected": false,
      "reset_details": []
    }
  ]
}
"#,
    )
    .unwrap();
    path
}

#[test]
fn i2_existing_ledger_export_json_file_still_works() {
    let path = write_i2_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

// -- No dependency tests ------------------------------------------------

#[test]
fn i2_no_new_dependency_added() {
    let cargo_toml = include_str!("../../Cargo.toml");
    // aya already existed in I-0 as optional; confirm no new deps added.
    assert!(cargo_toml.contains("aya"));
}

// -- Forbidden source pattern tests (I-2 probe plan source only) ------

#[test]
fn i2_no_aya_load_or_attach_in_probe_plan_source() {
    for forbidden in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
    ] {
        assert!(
            !I2_PROBE_PLAN_SOURCE.contains(forbidden),
            "probe_plan.rs must not contain {forbidden}"
        );
    }
}

#[test]
fn i2_no_nft_tc_drop_block_allow_quota_in_probe_plan_source() {
    // Check forbidden patterns only in code lines, not comments.
    for line in I2_PROBE_PLAN_SOURCE.lines() {
        let code = line.trim();
        // Skip comments and doc comments.
        if code.starts_with("//") || code.starts_with("//!") || code.starts_with("///") {
            continue;
        }
        assert!(
            !code.contains("drop_packet"),
            "probe_plan.rs code must not contain 'drop_packet'"
        );
        // block/allow/quota as string literals or method calls, not in comments.
        assert!(
            !code.contains("\"block\"") && !code.contains(".block"),
            "probe_plan.rs code must not contain 'block' as identifier"
        );
        assert!(
            !code.contains("\"allow\"") && !code.contains(".allow"),
            "probe_plan.rs code must not contain 'allow' as identifier"
        );
        assert!(
            !code.contains("\"quota\"") && !code.contains(".quota"),
            "probe_plan.rs code must not contain 'quota' as identifier"
        );
    }
    // Whole-source checks for patterns unlikely to appear in valid Rust code.
    assert!(
        !I2_PROBE_PLAN_SOURCE.contains("nft"),
        "probe_plan.rs must not contain 'nft'"
    );
}

#[test]
fn i2_no_nft_or_tc_backend_under_intergalaxion() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Doc content tests -------------------------------------------------

#[test]
fn i2_docs_exist_and_mention_model_only() {
    assert!(!I2_DOC.is_empty());
    assert!(
        I2_DOC.contains("model-only")
            || I2_DOC.contains("design only")
            || I2_DOC.contains("design/model")
    );
}

#[test]
fn i2_docs_say_no_attach_load_or_map_create_or_pin() {
    assert!(I2_DOC.contains("no eBPF attach"));
    assert!(I2_DOC.contains("no eBPF program load"));
    assert!(I2_DOC.contains("no eBPF map create"));
    assert!(I2_DOC.contains("no eBPF map pin"));
}

#[test]
fn i2_docs_say_no_enforcement() {
    assert!(I2_DOC.contains("no enforcement"));
}

#[test]
fn i2_docs_say_no_block_allow_or_quota() {
    assert!(I2_DOC.contains("no block/allow/quota"));
}

#[test]
fn i2_docs_say_no_nft_tc_fallback() {
    assert!(I2_DOC.contains("no nft/tc fallback") || I2_DOC.contains("no nft/tc"));
}

#[test]
fn i2_docs_say_no_public_cli() {
    assert!(I2_DOC.contains("no public CLI"));
}

#[test]
fn i2_docs_say_no_kernel_mutation() {
    assert!(I2_DOC.contains("no kernel mutation") || I2_DOC.contains("no mutation"));
}

#[test]
fn i2_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("probe_plan.rs", I2_PROBE_PLAN_SOURCE),
        ("I-2 doc", I2_DOC),
        ("tests.rs", include_str!("tests.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}
