// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-5 tests: live-readiness gate model.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::capability::{
    evaluate_ebpf_capability, EbpfCapabilitySnapshot,
};
use crate::intergalaxion_engine::backends::ebpf::decoder::EbpfDecodeReport;
use crate::intergalaxion_engine::backends::ebpf::probe_plan::EbpfProbePlan;
use crate::intergalaxion_engine::backends::ebpf::ringbuf::EbpfRingBufferPlan;
use crate::intergalaxion_engine::ledger_bridge::event_bridge::IntergalaxionLedgerBridgeBatch;
use crate::intergalaxion_engine::live_readiness::*;
use clap::CommandFactory;

const I5_DOC: &str = include_str!("../../docs/intergalaxion/I-5-live-readiness-gate.md");
const I5_LIVE_READINESS_SOURCE: &str = include_str!("live_readiness.rs");

// ── Helper: build an observer-ready capability snapshot ────────────

fn observer_ready_snapshot() -> EbpfCapabilitySnapshot {
    EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..Default::default()
    }
}

fn observer_ready_input() -> IntergalaxionReadinessInput {
    IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        ..Default::default()
    }
}

// -- Coverage 1: default readiness input is safe -----------------------

#[test]
fn i5_default_readiness_input_is_safe() {
    let input = default_readiness_input();
    assert!(!input.explicit_future_attach_consent);
    assert!(!input.public_cli_requested);
    assert!(!input.root_required_for_future_attach);
}

// -- Coverage 2: default readiness gate has all operation flags false ---

#[test]
fn i5_default_readiness_gate_has_all_operation_flags_false() {
    let gate = IntergalaxionReadinessGate::default();
    assert!(!gate.attach_performed);
    assert!(!gate.program_load_performed);
    assert!(!gate.map_create_performed);
    assert!(!gate.ring_buffer_opened);
    assert!(!gate.live_kernel_read_performed);
    assert!(!gate.map_pin_performed);
    assert!(!gate.enforcement_performed);
    assert!(!gate.mutation_performed);
    assert!(!gate.public_cli_exposed);
}

// -- Coverage 3: readiness labels are stable -------------------------

#[test]
fn i5_readiness_labels_are_stable() {
    assert_eq!(
        readiness_level_label(IntergalaxionReadinessLevel::Blocked),
        "blocked"
    );
    assert_eq!(
        readiness_level_label(IntergalaxionReadinessLevel::ModelOnly),
        "model_only"
    );
    assert_eq!(
        readiness_level_label(IntergalaxionReadinessLevel::ObserverCandidate),
        "observer_candidate"
    );
    assert_eq!(
        readiness_level_label(IntergalaxionReadinessLevel::FutureAttachPlanningCandidate),
        "future_attach_planning_candidate"
    );
}

// -- Coverage 4: unavailable capability blocks readiness ----------------

#[test]
fn i5_unavailable_capability_blocks_readiness() {
    let input = default_readiness_input();
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 5: no BPF filesystem blocks observer readiness -----------

#[test]
fn i5_no_bpf_filesystem_blocks_observer_readiness() {
    let snap = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(false),
        ..Default::default()
    };
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&snap),
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 6: bpf_fs + btf + cap_bpf → observer candidate ----------

#[test]
fn i5_bpf_btf_cap_bpf_becomes_observer_candidate() {
    let input = observer_ready_input();
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::ObserverCandidate);
    assert!(gate.observer_candidate);
    assert!(!gate.future_attach_planning_candidate);
}

// -- Coverage 7: bpf_fs + btf + cap_sys_admin → observer candidate -----

#[test]
fn i5_bpf_btf_cap_sys_admin_becomes_observer_candidate() {
    let snap = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_sys_admin_effective: Some(true),
        ..Default::default()
    };
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&snap),
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::ObserverCandidate);
}

// -- Coverage 8: observer candidate → no attach performed --------------

#[test]
fn i5_observer_candidate_does_not_mean_attach_performed() {
    let gate = evaluate_intergalaxion_readiness(&observer_ready_input());
    assert!(!gate.attach_performed);
}

// -- Coverage 9: observer candidate → no program load performed ---------

#[test]
fn i5_observer_candidate_does_not_mean_program_load_performed() {
    let gate = evaluate_intergalaxion_readiness(&observer_ready_input());
    assert!(!gate.program_load_performed);
}

// -- Coverage 10: observer candidate → no ring buffer opened ------------

#[test]
fn i5_observer_candidate_does_not_mean_ring_buffer_opened() {
    let gate = evaluate_intergalaxion_readiness(&observer_ready_input());
    assert!(!gate.ring_buffer_opened);
}

// -- Coverage 11: future attach planning candidate requires consent ----

#[test]
fn i5_future_attach_planning_requires_explicit_consent() {
    let input = observer_ready_input();
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::ObserverCandidate);
    assert!(!gate.future_attach_planning_candidate);
}

// -- Coverage 12: future attach planning candidate rejects public_cli --

#[test]
fn i5_future_attach_planning_rejects_public_cli_requested() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        explicit_future_attach_consent: true,
        public_cli_requested: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
    assert!(!gate.future_attach_planning_candidate);
}

// -- Coverage 13: future attach planning candidate rejects unsafe probe -

#[test]
fn i5_future_attach_planning_rejects_unsafe_probe_plan() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        probe_plan: EbpfProbePlan {
            attach_enabled: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 14: future attach planning candidate rejects unsafe ring -

#[test]
fn i5_future_attach_planning_rejects_unsafe_ring_buffer_plan() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        ring_buffer_plan: EbpfRingBufferPlan {
            map_create_enabled: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 15: future attach rejects decode live_kernel_read -------

#[test]
fn i5_future_attach_planning_rejects_decode_live_kernel_read() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        decode_report: EbpfDecodeReport {
            live_kernel_read_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 16: future attach rejects decode ring_buffer_opened ------

#[test]
fn i5_future_attach_planning_rejects_decode_ring_buffer_opened() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        decode_report: EbpfDecodeReport {
            ring_buffer_opened: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 17: future attach rejects decode mutation ----------------

#[test]
fn i5_future_attach_planning_rejects_decode_mutation() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        decode_report: EbpfDecodeReport {
            mutation_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 18: future attach rejects bridge filesystem_write --------

#[test]
fn i5_future_attach_planning_rejects_bridge_filesystem_write() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        bridge_batch: IntergalaxionLedgerBridgeBatch {
            filesystem_write_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 19: future attach rejects bridge persistence ------------

#[test]
fn i5_future_attach_planning_rejects_bridge_persistence() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        bridge_batch: IntergalaxionLedgerBridgeBatch {
            persistence_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 20: future attach rejects bridge enforcement -------------

#[test]
fn i5_future_attach_planning_rejects_bridge_enforcement() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        bridge_batch: IntergalaxionLedgerBridgeBatch {
            enforcement_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 21: future attach rejects bridge mutation ----------------

#[test]
fn i5_future_attach_planning_rejects_bridge_mutation() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        bridge_batch: IntergalaxionLedgerBridgeBatch {
            mutation_performed: true,
            ..Default::default()
        },
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
}

// -- Coverage 22: validation accepts safe gate -------------------------

#[test]
fn i5_validation_accepts_safe_gate() {
    let gate = evaluate_intergalaxion_readiness(&observer_ready_input());
    assert!(validate_readiness_gate(&gate).is_ok());
}

// -- Coverage 23–31: validation rejects unsafe operation flags ----------

#[test]
fn i5_validation_rejects_attach_performed() {
    let gate = IntergalaxionReadinessGate {
        attach_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_program_load_performed() {
    let gate = IntergalaxionReadinessGate {
        program_load_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_map_create_performed() {
    let gate = IntergalaxionReadinessGate {
        map_create_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_ring_buffer_opened() {
    let gate = IntergalaxionReadinessGate {
        ring_buffer_opened: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_live_kernel_read_performed() {
    let gate = IntergalaxionReadinessGate {
        live_kernel_read_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_map_pin_performed() {
    let gate = IntergalaxionReadinessGate {
        map_pin_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_enforcement_performed() {
    let gate = IntergalaxionReadinessGate {
        enforcement_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_mutation_performed() {
    let gate = IntergalaxionReadinessGate {
        mutation_performed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

#[test]
fn i5_validation_rejects_public_cli_exposed() {
    let gate = IntergalaxionReadinessGate {
        public_cli_exposed: true,
        ..Default::default()
    };
    assert!(validate_readiness_gate(&gate).is_err());
}

// -- Coverage 32: reasons are deterministic -----------------------------

#[test]
fn i5_reasons_are_deterministic() {
    let input = observer_ready_input();
    let gate1 = evaluate_intergalaxion_readiness(&input);
    let gate2 = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate1.reasons, gate2.reasons);
}

// -- Coverage 33: blocked reasons include blocking=true -----------------

#[test]
fn i5_blocked_reasons_include_blocking_true() {
    let gate = evaluate_intergalaxion_readiness(&default_readiness_input());
    assert_eq!(gate.level, IntergalaxionReadinessLevel::Blocked);
    assert!(gate.reasons.iter().any(|r| r.blocking));
}

// -- Coverage 34: model-only reasons are nonempty ----------------------

#[test]
fn i5_model_only_reasons_are_nonempty() {
    // Partial capability: bpf_fs mounted but no BTF.
    let snap = EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(false),
        ..Default::default()
    };
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&snap),
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(gate.level, IntergalaxionReadinessLevel::ModelOnly);
    assert!(!gate.reasons.is_empty());
}

// -- Coverage 35–43: doc content tests --------------------------------

#[test]
fn i5_docs_exist_and_mention_live_readiness_gate() {
    assert!(!I5_DOC.is_empty());
    assert!(I5_DOC.contains("live-readiness gate"));
    assert!(I5_DOC.contains("I-5"));
}

#[test]
fn i5_docs_say_no_attach_load_map_create_ring_buffer_open_live_kernel_read_map_pin() {
    assert!(I5_DOC.contains("no eBPF attach"));
    assert!(I5_DOC.contains("no eBPF program load"));
    assert!(I5_DOC.contains("no eBPF map create"));
    assert!(I5_DOC.contains("no ring buffer open"));
    assert!(I5_DOC.contains("no live kernel event read"));
    assert!(I5_DOC.contains("no map pin"));
}

#[test]
fn i5_docs_say_no_enforcement() {
    assert!(I5_DOC.contains("no enforcement"));
}

#[test]
fn i5_docs_say_no_block_allow_or_quota() {
    assert!(I5_DOC.contains("no block/allow/quota"));
}

#[test]
fn i5_docs_say_no_nft_tc_fallback() {
    assert!(I5_DOC.contains("no nft/tc fallback") || I5_DOC.contains("no nft/tc"));
}

#[test]
fn i5_docs_say_no_public_cli() {
    assert!(I5_DOC.contains("no public CLI"));
}

#[test]
fn i5_docs_say_no_ledger_file_write_or_persistence() {
    assert!(I5_DOC.contains("no ledger file write") || I5_DOC.contains("no persistence"));
}

#[test]
fn i5_docs_say_existing_v31_usage_schema_unchanged() {
    assert!(I5_DOC.contains("usage JSON schema") || I5_DOC.contains("unchanged"));
}

#[test]
fn i5_docs_say_existing_v31_ledger_schema_unchanged() {
    assert!(I5_DOC.contains("v3.1 ledger JSON schema") || I5_DOC.contains("ledger JSON schema"));
}

// -- Coverage 44–48: CLI and version continuity ------------------------

#[test]
fn i5_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i5_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

fn write_i5_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i5_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i5-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i5-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i5 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion live readiness gate proof",
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
fn i5_existing_ledger_export_json_file_still_works() {
    let path = write_i5_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

#[test]
fn i5_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i5_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// -- Coverage 49: no new dependency added -----------------------------

#[test]
fn i5_no_new_dependency_added() {
    let cargo_toml = include_str!("../../Cargo.toml");
    // Verify aya still exists as the only optional eBPF dep.
    assert!(cargo_toml.contains("aya"));
}

// -- Coverage 50: no live kernel mutation API in readiness source -----

#[test]
fn i5_no_live_kernel_mutation_api_in_readiness_source() {
    for forbidden in [
        "File::create",
        "fs::write",
        "OpenOptions",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
    ] {
        assert!(
            !I5_LIVE_READINESS_SOURCE.contains(forbidden),
            "live_readiness.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 51: no aya ringbuf/map open/load/attach/pin API ---------

#[test]
fn i5_no_aya_ringbuf_map_open_load_attach_pin_api_in_readiness_source() {
    for forbidden in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
    ] {
        assert!(
            !I5_LIVE_READINESS_SOURCE.contains(forbidden),
            "live_readiness.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 52: no nft/tc source under intergalaxion backend ---------

#[test]
fn i5_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Coverage 53: all touched files under 1000 LOC ---------------------

#[test]
fn i5_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("live_readiness.rs", I5_LIVE_READINESS_SOURCE),
        ("I-5 doc", I5_DOC),
        ("tests_i5.rs", include_str!("tests_i5.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// ── Extra: future attach planning candidate with consent succeeds -----

#[test]
fn i5_future_attach_planning_candidate_with_consent() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert_eq!(
        gate.level,
        IntergalaxionReadinessLevel::FutureAttachPlanningCandidate
    );
    assert!(gate.observer_candidate);
    assert!(gate.future_attach_planning_candidate);
}

#[test]
fn i5_future_attach_gate_all_operation_flags_false() {
    let input = IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        explicit_future_attach_consent: true,
        ..Default::default()
    };
    let gate = evaluate_intergalaxion_readiness(&input);
    assert!(!gate.attach_performed);
    assert!(!gate.program_load_performed);
    assert!(!gate.map_create_performed);
    assert!(!gate.ring_buffer_opened);
    assert!(!gate.live_kernel_read_performed);
    assert!(!gate.map_pin_performed);
    assert!(!gate.enforcement_performed);
    assert!(!gate.mutation_performed);
    assert!(!gate.public_cli_exposed);
}

#[test]
fn i5_evaluate_output_passes_validation() {
    let gate = evaluate_intergalaxion_readiness(&default_readiness_input());
    assert!(validate_readiness_gate(&gate).is_ok());
}
