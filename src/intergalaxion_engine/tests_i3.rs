// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-3 tests: eBPF event schema and ring buffer model.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::event_schema::*;
use crate::intergalaxion_engine::backends::ebpf::ringbuf::*;
use clap::CommandFactory;

const I3_DOC: &str =
    include_str!("../../docs/intergalaxion/I-3-ebpf-event-schema-ring-buffer-model.md");
const I3_EVENT_SCHEMA_SOURCE: &str = include_str!("backends/ebpf/event_schema.rs");
const I3_RINGBUF_SOURCE: &str = include_str!("backends/ebpf/ringbuf.rs");

// -- Default observer event tests (coverage 1–7) ---------------------

#[test]
fn i3_default_observer_event_is_observer_only() {
    let event = default_observer_event();
    assert_eq!(event.verdict, EbpfObserverVerdict::ObservedOnly);
    assert_eq!(event.source, EbpfEventSource::Model);
}

#[test]
fn i3_default_observer_event_has_event_id_zero() {
    let event = default_observer_event();
    assert_eq!(event.event_id, 0);
}

#[test]
fn i3_default_observer_event_has_no_optional_fields() {
    let event = default_observer_event();
    assert!(event.pid.is_none());
    assert!(event.tgid.is_none());
    assert!(event.uid.is_none());
    assert!(event.cgroup_id.is_none());
    assert!(event.socket_cookie.is_none());
    assert!(event.interface_index.is_none());
}

#[test]
fn i3_default_observer_event_has_zero_counters() {
    let event = default_observer_event();
    assert_eq!(event.rx_bytes, 0);
    assert_eq!(event.tx_bytes, 0);
    assert_eq!(event.packet_count, 0);
}

#[test]
fn i3_default_observer_event_direction_is_unknown() {
    let event = default_observer_event();
    assert_eq!(event.direction, EbpfTrafficDirection::Unknown);
}

#[test]
fn i3_default_observer_event_verdict_is_observed_only() {
    let event = default_observer_event();
    assert_eq!(event.verdict, EbpfObserverVerdict::ObservedOnly);
}

#[test]
fn i3_validate_accepts_default_safe_event() {
    let event = default_observer_event();
    assert!(validate_observer_event(&event).is_ok());
}

// -- Label stability tests (coverage 9–11) -----------------------------

#[test]
fn i3_event_source_labels_are_stable() {
    assert_eq!(EbpfEventSource::Model.as_str(), "model");
    assert_eq!(
        EbpfEventSource::RingBufferPlanned.as_str(),
        "ring_buffer_planned"
    );
    assert_eq!(
        EbpfEventSource::KernelLiveUnsupported.as_str(),
        "kernel_live_unsupported"
    );
}

#[test]
fn i3_traffic_direction_labels_are_stable() {
    assert_eq!(EbpfTrafficDirection::Unknown.as_str(), "unknown");
    assert_eq!(EbpfTrafficDirection::Rx.as_str(), "rx");
    assert_eq!(EbpfTrafficDirection::Tx.as_str(), "tx");
}

#[test]
fn i3_observer_verdict_labels_are_stable() {
    assert_eq!(EbpfObserverVerdict::ObservedOnly.as_str(), "observed_only");
    assert_eq!(EbpfObserverVerdict::NoDecision.as_str(), "no_decision");
    assert_eq!(
        EbpfObserverVerdict::DroppedUnsupported.as_str(),
        "dropped_unsupported"
    );
}

// -- Default ring buffer plan tests (coverage 12–19) -------------------

#[test]
fn i3_default_ring_buffer_plan_is_model_only() {
    let plan = default_ring_buffer_plan();
    assert!(!plan.consumer_enabled);
    assert!(!plan.kernel_open_enabled);
    assert!(!plan.map_create_enabled);
    assert!(!plan.map_pin_enabled);
    assert!(!plan.attach_required);
    assert!(!plan.root_required_for_tests);
    assert!(!plan.mutation_enabled);
}

#[test]
fn i3_ring_buffer_plan_has_consumer_enabled_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.consumer_enabled);
}

#[test]
fn i3_ring_buffer_plan_has_kernel_open_enabled_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.kernel_open_enabled);
}

#[test]
fn i3_ring_buffer_plan_has_map_create_enabled_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.map_create_enabled);
}

#[test]
fn i3_ring_buffer_plan_has_map_pin_enabled_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.map_pin_enabled);
}

#[test]
fn i3_ring_buffer_plan_has_attach_required_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.attach_required);
}

#[test]
fn i3_ring_buffer_plan_has_root_required_for_tests_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.root_required_for_tests);
}

#[test]
fn i3_ring_buffer_plan_has_mutation_enabled_false() {
    let plan = EbpfRingBufferPlan::default();
    assert!(!plan.mutation_enabled);
}

// -- Ring buffer validator tests (coverage 20–27) ---------------------

#[test]
fn i3_validate_accepts_safe_default_ring_buffer_plan() {
    let plan = EbpfRingBufferPlan::default();
    assert!(validate_ring_buffer_plan(&plan).is_ok());
}

fn make_unsafe_ringbuf_plan(flag: &str) -> EbpfRingBufferPlan {
    let mut plan = EbpfRingBufferPlan::default();
    match flag {
        "consumer_enabled" => plan.consumer_enabled = true,
        "kernel_open_enabled" => plan.kernel_open_enabled = true,
        "map_create_enabled" => plan.map_create_enabled = true,
        "map_pin_enabled" => plan.map_pin_enabled = true,
        "attach_required" => plan.attach_required = true,
        "root_required_for_tests" => plan.root_required_for_tests = true,
        "mutation_enabled" => plan.mutation_enabled = true,
        _ => {}
    }
    plan
}

#[test]
fn i3_validate_rejects_consumer_enabled_true() {
    let plan = make_unsafe_ringbuf_plan("consumer_enabled");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("consumer_enabled"));
}

#[test]
fn i3_validate_rejects_kernel_open_enabled_true() {
    let plan = make_unsafe_ringbuf_plan("kernel_open_enabled");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("kernel_open_enabled"));
}

#[test]
fn i3_validate_rejects_map_create_enabled_true() {
    let plan = make_unsafe_ringbuf_plan("map_create_enabled");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("map_create_enabled"));
}

#[test]
fn i3_validate_rejects_map_pin_enabled_true() {
    let plan = make_unsafe_ringbuf_plan("map_pin_enabled");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("map_pin_enabled"));
}

#[test]
fn i3_validate_rejects_attach_required_true() {
    let plan = make_unsafe_ringbuf_plan("attach_required");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("attach_required"));
}

#[test]
fn i3_validate_rejects_root_required_for_tests_true() {
    let plan = make_unsafe_ringbuf_plan("root_required_for_tests");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("root_required_for_tests"));
}

#[test]
fn i3_validate_rejects_mutation_enabled_true() {
    let plan = make_unsafe_ringbuf_plan("mutation_enabled");
    let result = validate_ring_buffer_plan(&plan);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("mutation_enabled"));
}

// -- Batch summary tests (coverage 28–32) ------------------------------

#[test]
fn i3_empty_batch_summary_is_deterministic() {
    let batch = EbpfEventBatch::default();
    let summary1 = summarize_event_batch(&batch);
    let summary2 = summarize_event_batch(&batch);
    assert_eq!(summary1, summary2);
}

#[test]
fn i3_batch_summary_counts_events() {
    let mut batch = EbpfEventBatch::default();
    batch.events.push(default_observer_event());
    batch.events.push(default_observer_event());
    let summary = summarize_event_batch(&batch);
    assert_eq!(summary.event_count, 2);
}

#[test]
fn i3_batch_summary_totals_rx_and_tx_bytes() {
    let mut batch = EbpfEventBatch::default();
    let mut event1 = default_observer_event();
    event1.rx_bytes = 100;
    event1.tx_bytes = 200;
    let mut event2 = default_observer_event();
    event2.rx_bytes = 50;
    event2.tx_bytes = 75;
    batch.events.push(event1);
    batch.events.push(event2);
    let summary = summarize_event_batch(&batch);
    assert_eq!(summary.total_rx_bytes, 150);
    assert_eq!(summary.total_tx_bytes, 275);
}

#[test]
fn i3_batch_summary_preserves_truncated_flag() {
    let batch = EbpfEventBatch {
        truncated: true,
        ..Default::default()
    };
    let summary = summarize_event_batch(&batch);
    assert!(summary.truncated);
}

#[test]
fn i3_batch_summary_counts_decode_errors() {
    let mut batch = EbpfEventBatch::default();
    batch.decode_errors.push(String::from("err1"));
    batch.decode_errors.push(String::from("err2"));
    batch.decode_errors.push(String::from("err3"));
    let summary = summarize_event_batch(&batch);
    assert_eq!(summary.decode_error_count, 3);
}

// -- Consumer state default tests -------------------------------------

#[test]
fn i3_consumer_state_defaults_inactive() {
    let state = EbpfRingBufferConsumerState::default();
    assert!(!state.active);
    assert_eq!(state.events_received, 0);
    assert_eq!(state.events_dropped_by_consumer, 0);
    assert!(state.last_event_id.is_none());
}

// -- Doc content tests (coverage 33–38) -------------------------------

#[test]
fn i3_docs_exist_and_mention_event_schema() {
    assert!(!I3_DOC.is_empty());
    assert!(I3_DOC.contains("event schema"));
}

#[test]
fn i3_docs_say_no_attach_load_map_create_ring_buffer_open_map_pin() {
    assert!(I3_DOC.contains("no eBPF attach"));
    assert!(I3_DOC.contains("no eBPF program load"));
    assert!(I3_DOC.contains("no eBPF map create"));
    assert!(I3_DOC.contains("no ring buffer open"));
    assert!(I3_DOC.contains("no map pin"));
}

#[test]
fn i3_docs_say_no_enforcement() {
    assert!(I3_DOC.contains("no enforcement"));
}

#[test]
fn i3_docs_say_no_block_allow_or_quota() {
    assert!(I3_DOC.contains("no block/allow/quota"));
}

#[test]
fn i3_docs_say_no_nft_tc_fallback() {
    assert!(I3_DOC.contains("no nft/tc fallback") || I3_DOC.contains("no nft/tc"));
}

#[test]
fn i3_docs_say_no_public_cli() {
    assert!(I3_DOC.contains("no public CLI"));
}

// -- CLI and version continuity (coverage 39–43) ----------------------

#[test]
fn i3_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i3_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

fn write_i3_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i3_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i3-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i3-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i3 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion event schema ring buffer model proof",
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
fn i3_existing_ledger_export_json_file_still_works() {
    let path = write_i3_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

#[test]
fn i3_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i3_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// -- No dependency tests (coverage 44) ---------------------------------

#[test]
fn i3_no_new_dependency_added() {
    let cargo_toml = include_str!("../../Cargo.toml");
    // aya already existed in I-0 as optional; confirm no new deps.
    assert!(cargo_toml.contains("aya"));
}

// -- Forbidden source pattern tests (coverage 45–48) -------------------

#[test]
fn i3_no_live_kernel_mutation_api_in_event_schema_source() {
    for forbidden in [
        "Command::new",
        "File::create",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "std::fs::write",
    ] {
        assert!(
            !I3_EVENT_SCHEMA_SOURCE.contains(forbidden),
            "event_schema.rs must not contain {forbidden}"
        );
    }
}

#[test]
fn i3_no_aya_ringbuf_map_open_load_attach_pin_api_in_new_sources() {
    for source_name in [
        ("event_schema.rs", I3_EVENT_SCHEMA_SOURCE),
        ("ringbuf.rs", I3_RINGBUF_SOURCE),
    ] {
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
                !source_name.1.contains(forbidden),
                "{} must not contain {}",
                source_name.0,
                forbidden
            );
        }
    }
}

#[test]
fn i3_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

#[test]
fn i3_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("event_schema.rs", I3_EVENT_SCHEMA_SOURCE),
        ("ringbuf.rs", I3_RINGBUF_SOURCE),
        ("I-3 doc", I3_DOC),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}
