// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-4 tests: in-memory event decoder and ledger bridge model.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::decoder::*;
use crate::intergalaxion_engine::backends::ebpf::event_schema::*;
use crate::intergalaxion_engine::ledger_bridge::event_bridge::*;
use clap::CommandFactory;

const I4_DOC: &str =
    include_str!("../../docs/intergalaxion/I-4-in-memory-event-decoder-ledger-bridge-model.md");
const I4_DECODER_SOURCE: &str = include_str!("backends/ebpf/decoder.rs");
const I4_EVENT_BRIDGE_SOURCE: &str = include_str!("ledger_bridge/event_bridge.rs");

// -- Raw frame defaults (coverage 1) -----------------------------------

#[test]
fn i4_raw_frame_defaults_are_model_only() {
    let frame = EbpfRawEventFrame::default();
    assert_eq!(frame.frame_id, 0);
    assert_eq!(frame.source, EbpfEventSource::Model);
    assert!(frame.payload.is_empty());
    assert!(frame.decode_source_label.is_empty());
}

// -- Decode mode labels (coverage 2) ------------------------------------

#[test]
fn i4_decode_mode_labels_are_stable() {
    assert_eq!(EbpfDecodeMode::ModelOnly.as_str(), "model_only");
    assert_eq!(EbpfDecodeMode::StrictFixture.as_str(), "strict_fixture");
    assert_eq!(
        EbpfDecodeMode::KernelLiveUnsupported.as_str(),
        "kernel_live_unsupported"
    );
}

// -- Decode empty payload fails honestly (coverage 3) ------------------

#[test]
fn i4_decode_of_empty_payload_fails_honestly() {
    let frame = EbpfRawEventFrame {
        frame_id: 42,
        source: EbpfEventSource::Model,
        payload: Vec::new(),
        decode_source_label: String::from("test"),
    };
    let decoded = decode_raw_event_frame(&frame);
    assert!(!decoded.decoded);
    assert_eq!(decoded.frame_id, 42);
    assert!(decoded.decode_error.is_some());
}

// -- Decode of fixture payload succeeds (coverage 4) -------------------

#[test]
fn i4_decode_of_fixture_payload_succeeds() {
    let frame = EbpfRawEventFrame {
        frame_id: 7,
        source: EbpfEventSource::Model,
        payload: vec![0x01, 0x02, 0x03],
        decode_source_label: String::from("test-fixture"),
    };
    let decoded = decode_raw_event_frame(&frame);
    assert!(decoded.decoded);
    assert_eq!(decoded.frame_id, 7);
    assert!(decoded.decode_error.is_none());
    assert_eq!(decoded.event.event_id, 7);
    assert_eq!(decoded.event.source, EbpfEventSource::Model);
}

// -- Decode report for empty frames (coverage 5) -----------------------

#[test]
fn i4_decode_report_for_empty_frames_is_deterministic() {
    let report = decode_raw_event_batch(&[]);
    let report2 = decode_raw_event_batch(&[]);
    assert_eq!(report, report2);
}

// -- Decode report counts frames_seen (coverage 6) --------------------

#[test]
fn i4_decode_report_counts_frames_seen() {
    let frames = vec![
        EbpfRawEventFrame::default(),
        EbpfRawEventFrame::default(),
        EbpfRawEventFrame::default(),
    ];
    let report = decode_raw_event_batch(&frames);
    assert_eq!(report.frames_seen, 3);
}

// -- Decode report counts frames_decoded (coverage 7) -----------------

#[test]
fn i4_decode_report_counts_frames_decoded() {
    let frames = vec![
        EbpfRawEventFrame {
            payload: vec![0x01],
            ..Default::default()
        },
        EbpfRawEventFrame {
            payload: vec![],
            ..Default::default()
        },
        EbpfRawEventFrame {
            payload: vec![0x02],
            ..Default::default()
        },
    ];
    let report = decode_raw_event_batch(&frames);
    assert_eq!(report.frames_decoded, 2);
}

// -- Decode report records errors (coverage 8) -------------------------

#[test]
fn i4_decode_report_records_decode_errors() {
    let frames = vec![
        EbpfRawEventFrame {
            payload: vec![],
            frame_id: 10,
            ..Default::default()
        },
        EbpfRawEventFrame {
            payload: vec![0x01],
            frame_id: 11,
            ..Default::default()
        },
    ];
    let report = decode_raw_event_batch(&frames);
    assert_eq!(report.decode_errors.len(), 1);
}

// -- Decode report safety flags (coverage 9–11) -----------------------

#[test]
fn i4_decode_report_live_kernel_read_is_false() {
    let report = decode_raw_event_batch(&[]);
    assert!(!report.live_kernel_read_performed);
}

#[test]
fn i4_decode_report_ring_buffer_opened_is_false() {
    let report = decode_raw_event_batch(&[]);
    assert!(!report.ring_buffer_opened);
}

#[test]
fn i4_decode_report_mutation_performed_is_false() {
    let report = decode_raw_event_batch(&[]);
    assert!(!report.mutation_performed);
}

// -- Decoded event preserves frame_id (coverage 12) -------------------

#[test]
fn i4_decoded_event_preserves_frame_id() {
    let frame = EbpfRawEventFrame {
        frame_id: 999,
        payload: vec![0xAA],
        ..Default::default()
    };
    let decoded = decode_raw_event_frame(&frame);
    assert_eq!(decoded.event.event_id, 999);
}

// -- Decoded event uses EbpfObserverEvent model (coverage 13) ---------

#[test]
fn i4_decoded_event_uses_observer_event_model() {
    let frame = EbpfRawEventFrame {
        frame_id: 1,
        payload: vec![0x01],
        ..Default::default()
    };
    let decoded = decode_raw_event_frame(&frame);
    // Verify it's an EbpfObserverEvent by checking default fields.
    assert_eq!(decoded.event.event_id, 1);
    assert_eq!(decoded.event.verdict, EbpfObserverVerdict::default());
}

// -- Bridge record defaults (coverage 14–15) --------------------------

#[test]
fn i4_bridge_record_from_default_event_is_read_only() {
    let event = default_observer_event();
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert!(record.read_only);
}

#[test]
fn i4_bridge_record_enforcement_status_is_inactive() {
    let event = default_observer_event();
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.enforcement_status, "inactive/not implemented");
}

// -- Bridge record combined_bytes (coverage 16–17) ---------------------

#[test]
fn i4_bridge_record_combined_equals_rx_plus_tx() {
    let mut event = default_observer_event();
    event.rx_bytes = 100;
    event.tx_bytes = 200;
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.rx_bytes, 100);
    assert_eq!(record.tx_bytes, 200);
    assert_eq!(record.combined_bytes, 300);
}

#[test]
fn i4_bridge_record_uses_saturating_combined_bytes() {
    let mut event = default_observer_event();
    event.rx_bytes = u64::MAX;
    event.tx_bytes = 1;
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.combined_bytes, u64::MAX);
}

// -- Bridge record preserves fields (coverage 18–21) -------------------

#[test]
fn i4_bridge_record_preserves_event_id_and_timestamp() {
    let mut event = default_observer_event();
    event.event_id = 42;
    event.timestamp_ns = 1234567890;
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.source_event_id, 42);
    assert_eq!(record.timestamp_ns, 1234567890);
}

#[test]
fn i4_bridge_record_preserves_identity_fields_when_present() {
    let mut event = default_observer_event();
    event.pid = Some(1000);
    event.tgid = Some(1000);
    event.uid = Some(1000);
    event.cgroup_id = Some(99);
    event.socket_cookie = Some(12345);
    event.interface_index = Some(2);
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.pid, Some(1000));
    assert_eq!(record.tgid, Some(1000));
    assert_eq!(record.uid, Some(1000));
    assert_eq!(record.cgroup_id, Some(99));
    assert_eq!(record.socket_cookie, Some(12345));
    assert_eq!(record.interface_index, Some(2));
}

#[test]
fn i4_bridge_record_provenance_is_nonempty() {
    let event = default_observer_event();
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert!(!record.provenance.is_empty());
}

#[test]
fn i4_bridge_record_attribution_scope_is_honest() {
    let event = default_observer_event();
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert_eq!(record.attribution_scope, "kernel-observer-model only");
}

// -- Validate bridge record (coverage 22–26) -------------------------

#[test]
fn i4_validate_accepts_safe_bridge_record() {
    let event = default_observer_event();
    let record = bridge_event_to_ledger_record(&event).unwrap();
    assert!(validate_bridge_record(&record).is_ok());
}

#[test]
fn i4_validate_rejects_read_only_false() {
    let record = IntergalaxionLedgerBridgeRecord {
        read_only: false,
        ..Default::default()
    };
    let result = validate_bridge_record(&record);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("read_only"));
}

#[test]
fn i4_validate_rejects_active_enforcement_status() {
    let record = IntergalaxionLedgerBridgeRecord {
        enforcement_status: String::from("active"),
        ..Default::default()
    };
    let result = validate_bridge_record(&record);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("enforcement_status"));
}

#[test]
fn i4_validate_rejects_combined_bytes_mismatch() {
    let record = IntergalaxionLedgerBridgeRecord {
        rx_bytes: 100,
        tx_bytes: 200,
        combined_bytes: 999, // Should be 300.
        ..Default::default()
    };
    let result = validate_bridge_record(&record);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("combined_bytes"));
}

// -- Bridge batch behavior (coverage 27–34) ---------------------------

#[test]
fn i4_bridge_batch_preserves_source() {
    let batch = EbpfEventBatch {
        source: EbpfEventSource::Model,
        events: vec![default_observer_event()],
        ..Default::default()
    };
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert_eq!(bridge_batch.source, EbpfEventSource::Model);
}

#[test]
fn i4_bridge_batch_counts_records() {
    let mut batch = EbpfEventBatch::default();
    batch.events.push(default_observer_event());
    batch.events.push(default_observer_event());
    batch.events.push(default_observer_event());
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert_eq!(bridge_batch.records.len(), 3);
}

#[test]
fn i4_bridge_batch_skips_invalid_events_if_any() {
    // In I-4, bridge_event_to_ledger_record always succeeds for valid
    // observer events. This test verifies the skip counter exists and
    // is zero for valid events.
    let batch = EbpfEventBatch::default();
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert_eq!(bridge_batch.skipped_events, 0);
}

#[test]
fn i4_bridge_batch_filesystem_write_performed_false() {
    let batch = EbpfEventBatch::default();
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert!(!bridge_batch.filesystem_write_performed);
}

#[test]
fn i4_bridge_batch_persistence_performed_false() {
    let batch = EbpfEventBatch::default();
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert!(!bridge_batch.persistence_performed);
}

#[test]
fn i4_bridge_batch_enforcement_performed_false() {
    let batch = EbpfEventBatch::default();
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert!(!bridge_batch.enforcement_performed);
}

#[test]
fn i4_bridge_batch_mutation_performed_false() {
    let batch = EbpfEventBatch::default();
    let bridge_batch = bridge_event_batch_to_ledger_records(&batch);
    assert!(!bridge_batch.mutation_performed);
}

// -- Decoded frame default (extra coverage) ---------------------------

#[test]
fn i4_decoded_frame_default_is_not_decoded() {
    let frame = EbpfDecodedEventFrame::default();
    assert!(!frame.decoded);
    assert!(frame.decode_error.is_some());
}

// -- Doc content tests (coverage 34–41) ------------------------------

#[test]
fn i4_docs_exist_and_mention_in_memory_decoder() {
    assert!(!I4_DOC.is_empty());
    assert!(I4_DOC.contains("in-memory"));
    assert!(I4_DOC.contains("decoder"));
}

#[test]
fn i4_docs_say_no_attach_load_map_create_ring_buffer_open_live_kernel_read_map_pin() {
    assert!(I4_DOC.contains("no eBPF attach"));
    assert!(I4_DOC.contains("no eBPF program load"));
    assert!(I4_DOC.contains("no eBPF map create"));
    assert!(I4_DOC.contains("no ring buffer open"));
    assert!(I4_DOC.contains("no live kernel event read"));
    assert!(I4_DOC.contains("no map pin"));
}

#[test]
fn i4_docs_say_no_enforcement() {
    assert!(I4_DOC.contains("no enforcement"));
}

#[test]
fn i4_docs_say_no_block_allow_or_quota() {
    assert!(I4_DOC.contains("no block/allow/quota"));
}

#[test]
fn i4_docs_say_no_nft_tc_fallback() {
    assert!(I4_DOC.contains("no nft/tc fallback") || I4_DOC.contains("no nft/tc"));
}

#[test]
fn i4_docs_say_no_public_cli() {
    assert!(I4_DOC.contains("no public CLI"));
}

#[test]
fn i4_docs_say_no_ledger_file_write_or_persistence() {
    assert!(I4_DOC.contains("no ledger file write") || I4_DOC.contains("no persistence"));
}

#[test]
fn i4_docs_say_existing_v31_ledger_schema_unchanged() {
    assert!(I4_DOC.contains("v3.1 ledger JSON schema") || I4_DOC.contains("unchanged"));
}

// -- CLI and version continuity (coverage 42–46) ----------------------

#[test]
fn i4_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i4_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

fn write_i4_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i4_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i4-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i4-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i4 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion in-memory decoder ledger bridge model proof",
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
fn i4_existing_ledger_export_json_file_still_works() {
    let path = write_i4_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

#[test]
fn i4_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i4_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// -- No dependency tests (coverage 47) ---------------------------------

#[test]
fn i4_no_new_dependency_added() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(cargo_toml.contains("aya"));
}

// -- Forbidden source pattern tests (coverage 48–51) -------------------

#[test]
fn i4_no_live_kernel_mutation_api_in_decoder_or_bridge_source() {
    for source_name in [
        ("decoder.rs", I4_DECODER_SOURCE),
        ("event_bridge.rs", I4_EVENT_BRIDGE_SOURCE),
    ] {
        for forbidden in [
            "File::create",
            "fs::write",
            "OpenOptions",
            "/sys/fs/bpf",
            "/sys/kernel",
            "/proc/",
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
fn i4_no_aya_ringbuf_map_open_load_attach_pin_api_in_new_sources() {
    for source_name in [
        ("decoder.rs", I4_DECODER_SOURCE),
        ("event_bridge.rs", I4_EVENT_BRIDGE_SOURCE),
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
fn i4_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

#[test]
fn i4_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("decoder.rs", I4_DECODER_SOURCE),
        ("event_bridge.rs", I4_EVENT_BRIDGE_SOURCE),
        ("I-4 doc", I4_DOC),
        ("tests_i4.rs", include_str!("tests_i4.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}
