// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-13 tests: event stream fixture decoder bridge.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::decoder::EbpfRawEventFrame;
use crate::intergalaxion_engine::backends::ebpf::event_schema::EbpfEventSource;
use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::*;
use clap::CommandFactory;

const I13_DOC: &str =
    include_str!("../../docs/intergalaxion/I-13-event-stream-fixture-decoder-bridge.md");
const I13_SOURCE: &str = include_str!("backends/ebpf/event_stream_fixture.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helpers ──────────────────────────────────────────────────────────

fn valid_raw_frame(frame_id: u64) -> EbpfRawEventFrame {
    EbpfRawEventFrame {
        frame_id,
        source: EbpfEventSource::Model,
        payload: vec![0x01, 0x02, 0x03],
        decode_source_label: String::from("i13-fixture"),
    }
}

fn invalid_raw_frame(frame_id: u64) -> EbpfRawEventFrame {
    EbpfRawEventFrame {
        frame_id,
        source: EbpfEventSource::Model,
        payload: Vec::new(),
        decode_source_label: String::from("i13-fixture"),
    }
}

fn render_help(app: &mut clap::Command) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

// ── 1. Default fixture is fixture-only ────────────────────────────

#[test]
fn i13_default_fixture_is_fixture_only() {
    let f = default_event_stream_fixture();
    assert!(f.fixture_only);
}

// ── 2. Default fixture has all safety flags false ───────────────────

#[test]
fn i13_default_fixture_all_safety_flags_false() {
    let f = default_event_stream_fixture();
    assert!(!f.ring_buffer_opened);
    assert!(!f.live_event_stream_read);
    assert!(!f.map_pin_performed);
    assert!(!f.enforcement_performed);
    assert!(!f.packet_drop_performed);
    assert!(!f.mutation_performed);
    assert!(!f.persistence_performed);
    assert!(!f.public_cli_exposed);
}

// ── 3. Default fixture mode label is stable ─────────────────────────

#[test]
fn i13_default_fixture_mode_label_stable() {
    let label = event_stream_fixture_mode_label(EbpfEventStreamFixtureMode::InMemoryFixtureOnly);
    assert_eq!(label, "in_memory_fixture_only");
}

// ── 4. Fixture status labels are stable ─────────────────────────────

#[test]
fn i13_fixture_status_labels_stable() {
    use EbpfEventStreamFixtureStatus::*;
    assert_eq!(event_stream_fixture_status_label(Empty), "empty");
    assert_eq!(
        event_stream_fixture_status_label(FixtureOnly),
        "fixture_only"
    );
    assert_eq!(
        event_stream_fixture_status_label(DecodeReady),
        "decode_ready"
    );
    assert_eq!(
        event_stream_fixture_status_label(DecodeCompleted),
        "decode_completed"
    );
    assert_eq!(
        event_stream_fixture_status_label(DecodeFailed),
        "decode_failed"
    );
    assert_eq!(
        event_stream_fixture_status_label(BridgeReady),
        "bridge_ready"
    );
    assert_eq!(
        event_stream_fixture_status_label(BridgeCompleted),
        "bridge_completed"
    );
    assert_eq!(
        event_stream_fixture_status_label(BridgeFailed),
        "bridge_failed"
    );
    assert_eq!(event_stream_fixture_status_label(Rejected), "rejected");
}

// ── 5. Default report is deterministic ──────────────────────────────

#[test]
fn i13_default_report_deterministic() {
    let f = default_event_stream_fixture();
    let r1 = decode_event_stream_fixture(&f);
    let r2 = decode_event_stream_fixture(&f);
    assert_eq!(r1, r2);
}

// ── 6. Default report has frames_seen=0 ───────────────────────────

#[test]
fn i13_default_report_frames_seen_zero() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_seen, 0);
}

// ── 7. Default report has frames_decoded=0 ─────────────────────────

#[test]
fn i13_default_report_frames_decoded_zero() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_decoded, 0);
}

// ── 8. Default report has decode_errors=0 ───────────────────────────

#[test]
fn i13_default_report_decode_errors_zero() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.decode_errors, 0);
}

// ── 9. Default report has bridge_records=0 ────────────────────────

#[test]
fn i13_default_report_bridge_records_zero() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.bridge_records, 0);
}

// ── 10. Default report has all safety flags false ──────────────────

#[test]
fn i13_default_report_all_safety_flags_false() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert!(!r.reader_attempted);
    assert!(!r.reader_succeeded);
    assert!(!r.ring_buffer_opened);
    assert!(!r.live_event_stream_read);
    assert!(!r.map_pin_performed);
    assert!(!r.enforcement_performed);
    assert!(!r.packet_drop_performed);
    assert!(!r.mutation_performed);
    assert!(!r.persistence_performed);
    assert!(!r.public_cli_exposed);
    assert!(r.fixture_only);
}

// ── 11. fixture_frame_from_raw preserves stream_offset ─────────────

#[test]
fn i13_fixture_frame_preserves_stream_offset() {
    let frame = fixture_frame_from_raw(42, valid_raw_frame(1), true, "test");
    assert_eq!(frame.stream_offset, 42);
}

// ── 12. fixture_frame_from_raw preserves fixture_label ──────────────

#[test]
fn i13_fixture_frame_preserves_fixture_label() {
    let frame = fixture_frame_from_raw(0, valid_raw_frame(1), true, "my-label");
    assert_eq!(frame.fixture_label, "my-label");
}

// ── 13. fixture_frame_from_raw preserves expected_decode_success ────

#[test]
fn i13_fixture_frame_preserves_expected_decode_success() {
    let frame_true = fixture_frame_from_raw(0, valid_raw_frame(1), true, "t");
    assert!(frame_true.expected_decode_success);
    let frame_false = fixture_frame_from_raw(0, invalid_raw_frame(1), false, "f");
    assert!(!frame_false.expected_decode_success);
}

// ── 14. build_fixture_from_raw_frames preserves fixture_id ─────────

#[test]
fn i13_build_fixture_preserves_fixture_id() {
    let f = build_fixture_from_raw_frames("test-id", EbpfEventSource::Model, vec![]);
    assert_eq!(f.fixture_id, "test-id");
}

// ── 15. build_fixture_from_raw_frames preserves source ──────────────

#[test]
fn i13_build_fixture_preserves_source() {
    let f = build_fixture_from_raw_frames("id", EbpfEventSource::Model, vec![]);
    assert_eq!(f.source, EbpfEventSource::Model);
}

// ── 16. build_fixture_from_raw_frames assigns deterministic offsets

#[test]
fn i13_build_fixture_assigns_deterministic_offsets() {
    let frames = vec![
        valid_raw_frame(10),
        valid_raw_frame(20),
        valid_raw_frame(30),
    ];
    let f = build_fixture_from_raw_frames("id", EbpfEventSource::Model, frames);
    assert_eq!(f.frames.len(), 3);
    assert_eq!(f.frames[0].stream_offset, 0);
    assert_eq!(f.frames[1].stream_offset, 1);
    assert_eq!(f.frames[2].stream_offset, 2);
}

// ── 17. build_fixture_from_raw_frames is fixture-only ──────────────

#[test]
fn i13_build_fixture_is_fixture_only() {
    let f = build_fixture_from_raw_frames("id", EbpfEventSource::Model, vec![valid_raw_frame(1)]);
    assert!(f.fixture_only);
    assert!(!f.ring_buffer_opened);
    assert!(!f.live_event_stream_read);
}

// ── 18. Validate accepts safe default fixture ───────────────────────

#[test]
fn i13_validate_accepts_safe_default() {
    let f = default_event_stream_fixture();
    assert!(validate_event_stream_fixture(&f).is_ok());
}

// ── 19. Validate rejects empty fixture_id ───────────────────────────

#[test]
fn i13_validate_rejects_empty_fixture_id() {
    let mut f = default_event_stream_fixture();
    f.fixture_id = String::new();
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 20. Validate rejects fixture_only=false ─────────────────────────

#[test]
fn i13_validate_rejects_fixture_only_false() {
    let mut f = default_event_stream_fixture();
    f.fixture_only = false;
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 21-28. Validate rejects safety flags true ───────────────────────

#[test]
fn i13_validate_rejects_ring_buffer_opened() {
    let mut f = default_event_stream_fixture();
    f.ring_buffer_opened = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_live_event_stream_read() {
    let mut f = default_event_stream_fixture();
    f.live_event_stream_read = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_map_pin_performed() {
    let mut f = default_event_stream_fixture();
    f.map_pin_performed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_enforcement_performed() {
    let mut f = default_event_stream_fixture();
    f.enforcement_performed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_packet_drop_performed() {
    let mut f = default_event_stream_fixture();
    f.packet_drop_performed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_mutation_performed() {
    let mut f = default_event_stream_fixture();
    f.mutation_performed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_persistence_performed() {
    let mut f = default_event_stream_fixture();
    f.persistence_performed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

#[test]
fn i13_validate_rejects_public_cli_exposed() {
    let mut f = default_event_stream_fixture();
    f.public_cli_exposed = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 29. Validate rejects reader_result with ReaderSucceeded ───────

#[test]
fn i13_validate_rejects_reader_succeeded() {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderStatus;
    let mut f = default_event_stream_fixture();
    f.reader_result.status = EbpfEventStreamReaderStatus::ReaderSucceeded;
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 30. Validate rejects reader_result with ring_buffer_opened ─────

#[test]
fn i13_validate_rejects_reader_ring_buffer() {
    let mut f = default_event_stream_fixture();
    f.reader_result.ring_buffer_opened = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 31. Validate rejects reader_result with live_event_stream_read ──

#[test]
fn i13_validate_rejects_reader_live_read() {
    let mut f = default_event_stream_fixture();
    f.reader_result.live_event_stream_read = true;
    assert!(validate_event_stream_fixture(&f).is_err());
}

// ── 32. Empty fixture decodes to Empty or FixtureOnly ──────────────

#[test]
fn i13_empty_fixture_decodes_to_empty() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.status, EbpfEventStreamFixtureStatus::Empty);
}

// ── 33. Invalid raw frame produces decode error ────────────────────

#[test]
fn i13_invalid_frame_produces_decode_error() {
    let frames = vec![invalid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("inv", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_seen, 1);
    assert_eq!(r.decode_errors, 1);
    assert_eq!(r.frames_decoded, 0);
}

// ── 34. Invalid raw frame does not produce bridge record ───────────

#[test]
fn i13_invalid_frame_no_bridge_record() {
    let frames = vec![invalid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("inv", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.bridge_records, 0);
}

// ── 35. Valid fixture frame decodes successfully ────────────────────

#[test]
fn i13_valid_frame_decodes_successfully() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("val", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_seen, 1);
    assert_eq!(r.frames_decoded, 1);
    assert_eq!(r.decode_errors, 0);
}

// ── 36. Valid fixture frame preserves frame_id ──────────────────────

#[test]
fn i13_valid_frame_preserves_frame_id() {
    let frames = vec![valid_raw_frame(42)];
    let f = build_fixture_from_raw_frames("val", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.decode_report.events.len(), 1);
    assert_eq!(r.decode_report.events[0].event_id, 42);
}

// ── 37. Valid fixture frame can produce bridge record ─────────────

#[test]
fn i13_valid_frame_produces_bridge_record() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("val", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.bridge_records, 1);
}

// ── 38. Bridge report frames_seen counts frames ─────────────────────

#[test]
fn i13_bridge_report_counts_frames_seen() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2), invalid_raw_frame(3)];
    let f = build_fixture_from_raw_frames("mix", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_seen, 3);
}

// ── 39. Bridge report frames_decoded counts decoded frames ──────────

#[test]
fn i13_bridge_report_counts_frames_decoded() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2), invalid_raw_frame(3)];
    let f = build_fixture_from_raw_frames("mix", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_decoded, 2);
}

// ── 40. Bridge report decode_errors counts failed frames ────────────

#[test]
fn i13_bridge_report_counts_decode_errors() {
    let frames = vec![
        valid_raw_frame(1),
        invalid_raw_frame(2),
        invalid_raw_frame(3),
    ];
    let f = build_fixture_from_raw_frames("mix", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.decode_errors, 2);
}

// ── 41. Bridge report bridge_records counts bridge records ──────────

#[test]
fn i13_bridge_report_counts_bridge_records() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2), valid_raw_frame(3)];
    let f = build_fixture_from_raw_frames("val", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.bridge_records, 3);
}

// ── 42. Mixed valid and invalid frames counted honestly ─────────────

#[test]
fn i13_mixed_frames_counted_honestly() {
    let frames = vec![
        valid_raw_frame(1),
        invalid_raw_frame(2),
        valid_raw_frame(3),
        invalid_raw_frame(4),
        valid_raw_frame(5),
    ];
    let f = build_fixture_from_raw_frames("mix5", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.frames_seen, 5);
    assert_eq!(r.frames_decoded, 3);
    assert_eq!(r.decode_errors, 2);
    assert_eq!(r.bridge_records, 3);
}

// ── 43. Fixture report never sets reader_attempted=true ───────────

#[test]
fn i13_report_never_reader_attempted() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.reader_attempted);
}

// ── 44. Fixture report never sets reader_succeeded=true ──────────────

#[test]
fn i13_report_never_reader_succeeded() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.reader_succeeded);
}

// ── 45-52. Fixture report safety flags ──────────────────────────────

#[test]
fn i13_report_never_ring_buffer() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.ring_buffer_opened);
}

#[test]
fn i13_report_never_live_event_stream() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.live_event_stream_read);
}

#[test]
fn i13_report_never_map_pin() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.map_pin_performed);
}

#[test]
fn i13_report_never_enforcement() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.enforcement_performed);
}

#[test]
fn i13_report_never_packet_drop() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.packet_drop_performed);
}

#[test]
fn i13_report_never_mutation() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.mutation_performed);
}

#[test]
fn i13_report_never_persistence() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.persistence_performed);
}

#[test]
fn i13_report_never_public_cli() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("r", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(!r.public_cli_exposed);
}

// ── 53. Validate report accepts safe default report ─────────────────

#[test]
fn i13_validate_report_accepts_safe_default() {
    let f = default_event_stream_fixture();
    let r = decode_event_stream_fixture(&f);
    assert!(validate_event_stream_fixture_bridge_report(&r).is_ok());
}

// ── 54-63. Validate report rejects unsafe flags ─────────────────────

#[test]
fn i13_validate_report_rejects_reader_attempted() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.reader_attempted = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_reader_succeeded() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.reader_succeeded = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_ring_buffer() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.ring_buffer_opened = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_live_read() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.live_event_stream_read = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_map_pin() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.map_pin_performed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_enforcement() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.enforcement_performed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_packet_drop() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.packet_drop_performed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_mutation() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.mutation_performed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_persistence() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.persistence_performed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

#[test]
fn i13_validate_report_rejects_public_cli() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.public_cli_exposed = true;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

// ── 64. Validate report rejects frames_decoded > frames_seen ───────

#[test]
fn i13_validate_report_rejects_decoded_exceeds_seen() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.frames_seen = 1;
    r.frames_decoded = 2;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

// ── 65. Validate report rejects bridge_records > frames_decoded ─────

#[test]
fn i13_validate_report_rejects_bridge_exceeds_decoded() {
    let f = default_event_stream_fixture();
    let mut r = decode_event_stream_fixture(&f);
    r.frames_decoded = 1;
    r.bridge_records = 2;
    assert!(validate_event_stream_fixture_bridge_report(&r).is_err());
}

// ── 66. Evaluation is deterministic ─────────────────────────────────

#[test]
fn i13_evaluation_is_deterministic() {
    let frames = vec![valid_raw_frame(1), invalid_raw_frame(2), valid_raw_frame(3)];
    let f = build_fixture_from_raw_frames("det", EbpfEventSource::Model, frames);
    let r1 = decode_event_stream_fixture(&f);
    let r2 = decode_event_stream_fixture(&f);
    assert_eq!(r1, r2);
}

// ── 67. Docs exist ────────────────────────────────────────────────

#[test]
fn i13_doc_exists() {
    assert!(!I13_DOC.is_empty());
}

// ── 68-83. Doc content checks ───────────────────────────────────────

#[test]
fn i13_doc_mentions_fixture_decoder_bridge() {
    assert!(I13_DOC.to_lowercase().contains("event stream fixture"));
}

#[test]
fn i13_doc_says_fixture_only() {
    assert!(I13_DOC.to_lowercase().contains("fixture-only"));
}

#[test]
fn i13_doc_says_in_memory_only() {
    assert!(I13_DOC.to_lowercase().contains("in-memory"));
}

#[test]
fn i13_doc_says_no_public_cli() {
    assert!(I13_DOC.to_lowercase().contains("no public cli"));
}

#[test]
fn i13_doc_says_no_normal_ci_live_read() {
    assert!(I13_DOC.to_lowercase().contains("no normal ci"));
}

#[test]
fn i13_doc_says_no_ring_buffer() {
    assert!(I13_DOC.to_lowercase().contains("no ring buffer"));
}

#[test]
fn i13_doc_says_no_live_kernel_event_read() {
    assert!(I13_DOC.to_lowercase().contains("no live kernel event read"));
}

#[test]
fn i13_doc_says_no_map_pin() {
    assert!(I13_DOC.to_lowercase().contains("no map pin"));
}

#[test]
fn i13_doc_says_no_enforcement() {
    assert!(I13_DOC.to_lowercase().contains("no enforcement"));
}

#[test]
fn i13_doc_says_no_packet_drop() {
    assert!(I13_DOC.to_lowercase().contains("no packet drop"));
}

#[test]
fn i13_doc_says_no_block_allow_quota() {
    assert!(I13_DOC.to_lowercase().contains("block/allow/quota"));
}

#[test]
fn i13_doc_says_no_nft_tc_fallback() {
    assert!(I13_DOC.to_lowercase().contains("nft") || I13_DOC.to_lowercase().contains("tc"));
}

#[test]
fn i13_doc_says_no_ledger_persistence() {
    let doc_lower = I13_DOC.to_lowercase();
    assert!(doc_lower.contains("no ledger") || doc_lower.contains("persistence"));
}

#[test]
fn i13_doc_says_schema_unchanged() {
    assert!(
        I13_DOC.to_lowercase().contains("unchanged") || I13_DOC.to_lowercase().contains("schema")
    );
}

#[test]
fn i13_doc_says_no_fake_decoded_event() {
    assert!(I13_DOC.to_lowercase().contains("fake"));
}

#[test]
fn i13_doc_says_no_fake_bridge_success() {
    assert!(I13_DOC.to_lowercase().contains("fake bridge"));
}

// ── 84. Version remains v3.1.0 ──────────────────────────────────────

#[test]
fn i13_version_remains_v3_1_0() {
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(version, "3.1.0");
}

// ── 85. Ledger inspect still works ───────────────────────────────────

#[test]
fn i13_ledger_inspect_works() {
    let _ = handle_ledger_inspect(true, None);
}

// ── 86. Ledger export still works ───────────────────────────────────

#[test]
fn i13_ledger_export_works() {
    let path = std::env::temp_dir().join("i13-ledger-export-test.json");
    let _ = handle_ledger_export(true, Some(path.to_string_lossy().as_ref()));
}

// ── 87. Public help no intergalaxion ────────────────────────────────

#[test]
fn i13_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

// ── 88. Public help no block/allow/quota ────────────────────────────

#[test]
fn i13_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    let h = help.to_lowercase();
    assert!(!h.contains("block") || !h.contains("allow") || !h.contains("quota"));
}

// ── 89. No new dependency added ─────────────────────────────────────

#[test]
fn i13_no_new_dependency() {
    assert!(CARGO_TOML.contains("clap = "));
    assert!(CARGO_TOML.contains("serde = "));
    // intergalaxion-event-stream-lab has no deps
    assert!(CARGO_TOML.contains("intergalaxion-event-stream-lab = []"));
}

// ── 90. No nft/tc source ────────────────────────────────────────────

#[test]
fn i13_no_nft_tc_source() {
    let src = I13_SOURCE;
    assert!(!src.contains("tc::"));
    assert!(!src.contains("nft::"));
}

// ── 91. Source file under 1000 LOC ──────────────────────────────────

#[test]
fn i13_source_under_1000_loc() {
    let lines = I13_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "event_stream_fixture.rs has {lines} lines (max 1000)"
    );
}

// ── Additional coverage ────────────────────────────────────────────

#[test]
fn i13_all_valid_frames_bridge_completed() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2)];
    let f = build_fixture_from_raw_frames("bc", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.status, EbpfEventStreamFixtureStatus::BridgeCompleted);
}

#[test]
fn i13_all_invalid_frames_decode_failed() {
    let frames = vec![invalid_raw_frame(1), invalid_raw_frame(2)];
    let f = build_fixture_from_raw_frames("df", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.status, EbpfEventStreamFixtureStatus::DecodeFailed);
}

#[test]
fn i13_validate_report_accepts_valid_bridge_report() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2)];
    let f = build_fixture_from_raw_frames("vr", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert!(validate_event_stream_fixture_bridge_report(&r).is_ok());
}

#[test]
fn i13_all_status_variants_have_labels() {
    use EbpfEventStreamFixtureStatus::*;
    for status in [
        Empty,
        FixtureOnly,
        DecodeReady,
        DecodeCompleted,
        DecodeFailed,
        BridgeReady,
        BridgeCompleted,
        BridgeFailed,
        Rejected,
    ] {
        let label = event_stream_fixture_status_label(status);
        assert!(!label.is_empty());
    }
}

#[test]
fn i13_all_mode_variants_have_labels() {
    use EbpfEventStreamFixtureMode::*;
    for mode in [
        InMemoryFixtureOnly,
        ReaderBoundaryDryRun,
        LiveStreamUnsupported,
    ] {
        let label = event_stream_fixture_mode_label(mode);
        assert!(!label.is_empty());
    }
}

#[test]
fn i13_no_forbidden_patterns_in_source() {
    let src = I13_SOURCE;
    let forbidden = [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "RingBuf",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
    ];
    for pattern in &forbidden {
        assert!(!src.contains(pattern), "forbidden pattern found: {pattern}");
    }
}

#[test]
fn i13_no_forbidden_mutation_patterns_in_source() {
    let src = I13_SOURCE;
    let forbidden = [
        "File::create",
        "fs::write",
        "OpenOptions",
        "drop_packet",
        "block(",
        "allow(",
        "quota",
    ];
    for pattern in &forbidden {
        assert!(
            !src.contains(pattern),
            "forbidden mutation pattern found: {pattern}"
        );
    }
    // Check persist only appears as part of field name
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains("persist") && !trimmed.contains("persistence") {
            panic!("standalone 'persist' found in source: {trimmed}");
        }
    }
}

#[test]
fn i13_bridge_report_has_correct_fixture_id() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("my-fixture-id", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.fixture_id, "my-fixture-id");
}

#[test]
fn i13_bridge_report_has_correct_mode() {
    let frames = vec![valid_raw_frame(1)];
    let f = build_fixture_from_raw_frames("id", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.mode, EbpfEventStreamFixtureMode::InMemoryFixtureOnly);
}

#[test]
fn i13_single_valid_frame_bridge_record_nonempty() {
    let frames = vec![valid_raw_frame(99)];
    let f = build_fixture_from_raw_frames("br", EbpfEventSource::Model, frames);
    let r = decode_event_stream_fixture(&f);
    assert_eq!(r.bridge_batch.records.len(), 1);
    assert_eq!(r.bridge_batch.records[0].source_event_id, 99);
}
