// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Event stream fixture decoder bridge for the Intergalaxion Engine.
//!
//! Phase I-13 adds a fixture-only event stream decoder bridge that proves
//! the future reader-to-decoder-to-bridge path using deterministic in-memory
//! fixture frames only. This phase does NOT open ring buffers, NOT read live
//! kernel events, NOT start the event stream reader, NOT expose public CLI,
//! NOT add enforcement, and NOT fake decoded event success.
//!
//! # Design constraints (I-13)
//!
//! * Fixture-only — all frames are deterministic in-memory data.
//! * Reuses I-4 decoder models and I-4 ledger bridge models.
//! * Reuses I-12 reader boundary result models.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake decoded event success.
//! * No fake bridge success.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::decoder::{
    decode_raw_event_batch, EbpfDecodeReport, EbpfRawEventFrame,
};
use crate::intergalaxion_engine::backends::ebpf::event_schema::EbpfEventSource;
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderResult;
use crate::intergalaxion_engine::ledger_bridge::event_bridge::{
    bridge_event_to_ledger_record, IntergalaxionLedgerBridgeBatch, IntergalaxionLedgerBridgeRecord,
};

/// Status of the event stream fixture decoder bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamFixtureStatus {
    /// No fixture frames are available.
    Empty,
    /// Fixture contains frames but decoding has not started.
    FixtureOnly,
    /// Fixture frames are ready for decoding.
    DecodeReady,
    /// All fixture frames decoded successfully.
    DecodeCompleted,
    /// One or more fixture frames failed to decode.
    DecodeFailed,
    /// Decoded frames are ready for bridging.
    BridgeReady,
    /// All decoded frames bridged successfully.
    BridgeCompleted,
    /// One or more bridge operations failed.
    BridgeFailed,
    /// Fixture was rejected due to unsafe configuration.
    Rejected,
}

impl EbpfEventStreamFixtureStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::FixtureOnly => "fixture_only",
            Self::DecodeReady => "decode_ready",
            Self::DecodeCompleted => "decode_completed",
            Self::DecodeFailed => "decode_failed",
            Self::BridgeReady => "bridge_ready",
            Self::BridgeCompleted => "bridge_completed",
            Self::BridgeFailed => "bridge_failed",
            Self::Rejected => "rejected",
        }
    }
}

/// Mode of the event stream fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamFixtureMode {
    /// In-memory fixture frames only.
    InMemoryFixtureOnly,
    /// Reader boundary dry run (not implemented in I-13).
    ReaderBoundaryDryRun,
    /// Live stream is not supported.
    LiveStreamUnsupported,
}

impl EbpfEventStreamFixtureMode {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InMemoryFixtureOnly => "in_memory_fixture_only",
            Self::ReaderBoundaryDryRun => "reader_boundary_dry_run",
            Self::LiveStreamUnsupported => "live_stream_unsupported",
        }
    }
}

/// A single fixture frame wrapping a raw event frame for decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamFixtureFrame {
    /// Stream offset within the fixture sequence.
    pub stream_offset: u64,
    /// The underlying raw event frame.
    pub raw_frame: EbpfRawEventFrame,
    /// Whether this frame is expected to decode successfully.
    pub expected_decode_success: bool,
    /// Human-readable label for this fixture frame.
    pub fixture_label: String,
}

/// A collection of fixture frames for the decoder bridge pipeline.
///
/// All frames are deterministic in-memory data. No ring buffer is opened,
/// no live kernel events are read. The fixture always has `fixture_only=true`
/// and all safety flags false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamFixture {
    /// Unique identifier for this fixture.
    pub fixture_id: String,
    /// The fixture mode.
    pub mode: EbpfEventStreamFixtureMode,
    /// The event source for all frames in this fixture.
    pub source: EbpfEventSource,
    /// The fixture frames.
    pub frames: Vec<EbpfEventStreamFixtureFrame>,
    /// The reader boundary result (informational in I-13).
    pub reader_result: EbpfEventStreamReaderResult,
    /// Whether this fixture is in-memory only (always true in I-13).
    pub fixture_only: bool,
    /// Whether a ring buffer was opened (always false in I-13).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-13).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-13).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
}

/// Report produced by decoding and bridging an event stream fixture.
///
/// All operation flags are always false in I-13. The report is pure and
/// deterministic. No ring buffer is opened, no live events are read, no
/// maps are pinned, no persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamFixtureBridgeReport {
    /// The determined fixture bridge status.
    pub status: EbpfEventStreamFixtureStatus,
    /// The fixture identifier.
    pub fixture_id: String,
    /// The fixture mode.
    pub mode: EbpfEventStreamFixtureMode,
    /// Total number of frames seen.
    pub frames_seen: usize,
    /// Total number of frames successfully decoded.
    pub frames_decoded: usize,
    /// Number of decode errors.
    pub decode_errors: usize,
    /// Number of bridge records produced.
    pub bridge_records: usize,
    /// Number of bridge errors.
    pub bridge_errors: usize,
    /// Number of events skipped during bridging.
    pub skipped_events: usize,
    /// The decode report from the I-4 decoder.
    pub decode_report: EbpfDecodeReport,
    /// The bridge batch from the I-4 ledger bridge.
    pub bridge_batch: IntergalaxionLedgerBridgeBatch,
    /// Whether this is a fixture-only report (always true in I-13).
    pub fixture_only: bool,
    /// Whether a reader was attempted (always false in I-13).
    pub reader_attempted: bool,
    /// Whether a reader succeeded (always false in I-13).
    pub reader_succeeded: bool,
    /// Whether a ring buffer was opened (always false in I-13).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-13).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-13).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default event stream fixture.
///
/// All fields are in their safest configuration: empty fixture,
/// in-memory-only mode, model source, all safety flags false.
pub fn default_event_stream_fixture() -> EbpfEventStreamFixture {
    let reader_result =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    let evaluated_reader = crate::intergalaxion_engine::backends::ebpf::event_stream_reader::evaluate_event_stream_reader(&reader_result);
    EbpfEventStreamFixture {
        fixture_id: String::from("default-fixture"),
        mode: EbpfEventStreamFixtureMode::InMemoryFixtureOnly,
        source: EbpfEventSource::default(),
        frames: Vec::new(),
        reader_result: evaluated_reader,
        fixture_only: true,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    }
}

/// Build a safe base report with all operation flags false.
fn safe_base_report(
    fixture_id: String,
    mode: EbpfEventStreamFixtureMode,
) -> EbpfEventStreamFixtureBridgeReport {
    EbpfEventStreamFixtureBridgeReport {
        status: EbpfEventStreamFixtureStatus::Empty,
        fixture_id,
        mode,
        frames_seen: 0,
        frames_decoded: 0,
        decode_errors: 0,
        bridge_records: 0,
        bridge_errors: 0,
        skipped_events: 0,
        decode_report: EbpfDecodeReport::default(),
        bridge_batch: IntergalaxionLedgerBridgeBatch::default(),
        fixture_only: true,
        reader_attempted: false,
        reader_succeeded: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    }
}

/// Create a single fixture frame from a raw event frame.
///
/// Wraps the raw frame with stream offset, expected decode success flag,
/// and a human-readable label for audit purposes.
pub fn fixture_frame_from_raw(
    stream_offset: u64,
    raw_frame: EbpfRawEventFrame,
    expected_decode_success: bool,
    fixture_label: &str,
) -> EbpfEventStreamFixtureFrame {
    EbpfEventStreamFixtureFrame {
        stream_offset,
        raw_frame,
        expected_decode_success,
        fixture_label: String::from(fixture_label),
    }
}

/// Build a fixture from a list of raw event frames.
///
/// Assigns deterministic stream offsets (0, 1, 2, ...) and sets
/// expected_decode_success based on whether the raw frame has a
/// non-empty payload. The resulting fixture is fixture-only with
/// all safety flags false.
pub fn build_fixture_from_raw_frames(
    fixture_id: &str,
    source: EbpfEventSource,
    frames: Vec<EbpfRawEventFrame>,
) -> EbpfEventStreamFixture {
    let reader_result =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    let evaluated_reader = crate::intergalaxion_engine::backends::ebpf::event_stream_reader::evaluate_event_stream_reader(&reader_result);
    let fixture_frames: Vec<EbpfEventStreamFixtureFrame> = frames
        .into_iter()
        .enumerate()
        .map(|(i, raw)| {
            let success = !raw.payload.is_empty();
            EbpfEventStreamFixtureFrame {
                stream_offset: i as u64,
                raw_frame: raw,
                expected_decode_success: success,
                fixture_label: format!("frame-{i}"),
            }
        })
        .collect();
    EbpfEventStreamFixture {
        fixture_id: String::from(fixture_id),
        mode: EbpfEventStreamFixtureMode::InMemoryFixtureOnly,
        source,
        frames: fixture_frames,
        reader_result: evaluated_reader,
        fixture_only: true,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        public_cli_exposed: false,
    }
}

/// Decode and bridge an event stream fixture.
///
/// This function is pure and deterministic. It extracts raw frames from
/// the fixture, decodes each one using the I-4 decoder, and bridges
/// decoded events into I-4 ledger bridge records. Invalid frames produce
/// decode errors honestly — no fake success is returned.
///
/// # Pipeline
///
/// 1. Extract raw frames from fixture.
/// 2. Decode batch using `decode_raw_event_batch`.
/// 3. Bridge decoded events using `bridge_event_to_ledger_record`.
/// 4. Aggregate counts and produce the bridge report.
///
/// # Safety
///
/// * No ring buffer is opened.
/// * No live kernel events are read.
/// * No reader is started.
/// * All operation flags remain false.
/// * reader_attempted and reader_succeeded remain false in I-13.
pub fn decode_event_stream_fixture(
    fixture: &EbpfEventStreamFixture,
) -> EbpfEventStreamFixtureBridgeReport {
    let base = safe_base_report(fixture.fixture_id.clone(), fixture.mode);

    if fixture.frames.is_empty() {
        return EbpfEventStreamFixtureBridgeReport {
            status: EbpfEventStreamFixtureStatus::Empty,
            ..base
        };
    }

    // Extract raw frames from fixture frames
    let raw_frames: Vec<EbpfRawEventFrame> =
        fixture.frames.iter().map(|f| f.raw_frame.clone()).collect();

    // Decode using I-4 decoder
    let decode_report = decode_raw_event_batch(&raw_frames);

    // Bridge decoded events using I-4 ledger bridge
    let mut bridge_records: Vec<IntergalaxionLedgerBridgeRecord> = Vec::new();
    let mut bridge_error_count = 0usize;

    for event in &decode_report.events {
        match bridge_event_to_ledger_record(event) {
            Ok(record) => bridge_records.push(record),
            Err(_) => bridge_error_count += 1,
        }
    }

    let bridge_batch = IntergalaxionLedgerBridgeBatch {
        source: fixture.source,
        records: bridge_records,
        skipped_events: 0,
        bridge_errors: Vec::new(), // errors counted but not stored separately
        filesystem_write_performed: false,
        persistence_performed: false,
        enforcement_performed: false,
        mutation_performed: false,
    };

    let frames_decoded = decode_report.frames_decoded;
    let decode_errors = decode_report.decode_errors.len();
    let bridge_records_count = bridge_batch.records.len();

    // Determine status
    let status = if decode_errors == 0 && bridge_error_count == 0 {
        if frames_decoded > 0 {
            EbpfEventStreamFixtureStatus::BridgeCompleted
        } else {
            EbpfEventStreamFixtureStatus::DecodeCompleted
        }
    } else if decode_errors > 0 && bridge_error_count > 0 {
        EbpfEventStreamFixtureStatus::BridgeFailed
    } else if decode_errors > 0 {
        EbpfEventStreamFixtureStatus::DecodeFailed
    } else {
        EbpfEventStreamFixtureStatus::BridgeFailed
    };

    EbpfEventStreamFixtureBridgeReport {
        status,
        frames_seen: fixture.frames.len(),
        frames_decoded,
        decode_errors,
        bridge_records: bridge_records_count,
        bridge_errors: bridge_error_count,
        skipped_events: bridge_batch.skipped_events,
        decode_report,
        bridge_batch,
        ..base
    }
}

/// Validate that an event stream fixture does not have any unsafe or
/// inconsistent flags.
///
/// Returns `Ok(())` if the fixture is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_fixture(fixture: &EbpfEventStreamFixture) -> Result<(), String> {
    if fixture.fixture_id.is_empty() {
        return Err("fixture_id must not be empty".to_string());
    }
    if !fixture.fixture_only {
        return Err("fixture_only must be true in I-13".to_string());
    }
    if fixture.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-13".to_string());
    }
    if fixture.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-13".to_string());
    }
    if fixture.map_pin_performed {
        return Err("map_pin_performed must be false in I-13".to_string());
    }
    if fixture.enforcement_performed {
        return Err("enforcement_performed must be false in I-13".to_string());
    }
    if fixture.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-13".to_string());
    }
    if fixture.mutation_performed {
        return Err("mutation_performed must be false in I-13".to_string());
    }
    if fixture.persistence_performed {
        return Err("persistence_performed must be false in I-13".to_string());
    }
    if fixture.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-13".to_string());
    }
    // Reader result validation
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::{
        validate_event_stream_reader_result, EbpfEventStreamReaderStatus,
    };
    if fixture.reader_result.status == EbpfEventStreamReaderStatus::ReaderSucceeded {
        return Err("reader_result status must not be ReaderSucceeded".to_string());
    }
    if validate_event_stream_reader_result(&fixture.reader_result).is_err() {
        return Err("reader_result must be a valid safe reader result".to_string());
    }
    Ok(())
}

/// Validate that an event stream fixture bridge report does not have any
/// unsafe or inconsistent flags.
///
/// Returns `Ok(())` if the report is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_fixture_bridge_report(
    report: &EbpfEventStreamFixtureBridgeReport,
) -> Result<(), String> {
    // Safety flags
    if report.reader_attempted {
        return Err("reader_attempted must be false in I-13".to_string());
    }
    if report.reader_succeeded {
        return Err("reader_succeeded must be false in I-13".to_string());
    }
    if report.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-13".to_string());
    }
    if report.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-13".to_string());
    }
    if report.map_pin_performed {
        return Err("map_pin_performed must be false in I-13".to_string());
    }
    if report.enforcement_performed {
        return Err("enforcement_performed must be false in I-13".to_string());
    }
    if report.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-13".to_string());
    }
    if report.mutation_performed {
        return Err("mutation_performed must be false in I-13".to_string());
    }
    if report.persistence_performed {
        return Err("persistence_performed must be false in I-13".to_string());
    }
    if report.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-13".to_string());
    }
    // Structural consistency
    if report.frames_decoded > report.frames_seen {
        return Err("frames_decoded must not exceed frames_seen".to_string());
    }
    if report.bridge_records > report.frames_decoded {
        return Err("bridge_records must not exceed frames_decoded".to_string());
    }
    Ok(())
}

/// Map an event stream fixture status to a stable human-readable label.
pub fn event_stream_fixture_status_label(status: EbpfEventStreamFixtureStatus) -> &'static str {
    status.as_str()
}

/// Map an event stream fixture mode to a stable human-readable label.
pub fn event_stream_fixture_mode_label(mode: EbpfEventStreamFixtureMode) -> &'static str {
    mode.as_str()
}
