// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Error case tests for delta JSON output.

use super::*;

// ── Error: first read failure ──────────────────────────────────────

#[test]
fn first_read_error_has_zero_interfaces() {
    let output = build_delta_json_first_read_error(
        DeltaJsonErrorType::Read,
        "read error: permission denied",
    );
    assert!(output.interfaces.is_empty());
    assert!(output.error.is_some());
    assert_eq!(output.sample_count, 0);
    assert_eq!(output.read_count, 0);
    assert!(output.start_sample.is_none());
    assert!(output.end_sample.is_none());
}

#[test]
fn first_read_error_honesty_flags() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert!(!output.honesty.live_read_performed);
    assert_eq!(output.honesty.read_count, 0);
}

#[test]
fn first_read_error_totals_zero() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert_eq!(output.totals.total_delta_rx_bytes, 0);
    assert_eq!(output.totals.total_delta_tx_bytes, 0);
    assert_eq!(output.totals.total_delta_combined_bytes, 0);
    assert_eq!(output.totals.interface_count, 0);
}

// ── Error: second read failure ──────────────────────────────────────

#[test]
fn second_read_error_has_start_sample() {
    let start = parse(START_SAMPLE);
    let output = build_delta_json_second_read_error(
        &start,
        DeltaJsonErrorType::Read,
        "read error: second sample failed",
    );
    assert!(output.error.is_some());
    assert_eq!(output.sample_count, 1);
    assert_eq!(output.read_count, 1);
    assert!(output.start_sample.is_some());
    assert!(output.end_sample.is_none());
    assert!(output.interfaces.is_empty());
}

#[test]
fn second_read_error_honesty_flags() {
    let start = parse(START_SAMPLE);
    let output = build_delta_json_second_read_error(&start, DeltaJsonErrorType::Read, "test");
    assert!(output.honesty.live_read_performed);
    assert_eq!(output.honesty.read_count, 1);
}

#[test]
fn second_read_error_start_summary_correct() {
    let start = parse(START_SAMPLE);
    let output = build_delta_json_second_read_error(&start, DeltaJsonErrorType::Read, "test");
    let ss = output.start_sample.as_ref().unwrap();
    assert_eq!(ss.status, "success");
    assert_eq!(ss.interface_count, 2);
}

// ── Error: unsupported flag ────────────────────────────────────────

#[test]
fn unsupported_flag_error() {
    let output =
        build_delta_json_unsupported_flag_error("unsupported flag: --delta is not implemented");
    assert!(output.error.is_some());
    assert_eq!(output.sample_count, 0);
    assert_eq!(output.read_count, 0);
    assert!(output.start_sample.is_none());
    assert!(output.end_sample.is_none());
    assert!(output.interfaces.is_empty());
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("unsupported_flag_error"));
}

// ── Error: warnings present ──────────────────────────────────────────

#[test]
fn error_output_includes_default_warnings() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert_eq!(output.warnings.len(), 13);
}

// ── Error JSON includes all default warnings ────────────────────────

#[test]
fn first_read_error_warnings_are_default_only() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert_eq!(output.warnings.len(), 13);
}

// ── Serialization: error ───────────────────────────────────────────

#[test]
fn serializes_error_json() {
    let output = build_delta_json_first_read_error(
        DeltaJsonErrorType::Read,
        "read error: permission denied",
    );
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"read_error\""));
    assert!(json.contains("permission denied"));
    assert!(json.contains("\"interface_level_only\": true"));
    assert!(json.contains("\"sample_count\": 0"));
    assert!(json.contains("\"read_count\": 0"));
}

// ── Serialization: second read error ──────────────────────────────────

#[test]
fn serializes_second_read_error_json() {
    let start = parse(START_SAMPLE);
    let output = build_delta_json_second_read_error(
        &start,
        DeltaJsonErrorType::Parse,
        "parse error: malformed content",
    );
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"parse_error\""));
    assert!(json.contains("\"sample_count\": 1"));
    assert!(json.contains("\"read_count\": 1"));
    assert!(json.contains("\"live_read_performed\": true"));
}

// ── Round-trip: error ──────────────────────────────────────────────

#[test]
fn round_trips_first_read_error_json() {
    let output = build_delta_json_first_read_error(
        DeltaJsonErrorType::Read,
        "read error: permission denied",
    );
    let json = serialize_delta_json(&output).unwrap();
    let deserialized: UsageDeltaJsonOutput = deserialize_delta_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

#[test]
fn round_trips_second_read_error_json() {
    let start = parse(START_SAMPLE);
    let output =
        build_delta_json_second_read_error(&start, DeltaJsonErrorType::Read, "second read failed");
    let json = serialize_delta_json(&output).unwrap();
    let deserialized: UsageDeltaJsonOutput = deserialize_delta_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

// ── Deserialize rejects malformed JSON ──────────────────────────────

#[test]
fn deserialize_rejects_malformed_json() {
    let result = deserialize_delta_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn deserialize_rejects_missing_required_fields() {
    let result = deserialize_delta_json("{}");
    assert!(result.is_err());
}

// ── Error type display ──────────────────────────────────────────────

#[test]
fn error_type_display() {
    assert_eq!(DeltaJsonErrorType::Read.to_string(), "read_error");
    assert_eq!(DeltaJsonErrorType::Parse.to_string(), "parse_error");
    assert_eq!(
        DeltaJsonErrorType::UnsupportedFlag.to_string(),
        "unsupported_flag_error"
    );
}

// ── Error JSON excludes samples ────────────────────────────────────

#[test]
fn serialized_error_json_excludes_samples() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"start_sample\": null"));
    assert!(json.contains("\"end_sample\": null"));
}
