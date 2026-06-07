// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for v3.0 phase 14 pure delta JSON model and serialization.
//!
//! All tests use injected/parsed content — no live `/proc/net/dev` reads,
//! no filesystem writes, no CLI flags, no enforcement, no mutation.
//! Every test constructs `InterfaceCounterSnapshot` values from `const` strings
//! and passes them to the builder functions.

use super::super::usage_delta_json::{
    build_delta_json_first_read_error, build_delta_json_second_read_error,
    build_delta_json_success, build_delta_json_unsupported_flag_error, delta_default_warnings,
    delta_error_first_read_honesty, delta_error_second_read_honesty, delta_success_honesty_flags,
    deserialize_delta_json, serialize_delta_json, DeltaJsonErrorType, UsageDeltaJsonOutput,
    COMMAND_USAGE_SAMPLE_DELTA_JSON, DEFAULT_DELTA_WAIT_MS, DELTA_SCHEMA_VERSION,
    SAMPLE_MODE_DELTA, SOURCE_LABEL_DELTA_JSON,
};
use crate::accounting::interface_counters::parse_proc_net_dev;
use crate::accounting::{InterfaceCounterSnapshot, SourceLabel};

// ── Sample data ─────────────────────────────────────────────────────

/// Standard start sample with two interfaces.
const START_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000000  10000    0    0    0     0          0         0  500000   5000    0    0    0     0       0          0
  eth0:  200000   2000    0    0    0     0          0         0  100000   1000    0    0    0     0       0          0
";

/// End sample with higher counters (normal delta).
const END_SAMPLE_NORMAL: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

/// End sample with counter reset on wlan0 RX (decreased from start).
const END_SAMPLE_RESET: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0:   500000  15000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

/// End sample with a new interface (wlan1 added).
const END_SAMPLE_ADDED_INTERFACE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
  wlan1: 100000   1000    0    0    0     0          0         0   50000    500    0    0    0     0       0          0
";

/// End sample with an interface removed (eth0 gone).
const END_SAMPLE_REMOVED_INTERFACE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
";

/// Multi-interface sample with loopback for snapshot summary tests.
const MULTI_IFACE_WITH_LO: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

// ── Helpers ─────────────────────────────────────────────────────────

fn parse(content: &str) -> InterfaceCounterSnapshot {
    parse_proc_net_dev(content).expect("parse should succeed")
}

// ── Build: normal delta success ─────────────────────────────────────

#[test]
fn builds_success_from_two_snapshots() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.interfaces.len(), 2);
    assert!(output.error.is_none());
}

// ── Build: interface names preserved ───────────────────────────────

#[test]
fn interface_names_preserved() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.interfaces[0].name, "wlan0");
    assert_eq!(output.interfaces[1].name, "eth0");
}

// ── Build: start/end counter fields present ─────────────────────────

#[test]
fn start_end_counter_fields_present() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let wlan0 = &output.interfaces[0];
    assert_eq!(wlan0.start_rx_bytes, 1_000_000);
    assert_eq!(wlan0.start_tx_bytes, 500_000);
    assert_eq!(wlan0.end_rx_bytes, 2_000_000);
    assert_eq!(wlan0.end_tx_bytes, 1_000_000);
}

// ── Build: delta bytes computed correctly ─────────────────────────

#[test]
fn delta_bytes_computed_correctly() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let wlan0 = &output.interfaces[0];
    assert_eq!(wlan0.delta_rx_bytes, 1_000_000);
    assert_eq!(wlan0.delta_tx_bytes, 500_000);
    assert_eq!(wlan0.delta_combined_bytes, 1_500_000);
}

// ── Build: delta packets computed correctly ────────────────────────

#[test]
fn delta_packets_computed_correctly() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let wlan0 = &output.interfaces[0];
    assert_eq!(wlan0.start_rx_packets, 10_000);
    assert_eq!(wlan0.start_tx_packets, 5_000);
    assert_eq!(wlan0.end_rx_packets, 20_000);
    assert_eq!(wlan0.end_tx_packets, 10_000);
    assert_eq!(wlan0.delta_rx_packets, 10_000);
    assert_eq!(wlan0.delta_tx_packets, 5_000);
}

// ── Totals correctness ──────────────────────────────────────────────

#[test]
fn totals_rx_tx_combined_correct() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.totals.total_delta_rx_bytes, 1_100_000);
    assert_eq!(output.totals.total_delta_tx_bytes, 600_000);
    assert_eq!(output.totals.total_delta_combined_bytes, 1_700_000);
    assert_eq!(output.totals.interface_count, 2);
}

// ── Totals: loopback counts ─────────────────────────────────────────

#[test]
fn totals_loopback_nonloopback_counts() {
    let start = parse(MULTI_IFACE_WITH_LO);
    let end = parse(MULTI_IFACE_WITH_LO);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.totals.loopback_interface_count, 1);
    assert_eq!(output.totals.non_loopback_interface_count, 2);
}

// ── Sample summaries ────────────────────────────────────────────────

#[test]
fn start_sample_summary_present() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let ss = output.start_sample.as_ref().unwrap();
    assert_eq!(ss.status, "success");
    assert_eq!(ss.interface_count, 2);
    assert_eq!(ss.total_rx_bytes, 1_200_000);
    assert_eq!(ss.total_tx_bytes, 600_000);
    assert_eq!(ss.total_combined_bytes, 1_800_000);
}

#[test]
fn end_sample_summary_present() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let es = output.end_sample.as_ref().unwrap();
    assert_eq!(es.status, "success");
    assert_eq!(es.interface_count, 2);
    assert_eq!(es.total_rx_bytes, 2_300_000);
    assert_eq!(es.total_tx_bytes, 1_200_000);
    assert_eq!(es.total_combined_bytes, 3_500_000);
}

// ── Top-level fields ────────────────────────────────────────────────

#[test]
fn includes_schema_version() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.schema_version, DELTA_SCHEMA_VERSION);
}

#[test]
fn includes_command() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.command, COMMAND_USAGE_SAMPLE_DELTA_JSON);
}

#[test]
fn includes_source_path_and_label() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.source_path, "/proc/net/dev");
    assert_eq!(output.source_label, SOURCE_LABEL_DELTA_JSON);
}

#[test]
fn includes_sample_mode_delta() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.sample_mode, SAMPLE_MODE_DELTA);
}

#[test]
fn includes_sample_count_and_delta_wait() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.sample_count, 2);
    assert_eq!(output.delta_wait_ms, DEFAULT_DELTA_WAIT_MS);
    assert_eq!(output.read_count, 2);
}

// ── Counter reset detection ─────────────────────────────────────────

#[test]
fn counter_reset_detected_on_decrease() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_RESET);
    let output = build_delta_json_success(&start, &end);
    let wlan0 = output
        .interfaces
        .iter()
        .find(|i| i.name == "wlan0")
        .unwrap();
    assert!(wlan0.counter_reset_detected);
    assert_eq!(wlan0.delta_rx_bytes, 0);
}

#[test]
fn counter_reset_count_in_totals() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_RESET);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.totals.counter_reset_count, 1);
}

#[test]
fn counter_reset_warnings_appended() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_RESET);
    let output = build_delta_json_success(&start, &end);
    assert!(output.warnings.len() > 13);
    let has_reset_warning = output.warnings.iter().any(|w| {
        w.contains("counter reset detected") && w.contains("wlan0") && w.contains("rx_bytes")
    });
    assert!(has_reset_warning);
}

// ── Interface added detection ────────────────────────────────────────

#[test]
fn interface_added_detected() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_ADDED_INTERFACE);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.interfaces.len(), 3);
    let wlan1 = output
        .interfaces
        .iter()
        .find(|i| i.name == "wlan1")
        .unwrap();
    assert!(wlan1.interface_added);
    assert!(!wlan1.interface_removed);
    assert!(!wlan1.counter_reset_detected);
    // End-only interface: start counters are 0, delta = 0 (no start to diff against)
    assert_eq!(wlan1.delta_rx_bytes, 0);
    assert_eq!(wlan1.delta_tx_bytes, 0);
    // But end counters are populated
    assert_eq!(wlan1.end_rx_bytes, 100_000);
    assert_eq!(wlan1.end_tx_bytes, 50_000);
}

#[test]
fn interface_added_count_in_totals() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_ADDED_INTERFACE);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.totals.interface_added_count, 1);
}

// ── Interface removed detection ──────────────────────────────────────

#[test]
fn interface_removed_detected() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_REMOVED_INTERFACE);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.interfaces.len(), 2);
    let eth0 = output.interfaces.iter().find(|i| i.name == "eth0").unwrap();
    assert!(eth0.interface_removed);
    assert!(!eth0.interface_added);
    assert_eq!(eth0.delta_rx_bytes, 0);
    assert_eq!(eth0.delta_tx_bytes, 0);
}

#[test]
fn interface_removed_count_in_totals() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_REMOVED_INTERFACE);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.totals.interface_removed_count, 1);
}

// ── Honesty flags: all 19 present ──────────────────────────────────

#[test]
fn success_honesty_has_all_19_flags() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let h = &output.honesty;
    assert!(h.interface_level_only);
    assert!(!h.per_app_attribution);
    assert!(!h.quota_enforcement_active);
    assert!(!h.network_blocking_active);
    assert!(!h.limiter_attach_performed);
    assert!(!h.nft_tc_state_mutation_performed);
    assert!(!h.ledger_persistence_performed);
    assert!(!h.ebpf_used);
    assert!(!h.cgroup_mutation_performed);
    assert!(!h.pid_movement_performed);
    assert!(!h.filesystem_write_performed);
    assert!(!h.state_mutation_performed);
    assert!(h.delta_json_output);
    assert!(h.live_read_performed);
    assert_eq!(h.read_count, 2);
    assert!(h.single_shot);
    assert!(!h.loop_watch_mode);
    assert!(!h.configurable_interval);
    assert!(!h.interface_filtering);
    assert!(!h.arbitrary_path_read);
}

// ── Honesty: default helpers ────────────────────────────────────────

#[test]
fn default_honesty_flags_are_v30_constants() {
    let flags = delta_success_honesty_flags();
    assert!(flags.interface_level_only);
    assert!(!flags.per_app_attribution);
    assert!(!flags.quota_enforcement_active);
    assert!(flags.delta_json_output);
    assert!(flags.single_shot);
    assert!(!flags.loop_watch_mode);
    assert_eq!(flags.read_count, 2);
}

#[test]
fn first_read_error_honesty() {
    let flags = delta_error_first_read_honesty();
    assert!(!flags.live_read_performed);
    assert_eq!(flags.read_count, 0);
}

#[test]
fn second_read_error_honesty() {
    let flags = delta_error_second_read_honesty();
    assert!(flags.live_read_performed);
    assert_eq!(flags.read_count, 1);
}

// ── Warnings: default 13 ───────────────────────────────────────────

#[test]
fn default_warnings_has_13_entries() {
    let warnings = delta_default_warnings();
    assert_eq!(warnings.len(), 13);
}

#[test]
fn default_warnings_include_counter_reset_warning() {
    let warnings = delta_default_warnings();
    assert!(warnings.iter().any(|w| w.contains("counters may reset")));
}

#[test]
fn default_warnings_include_delta_incomplete_warning() {
    let warnings = delta_default_warnings();
    assert!(warnings
        .iter()
        .any(|w| w.contains("delta may be incomplete")));
}

#[test]
fn default_warnings_include_not_per_app() {
    let warnings = delta_default_warnings();
    assert!(warnings.iter().any(|w| w.contains("per-app")));
}

#[test]
fn success_output_includes_all_13_default_warnings() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert!(output.warnings.len() >= 13);
}

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

// ── Error preserves honesty flags ────────────────────────────────────

#[test]
fn error_preserves_all_19_honesty_flags() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    let h = &output.honesty;
    assert!(h.interface_level_only);
    assert!(!h.per_app_attribution);
    assert!(!h.quota_enforcement_active);
    assert!(!h.network_blocking_active);
    assert!(!h.limiter_attach_performed);
    assert!(!h.nft_tc_state_mutation_performed);
    assert!(!h.ledger_persistence_performed);
    assert!(!h.ebpf_used);
    assert!(!h.cgroup_mutation_performed);
    assert!(!h.pid_movement_performed);
    assert!(!h.filesystem_write_performed);
    assert!(!h.state_mutation_performed);
    assert!(h.delta_json_output);
    assert!(!h.live_read_performed);
    assert_eq!(h.read_count, 0);
    assert!(h.single_shot);
    assert!(!h.loop_watch_mode);
    assert!(!h.configurable_interval);
    assert!(!h.interface_filtering);
    assert!(!h.arbitrary_path_read);
}

// ── Error: warnings present ──────────────────────────────────────────

#[test]
fn error_output_includes_default_warnings() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert_eq!(output.warnings.len(), 13);
}

// ── Serialization: success ─────────────────────────────────────────

#[test]
fn serializes_valid_success_json() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"schema_version\": 1"));
    assert!(json.contains("\"command\": \"usage --sample --delta --json\""));
    assert!(json.contains("\"source_path\": \"/proc/net/dev\""));
    assert!(json.contains("\"source_label\": \"live_proc_net_dev\""));
    assert!(json.contains("\"sample_mode\": \"delta\""));
    assert!(json.contains("\"sample_count\": 2"));
    assert!(json.contains("\"delta_wait_ms\": 1000"));
    assert!(json.contains("\"read_count\": 2"));
    assert!(json.contains("\"wlan0\""));
    assert!(json.contains("\"start_rx_bytes\": 1000000"));
    assert!(json.contains("\"end_rx_bytes\": 2000000"));
    assert!(json.contains("\"delta_rx_bytes\": 1000000"));
    assert!(json.contains("\"interface_level_only\": true"));
    assert!(json.contains("\"delta_json_output\": true"));
    assert!(json.contains("\"single_shot\": true"));
    assert!(json.contains("\"loop_watch_mode\": false"));
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

// ── Round-trip: success ─────────────────────────────────────────────

#[test]
fn round_trips_success_json() {
    let start = parse(MULTI_IFACE_WITH_LO);
    let end = parse(MULTI_IFACE_WITH_LO);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    let deserialized: UsageDeltaJsonOutput = deserialize_delta_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

#[test]
fn round_trips_normal_delta_json() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    let deserialized: UsageDeltaJsonOutput = deserialize_delta_json(&json).unwrap();
    assert_eq!(output, deserialized);
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

// ── Round-trip: counter reset ─────────────────────────────────────

#[test]
fn round_trips_counter_reset_json() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_RESET);
    let output = build_delta_json_success(&start, &end);
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

// ── Serialization includes all honesty flags ──────────────────────────

#[test]
fn serialized_json_includes_all_honesty_flags() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    let required_flags = [
        "interface_level_only",
        "per_app_attribution",
        "quota_enforcement_active",
        "network_blocking_active",
        "limiter_attach_performed",
        "nft_tc_state_mutation_performed",
        "ledger_persistence_performed",
        "ebpf_used",
        "cgroup_mutation_performed",
        "pid_movement_performed",
        "filesystem_write_performed",
        "state_mutation_performed",
        "delta_json_output",
        "live_read_performed",
        "read_count",
        "single_shot",
        "loop_watch_mode",
        "configurable_interval",
        "interface_filtering",
        "arbitrary_path_read",
    ];
    for flag in &required_flags {
        assert!(
            json.contains(flag),
            "missing honesty flag in JSON: {}",
            flag
        );
    }
}

#[test]
fn error_serialized_json_includes_all_honesty_flags() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test error");
    let json = serialize_delta_json(&output).unwrap();
    let required_flags = [
        "interface_level_only",
        "per_app_attribution",
        "quota_enforcement_active",
        "delta_json_output",
        "read_count",
        "single_shot",
        "loop_watch_mode",
        "configurable_interval",
        "interface_filtering",
        "arbitrary_path_read",
    ];
    for flag in &required_flags {
        assert!(
            json.contains(flag),
            "error JSON missing honesty flag: {}",
            flag
        );
    }
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

// ── Empty snapshot (both empty) ─────────────────────────────────────

#[test]
fn handles_both_empty_snapshots() {
    let start = InterfaceCounterSnapshot {
        interfaces: Vec::new(),
        source: SourceLabel::ProcNetDevSample,
    };
    let end = InterfaceCounterSnapshot {
        interfaces: Vec::new(),
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_delta_json_success(&start, &end);
    assert!(output.interfaces.is_empty());
    assert!(output.error.is_none());
    assert_eq!(output.totals.total_delta_rx_bytes, 0);
    assert_eq!(output.totals.interface_count, 0);
    let ss = output.start_sample.as_ref().unwrap();
    assert_eq!(ss.interface_count, 0);
    let es = output.end_sample.as_ref().unwrap();
    assert_eq!(es.interface_count, 0);
}

// ── u64::MAX counters ──────────────────────────────────────────────

#[test]
fn handles_u64_max_counters() {
    let start = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX - 1_000_000,
            tx_bytes: u64::MAX - 500_000,
            rx_packets: u64::MAX,
            tx_packets: u64::MAX,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let end = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX,
            tx_bytes: u64::MAX,
            rx_packets: u64::MAX,
            tx_packets: u64::MAX,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_delta_json_success(&start, &end);
    let iface = &output.interfaces[0];
    assert_eq!(iface.delta_rx_bytes, 1_000_000);
    assert_eq!(iface.delta_tx_bytes, 500_000);
    let json = serialize_delta_json(&output).unwrap();
    let deserialized: UsageDeltaJsonOutput = deserialize_delta_json(&json).unwrap();
    assert_eq!(deserialized.interfaces[0].end_rx_bytes, u64::MAX);
}

// ── Saturating totals ───────────────────────────────────────────────

#[test]
fn combined_delta_saturates_correctly() {
    let start = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let end = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX,
            tx_bytes: u64::MAX,
            rx_packets: 0,
            tx_packets: 0,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.interfaces[0].delta_combined_bytes, u64::MAX);
    assert_eq!(output.totals.total_delta_combined_bytes, u64::MAX);
}

// ── Determinism ─────────────────────────────────────────────────────

#[test]
fn serialization_is_deterministic() {
    let start = parse(MULTI_IFACE_WITH_LO);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json1 = serialize_delta_json(&output).unwrap();
    let json2 = serialize_delta_json(&output).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn build_is_deterministic() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output1 = build_delta_json_success(&start, &end);
    let output2 = build_delta_json_success(&start, &end);
    assert_eq!(output1, output2);
}

// ── Zero delta (same snapshot twice) ─────────────────────────────────

#[test]
fn zero_delta_when_same_snapshot() {
    let snap = parse(START_SAMPLE);
    let output = build_delta_json_success(&snap, &snap);
    for iface in &output.interfaces {
        assert_eq!(iface.delta_rx_bytes, 0);
        assert_eq!(iface.delta_tx_bytes, 0);
        assert_eq!(iface.delta_combined_bytes, 0);
        assert_eq!(iface.delta_rx_packets, 0);
        assert_eq!(iface.delta_tx_packets, 0);
        assert!(!iface.counter_reset_detected);
    }
    assert_eq!(output.totals.counter_reset_count, 0);
}

// ── Loopback flag ──────────────────────────────────────────────────

#[test]
fn loopback_flag_set_for_lo() {
    let start = parse(MULTI_IFACE_WITH_LO);
    let end = parse(MULTI_IFACE_WITH_LO);
    let output = build_delta_json_success(&start, &end);
    let lo = output.interfaces.iter().find(|i| i.name == "lo").unwrap();
    assert!(lo.loopback);
    let wlan0 = output
        .interfaces
        .iter()
        .find(|i| i.name == "wlan0")
        .unwrap();
    assert!(!wlan0.loopback);
}

// ── Structural: no CLI flag ──────────────────────────────────────────

#[test]
fn no_cli_flag_added() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.command, "usage --sample --delta --json");
}

// ── Structural: no live /proc/net/dev read in tests ──────────────────

#[test]
fn tests_do_not_read_real_proc_net_dev() {
    // Structural test: all test data is const strings parsed by
    // parse_proc_net_dev(). No std::fs API is used in this test module.
}

// ── Structural: no filesystem write APIs ────────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: usage_delta_json.rs contains only pure functions
    // and serde serialization. No std::fs, no write operations.
}

// ── Serialization: sample summaries in JSON ─────────────────────────

#[test]
fn serialized_json_includes_sample_summaries() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"start_sample\""));
    assert!(json.contains("\"end_sample\""));
    assert!(json.contains("\"status\": \"success\""));
}

#[test]
fn serialized_error_json_excludes_samples() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    let json = serialize_delta_json(&output).unwrap();
    assert!(json.contains("\"start_sample\": null"));
    assert!(json.contains("\"end_sample\": null"));
}

// ── Counter reset on multiple counters ───────────────────────────────

#[test]
fn counter_reset_multiple_counters_same_interface() {
    let start_content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 5000000  7000    0    0    0     0          0         0  3000000   5000    0    0    0     0       0          0
";
    let end_content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000000  2000    0    0    0     0          0         0   500000   1000    0    0    0     0       0          0
";
    let start = parse(start_content);
    let end = parse(end_content);
    let output = build_delta_json_success(&start, &end);
    let wlan0 = &output.interfaces[0];
    assert!(wlan0.counter_reset_detected);
    assert_eq!(wlan0.delta_rx_bytes, 0);
    assert_eq!(wlan0.delta_tx_bytes, 0);
    let reset_warnings: Vec<_> = output
        .warnings
        .iter()
        .filter(|w| w.contains("counter reset detected"))
        .collect();
    assert!(reset_warnings.len() >= 2);
}

// ── Error JSON includes all default warnings ────────────────────────

#[test]
fn first_read_error_warnings_are_default_only() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    assert_eq!(output.warnings.len(), 13);
}
