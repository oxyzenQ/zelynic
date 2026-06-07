// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Success build and validation tests for delta JSON output.

use super::*;

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
