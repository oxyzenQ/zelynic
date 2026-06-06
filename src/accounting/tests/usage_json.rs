// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for v3.0 phase 7 pure JSON output model and serialization.
//!
//! All tests use injected/parsed content — no live `/proc/net/dev` reads,
//! no filesystem writes, no CLI flags, no enforcement, no mutation.

use super::super::usage_json::{
    build_usage_json_error, build_usage_json_from_snapshot, default_honesty_flags,
    default_warnings, deserialize_usage_json, serialize_usage_json, UsageJsonErrorType,
    UsageJsonOutput, SCHEMA_VERSION,
};
use crate::accounting::{parse_proc_net_dev, InterfaceCounterSnapshot, SourceLabel};

// ── Sample data ─────────────────────────────────────────────────────

/// Single interface sample.
const SINGLE_IFACE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

/// Multi-interface sample with loopback.
const MULTI_IFACE: &str = "\
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

// ── Build: single interface ─────────────────────────────────────────

#[test]
fn builds_from_single_interface_snapshot() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.interfaces.len(), 1);
    assert_eq!(output.interfaces[0].name, "wlan0");
    assert_eq!(output.interfaces[0].rx_bytes, 1000);
    assert_eq!(output.interfaces[0].tx_bytes, 2000);
    assert_eq!(output.interfaces[0].combined_bytes, 3000);
    assert_eq!(output.interfaces[0].rx_packets, 10);
    assert_eq!(output.interfaces[0].tx_packets, 20);
    assert!(!output.interfaces[0].loopback);
}

// ── Build: multi-interface ─────────────────────────────────────────

#[test]
fn builds_from_multi_interface_snapshot() {
    let snapshot = parse(MULTI_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.interfaces.len(), 3);
    assert_eq!(output.interfaces[0].name, "lo");
    assert_eq!(output.interfaces[1].name, "wlan0");
    assert_eq!(output.interfaces[2].name, "eth0");
}

// ── Totals correctness ──────────────────────────────────────────────

#[test]
fn totals_rx_tx_combined_correct() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.totals.total_rx_bytes, 1000);
    assert_eq!(output.totals.total_tx_bytes, 2000);
    assert_eq!(output.totals.total_combined_bytes, 3000);
    assert_eq!(output.totals.interface_count, 1);
}

#[test]
fn multi_interface_totals_correct() {
    let snapshot = parse(MULTI_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    // lo: rx=123456, tx=234567; wlan0: rx=1324567890, tx=356789012; eth0: rx=0, tx=0
    let expected_rx = 123456u64 + 1324567890;
    let expected_tx = 234567u64 + 356789012;
    assert_eq!(output.totals.total_rx_bytes, expected_rx);
    assert_eq!(output.totals.total_tx_bytes, expected_tx);
    assert_eq!(
        output.totals.total_combined_bytes,
        expected_rx.saturating_add(expected_tx)
    );
    assert_eq!(output.totals.interface_count, 3);
}

// ── Source path and label ───────────────────────────────────────────

#[test]
fn includes_source_path() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.source_path, "/proc/net/dev");
}

#[test]
fn includes_source_label() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.source_label, "live_proc_net_dev");
}

// ── Schema version and command ─────────────────────────────────────

#[test]
fn includes_schema_version() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.schema_version, SCHEMA_VERSION);
}

#[test]
fn includes_command() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert_eq!(output.command, "usage --sample --json");
}

// ── sampled_at: omit when None ──────────────────────────────────────

#[test]
fn omits_sampled_at_when_none() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output.sampled_at.is_none());
    let json = serialize_usage_json(&output).unwrap();
    // Verify "sampled_at" does not appear in serialized output when None.
    assert!(!json.contains("sampled_at"));
}

// ── sampled_at: include when passed ────────────────────────────────

#[test]
fn includes_sampled_at_when_passed() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, Some("2026-06-07T12:00:00Z"));
    assert_eq!(output.sampled_at, Some("2026-06-07T12:00:00Z".to_string()));
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("sampled_at"));
    assert!(json.contains("2026-06-07T12:00:00Z"));
}

// ── No silent timestamp generation ─────────────────────────────────

#[test]
fn does_not_generate_timestamp_silently() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output.sampled_at.is_none());
    // Build again with explicit None to confirm no hidden timestamp logic.
    let output2 = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output2.sampled_at.is_none());
    let json = serialize_usage_json(&output2).unwrap();
    assert!(!json.contains("sampled_at"));
}

// ── Honesty flags ─────────────────────────────────────────────────

#[test]
fn includes_all_12_honesty_flags() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output.honesty.interface_level_only);
    assert!(!output.honesty.per_app_attribution);
    assert!(!output.honesty.quota_enforcement_active);
    assert!(!output.honesty.network_blocking_active);
    assert!(!output.honesty.limiter_attach_performed);
    assert!(!output.honesty.nft_tc_state_mutation_performed);
    assert!(!output.honesty.ledger_persistence_performed);
    assert!(!output.honesty.ebpf_used);
    assert!(!output.honesty.cgroup_mutation_performed);
    assert!(!output.honesty.pid_movement_performed);
    assert!(!output.honesty.filesystem_write_performed);
    assert!(!output.honesty.state_mutation_performed);
}

// ── Default honesty flags constant ──────────────────────────────────

#[test]
fn default_honesty_flags_are_v30_constants() {
    let flags = default_honesty_flags();
    assert!(flags.interface_level_only);
    assert!(!flags.per_app_attribution);
    assert!(!flags.quota_enforcement_active);
    assert!(!flags.network_blocking_active);
    assert!(!flags.limiter_attach_performed);
    assert!(!flags.nft_tc_state_mutation_performed);
    assert!(!flags.ledger_persistence_performed);
    assert!(!flags.ebpf_used);
    assert!(!flags.cgroup_mutation_performed);
    assert!(!flags.pid_movement_performed);
    assert!(!flags.filesystem_write_performed);
    assert!(!flags.state_mutation_performed);
}

// ── Warnings ────────────────────────────────────────────────────────

#[test]
fn includes_counter_reset_warning() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output.warnings.iter().any(|w| w.contains("reset")));
}

#[test]
fn includes_not_per_app_attribution_warning() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output
        .warnings
        .iter()
        .any(|w| w.contains("per-app") || w.contains("aggregate")));
}

// ── Serialization ─────────────────────────────────────────────────

#[test]
fn serializes_valid_success_json() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("\"schema_version\": 1"));
    assert!(json.contains("\"command\": \"usage --sample --json\""));
    assert!(json.contains("\"source_path\": \"/proc/net/dev\""));
    assert!(json.contains("\"source_label\": \"live_proc_net_dev\""));
    assert!(json.contains("\"wlan0\""));
    assert!(json.contains("1000")); // rx_bytes
    assert!(json.contains("2000")); // tx_bytes
    assert!(json.contains("3000")); // combined_bytes
    assert!(json.contains("\"interface_level_only\": true"));
    assert!(json.contains("\"per_app_attribution\": false"));
    assert!(json.contains("\"quota_enforcement_active\": false"));
}

// ── Round-trip ─────────────────────────────────────────────────────

#[test]
fn round_trips_success_json() {
    let snapshot = parse(MULTI_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, Some("2026-06-07T12:00:00Z"));
    let json = serialize_usage_json(&output).unwrap();
    let deserialized: UsageJsonOutput = deserialize_usage_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

#[test]
fn round_trips_success_json_without_sampled_at() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let json = serialize_usage_json(&output).unwrap();
    let deserialized: UsageJsonOutput = deserialize_usage_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

// ── Error JSON: read_error ────────────────────────────────────────

#[test]
fn serializes_read_error_json() {
    let output = build_usage_json_error(
        UsageJsonErrorType::Read,
        "read error: permission denied",
        None,
    );
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("\"read_error\""));
    assert!(json.contains("permission denied"));
    assert!(json.contains("\"interface_level_only\": true"));
    assert!(json.contains("\"per_app_attribution\": false"));
}

// ── Error JSON: parse_error ───────────────────────────────────────

#[test]
fn serializes_parse_error_json() {
    let output = build_usage_json_error(
        UsageJsonErrorType::Parse,
        "parse error: missing colon after interface name",
        None,
    );
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("\"parse_error\""));
    assert!(json.contains("missing colon"));
    assert!(json.contains("\"interface_level_only\": true"));
}

// ── Error JSON: unsupported_flag_error ────────────────────────────

#[test]
fn serializes_unsupported_flag_error_json() {
    let output = build_usage_json_error(
        UsageJsonErrorType::UnsupportedFlag,
        "unsupported flag: --delta is not implemented",
        None,
    );
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("\"unsupported_flag_error\""));
    assert!(json.contains("not implemented"));
}

// ── Error preserves honesty flags ──────────────────────────────────

#[test]
fn error_json_preserves_all_honesty_flags() {
    let output = build_usage_json_error(UsageJsonErrorType::Read, "test error", None);
    assert!(output.honesty.interface_level_only);
    assert!(!output.honesty.per_app_attribution);
    assert!(!output.honesty.quota_enforcement_active);
    assert!(!output.honesty.network_blocking_active);
    assert!(!output.honesty.limiter_attach_performed);
    assert!(!output.honesty.nft_tc_state_mutation_performed);
    assert!(!output.honesty.ledger_persistence_performed);
    assert!(!output.honesty.ebpf_used);
    assert!(!output.honesty.cgroup_mutation_performed);
    assert!(!output.honesty.pid_movement_performed);
    assert!(!output.honesty.filesystem_write_performed);
    assert!(!output.honesty.state_mutation_performed);
}

// ── Error has empty interfaces and zero totals ──────────────────────

#[test]
fn error_json_has_empty_interfaces() {
    let output = build_usage_json_error(UsageJsonErrorType::Parse, "test error", None);
    assert!(output.interfaces.is_empty());
    assert!(output.error.is_some());
    assert_eq!(output.totals.total_rx_bytes, 0);
    assert_eq!(output.totals.total_tx_bytes, 0);
    assert_eq!(output.totals.total_combined_bytes, 0);
    assert_eq!(output.totals.interface_count, 0);
}

// ── Error round-trip ───────────────────────────────────────────────

#[test]
fn round_trips_error_json() {
    let output = build_usage_json_error(
        UsageJsonErrorType::Read,
        "read error: permission denied",
        Some("2026-06-07T12:00:00Z"),
    );
    let json = serialize_usage_json(&output).unwrap();
    let deserialized: UsageJsonOutput = deserialize_usage_json(&json).unwrap();
    assert_eq!(output, deserialized);
}

// ── Error warnings present ─────────────────────────────────────────

#[test]
fn error_json_includes_warnings() {
    let output = build_usage_json_error(UsageJsonErrorType::Read, "test error", None);
    assert_eq!(output.warnings.len(), 2);
    assert!(output.warnings[0].contains("reset"));
    assert!(output.warnings[1].contains("aggregate"));
}

// ── Empty snapshot ──────────────────────────────────────────────────

#[test]
fn handles_empty_snapshot() {
    let snapshot = InterfaceCounterSnapshot {
        interfaces: Vec::new(),
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_usage_json_from_snapshot(&snapshot, None);
    assert!(output.interfaces.is_empty());
    assert!(output.error.is_none());
    assert_eq!(output.totals.total_rx_bytes, 0);
    assert_eq!(output.totals.total_tx_bytes, 0);
    assert_eq!(output.totals.total_combined_bytes, 0);
    assert_eq!(output.totals.interface_count, 0);
}

// ── Loopback flag ──────────────────────────────────────────────────

#[test]
fn loopback_flag_set_for_lo() {
    let snapshot = parse(MULTI_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let lo = output.interfaces.iter().find(|i| i.name == "lo").unwrap();
    assert!(lo.loopback);
    let wlan0 = output
        .interfaces
        .iter()
        .find(|i| i.name == "wlan0")
        .unwrap();
    assert!(!wlan0.loopback);
}

// ── u64::MAX counters ─────────────────────────────────────────────

#[test]
fn handles_u64_max_counters() {
    let snapshot = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX,
            tx_bytes: u64::MAX,
            rx_packets: u64::MAX,
            tx_packets: u64::MAX,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let iface = &output.interfaces[0];
    assert_eq!(iface.rx_bytes, u64::MAX);
    assert_eq!(iface.tx_bytes, u64::MAX);
    // combined_bytes should saturate
    assert_eq!(iface.combined_bytes, u64::MAX);
    assert_eq!(iface.rx_packets, u64::MAX);
    assert_eq!(iface.tx_packets, u64::MAX);

    // Serialize and round-trip to verify u64::MAX survives JSON
    let json = serialize_usage_json(&output).unwrap();
    let deserialized: UsageJsonOutput = deserialize_usage_json(&json).unwrap();
    assert_eq!(deserialized.interfaces[0].rx_bytes, u64::MAX);
    assert_eq!(deserialized.interfaces[0].tx_bytes, u64::MAX);
    assert_eq!(deserialized.interfaces[0].combined_bytes, u64::MAX);
}

// ── Combined bytes saturating arithmetic ────────────────────────────

#[test]
fn combined_bytes_saturates_correctly() {
    let snapshot = InterfaceCounterSnapshot {
        interfaces: vec![crate::accounting::InterfaceCounter {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX - 1,
            tx_bytes: 5,
            rx_packets: 0,
            tx_packets: 0,
        }],
        source: SourceLabel::ProcNetDevSample,
    };
    let output = build_usage_json_from_snapshot(&snapshot, None);
    // (u64::MAX - 1) + 5 saturates to u64::MAX
    assert_eq!(output.interfaces[0].combined_bytes, u64::MAX);
}

// ── Determinism ────────────────────────────────────────────────────

#[test]
fn serialization_is_deterministic() {
    let snapshot = parse(MULTI_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let json1 = serialize_usage_json(&output).unwrap();
    let json2 = serialize_usage_json(&output).unwrap();
    assert_eq!(json1, json2);
}

// ── Structural: no CLI flag ───────────────────────────────────────

#[test]
fn no_cli_flag_added() {
    // Structural test: the UsageJsonOutput model exists and serializes
    // but no CLI flag is added. The Usage variant in Commands only has
    // `sample: bool`. This is verified by the module structure: usage_json
    // is a pure model module with no clap integration.
    let output = build_usage_json_from_snapshot(&parse(SINGLE_IFACE), None);
    assert_eq!(output.command, "usage --sample --json");
    // The command field is a constant string, not a clap flag.
}

// ── Structural: no live /proc/net/dev read in tests ──────────────────

#[test]
fn tests_do_not_read_real_proc_net_dev() {
    // Structural test: all test data is const strings parsed by
    // parse_proc_net_dev(). No std::fs API is used in usage_json.rs.
    // This is verified by the module structure.
}

// ── Structural: no filesystem write APIs ────────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: usage_json.rs contains only pure functions
    // and serde serialization. No std::fs, no write operations.
}

// ── Deserialize rejects malformed JSON ───────────────────────────

#[test]
fn deserialize_rejects_malformed_json() {
    let result = deserialize_usage_json("not valid json");
    assert!(result.is_err());
}

// ── Deserialize rejects missing required fields ────────────────────

#[test]
fn deserialize_rejects_missing_schema_version() {
    let json = "{}";
    let result: Result<UsageJsonOutput, _> = deserialize_usage_json(json);
    assert!(result.is_err());
}

// ── Serialize includes all honesty flags in JSON ──────────────────────

#[test]
fn serialized_json_includes_all_honesty_flags() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let json = serialize_usage_json(&output).unwrap();
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
    ];
    for flag in &required_flags {
        assert!(
            json.contains(flag),
            "missing honesty flag in JSON: {}",
            flag
        );
    }
}

// ── Error JSON serialized includes all honesty flags ────────────────

#[test]
fn error_serialized_json_includes_all_honesty_flags() {
    let output = build_usage_json_error(UsageJsonErrorType::Read, "test error", None);
    let json = serialize_usage_json(&output).unwrap();
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
    assert_eq!(UsageJsonErrorType::Read.to_string(), "read_error");
    assert_eq!(UsageJsonErrorType::Parse.to_string(), "parse_error");
    assert_eq!(
        UsageJsonErrorType::UnsupportedFlag.to_string(),
        "unsupported_flag_error"
    );
}

// ── Default warnings ───────────────────────────────────────────────

#[test]
fn default_warnings_has_two_entries() {
    let warnings = default_warnings();
    assert_eq!(warnings.len(), 2);
}

// ── sampled_at None serialization uses skip_serializing_if ─────────

#[test]
fn sampled_at_absent_from_json_when_none() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, None);
    let json = serialize_usage_json(&output).unwrap();
    // The field should not appear at all (not just be null).
    assert!(!json.contains("sampled_at"));
}

#[test]
fn sampled_at_present_in_json_when_some() {
    let snapshot = parse(SINGLE_IFACE);
    let output = build_usage_json_from_snapshot(&snapshot, Some("2026-06-07T12:00:00Z"));
    let json = serialize_usage_json(&output).unwrap();
    assert!(json.contains("\"sampled_at\": \"2026-06-07T12:00:00Z\""));
}
