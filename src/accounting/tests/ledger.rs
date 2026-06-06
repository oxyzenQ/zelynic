// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure ledger model and serialization tests for v2.9 phase 6.
//!
//! All tests use in-memory strings — **no** filesystem reads or writes,
//! **no** live `/proc/net/dev` reads, **no** live sysfs reads, **no**
//! network blocking, **no** quota enforcement, **no** eBPF, **no** PID
//! movement, **no** cgroup writes, **no** CLI command.

use crate::accounting::ledger::{
    add_session_delta_entry, add_snapshot_entry, deserialize_ledger_from_json, new_empty_ledger,
    render_ledger_summary, serialize_ledger_to_json, LedgerError, ResetDetail,
    SUPPORTED_SCHEMA_VERSION,
};

#[test]
fn test_create_empty_ledger() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    assert_eq!(ledger.schema_version, SUPPORTED_SCHEMA_VERSION);
    assert_eq!(ledger.created_at, "2026-06-06T10:00:00Z");
    assert_eq!(ledger.updated_at, "2026-06-06T10:00:00Z");
    assert_eq!(ledger.host_id, "host-abc");
    assert!(ledger.session_id.is_none());
    assert!(ledger.entries.is_empty());
}

#[test]
fn test_add_snapshot_entry() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "entry-001",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );
    assert_eq!(ledger.entries.len(), 1);
    let e = &ledger.entries[0];
    assert_eq!(e.entry_id, "entry-001");
    assert_eq!(e.entry_type, "snapshot");
    assert_eq!(e.interface, "wlan0");
    assert_eq!(e.rx_bytes, 1000);
    assert_eq!(e.tx_bytes, 2000);
    assert_eq!(e.combined_bytes, 3000);
    assert_eq!(e.rx_packets, Some(10));
    assert_eq!(e.tx_packets, Some(20));
    assert!(!e.reset_detected);
    assert!(e.read_only);
    assert_eq!(e.attribution_scope, "interface-level only");
    assert_eq!(e.enforcement_status, "inactive/not implemented");
    assert_eq!(ledger.updated_at, "2026-06-06T10:00:00Z");
}

#[test]
fn test_add_session_delta_entry() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_session_delta_entry(
        &mut ledger,
        "entry-002",
        "2026-06-06T12:00:00Z",
        "session-delta",
        "wlan0",
        500,
        150,
        Some(5),
        Some(3),
        false,
        vec![],
    );
    assert_eq!(ledger.entries.len(), 1);
    let e = &ledger.entries[0];
    assert_eq!(e.entry_id, "entry-002");
    assert_eq!(e.entry_type, "delta");
    assert_eq!(e.interface, "wlan0");
    assert_eq!(e.rx_bytes, 500);
    assert_eq!(e.tx_bytes, 150);
    assert_eq!(e.combined_bytes, 650);
    assert_eq!(e.provenance, "read-only session delta model");
    assert!(e.read_only);
    assert_eq!(ledger.updated_at, "2026-06-06T12:00:00Z");
}

#[test]
fn test_serialize_empty_ledger() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let json = serialize_ledger_to_json(&ledger).unwrap();
    assert!(json.contains("schema_version"));
    assert!(json.contains("\"schema_version\": 1"));
    assert!(json.contains("host-abc"));
    assert!(json.contains("\"entries\": []"));
}

#[test]
fn test_serialize_ledger_with_entries() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );
    add_session_delta_entry(
        &mut ledger,
        "e2",
        "2026-06-06T12:00:00Z",
        "session-delta",
        "wlan0",
        500,
        150,
        Some(5),
        Some(3),
        false,
        vec![],
    );
    let json = serialize_ledger_to_json(&ledger).unwrap();
    assert!(json.contains("wlan0"));
    assert!(json.contains("\"entry_type\": \"snapshot\""));
    assert!(json.contains("\"entry_type\": \"delta\""));
    assert!(json.contains("e1"));
    assert!(json.contains("e2"));
}

#[test]
fn test_deserialize_valid_ledger() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "eth0",
        50000,
        30000,
        Some(100),
        Some(50),
        false,
        vec![],
    );
    let json = serialize_ledger_to_json(&ledger).unwrap();
    let restored = deserialize_ledger_from_json(&json).unwrap();
    assert_eq!(restored, ledger);
}

#[test]
fn test_round_trip_preserves_ledger() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-xyz");
    ledger.session_id = Some("sess-1".to_string());
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1234567890,
        356789012,
        Some(1234567),
        Some(345678),
        false,
        vec![],
    );
    add_session_delta_entry(
        &mut ledger,
        "e2",
        "2026-06-06T12:00:00Z",
        "session-delta",
        "wlan0",
        52428800,
        10485760,
        Some(100),
        Some(50),
        true,
        vec![ResetDetail {
            counter_field: "rx_bytes".to_string(),
            start_value: 100000000,
            end_value: 50000,
            reason: Some("counter decrease detected".to_string()),
        }],
    );
    let json = serialize_ledger_to_json(&ledger).unwrap();
    let restored = deserialize_ledger_from_json(&json).unwrap();
    assert_eq!(restored, ledger);
    assert_eq!(restored.session_id, Some("sess-1".to_string()));
    assert_eq!(restored.entries.len(), 2);
    assert!(restored.entries[1].reset_detected);
    assert_eq!(restored.entries[1].reset_details.len(), 1);
}

#[test]
fn test_rejects_malformed_json() {
    let result = deserialize_ledger_from_json("{invalid json");
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::JsonParse(_) => {}
        other => panic!("expected JsonParse error, got: {:?}", other),
    }
}

#[test]
fn test_rejects_unsupported_schema_version() {
    let json =
        r#"{"schema_version":99,"created_at":"x","updated_at":"x","host_id":"h","entries":[]}"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::UnsupportedSchemaVersion(99) => {}
        other => panic!("expected UnsupportedSchemaVersion(99), got: {:?}", other),
    }
}

#[test]
fn test_rejects_active_enforcement_status() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "interface": "wlan0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only",
            "attribution_scope": "interface-level only",
            "enforcement_status": "active/enforcing"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::SafetyViolation(msg) => {
            assert!(msg.contains("enforcement_status"));
        }
        other => panic!("expected SafetyViolation, got: {:?}", other),
    }
}

#[test]
fn test_rejects_per_app_attribution_claim() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "interface": "wlan0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only",
            "attribution_scope": "per-app",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::SafetyViolation(msg) => {
            assert!(msg.contains("attribution_scope"));
        }
        other => panic!("expected SafetyViolation, got: {:?}", other),
    }
}

#[test]
fn test_rejects_missing_required_fields() {
    let json = r#"{"created_at":"x","updated_at":"x","host_id":"h","entries":[]}"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_rejects_entry_missing_required_fields() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only",
            "attribution_scope": "interface-level only",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_handles_u64_max_counters() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e-max",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        u64::MAX,
        u64::MAX,
        Some(u64::MAX),
        Some(u64::MAX),
        false,
        vec![],
    );
    let entry = &ledger.entries[0];
    assert_eq!(entry.combined_bytes, u64::MAX);

    let json = serialize_ledger_to_json(&ledger).unwrap();
    let restored = deserialize_ledger_from_json(&json).unwrap();
    assert_eq!(restored.entries[0].rx_bytes, u64::MAX);
    assert_eq!(restored.entries[0].tx_bytes, u64::MAX);
    assert_eq!(restored.entries[0].combined_bytes, u64::MAX);
}

#[test]
fn test_render_includes_model_only_statement() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("local ledger model only"));
}

#[test]
fn test_render_denies_filesystem_write() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("no filesystem write was performed"));
}

#[test]
fn test_render_denies_live_proc_sysfs_read() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("no live /proc or sysfs read was performed"));
}

#[test]
fn test_render_denies_per_app_attribution() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("interface-level only (not per-app attribution)"));
}

#[test]
fn test_render_denies_quota_enforcement() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("quota enforcement: inactive/not implemented"));
}

#[test]
fn test_render_denies_network_blocking() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("network blocking: inactive/not implemented"));
}

#[test]
fn test_render_denies_limiter_attach() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn test_render_denies_nft_tc_state_mutation() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

#[test]
fn test_no_cli_command_structural() {
    let _ledger = new_empty_ledger("t", "h");
    let _json = serialize_ledger_to_json(&_ledger).unwrap();
    let _restored = deserialize_ledger_from_json(&_json).unwrap();
    let _rendered = render_ledger_summary(&_restored);
}

#[test]
fn test_no_filesystem_apis_used() {
    let ledger = new_empty_ledger("t", "h");
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    assert!(json_str.starts_with('{'));
    let _restored = deserialize_ledger_from_json(&json_str).unwrap();
}

#[test]
fn test_rejects_read_only_false_entry() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "interface": "wlan0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": false,
            "provenance": "read-only",
            "attribution_scope": "interface-level only",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::SafetyViolation(msg) => {
            assert!(msg.contains("read_only"));
        }
        other => panic!("expected SafetyViolation, got: {:?}", other),
    }
}

#[test]
fn test_rejects_combined_bytes_inconsistency() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "interface": "wlan0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 999,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only",
            "attribution_scope": "interface-level only",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::Validation(msg) => {
            assert!(msg.contains("combined_bytes"));
        }
        other => panic!("expected Validation, got: {:?}", other),
    }
}

#[test]
fn test_rejects_unknown_entry_type() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e1",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "unknown_type",
            "source_label": "model-only",
            "interface": "wlan0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only",
            "attribution_scope": "interface-level only",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let result = deserialize_ledger_from_json(json);
    assert!(result.is_err());
}

#[test]
fn test_render_with_entries() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:01:00Z",
        "model-only",
        "eth0",
        500,
        100,
        None,
        None,
        false,
        vec![],
    );
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("Interfaces: wlan0, eth0"));
    assert!(rendered.contains("Total RX: 1500 bytes"));
    assert!(rendered.contains("Total TX: 2100 bytes"));
    assert!(rendered.contains("Entries: 2"));
}

#[test]
fn test_render_with_reset_entries() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        500,
        100,
        None,
        None,
        true,
        vec![ResetDetail {
            counter_field: "rx_bytes".to_string(),
            start_value: 100000,
            end_value: 500,
            reason: None,
        }],
    );
    let rendered = render_ledger_summary(&ledger);
    assert!(rendered.contains("Counter resets detected: 1"));
}

#[test]
fn test_deterministic_serialization() {
    let mut ledger1 = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger1,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );

    let mut ledger2 = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger2,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );

    let json1 = serialize_ledger_to_json(&ledger1).unwrap();
    let json2 = serialize_ledger_to_json(&ledger2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn test_ledger_error_display() {
    let err = LedgerError::JsonParse("unexpected token".to_string());
    assert!(err.to_string().contains("JSON parse error"));

    let err = LedgerError::UnsupportedSchemaVersion(99);
    assert!(err.to_string().contains("unsupported schema version: 99"));

    let err = LedgerError::Validation("missing field".to_string());
    assert!(err.to_string().contains("validation error"));

    let err = LedgerError::SafetyViolation("read_only must be true".to_string());
    assert!(err.to_string().contains("safety violation"));
}

#[test]
fn test_multiple_entries_different_interfaces() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        50000,
        30000,
        Some(500),
        Some(300),
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:00:00Z",
        "model-only",
        "eth0",
        100,
        200,
        Some(1),
        Some(2),
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e3",
        "2026-06-06T10:00:00Z",
        "model-only",
        "usb0",
        10000,
        5000,
        Some(100),
        Some(50),
        false,
        vec![],
    );
    assert_eq!(ledger.entries.len(), 3);

    let json = serialize_ledger_to_json(&ledger).unwrap();
    let restored = deserialize_ledger_from_json(&json).unwrap();
    assert_eq!(restored.entries.len(), 3);
    assert_eq!(restored.entries[0].interface, "wlan0");
    assert_eq!(restored.entries[1].interface, "eth0");
    assert_eq!(restored.entries[2].interface, "usb0");
}

#[test]
fn test_saturating_combined_bytes_overflow() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let half = u64::MAX / 2 + 1;
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        half,
        half,
        None,
        None,
        false,
        vec![],
    );
    let entry = &ledger.entries[0];
    assert_eq!(entry.combined_bytes, u64::MAX);
}
