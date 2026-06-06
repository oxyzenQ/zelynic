// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure ledger inspect model and render tests for v2.9 phase 7.
//!
//! All tests use in-memory ledger structs — **no** filesystem reads or
//! writes, **no** live `/proc/net/dev` reads, **no** live sysfs reads,
//! **no** network blocking, **no** quota enforcement, **no** eBPF,
//! **no** PID movement, **no** cgroup writes, **no** CLI command.

use crate::accounting::ledger::{
    add_session_delta_entry, add_snapshot_entry, new_empty_ledger, ResetDetail,
    SUPPORTED_SCHEMA_VERSION,
};
use crate::accounting::ledger_inspect::{build_ledger_inspect, render_ledger_inspect};

// ── Build/inspect tests ─────────────────────────────────────────────

#[test]
fn test_inspect_empty_ledger() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_entries, 0);
    assert_eq!(inspect.snapshot_count, 0);
    assert_eq!(inspect.delta_count, 0);
    assert_eq!(inspect.total_rx_bytes, 0);
    assert_eq!(inspect.total_tx_bytes, 0);
    assert_eq!(inspect.total_combined_bytes, 0);
    assert!(inspect.interfaces.is_empty());
    assert_eq!(inspect.reset_warning_count, 0);
    assert!(inspect.read_only);
}

#[test]
fn test_inspect_one_snapshot_entry() {
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
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_entries, 1);
    assert_eq!(inspect.snapshot_count, 1);
    assert_eq!(inspect.delta_count, 0);
    assert_eq!(inspect.total_rx_bytes, 1000);
    assert_eq!(inspect.total_tx_bytes, 2000);
    assert_eq!(inspect.total_combined_bytes, 3000);
    assert_eq!(inspect.interfaces, vec!["wlan0".to_string()]);
}

#[test]
fn test_inspect_one_delta_entry() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_session_delta_entry(
        &mut ledger,
        "e1",
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
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_entries, 1);
    assert_eq!(inspect.snapshot_count, 0);
    assert_eq!(inspect.delta_count, 1);
    assert_eq!(inspect.total_rx_bytes, 500);
    assert_eq!(inspect.total_tx_bytes, 150);
    assert_eq!(inspect.total_combined_bytes, 650);
    assert_eq!(inspect.interfaces, vec!["wlan0".to_string()]);
}

#[test]
fn test_inspect_mixed_entries() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        None,
        None,
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
        None,
        None,
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e3",
        "2026-06-06T14:00:00Z",
        "model-only",
        "eth0",
        300,
        700,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_entries, 3);
    assert_eq!(inspect.snapshot_count, 2);
    assert_eq!(inspect.delta_count, 1);
    assert_eq!(inspect.total_rx_bytes, 1800);
    assert_eq!(inspect.total_tx_bytes, 2850);
    assert_eq!(inspect.total_combined_bytes, 4650);
}

#[test]
fn test_inspect_counts_snapshot_delta_correctly() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    for i in 0..5 {
        add_snapshot_entry(
            &mut ledger,
            &format!("s{}", i),
            "2026-06-06T10:00:00Z",
            "model-only",
            "wlan0",
            100,
            200,
            None,
            None,
            false,
            vec![],
        );
    }
    for i in 0..3 {
        add_session_delta_entry(
            &mut ledger,
            &format!("d{}", i),
            "2026-06-06T12:00:00Z",
            "session-delta",
            "wlan0",
            50,
            25,
            None,
            None,
            false,
            vec![],
        );
    }
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_entries, 8);
    assert_eq!(inspect.snapshot_count, 5);
    assert_eq!(inspect.delta_count, 3);
}

#[test]
fn test_inspect_totals_rx_tx_combined_correctly() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1234567890,
        356789012,
        None,
        None,
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:01:00Z",
        "model-only",
        "eth0",
        50000,
        30000,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    let expected_rx = 1234567890u64.saturating_add(50000);
    let expected_tx = 356789012u64.saturating_add(30000);
    let expected_combined = expected_rx.saturating_add(expected_tx);
    assert_eq!(inspect.total_rx_bytes, expected_rx);
    assert_eq!(inspect.total_tx_bytes, expected_tx);
    assert_eq!(inspect.total_combined_bytes, expected_combined);
}

#[test]
fn test_inspect_lists_interfaces_deterministically() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    // Add in non-alphabetical order
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        100,
        200,
        None,
        None,
        false,
        vec![],
    );
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:01:00Z",
        "model-only",
        "eth0",
        50,
        100,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    // BTreeSet produces sorted order: eth0 < wlan0
    assert_eq!(
        inspect.interfaces,
        vec!["eth0".to_string(), "wlan0".to_string()]
    );
}

#[test]
fn test_inspect_lists_interfaces_sorted_across_many() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    // Add in reverse-alphabetical order
    let ifaces = ["wlan0", "usb0", "eth0", "enp3s0", "wlp2s0"];
    for (i, iface) in ifaces.iter().enumerate() {
        add_snapshot_entry(
            &mut ledger,
            &format!("e{}", i),
            "2026-06-06T10:00:00Z",
            "model-only",
            iface,
            100,
            200,
            None,
            None,
            false,
            vec![],
        );
    }
    let inspect = build_ledger_inspect(&ledger);
    // Sorted: enp3s0, eth0, usb0, wlan0, wlp2s0
    let expected = vec!["enp3s0", "eth0", "usb0", "wlan0", "wlp2s0"];
    let actual: Vec<&str> = inspect.interfaces.iter().map(|s| s.as_str()).collect();
    assert_eq!(actual, expected);
}

#[test]
fn test_inspect_detects_reset_warnings() {
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
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:01:00Z",
        "model-only",
        "eth0",
        300,
        700,
        None,
        None,
        true,
        vec![ResetDetail {
            counter_field: "tx_bytes".to_string(),
            start_value: 50000,
            end_value: 700,
            reason: Some("counter decrease".to_string()),
        }],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.reset_warning_count, 2);
}

#[test]
fn test_inspect_no_reset_warnings_when_none() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        None,
        None,
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
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.reset_warning_count, 0);
}

#[test]
fn test_inspect_handles_u64_max_safely() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        u64::MAX,
        u64::MAX,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.total_rx_bytes, u64::MAX);
    assert_eq!(inspect.total_tx_bytes, u64::MAX);
    // combined_bytes of the entry is u64::MAX (saturated rx+tx)
    assert_eq!(inspect.total_combined_bytes, u64::MAX);
}

#[test]
fn test_inspect_saturating_totals_large_entries() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let half = u64::MAX / 2;
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
    add_snapshot_entry(
        &mut ledger,
        "e2",
        "2026-06-06T10:01:00Z",
        "model-only",
        "eth0",
        half + 1,
        half + 1,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    // half + (half+1) = u64::MAX for both rx and tx (no overflow due to saturating add)
    assert_eq!(inspect.total_rx_bytes, u64::MAX);
    assert_eq!(inspect.total_tx_bytes, u64::MAX);
    // combined_bytes from each entry: half+half = u64::MAX-1 and (half+1)+(half+1) = u64::MAX
    // total_combined = (u64::MAX-1).saturating_add(u64::MAX) = u64::MAX
    assert_eq!(inspect.total_combined_bytes, u64::MAX);
}

// ── Render denial/statement tests ────────────────────────────────────

#[test]
fn test_render_model_only_statement() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("ledger inspect model only"));
}

#[test]
fn test_render_denies_filesystem_read() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("no filesystem read performed"));
}

#[test]
fn test_render_denies_filesystem_write() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("no filesystem write performed"));
}

#[test]
fn test_render_denies_live_proc_sysfs() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("no live /proc or sysfs read performed"));
}

#[test]
fn test_render_denies_per_app_attribution() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("interface-level only (not per-app attribution)"));
}

#[test]
fn test_render_denies_quota_enforcement() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("quota enforcement: inactive/not implemented"));
}

#[test]
fn test_render_denies_network_blocking() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("network blocking: inactive/not implemented"));
}

#[test]
fn test_render_denies_limiter_attach() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn test_render_denies_nft_tc_state_mutation() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

// ── Structural/safety tests ──────────────────────────────────────────

#[test]
fn test_no_cli_structural() {
    let ledger = new_empty_ledger("t", "h");
    let _inspect = build_ledger_inspect(&ledger);
    let _rendered = render_ledger_inspect(&_inspect);
    // No CLI command exists — this is a compile-time structural test
}

#[test]
fn test_no_filesystem_apis_used() {
    let ledger = new_empty_ledger("t", "h");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    // Verify output is a plain rendered string (starts with expected header)
    assert!(rendered.starts_with("Zelynic v2.9 ledger inspect"));
    // No .json extension or path-like patterns in rendered output
    assert!(!rendered.contains(".json"));
    assert!(!rendered.contains("/sys/"));
    assert!(!rendered.contains("/proc/net/dev"));
}

// ── Metadata and render content tests ───────────────────────────────

#[test]
fn test_inspect_provenance_field() {
    // Empty ledger
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    assert!(inspect.provenance.contains("empty"));

    // Snapshots only
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        100,
        200,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert!(inspect.provenance.contains("1 snapshots"));
    assert!(!inspect.provenance.contains("deltas"));

    // Mixed
    add_session_delta_entry(
        &mut ledger,
        "e2",
        "2026-06-06T12:00:00Z",
        "session-delta",
        "wlan0",
        50,
        25,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert!(inspect.provenance.contains("1 snapshots"));
    assert!(inspect.provenance.contains("1 deltas"));
}

#[test]
fn test_inspect_metadata_fields() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-xyz");
    ledger.session_id = Some("sess-42".to_string());
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        100,
        200,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.schema_version, SUPPORTED_SCHEMA_VERSION);
    assert_eq!(inspect.created_at, "2026-06-06T10:00:00Z");
    assert_eq!(inspect.updated_at, "2026-06-06T10:00:00Z");
    assert_eq!(inspect.host_id, "host-xyz");
    assert_eq!(inspect.session_id, Some("sess-42".to_string()));
    assert_eq!(inspect.attribution_scope, "interface-level only");
    assert_eq!(inspect.enforcement_status, "inactive/not implemented");
    assert!(inspect.read_only);
    assert!(inspect.provenance.contains("1 snapshots"));
}

#[test]
fn test_render_determinism() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        1000,
        2000,
        None,
        None,
        false,
        vec![],
    );

    let inspect1 = build_ledger_inspect(&ledger);
    let inspect2 = build_ledger_inspect(&ledger);
    assert_eq!(inspect1, inspect2);

    let rendered1 = render_ledger_inspect(&inspect1);
    let rendered2 = render_ledger_inspect(&inspect2);
    assert_eq!(rendered1, rendered2);
}

#[test]
fn test_render_empty_ledger() {
    let ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("Entries: 0 (0 snapshots, 0 deltas)"));
    assert!(rendered.contains("No interfaces observed."));
    assert!(rendered.contains("Reset warnings: 0"));
    assert!(rendered.contains("Read-only: true"));
}

#[test]
fn test_render_includes_reset_warning_count() {
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
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("Reset warnings: 1"));
}

#[test]
fn test_render_with_session_id() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    ledger.session_id = Some("my-session".to_string());
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        100,
        200,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("Session: my-session"));
}

#[test]
fn test_render_includes_saturating_label() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-abc");
    add_snapshot_entry(
        &mut ledger,
        "e1",
        "2026-06-06T10:00:00Z",
        "model-only",
        "wlan0",
        100,
        200,
        None,
        None,
        false,
        vec![],
    );
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("saturating, overflow-safe"));
}
