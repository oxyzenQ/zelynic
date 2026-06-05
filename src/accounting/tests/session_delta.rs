// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure tests for v2.9 Network Accounting Lab session delta model.
//!
//! All tests use constructed snapshots — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes.

use crate::accounting::interface_counters::*;
use crate::accounting::session_delta::*;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Helper to create a snapshot from interface counter values.
fn make_snapshot(interfaces: Vec<InterfaceCounter>) -> InterfaceCounterSnapshot {
    InterfaceCounterSnapshot {
        interfaces,
        source: SourceLabel::ProcNetDevSample,
    }
}

/// Helper to construct a single interface counter.
fn make_counter(
    interface: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
) -> InterfaceCounter {
    InterfaceCounter {
        interface: interface.to_string(),
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
    }
}

// ── computes delta for one interface ──────────────────────────────────────────

#[test]
fn delta_one_interface_normal() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 1);
    assert_eq!(delta.rows[0].rx_delta_bytes, 4000);
    assert_eq!(delta.rows[0].tx_delta_bytes, 5000);
    assert_eq!(delta.rows[0].combined_delta_bytes, 9000);
    assert_eq!(delta.rows[0].rx_delta_packets, 40);
    assert_eq!(delta.rows[0].tx_delta_packets, 50);
    assert!(!delta.rows[0].rx_reset);
    assert!(!delta.rows[0].tx_reset);
}

// ── computes delta for multiple interfaces ────────────────────────────────────

#[test]
fn delta_multiple_interfaces() {
    let start = make_snapshot(vec![
        make_counter("wlan0", 1000, 2000, 10, 20),
        make_counter("eth0", 500, 600, 5, 6),
    ]);
    let end = make_snapshot(vec![
        make_counter("wlan0", 5000, 7000, 50, 70),
        make_counter("eth0", 1500, 2600, 15, 26),
    ]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 2);
    assert_eq!(delta.rows[0].interface, "wlan0");
    assert_eq!(delta.rows[0].rx_delta_bytes, 4000);
    assert_eq!(delta.rows[1].interface, "eth0");
    assert_eq!(delta.rows[1].rx_delta_bytes, 1000);
    assert_eq!(delta.rows[1].tx_delta_bytes, 2000);
}

// ── totals rx/tx/combined correctly ────────────────────────────────────────────

#[test]
fn delta_totals_correct() {
    let start = make_snapshot(vec![
        make_counter("wlan0", 1000, 2000, 10, 20),
        make_counter("eth0", 500, 600, 5, 6),
    ]);
    let end = make_snapshot(vec![
        make_counter("wlan0", 5000, 7000, 50, 70),
        make_counter("eth0", 1500, 2600, 15, 26),
    ]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.total_rx_delta_bytes, 4000 + 1000);
    assert_eq!(delta.total_tx_delta_bytes, 5000 + 2000);
    assert_eq!(delta.total_combined_delta_bytes, 9000 + 3000);
}

// ── handles zero delta ───────────────────────────────────────────────────────

#[test]
fn delta_zero_when_same() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    assert_eq!(delta.rows[0].tx_delta_bytes, 0);
    assert_eq!(delta.rows[0].combined_delta_bytes, 0);
    assert!(!delta.rows[0].rx_reset);
    assert!(!delta.rows[0].tx_reset);
    assert!(delta.warnings.is_empty());
}

// ── handles interface present only in end ────────────────────────────────────

#[test]
fn delta_interface_only_in_end() {
    let start = make_snapshot(vec![]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 1);
    assert_eq!(delta.rows[0].interface, "wlan0");
    assert!(!delta.rows[0].present_in_start);
    assert!(delta.rows[0].present_in_end);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    assert_eq!(delta.rows[0].tx_delta_bytes, 0);
}

// ── handles interface present only in start ───────────────────────────────────

#[test]
fn delta_interface_only_in_start() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 1);
    assert_eq!(delta.rows[0].interface, "wlan0");
    assert!(delta.rows[0].present_in_start);
    assert!(!delta.rows[0].present_in_end);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    assert_eq!(delta.rows[0].tx_delta_bytes, 0);
}

// ── detects rx counter decrease/reset ────────────────────────────────────────

#[test]
fn delta_detects_rx_counter_reset() {
    let start = make_snapshot(vec![make_counter("wlan0", 5000, 2000, 50, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 1000, 3000, 10, 30)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.rows[0].rx_reset);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    // TX should be normal
    assert_eq!(delta.rows[0].tx_delta_bytes, 1000);
    assert!(!delta.rows[0].tx_reset);
    // Warning present
    assert!(delta
        .warnings
        .iter()
        .any(|w| w.counter_field == "rx_bytes" && w.interface == "wlan0"));
}

// ── detects tx counter decrease/reset ────────────────────────────────────────

#[test]
fn delta_detects_tx_counter_reset() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 7000, 10, 70)]);
    let end = make_snapshot(vec![make_counter("wlan0", 2000, 3000, 20, 30)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.rows[0].tx_reset);
    assert_eq!(delta.rows[0].tx_delta_bytes, 0);
    // RX should be normal
    assert_eq!(delta.rows[0].rx_delta_bytes, 1000);
    assert!(!delta.rows[0].rx_reset);
    assert!(delta
        .warnings
        .iter()
        .any(|w| w.counter_field == "tx_bytes" && w.interface == "wlan0"));
}

// ── detects packet counter decrease/reset ────────────────────────────────────

#[test]
fn delta_detects_rx_packet_counter_reset() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 100, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 2000, 3000, 10, 30)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.rows[0].rx_packets_reset);
    assert_eq!(delta.rows[0].rx_delta_packets, 0);
    assert!(delta
        .warnings
        .iter()
        .any(|w| w.counter_field == "rx_packets" && w.interface == "wlan0"));
}

#[test]
fn delta_detects_tx_packet_counter_reset() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 200)]);
    let end = make_snapshot(vec![make_counter("wlan0", 2000, 3000, 20, 30)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.rows[0].tx_packets_reset);
    assert_eq!(delta.rows[0].tx_delta_packets, 0);
    assert!(delta
        .warnings
        .iter()
        .any(|w| w.counter_field == "tx_packets" && w.interface == "wlan0"));
}

// ── does not silently underflow ──────────────────────────────────────────────

#[test]
fn delta_no_silent_underflow() {
    // RX: start=100, end=50 -> should be 0 with reset, NOT wrap to u64::MAX
    let start = make_snapshot(vec![make_counter("wlan0", 100, 200, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 50, 300, 5, 30)]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    assert!(delta.rows[0].rx_reset);
    // Must not produce wrapped/negative value
    assert!(delta.rows[0].rx_delta_bytes < start.interfaces[0].rx_bytes);
}

// ── deterministic output order ───────────────────────────────────────────────

#[test]
fn delta_deterministic_order() {
    let start = make_snapshot(vec![
        make_counter("wlan0", 1000, 2000, 10, 20),
        make_counter("eth0", 500, 600, 5, 6),
    ]);
    let end = make_snapshot(vec![
        make_counter("eth0", 1500, 2600, 15, 26),
        make_counter("wlan0", 5000, 7000, 50, 70),
    ]);
    let a = build_session_delta(&start, &end);
    let b = build_session_delta(&start, &end);
    assert_eq!(a, b);
    // Start interfaces come first in their original order
    assert_eq!(a.rows[0].interface, "wlan0");
    assert_eq!(a.rows[1].interface, "eth0");
}

// ── render includes read-only/model-only line ────────────────────────────────

#[test]
fn render_includes_read_only_model_only() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("read-only session delta model"));
    assert!(rendered.contains("model-only"));
}

// ── render denies per-app attribution ───────────────────────────────────────

#[test]
fn render_denies_per_app_attribution() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("not per-app attribution"));
    assert!(rendered.contains("interface-level only"));
}

// ── render denies quota enforcement ──────────────────────────────────────────

#[test]
fn render_denies_quota_enforcement() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("no quota enforcement active"));
}

// ── render denies network blocking ──────────────────────────────────────────

#[test]
fn render_denies_network_blocking() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("no network blocking active"));
}

// ── render denies limiter attach ─────────────────────────────────────────────

#[test]
fn render_denies_limiter_attach() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("no limiter attach performed"));
}

// ── render denies nft/tc/state mutation ─────────────────────────────────────

#[test]
fn render_denies_nft_tc_state_mutation() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

// ── render denies live /proc/sysfs read ──────────────────────────────────────

#[test]
fn render_denies_live_proc_sysfs_read() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("no live /proc or sysfs read performed"));
}

// ── render includes reset/decrease warnings ──────────────────────────────────

#[test]
fn render_includes_reset_warnings() {
    let start = make_snapshot(vec![make_counter("wlan0", 5000, 2000, 50, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 1000, 3000, 10, 30)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("counter reset"));
    assert!(rendered.contains("rx_bytes"));
    assert!(rendered.contains("exact usage unknown"));
}

// ── overflow-safe total behavior ────────────────────────────────────────────

#[test]
fn delta_overflow_safe_totals() {
    // Both start and end at u64::MAX: delta = 0 (no reset since end >= start)
    let start = make_snapshot(vec![make_counter(
        "wlan0",
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    )]);
    let end = make_snapshot(vec![make_counter(
        "wlan0",
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    )]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.rows[0].rx_delta_bytes, 0);
    assert_eq!(delta.total_rx_delta_bytes, 0);
    // No panic
}

#[test]
fn delta_saturating_totals_no_panic() {
    // Large deltas that would overflow if added with non-saturating arithmetic.
    let start = make_snapshot(vec![
        make_counter("wlan0", 0, 0, 0, 0),
        make_counter("eth0", 0, 0, 0, 0),
    ]);
    let end = make_snapshot(vec![
        make_counter("wlan0", u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        make_counter("eth0", u64::MAX, u64::MAX, u64::MAX, u64::MAX),
    ]);
    let delta = build_session_delta(&start, &end);
    // Saturating: u64::MAX + u64::MAX = u64::MAX
    assert_eq!(delta.total_rx_delta_bytes, u64::MAX);
    assert_eq!(delta.total_tx_delta_bytes, u64::MAX);
    assert_eq!(delta.total_combined_delta_bytes, u64::MAX);
    // No panic during total computation
}

// ── no CLI command is added (structural test) ───────────────────────────────

#[test]
fn session_delta_model_has_no_cli_fields() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    // Verify model fields: no cmd, no cli, no enforcement_trigger, etc.
    assert_eq!(delta.attribution_scope, "interface-level only");
    assert_eq!(delta.enforcement_status, "inactive/not implemented");
    assert_eq!(delta.read_only, "model-only");
    // The struct has no CLI-related fields - enforced by compilation.
}

// ── empty snapshots ──────────────────────────────────────────────────────────

#[test]
fn delta_both_empty() {
    let start = make_snapshot(vec![]);
    let end = make_snapshot(vec![]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 0);
    assert!(delta.rows.is_empty());
    assert!(delta.warnings.is_empty());
    assert_eq!(delta.total_rx_delta_bytes, 0);
    assert_eq!(delta.total_tx_delta_bytes, 0);
    assert_eq!(delta.total_combined_delta_bytes, 0);
}

// ── source label ────────────────────────────────────────────────────────────

#[test]
fn delta_source_label() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.source_label.contains("session_delta"));
    assert!(delta.source_label.contains("proc_net_dev_sample"));
}

// ── render determinism ──────────────────────────────────────────────────────

#[test]
fn render_is_deterministic() {
    let start = make_snapshot(vec![
        make_counter("wlan0", 1000, 2000, 10, 20),
        make_counter("eth0", 500, 600, 5, 6),
    ]);
    let end = make_snapshot(vec![
        make_counter("wlan0", 5000, 7000, 50, 70),
        make_counter("eth0", 1500, 2600, 15, 26),
    ]);
    let delta = build_session_delta(&start, &end);
    let a = render_session_delta(&delta);
    let b = render_session_delta(&delta);
    assert_eq!(a, b);
}

// ── render empty delta ───────────────────────────────────────────────────────

#[test]
fn render_empty_delta() {
    let start = make_snapshot(vec![]);
    let end = make_snapshot(vec![]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("No interface deltas computed"));
    assert!(rendered.contains("read-only session delta model"));
}

// ── multiple resets on same interface ───────────────────────────────────────

#[test]
fn delta_multiple_resets_same_interface() {
    let start = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 100, 200)]);
    let end = make_snapshot(vec![make_counter("wlan0", 1000, 3000, 10, 30)]);
    let delta = build_session_delta(&start, &end);
    assert!(delta.rows[0].rx_reset);
    assert!(delta.rows[0].tx_reset);
    assert!(delta.rows[0].rx_packets_reset);
    assert!(delta.rows[0].tx_packets_reset);
    assert_eq!(delta.warnings.len(), 4);
}

// ── end-only interface in union ──────────────────────────────────────────────

#[test]
fn delta_end_only_interface_appears_after_start_interfaces() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![
        make_counter("wlan0", 2000, 3000, 20, 30),
        make_counter("eth0", 500, 600, 5, 6),
    ]);
    let delta = build_session_delta(&start, &end);
    assert_eq!(delta.interface_count, 2);
    assert_eq!(delta.rows[0].interface, "wlan0");
    assert!(delta.rows[0].present_in_start);
    assert!(delta.rows[0].present_in_end);
    assert_eq!(delta.rows[1].interface, "eth0");
    assert!(!delta.rows[1].present_in_start);
    assert!(delta.rows[1].present_in_end);
}

// ── warning display formatting ───────────────────────────────────────────────

#[test]
fn warning_display_contains_details() {
    let w = CounterResetWarning {
        interface: "wlan0".to_string(),
        counter_field: "rx_bytes".to_string(),
        start_value: 5000,
        end_value: 1000,
    };
    let display = format!("{}", w);
    assert!(display.contains("wlan0"));
    assert!(display.contains("rx_bytes"));
    assert!(display.contains("5000"));
    assert!(display.contains("1000"));
    assert!(display.contains("exact usage unknown"));
}

// ── render source label present ──────────────────────────────────────────────

#[test]
fn render_contains_source_label() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("session_delta(start="));
}

// ── render includes saturating label ────────────────────────────────────────

#[test]
fn render_includes_saturating_label() {
    let start = make_snapshot(vec![make_counter("wlan0", 1000, 2000, 10, 20)]);
    let end = make_snapshot(vec![make_counter("wlan0", 5000, 7000, 50, 70)]);
    let delta = build_session_delta(&start, &end);
    let rendered = render_session_delta(&delta);
    assert!(rendered.contains("saturating"));
    assert!(rendered.contains("overflow-safe"));
}

// ── combined_delta_bytes uses saturating add ──────────────────────────────────

#[test]
fn combined_delta_bytes_saturating() {
    let start = make_snapshot(vec![make_counter("wlan0", 0, 0, 0, 0)]);
    let end = make_snapshot(vec![make_counter("wlan0", u64::MAX, u64::MAX, 0, 0)]);
    let delta = build_session_delta(&start, &end);
    // u64::MAX + u64::MAX = u64::MAX (saturated)
    assert_eq!(delta.rows[0].combined_delta_bytes, u64::MAX);
}
