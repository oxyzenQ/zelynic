// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for the pure delta output model and renderer (v3.0 phase 10).
//!
//! All tests use in-memory `SessionDelta` values built from injected content.
//! No live `/proc/net/dev` reads, no live sysfs reads, no filesystem access,
//! no network blocking, no quota enforcement, no eBPF, no PID movement,
//! no cgroup writes.

use crate::accounting::interface_counters::parse_proc_net_dev;
use crate::accounting::session_delta::{build_session_delta, SessionDelta};
use crate::accounting::usage_delta::{
    build_usage_delta_from_session_delta, render_usage_delta, UsageDeltaOutput,
};

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

/// Build a simple session delta from two sample strings.
fn make_session_delta(start_content: &str, end_content: &str) -> SessionDelta {
    let start = parse_proc_net_dev(start_content).expect("start parse should succeed");
    let end = parse_proc_net_dev(end_content).expect("end parse should succeed");
    build_session_delta(&start, &end)
}

// ── Build delta output from simple session_delta ──────────────────

#[test]
fn builds_delta_output_from_simple_session_delta() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    assert_eq!(output.rows.len(), 2);
    assert_eq!(output.interface_count, 2);
    assert_eq!(output.total_rx_delta_bytes, 1_000_000 + 100_000);
    assert_eq!(output.total_tx_delta_bytes, 500_000 + 100_000);
    assert_eq!(
        output.total_combined_delta_bytes,
        (1_000_000 + 100_000) + (500_000 + 100_000)
    );
    assert_eq!(output.warning_count, 0);
    assert!(output.warnings.is_empty());
}

// ── Totals rx/tx/combined correctly ────────────────────────────────

#[test]
fn totals_rx_tx_combined_correctly() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);

    // wlan0: rx=1000000, tx=500000 → combined=1500000
    // eth0: rx=100000, tx=100000 → combined=200000
    assert_eq!(output.rows[0].rx_delta_bytes, 1_000_000);
    assert_eq!(output.rows[0].tx_delta_bytes, 500_000);
    assert_eq!(output.rows[0].combined_delta_bytes, 1_500_000);
    assert_eq!(output.rows[1].rx_delta_bytes, 100_000);
    assert_eq!(output.rows[1].tx_delta_bytes, 100_000);
    assert_eq!(output.rows[1].combined_delta_bytes, 200_000);

    assert_eq!(output.total_rx_delta_bytes, 1_100_000);
    assert_eq!(output.total_tx_delta_bytes, 600_000);
    assert_eq!(output.total_combined_delta_bytes, 1_700_000);
}

// ── Handles empty delta ────────────────────────────────────────────

#[test]
fn handles_empty_delta() {
    let start = parse_proc_net_dev("").expect("empty parse should succeed");
    let end = parse_proc_net_dev("").expect("empty parse should succeed");
    let delta = build_session_delta(&start, &end);
    let output = build_usage_delta_from_session_delta(&delta);

    assert_eq!(output.rows.len(), 0);
    assert_eq!(output.interface_count, 0);
    assert_eq!(output.total_rx_delta_bytes, 0);
    assert_eq!(output.total_tx_delta_bytes, 0);
    assert_eq!(output.total_combined_delta_bytes, 0);
    assert_eq!(output.warning_count, 0);
}

// ── Handles interface added ─────────────────────────────────────────

#[test]
fn handles_interface_added() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_ADDED_INTERFACE);
    let output = build_usage_delta_from_session_delta(&delta);

    // Should have 3 interfaces: wlan0, eth0 (from start), wlan1 (end-only)
    assert_eq!(output.interface_count, 3);
    assert_eq!(output.rows.len(), 3);

    // wlan1 is end-only, so all deltas = 0
    let wlan1 = output.rows.iter().find(|r| r.interface == "wlan1").unwrap();
    assert_eq!(wlan1.rx_delta_bytes, 0);
    assert_eq!(wlan1.tx_delta_bytes, 0);
    assert_eq!(wlan1.combined_delta_bytes, 0);
}

// ── Handles interface removed ──────────────────────────────────────

#[test]
fn handles_interface_removed() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_REMOVED_INTERFACE);
    let output = build_usage_delta_from_session_delta(&delta);

    // Should have 2 interfaces: wlan0, eth0 (from start), eth0 is end-missing
    assert_eq!(output.interface_count, 2);

    // eth0 is start-only, so all deltas = 0
    let eth0 = output.rows.iter().find(|r| r.interface == "eth0").unwrap();
    assert_eq!(eth0.rx_delta_bytes, 0);
    assert_eq!(eth0.tx_delta_bytes, 0);
    assert_eq!(eth0.combined_delta_bytes, 0);
}

// ── Handles counter reset/decrease warnings ─────────────────────────

#[test]
fn handles_counter_reset_warnings() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_RESET);
    let output = build_usage_delta_from_session_delta(&delta);

    // wlan0 RX decreased: 1000000 → 500000 → reset detected
    assert!(output.warning_count > 0);
    assert!(!output.warnings.is_empty());

    // Check that a warning exists for wlan0 rx_bytes
    let has_rx_warning = output
        .warnings
        .iter()
        .any(|w| w.interface == "wlan0" && w.counter_field == "rx_bytes");
    assert!(has_rx_warning, "expected rx_bytes reset warning for wlan0");

    // wlan0 RX delta should be 0 (reset)
    let wlan0 = output.rows.iter().find(|r| r.interface == "wlan0").unwrap();
    assert_eq!(wlan0.rx_delta_bytes, 0);
    assert!(wlan0.has_reset);
}

// ── Render includes future-model-only statement ────────────────────

#[test]
fn render_includes_future_model_only_statement() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("future delta output model only"));
}

// ── Render says CLI flag not enabled yet ────────────────────────────

#[test]
fn render_says_cli_flag_not_enabled_yet() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no CLI flag enabled yet"));
}

// ── Render says no live second sample was taken by this model ───────

#[test]
fn render_says_no_live_second_sample_taken() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no live second sample was taken by this model"));
}

// ── Render denies per-app attribution ───────────────────────────────

#[test]
fn render_denies_per_app_attribution() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("not per-app attribution"));
}

// ── Render denies quota enforcement ────────────────────────────────

#[test]
fn render_denies_quota_enforcement() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no quota enforcement active"));
}

// ── Render denies network blocking ─────────────────────────────────

#[test]
fn render_denies_network_blocking() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no network blocking active"));
}

// ── Render denies limiter attach ───────────────────────────────────

#[test]
fn render_denies_limiter_attach() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no limiter attach performed"));
}

// ── Render denies nft/tc/state mutation ─────────────────────────────

#[test]
fn render_denies_nft_tc_state_mutation() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

// ── Render denies ledger persistence ──────────────────────────────

#[test]
fn render_denies_ledger_persistence() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no ledger persistence performed"));
}

// ── Render denies eBPF ──────────────────────────────────────────────

#[test]
fn render_denies_ebpf() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no eBPF used"));
}

// ── Render denies cgroup mutation ─────────────────────────────────

#[test]
fn render_denies_cgroup_mutation() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no cgroup mutation performed"));
}

// ── Render denies PID movement ──────────────────────────────────────

#[test]
fn render_denies_pid_movement() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("no PID movement performed"));
}

// ── Render denies filesystem write ─────────────────────────────────

#[test]
fn render_denies_filesystem_write() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("filesystem write not performed"));
}

// ── Render denies state mutation ───────────────────────────────────

#[test]
fn render_denies_state_mutation() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("state mutation not performed"));
}

// ── No CLI flag is added (structural test) ──────────────────────────

#[test]
fn no_delta_cli_flag_is_added() {
    // Structural test: the UsageDeltaOutput and UsageDeltaRow types exist,
    // but no --delta flag is registered in the CLI.
    // This is verified by the CLI structure: Usage { sample: bool, json: bool }
    // has no delta field.
    let _output = UsageDeltaOutput {
        schema_source_label: "test".to_string(),
        start_source_label: "test".to_string(),
        end_source_label: "test".to_string(),
        rows: Vec::new(),
        total_rx_delta_bytes: 0,
        total_tx_delta_bytes: 0,
        total_combined_delta_bytes: 0,
        interface_count: 0,
        warnings: Vec::new(),
        warning_count: 0,
    };
    // If this compiles, the types exist. CLI flag absence is verified
    // by the no_delta_interval_interface_flags_on_usage_command test
    // in src/commands/usage.rs.
}

// ── No live /proc read in tests (structural) ────────────────────────

#[test]
fn no_live_proc_read_in_tests() {
    // Structural test: all test data uses const strings, not live reads.
    // No std::fs::read_to_string("/proc/net/dev") in this test module.
    // This test exists to document the constraint.
    let _start = START_SAMPLE;
    let _end = END_SAMPLE_NORMAL;
    // No File, no fs, no std::io in this test module.
}

// ── No filesystem write APIs (structural) ────────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: this module does not use std::fs::write,
    // std::fs::create_dir, or any filesystem write API.
    // The build_usage_delta_from_session_delta function only transforms
    // in-memory data.
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let _output = build_usage_delta_from_session_delta(&delta);
    let _rendered = render_usage_delta(&_output);
}

// ── Render includes counter reset warnings when present ─────────────

#[test]
fn render_includes_counter_reset_warnings() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_RESET);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("Counter reset/decrease warnings"));
    assert!(rendered.contains("exact usage unknown"));
}

// ── Render includes delta incomplete warning on reset ───────────────

#[test]
fn render_includes_delta_incomplete_warning_on_reset() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_RESET);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("delta may be incomplete"));
}

// ── Render includes counters may reset disclaimer ────────────────────

#[test]
fn render_includes_counters_may_reset_disclaimer() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("counters may reset"));
}

// ── Render shows interface-level only in header ─────────────────────

#[test]
fn render_shows_interface_level_only_in_header() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered = render_usage_delta(&output);
    assert!(rendered.contains("interface-level only"));
}

// ── Human-readable formatting works ────────────────────────────────

#[test]
fn human_readable_formatting_works() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);

    // wlan0 rx_delta = 1,000,000 → should have human-readable field
    let wlan0 = &output.rows[0];
    assert_eq!(wlan0.rx_delta_human, "976.56 KiB");
    assert!(!wlan0.rx_delta_human.is_empty());
    assert_ne!(wlan0.rx_delta_human, wlan0.rx_delta_bytes.to_string());
}

// ── Zero delta produces zero human-readable ─────────────────────────

#[test]
fn zero_delta_produces_zero_human_readable() {
    let delta = make_session_delta(START_SAMPLE, START_SAMPLE); // same content = zero delta
    let output = build_usage_delta_from_session_delta(&delta);
    for row in &output.rows {
        assert_eq!(row.rx_delta_human, "0 B");
        assert_eq!(row.tx_delta_human, "0 B");
        assert_eq!(row.combined_delta_human, "0 B");
    }
}

// ── Render determinism ────────────────────────────────────────────

#[test]
fn render_is_deterministic() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    let rendered1 = render_usage_delta(&output);
    let rendered2 = render_usage_delta(&output);
    assert_eq!(rendered1, rendered2);
}

// ── Build is deterministic ────────────────────────────────────────

#[test]
fn build_is_deterministic() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output1 = build_usage_delta_from_session_delta(&delta);
    let output2 = build_usage_delta_from_session_delta(&delta);
    assert_eq!(output1, output2);
}

// ── Source label is model-only ────────────────────────────────────

#[test]
fn source_label_is_model_only() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    assert_eq!(output.schema_source_label, "usage_delta_output_model");
    assert_eq!(output.start_source_label, "model-only (no live sample)");
    assert_eq!(output.end_source_label, "model-only (no live sample)");
}

// ── has_reset flag reflects underlying session_delta ───────────────

#[test]
fn has_reset_flag_reflects_session_delta() {
    let delta = make_session_delta(START_SAMPLE, END_SAMPLE_NORMAL);
    let output = build_usage_delta_from_session_delta(&delta);
    for row in &output.rows {
        assert!(!row.has_reset, "normal delta should have no resets");
    }

    let reset_delta = make_session_delta(START_SAMPLE, END_SAMPLE_RESET);
    let reset_output = build_usage_delta_from_session_delta(&reset_delta);
    let wlan0 = reset_output
        .rows
        .iter()
        .find(|r| r.interface == "wlan0")
        .unwrap();
    assert!(wlan0.has_reset, "reset delta should set has_reset");
}
