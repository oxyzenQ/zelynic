// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure tests for v2.9 Network Accounting Lab usage preview renderer.
//!
//! All tests use const sample strings — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes.

use super::*;
use crate::accounting::interface_counters::parse_proc_net_dev;
use crate::accounting::usage_preview::*;

// ── format_bytes_human ──────────────────────────────────────────────────────────

#[test]
fn format_bytes_zero() {
    assert_eq!(format_bytes_human(0), "0 B");
}

#[test]
fn format_bytes_bytes_range() {
    assert_eq!(format_bytes_human(1), "1 B");
    assert_eq!(format_bytes_human(512), "512 B");
    assert_eq!(format_bytes_human(1023), "1023 B");
}

#[test]
fn format_bytes_kib_range() {
    let rendered = format_bytes_human(1024);
    assert!(rendered.contains("KiB"));
    let rendered = format_bytes_human(1536);
    assert!(rendered.contains("KiB"));
}

#[test]
fn format_bytes_mib_range() {
    let rendered = format_bytes_human(1024 * 1024);
    assert!(rendered.contains("MiB"));
    let rendered = format_bytes_human(5 * 1024 * 1024);
    assert!(rendered.contains("MiB"));
}

#[test]
fn format_bytes_gib_range() {
    let rendered = format_bytes_human(1024 * 1024 * 1024);
    assert!(rendered.contains("GiB"));
    let rendered = format_bytes_human(1324567890);
    assert!(rendered.contains("GiB"));
}

#[test]
fn format_bytes_tib_range() {
    // Use explicit u64 literals to avoid overflow in debug mode
    let one_tib: u64 = 1024 * 1024 * 1024 * 1024;
    let rendered = format_bytes_human(one_tib + one_tib / 2);
    assert!(rendered.contains("TiB"));
}

#[test]
fn format_bytes_u64_max_no_panic() {
    // Must not panic on u64::MAX — saturating display.
    let rendered = format_bytes_human(u64::MAX);
    assert!(!rendered.is_empty());
}

// ── build_usage_preview ──────────────────────────────────────────────────────────

#[test]
fn build_preview_one_interface() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.interface_count, 1);
    assert_eq!(preview.rows[0].interface, "wlan0");
    assert_eq!(preview.rows[0].rx_bytes, 1000);
    assert_eq!(preview.rows[0].tx_bytes, 2000);
    assert_eq!(preview.rows[0].total_bytes, 3000);
    assert_eq!(preview.total_rx_bytes, 1000);
    assert_eq!(preview.total_tx_bytes, 2000);
    assert_eq!(preview.total_combined_bytes, 3000);
}

#[test]
fn build_preview_multiple_interfaces() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.interface_count, 3);
    // wlan0 RX + TX
    assert_eq!(preview.rows[1].interface, "wlan0");
    assert_eq!(preview.rows[1].total_bytes, 1324567890 + 356789012);
    // Totals include loopback
    assert!(preview.total_rx_bytes > 0);
    assert!(preview.total_tx_bytes > 0);
}

#[test]
fn build_preview_empty_snapshot() {
    let snapshot = parse_proc_net_dev(EMPTY_CONTENT).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.interface_count, 0);
    assert!(preview.rows.is_empty());
    assert_eq!(preview.total_rx_bytes, 0);
    assert_eq!(preview.total_tx_bytes, 0);
    assert_eq!(preview.total_combined_bytes, 0);
}

#[test]
fn build_preview_preserves_interface_order() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  eth0: 3000 30 0 0 0 0 0 0 4000 40 0 0 0 0 0 0
    lo: 100 5 0 0 0 0 0 0 200 10 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.rows[0].interface, "wlan0");
    assert_eq!(preview.rows[1].interface, "eth0");
    assert_eq!(preview.rows[2].interface, "lo");
}

#[test]
fn build_preview_source_label() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.source_label, "proc_net_dev_sample");
}

#[test]
fn build_preview_attribution_scope_is_interface_only() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.attribution_scope, "interface-only");
}

#[test]
fn build_preview_enforcement_status_inactive() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert_eq!(preview.enforcement_status, "inactive/not implemented");
}

#[test]
fn build_preview_loopback_flag() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert!(preview.rows[0].is_loopback); // lo
    assert!(!preview.rows[1].is_loopback); // wlan0
}

#[test]
fn build_preview_human_readable_filled() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    assert!(!preview.rows[0].rx_human.is_empty());
    assert!(!preview.rows[0].tx_human.is_empty());
    assert!(!preview.rows[0].total_human.is_empty());
}

// ── render_usage_preview ─────────────────────────────────────────────────────────

#[test]
fn render_includes_read_only_statement() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("read-only parsed snapshot"));
}

#[test]
fn render_includes_interface_level_only() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("interface-level only"));
}

#[test]
fn render_denies_per_app_attribution() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("not per-app attribution"));
}

#[test]
fn render_denies_quota_enforcement() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("no quota enforcement active"));
}

#[test]
fn render_denies_network_blocking() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("no network blocking active"));
}

#[test]
fn render_denies_limiter_attach() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn render_denies_nft_tc_state_mutation() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

#[test]
fn render_denies_live_proc_sysfs_read() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("no live /proc or sysfs read performed"));
}

#[test]
fn render_includes_source_label() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("proc_net_dev_sample"));
}

#[test]
fn render_uses_human_readable_bytes() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1324567890 1234567 0 0 0 0 0 0 356789012 345678 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    // 1324567890 bytes ≈ 1.23 GiB
    assert!(rendered.contains("GiB"));
}

#[test]
fn render_empty_snapshot_handled() {
    let snapshot = parse_proc_net_dev(EMPTY_CONTENT).unwrap();
    let preview = build_usage_preview(&snapshot);
    let rendered = render_usage_preview(&preview);
    assert!(rendered.contains("No interfaces found"));
    assert!(rendered.contains("read-only"));
}

#[test]
fn render_is_deterministic() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let preview = build_usage_preview(&snapshot);
    let a = render_usage_preview(&preview);
    let b = render_usage_preview(&preview);
    assert_eq!(a, b);
}

// ── overflow-safe totals ──────────────────────────────────────────────────────────

#[test]
fn build_preview_u64_max_saturating() {
    // u64::MAX on both RX and TX should not panic.
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 18446744073709551615 999 0 0 0 0 0 0 18446744073709551615 999 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    let preview = build_usage_preview(&snapshot);
    // Saturating: u64::MAX + u64::MAX = u64::MAX (saturated)
    assert_eq!(preview.rows[0].rx_bytes, u64::MAX);
    assert_eq!(preview.rows[0].tx_bytes, u64::MAX);
    assert_eq!(preview.rows[0].total_bytes, u64::MAX);
    assert_eq!(preview.total_rx_bytes, u64::MAX);
    assert_eq!(preview.total_tx_bytes, u64::MAX);
    assert_eq!(preview.total_combined_bytes, u64::MAX);
}

#[test]
fn render_u64_max_no_panic() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 18446744073709551615 999 0 0 0 0 0 0 18446744073709551615 999 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    let preview = build_usage_preview(&snapshot);
    // Must not panic when rendering u64::MAX
    let _rendered = render_usage_preview(&preview);
}
