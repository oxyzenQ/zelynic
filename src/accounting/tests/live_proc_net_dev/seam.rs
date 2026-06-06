// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 2: Injected content parsing, read plan, and interface feature tests.
//!
//! Tests the injected content parsing path, read plan construction,
//! error handling, loopback detection, and large counter handling.
//! All tests use injected/fake content — no live filesystem reads.

use super::*;

// ── Injected content parsing ──────────────────────────────────────

#[test]
fn injected_content_parses_via_existing_parser() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap.interfaces[0].interface, "lo");
    assert_eq!(snap.interfaces[1].interface, "wlan0");
    assert_eq!(snap.interfaces[2].interface, "eth0");
}

#[test]
fn injected_content_uses_honest_source_label() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    assert_eq!(plan.source_label, SOURCE_LABEL_INJECTED);
    assert_eq!(plan.source_label, "live_proc_net_dev_sample");
    assert!(plan.is_injected());
    assert!(!plan.is_live());
}

#[test]
fn injected_minimal_content_parses() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_MINIMAL).unwrap();
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap.interfaces[0].interface, "wlan0");
    assert_eq!(snap.interfaces[0].rx_bytes, 5000);
    assert_eq!(snap.interfaces[0].tx_bytes, 6000);
}

#[test]
fn injected_unusual_interface_names_parse() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_UNUSUAL_NAMES).unwrap();
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap.interfaces[0].interface, "wlp2s0");
    assert_eq!(snap.interfaces[1].interface, "enp3s0");
    assert_eq!(snap.interfaces[2].interface, "usb0");
}

// ── Error cases ───────────────────────────────────────────────────

#[test]
fn malformed_injected_content_returns_parse_error_no_colon() {
    let result = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_MALFORMED_NO_COLON);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("missing colon"),
        "expected 'missing colon' in error: {}",
        err_msg
    );
}

#[test]
fn malformed_injected_content_returns_parse_error_too_few() {
    let result = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_MALFORMED_TOO_FEW);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("too few fields"),
        "expected 'too few fields' in error: {}",
        err_msg
    );
}

#[test]
fn malformed_injected_content_returns_parse_error_non_numeric() {
    let result = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_MALFORMED_NON_NUMERIC);
    assert!(result.is_err());
}

#[test]
fn empty_injected_content_returns_empty_snapshot() {
    // Empty content should produce an empty snapshot (matching existing parser behavior).
    let plan = build_live_proc_net_dev_snapshot_from_content("").unwrap();
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert!(snap.is_empty());
    assert_eq!(snap.len(), 0);
}

#[test]
fn headers_only_content_returns_empty_snapshot() {
    let plan = build_live_proc_net_dev_snapshot_from_content(HEADERS_ONLY).unwrap();
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert!(snap.is_empty());
}

// ── Read plan ────────────────────────────────────────────────────

#[test]
fn read_plan_points_only_to_proc_net_dev() {
    let plan = build_live_proc_net_dev_read_plan();
    assert_eq!(plan.source_path, "/proc/net/dev");
    assert_eq!(plan.source_path, DEFAULT_LIVE_SOURCE_PATH);
}

#[test]
fn read_plan_does_not_accept_arbitrary_path() {
    let plan = build_live_proc_net_dev_read_plan();
    // The source path is always hardcoded — there is no parameter to change it.
    assert_ne!(plan.source_path, "/etc/passwd");
    assert_ne!(plan.source_path, "/proc/self/mountinfo");
    assert_ne!(plan.source_path, "/sys/class/net/eth0/statistics/rx_bytes");
}

#[test]
fn read_plan_is_planned_state() {
    let plan = build_live_proc_net_dev_read_plan();
    assert_eq!(plan.read_status, LiveReadStatus::Planned);
    assert!(plan.snapshot.is_none());
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

#[test]
fn read_plan_is_live_source_label() {
    let plan = build_live_proc_net_dev_read_plan();
    assert_eq!(plan.source_label, SOURCE_LABEL_LIVE);
    assert!(!plan.is_injected());
    assert!(plan.is_live());
}

#[test]
fn error_plan_has_correct_status() {
    let err_content = "wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = build_live_proc_net_dev_snapshot_from_content(err_content);
    assert!(result.is_err());
    let parse_err = result.unwrap_err();
    let plan = build_live_proc_net_dev_error_plan(&parse_err);
    assert!(matches!(plan.read_status, LiveReadStatus::Error(_)));
    assert!(plan.snapshot.is_none());
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

#[test]
fn injected_plan_flags_are_correct() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── Interface-level loopback detection ─────────────────────────────

#[test]
fn injected_content_loopback_detection() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let snap = plan.snapshot.as_ref().unwrap();
    let lo = snap.get("lo").unwrap();
    assert!(lo.is_loopback());
    let wlan0 = snap.get("wlan0").unwrap();
    assert!(!wlan0.is_loopback());
}

// ── Large counter handling ────────────────────────────────────────

#[test]
fn injected_content_large_counters() {
    let large_sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 18446744073709551615 18446744073709551615 0 0 0 0 0 0 18446744073709551615 18446744073709551615 0 0 0 0 0 0 0
";
    let plan = build_live_proc_net_dev_snapshot_from_content(large_sample).unwrap();
    let snap = plan.snapshot.as_ref().unwrap();
    assert_eq!(snap.interfaces[0].rx_bytes, u64::MAX);
    assert_eq!(snap.interfaces[0].tx_bytes, u64::MAX);
}
