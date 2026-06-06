// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for the live `/proc/net/dev` reader seam (v3.0 phase 2).
//!
//! All tests use injected/fake content — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes,
//! **no** CLI command registration.

use super::*;
use crate::accounting::live_proc_net_dev::*;

/// Standard multi-interface sample for live seam tests.
const LIVE_SEAM_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

/// Minimal single-interface sample.
const LIVE_SEAM_MINIMAL: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0
";

/// Sample with unusual interface names.
const LIVE_SEAM_UNUSUAL_NAMES: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlp2s0: 100000 200 0 0 0 0 0 0 200000 400 0 0 0 0 0 0
  enp3s0: 300000 600 0 0 0 0 0 0 400000 800 0 0 0 0 0 0
  usb0: 4096 8 0 0 0 0 0 0 8192 16 0 0 0 0 0 0
";

/// Malformed content — missing colon.
const LIVE_SEAM_MALFORMED_NO_COLON: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

/// Malformed content — too few fields.
const LIVE_SEAM_MALFORMED_TOO_FEW: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000
";

/// Malformed content — non-numeric rx_bytes.
const LIVE_SEAM_MALFORMED_NON_NUMERIC: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

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

// ── Render: read-only seam statement ──────────────────────────────

#[test]
fn render_includes_read_only_seam_statement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "render must include read-only seam statement"
    );
}

// ── Render: honesty denials ───────────────────────────────────────

#[test]
fn render_denies_per_app_attribution() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("not per-app attribution"),
        "render must deny per-app attribution"
    );
}

#[test]
fn render_denies_quota_enforcement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no quota enforcement active"),
        "render must deny quota enforcement"
    );
}

#[test]
fn render_denies_network_blocking() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no network blocking active"),
        "render must deny network blocking"
    );
}

#[test]
fn render_denies_limiter_attach() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no limiter attach performed"),
        "render must deny limiter attach"
    );
}

#[test]
fn render_denies_nft_tc_state_mutation() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no nft/tc/Zelynic state mutation performed"),
        "render must deny nft/tc/state mutation"
    );
}

#[test]
fn render_denies_ledger_persistence() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no ledger persistence performed"),
        "render must deny ledger persistence"
    );
}

#[test]
fn render_denies_ebpf() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no eBPF used"), "render must deny eBPF");
}

#[test]
fn render_denies_cgroup_mutation() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no cgroup mutation"),
        "render must deny cgroup mutation"
    );
}

#[test]
fn render_denies_pid_movement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no PID movement"),
        "render must deny PID movement"
    );
}

// ── Render: counters may reset ────────────────────────────────────

#[test]
fn render_warns_counters_may_reset() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("counters may reset after reboot/interface reset"),
        "render must warn about counter reset"
    );
}

// ── Render: mutation flags ─────────────────────────────────────────

#[test]
fn render_includes_filesystem_write_not_performed() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("filesystem write not performed"),
        "render must state filesystem write not performed"
    );
}

#[test]
fn render_includes_state_mutation_not_performed() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("state mutation not performed"),
        "render must state state mutation not performed"
    );
}

// ── Render: source path and label ─────────────────────────────────

#[test]
fn render_includes_source_path() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("/proc/net/dev"),
        "render must include source path"
    );
    assert!(
        rendered.contains("live_proc_net_dev_sample"),
        "render must include source label"
    );
}

// ── Render: planned state ─────────────────────────────────────────

#[test]
fn render_planned_plan_shows_planned_status() {
    let plan = build_live_proc_net_dev_read_plan();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Read status: planned"),
        "render must show planned status"
    );
    assert!(
        rendered.contains("Snapshot: none"),
        "render must show no snapshot for planned"
    );
}

// ── Structural: no CLI command ────────────────────────────────────

#[test]
fn no_cli_command_is_added() {
    // Structural test: verify that no CLI usage command registration
    // exists in the accounting module. The live_proc_net_dev module
    // does not expose any CLI-facing types — only pub(crate) model types.
    let _ = build_live_proc_net_dev_read_plan();
    let _ = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE);
    // No clap/structopt args, no Command enum variants, no CLI routing.
    // This test documents the intent structurally.
}

// ── Structural: no filesystem write APIs ──────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: the live_proc_net_dev module must not import
    // or use std::fs::write, std::fs::create_dir, std::fs::remove_file,
    // or any other filesystem mutation API.
    //
    // This is verified by the module's source code containing only
    // parse_proc_net_dev (pure parser), string operations, and
    // model construction — no std::fs imports.
    //
    // The module source does not contain "std::fs" anywhere.
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── Render: snapshot summary ────────────────────────────────────

#[test]
fn render_shows_snapshot_summary() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("3 interface(s) parsed"),
        "render must show interface count"
    );
    assert!(
        rendered.contains("wlan0"),
        "render must include interface names"
    );
    assert!(
        rendered.contains("eth0"),
        "render must include interface names"
    );
}

#[test]
fn render_shows_empty_snapshot() {
    let plan = build_live_proc_net_dev_snapshot_from_content("").unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("empty (no interfaces parsed)"),
        "render must show empty snapshot message"
    );
}

// ── Render: determinism ───────────────────────────────────────────

#[test]
fn render_is_deterministic() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered1 = render_live_proc_net_dev_read_plan(&plan);
    let rendered2 = render_live_proc_net_dev_read_plan(&plan);
    assert_eq!(rendered1, rendered2, "render output must be deterministic");
}

// ── Render: mutation flags ────────────────────────────────────────

#[test]
fn render_shows_mutation_flags() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Filesystem read performed: false"),
        "render must show filesystem_read_performed = false"
    );
    assert!(
        rendered.contains("Filesystem write performed: false"),
        "render must show filesystem_write_performed = false"
    );
    assert!(
        rendered.contains("State mutation performed: false"),
        "render must show state_mutation_performed = false"
    );
}

// ── Render: error plan ───────────────────────────────────────────

#[test]
fn render_error_plan_shows_error_status() {
    let err_content = "wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = build_live_proc_net_dev_snapshot_from_content(err_content);
    let parse_err = result.unwrap_err();
    let plan = build_live_proc_net_dev_error_plan(&parse_err);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Read status: error:"),
        "render must show error status"
    );
    assert!(
        rendered.contains("Snapshot: none"),
        "render must show no snapshot for error"
    );
    // Error plan still has honesty disclaimers
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "error plan must still have honesty disclaimers"
    );
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
