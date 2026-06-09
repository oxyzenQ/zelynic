// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure Ledger Identity Report tests for v3.1 phase 4.
//!
//! All tests use in-memory structs — **no** filesystem reads or writes,
//! **no** live `/proc/net/dev` reads, **no** live sysfs reads, **no**
//! network blocking, **no** quota enforcement, **no** eBPF, **no** PID
//! movement, **no** cgroup writes, **no** CLI command, **no** persistence
//! write enabled.

use crate::accounting::identity::*;
use crate::accounting::ledger::{add_session_delta_entry, add_snapshot_entry, new_empty_ledger};
use crate::accounting::ledger_identity::{
    build_identity_attachment, build_interface_only_attachment, build_no_identity_attachment,
};
use crate::accounting::ledger_identity_report::*;

fn make_snapshot_entry(
    interface: &str,
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger::LedgerEntry {
    let mut ledger = new_empty_ledger("2026-06-07T10:00:00Z", "host-test");
    add_snapshot_entry(
        &mut ledger,
        &format!("entry-snap-{}", interface),
        "2026-06-07T10:00:00Z",
        "model-only",
        interface,
        rx,
        tx,
        Some(10),
        Some(20),
        false,
        vec![],
    );
    ledger.entries.into_iter().next().unwrap()
}

#[allow(dead_code)]
fn make_delta_entry(interface: &str, rx: u64, tx: u64) -> crate::accounting::ledger::LedgerEntry {
    let mut ledger = new_empty_ledger("2026-06-07T10:00:00Z", "host-test");
    add_session_delta_entry(
        &mut ledger,
        &format!("entry-delta-{}", interface),
        "2026-06-07T12:00:00Z",
        "session-delta",
        interface,
        rx,
        tx,
        Some(5),
        Some(3),
        false,
        vec![],
    );
    ledger.entries.into_iter().next().unwrap()
}

fn make_process_attachment(
    interface: &str,
    comm: &str,
    pid: u32,
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger_identity::LedgerIdentityAttachment {
    let entry = make_snapshot_entry(interface, rx, tx);
    let proc = ProcessIdentity {
        pid: Some(pid),
        comm: Some(comm.to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new(interface, interface == "lo")),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    build_identity_attachment(&entry, resolved)
}

fn make_cgroup_attachment(
    interface: &str,
    cg_path: &str,
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger_identity::LedgerIdentityAttachment {
    let entry = make_snapshot_entry(interface, rx, tx);
    let cg = CgroupIdentity {
        cgroup_path: Some(cg_path.to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new(interface, false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    build_identity_attachment(&entry, resolved)
}

fn make_target_attachment(
    interface: &str,
    comm: &str,
    pid: u32,
    cg_path: &str,
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger_identity::LedgerIdentityAttachment {
    let entry = make_snapshot_entry(interface, rx, tx);
    let proc = ProcessIdentity {
        pid: Some(pid),
        comm: Some(comm.to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let cg = CgroupIdentity {
        cgroup_path: Some(cg_path.to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new(interface, false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::TargetBestEffort);
    build_identity_attachment(&entry, resolved)
}

fn make_unknown_attachment(
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger_identity::LedgerIdentityAttachment {
    let entry = make_snapshot_entry("eth0", rx, tx);
    let resolved = ResolvedUsageTarget::unknown();
    build_identity_attachment(&entry, resolved)
}

// ── Empty report ───────────────────────────────────────────────────

#[test]
fn empty_report() {
    let attachments: Vec<crate::accounting::ledger_identity::LedgerIdentityAttachment> = vec![];
    let report = build_ledger_identity_report(&attachments);
    assert_eq!(report.total_attachments, 0);
    assert_eq!(report.totals.entry_count, 0);
    assert_eq!(report.totals.total_rx_bytes, 0);
    assert_eq!(report.totals.total_tx_bytes, 0);
    assert_eq!(report.totals.total_combined_bytes, 0);
    assert!(report.targets.is_empty());
    assert!(report.interfaces.is_empty());
    assert_eq!(report.unknown_target_count, 0);
    assert_eq!(report.no_identity_count, 0);
    assert_eq!(report.interface_only_count, 0);
    assert_eq!(report.process_best_effort_count, 0);
    assert_eq!(report.cgroup_best_effort_count, 0);
    assert_eq!(report.target_best_effort_count, 0);
    assert!(report.honesty.attribution_is_best_effort);
    assert!(report.honesty.enforcement_inactive);
    assert!(report.provenance.contains("empty"));
}

// ── Interface-only attachment report ───────────────────────────────

#[test]
fn interface_only_attachment_report() {
    let e1 = make_snapshot_entry("eth0", 1000, 2000);
    let e2 = make_snapshot_entry("wlan0", 3000, 4000);
    let a1 = build_interface_only_attachment(&e1);
    let a2 = build_interface_only_attachment(&e2);
    let report = build_ledger_identity_report(&[a1, a2]);

    assert_eq!(report.total_attachments, 2);
    assert_eq!(report.interface_only_count, 2);
    assert_eq!(report.no_identity_count, 0);
    assert_eq!(report.interfaces.len(), 2);
    assert_eq!(report.totals.total_rx_bytes, 4000);
    assert_eq!(report.totals.total_tx_bytes, 6000);
    assert_eq!(report.totals.total_combined_bytes, 10000);
}

// ── Process best-effort attachment report ───────────────────────────

#[test]
fn process_best_effort_attachment_report() {
    let a = make_process_attachment("eth0", "firefox", 1234, 5000, 3000);
    let report = build_ledger_identity_report(&[a]);

    assert_eq!(report.total_attachments, 1);
    assert_eq!(report.process_best_effort_count, 1);
    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.attribution_scope, "process_best_effort");
    assert_eq!(target.process_comm.as_deref(), Some("firefox"));
    assert_eq!(target.process_pid, Some(1234));
    assert_eq!(target.rx_bytes, 5000);
    assert_eq!(target.tx_bytes, 3000);
}

// ── Cgroup best-effort attachment report ───────────────────────────

#[test]
fn cgroup_best_effort_attachment_report() {
    let a = make_cgroup_attachment("wlan0", "/sys/fs/cgroup/user.slice/app.scope", 2000, 1000);
    let report = build_ledger_identity_report(&[a]);

    assert_eq!(report.total_attachments, 1);
    assert_eq!(report.cgroup_best_effort_count, 1);
    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.attribution_scope, "cgroup_best_effort");
    assert_eq!(
        target.cgroup_path.as_deref(),
        Some("/sys/fs/cgroup/user.slice/app.scope")
    );
    assert_eq!(target.rx_bytes, 2000);
    assert_eq!(target.tx_bytes, 1000);
}

// ── Target best-effort attachment report ───────────────────────────

#[test]
fn target_best_effort_attachment_report() {
    let a = make_target_attachment(
        "eth0",
        "chrome",
        42,
        "/sys/fs/cgroup/user.slice/chrome.scope",
        8000,
        4000,
    );
    let report = build_ledger_identity_report(&[a]);

    assert_eq!(report.total_attachments, 1);
    assert_eq!(report.target_best_effort_count, 1);
    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.attribution_scope, "target_best_effort");
    assert_eq!(target.process_comm.as_deref(), Some("chrome"));
    assert_eq!(target.process_pid, Some(42));
    assert_eq!(
        target.cgroup_path.as_deref(),
        Some("/sys/fs/cgroup/user.slice/chrome.scope")
    );
    assert_eq!(target.rx_bytes, 8000);
    assert_eq!(target.tx_bytes, 4000);
}

// ── Mixed interface/process/cgroup attachments ──────────────────────

#[test]
fn mixed_interface_process_cgroup_attachments() {
    let a1 = build_interface_only_attachment(&make_snapshot_entry("eth0", 1000, 2000));
    let a2 = make_process_attachment("wlan0", "firefox", 1234, 3000, 4000);
    let a3 = make_cgroup_attachment("eth0", "/sys/fs/cgroup/user.slice/app.scope", 500, 600);
    let report = build_ledger_identity_report(&[a1, a2, a3]);

    assert_eq!(report.total_attachments, 3);
    assert_eq!(report.interface_only_count, 1);
    assert_eq!(report.process_best_effort_count, 1);
    assert_eq!(report.cgroup_best_effort_count, 1);
    assert_eq!(report.targets.len(), 3);
    assert_eq!(report.interfaces.len(), 2); // eth0 and wlan0
    assert_eq!(report.totals.total_rx_bytes, 4500);
    assert_eq!(report.totals.total_tx_bytes, 6600);
    assert_eq!(report.totals.total_combined_bytes, 11100);
}

// ── Unknown target attachment ──────────────────────────────────────

#[test]
fn unknown_target_attachment() {
    let a = make_unknown_attachment(100, 200);
    let report = build_ledger_identity_report(&[a]);

    assert_eq!(report.total_attachments, 1);
    assert_eq!(report.unknown_target_count, 1);
    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0];
    assert_eq!(target.attribution_scope, "unknown");
    assert!(target.process_comm.is_none());
    assert!(target.cgroup_path.is_none());
}

// ── Totals preserve rx bytes ────────────────────────────────────────

#[test]
fn totals_preserve_rx_bytes() {
    let a1 = make_process_attachment("eth0", "a", 1, 10, 100);
    let a2 = make_process_attachment("wlan0", "b", 2, 20, 200);
    let report = build_ledger_identity_report(&[a1, a2]);
    assert_eq!(report.totals.total_rx_bytes, 30);
}

// ── Totals preserve tx bytes ────────────────────────────────────────

#[test]
fn totals_preserve_tx_bytes() {
    let a1 = make_process_attachment("eth0", "a", 1, 10, 100);
    let a2 = make_process_attachment("wlan0", "b", 2, 20, 200);
    let report = build_ledger_identity_report(&[a1, a2]);
    assert_eq!(report.totals.total_tx_bytes, 300);
}

// ── Totals preserve combined bytes ─────────────────────────────────

#[test]
fn totals_preserve_combined_bytes() {
    let a1 = make_process_attachment("eth0", "a", 1, 10, 100);
    let a2 = make_process_attachment("wlan0", "b", 2, 20, 200);
    let report = build_ledger_identity_report(&[a1, a2]);
    assert_eq!(report.totals.total_combined_bytes, 330);
}

// ── Entry counts are correct ───────────────────────────────────────

#[test]
fn entry_counts_are_correct() {
    let a1 = build_interface_only_attachment(&make_snapshot_entry("eth0", 100, 200));
    let a2 = build_interface_only_attachment(&make_snapshot_entry("eth0", 300, 400));
    let a3 = build_interface_only_attachment(&make_snapshot_entry("wlan0", 500, 600));
    let report = build_ledger_identity_report(&[a1, a2, a3]);

    assert_eq!(report.total_attachments, 3);
    assert_eq!(report.totals.entry_count, 3);

    // eth0 interface should have 2 entries
    let eth0_iface = report
        .interfaces
        .iter()
        .find(|i| i.interface == "eth0")
        .unwrap();
    assert_eq!(eth0_iface.entry_count, 2);

    // wlan0 interface should have 1 entry
    let wlan0_iface = report
        .interfaces
        .iter()
        .find(|i| i.interface == "wlan0")
        .unwrap();
    assert_eq!(wlan0_iface.entry_count, 1);

    // eth0 interface_only target should have 2 entries (merged)
    let eth0_target = report
        .targets
        .iter()
        .find(|t| t.interface == "eth0")
        .unwrap();
    assert_eq!(eth0_target.entry_count, 2);
}

// ── Deterministic ordering by interface/target key ───────────────────

#[test]
fn deterministic_ordering_by_interface_target_key() {
    let a1 = build_interface_only_attachment(&make_snapshot_entry("wlan0", 100, 200));
    let a2 = build_interface_only_attachment(&make_snapshot_entry("eth0", 300, 400));
    let report = build_ledger_identity_report(&[a1, a2]);

    // Interfaces sorted alphabetically: eth0 before wlan0
    assert_eq!(report.interfaces[0].interface, "eth0");
    assert_eq!(report.interfaces[1].interface, "wlan0");

    // Targets sorted by key: eth0| before wlan0|
    assert_eq!(report.targets[0].interface, "eth0");
    assert_eq!(report.targets[1].interface, "wlan0");
}

// ── Serialization round-trip ───────────────────────────────────────

#[test]
fn serialization_round_trip() {
    let a1 = make_process_attachment("eth0", "firefox", 1234, 5000, 3000);
    let a2 = make_cgroup_attachment("wlan0", "/sys/fs/cgroup/user.slice/app.scope", 2000, 1000);
    let report = build_ledger_identity_report(&[a1, a2]);
    let json = serialize_report_json(&report).unwrap();
    let deserialized: LedgerIdentityReport = deserialize_report_json(&json).unwrap();
    assert_eq!(report, deserialized);
}

// ── Serialization deterministic ────────────────────────────────────

#[test]
fn serialization_deterministic() {
    let a1 = make_process_attachment("eth0", "firefox", 1234, 5000, 3000);
    let report = build_ledger_identity_report(&[a1]);
    let json1 = serialize_report_json(&report).unwrap();
    let json2 = serialize_report_json(&report).unwrap();
    assert_eq!(json1, json2);
}

// ── Render output says best-effort for identity ────────────────────

#[test]
fn render_output_says_best_effort_for_identity() {
    let a = make_process_attachment("eth0", "firefox", 1234, 100, 200);
    let report = build_ledger_identity_report(&[a]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("best-effort"));
}

// ── Render output says interface-level source remains authoritative ──

#[test]
fn render_output_says_interface_level_authoritative() {
    let a = make_process_attachment("eth0", "firefox", 1234, 100, 200);
    let report = build_ledger_identity_report(&[a]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("interface-level data source remains authoritative"));
}

// ── Render output says no enforcement ────────────────────────────────

#[test]
fn render_output_says_no_enforcement() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no enforcement"));
}

// ── Render output says no persistence ───────────────────────────────

#[test]
fn render_output_says_no_persistence() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no persistence"));
}

// ── Render output says no filesystem write ──────────────────────────

#[test]
fn render_output_says_no_filesystem_write() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no filesystem write"));
}

// ── Render output says no network blocking ──────────────────────────

#[test]
fn render_output_says_no_network_blocking() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no network blocking"));
}

// ── Render output says no quota ─────────────────────────────────────

#[test]
fn render_output_says_no_quota() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no quota"));
}

// ── Render output says no eBPF ──────────────────────────────────────

#[test]
fn render_output_says_no_ebpf() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no eBPF"));
}

// ── No live /proc reads in tests ───────────────────────────────────

#[test]
fn no_live_proc_reads_in_tests_structural() {
    let a = make_process_attachment("eth0", "test", 1, 100, 200);
    let _report = build_ledger_identity_report(&[a]);
}

// ── No filesystem read/write APIs added ─────────────────────────────

#[test]
fn no_filesystem_read_write_apis_added() {
    let a = make_process_attachment("eth0", "test", 1, 100, 200);
    let report = build_ledger_identity_report(&[a]);
    let rendered = render_ledger_identity_report(&report);
    assert!(!rendered.contains("/proc/net/dev"));
    assert!(!rendered.contains(".json"));
}

// ── No CLI command added ───────────────────────────────────────────

#[test]
fn no_cli_command_added_structural() {
    let a = make_process_attachment("eth0", "test", 1, 100, 200);
    let _report = build_ledger_identity_report(&[a]);
}

// ── No persistence enabled ──────────────────────────────────────────

#[test]
fn no_persistence_enabled() {
    let report = build_ledger_identity_report(&[]);
    assert!(!report.honesty.persistence_performed);
    assert!(report.honesty.attribution_is_best_effort);
}

// ── No enforcement active ──────────────────────────────────────────

#[test]
fn no_enforcement_active() {
    let report = build_ledger_identity_report(&[]);
    assert!(report.honesty.enforcement_inactive);
    assert!(!report.honesty.filesystem_write);
    assert!(!report.honesty.network_blocking);
    assert!(!report.honesty.quota);
    assert!(!report.honesty.ebpf);
    assert!(!report.honesty.nft_tc_mutation);
    assert!(!report.honesty.cgroup_mutation);
    assert!(!report.honesty.daemon_watch);
}

// ── Default report honesty flags ────────────────────────────────────

#[test]
fn default_report_honesty_flags() {
    let h = default_report_honesty();
    assert!(h.attribution_is_best_effort);
    assert!(h.interface_level_data_source);
    assert!(h.per_app_attribution_may_be_partial);
    assert!(h.interface_level_remains_authoritative);
    assert!(h.enforcement_inactive);
    assert!(!h.persistence_performed);
    assert!(!h.filesystem_write);
    assert!(!h.network_blocking);
    assert!(!h.quota);
    assert!(!h.ebpf);
    assert!(!h.nft_tc_mutation);
    assert!(!h.cgroup_mutation);
    assert!(!h.daemon_watch);
}

// ── Report with no-identity attachments ─────────────────────────────

#[test]
fn report_with_no_identity_attachments() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let e2 = make_snapshot_entry("wlan0", 300, 400);
    let a1 = build_no_identity_attachment(&e1);
    let a2 = build_no_identity_attachment(&e2);
    let report = build_ledger_identity_report(&[a1, a2]);

    assert_eq!(report.total_attachments, 2);
    assert_eq!(report.no_identity_count, 2);
    assert_eq!(report.interface_only_count, 0);
    assert_eq!(report.interfaces.len(), 2);
}

// ── Render includes target details ─────────────────────────────────

#[test]
fn render_includes_target_details() {
    let a = make_process_attachment("eth0", "firefox", 1234, 500, 300);
    let report = build_ledger_identity_report(&[a]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("firefox"));
    assert!(rendered.contains("1234"));
    assert!(rendered.contains("PIDs are recycled"));
}

// ── Render includes interface breakdown ──────────────────────────────

#[test]
fn render_includes_interface_breakdown() {
    let a1 = make_process_attachment("eth0", "a", 1, 1000, 2000);
    let a2 = make_process_attachment("wlan0", "b", 2, 3000, 4000);
    let report = build_ledger_identity_report(&[a1, a2]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("Interface breakdown:"));
    assert!(rendered.contains("eth0"));
    assert!(rendered.contains("wlan0"));
}

// ── Render includes totals section ─────────────────────────────────

#[test]
fn render_includes_totals_section() {
    let a = make_process_attachment("eth0", "a", 1, 100, 200);
    let report = build_ledger_identity_report(&[a]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("Totals:"));
    assert!(rendered.contains("RX: 100 bytes"));
    assert!(rendered.contains("TX: 200 bytes"));
    assert!(rendered.contains("Combined: 300 bytes"));
}

// ── Render includes no daemon/watch ─────────────────────────────────

#[test]
fn render_includes_no_daemon_watch() {
    let report = build_ledger_identity_report(&[]);
    let rendered = render_ledger_identity_report(&report);
    assert!(rendered.contains("no daemon/watch"));
}

// ── Serialization empty report round-trip ───────────────────────────

#[test]
fn serialization_empty_report_round_trip() {
    let report = build_ledger_identity_report(&[]);
    let json = serialize_report_json(&report).unwrap();
    let deserialized: LedgerIdentityReport = deserialize_report_json(&json).unwrap();
    assert_eq!(report, deserialized);
}

// ── Deserialize rejects invalid JSON ────────────────────────────────

#[test]
fn deserialize_rejects_invalid_json() {
    assert!(deserialize_report_json("{not valid").is_err());
    assert!(deserialize_report_json("").is_err());
}

// ── Report with mixed no-identity and identity attachments ─────────

#[test]
fn report_mixed_no_identity_and_identity() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let a1 = build_no_identity_attachment(&e1);
    let a2 = make_process_attachment("eth0", "firefox", 1234, 300, 400);
    let report = build_ledger_identity_report(&[a1, a2]);

    assert_eq!(report.total_attachments, 2);
    assert_eq!(report.no_identity_count, 1);
    assert_eq!(report.process_best_effort_count, 1);
    // eth0 interface aggregates both
    assert_eq!(report.interfaces.len(), 1);
    let eth0 = &report.interfaces[0];
    assert_eq!(eth0.rx_bytes, 400);
    assert_eq!(eth0.tx_bytes, 600);
    assert_eq!(eth0.entry_count, 2);
}

// ── Report with loopback interface ──────────────────────────────────

#[test]
fn report_with_loopback_interface() {
    let entry = make_snapshot_entry("lo", 500, 600);
    let a = build_interface_only_attachment(&entry);
    let report = build_ledger_identity_report(&[a]);

    assert_eq!(report.interfaces.len(), 1);
    assert!(report.interfaces[0].loopback);
    assert!(report.targets[0].loopback);
}
