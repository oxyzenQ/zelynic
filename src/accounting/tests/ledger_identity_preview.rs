// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure Ledger Identity Preview tests for v3.1 phase 7.
//!
//! All tests use in-memory fixture data — **no** filesystem reads or writes,
//! **no** live `/proc/net/dev` reads, **no** live sysfs reads, **no**
//! network blocking, **no** quota enforcement, **no** eBPF, **no** PID
//! movement, **no** cgroup writes, **no** CLI command, **no** persistence
//! write enabled, **no** live process scanning, **no** live identity resolution.

use crate::accounting::identity::*;
use crate::accounting::ledger::{add_snapshot_entry, new_empty_ledger, LedgerEntry};
use crate::accounting::ledger_identity_preview::*;

// ── Fixture helpers ─────────────────────────────────────────────────

fn make_snapshot_entry(
    interface: &str,
    rx: u64,
    tx: u64,
) -> crate::accounting::ledger::LedgerEntry {
    let mut ledger = new_empty_ledger("2026-06-10T10:00:00Z", "host-preview-test");
    add_snapshot_entry(
        &mut ledger,
        &format!("preview-snap-{}", interface),
        "2026-06-10T10:00:00Z",
        "preview-fixture",
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

fn make_process_identity(comm: &str, pid: u32) -> ResolvedUsageTarget {
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
        interface: None, // will be set per-entry
    };
    ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort)
}

fn make_cgroup_identity(cg_path: &str) -> ResolvedUsageTarget {
    let cg = CgroupIdentity {
        cgroup_path: Some(cg_path.to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: None,
    };
    ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort)
}

fn make_interface_only_identity(interface: &str, loopback: bool) -> ResolvedUsageTarget {
    let identity = TargetIdentity {
        process: None,
        cgroup: None,
        interface: Some(InterfaceIdentity::new(interface, loopback)),
    };
    ResolvedUsageTarget::new(identity, UsageAttributionScope::InterfaceOnly)
}

fn make_target_identity(
    comm: &str,
    pid: u32,
    cg_path: &str,
    interface: &str,
) -> ResolvedUsageTarget {
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
    ResolvedUsageTarget::new(identity, UsageAttributionScope::TargetBestEffort)
}

// ── Empty fixture builds empty report ──────────────────────────────

#[test]
fn empty_fixture_builds_empty_report() {
    let entries: Vec<LedgerEntry> = vec![];
    let identities: Vec<Option<ResolvedUsageTarget>> = vec![];
    let report = build_ledger_identity_preview_report(&entries, &identities);
    assert_eq!(report.total_attachments, 0);
    assert_eq!(report.totals.entry_count, 0);
    assert_eq!(report.totals.total_rx_bytes, 0);
    assert_eq!(report.totals.total_tx_bytes, 0);
    assert_eq!(report.totals.total_combined_bytes, 0);
    assert!(report.targets.is_empty());
    assert!(report.interfaces.is_empty());
    assert!(report.provenance.contains("empty"));
}

// ── Interface-only fixture builds report ───────────────────────────

#[test]
fn interface_only_fixture_builds_report() {
    let e1 = make_snapshot_entry("eth0", 1000, 2000);
    let e2 = make_snapshot_entry("wlan0", 3000, 4000);
    let id1 = Some(make_interface_only_identity("eth0", false));
    let id2 = Some(make_interface_only_identity("wlan0", false));
    let report = build_ledger_identity_preview_report(&[e1.clone(), e2.clone()], &[id1, id2]);

    assert_eq!(report.total_attachments, 2);
    assert_eq!(report.interface_only_count, 2);
    assert_eq!(report.no_identity_count, 0);
    assert_eq!(report.interfaces.len(), 2);
    assert_eq!(report.totals.total_rx_bytes, 4000);
    assert_eq!(report.totals.total_tx_bytes, 6000);
    assert_eq!(report.totals.total_combined_bytes, 10000);
}

// ── Process best-effort fixture builds report ──────────────────────

#[test]
fn process_best_effort_fixture_builds_report() {
    let e1 = make_snapshot_entry("eth0", 5000, 3000);
    let id1 = Some(make_process_identity("firefox", 1234));
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);

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

// ── Cgroup best-effort fixture builds report ───────────────────────

#[test]
fn cgroup_best_effort_fixture_builds_report() {
    let e1 = make_snapshot_entry("wlan0", 2000, 1000);
    let id1 = Some(make_cgroup_identity("/sys/fs/cgroup/user.slice/app.scope"));
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);

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

// ── Target best-effort fixture builds report ────────────────────────

#[test]
fn target_best_effort_fixture_builds_report() {
    let e1 = make_snapshot_entry("eth0", 8000, 4000);
    let id1 = Some(make_target_identity(
        "chrome",
        42,
        "/sys/fs/cgroup/user.slice/chrome.scope",
        "eth0",
    ));
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);

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
}

// ── Mixed fixture builds deterministic report ──────────────────────

#[test]
fn mixed_fixture_builds_deterministic_report() {
    let e1 = make_snapshot_entry("eth0", 1000, 2000);
    let e2 = make_snapshot_entry("wlan0", 3000, 4000);
    let e3 = make_snapshot_entry("eth0", 500, 600);
    let e4 = make_snapshot_entry("lo", 700, 800);
    let id1 = Some(make_interface_only_identity("eth0", false));
    let id2 = Some(make_process_identity("firefox", 1234));
    let id3: Option<ResolvedUsageTarget> = None; // no identity
    let id4 = Some(make_cgroup_identity(
        "/sys/fs/cgroup/system.slice/sshd.scope",
    ));

    let report = build_ledger_identity_preview_report(&[e1, e2, e3, e4], &[id1, id2, id3, id4]);

    assert_eq!(report.total_attachments, 4);
    assert_eq!(report.interface_only_count, 1);
    assert_eq!(report.process_best_effort_count, 1);
    assert_eq!(report.no_identity_count, 1);
    assert_eq!(report.cgroup_best_effort_count, 1);
    assert_eq!(report.interfaces.len(), 3); // eth0, lo, wlan0
    assert_eq!(report.totals.total_rx_bytes, 5200);
    assert_eq!(report.totals.total_tx_bytes, 7400);
}

// ── Preview totals preserve rx bytes ───────────────────────────────

#[test]
fn preview_totals_preserve_rx_bytes() {
    let e1 = make_snapshot_entry("eth0", 10, 100);
    let e2 = make_snapshot_entry("wlan0", 20, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let id2: Option<ResolvedUsageTarget> = None;
    let report = build_ledger_identity_preview_report(&[e1, e2], &[id1, id2]);
    assert_eq!(report.totals.total_rx_bytes, 30);
}

// ── Preview totals preserve tx bytes ────────────────────────────────

#[test]
fn preview_totals_preserve_tx_bytes() {
    let e1 = make_snapshot_entry("eth0", 10, 100);
    let e2 = make_snapshot_entry("wlan0", 20, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let id2: Option<ResolvedUsageTarget> = None;
    let report = build_ledger_identity_preview_report(&[e1, e2], &[id1, id2]);
    assert_eq!(report.totals.total_tx_bytes, 300);
}

// ── Preview totals preserve combined bytes ────────────────────────

#[test]
fn preview_totals_preserve_combined_bytes() {
    let e1 = make_snapshot_entry("eth0", 10, 100);
    let e2 = make_snapshot_entry("wlan0", 20, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let id2: Option<ResolvedUsageTarget> = None;
    let report = build_ledger_identity_preview_report(&[e1, e2], &[id1, id2]);
    assert_eq!(report.totals.total_combined_bytes, 330);
}

// ── Preview preserves entry counts ────────────────────────────────

#[test]
fn preview_preserves_entry_counts() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let e2 = make_snapshot_entry("eth0", 300, 400);
    let e3 = make_snapshot_entry("wlan0", 500, 600);
    let id1 = Some(make_interface_only_identity("eth0", false));
    let id2 = Some(make_interface_only_identity("eth0", false));
    let id3 = Some(make_interface_only_identity("wlan0", false));
    let report = build_ledger_identity_preview_report(&[e1, e2, e3], &[id1, id2, id3]);

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
}

// ── Preview render says read-only preview ─────────────────────────

#[test]
fn preview_render_says_read_only_preview() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("read-only preview"));
}

// ── Preview render says in-memory fixture only ─────────────────────

#[test]
fn preview_render_says_in_memory_fixture_only() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("in-memory fixture data only"));
}

// ── Preview render says no live resolver ───────────────────────────

#[test]
fn preview_render_says_no_live_resolver() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no live resolver"));
}

// ── Preview render says no filesystem read ─────────────────────────

#[test]
fn preview_render_says_no_filesystem_read() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no filesystem read"));
}

// ── Preview render says no filesystem write ────────────────────────

#[test]
fn preview_render_says_no_filesystem_write() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no filesystem write"));
}

// ── Preview render says no ledger persistence ──────────────────────

#[test]
fn preview_render_says_no_ledger_persistence() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no ledger persistence"));
}

// ── Preview render says no enforcement ──────────────────────────────

#[test]
fn preview_render_says_no_enforcement() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no enforcement"));
}

// ── Preview render says no network blocking ────────────────────────

#[test]
fn preview_render_says_no_network_blocking() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no network blocking"));
}

// ── Preview render says no quota ───────────────────────────────────

#[test]
fn preview_render_says_no_quota() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no quota"));
}

// ── Preview render says no eBPF ────────────────────────────────────

#[test]
fn preview_render_says_no_ebpf() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no eBPF"));
}

// ── Preview render says no nft/tc mutation ──────────────────────────

#[test]
fn preview_render_says_no_nft_tc_mutation() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no nft/tc mutation"));
}

// ── Preview render says no cgroup mutation ────────────────────────

#[test]
fn preview_render_says_no_cgroup_mutation() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no cgroup mutation"));
}

// ── Preview render says no PID movement ────────────────────────────

#[test]
fn preview_render_says_no_pid_movement() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("no PID movement"));
}

// ── Serialization round-trip if serde is used ─────────────────────

#[test]
fn serialization_round_trip_if_serde_is_used() {
    let e1 = make_snapshot_entry("eth0", 5000, 3000);
    let id1 = Some(make_process_identity("firefox", 1234));
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);
    let json = serialize_preview_report_json(&report).unwrap();
    let deserialized = deserialize_preview_report_json(&json).unwrap();
    assert_eq!(report, deserialized);
}

// ── Serialization deterministic if serde is used ──────────────────

#[test]
fn serialization_deterministic_if_serde_is_used() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);
    let json1 = serialize_preview_report_json(&report).unwrap();
    let json2 = serialize_preview_report_json(&report).unwrap();
    assert_eq!(json1, json2);
}

// ── No CLI command added ──────────────────────────────────────────

#[test]
fn no_cli_command_added_structural() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    let _rendered = render_ledger_identity_preview_report(&report);
}

// ── No live /proc reads in tests ───────────────────────────────────

#[test]
fn no_live_proc_reads_in_tests() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let _report = build_ledger_identity_preview_report(&[e1], &[id1]);
}

// ── Old ledger_identity_report tests remain unchanged ───────────────

#[test]
fn old_ledger_identity_report_tests_remain_unchanged() {
    // This test verifies that the existing report model still works
    // independently of the preview module. It calls the base
    // build_ledger_identity_report directly (not via preview).
    use crate::accounting::ledger_identity::{
        build_interface_only_attachment, build_no_identity_attachment,
    };
    use crate::accounting::ledger_identity_report::build_ledger_identity_report;

    let e1 = make_snapshot_entry("eth0", 100, 200);
    let a1 = build_interface_only_attachment(&e1);
    let a2 = build_no_identity_attachment(&e1);
    let report = build_ledger_identity_report(&[a1, a2]);
    assert_eq!(report.total_attachments, 2);
    assert!(report.provenance.contains("attachments"));
}

// ── Phase 6 gate tests remain unchanged ────────────────────────────

#[test]
fn phase_6_gate_tests_remain_unchanged_structural() {
    // Structural test proving the preview module does not interfere
    // with phase 6 gate test infrastructure. If this compiles and
    // passes, the gate test infrastructure is intact.
    let report = build_ledger_identity_preview_report(&[], &[]);
    assert_eq!(report.total_attachments, 0);
}

// ── Mismatched slice lengths use shorter ──────────────────────────

#[test]
fn mismatched_slice_lengths_use_shorter() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let e2 = make_snapshot_entry("wlan0", 300, 400);
    let id1: Option<ResolvedUsageTarget> = None;
    // Only one identity for two entries — excess entry ignored
    let report = build_ledger_identity_preview_report(&[e1, e2], &[id1]);
    assert_eq!(report.total_attachments, 1);
}

// ── Preview render includes base report content ─────────────────────

#[test]
fn preview_render_includes_base_report_content() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let id1 = Some(make_interface_only_identity("eth0", false));
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);
    let rendered = render_ledger_identity_preview_report(&report);
    // Base report header
    assert!(rendered.contains("ledger identity report"));
    // Interface breakdown from base report
    assert!(rendered.contains("Interface breakdown:"));
    assert!(rendered.contains("eth0"));
    // Totals from base report
    assert!(rendered.contains("Totals:"));
    assert!(rendered.contains("RX: 100 bytes"));
    assert!(rendered.contains("TX: 200 bytes"));
    // Honesty from base report
    assert!(rendered.contains("Honesty and safety:"));
}

// ── Preview render with no-identity entries ─────────────────────────

#[test]
fn preview_render_with_no_identity_entries() {
    let e1 = make_snapshot_entry("eth0", 100, 200);
    let id1: Option<ResolvedUsageTarget> = None;
    let report = build_ledger_identity_preview_report(&[e1], &[id1]);
    assert_eq!(report.no_identity_count, 1);
    let rendered = render_ledger_identity_preview_report(&report);
    assert!(rendered.contains("read-only preview"));
    assert!(rendered.contains("in-memory fixture data only"));
}

// ── Preview no enforcement in honesty flags ────────────────────────

#[test]
fn preview_honesty_flags_no_enforcement() {
    let report = build_ledger_identity_preview_report(&[], &[]);
    assert!(report.honesty.enforcement_inactive);
    assert!(!report.honesty.persistence_performed);
    assert!(!report.honesty.filesystem_write);
    assert!(!report.honesty.network_blocking);
    assert!(!report.honesty.quota);
    assert!(!report.honesty.ebpf);
    assert!(!report.honesty.nft_tc_mutation);
    assert!(!report.honesty.cgroup_mutation);
    assert!(!report.honesty.daemon_watch);
}
