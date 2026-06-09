// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure ledger-identity alignment tests for v3.1 phase 3.
//!
//! All tests use in-memory structs — **no** filesystem reads or writes,
//! **no** live `/proc/net/dev` reads, **no** live sysfs reads, **no**
//! network blocking, **no** quota enforcement, **no** eBPF, **no** PID
//! movement, **no** cgroup writes, **no** CLI command, **no** persistence
//! write enabled.

use crate::accounting::identity::*;
use crate::accounting::ledger::{
    add_session_delta_entry, add_snapshot_entry, new_empty_ledger, LedgerEntry,
};
use crate::accounting::ledger_identity::{
    build_identity_attachment, build_interface_only_attachment, build_no_identity_attachment,
    render_identity_summary, render_ledger_identity_attachment, LedgerIdentityAttachment,
};

fn make_snapshot_entry(interface: &str) -> LedgerEntry {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-test");
    add_snapshot_entry(
        &mut ledger,
        "entry-snap-001",
        "2026-06-06T10:00:00Z",
        "model-only",
        interface,
        1000,
        2000,
        Some(10),
        Some(20),
        false,
        vec![],
    );
    ledger.entries.into_iter().next().unwrap()
}

fn make_delta_entry(interface: &str) -> LedgerEntry {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-test");
    add_session_delta_entry(
        &mut ledger,
        "entry-delta-001",
        "2026-06-06T12:00:00Z",
        "session-delta",
        interface,
        500,
        150,
        Some(5),
        Some(3),
        false,
        vec![],
    );
    ledger.entries.into_iter().next().unwrap()
}

// ── Old ledger entries without identity still work ──────────────────

#[test]
fn old_ledger_entry_without_identity_still_works() {
    let entry = make_snapshot_entry("wlan0");
    let att = build_no_identity_attachment(&entry);
    assert!(att.identity.is_none());
    assert_eq!(att.entry.entry_id, "entry-snap-001");
    assert_eq!(att.entry.interface, "wlan0");
    assert!(att.honesty.attribution_is_best_effort);
}

#[test]
fn old_ledger_entry_deserializes_without_identity_field() {
    let json = r#"{
        "schema_version": 1,
        "created_at": "2026-06-06T10:00:00Z",
        "updated_at": "2026-06-06T10:00:00Z",
        "host_id": "h",
        "entries": [{
            "entry_id": "e-old",
            "timestamp": "2026-06-06T10:00:00Z",
            "entry_type": "snapshot",
            "source_label": "model-only",
            "interface": "eth0",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "combined_bytes": 300,
            "reset_detected": false,
            "reset_details": [],
            "read_only": true,
            "provenance": "read-only parsed snapshot",
            "attribution_scope": "interface-level only",
            "enforcement_status": "inactive/not implemented"
        }]
    }"#;
    let ledger = crate::accounting::ledger::deserialize_ledger_from_json(json).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    let entry = &ledger.entries[0];
    assert_eq!(entry.interface, "eth0");
    assert_eq!(entry.attribution_scope, "interface-level only");
    let att = build_no_identity_attachment(entry);
    assert!(att.identity.is_none());
}

// ── Interface-only identity ──────────────────────────────────────────

#[test]
fn ledger_entry_with_interface_only_identity() {
    let entry = make_snapshot_entry("wlan0");
    let att = build_interface_only_attachment(&entry);
    assert!(att.identity.is_some());
    let resolved = att.identity.as_ref().unwrap();
    assert_eq!(
        resolved.attribution_scope,
        UsageAttributionScope::InterfaceOnly
    );
    assert_eq!(resolved.identity.interface.as_ref().unwrap().name, "wlan0");
    assert!(!resolved.identity.interface.as_ref().unwrap().loopback);
    assert!(resolved.identity.process.is_none());
    assert!(resolved.identity.cgroup.is_none());
}

#[test]
fn ledger_entry_loopback_interface_only_identity() {
    let entry = make_snapshot_entry("lo");
    let att = build_interface_only_attachment(&entry);
    let resolved = att.identity.as_ref().unwrap();
    assert_eq!(
        resolved.attribution_scope,
        UsageAttributionScope::InterfaceOnly
    );
    assert!(resolved.identity.interface.as_ref().unwrap().loopback);
}

#[test]
fn delta_entry_with_interface_only_identity() {
    let entry = make_delta_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    let resolved = att.identity.as_ref().unwrap();
    assert_eq!(
        resolved.attribution_scope,
        UsageAttributionScope::InterfaceOnly
    );
    assert_eq!(resolved.identity.interface.as_ref().unwrap().name, "eth0");
    assert_eq!(att.entry.entry_type, "delta");
}

// ── Process best-effort identity ────────────────────────────────────

#[test]
fn ledger_entry_with_process_best_effort_identity() {
    let entry = make_snapshot_entry("wlan0");
    let proc = ProcessIdentity {
        pid: Some(1234),
        comm: Some("firefox".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: Some("/usr/bin/firefox".to_string()),
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("wlan0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let att = build_identity_attachment(&entry, resolved);

    assert!(att.identity.is_some());
    let r = att.identity.as_ref().unwrap();
    assert_eq!(
        r.attribution_scope,
        UsageAttributionScope::ProcessBestEffort
    );
    assert_eq!(r.identity.process.as_ref().unwrap().pid, Some(1234));
    assert_eq!(
        r.identity.process.as_ref().unwrap().comm.as_deref(),
        Some("firefox")
    );
    assert!(r.identity.cgroup.is_none());
}

// ── Cgroup best-effort identity ──────────────────────────────────────

#[test]
fn ledger_entry_with_cgroup_best_effort_identity() {
    let entry = make_snapshot_entry("wlan0");
    let cg = CgroupIdentity {
        cgroup_path: Some(
            "/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/app.service".to_string(),
        ),
        systemd_unit: Some("app.service".to_string()),
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new("wlan0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    let att = build_identity_attachment(&entry, resolved);

    assert!(att.identity.is_some());
    let r = att.identity.as_ref().unwrap();
    assert_eq!(r.attribution_scope, UsageAttributionScope::CgroupBestEffort);
    assert_eq!(
        r.identity.cgroup.as_ref().unwrap().cgroup_path.as_deref(),
        Some("/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/app.service")
    );
    assert!(r.identity.process.is_none());
}

// ── Serialization round-trip with identity ───────────────────────────

#[test]
fn serialization_round_trip_with_interface_identity() {
    let entry = make_snapshot_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    let resolved = att.identity.as_ref().unwrap();
    let json = serialize_identity_json(resolved).unwrap();
    let deserialized: ResolvedUsageTarget = deserialize_identity_json(&json).unwrap();
    assert_eq!(*resolved, deserialized);
}

#[test]
fn serialization_round_trip_with_process_identity() {
    let _entry = make_snapshot_entry("wlan0");
    let proc = ProcessIdentity {
        pid: Some(42),
        comm: Some("chrome".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("wlan0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let json = serialize_identity_json(&resolved).unwrap();
    let deserialized: ResolvedUsageTarget = deserialize_identity_json(&json).unwrap();
    assert_eq!(resolved, deserialized);
}

#[test]
fn serialization_round_trip_with_cgroup_identity() {
    let cg = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/system.slice/sshd.service".to_string()),
        systemd_unit: Some("sshd.service".to_string()),
        systemd_scope: Some("system".to_string()),
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: None,
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    let json = serialize_identity_json(&resolved).unwrap();
    let deserialized: ResolvedUsageTarget = deserialize_identity_json(&json).unwrap();
    assert_eq!(resolved, deserialized);
}

// ── Serialization determinism ────────────────────────────────────────

#[test]
fn serialization_is_deterministic_for_attachment() {
    let entry = make_snapshot_entry("eth0");
    let att1 = build_interface_only_attachment(&entry);
    let att2 = build_interface_only_attachment(&entry);
    let json1 = serialize_identity_json(att1.identity.as_ref().unwrap()).unwrap();
    let json2 = serialize_identity_json(att2.identity.as_ref().unwrap()).unwrap();
    assert_eq!(json1, json2);
}

// ── No live /proc reads in tests ────────────────────────────────────

#[test]
fn no_live_proc_reads_in_tests_structural() {
    let entry = make_snapshot_entry("eth0");
    let _att = build_interface_only_attachment(&entry);
    let _att2 = build_no_identity_attachment(&entry);
}

// ── No filesystem read/write APIs added ──────────────────────────────

#[test]
fn no_filesystem_apis_added_structural() {
    let entry = make_snapshot_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(!rendered.contains("/proc/net/dev"));
    assert!(!rendered.contains("/sys/fs/cgroup"));
    assert!(!rendered.contains(".json"));
}

// ── No CLI command added ────────────────────────────────────────────

#[test]
fn no_cli_command_added_structural() {
    let entry = make_snapshot_entry("eth0");
    let _att = build_interface_only_attachment(&entry);
    let _att2 = build_no_identity_attachment(&entry);
}

// ── No persistence enabled ──────────────────────────────────────────

#[test]
fn no_persistence_enabled() {
    let entry = make_snapshot_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    assert!(!att.honesty.persistence_performed);
    assert!(att.honesty.attribution_is_best_effort);
}

// ── No enforcement flags active ──────────────────────────────────────

#[test]
fn no_enforcement_flags_active() {
    let entry = make_snapshot_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    assert!(!att.honesty.enforcement_active);

    let proc = ProcessIdentity {
        pid: Some(1),
        comm: Some("init".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let att2 = build_identity_attachment(&entry, resolved);
    assert!(!att2.honesty.enforcement_active);
}

// ── Render/inspect output says identity attribution is best-effort ──

#[test]
fn render_interface_only_says_interface_level_only() {
    let entry = make_snapshot_entry("eth0");
    let att = build_no_identity_attachment(&entry);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("interface-level only"));
    assert!(rendered.contains("no per-app identity"));
}

#[test]
fn render_with_identity_says_best_effort() {
    let entry = make_snapshot_entry("wlan0");
    let att = build_interface_only_attachment(&entry);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("best-effort"));
    assert!(rendered.contains("Identity attribution is best-effort."));
}

#[test]
fn render_with_process_identity_includes_pid() {
    let entry = make_snapshot_entry("eth0");
    let proc = ProcessIdentity {
        pid: Some(999),
        comm: Some("steam".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let att = build_identity_attachment(&entry, resolved);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("PID: 999"));
    assert!(rendered.contains("PIDs are recycled"));
    assert!(rendered.contains("steam"));
    assert!(rendered.contains("best-effort"));
}

#[test]
fn render_with_cgroup_identity_includes_cgroup_path() {
    let entry = make_snapshot_entry("wlan0");
    let cg = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/app.scope".to_string()),
        systemd_unit: Some("app.scope".to_string()),
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new("wlan0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    let att = build_identity_attachment(&entry, resolved);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("/sys/fs/cgroup/user.slice/app.scope"));
    assert!(rendered.contains("app.scope"));
    assert!(rendered.contains("best-effort"));
}

#[test]
fn render_no_enforcement_no_persistence() {
    let entry = make_snapshot_entry("eth0");
    let att = build_interface_only_attachment(&entry);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("No enforcement, no persistence, no mutation."));
}

#[test]
fn render_loopback_includes_loopback_marker() {
    let entry = make_snapshot_entry("lo");
    let att = build_interface_only_attachment(&entry);
    let rendered = render_ledger_identity_attachment(&att);
    assert!(rendered.contains("(loopback)"));
}

// ── Summary render ──────────────────────────────────────────────────

#[test]
fn render_summary_empty() {
    let attachments: Vec<LedgerIdentityAttachment> = vec![];
    let rendered = render_identity_summary(&attachments);
    assert!(rendered.contains("0 entries"));
    assert!(rendered.contains("Without identity (interface-only): 0"));
}

#[test]
fn render_summary_mixed() {
    let entry1 = make_snapshot_entry("eth0");
    let entry2 = make_snapshot_entry("wlan0");
    let att1 = build_interface_only_attachment(&entry1);
    let att2 = build_no_identity_attachment(&entry2);
    let rendered = render_identity_summary(&[att1, att2]);
    assert!(rendered.contains("2 entries"));
    assert!(rendered.contains("With identity (best-effort): 1"));
    assert!(rendered.contains("Without identity (interface-only): 1"));
    assert!(rendered.contains("interface_only"));
    assert!(rendered.contains("interface-level only"));
}

#[test]
fn render_summary_all_with_identity() {
    let e1 = make_snapshot_entry("eth0");
    let e2 = make_snapshot_entry("wlan0");
    let a1 = build_interface_only_attachment(&e1);
    let a2 = build_interface_only_attachment(&e2);
    let rendered = render_identity_summary(&[a1, a2]);
    assert!(rendered.contains("With identity (best-effort): 2"));
    assert!(rendered.contains("Without identity (interface-only): 0"));
}

#[test]
fn render_summary_includes_best_effort_disclaimer() {
    let e1 = make_snapshot_entry("eth0");
    let a1 = build_interface_only_attachment(&e1);
    let rendered = render_identity_summary(&[a1]);
    assert!(rendered.contains("All identity attribution is best-effort."));
    assert!(rendered.contains("No enforcement, no persistence, no mutation."));
}

// ── Existing ledger behavior remains backward compatible ─────────────

#[test]
fn existing_ledger_json_deserializes_unchanged() {
    let mut ledger = new_empty_ledger("2026-06-06T10:00:00Z", "host-test");
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
    let json = crate::accounting::ledger::serialize_ledger_to_json(&ledger).unwrap();
    let restored = crate::accounting::ledger::deserialize_ledger_from_json(&json).unwrap();
    assert_eq!(restored, ledger);
    assert!(!json.contains("identity"));
    assert!(!json.contains("ResolvedUsageTarget"));
}

#[test]
fn attachment_does_not_mutate_original_entry() {
    let entry = make_snapshot_entry("wlan0");
    let original_interface = entry.interface.clone();
    let original_entry_type = entry.entry_type.clone();
    let original_attribution = entry.attribution_scope.clone();

    let _att = build_interface_only_attachment(&entry);

    assert_eq!(entry.interface, original_interface);
    assert_eq!(entry.entry_type, original_entry_type);
    assert_eq!(entry.attribution_scope, original_attribution);
}

// ── TargetBestEffort combined identity ───────────────────────────────

#[test]
fn ledger_entry_with_target_best_effort_identity() {
    let entry = make_snapshot_entry("eth0");
    let proc = ProcessIdentity {
        pid: Some(500),
        comm: Some("spotify".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let cg = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/u-500.slice".to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let resolved = ResolvedUsageTarget::new(identity, UsageAttributionScope::TargetBestEffort);
    let att = build_identity_attachment(&entry, resolved);

    assert!(att.identity.is_some());
    let r = att.identity.as_ref().unwrap();
    assert_eq!(r.attribution_scope, UsageAttributionScope::TargetBestEffort);
    assert!(r.identity.process.is_some());
    assert!(r.identity.cgroup.is_some());
    assert!(r.identity.interface.is_some());
    assert!(!att.honesty.enforcement_active);
    assert!(!att.honesty.persistence_performed);
}
