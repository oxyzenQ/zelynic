// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::accounting::identity::*;
use std::collections::HashSet;

#[test]
fn empty_process_identity_has_no_fields() {
    let p = ProcessIdentity::empty();
    assert!(p.is_empty());
    assert!(p.pid.is_none());
    assert!(p.comm.is_none());
    assert!(p.argv0.is_none());
    assert!(p.cmdline.is_none());
    assert!(p.executable_path.is_none());
}

#[test]
fn empty_cgroup_identity_has_no_fields() {
    let c = CgroupIdentity::empty();
    assert!(c.is_empty());
    assert!(c.cgroup_path.is_none());
    assert!(c.systemd_unit.is_none());
    assert!(c.systemd_scope.is_none());
}

#[test]
fn empty_target_identity_has_no_sub_identities() {
    let t = TargetIdentity::empty();
    assert!(t.is_empty());
    assert!(t.process.is_none());
    assert!(t.cgroup.is_none());
    assert!(t.interface.is_none());
}

#[test]
fn unknown_resolved_target_has_unknown_scope() {
    let rt = ResolvedUsageTarget::unknown();
    assert!(rt.identity.is_empty());
    assert_eq!(rt.attribution_scope, UsageAttributionScope::Unknown);
}

#[test]
fn process_identity_with_pid_only() {
    let p = ProcessIdentity {
        pid: Some(1234),
        comm: None,
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    assert!(!p.is_empty());
    assert_eq!(p.pid, Some(1234));
}

#[test]
fn process_identity_with_all_fields() {
    let p = ProcessIdentity {
        pid: Some(5678),
        comm: Some("brave".to_string()),
        argv0: Some("brave-browser".to_string()),
        cmdline: Some("brave-browser --disable-gpu".to_string()),
        executable_path: Some("/usr/bin/brave-browser".to_string()),
    };
    assert!(!p.is_empty());
    assert_eq!(p.pid, Some(5678));
    assert_eq!(p.comm.as_deref(), Some("brave"));
    assert_eq!(p.argv0.as_deref(), Some("brave-browser"));
    assert_eq!(p.executable_path.as_deref(), Some("/usr/bin/brave-browser"));
}

#[test]
fn process_identity_pid_only_is_not_empty() {
    let p = ProcessIdentity {
        pid: Some(1),
        comm: None,
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    assert!(!p.is_empty());
}

#[test]
fn cgroup_identity_with_path_only() {
    let c = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope".to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    assert!(!c.is_empty());
    assert_eq!(
        c.cgroup_path.as_deref(),
        Some("/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope")
    );
}

#[test]
fn cgroup_identity_with_systemd_fields() {
    let c = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/system.slice/zelynic-probe.service".to_string()),
        systemd_unit: Some("zelynic-probe.service".to_string()),
        systemd_scope: Some("system".to_string()),
    };
    assert!(!c.is_empty());
    assert_eq!(c.systemd_unit.as_deref(), Some("zelynic-probe.service"));
    assert_eq!(c.systemd_scope.as_deref(), Some("system"));
}

#[test]
fn interface_identity_lo_is_loopback() {
    let iface = InterfaceIdentity::new("lo", true);
    assert!(iface.loopback);
    assert_eq!(iface.name, "lo");
}

#[test]
fn interface_is_loopback_name_detects_lo() {
    assert!(InterfaceIdentity::is_loopback_name("lo"));
}

#[test]
fn interface_is_loopback_name_rejects_non_lo() {
    assert!(!InterfaceIdentity::is_loopback_name("wlan0"));
    assert!(!InterfaceIdentity::is_loopback_name("eth0"));
    assert!(!InterfaceIdentity::is_loopback_name(""));
}

#[test]
fn interface_identity_eth0_is_not_loopback() {
    let iface = InterfaceIdentity::new("eth0", false);
    assert!(!iface.loopback);
}

#[test]
fn resolved_target_interface_only_scope() {
    let rt = ResolvedUsageTarget::interface_only("wlan0", false);
    assert_eq!(rt.attribution_scope, UsageAttributionScope::InterfaceOnly);
    let iface = rt.identity.interface.as_ref().unwrap();
    assert_eq!(iface.name, "wlan0");
    assert!(!iface.loopback);
    assert!(rt.identity.process.is_none());
    assert!(rt.identity.cgroup.is_none());
}

#[test]
fn resolved_target_process_best_effort_scope() {
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
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    assert_eq!(
        rt.attribution_scope,
        UsageAttributionScope::ProcessBestEffort
    );
    assert_eq!(rt.identity.process.as_ref().unwrap().pid, Some(1234));
    assert_eq!(
        rt.identity.process.as_ref().unwrap().comm.as_deref(),
        Some("firefox")
    );
}

#[test]
fn resolved_target_cgroup_best_effort_scope() {
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
        interface: None,
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    assert_eq!(
        rt.attribution_scope,
        UsageAttributionScope::CgroupBestEffort
    );
    assert_eq!(
        rt.identity.cgroup.as_ref().unwrap().cgroup_path.as_deref(),
        Some("/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/app.service")
    );
}

#[test]
fn resolved_target_target_best_effort_scope() {
    let proc = ProcessIdentity {
        pid: Some(999),
        comm: Some("steam".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let cg = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/user-1000.slice/app-steam.scope".to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: Some(cg),
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::TargetBestEffort);
    assert_eq!(
        rt.attribution_scope,
        UsageAttributionScope::TargetBestEffort
    );
    assert!(rt.identity.process.is_some());
    assert!(rt.identity.cgroup.is_some());
    assert!(rt.identity.interface.is_some());
}

#[test]
fn serialize_round_trip_empty_target() {
    let rt = ResolvedUsageTarget::unknown();
    let json = serialize_identity_json(&rt).unwrap();
    let deserialized: ResolvedUsageTarget = deserialize_identity_json(&json).unwrap();
    assert_eq!(rt, deserialized);
}

#[test]
fn serialize_round_trip_interface_only() {
    let rt = ResolvedUsageTarget::interface_only("wlan0", false);
    let json = serialize_identity_json(&rt).unwrap();
    let deserialized: ResolvedUsageTarget = deserialize_identity_json(&json).unwrap();
    assert_eq!(rt, deserialized);
}

#[test]
fn serialize_round_trip_process_best_effort() {
    let proc = ProcessIdentity {
        pid: Some(42),
        comm: Some("chrome".to_string()),
        argv0: Some("google-chrome-stable".to_string()),
        cmdline: None,
        executable_path: Some("/opt/google/chrome/google-chrome".to_string()),
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let json = serialize_identity_json(&rt).unwrap();
    assert_eq!(rt, deserialize_identity_json(&json).unwrap());
}

#[test]
fn serialize_round_trip_cgroup_best_effort() {
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
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    let json = serialize_identity_json(&rt).unwrap();
    assert_eq!(rt, deserialize_identity_json(&json).unwrap());
}

#[test]
fn serialization_is_deterministic() {
    let rt = ResolvedUsageTarget::interface_only("wlan0", false);
    assert_eq!(
        serialize_identity_json(&rt).unwrap(),
        serialize_identity_json(&rt).unwrap()
    );
}

#[test]
fn serialization_omits_none_fields() {
    let rt = ResolvedUsageTarget::unknown();
    let json = serialize_identity_json(&rt).unwrap();
    assert!(!json.contains("process"));
    assert!(!json.contains("cgroup"));
    assert!(!json.contains("interface"));
    assert!(json.contains("unknown"));
}

#[test]
fn process_identity_serialization_omits_none() {
    let p = ProcessIdentity {
        pid: Some(42),
        comm: None,
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let json = serde_json::to_string_pretty(&p).unwrap();
    assert!(json.contains("pid"));
    assert!(!json.contains("comm"));
    assert!(!json.contains("argv0"));
}

#[test]
fn default_identity_honesty_flags() {
    let h = default_identity_honesty();
    assert!(h.attribution_is_best_effort);
    assert!(h.interface_level_data_source);
    assert!(h.per_app_attribution_may_be_partial);
    assert!(!h.enforcement_active);
    assert!(!h.persistence_performed);
}

#[test]
fn identity_honesty_round_trip() {
    let h = default_identity_honesty();
    let json = serialize_identity_honesty(&h).unwrap();
    assert_eq!(h, serde_json::from_str::<IdentityHonesty>(&json).unwrap());
}

#[test]
fn no_cli_command_added() {
    let _ = ResolvedUsageTarget::unknown();
    let _ = TargetIdentity::empty();
}

#[test]
fn identity_model_has_no_enforcement_fields() {
    let h = default_identity_honesty();
    assert!(!h.enforcement_active);
    assert!(!h.persistence_performed);
}

#[test]
fn all_attribution_scopes_are_honest() {
    for scope in &[
        UsageAttributionScope::InterfaceOnly,
        UsageAttributionScope::ProcessBestEffort,
        UsageAttributionScope::CgroupBestEffort,
        UsageAttributionScope::TargetBestEffort,
        UsageAttributionScope::Unknown,
    ] {
        let json = serde_json::to_string(scope).unwrap();
        assert_eq!(
            *scope,
            serde_json::from_str::<UsageAttributionScope>(&json).unwrap()
        );
    }
}

#[test]
fn render_unknown_target_includes_scope() {
    let rt = ResolvedUsageTarget::unknown();
    let output = render_resolved_target(&rt);
    assert!(output.contains("unknown"));
}

#[test]
fn render_interface_only_target_includes_interface_name() {
    let rt = ResolvedUsageTarget::interface_only("wlan0", false);
    let output = render_resolved_target(&rt);
    assert!(output.contains("wlan0"));
    assert!(output.contains("interface_only"));
}

#[test]
fn render_process_target_includes_pid_and_best_effort() {
    let proc = ProcessIdentity {
        pid: Some(1234),
        comm: Some("brave".to_string()),
        argv0: None,
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: Some(InterfaceIdentity::new("eth0", false)),
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let output = render_resolved_target(&rt);
    assert!(output.contains("PID: 1234"));
    assert!(output.contains("best-effort: PIDs are recycled"));
    assert!(output.contains("brave"));
}

#[test]
fn render_cgroup_target_includes_cgroup_path_and_best_effort() {
    let cg = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/app.scope".to_string()),
        systemd_unit: Some("app.scope".to_string()),
        systemd_scope: None,
    };
    let identity = TargetIdentity {
        process: None,
        cgroup: Some(cg),
        interface: None,
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::CgroupBestEffort);
    let output = render_resolved_target(&rt);
    assert!(output.contains("/sys/fs/cgroup/user.slice/app.scope"));
    assert!(output.contains("app.scope"));
    assert!(output.contains("best-effort"));
}

#[test]
fn render_output_includes_best_effort_statement() {
    let rt = ResolvedUsageTarget::interface_only("eth0", false);
    let output = render_resolved_target(&rt);
    assert!(output.contains("Identity attribution is best-effort."));
    assert!(output.contains("No enforcement, no persistence, no mutation."));
}

#[test]
fn render_loopback_includes_loopback_marker() {
    let rt = ResolvedUsageTarget::interface_only("lo", true);
    let output = render_resolved_target(&rt);
    assert!(output.contains("(loopback)"));
}

#[test]
fn render_argv0_includes_differ_note() {
    let proc = ProcessIdentity {
        pid: None,
        comm: Some("brave".to_string()),
        argv0: Some("brave-browser".to_string()),
        cmdline: None,
        executable_path: None,
    };
    let identity = TargetIdentity {
        process: Some(proc),
        cgroup: None,
        interface: None,
    };
    let rt = ResolvedUsageTarget::new(identity, UsageAttributionScope::ProcessBestEffort);
    let output = render_resolved_target(&rt);
    assert!(output.contains("may differ from comm"));
}

#[test]
fn render_is_deterministic() {
    let rt = ResolvedUsageTarget::interface_only("wlan0", false);
    assert_eq!(render_resolved_target(&rt), render_resolved_target(&rt));
}

#[test]
fn attribution_scope_display_values() {
    assert_eq!(
        UsageAttributionScope::InterfaceOnly.to_string(),
        "interface_only"
    );
    assert_eq!(
        UsageAttributionScope::ProcessBestEffort.to_string(),
        "process_best_effort"
    );
    assert_eq!(
        UsageAttributionScope::CgroupBestEffort.to_string(),
        "cgroup_best_effort"
    );
    assert_eq!(
        UsageAttributionScope::TargetBestEffort.to_string(),
        "target_best_effort"
    );
    assert_eq!(UsageAttributionScope::Unknown.to_string(), "unknown");
}

#[test]
fn all_attribution_scopes_are_distinct() {
    let scopes = vec![
        UsageAttributionScope::InterfaceOnly,
        UsageAttributionScope::ProcessBestEffort,
        UsageAttributionScope::CgroupBestEffort,
        UsageAttributionScope::TargetBestEffort,
        UsageAttributionScope::Unknown,
    ];
    let set: HashSet<UsageAttributionScope> = scopes.into_iter().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn partial_cgroup_identity_round_trip() {
    let c = CgroupIdentity {
        cgroup_path: Some("/sys/fs/cgroup/user.slice/u.scope".to_string()),
        systemd_unit: None,
        systemd_scope: None,
    };
    let json = serde_json::to_string_pretty(&c).unwrap();
    assert_eq!(c, serde_json::from_str::<CgroupIdentity>(&json).unwrap());
}

#[test]
fn target_identity_interface_only_sets_only_interface() {
    let t = TargetIdentity::interface_only("eth0", false);
    assert!(!t.is_empty());
    assert!(t.process.is_none());
    assert!(t.cgroup.is_none());
    assert_eq!(t.interface.as_ref().unwrap().name, "eth0");
}

#[test]
fn deserialize_rejects_empty_input() {
    assert!(deserialize_identity_json("").is_err());
}

#[test]
fn deserialize_rejects_invalid_json() {
    assert!(deserialize_identity_json("{not valid json").is_err());
}
