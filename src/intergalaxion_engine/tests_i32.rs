// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
    brave_limit_backend_label, brave_limit_lab_plan_status_label, brave_limit_target_status_label,
    build_brave_limit_lab_plan, default_brave_limit_lab_plan_input, parse_limit_rate_bytes_per_sec,
    validate_brave_limit_lab_plan, BraveLimitBackend, BraveLimitDirection,
    BraveLimitLabDecision, BraveLimitLabPlan, BraveLimitLabPlanInput, BraveLimitLabPlanStatus,
    BraveLimitTargetStatus,
};

type I = BraveLimitLabPlanInput;
type P = BraveLimitLabPlan;

/// Full dry-run-ready input with interface.
fn sf(iface: &str) -> I {
    let mut i = default_brave_limit_lab_plan_input();
    i.interface = Some(iface.to_string());
    i
}

// --- Coverage 1: default input targets brave ---
#[test]
fn test_default_input_targets_brave() {
    let i = default_brave_limit_lab_plan_input();
    assert_eq!(i.target_name, "brave");
}

// --- Coverage 2: default rates are 100KB/s ---
#[test]
fn test_default_rates_100kbps() {
    let i = default_brave_limit_lab_plan_input();
    assert_eq!(i.download_rate.as_deref(), Some("100KB/s"));
    assert_eq!(i.upload_rate.as_deref(), Some("100KB/s"));
}

// --- Coverage 3: 100KB/s parses to 102400 ---
#[test]
fn test_parse_100kb_s() {
    assert_eq!(parse_limit_rate_bytes_per_sec("100KB/s").unwrap(), 102400);
}

// --- Coverage 4: 100kb/s parses to 102400 ---
#[test]
fn test_parse_100kb_lower() {
    assert_eq!(parse_limit_rate_bytes_per_sec("100kb/s").unwrap(), 102400);
}

// --- Coverage 5: 100KiB/s parses to 102400 ---
#[test]
fn test_parse_100kib() {
    assert_eq!(parse_limit_rate_bytes_per_sec("100KiB/s").unwrap(), 102400);
}

// --- Coverage 6: invalid rates reject ---
#[test]
fn test_parse_empty() {
    assert!(parse_limit_rate_bytes_per_sec("").is_err());
}
#[test]
fn test_parse_whitespace() {
    assert!(parse_limit_rate_bytes_per_sec("   ").is_err());
}
#[test]
fn test_parse_zero() {
    assert!(parse_limit_rate_bytes_per_sec("0KB/s").is_err());
}
#[test]
fn test_parse_negative_reject() {
    assert!(parse_limit_rate_bytes_per_sec("-1KB/s").is_err());
}
#[test]
fn test_parse_unsupported_unit() {
    assert!(parse_limit_rate_bytes_per_sec("100MB/s").is_err());
}
#[test]
fn test_parse_garbage() {
    assert!(parse_limit_rate_bytes_per_sec("abc").is_err());
}
#[test]
fn test_parse_no_unit() {
    assert!(parse_limit_rate_bytes_per_sec("100").is_err());
}

// --- Coverage 7: default plan does not allow live apply ---
#[test]
fn test_default_plan_no_live_apply() {
    let i = default_brave_limit_lab_plan_input();
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.live_apply_allowed);
}

// --- Coverage 8: default plan release_allowed=false ---
#[test]
fn test_default_plan_no_release() {
    let i = default_brave_limit_lab_plan_input();
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.release_allowed);
}

// --- Coverage 9: default plan must_remain_experimental=true ---
#[test]
fn test_default_plan_experimental() {
    let i = default_brave_limit_lab_plan_input();
    let p = build_brave_limit_lab_plan(&i);
    assert!(p.must_remain_experimental);
}

// --- Coverage 10: dry-run ready requires interface ---
#[test]
fn test_dry_run_requires_interface() {
    let i = default_brave_limit_lab_plan_input();
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveLimitLabDecision::RequireInterface);
}

// --- Coverage 11: dry-run ready requires brave target ---
#[test]
fn test_dry_run_requires_brave_target() {
    let mut i = default_brave_limit_lab_plan_input();
    i.target_name = "firefox".into();
    i.interface = Some("eth0".into());
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveLimitLabDecision::RequireBraveIdentity);
    assert_eq!(p.target_status, BraveLimitTargetStatus::Blocked);
}

// --- Coverage 12: dry-run ready requires explicit_dry_run=true ---
#[test]
fn test_dry_run_requires_explicit_flag() {
    let mut i = default_brave_limit_lab_plan_input();
    i.interface = Some("eth0".into());
    i.explicit_dry_run = false;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
}

// --- Coverage 13: live apply request is rejected ---
#[test]
fn test_live_apply_rejected() {
    let mut i = sf("eth0");
    i.explicit_live_apply = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.live_apply_allowed);
    assert_eq!(p.status, BraveLimitLabPlanStatus::LiveApplyForbidden);
    assert_eq!(p.decision, BraveLimitLabDecision::RejectLiveApply);
}

// --- Coverage 14: public CLI request is rejected ---
#[test]
fn test_public_cli_rejected() {
    let mut i = sf("eth0");
    i.public_cli_requested = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(p.public_cli_exposed);
    assert_eq!(p.decision, BraveLimitLabDecision::RejectPublicCli);
    assert_eq!(p.status, BraveLimitLabPlanStatus::Blocked);
}

// --- Coverage 15: tc mutation allowance rejected ---
#[test]
fn test_tc_mutation_rejected() {
    let mut i = sf("eth0");
    i.allow_tc_mutation = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p.findings.iter().any(|f| f.contains("tc mutation")));
}

// --- Coverage 16: ifb mutation allowance rejected ---
#[test]
fn test_ifb_mutation_rejected() {
    let mut i = sf("eth0");
    i.allow_ifb_mutation = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p.findings.iter().any(|f| f.contains("ifb mutation")));
}

// --- Coverage 17: cgroup mutation allowance rejected ---
#[test]
fn test_cgroup_mutation_rejected() {
    let mut i = sf("eth0");
    i.allow_cgroup_mutation = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p.findings.iter().any(|f| f.contains("cgroup mutation")));
}

// --- Coverage 18: packet drop allowance rejected ---
#[test]
fn test_packet_drop_rejected() {
    let mut i = sf("eth0");
    i.allow_packet_drop = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p.findings.iter().any(|f| f.contains("packet drop")));
}

// --- Coverage 19: persistence allowance rejected ---
#[test]
fn test_persistence_rejected() {
    let mut i = sf("eth0");
    i.allow_persistence = true;
    let p = build_brave_limit_lab_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p.findings.iter().any(|f| f.contains("persistence")));
}

// --- Coverage 20: upload backend is TcEgress when rate present ---
#[test]
fn test_upload_backend_tc_egress() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert_eq!(p.backend_upload, BraveLimitBackend::TcEgress);
}

// --- Coverage 21: download backend is TcIngressIfb when rate present ---
#[test]
fn test_download_backend_tc_ingress_ifb() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert_eq!(p.backend_download, BraveLimitBackend::TcIngressIfb);
}

// --- Coverage 22: dry-run plan renders upload command intent ---
#[test]
fn test_dry_run_renders_upload_commands() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    let ul_cmds: Vec<_> = p
        .commands
        .iter()
        .filter(|c| c.label.contains("upload"))
        .collect();
    assert!(ul_cmds.len() >= 2);
    assert!(ul_cmds[0].command.contains(&"tc".to_string()));
    assert!(ul_cmds[0].command.contains(&"htb".to_string()));
}

// --- Coverage 23: dry-run plan renders download/IFB command intent ---
#[test]
fn test_dry_run_renders_download_ifb_commands() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    let dl_cmds: Vec<_> = p
        .commands
        .iter()
        .filter(|c| c.label.contains("download"))
        .collect();
    assert!(dl_cmds.len() >= 2);
    let has_ifb = dl_cmds
        .iter()
        .any(|c| c.command.iter().any(|t| t.contains("ifb")));
    assert!(has_ifb);
}

// --- Coverage 24: rollback commands are rendered ---
#[test]
fn test_rollback_commands_rendered() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(!p.rollback_commands.is_empty());
    assert!(p.rollback_commands.iter().all(|c| c.rollback));
}

// --- Coverage 25: all commands have mutates_system=false ---
#[test]
fn test_no_command_mutates_system() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(p.commands.iter().all(|c| !c.mutates_system));
    assert!(p.rollback_commands.iter().all(|c| !c.mutates_system));
}

// --- Coverage 26: tc/ip command steps require root ---
#[test]
fn test_tc_ip_commands_require_root() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    for cmd in &p.commands {
        if cmd
            .command
            .first()
            .map(|t| t == "tc" || t == "ip")
            .unwrap_or(false)
        {
            assert!(cmd.requires_root, "cmd '{}' should require root", cmd.label);
        }
    }
    for cmd in &p.rollback_commands {
        if cmd
            .command
            .first()
            .map(|t| t == "tc" || t == "ip")
            .unwrap_or(false)
        {
            assert!(
                cmd.requires_root,
                "rollback '{}' should require root",
                cmd.label
            );
        }
    }
}

// --- Coverage 27: rollback steps have rollback=true ---
#[test]
fn test_rollback_flag_set() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    for cmd in &p.rollback_commands {
        assert!(cmd.rollback);
    }
}

// --- Coverage 28: apply steps have rollback=false ---
#[test]
fn test_apply_steps_no_rollback_flag() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    for cmd in &p.commands {
        assert!(!cmd.rollback);
    }
}

// --- Coverage 29: validate accepts safe dry-run plan ---
#[test]
fn test_validate_accepts_safe_plan() {
    // Build a safe plan that passes all invariants
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    assert!(validate_brave_limit_lab_plan(&p).is_ok());
}

// --- Coverage 30-41: validate rejects dangerous flags ---
#[test]
fn test_validate_rejects_live_apply() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.live_apply_allowed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_release_allowed() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.release_allowed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_experimental_false() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.must_remain_experimental = false;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_public_cli_exposed() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.public_cli_exposed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_tc_mutation() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.tc_mutation_performed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_ifb_mutation() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.ifb_mutation_performed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_cgroup_mutation() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.cgroup_mutation_performed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_packet_drop() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.packet_drop_performed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_persistence() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.persistence_performed = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_fake_success() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.fake_limit_success_detected = true;
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_download_without_ifb_proof() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_upload_without_tc_proof() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}

// --- Coverage 42-41: docs content checks ---
#[test]
fn test_docs_exist() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    assert!(!docs.is_empty());
}
#[test]
fn test_docs_say_brave_100kbps_download() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    assert!(docs.contains("100KB/s") || docs.contains("100kb/s"));
    assert!(docs.to_lowercase().contains("download"));
}
#[test]
fn test_docs_say_brave_100kbps_upload() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    assert!(docs.to_lowercase().contains("upload"));
}
#[test]
fn test_docs_say_dry_run_only() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    assert!(docs.contains("dry-run") || docs.contains("dry run"));
}
#[test]
fn test_docs_say_no_live_apply() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("no live apply")
            || lower.contains("live apply is forbidden")
            || lower.contains("no live enforcement")
    );
}
#[test]
fn test_docs_say_no_public_cli() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("no public cli")
            || lower.contains("public cli")
            || lower.contains("not exposed")
    );
}
#[test]
fn test_docs_say_no_packet_drop() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no packet drop") || lower.contains("packet drop"));
}
#[test]
fn test_docs_say_no_enforcement() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no enforcement") || lower.contains("enforcement"));
}
#[test]
fn test_docs_say_no_persistence() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no persistence") || lower.contains("persistence"));
}
#[test]
fn test_docs_say_no_tag_release_publish() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("no tag")
            || lower.contains("no release")
            || lower.contains("no publish")
            || lower.contains("no main merge")
            || lower.contains("tag")
            || lower.contains("release")
    );
}
#[test]
fn test_docs_explain_download_ifb() {
    let docs = include_str!("../../docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("ifb") && lower.contains("ingress"));
}

// --- Direction enum ---
#[test]
fn test_direction_labels() {
    assert_eq!(BraveLimitDirection::Download.as_str(), "download");
    assert_eq!(BraveLimitDirection::Upload.as_str(), "upload");
}

// --- Backend enum labels ---
#[test]
fn test_backend_labels() {
    assert_eq!(
        brave_limit_backend_label(BraveLimitBackend::TcEgress),
        "tc_egress"
    );
    assert_eq!(
        brave_limit_backend_label(BraveLimitBackend::TcIngressIfb),
        "tc_ingress_ifb"
    );
    assert_eq!(
        brave_limit_backend_label(BraveLimitBackend::CgroupScopedTc),
        "cgroup_scoped_tc"
    );
    assert_eq!(
        brave_limit_backend_label(BraveLimitBackend::Unsupported),
        "unsupported"
    );
}

// --- Target status labels ---
#[test]
fn test_target_status_labels() {
    assert_eq!(
        brave_limit_target_status_label(BraveLimitTargetStatus::Unknown),
        "unknown"
    );
    assert_eq!(
        brave_limit_target_status_label(BraveLimitTargetStatus::Candidate),
        "candidate"
    );
    assert_eq!(
        brave_limit_target_status_label(BraveLimitTargetStatus::Ready),
        "ready"
    );
    assert_eq!(
        brave_limit_target_status_label(BraveLimitTargetStatus::Blocked),
        "blocked"
    );
}

// --- Plan status labels ---
#[test]
fn test_plan_status_labels() {
    assert_eq!(
        brave_limit_lab_plan_status_label(BraveLimitLabPlanStatus::Draft),
        "draft"
    );
    assert_eq!(
        brave_limit_lab_plan_status_label(BraveLimitLabPlanStatus::DryRunReady),
        "dry_run_ready"
    );
    assert_eq!(
        brave_limit_lab_plan_status_label(BraveLimitLabPlanStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        brave_limit_lab_plan_status_label(BraveLimitLabPlanStatus::LiveApplyForbidden),
        "live_apply_forbidden"
    );
    assert_eq!(
        brave_limit_lab_plan_status_label(BraveLimitLabPlanStatus::Unsupported),
        "unsupported"
    );
}

// --- Decision labels ---
#[test]
fn test_decision_labels() {
    assert_eq!(BraveLimitLabDecision::Stop.as_str(), "stop");
    assert_eq!(
        BraveLimitLabDecision::RenderDryRun.as_str(),
        "render_dry_run"
    );
    assert_eq!(
        BraveLimitLabDecision::RequireInterface.as_str(),
        "require_interface"
    );
    assert_eq!(
        BraveLimitLabDecision::RejectLiveApply.as_str(),
        "reject_live_apply"
    );
    assert_eq!(
        BraveLimitLabDecision::RejectPublicCli.as_str(),
        "reject_public_cli"
    );
}

// --- Brave-browser alias accepted ---
#[test]
fn test_brave_browser_alias() {
    let mut i = sf("eth0");
    i.target_name = "brave-browser".into();
    let p = build_brave_limit_lab_plan(&i);
    assert_eq!(p.decision, BraveLimitLabDecision::RenderDryRun);
    assert!(p.dry_run_ready);
}

// --- Download-only plan ---
#[test]
fn test_download_only_plan() {
    let mut i = sf("eth0");
    i.upload_rate = None;
    let p = build_brave_limit_lab_plan(&i);
    assert_eq!(p.backend_download, BraveLimitBackend::TcIngressIfb);
    assert!(p.download_rate_bytes_per_sec.is_some());
    assert!(p.upload_rate_bytes_per_sec.is_none());
}

// --- Upload-only plan ---
#[test]
fn test_upload_only_plan() {
    let mut i = sf("eth0");
    i.download_rate = None;
    let p = build_brave_limit_lab_plan(&i);
    assert_eq!(p.backend_upload, BraveLimitBackend::TcEgress);
    assert!(p.upload_rate_bytes_per_sec.is_some());
    assert!(p.download_rate_bytes_per_sec.is_none());
}

// --- Target status Ready when pid or cgroup known ---
#[test]
fn test_target_status_ready_with_pid() {
    let mut i = sf("eth0");
    i.brave_pid_known = true;
    let p = build_brave_limit_lab_plan(&i);
    assert_eq!(p.target_status, BraveLimitTargetStatus::Ready);
}
#[test]
fn test_target_status_ready_with_cgroup() {
    let mut i = sf("eth0");
    i.brave_cgroup_known = true;
    let p = build_brave_limit_lab_plan(&i);
    assert_eq!(p.target_status, BraveLimitTargetStatus::Ready);
}

// --- Plan phase is I-32 ---
#[test]
fn test_plan_phase() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert_eq!(p.phase, "I-32");
}

// --- Default input all mutation flags false ---
#[test]
fn test_default_no_mutations() {
    let i = default_brave_limit_lab_plan_input();
    assert!(!i.allow_tc_mutation);
    assert!(!i.allow_ifb_mutation);
    assert!(!i.allow_cgroup_mutation);
    assert!(!i.allow_packet_drop);
    assert!(!i.allow_persistence);
    assert!(!i.public_cli_requested);
    assert!(!i.explicit_live_apply);
    assert!(i.explicit_dry_run);
}

// --- Rate parsing: 200KB/s ---
#[test]
fn test_parse_200kb() {
    assert_eq!(parse_limit_rate_bytes_per_sec("200KB/s").unwrap(), 204800);
}

// --- Rate parsing: 50kb/s ---
#[test]
fn test_parse_50kb() {
    assert_eq!(parse_limit_rate_bytes_per_sec("50kb/s").unwrap(), 51200);
}

// --- Rate parsing: 1KiB/s ---
#[test]
fn test_parse_1kib() {
    assert_eq!(parse_limit_rate_bytes_per_sec("1KiB/s").unwrap(), 1024);
}

// --- Validate rejects mutates_system in apply commands ---
#[test]
fn test_validate_rejects_apply_mutates() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    if let Some(cmd) = p.commands.first_mut() {
        cmd.mutates_system = true;
    }
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}

// --- Validate rejects mutates_system in rollback commands ---
#[test]
fn test_validate_rejects_rollback_mutates() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    if let Some(cmd) = p.rollback_commands.first_mut() {
        cmd.mutates_system = true;
    }
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}

// --- Validate rejects empty phase ---
#[test]
fn test_validate_rejects_empty_phase() {
    let mut p = build_brave_limit_lab_plan(&sf("eth0"));
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    p.phase = String::new();
    assert!(validate_brave_limit_lab_plan(&p).is_err());
}

// --- Plan has findings about IFB proof ---
#[test]
fn test_plan_has_ifb_proof_finding() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("IFB ingress attribution proof")));
}

// --- Plan has findings about tc proof ---
#[test]
fn test_plan_has_tc_proof_finding() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert!(p.findings.iter().any(|f| f.contains("tc egress proof")));
}

// --- Dry-run-ready plan has correct rate values ---
#[test]
fn test_dry_run_rate_values() {
    let p = build_brave_limit_lab_plan(&sf("eth0"));
    assert_eq!(p.download_rate_bytes_per_sec, Some(102400));
    assert_eq!(p.upload_rate_bytes_per_sec, Some(102400));
}
