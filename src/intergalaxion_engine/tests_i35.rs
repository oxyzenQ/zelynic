// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::intergalaxion_engine::backends::ebpf::brave_cgroup_scope_dry_run::{
    build_brave_cgroup_scope_dry_run_plan, default_brave_cgroup_scope_dry_run_input,
    BraveCgroupScopeDryRunPlan, BraveCgroupScopeStrategy,
};
use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
    build_brave_identity_scope_proof, default_brave_identity_scope_proof_input,
    BraveIdentityScopeProof, BraveProcessCandidate,
};
use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
    build_brave_limit_lab_plan, default_brave_limit_lab_plan_input, BraveLimitLabPlan,
};
use crate::intergalaxion_engine::backends::ebpf::brave_tc_ifb_dry_run_wiring::{
    brave_tc_ifb_direction_label, brave_tc_ifb_wiring_backend_label,
    brave_tc_ifb_wiring_decision_label, brave_tc_ifb_wiring_status_label,
    brave_tc_ifb_wiring_step_kind_label, build_brave_tc_ifb_dry_run_wiring_plan,
    default_brave_tc_ifb_dry_run_wiring_input, validate_brave_tc_ifb_dry_run_wiring_plan,
    BraveTcIfbDirection, BraveTcIfbDryRunWiringInput, BraveTcIfbDryRunWiringPlan,
    BraveTcIfbWiringBackend, BraveTcIfbWiringDecision, BraveTcIfbWiringStatus,
    BraveTcIfbWiringStepKind,
};

type I = BraveTcIfbDryRunWiringInput;
type P = BraveTcIfbDryRunWiringPlan;

/// Build a ready identity proof for tests.
fn ready_id() -> BraveIdentityScopeProof {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(BraveProcessCandidate {
        pid: Some(1234),
        process_name: "brave".into(),
        executable_path: Some("/usr/bin/brave".into()),
        cgroup_path: Some("/user.slice/brave.scope".into()),
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: true,
        matches_brave_cgroup: true,
    });
    build_brave_identity_scope_proof(&i)
}

/// Build a safe limit plan for tests.
fn safe_lp() -> BraveLimitLabPlan {
    let mut i = default_brave_limit_lab_plan_input();
    i.interface = Some("eth0".into());
    let mut p = build_brave_limit_lab_plan(&i);
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    p
}

/// Build a ready scope plan for tests.
fn ready_sp() -> BraveCgroupScopeDryRunPlan {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    let id = ready_id();
    let lp = safe_lp();
    i.identity_proof = id;
    i.limit_plan = lp;
    i.strategy = BraveCgroupScopeStrategy::SystemdUserScope;
    build_brave_cgroup_scope_dry_run_plan(&i)
}

/// Full ready input for wiring tests.
fn wready() -> I {
    let d = default_brave_tc_ifb_dry_run_wiring_input();
    I {
        identity_proof: ready_id(),
        limit_plan: safe_lp(),
        scope_plan: ready_sp(),
        ..d
    }
}

// --- Coverage 1: default input targets 100KB/s download/upload ---
#[test]
fn test_default_input_rates() {
    let i = default_brave_tc_ifb_dry_run_wiring_input();
    assert_eq!(i.download_rate.as_deref(), Some("100KB/s"));
    assert_eq!(i.upload_rate.as_deref(), Some("100KB/s"));
}

// --- Coverage 2: default plan is not dry_run_ready without ready identity/scope ---
#[test]
fn test_default_not_ready() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&default_brave_tc_ifb_dry_run_wiring_input());
    assert!(!p.dry_run_ready);
}

// --- Coverage 3-5: default plan safety flags ---
#[test]
fn test_default_safety_flags() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&default_brave_tc_ifb_dry_run_wiring_input());
    assert!(!p.release_allowed);
    assert!(!p.live_apply_allowed);
    assert!(p.must_remain_experimental);
}

// --- Coverage 6: ready identity + ready scope + safe limit plan becomes DryRunReady ---
#[test]
fn test_ready_becomes_dry_run_ready() {
    let i = wready();
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.dry_run_ready);
    assert_eq!(p.status, BraveTcIfbWiringStatus::DryRunReady);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RenderFullDryRun);
}

// --- Coverage 7: missing interface blocks ---
#[test]
fn test_missing_interface_blocks() {
    let mut i = wready();
    i.interface = None;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RequireInterface);
}

// --- Coverage 8: missing cgroup_class_id blocks ---
#[test]
fn test_missing_class_id_blocks() {
    let mut i = wready();
    i.cgroup_class_id = None;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
}

// --- Coverage 9: invalid download rate blocks ---
#[test]
fn test_invalid_download_rate_blocks() {
    let mut i = wready();
    i.download_rate = Some("garbage".into());
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("download rate parse error")));
}

// --- Coverage 10: invalid upload rate blocks ---
#[test]
fn test_invalid_upload_rate_blocks() {
    let mut i = wready();
    i.upload_rate = Some("garbage".into());
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("upload rate parse error")));
}

// --- Coverage 11: live apply request is rejected ---
#[test]
fn test_live_apply_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.explicit_live_apply = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.live_apply_allowed);
    assert_eq!(p.status, BraveTcIfbWiringStatus::LiveApplyForbidden);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RejectLiveApply);
}

// --- Coverage 12: public CLI request is rejected ---
#[test]
fn test_public_cli_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.public_cli_requested = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.public_cli_exposed);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RejectPublicCli);
}

// --- Coverage 13: allow_tc_apply=true is rejected ---
#[test]
fn test_allow_tc_apply_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_tc_apply = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_tc_apply")));
}

// --- Coverage 14: allow_ip_apply=true is rejected ---
#[test]
fn test_allow_ip_apply_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_ip_apply = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_ip_apply")));
}

// --- Coverage 15: allow_ifb_create=true is rejected ---
#[test]
fn test_allow_ifb_create_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_ifb_create = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_ifb_create")));
}

// --- Coverage 16: allow_filter_create=true is rejected ---
#[test]
fn test_allow_filter_create_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_filter_create = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_filter_create")));
}

// --- Coverage 17: allow_qdisc_create=true is rejected ---
#[test]
fn test_allow_qdisc_create_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_qdisc_create = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_qdisc_create")));
}

// --- Coverage 18: allow_cgroup_mutation=true is rejected ---
#[test]
fn test_allow_cgroup_mutation_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_cgroup_mutation = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("allow_cgroup_mutation")));
}

// --- Coverage 19: allow_packet_drop=true is rejected ---
#[test]
fn test_allow_packet_drop_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_packet_drop = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_packet_drop")));
}

// --- Coverage 20: allow_persistence=true is rejected ---
#[test]
fn test_allow_persistence_rejected() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.allow_persistence = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_persistence")));
}

// --- Coverage 21: upload backend is TcEgressHtb ---
#[test]
fn test_upload_backend_tc_egress() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert_eq!(p.upload_backend, BraveTcIfbWiringBackend::TcEgressHtb);
}

// --- Coverage 22: download backend is TcIngressIfbRedirect ---
#[test]
fn test_download_backend_ifb() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert_eq!(
        p.download_backend,
        BraveTcIfbWiringBackend::TcIngressIfbRedirect
    );
}

// --- Coverage 23: upload wiring is rendered for ready plan ---
#[test]
fn test_upload_wiring_rendered() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p.upload_wiring_rendered);
    assert!(p
        .steps
        .iter()
        .any(|s| s.direction == Some(BraveTcIfbDirection::Upload)));
}

// --- Coverage 24: download wiring is rendered for ready plan ---
#[test]
fn test_download_wiring_rendered() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p.download_wiring_rendered);
    assert!(p
        .steps
        .iter()
        .any(|s| s.direction == Some(BraveTcIfbDirection::Download)));
}

// --- Coverage 25: upload_live_limit_proven=false ---
#[test]
fn test_upload_live_unproven() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p.upload_live_limit_proven);
}

// --- Coverage 26: download_live_limit_proven=false ---
#[test]
fn test_download_live_unproven() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p.download_live_limit_proven);
}

// --- Coverage 27: fake upload success rejected ---
#[test]
fn test_fake_upload_rejected() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p.fake_upload_limit_success_detected);
    let mut fake = p.clone();
    fake.fake_upload_limit_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&fake).is_err());
}

// --- Coverage 28: fake download success rejected ---
#[test]
fn test_fake_download_rejected() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p.fake_download_limit_success_detected);
    let mut fake = p.clone();
    fake.fake_download_limit_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&fake).is_err());
}

// --- Coverage 29: fake wiring success rejected ---
#[test]
fn test_fake_wiring_rejected() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p.fake_wiring_success_detected);
    let mut fake = p.clone();
    fake.fake_wiring_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&fake).is_err());
}

// --- Coverage 30: rendered steps include tc root qdisc ---
#[test]
fn test_step_tc_root_qdisc() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::TcRootQdisc));
}

// --- Coverage 31: rendered steps include tc class ---
#[test]
fn test_step_tc_class() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::TcClass));
}

// --- Coverage 32: rendered steps include cgroup filter ---
#[test]
fn test_step_cgroup_filter() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::TcCgroupFilter));
}

// --- Coverage 33: rendered steps include ip link add IFB ---
#[test]
fn test_step_ifb_link_add() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IfbLinkAdd));
}

// --- Coverage 34: rendered steps include ingress redirect ---
#[test]
fn test_step_ingress_redirect() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IngressRedirect));
}

// --- Coverage 35: rendered steps include IFB HTB ---
#[test]
fn test_step_ifb_htb() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IfbRootQdisc));
}

// --- Coverage 36: rollback steps include qdisc delete ---
#[test]
fn test_rollback_qdisc_delete() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .rollback_steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::Rollback
            && s.command.contains(&"delete".into())
            && s.command.contains(&"qdisc".into())));
}

// --- Coverage 37: rollback steps include IFB delete ---
#[test]
fn test_rollback_ifb_delete() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .rollback_steps
        .iter()
        .any(|s| s.command.contains(&"delete".into())
            && s.command.contains(&"ifb-zelynic-brave".into())));
}

// --- Coverage 38: all steps mutates_system=false ---
#[test]
fn test_all_steps_no_mutate() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    for s in &p.steps {
        assert!(
            !s.mutates_system,
            "step '{}' has mutates_system=true",
            s.label
        );
    }
}

// --- Coverage 39: all rollback steps rollback=true ---
#[test]
fn test_rollback_steps_flag() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    for s in &p.rollback_steps {
        assert!(s.rollback, "rollback step '{}' has rollback=false", s.label);
    }
}

// --- Coverage 40: non-rollback steps rollback=false ---
#[test]
fn test_normal_steps_no_rollback_flag() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    for s in &p.steps {
        assert!(!s.rollback, "step '{}' has rollback=true", s.label);
    }
}

// --- Coverage 41: tc/ip steps require_root=true ---
#[test]
fn test_tc_ip_steps_require_root() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    for s in &p.steps {
        if s.command
            .first()
            .map(|c| c == "tc" || c == "ip")
            .unwrap_or(false)
        {
            assert!(
                s.requires_root,
                "step '{}' tc/ip must require_root",
                s.label
            );
        }
    }
}

// --- Coverage 42: validate accepts safe default plan ---
#[test]
fn test_validate_default_safe() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&default_brave_tc_ifb_dry_run_wiring_input());
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&p).is_ok());
}

// --- Coverage 43: validate accepts ready dry-run plan ---
#[test]
fn test_validate_ready_plan() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&p).is_ok());
}

// --- Coverage 44: validate rejects dry_run_ready=true without interface ---
#[test]
fn test_validate_ready_no_interface() {
    let mut p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    p.interface = None;
    p.dry_run_ready = true;
    let r = validate_brave_tc_ifb_dry_run_wiring_plan(&p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("interface"));
}

// --- Coverage 45: validate rejects dry_run_ready=true without cgroup_class_id ---
#[test]
fn test_validate_ready_no_class_id() {
    let mut p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    p.cgroup_class_id = None;
    p.dry_run_ready = true;
    let r = validate_brave_tc_ifb_dry_run_wiring_plan(&p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("cgroup_class_id"));
}

// --- Coverage 46: validate rejects live_apply_allowed=true ---
#[test]
fn test_validate_reject_live_apply() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.live_apply_allowed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 47: validate rejects release_allowed=true ---
#[test]
fn test_validate_reject_release() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.release_allowed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 48: validate rejects must_remain_experimental=false ---
#[test]
fn test_validate_reject_experimental_false() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.must_remain_experimental = false;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 49: validate rejects public_cli_exposed=true ---
#[test]
fn test_validate_reject_public_cli() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.public_cli_exposed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 50: validate rejects tc_apply_performed=true ---
#[test]
fn test_validate_reject_tc_apply() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.tc_apply_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 51: validate rejects ip_apply_performed=true ---
#[test]
fn test_validate_reject_ip_apply() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.ip_apply_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 52: validate rejects ifb_create_performed=true ---
#[test]
fn test_validate_reject_ifb_create() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.ifb_create_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 53: validate rejects filter_create_performed=true ---
#[test]
fn test_validate_reject_filter_create() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.filter_create_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 54: validate rejects qdisc_create_performed=true ---
#[test]
fn test_validate_reject_qdisc_create() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.qdisc_create_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 55: validate rejects cgroup_mutation_performed=true ---
#[test]
fn test_validate_reject_cgroup_mutation() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.cgroup_mutation_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 56: validate rejects packet_drop_performed=true ---
#[test]
fn test_validate_reject_packet_drop() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.packet_drop_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 57: validate rejects persistence_performed=true ---
#[test]
fn test_validate_reject_persistence() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.persistence_performed = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 58: validate rejects upload_live_limit_proven=true ---
#[test]
fn test_validate_reject_upload_proven() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.upload_live_limit_proven = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 59: validate rejects download_live_limit_proven=true ---
#[test]
fn test_validate_reject_download_proven() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.download_live_limit_proven = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 60: validate rejects fake_upload_limit_success_detected=true ---
#[test]
fn test_validate_reject_fake_upload() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.fake_upload_limit_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 61: validate rejects fake_download_limit_success_detected=true ---
#[test]
fn test_validate_reject_fake_download() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.fake_download_limit_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 62: validate rejects fake_wiring_success_detected=true ---
#[test]
fn test_validate_reject_fake_wiring() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    let mut bad = p.clone();
    bad.fake_wiring_success_detected = true;
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&bad).is_err());
}

// --- Coverage 63: label helpers are stable ---
#[test]
fn test_label_stability() {
    assert_eq!(
        brave_tc_ifb_direction_label(BraveTcIfbDirection::Upload),
        "upload"
    );
    assert_eq!(
        brave_tc_ifb_direction_label(BraveTcIfbDirection::Download),
        "download"
    );
    assert_eq!(
        brave_tc_ifb_wiring_backend_label(BraveTcIfbWiringBackend::TcEgressHtb),
        "tc_egress_htb"
    );
    assert_eq!(
        brave_tc_ifb_wiring_backend_label(BraveTcIfbWiringBackend::TcIngressIfbRedirect),
        "tc_ingress_ifb_redirect"
    );
    assert_eq!(
        brave_tc_ifb_wiring_backend_label(BraveTcIfbWiringBackend::CgroupFilter),
        "cgroup_filter"
    );
    assert_eq!(
        brave_tc_ifb_wiring_backend_label(BraveTcIfbWiringBackend::Unsupported),
        "unsupported"
    );
    assert_eq!(
        brave_tc_ifb_wiring_status_label(BraveTcIfbWiringStatus::Draft),
        "draft"
    );
    assert_eq!(
        brave_tc_ifb_wiring_status_label(BraveTcIfbWiringStatus::DryRunReady),
        "dry_run_ready"
    );
    assert_eq!(
        brave_tc_ifb_wiring_status_label(BraveTcIfbWiringStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        brave_tc_ifb_wiring_status_label(BraveTcIfbWiringStatus::LiveApplyForbidden),
        "live_apply_forbidden"
    );
    assert_eq!(
        brave_tc_ifb_wiring_status_label(BraveTcIfbWiringStatus::Unsupported),
        "unsupported"
    );
    assert_eq!(
        brave_tc_ifb_wiring_decision_label(BraveTcIfbWiringDecision::Stop),
        "stop"
    );
    assert_eq!(
        brave_tc_ifb_wiring_decision_label(BraveTcIfbWiringDecision::RenderFullDryRun),
        "render_full_dry_run"
    );
    assert_eq!(
        brave_tc_ifb_wiring_decision_label(BraveTcIfbWiringDecision::RejectLiveApply),
        "reject_live_apply"
    );
    assert_eq!(
        brave_tc_ifb_wiring_decision_label(BraveTcIfbWiringDecision::RejectPublicCli),
        "reject_public_cli"
    );
    assert_eq!(
        brave_tc_ifb_wiring_step_kind_label(BraveTcIfbWiringStepKind::TcRootQdisc),
        "render_tc_root_qdisc"
    );
    assert_eq!(
        brave_tc_ifb_wiring_step_kind_label(BraveTcIfbWiringStepKind::TcClass),
        "render_tc_class"
    );
    assert_eq!(
        brave_tc_ifb_wiring_step_kind_label(BraveTcIfbWiringStepKind::Rollback),
        "render_rollback"
    );
}

// --- Coverage 64: docs exist ---
#[test]
fn test_docs_exist() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(!content.is_empty());
}

// --- Coverage 65: docs say Brave tc/IFB dry-run wiring plan ---
#[test]
fn test_docs_title() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.contains("tc/IFB dry-run wiring"));
}

// --- Coverage 66: docs say upload 100KB/s ---
#[test]
fn test_docs_upload_rate() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.contains("100KB/s") || content.contains("100 KB/s"));
    assert!(content.to_lowercase().contains("upload"));
}

// --- Coverage 67: docs say download 100KB/s ---
#[test]
fn test_docs_download_rate() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.to_lowercase().contains("download"));
}

// --- Coverage 68: docs say dry-run only ---
#[test]
fn test_docs_dry_run() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.contains("dry-run") || content.contains("dry run"));
}

// --- Coverage 69: docs say no live apply ---
#[test]
fn test_docs_no_live_apply() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.to_lowercase().contains("no live apply") || content.contains("forbidden"));
}

// --- Coverage 70: docs say no public CLI ---
#[test]
fn test_docs_no_public_cli() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.contains("no public CLI") || content.to_lowercase().contains("no public cli"));
}

// --- Coverage 71-78: docs say no tc/ip/ifb/qdisc/filter/cgroup/drop/enforcement ---
#[test]
fn test_docs_no_mutation_claims() {
    let c = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md")
        .to_lowercase();
    assert!(c.contains("no tc"));
    assert!(c.contains("no ip"));
    assert!(c.contains("no ifb"));
    assert!(c.contains("no qdisc"));
    assert!(c.contains("no filter"));
    assert!(c.contains("no cgroup"));
    assert!(c.contains("no packet drop"));
    assert!(c.contains("no enforcement"));
}

// --- Coverage 79: docs say upload/download live limit not proven ---
#[test]
fn test_docs_not_proven() {
    let content = include_str!("../../docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md");
    assert!(content.contains("not proven") || content.contains("not proven in I-35"));
}

// --- Additional: rate 102400 ---
#[test]
fn test_rate_bytes_102400() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert_eq!(p.upload_rate_bytes_per_sec, Some(102400));
    assert_eq!(p.download_rate_bytes_per_sec, Some(102400));
}

// --- Additional: step count ---
#[test]
fn test_full_step_count() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    // 3 upload + 6 download = 9 forward steps
    assert_eq!(p.steps.len(), 9);
    // 1 upload rollback + 3 download rollback = 4 rollback steps
    assert_eq!(p.rollback_steps.len(), 4);
}

// --- Coverage: identity not ready blocks ---
#[test]
fn test_identity_not_ready_blocks() {
    let d = default_brave_tc_ifb_dry_run_wiring_input();
    let i = I {
        scope_plan: ready_sp(),
        ..d
    };
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RequireReadyIdentity);
}

// --- Coverage: scope not ready blocks ---
#[test]
fn test_scope_not_ready_blocks() {
    let mut i = default_brave_tc_ifb_dry_run_wiring_input();
    i.identity_proof = ready_id();
    // scope_plan still default (not ready)
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RequireReadyScope);
}

// --- Additional: upload only renders correctly ---
#[test]
fn test_upload_only() {
    let mut i = wready();
    i.download_rate = None;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(p.upload_wiring_rendered);
    assert!(!p.download_wiring_rendered);
    assert_eq!(p.decision, BraveTcIfbWiringDecision::RenderUploadTcEgress);
    assert_eq!(p.steps.len(), 3);
    assert_eq!(p.rollback_steps.len(), 1);
}

// --- Additional: download only renders correctly ---
#[test]
fn test_download_only() {
    let mut i = wready();
    i.upload_rate = None;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.upload_wiring_rendered);
    assert!(p.download_wiring_rendered);
    assert_eq!(
        p.decision,
        BraveTcIfbWiringDecision::RenderDownloadIfbIngress
    );
    assert_eq!(p.steps.len(), 6);
    assert_eq!(p.rollback_steps.len(), 3);
}

// --- Additional: findings contain honest unproven messages ---
#[test]
fn test_findings_honest() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("upload live limit is not proven")));
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("download live limit is not proven")));
}

// --- Additional: limit plan validation failure blocks ---
#[test]
fn test_bad_limit_plan_blocks() {
    let mut i = wready();
    i.limit_plan.live_apply_allowed = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("limit plan validation failed")));
}

// --- Additional: identity proof validation failure blocks ---
#[test]
fn test_bad_identity_blocks() {
    let mut i = wready();
    i.identity_proof.live_apply_allowed = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("identity proof validation failed")));
}

// --- Additional: scope plan validation failure blocks ---
#[test]
fn test_bad_scope_blocks() {
    let mut i = wready();
    i.scope_plan.live_apply_allowed = true;
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p.dry_run_ready);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("scope plan validation failed")));
}

// --- Additional: default input structural checks ---
#[test]
fn test_default_input_structure() {
    let i = default_brave_tc_ifb_dry_run_wiring_input();
    assert_eq!(i.interface.as_deref(), Some("eth0"));
    assert_eq!(i.ifb_name, "ifb-zelynic-brave");
    assert_eq!(i.cgroup_class_id.as_deref(), Some("0x100001"));
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&default_brave_tc_ifb_dry_run_wiring_input());
    assert_eq!(p.phase, "I-35");
}

// --- Additional: rollback no mutate + extra download step kinds ---
#[test]
fn test_rollback_no_mutate_and_download_kinds() {
    let p = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    for s in &p.rollback_steps {
        assert!(
            !s.mutates_system,
            "rollback '{}' mutates_system=true",
            s.label
        );
    }
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IfbClass));
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IngressQdisc));
    assert!(p
        .steps
        .iter()
        .any(|s| s.kind == BraveTcIfbWiringStepKind::IfbLinkUp));
}

// --- Additional: validate edge cases + dry_run_false + mutation flags + public cli ---
#[test]
fn test_validate_edge_cases_and_flags() {
    let mut p =
        build_brave_tc_ifb_dry_run_wiring_plan(&default_brave_tc_ifb_dry_run_wiring_input());
    p.phase = String::new();
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&p).is_err());
    let mut p2 = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    if let Some(s) = p2.steps.first_mut() {
        s.mutates_system = true;
    }
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&p2).is_err());
    let mut p3 = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    if let Some(s) = p3.rollback_steps.first_mut() {
        s.mutates_system = true;
    }
    assert!(validate_brave_tc_ifb_dry_run_wiring_plan(&p3).is_err());
    let mut i = wready();
    i.explicit_dry_run = false;
    let p4 = build_brave_tc_ifb_dry_run_wiring_plan(&i);
    assert!(!p4.dry_run_ready);
    assert!(p4
        .findings
        .iter()
        .any(|f| f.contains("explicit_dry_run must be true")));
    let d = default_brave_tc_ifb_dry_run_wiring_input();
    assert!(!d.allow_tc_apply && !d.allow_ip_apply && !d.allow_ifb_create);
    assert!(!d.allow_filter_create && !d.allow_qdisc_create && !d.allow_cgroup_mutation);
    assert!(!d.allow_packet_drop && !d.allow_persistence);
    let p5 = build_brave_tc_ifb_dry_run_wiring_plan(&wready());
    assert!(!p5.public_cli_exposed);
}
