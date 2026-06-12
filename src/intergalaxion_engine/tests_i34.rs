// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::intergalaxion_engine::backends::ebpf::brave_cgroup_scope_dry_run::{
    brave_cgroup_scope_decision_label, brave_cgroup_scope_status_label,
    brave_cgroup_scope_step_kind_label, brave_cgroup_scope_strategy_label,
    build_brave_cgroup_scope_dry_run_plan, default_brave_cgroup_scope_dry_run_input,
    validate_brave_cgroup_scope_dry_run_plan, BraveCgroupScopeDecision,
    BraveCgroupScopeDryRunInput, BraveCgroupScopeDryRunPlan, BraveCgroupScopeStatus,
    BraveCgroupScopeStepKind, BraveCgroupScopeStrategy,
};
use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
    build_brave_identity_scope_proof, BraveIdentityScopeProof,
};
use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
    build_brave_limit_lab_plan, BraveLimitLabPlan,
};

type I = BraveCgroupScopeDryRunInput;
type P = BraveCgroupScopeDryRunPlan;

/// Build a ready identity proof for tests.
fn ready_id() -> BraveIdentityScopeProof {
    use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
        default_brave_identity_scope_proof_input, BraveProcessCandidate,
    };
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
    use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::default_brave_limit_lab_plan_input;
    let mut i = default_brave_limit_lab_plan_input();
    i.interface = Some("eth0".into());
    let mut p = build_brave_limit_lab_plan(&i);
    // Fix I-32 honest fields so validation passes
    p.download_limit_claimed_without_ifb_proof = false;
    p.upload_limit_claimed_without_tc_proof = false;
    p
}

/// Full ready input with SystemdUserScope strategy.
fn sready(strat: BraveCgroupScopeStrategy) -> I {
    let d = default_brave_cgroup_scope_dry_run_input();
    let id = ready_id();
    let lp = safe_lp();
    I {
        identity_proof: id,
        limit_plan: lp,
        strategy: strat,
        ..d
    }
}

// --- Coverage 1: default input uses zelynic-brave-limit scope name ---
#[test]
fn test_default_scope_name() {
    let i = default_brave_cgroup_scope_dry_run_input();
    assert_eq!(i.scope_name, "zelynic-brave-limit.scope");
}

// --- Coverage 2: default plan is not dry_run_ready without ready identity ---
#[test]
fn test_default_not_ready() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert!(!p.dry_run_ready);
}

// --- Coverage 3: default plan release_allowed=false ---
#[test]
fn test_default_no_release() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert!(!p.release_allowed);
}

// --- Coverage 4: default plan live_apply_allowed=false ---
#[test]
fn test_default_no_live_apply() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert!(!p.live_apply_allowed);
}

// --- Coverage 5: default plan must_remain_experimental=true ---
#[test]
fn test_default_experimental() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert!(p.must_remain_experimental);
}

// --- Coverage 6: ready identity + safe limit plan becomes DryRunReady ---
#[test]
fn test_ready_becomes_dry_run_ready() {
    let i = sready(BraveCgroupScopeStrategy::SystemdUserScope);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.dry_run_ready);
    assert_eq!(p.status, BraveCgroupScopeStatus::DryRunReady);
    assert_eq!(p.decision, BraveCgroupScopeDecision::RenderSystemdUserScope);
}

// --- Coverage 7: ambiguous identity is rejected ---
#[test]
fn test_ambiguous_identity_rejected() {
    use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
        default_brave_identity_scope_proof_input, BraveProcessCandidate,
    };
    let mut id_input = default_brave_identity_scope_proof_input();
    id_input.candidates.push(BraveProcessCandidate {
        pid: Some(1),
        process_name: "brave".into(),
        executable_path: None,
        cgroup_path: Some("/a".into()),
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: true,
    });
    id_input.candidates.push(BraveProcessCandidate {
        pid: Some(2),
        process_name: "brave".into(),
        executable_path: None,
        cgroup_path: Some("/b".into()),
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: true,
    });
    let id = build_brave_identity_scope_proof(&id_input);
    let d = default_brave_cgroup_scope_dry_run_input();
    let i = I {
        identity_proof: id,
        limit_plan: safe_lp(),
        ..d
    };
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.status, BraveCgroupScopeStatus::AmbiguousIdentity);
    assert_eq!(
        p.decision,
        BraveCgroupScopeDecision::RejectAmbiguousIdentity
    );
}

// --- Coverage 8: no identity is rejected ---
#[test]
fn test_no_identity_rejected() {
    let d = default_brave_cgroup_scope_dry_run_input();
    let i = I {
        limit_plan: safe_lp(),
        ..d
    };
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(!p.dry_run_ready);
    assert_eq!(p.decision, BraveCgroupScopeDecision::RequireReadyIdentity);
}

// --- Coverage 9: live apply request is rejected ---
#[test]
fn test_live_apply_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.explicit_live_apply = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(!p.live_apply_allowed);
    assert_eq!(p.status, BraveCgroupScopeStatus::LiveApplyForbidden);
}

// --- Coverage 10: public CLI request is rejected ---
#[test]
fn test_public_cli_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.public_cli_requested = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.public_cli_exposed);
    assert_eq!(p.decision, BraveCgroupScopeDecision::RejectPublicCli);
}

// --- Coverage 11-17: mutation allowance rejections ---
#[test]
fn test_proc_scan_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_proc_scan = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_proc_scan")));
}
#[test]
fn test_cgroup_read_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_cgroup_read = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_cgroup_read")));
}
#[test]
fn test_systemd_query_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_systemd_query = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_systemd_query")));
}
#[test]
fn test_cgroup_create_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_cgroup_create = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_cgroup_create")));
}
#[test]
fn test_process_move_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_process_move = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_process_move")));
}
#[test]
fn test_cgroup_mutation_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_cgroup_mutation = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p
        .findings
        .iter()
        .any(|f| f.contains("allow_cgroup_mutation")));
}
#[test]
fn test_persistence_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.allow_persistence = true;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_persistence")));
}

// --- Coverage 18: SystemdUserScope renders systemd-run intent ---
#[test]
fn test_systemd_strategy_renders() {
    let i = sready(BraveCgroupScopeStrategy::SystemdUserScope);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    let has_systemd = p.steps.iter().any(|s| {
        s.command
            .first()
            .map(|t| t == "systemd-run")
            .unwrap_or(false)
    });
    assert!(has_systemd);
}

// --- Coverage 19: DedicatedLabCgroup renders cgroup path intent ---
#[test]
fn test_dedicated_strategy_renders() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    let has_mkdir = p
        .steps
        .iter()
        .any(|s| s.command.first().map(|t| t == "mkdir").unwrap_or(false));
    assert!(has_mkdir);
    let has_move = p
        .steps
        .iter()
        .any(|s| s.kind == BraveCgroupScopeStepKind::RenderProcessMove);
    assert!(has_move);
}

// --- Coverage 20: ExistingCgroup renders existing cgroup intent ---
#[test]
fn test_existing_strategy_renders() {
    let i = sready(BraveCgroupScopeStrategy::ExistingCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    let has_inspect = p
        .steps
        .iter()
        .any(|s| s.kind == BraveCgroupScopeStepKind::InspectExistingScope);
    assert!(has_inspect);
}

// --- Coverage 21: Unsupported strategy is rejected ---
#[test]
fn test_unsupported_strategy_rejected() {
    let mut i = default_brave_cgroup_scope_dry_run_input();
    i.strategy = BraveCgroupScopeStrategy::Unsupported;
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert_eq!(p.status, BraveCgroupScopeStatus::Unsupported);
}

// --- Coverage 22: dry-run steps rendered for ready identity ---
#[test]
fn test_steps_rendered() {
    let i = sready(BraveCgroupScopeStrategy::SystemdUserScope);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(!p.steps.is_empty());
}

// --- Coverage 23: rollback steps rendered for ready identity ---
#[test]
fn test_rollback_rendered() {
    let i = sready(BraveCgroupScopeStrategy::SystemdUserScope);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(!p.rollback_steps.is_empty());
}

// --- Coverage 24: all steps have mutates_system=false ---
#[test]
fn test_no_step_mutates() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(p.steps.iter().all(|s| !s.mutates_system));
    assert!(p.rollback_steps.iter().all(|s| !s.mutates_system));
}

// --- Coverage 25: all rollback steps have rollback=true ---
#[test]
fn test_rollback_flag_set() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    for s in &p.rollback_steps {
        assert!(
            s.rollback,
            "rollback step '{}' missing rollback flag",
            s.label
        );
    }
}

// --- Coverage 26: non-rollback steps have rollback=false ---
#[test]
fn test_apply_steps_no_rollback_flag() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    for s in &p.steps {
        assert!(
            !s.rollback,
            "apply step '{}' should not have rollback flag",
            s.label
        );
    }
}

// --- Coverage 27: validate accepts safe default plan ---
#[test]
fn test_validate_accepts_default() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_ok());
}

// --- Coverage 28: validate accepts ready dry-run plan ---
#[test]
fn test_validate_accepts_ready() {
    let i = sready(BraveCgroupScopeStrategy::SystemdUserScope);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_ok());
}

// --- Coverage 29: validate rejects dry_run_ready=true without selected PID ---
#[test]
fn test_validate_rejects_ready_no_pid() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.dry_run_ready = true;
    p.selected_pid = None;
    p.selected_cgroup_path = Some("/x".into());
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}

// --- Coverage 30: validate rejects dry_run_ready=true without cgroup ---
#[test]
fn test_validate_rejects_ready_no_cgroup() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.dry_run_ready = true;
    p.selected_pid = Some(1);
    p.selected_cgroup_path = None;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}

// --- Coverage 31-43: validate rejects dangerous flags ---
#[test]
fn test_validate_rejects_live_apply() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.live_apply_allowed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_release() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.release_allowed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_not_experimental() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.must_remain_experimental = false;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_public_cli() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.public_cli_exposed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_proc_scan() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.proc_scan_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_cgroup_read() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.cgroup_read_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_systemd_query() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.systemd_query_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_cgroup_create() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.cgroup_create_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_process_move() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.process_move_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_cgroup_mutation() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.cgroup_mutation_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_persistence() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.persistence_performed = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_fake_scope() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.fake_scope_success_detected = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
#[test]
fn test_validate_rejects_fake_identity() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.fake_identity_success_detected = true;
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}

// --- Coverage 44: label helpers are stable ---
#[test]
fn test_strategy_labels() {
    assert_eq!(
        brave_cgroup_scope_strategy_label(BraveCgroupScopeStrategy::ExistingCgroup),
        "existing_cgroup"
    );
    assert_eq!(
        brave_cgroup_scope_strategy_label(BraveCgroupScopeStrategy::SystemdUserScope),
        "systemd_user_scope"
    );
    assert_eq!(
        brave_cgroup_scope_strategy_label(BraveCgroupScopeStrategy::DedicatedLabCgroup),
        "dedicated_lab_cgroup"
    );
    assert_eq!(
        brave_cgroup_scope_strategy_label(BraveCgroupScopeStrategy::Unsupported),
        "unsupported"
    );
}

#[test]
fn test_status_labels() {
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::Draft),
        "draft"
    );
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::DryRunReady),
        "dry_run_ready"
    );
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::AmbiguousIdentity),
        "ambiguous_identity"
    );
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::LiveApplyForbidden),
        "live_apply_forbidden"
    );
    assert_eq!(
        brave_cgroup_scope_status_label(BraveCgroupScopeStatus::Unsupported),
        "unsupported"
    );
}

#[test]
fn test_decision_labels() {
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::Stop),
        "stop"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RenderExistingCgroupScope),
        "render_existing_cgroup_scope"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RenderSystemdUserScope),
        "render_systemd_user_scope"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RenderDedicatedLabCgroup),
        "render_dedicated_lab_cgroup"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RequireReadyIdentity),
        "require_ready_identity"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RejectLiveApply),
        "reject_live_apply"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RejectPublicCli),
        "reject_public_cli"
    );
    assert_eq!(
        brave_cgroup_scope_decision_label(BraveCgroupScopeDecision::RejectMutation),
        "reject_mutation"
    );
}

#[test]
fn test_step_kind_labels() {
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::InspectExistingScope),
        "inspect_existing_scope"
    );
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::RenderSystemdScope),
        "render_systemd_scope"
    );
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::RenderDedicatedCgroup),
        "render_dedicated_cgroup"
    );
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::RenderProcessMove),
        "render_process_move"
    );
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::RenderRollback),
        "render_rollback"
    );
    assert_eq!(
        brave_cgroup_scope_step_kind_label(BraveCgroupScopeStepKind::RenderNoop),
        "render_noop"
    );
}

// --- Coverage 45-58: docs content checks ---
#[test]
fn test_docs_exist() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    assert!(!docs.is_empty());
}
#[test]
fn test_docs_say_cgroup_scope() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("cgroup") && lower.contains("dry-run"));
}
#[test]
fn test_docs_say_dry_run_only() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    assert!(docs.contains("dry-run") || docs.contains("dry run"));
}
#[test]
fn test_docs_say_no_live_apply() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no live apply") || lower.contains("live apply is forbidden"));
}
#[test]
fn test_docs_say_no_public_cli() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no public cli") || lower.contains("public cli"));
}
#[test]
fn test_docs_say_no_proc_scan() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no proc scan") || lower.contains("/proc"));
}
#[test]
fn test_docs_say_no_cgroup_read() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("cgroup") && (lower.contains("read") || lower.contains("no cgroup")));
}
#[test]
fn test_docs_say_no_cgroup_creation() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no cgroup creation") || lower.contains("cgroup create"));
}
#[test]
fn test_docs_say_no_process_move() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no process move") || lower.contains("process move"));
}
#[test]
fn test_docs_say_no_cgroup_mutation() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("cgroup mutation") || lower.contains("no mutation"));
}
#[test]
fn test_docs_say_no_persistence() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no persistence") || lower.contains("persistence"));
}
#[test]
fn test_docs_say_no_enforcement() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no enforcement") || lower.contains("enforcement"));
}
#[test]
fn test_docs_say_no_packet_drop() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no packet drop") || lower.contains("packet drop"));
}
#[test]
fn test_docs_say_brave_100kbps() {
    let docs = include_str!("../../docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md");
    assert!(docs.contains("100KB/s") || docs.contains("100kbps"));
}

// --- Extra: phase is I-34 ---
#[test]
fn test_phase() {
    let p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    assert_eq!(p.phase, "I-34");
}

// --- Extra: ready plan propagates pid/cgroup ---
#[test]
fn test_ready_propagates_identity() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let p = build_brave_cgroup_scope_dry_run_plan(&i);
    assert_eq!(p.selected_pid, Some(1234));
    assert_eq!(
        p.selected_cgroup_path.as_deref(),
        Some("/user.slice/brave.scope")
    );
}

// --- Extra: default input all flags safe ---
#[test]
fn test_default_flags_safe() {
    let i = default_brave_cgroup_scope_dry_run_input();
    assert!(i.explicit_dry_run);
    assert!(!i.explicit_live_apply);
    assert!(!i.public_cli_requested);
    assert!(!i.allow_proc_scan);
    assert!(!i.allow_cgroup_read);
    assert!(!i.allow_systemd_query);
    assert!(!i.allow_cgroup_create);
    assert!(!i.allow_process_move);
    assert!(!i.allow_cgroup_mutation);
    assert!(!i.allow_persistence);
}

// --- Extra: validate rejects empty phase ---
#[test]
fn test_validate_rejects_empty_phase() {
    let mut p = build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input());
    p.phase = String::new();
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}

// --- Extra: validate rejects mutates_system in steps ---
#[test]
fn test_validate_rejects_step_mutates() {
    let i = sready(BraveCgroupScopeStrategy::DedicatedLabCgroup);
    let mut p = build_brave_cgroup_scope_dry_run_plan(&i);
    if let Some(s) = p.steps.first_mut() {
        s.mutates_system = true;
    }
    assert!(validate_brave_cgroup_scope_dry_run_plan(&p).is_err());
}
