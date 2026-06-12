// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Brave cgroup dry-run scope renderer for the Intergalaxion Engine (I-34).
//!
//! Renders a deterministic cgroup/systemd scope plan for Brave, using
//! fixture-provided identity evidence from I-33 and limit plan from I-32.
//! Dry-run only. No cgroup creation, no process move, no systemd-run,
//! no /proc scan, no /sys/fs/cgroup read/write, no enforcement.

use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
    validate_brave_identity_scope_proof, BraveIdentityScopeProof,
};
use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
    validate_brave_limit_lab_plan, BraveLimitLabPlan,
};

/// Strategy for placing Brave into a controllable scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveCgroupScopeStrategy {
    ExistingCgroup,
    SystemdUserScope,
    DedicatedLabCgroup,
    Unsupported,
}
impl BraveCgroupScopeStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExistingCgroup => "existing_cgroup",
            Self::SystemdUserScope => "systemd_user_scope",
            Self::DedicatedLabCgroup => "dedicated_lab_cgroup",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Status of the cgroup scope dry-run plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveCgroupScopeStatus {
    Draft,
    DryRunReady,
    Blocked,
    AmbiguousIdentity,
    LiveApplyForbidden,
    Unsupported,
}
impl BraveCgroupScopeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::DryRunReady => "dry_run_ready",
            Self::Blocked => "blocked",
            Self::AmbiguousIdentity => "ambiguous_identity",
            Self::LiveApplyForbidden => "live_apply_forbidden",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Decision produced by the cgroup scope dry-run evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveCgroupScopeDecision {
    Stop,
    RenderExistingCgroupScope,
    RenderSystemdUserScope,
    RenderDedicatedLabCgroup,
    RequireReadyIdentity,
    RejectAmbiguousIdentity,
    RejectLiveApply,
    RejectPublicCli,
    RejectMutation,
}
impl BraveCgroupScopeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::RenderExistingCgroupScope => "render_existing_cgroup_scope",
            Self::RenderSystemdUserScope => "render_systemd_user_scope",
            Self::RenderDedicatedLabCgroup => "render_dedicated_lab_cgroup",
            Self::RequireReadyIdentity => "require_ready_identity",
            Self::RejectAmbiguousIdentity => "reject_ambiguous_identity",
            Self::RejectLiveApply => "reject_live_apply",
            Self::RejectPublicCli => "reject_public_cli",
            Self::RejectMutation => "reject_mutation",
        }
    }
}

/// Kind of dry-run scope step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveCgroupScopeStepKind {
    InspectExistingScope,
    RenderSystemdScope,
    RenderDedicatedCgroup,
    RenderProcessMove,
    RenderRollback,
    RenderNoop,
}
impl BraveCgroupScopeStepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InspectExistingScope => "inspect_existing_scope",
            Self::RenderSystemdScope => "render_systemd_scope",
            Self::RenderDedicatedCgroup => "render_dedicated_cgroup",
            Self::RenderProcessMove => "render_process_move",
            Self::RenderRollback => "render_rollback",
            Self::RenderNoop => "render_noop",
        }
    }
}

/// A single dry-run step rendered by the scope plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveCgroupScopeDryRunStep {
    pub label: String,
    pub kind: BraveCgroupScopeStepKind,
    pub command: Vec<String>,
    pub requires_root: bool,
    pub mutates_system: bool,
    pub rollback: bool,
}

/// Input to the cgroup scope dry-run builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveCgroupScopeDryRunInput {
    pub identity_proof: BraveIdentityScopeProof,
    pub limit_plan: BraveLimitLabPlan,
    pub scope_name: String,
    pub strategy: BraveCgroupScopeStrategy,
    pub explicit_dry_run: bool,
    pub explicit_live_apply: bool,
    pub explicit_experimental_ack: bool,
    pub public_cli_requested: bool,
    pub allow_proc_scan: bool,
    pub allow_cgroup_read: bool,
    pub allow_systemd_query: bool,
    pub allow_cgroup_create: bool,
    pub allow_process_move: bool,
    pub allow_cgroup_mutation: bool,
    pub allow_persistence: bool,
}

/// Output cgroup scope dry-run plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveCgroupScopeDryRunPlan {
    pub phase: String,
    pub status: BraveCgroupScopeStatus,
    pub decision: BraveCgroupScopeDecision,
    pub strategy: BraveCgroupScopeStrategy,
    pub scope_name: String,
    pub dry_run_ready: bool,
    pub live_apply_allowed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub identity_ready: bool,
    pub identity_ambiguous: bool,
    pub selected_pid: Option<u32>,
    pub selected_cgroup_path: Option<String>,
    pub selected_systemd_scope: Option<String>,
    pub public_cli_exposed: bool,
    pub proc_scan_performed: bool,
    pub cgroup_read_performed: bool,
    pub systemd_query_performed: bool,
    pub cgroup_create_performed: bool,
    pub process_move_performed: bool,
    pub cgroup_mutation_performed: bool,
    pub persistence_performed: bool,
    pub fake_scope_success_detected: bool,
    pub fake_identity_success_detected: bool,
    pub steps: Vec<BraveCgroupScopeDryRunStep>,
    pub rollback_steps: Vec<BraveCgroupScopeDryRunStep>,
    pub findings: Vec<String>,
}

fn safe_base_plan() -> BraveCgroupScopeDryRunPlan {
    BraveCgroupScopeDryRunPlan {
        phase: "I-34".into(),
        status: BraveCgroupScopeStatus::Draft,
        decision: BraveCgroupScopeDecision::Stop,
        strategy: BraveCgroupScopeStrategy::Unsupported,
        scope_name: String::new(),
        dry_run_ready: false,
        live_apply_allowed: false,
        release_allowed: false,
        must_remain_experimental: true,
        identity_ready: false,
        identity_ambiguous: false,
        selected_pid: None,
        selected_cgroup_path: None,
        selected_systemd_scope: None,
        public_cli_exposed: false,
        proc_scan_performed: false,
        cgroup_read_performed: false,
        systemd_query_performed: false,
        cgroup_create_performed: false,
        process_move_performed: false,
        cgroup_mutation_performed: false,
        persistence_performed: false,
        fake_scope_success_detected: false,
        fake_identity_success_detected: false,
        steps: Vec::new(),
        rollback_steps: Vec::new(),
        findings: Vec::new(),
    }
}

/// Returns a safe default input for the cgroup scope dry-run.
#[rustfmt::skip]
pub fn default_brave_cgroup_scope_dry_run_input() -> BraveCgroupScopeDryRunInput {
    use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{build_brave_identity_scope_proof, default_brave_identity_scope_proof_input};
    use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{build_brave_limit_lab_plan, default_brave_limit_lab_plan_input};
    BraveCgroupScopeDryRunInput {
        identity_proof: build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input()),
        limit_plan: build_brave_limit_lab_plan(&default_brave_limit_lab_plan_input()),
        scope_name: "zelynic-brave-limit.scope".into(),
        strategy: BraveCgroupScopeStrategy::SystemdUserScope,
        explicit_dry_run: true,
        explicit_live_apply: false,
        explicit_experimental_ack: false,
        public_cli_requested: false,
        allow_proc_scan: false,
        allow_cgroup_read: false,
        allow_systemd_query: false,
        allow_cgroup_create: false,
        allow_process_move: false,
        allow_cgroup_mutation: false,
        allow_persistence: false,
    }
}

#[inline]
fn step(
    label: &str,
    kind: BraveCgroupScopeStepKind,
    cmd: Vec<String>,
    root: bool,
) -> BraveCgroupScopeDryRunStep {
    BraveCgroupScopeDryRunStep {
        label: label.into(),
        kind,
        command: cmd,
        requires_root: root,
        mutates_system: false,
        rollback: false,
    }
}

#[inline]
fn rb_step(
    label: &str,
    kind: BraveCgroupScopeStepKind,
    cmd: Vec<String>,
    root: bool,
) -> BraveCgroupScopeDryRunStep {
    BraveCgroupScopeDryRunStep {
        label: label.into(),
        kind,
        command: cmd,
        requires_root: root,
        mutates_system: false,
        rollback: true,
    }
}

/// Build the brave cgroup scope dry-run plan from the given input.
///
/// Renders command intent only. Never executes. Never mutates system.
pub fn build_brave_cgroup_scope_dry_run_plan(
    input: &BraveCgroupScopeDryRunInput,
) -> BraveCgroupScopeDryRunPlan {
    let mut plan = safe_base_plan();
    let mut findings: Vec<String> = Vec::new();
    let mut blocked = false;
    plan.scope_name = input.scope_name.clone();
    plan.strategy = input.strategy;
    // Public CLI rejection
    if input.public_cli_requested {
        plan.decision = BraveCgroupScopeDecision::RejectPublicCli;
        plan.status = BraveCgroupScopeStatus::Blocked;
        plan.public_cli_exposed = true;
        findings.push("public CLI is not exposed in I-34".into());
        blocked = true;
    }
    // Live apply rejection
    if input.explicit_live_apply {
        plan.decision = BraveCgroupScopeDecision::RejectLiveApply;
        plan.status = BraveCgroupScopeStatus::LiveApplyForbidden;
        findings.push("live apply is forbidden in I-34".into());
        blocked = true;
    }
    // Mutation/system-read allowance rejections
    if input.allow_proc_scan {
        findings.push("allow_proc_scan is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_cgroup_read {
        findings.push("allow_cgroup_read is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_systemd_query {
        findings.push("allow_systemd_query is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_cgroup_create {
        findings.push("allow_cgroup_create is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_process_move {
        findings.push("allow_process_move is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_cgroup_mutation {
        findings.push("allow_cgroup_mutation is rejected in I-34".into());
        blocked = true;
    }
    if input.allow_persistence {
        findings.push("allow_persistence is rejected in I-34".into());
        blocked = true;
    }
    // Unsupported strategy
    if input.strategy == BraveCgroupScopeStrategy::Unsupported {
        plan.decision = BraveCgroupScopeDecision::Stop;
        plan.status = BraveCgroupScopeStatus::Unsupported;
        findings.push("unsupported strategy".into());
        blocked = true;
    }
    if blocked {
        plan.findings = findings;
        return plan;
    }
    // Validate consumed evidence
    let id_ok = validate_brave_identity_scope_proof(&input.identity_proof).is_ok();
    let lp_ok = validate_brave_limit_lab_plan(&input.limit_plan).is_ok();
    if !id_ok {
        findings.push("identity proof validation failed".into());
        blocked = true;
    }
    if !lp_ok {
        findings.push("limit plan validation failed".into());
        blocked = true;
    }
    // Identity readiness check
    plan.identity_ready = input.identity_proof.identity_ready;
    plan.identity_ambiguous = input.identity_proof.ambiguous_identity_detected;
    plan.selected_pid = input.identity_proof.selected_pid;
    plan.selected_cgroup_path = input.identity_proof.selected_cgroup_path.clone();
    plan.selected_systemd_scope = input.identity_proof.selected_systemd_scope.clone();
    if input.identity_proof.ambiguous_identity_detected {
        plan.decision = BraveCgroupScopeDecision::RejectAmbiguousIdentity;
        plan.status = BraveCgroupScopeStatus::AmbiguousIdentity;
        findings.push("identity is ambiguous — cannot scope".into());
        blocked = true;
    } else if !input.identity_proof.identity_ready {
        plan.decision = BraveCgroupScopeDecision::RequireReadyIdentity;
        plan.status = BraveCgroupScopeStatus::Blocked;
        findings.push("identity proof is not ready — requires PID + cgroup".into());
        blocked = true;
    }
    if blocked {
        plan.findings = findings;
        return plan;
    }
    // Dry-run check
    if !input.explicit_dry_run {
        findings.push("explicit_dry_run must be true".into());
        plan.findings = findings;
        return plan;
    }
    // Render scope steps based on strategy
    let pid_str = input
        .identity_proof
        .selected_pid
        .map(|p| p.to_string())
        .unwrap_or_default();
    let scope = &input.scope_name;
    let cgroup = input
        .identity_proof
        .selected_cgroup_path
        .as_deref()
        .unwrap_or("<cgroup>");
    match input.strategy {
        BraveCgroupScopeStrategy::ExistingCgroup => {
            plan.decision = BraveCgroupScopeDecision::RenderExistingCgroupScope;
            plan.steps.push(step(
                "inspect: read existing cgroup",
                BraveCgroupScopeStepKind::InspectExistingScope,
                vec!["cat".into(), cgroup.into()],
                false,
            ));
            plan.steps.push(step(
                "inspect: verify process in cgroup",
                BraveCgroupScopeStepKind::InspectExistingScope,
                vec!["cat".into(), format!("{cgroup}/cgroup.procs")],
                false,
            ));
            plan.rollback_steps.push(rb_step(
                "rollback: no-op (existing scope untouched)",
                BraveCgroupScopeStepKind::RenderNoop,
                vec!["true".into()],
                false,
            ));
        }
        BraveCgroupScopeStrategy::SystemdUserScope => {
            plan.decision = BraveCgroupScopeDecision::RenderSystemdUserScope;
            plan.steps.push(step(
                "scope: render systemd-run user scope",
                BraveCgroupScopeStepKind::RenderSystemdScope,
                vec![
                    "systemd-run".into(),
                    "--user".into(),
                    "--scope".into(),
                    "--unit".into(),
                    scope.into(),
                    "--property".into(),
                    "Slice=zelynic.slice".into(),
                    "brave".into(),
                ],
                false,
            ));
            plan.steps.push(step(
                "scope: inspect PID in systemd scope",
                BraveCgroupScopeStepKind::InspectExistingScope,
                vec![
                    "systemctl".into(),
                    "--user".into(),
                    "show".into(),
                    scope.clone(),
                ],
                false,
            ));
            plan.rollback_steps.push(rb_step(
                "rollback: stop transient systemd scope",
                BraveCgroupScopeStepKind::RenderRollback,
                vec![
                    "systemctl".into(),
                    "--user".into(),
                    "stop".into(),
                    scope.clone(),
                ],
                false,
            ));
        }
        BraveCgroupScopeStrategy::DedicatedLabCgroup => {
            plan.decision = BraveCgroupScopeDecision::RenderDedicatedLabCgroup;
            let lab_path = "/sys/fs/cgroup/zelynic/intergalaxion/brave-limit".to_string();
            plan.steps.push(step(
                "scope: create dedicated lab cgroup",
                BraveCgroupScopeStepKind::RenderDedicatedCgroup,
                vec!["mkdir".into(), "-p".into(), lab_path.clone()],
                true,
            ));
            plan.steps.push(step(
                "scope: move process to lab cgroup",
                BraveCgroupScopeStepKind::RenderProcessMove,
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!("echo {pid_str} > {lab_path}/cgroup.procs"),
                ],
                true,
            ));
            plan.steps.push(step(
                "scope: verify process in lab cgroup",
                BraveCgroupScopeStepKind::InspectExistingScope,
                vec!["cat".into(), format!("{lab_path}/cgroup.procs")],
                true,
            ));
            plan.rollback_steps.push(rb_step(
                "rollback: move process back to parent cgroup",
                BraveCgroupScopeStepKind::RenderRollback,
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!("echo {pid_str} > /sys/fs/cgroup/cgroup.procs"),
                ],
                true,
            ));
            plan.rollback_steps.push(rb_step(
                "rollback: remove dedicated lab cgroup",
                BraveCgroupScopeStepKind::RenderRollback,
                vec!["rmdir".into(), lab_path],
                true,
            ));
        }
        BraveCgroupScopeStrategy::Unsupported => {
            plan.decision = BraveCgroupScopeDecision::Stop;
            plan.status = BraveCgroupScopeStatus::Unsupported;
            findings.push("unsupported strategy".into());
            blocked = true;
        }
    }
    if !blocked {
        plan.status = BraveCgroupScopeStatus::DryRunReady;
        plan.dry_run_ready = true;
    }
    plan.findings = findings;
    plan
}

/// Validate a brave cgroup scope dry-run plan.
///
/// Rejects any plan that violates I-34 safety invariants.
pub fn validate_brave_cgroup_scope_dry_run_plan(
    plan: &BraveCgroupScopeDryRunPlan,
) -> Result<(), String> {
    if plan.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-34"))
        } else {
            Ok(())
        }
    };
    deny(plan.live_apply_allowed, "live_apply_allowed")?;
    deny(plan.release_allowed, "release_allowed")?;
    deny(!plan.must_remain_experimental, "must_remain_experimental")?;
    deny(plan.public_cli_exposed, "public_cli_exposed")?;
    deny(plan.proc_scan_performed, "proc_scan_performed")?;
    deny(plan.cgroup_read_performed, "cgroup_read_performed")?;
    deny(plan.systemd_query_performed, "systemd_query_performed")?;
    deny(plan.cgroup_create_performed, "cgroup_create_performed")?;
    deny(plan.process_move_performed, "process_move_performed")?;
    deny(plan.cgroup_mutation_performed, "cgroup_mutation_performed")?;
    deny(plan.persistence_performed, "persistence_performed")?;
    deny(
        plan.fake_scope_success_detected,
        "fake_scope_success_detected",
    )?;
    deny(
        plan.fake_identity_success_detected,
        "fake_identity_success_detected",
    )?;
    // dry_run_ready requires selected PID and cgroup
    if plan.dry_run_ready && plan.selected_pid.is_none() {
        return Err("dry_run_ready requires selected_pid".to_string());
    }
    if plan.dry_run_ready && plan.selected_cgroup_path.is_none() {
        return Err("dry_run_ready requires selected_cgroup_path".to_string());
    }
    // No step may have mutates_system=true
    for (i, s) in plan.steps.iter().enumerate() {
        if s.mutates_system {
            return Err(format!("step [{i}] ({}) has mutates_system=true", s.label));
        }
    }
    for (i, s) in plan.rollback_steps.iter().enumerate() {
        if s.mutates_system {
            return Err(format!(
                "rollback [{i}] ({}) has mutates_system=true",
                s.label
            ));
        }
    }
    Ok(())
}

/// Map strategy to label.
pub fn brave_cgroup_scope_strategy_label(strategy: BraveCgroupScopeStrategy) -> &'static str {
    strategy.as_str()
}

/// Map scope status to label.
pub fn brave_cgroup_scope_status_label(status: BraveCgroupScopeStatus) -> &'static str {
    status.as_str()
}

/// Map decision to label.
pub fn brave_cgroup_scope_decision_label(decision: BraveCgroupScopeDecision) -> &'static str {
    decision.as_str()
}

/// Map step kind to label.
pub fn brave_cgroup_scope_step_kind_label(kind: BraveCgroupScopeStepKind) -> &'static str {
    kind.as_str()
}
