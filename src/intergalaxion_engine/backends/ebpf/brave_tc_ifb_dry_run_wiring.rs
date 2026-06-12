// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Brave tc/IFB dry-run wiring plan model for the Intergalaxion Engine (I-35).
//!
//! Connects I-32 Brave 100KB/s limit plan, I-33 Brave identity scope proof,
//! and I-34 Brave cgroup scope dry-run plan into a concrete tc/IFB wiring
//! plan. Renders command intent only. Dry-run only. No tc execution, no ip
//! execution, no IFB creation, no qdisc/filter creation, no cgroup mutation,
//! no packet drop, no enforcement, no public CLI exposure.
//! release_allowed is always false. must_remain_experimental is always true.
//! Live apply is forbidden in I-35.

use crate::intergalaxion_engine::backends::ebpf::brave_cgroup_scope_dry_run::{
    validate_brave_cgroup_scope_dry_run_plan, BraveCgroupScopeDryRunPlan,
};
use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
    validate_brave_identity_scope_proof, BraveIdentityScopeProof,
};
use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
    parse_limit_rate_bytes_per_sec, validate_brave_limit_lab_plan, BraveLimitLabPlan,
};

/// Direction of the wiring path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveTcIfbDirection {
    Upload,
    Download,
}
impl BraveTcIfbDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

/// Backend path for tc/IFB wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveTcIfbWiringBackend {
    TcEgressHtb,
    TcIngressIfbRedirect,
    CgroupFilter,
    Unsupported,
}
impl BraveTcIfbWiringBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcEgressHtb => "tc_egress_htb",
            Self::TcIngressIfbRedirect => "tc_ingress_ifb_redirect",
            Self::CgroupFilter => "cgroup_filter",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Status of the wiring plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveTcIfbWiringStatus {
    Draft,
    DryRunReady,
    Blocked,
    LiveApplyForbidden,
    Unsupported,
}
impl BraveTcIfbWiringStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::DryRunReady => "dry_run_ready",
            Self::Blocked => "blocked",
            Self::LiveApplyForbidden => "live_apply_forbidden",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Decision produced by the wiring plan evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveTcIfbWiringDecision {
    Stop,
    RenderUploadTcEgress,
    RenderDownloadIfbIngress,
    RenderFullDryRun,
    RequireReadyIdentity,
    RequireReadyScope,
    RequireInterface,
    RejectLiveApply,
    RejectPublicCli,
    RejectMutation,
}
impl BraveTcIfbWiringDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::RenderUploadTcEgress => "render_upload_tc_egress",
            Self::RenderDownloadIfbIngress => "render_download_ifb_ingress",
            Self::RenderFullDryRun => "render_full_dry_run",
            Self::RequireReadyIdentity => "require_ready_identity",
            Self::RequireReadyScope => "require_ready_scope",
            Self::RequireInterface => "require_interface",
            Self::RejectLiveApply => "reject_live_apply",
            Self::RejectPublicCli => "reject_public_cli",
            Self::RejectMutation => "reject_mutation",
        }
    }
}

/// Kind of dry-run wiring step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveTcIfbWiringStepKind {
    TcRootQdisc,
    TcClass,
    TcCgroupFilter,
    IngressQdisc,
    IfbLinkAdd,
    IfbLinkUp,
    IngressRedirect,
    IfbRootQdisc,
    IfbClass,
    Rollback,
    Noop,
}
impl BraveTcIfbWiringStepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcRootQdisc => "render_tc_root_qdisc",
            Self::TcClass => "render_tc_class",
            Self::TcCgroupFilter => "render_tc_cgroup_filter",
            Self::IngressQdisc => "render_ingress_qdisc",
            Self::IfbLinkAdd => "render_ifb_link_add",
            Self::IfbLinkUp => "render_ifb_link_up",
            Self::IngressRedirect => "render_ingress_redirect",
            Self::IfbRootQdisc => "render_ifb_root_qdisc",
            Self::IfbClass => "render_ifb_class",
            Self::Rollback => "render_rollback",
            Self::Noop => "render_noop",
        }
    }
}

/// A single dry-run step rendered by the wiring plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveTcIfbDryRunStep {
    pub label: String,
    pub kind: BraveTcIfbWiringStepKind,
    pub direction: Option<BraveTcIfbDirection>,
    pub command: Vec<String>,
    pub requires_root: bool,
    pub mutates_system: bool,
    pub rollback: bool,
}

/// Input to the tc/IFB dry-run wiring builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveTcIfbDryRunWiringInput {
    pub limit_plan: BraveLimitLabPlan,
    pub identity_proof: BraveIdentityScopeProof,
    pub scope_plan: BraveCgroupScopeDryRunPlan,
    pub interface: Option<String>,
    pub ifb_name: String,
    pub cgroup_class_id: Option<String>,
    pub download_rate: Option<String>,
    pub upload_rate: Option<String>,
    pub explicit_dry_run: bool,
    pub explicit_live_apply: bool,
    pub explicit_experimental_ack: bool,
    pub public_cli_requested: bool,
    pub allow_tc_apply: bool,
    pub allow_ip_apply: bool,
    pub allow_ifb_create: bool,
    pub allow_filter_create: bool,
    pub allow_qdisc_create: bool,
    pub allow_cgroup_mutation: bool,
    pub allow_packet_drop: bool,
    pub allow_persistence: bool,
}

/// Output tc/IFB dry-run wiring plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveTcIfbDryRunWiringPlan {
    pub phase: String,
    pub status: BraveTcIfbWiringStatus,
    pub decision: BraveTcIfbWiringDecision,
    pub upload_backend: BraveTcIfbWiringBackend,
    pub download_backend: BraveTcIfbWiringBackend,
    pub dry_run_ready: bool,
    pub live_apply_allowed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub interface: Option<String>,
    pub ifb_name: String,
    pub cgroup_class_id: Option<String>,
    pub download_rate_bytes_per_sec: Option<u64>,
    pub upload_rate_bytes_per_sec: Option<u64>,
    pub identity_ready: bool,
    pub scope_dry_run_ready: bool,
    pub upload_wiring_rendered: bool,
    pub download_wiring_rendered: bool,
    pub upload_live_limit_proven: bool,
    pub download_live_limit_proven: bool,
    pub public_cli_exposed: bool,
    pub tc_apply_performed: bool,
    pub ip_apply_performed: bool,
    pub ifb_create_performed: bool,
    pub filter_create_performed: bool,
    pub qdisc_create_performed: bool,
    pub cgroup_mutation_performed: bool,
    pub packet_drop_performed: bool,
    pub persistence_performed: bool,
    pub fake_upload_limit_success_detected: bool,
    pub fake_download_limit_success_detected: bool,
    pub fake_wiring_success_detected: bool,
    pub steps: Vec<BraveTcIfbDryRunStep>,
    pub rollback_steps: Vec<BraveTcIfbDryRunStep>,
    pub findings: Vec<String>,
}

fn safe_base_plan() -> BraveTcIfbDryRunWiringPlan {
    BraveTcIfbDryRunWiringPlan {
        phase: "I-35".into(),
        status: BraveTcIfbWiringStatus::Draft,
        decision: BraveTcIfbWiringDecision::Stop,
        upload_backend: BraveTcIfbWiringBackend::Unsupported,
        download_backend: BraveTcIfbWiringBackend::Unsupported,
        dry_run_ready: false,
        live_apply_allowed: false,
        release_allowed: false,
        must_remain_experimental: true,
        interface: None,
        ifb_name: String::new(),
        cgroup_class_id: None,
        download_rate_bytes_per_sec: None,
        upload_rate_bytes_per_sec: None,
        identity_ready: false,
        scope_dry_run_ready: false,
        upload_wiring_rendered: false,
        download_wiring_rendered: false,
        upload_live_limit_proven: false,
        download_live_limit_proven: false,
        public_cli_exposed: false,
        tc_apply_performed: false,
        ip_apply_performed: false,
        ifb_create_performed: false,
        filter_create_performed: false,
        qdisc_create_performed: false,
        cgroup_mutation_performed: false,
        packet_drop_performed: false,
        persistence_performed: false,
        fake_upload_limit_success_detected: false,
        fake_download_limit_success_detected: false,
        fake_wiring_success_detected: false,
        steps: Vec::new(),
        rollback_steps: Vec::new(),
        findings: Vec::new(),
    }
}

/// Returns a safe default input for the tc/IFB dry-run wiring plan.
#[rustfmt::skip]
pub fn default_brave_tc_ifb_dry_run_wiring_input() -> BraveTcIfbDryRunWiringInput {
    use crate::intergalaxion_engine::backends::ebpf::brave_cgroup_scope_dry_run::{
        build_brave_cgroup_scope_dry_run_plan, default_brave_cgroup_scope_dry_run_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
        build_brave_identity_scope_proof, default_brave_identity_scope_proof_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::brave_limit_lab_plan::{
        build_brave_limit_lab_plan, default_brave_limit_lab_plan_input,
    };
    BraveTcIfbDryRunWiringInput {
        limit_plan: build_brave_limit_lab_plan(&default_brave_limit_lab_plan_input()),
        identity_proof: build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input()),
        scope_plan: build_brave_cgroup_scope_dry_run_plan(&default_brave_cgroup_scope_dry_run_input()),
        interface: Some("eth0".into()),
        ifb_name: "ifb-zelynic-brave".into(),
        cgroup_class_id: Some("0x100001".into()),
        download_rate: Some("100KB/s".into()),
        upload_rate: Some("100KB/s".into()),
        explicit_dry_run: true,
        explicit_live_apply: false,
        explicit_experimental_ack: false,
        public_cli_requested: false,
        allow_tc_apply: false,
        allow_ip_apply: false,
        allow_ifb_create: false,
        allow_filter_create: false,
        allow_qdisc_create: false,
        allow_cgroup_mutation: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

#[inline]
fn step(
    label: &str,
    kind: BraveTcIfbWiringStepKind,
    direction: Option<BraveTcIfbDirection>,
    cmd: Vec<String>,
    root: bool,
) -> BraveTcIfbDryRunStep {
    BraveTcIfbDryRunStep {
        label: label.into(),
        kind,
        direction,
        command: cmd,
        requires_root: root,
        mutates_system: false,
        rollback: false,
    }
}

#[inline]
fn rb_step(
    label: &str,
    kind: BraveTcIfbWiringStepKind,
    direction: Option<BraveTcIfbDirection>,
    cmd: Vec<String>,
    root: bool,
) -> BraveTcIfbDryRunStep {
    BraveTcIfbDryRunStep {
        label: label.into(),
        kind,
        direction,
        command: cmd,
        requires_root: root,
        mutates_system: false,
        rollback: true,
    }
}

/// Build the brave tc/IFB dry-run wiring plan from the given input.
///
/// Renders command intent only. Never executes. Never mutates system.
pub fn build_brave_tc_ifb_dry_run_wiring_plan(
    input: &BraveTcIfbDryRunWiringInput,
) -> BraveTcIfbDryRunWiringPlan {
    let mut plan = safe_base_plan();
    let mut findings: Vec<String> = Vec::new();
    let mut blocked = false;

    plan.interface = input.interface.clone();
    plan.ifb_name = input.ifb_name.clone();
    plan.cgroup_class_id = input.cgroup_class_id.clone();

    // Public CLI rejection
    if input.public_cli_requested {
        plan.decision = BraveTcIfbWiringDecision::RejectPublicCli;
        plan.status = BraveTcIfbWiringStatus::Blocked;
        plan.public_cli_exposed = true;
        findings.push("public CLI is not exposed in I-35".into());
        blocked = true;
    }
    // Live apply rejection (always forbidden in I-35)
    if input.explicit_live_apply {
        plan.decision = BraveTcIfbWiringDecision::RejectLiveApply;
        plan.status = BraveTcIfbWiringStatus::LiveApplyForbidden;
        findings.push("live apply is forbidden in I-35".into());
        blocked = true;
    }
    // Mutation allowance rejections
    if input.allow_tc_apply {
        findings.push("allow_tc_apply is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_ip_apply {
        findings.push("allow_ip_apply is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_ifb_create {
        findings.push("allow_ifb_create is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_filter_create {
        findings.push("allow_filter_create is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_qdisc_create {
        findings.push("allow_qdisc_create is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_cgroup_mutation {
        findings.push("allow_cgroup_mutation is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_packet_drop {
        findings.push("allow_packet_drop is rejected in I-35".into());
        blocked = true;
    }
    if input.allow_persistence {
        findings.push("allow_persistence is rejected in I-35".into());
        blocked = true;
    }
    if blocked {
        plan.findings = findings;
        return plan;
    }

    // Validate consumed evidence
    let lp_ok = validate_brave_limit_lab_plan(&input.limit_plan).is_ok();
    let id_ok = validate_brave_identity_scope_proof(&input.identity_proof).is_ok();
    let sp_ok = validate_brave_cgroup_scope_dry_run_plan(&input.scope_plan).is_ok();
    if !lp_ok {
        findings.push("limit plan validation failed".into());
        blocked = true;
    }
    if !id_ok {
        findings.push("identity proof validation failed".into());
        blocked = true;
    }
    if !sp_ok {
        findings.push("scope plan validation failed".into());
        blocked = true;
    }

    // Identity readiness check
    plan.identity_ready = input.identity_proof.identity_ready;
    if !input.identity_proof.identity_ready {
        plan.decision = BraveTcIfbWiringDecision::RequireReadyIdentity;
        plan.status = BraveTcIfbWiringStatus::Blocked;
        findings.push("identity proof is not ready — requires PID + cgroup".into());
        blocked = true;
    }

    // Scope readiness check
    plan.scope_dry_run_ready = input.scope_plan.dry_run_ready;
    if !input.scope_plan.dry_run_ready {
        plan.decision = BraveTcIfbWiringDecision::RequireReadyScope;
        plan.status = BraveTcIfbWiringStatus::Blocked;
        findings.push("scope plan is not dry-run ready".into());
        blocked = true;
    }

    // Interface required
    if input.interface.is_none() {
        plan.decision = BraveTcIfbWiringDecision::RequireInterface;
        plan.status = BraveTcIfbWiringStatus::Blocked;
        findings.push("interface is required for tc/IFB wiring".into());
        blocked = true;
    }

    // cgroup_class_id required
    if input.cgroup_class_id.is_none() {
        findings.push("cgroup_class_id is required for cgroup filter wiring".into());
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

    // Parse rates
    let dl_rate: Option<u64> = match &input.download_rate {
        Some(r) => match parse_limit_rate_bytes_per_sec(r) {
            Ok(v) => Some(v),
            Err(e) => {
                findings.push(format!("download rate parse error: {e}"));
                blocked = true;
                None
            }
        },
        None => None,
    };
    let ul_rate: Option<u64> = match &input.upload_rate {
        Some(r) => match parse_limit_rate_bytes_per_sec(r) {
            Ok(v) => Some(v),
            Err(e) => {
                findings.push(format!("upload rate parse error: {e}"));
                blocked = true;
                None
            }
        },
        None => None,
    };
    if blocked {
        plan.findings = findings;
        return plan;
    }

    plan.download_rate_bytes_per_sec = dl_rate;
    plan.upload_rate_bytes_per_sec = ul_rate;

    let iface = input.interface.as_deref().unwrap_or("<iface>");
    let ifb = &input.ifb_name;
    let class_id = input.cgroup_class_id.as_deref().unwrap_or("<class>");
    let rate_str = |bps: u64| format!("{bps}bps");

    // Render upload wiring (tc egress HTB + cgroup filter)
    if let Some(ul) = ul_rate {
        plan.upload_backend = BraveTcIfbWiringBackend::TcEgressHtb;
        plan.steps.push(step(
            "upload: create root HTB qdisc",
            BraveTcIfbWiringStepKind::TcRootQdisc,
            Some(BraveTcIfbDirection::Upload),
            vec![
                "tc".into(),
                "qdisc".into(),
                "replace".into(),
                "dev".into(),
                iface.into(),
                "root".into(),
                "handle".into(),
                "1:".into(),
                "htb".into(),
                "default".into(),
                "10".into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "upload: create class with rate limit",
            BraveTcIfbWiringStepKind::TcClass,
            Some(BraveTcIfbDirection::Upload),
            vec![
                "tc".into(),
                "class".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "parent".into(),
                "1:".into(),
                "classid".into(),
                class_id.into(),
                "htb".into(),
                "rate".into(),
                rate_str(ul),
            ],
            true,
        ));
        plan.steps.push(step(
            "upload: add cgroup filter",
            BraveTcIfbWiringStepKind::TcCgroupFilter,
            Some(BraveTcIfbDirection::Upload),
            vec![
                "tc".into(),
                "filter".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "protocol".into(),
                "ip".into(),
                "parent".into(),
                "1:".into(),
                "prio".into(),
                "1".into(),
                "cgroup".into(),
            ],
            true,
        ));
        plan.upload_wiring_rendered = true;
        // Upload rollback
        plan.rollback_steps.push(rb_step(
            "rollback: delete root qdisc on interface",
            BraveTcIfbWiringStepKind::Rollback,
            Some(BraveTcIfbDirection::Upload),
            vec![
                "tc".into(),
                "qdisc".into(),
                "delete".into(),
                "dev".into(),
                iface.into(),
                "root".into(),
            ],
            true,
        ));
    }

    // Render download wiring (IFB ingress redirect)
    if let Some(dl) = dl_rate {
        plan.download_backend = BraveTcIfbWiringBackend::TcIngressIfbRedirect;
        plan.steps.push(step(
            "download: add IFB device",
            BraveTcIfbWiringStepKind::IfbLinkAdd,
            Some(BraveTcIfbDirection::Download),
            vec![
                "ip".into(),
                "link".into(),
                "add".into(),
                ifb.into(),
                "type".into(),
                "ifb".into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "download: set IFB device up",
            BraveTcIfbWiringStepKind::IfbLinkUp,
            Some(BraveTcIfbDirection::Download),
            vec![
                "ip".into(),
                "link".into(),
                "set".into(),
                ifb.into(),
                "up".into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "download: add ingress qdisc on interface",
            BraveTcIfbWiringStepKind::IngressQdisc,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "qdisc".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "download: redirect ingress to IFB",
            BraveTcIfbWiringStepKind::IngressRedirect,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "filter".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
                "protocol".into(),
                "ip".into(),
                "parent".into(),
                "ffff:".into(),
                "prio".into(),
                "1".into(),
                "flower".into(),
                "action".into(),
                "mirred".into(),
                "egress".into(),
                "redirect".into(),
                "dev".into(),
                ifb.into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "download: create root HTB on IFB",
            BraveTcIfbWiringStepKind::IfbRootQdisc,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "qdisc".into(),
                "add".into(),
                "dev".into(),
                ifb.into(),
                "root".into(),
                "handle".into(),
                "1:".into(),
                "htb".into(),
            ],
            true,
        ));
        plan.steps.push(step(
            "download: create class with rate limit on IFB",
            BraveTcIfbWiringStepKind::IfbClass,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "class".into(),
                "add".into(),
                "dev".into(),
                ifb.into(),
                "parent".into(),
                "1:".into(),
                "classid".into(),
                "1:10".into(),
                "htb".into(),
                "rate".into(),
                rate_str(dl),
            ],
            true,
        ));
        plan.download_wiring_rendered = true;
        // Download rollback
        plan.rollback_steps.push(rb_step(
            "rollback: delete ingress qdisc on interface",
            BraveTcIfbWiringStepKind::Rollback,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "qdisc".into(),
                "delete".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
            ],
            true,
        ));
        plan.rollback_steps.push(rb_step(
            "rollback: delete root qdisc on IFB",
            BraveTcIfbWiringStepKind::Rollback,
            Some(BraveTcIfbDirection::Download),
            vec![
                "tc".into(),
                "qdisc".into(),
                "delete".into(),
                "dev".into(),
                ifb.into(),
                "root".into(),
            ],
            true,
        ));
        plan.rollback_steps.push(rb_step(
            "rollback: delete IFB device",
            BraveTcIfbWiringStepKind::Rollback,
            Some(BraveTcIfbDirection::Download),
            vec!["ip".into(), "link".into(), "delete".into(), ifb.into()],
            true,
        ));
    }

    // Final plan status
    if ul_rate.is_some() && dl_rate.is_some() {
        plan.decision = BraveTcIfbWiringDecision::RenderFullDryRun;
    } else if ul_rate.is_some() {
        plan.decision = BraveTcIfbWiringDecision::RenderUploadTcEgress;
    } else {
        plan.decision = BraveTcIfbWiringDecision::RenderDownloadIfbIngress;
    }
    plan.status = BraveTcIfbWiringStatus::DryRunReady;
    plan.dry_run_ready = true;
    plan.live_apply_allowed = false;

    findings.push("upload live limit is not proven in I-35".into());
    findings.push("download live limit is not proven in I-35".into());

    plan.findings = findings;
    plan
}

/// Validate a brave tc/IFB dry-run wiring plan.
///
/// Rejects any plan that violates I-35 safety invariants.
pub fn validate_brave_tc_ifb_dry_run_wiring_plan(
    plan: &BraveTcIfbDryRunWiringPlan,
) -> Result<(), String> {
    if plan.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-35"))
        } else {
            Ok(())
        }
    };
    deny(plan.live_apply_allowed, "live_apply_allowed")?;
    deny(plan.release_allowed, "release_allowed")?;
    deny(!plan.must_remain_experimental, "must_remain_experimental")?;
    deny(plan.public_cli_exposed, "public_cli_exposed")?;
    deny(plan.tc_apply_performed, "tc_apply_performed")?;
    deny(plan.ip_apply_performed, "ip_apply_performed")?;
    deny(plan.ifb_create_performed, "ifb_create_performed")?;
    deny(plan.filter_create_performed, "filter_create_performed")?;
    deny(plan.qdisc_create_performed, "qdisc_create_performed")?;
    deny(plan.cgroup_mutation_performed, "cgroup_mutation_performed")?;
    deny(plan.packet_drop_performed, "packet_drop_performed")?;
    deny(plan.persistence_performed, "persistence_performed")?;
    deny(plan.upload_live_limit_proven, "upload_live_limit_proven")?;
    deny(
        plan.download_live_limit_proven,
        "download_live_limit_proven",
    )?;
    deny(
        plan.fake_upload_limit_success_detected,
        "fake_upload_limit_success_detected",
    )?;
    deny(
        plan.fake_download_limit_success_detected,
        "fake_download_limit_success_detected",
    )?;
    deny(
        plan.fake_wiring_success_detected,
        "fake_wiring_success_detected",
    )?;
    // dry_run_ready requires interface
    if plan.dry_run_ready && plan.interface.is_none() {
        return Err("dry_run_ready requires interface".to_string());
    }
    // dry_run_ready requires cgroup_class_id
    if plan.dry_run_ready && plan.cgroup_class_id.is_none() {
        return Err("dry_run_ready requires cgroup_class_id".to_string());
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

/// Map direction to label.
pub fn brave_tc_ifb_direction_label(direction: BraveTcIfbDirection) -> &'static str {
    direction.as_str()
}

/// Map wiring backend to label.
pub fn brave_tc_ifb_wiring_backend_label(backend: BraveTcIfbWiringBackend) -> &'static str {
    backend.as_str()
}

/// Map wiring status to label.
pub fn brave_tc_ifb_wiring_status_label(status: BraveTcIfbWiringStatus) -> &'static str {
    status.as_str()
}

/// Map wiring decision to label.
pub fn brave_tc_ifb_wiring_decision_label(decision: BraveTcIfbWiringDecision) -> &'static str {
    decision.as_str()
}

/// Map wiring step kind to label.
pub fn brave_tc_ifb_wiring_step_kind_label(kind: BraveTcIfbWiringStepKind) -> &'static str {
    kind.as_str()
}
