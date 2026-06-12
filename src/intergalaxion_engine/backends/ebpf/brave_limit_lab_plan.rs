// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Brave 100KB/s local limit lab plan model for the Intergalaxion Engine (I-32).
//!
//! First concrete local lab plan for limiting Brave browser to 100KB/s download
//! and 100KB/s upload. Model-only, dry-run only. No actual tc/ifb/cgroup execution.
//! No packet drop. No enforcement. No public CLI exposure.
//! release_allowed is always false. must_remain_experimental is always true.

/// Direction of the rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveLimitDirection {
    Download,
    Upload,
}
impl BraveLimitDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

/// Backend path for rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveLimitBackend {
    /// tc egress qdisc for upload shaping.
    TcEgress,
    /// IFB ingress redirect for download shaping.
    TcIngressIfb,
    /// cgroup-scoped tc for process-attributed shaping.
    CgroupScopedTc,
    /// Backend not supported for this phase.
    Unsupported,
}
impl BraveLimitBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcEgress => "tc_egress",
            Self::TcIngressIfb => "tc_ingress_ifb",
            Self::CgroupScopedTc => "cgroup_scoped_tc",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Status of the Brave target identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveLimitTargetStatus {
    Unknown,
    Candidate,
    Ready,
    Blocked,
}
impl BraveLimitTargetStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Candidate => "candidate",
            Self::Ready => "ready",
            Self::Blocked => "blocked",
        }
    }
}

/// Status of the lab plan itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveLimitLabPlanStatus {
    Draft,
    DryRunReady,
    Blocked,
    LiveApplyForbidden,
    Unsupported,
}
impl BraveLimitLabPlanStatus {
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

/// Decision produced by the lab plan evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveLimitLabDecision {
    Stop,
    RenderDryRun,
    RequireInterface,
    RequireBraveIdentity,
    RequireRootForFutureApply,
    RequireIfbForDownload,
    RejectLiveApply,
    RejectPublicCli,
}
impl BraveLimitLabDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::RenderDryRun => "render_dry_run",
            Self::RequireInterface => "require_interface",
            Self::RequireBraveIdentity => "require_brave_identity",
            Self::RequireRootForFutureApply => "require_root_for_future_apply",
            Self::RequireIfbForDownload => "require_ifb_for_download",
            Self::RejectLiveApply => "reject_live_apply",
            Self::RejectPublicCli => "reject_public_cli",
        }
    }
}

/// A single command step rendered by the lab plan (dry-run only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveLimitCommandStep {
    /// Human-readable label for this step.
    pub label: String,
    /// Command tokens that would be executed.
    pub command: Vec<String>,
    /// Whether this step requires root (sudo).
    pub requires_root: bool,
    /// Whether this step would mutate the system.
    pub mutates_system: bool,
    /// Whether this step is a rollback command.
    pub rollback: bool,
}

/// Input to the brave limit lab plan builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveLimitLabPlanInput {
    pub target_name: String,
    pub interface: Option<String>,
    pub download_rate: Option<String>,
    pub upload_rate: Option<String>,
    pub brave_pid_known: bool,
    pub brave_cgroup_known: bool,
    pub explicit_dry_run: bool,
    pub explicit_live_apply: bool,
    pub explicit_experimental_ack: bool,
    pub public_cli_requested: bool,
    pub allow_tc_mutation: bool,
    pub allow_ifb_mutation: bool,
    pub allow_cgroup_mutation: bool,
    pub allow_packet_drop: bool,
    pub allow_persistence: bool,
}

/// Output lab plan with rendered dry-run commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveLimitLabPlan {
    pub phase: String,
    pub status: BraveLimitLabPlanStatus,
    pub decision: BraveLimitLabDecision,
    pub target_status: BraveLimitTargetStatus,
    pub backend_upload: BraveLimitBackend,
    pub backend_download: BraveLimitBackend,
    pub dry_run_ready: bool,
    pub live_apply_allowed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub target_name: String,
    pub interface: Option<String>,
    pub download_rate_bytes_per_sec: Option<u64>,
    pub upload_rate_bytes_per_sec: Option<u64>,
    pub brave_pid_known: bool,
    pub brave_cgroup_known: bool,
    pub public_cli_exposed: bool,
    pub tc_mutation_performed: bool,
    pub ifb_mutation_performed: bool,
    pub cgroup_mutation_performed: bool,
    pub packet_drop_performed: bool,
    pub persistence_performed: bool,
    pub fake_limit_success_detected: bool,
    pub download_limit_claimed_without_ifb_proof: bool,
    pub upload_limit_claimed_without_tc_proof: bool,
    pub commands: Vec<BraveLimitCommandStep>,
    pub rollback_commands: Vec<BraveLimitCommandStep>,
    pub findings: Vec<String>,
}

/// Parse a human-readable rate string into bytes per second.
///
/// Accepted formats: "100KB/s", "100kb/s", "100KiB/s"
/// 1 KB = 1024 bytes (binary interpretation).
/// Returns the rate in bytes per second.
pub fn parse_limit_rate_bytes_per_sec(rate: &str) -> Result<u64, String> {
    let trimmed = rate.trim();
    if trimmed.is_empty() {
        return Err("rate must not be empty".to_string());
    }
    let lower = trimmed.to_lowercase();
    let (num_str, multiplier) = if lower.ends_with("kib/s") {
        (&lower[..lower.len() - 5], 1024u64)
    } else if lower.ends_with("kb/s") {
        // Accepts both "100KB/s" and "100kb/s" (case-insensitive after lower)
        (&lower[..lower.len() - 4], 1024u64)
    } else {
        return Err(format!("unsupported rate format: {trimmed}"));
    };
    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("cannot parse rate number: {num_str}"))?;
    if num == 0 {
        return Err("rate must not be zero".to_string());
    }
    Ok(num * multiplier)
}

#[inline]
fn safe_base_plan() -> BraveLimitLabPlan {
    BraveLimitLabPlan {
        phase: "I-32".into(),
        status: BraveLimitLabPlanStatus::Draft,
        decision: BraveLimitLabDecision::Stop,
        target_status: BraveLimitTargetStatus::Unknown,
        backend_upload: BraveLimitBackend::Unsupported,
        backend_download: BraveLimitBackend::Unsupported,
        dry_run_ready: false,
        live_apply_allowed: false,
        release_allowed: false,
        must_remain_experimental: true,
        target_name: String::new(),
        interface: None,
        download_rate_bytes_per_sec: None,
        upload_rate_bytes_per_sec: None,
        brave_pid_known: false,
        brave_cgroup_known: false,
        public_cli_exposed: false,
        tc_mutation_performed: false,
        ifb_mutation_performed: false,
        cgroup_mutation_performed: false,
        packet_drop_performed: false,
        persistence_performed: false,
        fake_limit_success_detected: false,
        download_limit_claimed_without_ifb_proof: false,
        upload_limit_claimed_without_tc_proof: false,
        commands: Vec::new(),
        rollback_commands: Vec::new(),
        findings: Vec::new(),
    }
}

/// Returns a safe default input for the brave limit lab plan.
#[rustfmt::skip]
pub fn default_brave_limit_lab_plan_input() -> BraveLimitLabPlanInput {
    BraveLimitLabPlanInput {
        target_name: "brave".into(),
        interface: None,
        download_rate: Some("100KB/s".into()),
        upload_rate: Some("100KB/s".into()),
        brave_pid_known: false,
        brave_cgroup_known: false,
        explicit_dry_run: true,
        explicit_live_apply: false,
        explicit_experimental_ack: false,
        public_cli_requested: false,
        allow_tc_mutation: false,
        allow_ifb_mutation: false,
        allow_cgroup_mutation: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

/// Build the brave limit lab plan from the given input.
///
/// This function only renders dry-run command intent. It never executes
/// any command, never mutates the system, and never performs packet drop.
pub fn build_brave_limit_lab_plan(input: &BraveLimitLabPlanInput) -> BraveLimitLabPlan {
    let mut plan = safe_base_plan();
    let mut findings: Vec<String> = Vec::new();
    let mut blocked = false;
    // Target identification
    let is_brave = input.target_name == "brave" || input.target_name == "brave-browser";
    if !is_brave {
        plan.decision = BraveLimitLabDecision::RequireBraveIdentity;
        plan.target_status = BraveLimitTargetStatus::Blocked;
        plan.status = BraveLimitLabPlanStatus::Blocked;
        findings.push("target_name must be brave or brave-browser".into());
        blocked = true;
    } else {
        plan.target_status = BraveLimitTargetStatus::Candidate;
        plan.target_name = input.target_name.clone();
    }
    // Public CLI request rejection
    if input.public_cli_requested {
        plan.decision = BraveLimitLabDecision::RejectPublicCli;
        plan.status = BraveLimitLabPlanStatus::Blocked;
        plan.public_cli_exposed = true;
        findings.push("public CLI is not exposed in I-32".into());
        blocked = true;
    }
    // Live apply rejection (always forbidden in I-32)
    if input.explicit_live_apply {
        plan.decision = BraveLimitLabDecision::RejectLiveApply;
        plan.status = BraveLimitLabPlanStatus::LiveApplyForbidden;
        findings.push("live apply is forbidden in I-32".into());
        blocked = true;
    }
    // Mutation allowance rejections
    if input.allow_tc_mutation {
        findings.push("tc mutation allowance is rejected in I-32".into());
        blocked = true;
    }
    if input.allow_ifb_mutation {
        findings.push("ifb mutation allowance is rejected in I-32".into());
        blocked = true;
    }
    if input.allow_cgroup_mutation {
        findings.push("cgroup mutation allowance is rejected in I-32".into());
        blocked = true;
    }
    if input.allow_packet_drop {
        findings.push("packet drop allowance is rejected in I-32".into());
        blocked = true;
    }
    if input.allow_persistence {
        findings.push("persistence allowance is rejected in I-32".into());
        blocked = true;
    }
    // Interface required
    if input.interface.is_none() && is_brave {
        plan.decision = BraveLimitLabDecision::RequireInterface;
        plan.status = BraveLimitLabPlanStatus::Draft;
        findings.push("interface is required for dry-run rendering".into());
        blocked = true;
    }
    // Dry-run check
    if !input.explicit_dry_run && is_brave && input.interface.is_some() {
        findings.push("explicit_dry_run must be true for dry-run rendering".into());
        blocked = true;
    }
    if blocked {
        plan.findings = findings;
        return plan;
    }
    // Parse rates
    let dl_rate = match &input.download_rate {
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
    let ul_rate = match &input.upload_rate {
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
    // Backend selection
    if ul_rate.is_some() {
        plan.backend_upload = BraveLimitBackend::TcEgress;
    }
    if dl_rate.is_some() {
        plan.backend_download = BraveLimitBackend::TcIngressIfb;
        // Download limiting per app requires IFB ingress attribution proof.
        plan.download_limit_claimed_without_ifb_proof = true;
        findings.push(
            "download limit requires IFB ingress attribution proof (not yet proven in I-32)".into(),
        );
    }
    if ul_rate.is_some() {
        // Upload limiting via tc egress is the planned path but not yet proven.
        plan.upload_limit_claimed_without_tc_proof = true;
        findings.push("upload limit requires tc egress proof (not yet proven in I-32)".into());
    }
    // Target status
    if input.brave_pid_known || input.brave_cgroup_known {
        plan.target_status = BraveLimitTargetStatus::Ready;
    }
    plan.brave_pid_known = input.brave_pid_known;
    plan.brave_cgroup_known = input.brave_cgroup_known;
    // Render dry-run commands
    let iface = input.interface.as_deref().unwrap_or("<iface>");
    let rate_str = |bps: u64| format!("{bps}bps");
    // Upload: tc egress qdisc
    if let Some(ul) = ul_rate {
        plan.commands.push(BraveLimitCommandStep {
            label: "upload: create egress qdisc".into(),
            command: vec![
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
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "upload: create class with rate limit".into(),
            command: vec![
                "tc".into(),
                "class".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "parent".into(),
                "1:".into(),
                "classid".into(),
                "1:10".into(),
                "htb".into(),
                "rate".into(),
                rate_str(ul),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "upload: add filter for brave cgroup".into(),
            command: vec![
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
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        // Rollback for upload
        plan.rollback_commands.push(BraveLimitCommandStep {
            label: "rollback: remove egress qdisc".into(),
            command: vec![
                "tc".into(),
                "qdisc".into(),
                "delete".into(),
                "dev".into(),
                iface.into(),
                "root".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: true,
        });
    }
    // Download: IFB ingress redirect
    if let Some(dl) = dl_rate {
        plan.commands.push(BraveLimitCommandStep {
            label: "download: create IFB device".into(),
            command: vec![
                "ip".into(),
                "link".into(),
                "add".into(),
                "ifb-zelynic-brave".into(),
                "type".into(),
                "ifb".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "download: set IFB device up".into(),
            command: vec![
                "ip".into(),
                "link".into(),
                "set".into(),
                "ifb-zelynic-brave".into(),
                "up".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "download: add ingress qdisc on real iface".into(),
            command: vec![
                "tc".into(),
                "qdisc".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "download: redirect ingress to IFB".into(),
            command: vec![
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
                "ifb-zelynic-brave".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "download: create htb qdisc on IFB".into(),
            command: vec![
                "tc".into(),
                "qdisc".into(),
                "add".into(),
                "dev".into(),
                "ifb-zelynic-brave".into(),
                "root".into(),
                "handle".into(),
                "1:".into(),
                "htb".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        plan.commands.push(BraveLimitCommandStep {
            label: "download: create class with rate limit on IFB".into(),
            command: vec![
                "tc".into(),
                "class".into(),
                "add".into(),
                "dev".into(),
                "ifb-zelynic-brave".into(),
                "parent".into(),
                "1:".into(),
                "classid".into(),
                "1:10".into(),
                "htb".into(),
                "rate".into(),
                rate_str(dl),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: false,
        });
        // Rollback for download/IFB
        plan.rollback_commands.push(BraveLimitCommandStep {
            label: "rollback: remove IFB device".into(),
            command: vec![
                "ip".into(),
                "link".into(),
                "delete".into(),
                "ifb-zelynic-brave".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: true,
        });
        plan.rollback_commands.push(BraveLimitCommandStep {
            label: "rollback: remove ingress qdisc".into(),
            command: vec![
                "tc".into(),
                "qdisc".into(),
                "delete".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
            ],
            requires_root: true,
            mutates_system: false,
            rollback: true,
        });
    }
    // Final plan status
    plan.decision = BraveLimitLabDecision::RenderDryRun;
    plan.status = BraveLimitLabPlanStatus::DryRunReady;
    plan.dry_run_ready = true;
    plan.live_apply_allowed = false;
    plan.findings = findings;
    plan
}

/// Validate a brave limit lab plan.
///
/// Rejects any plan that violates I-32 safety invariants.
pub fn validate_brave_limit_lab_plan(plan: &BraveLimitLabPlan) -> Result<(), String> {
    if plan.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-32"))
        } else {
            Ok(())
        }
    };
    deny(plan.live_apply_allowed, "live_apply_allowed")?;
    deny(plan.release_allowed, "release_allowed")?;
    deny(!plan.must_remain_experimental, "must_remain_experimental")?;
    deny(plan.public_cli_exposed, "public_cli_exposed")?;
    deny(plan.tc_mutation_performed, "tc_mutation_performed")?;
    deny(plan.ifb_mutation_performed, "ifb_mutation_performed")?;
    deny(plan.cgroup_mutation_performed, "cgroup_mutation_performed")?;
    deny(plan.packet_drop_performed, "packet_drop_performed")?;
    deny(plan.persistence_performed, "persistence_performed")?;
    deny(
        plan.fake_limit_success_detected,
        "fake_limit_success_detected",
    )?;
    deny(
        plan.download_limit_claimed_without_ifb_proof,
        "download_limit_claimed_without_ifb_proof",
    )?;
    deny(
        plan.upload_limit_claimed_without_tc_proof,
        "upload_limit_claimed_without_tc_proof",
    )?;
    // No command step may have mutates_system=true
    for (i, cmd) in plan.commands.iter().enumerate() {
        if cmd.mutates_system {
            return Err(format!(
                "apply command [{i}] ({}) has mutates_system=true",
                cmd.label
            ));
        }
    }
    for (i, cmd) in plan.rollback_commands.iter().enumerate() {
        if cmd.mutates_system {
            return Err(format!(
                "rollback command [{i}] ({}) has mutates_system=true",
                cmd.label
            ));
        }
    }
    Ok(())
}

/// Map lab plan status to label.
pub fn brave_limit_lab_plan_status_label(status: BraveLimitLabPlanStatus) -> &'static str {
    status.as_str()
}

/// Map backend to label.
pub fn brave_limit_backend_label(backend: BraveLimitBackend) -> &'static str {
    backend.as_str()
}

/// Map target status to label.
pub fn brave_limit_target_status_label(status: BraveLimitTargetStatus) -> &'static str {
    status.as_str()
}
