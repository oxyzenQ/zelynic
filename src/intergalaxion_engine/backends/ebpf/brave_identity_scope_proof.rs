// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Brave identity scope proof model for the Intergalaxion Engine (I-33).
//!
//! Deterministic model for proving Brave identity scope before any future
//! live 100KB/s upload/download limit. Model-only, dry-run only. No /proc
//! scan, no cgroup read/write, no systemd query, no process mutation.
//! release_allowed is always false. must_remain_experimental is always true.

/// Source of Brave identity information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveIdentitySource {
    ProcessName,
    ExecutablePath,
    CgroupPath,
    SystemdScope,
    FixturePidList,
}
impl BraveIdentitySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessName => "process_name",
            Self::ExecutablePath => "executable_path",
            Self::CgroupPath => "cgroup_path",
            Self::SystemdScope => "systemd_scope",
            Self::FixturePidList => "fixture_pid_list",
        }
    }
}

/// Confidence level of Brave identity attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveIdentityConfidence {
    None,
    Low,
    Medium,
    High,
    Ambiguous,
}
impl BraveIdentityConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Status of the identity scope proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveIdentityScopeStatus {
    Draft,
    Candidate,
    Ready,
    Ambiguous,
    Blocked,
    LiveApplyForbidden,
}
impl BraveIdentityScopeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Candidate => "candidate",
            Self::Ready => "ready",
            Self::Ambiguous => "ambiguous",
            Self::Blocked => "blocked",
            Self::LiveApplyForbidden => "live_apply_forbidden",
        }
    }
}

/// Decision produced by identity scope proof evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraveIdentityDecision {
    Stop,
    AcceptCandidate,
    AcceptReadyScope,
    RequirePidEvidence,
    RequireCgroupEvidence,
    RejectAmbiguousTarget,
    RejectNoTarget,
    RejectLiveApply,
    RejectPublicCli,
}
impl BraveIdentityDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::AcceptCandidate => "accept_candidate",
            Self::AcceptReadyScope => "accept_ready_scope",
            Self::RequirePidEvidence => "require_pid_evidence",
            Self::RequireCgroupEvidence => "require_cgroup_evidence",
            Self::RejectAmbiguousTarget => "reject_ambiguous_target",
            Self::RejectNoTarget => "reject_no_target",
            Self::RejectLiveApply => "reject_live_apply",
            Self::RejectPublicCli => "reject_public_cli",
        }
    }
}

/// A single process candidate for Brave identity matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveProcessCandidate {
    pub pid: Option<u32>,
    pub process_name: String,
    pub executable_path: Option<String>,
    pub cgroup_path: Option<String>,
    pub systemd_scope: Option<String>,
    pub matches_brave_name: bool,
    pub matches_brave_executable: bool,
    pub matches_brave_cgroup: bool,
}

/// Input to the brave identity scope proof builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveIdentityScopeProofInput {
    pub target_name: String,
    pub candidates: Vec<BraveProcessCandidate>,
    pub explicit_dry_run: bool,
    pub explicit_live_apply: bool,
    pub public_cli_requested: bool,
    pub allow_proc_scan: bool,
    pub allow_cgroup_read: bool,
    pub allow_systemd_query: bool,
    pub allow_cgroup_mutation: bool,
    pub allow_process_mutation: bool,
    pub allow_persistence: bool,
}

/// Output identity scope proof report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraveIdentityScopeProof {
    pub phase: String,
    pub status: BraveIdentityScopeStatus,
    pub decision: BraveIdentityDecision,
    pub confidence: BraveIdentityConfidence,
    pub target_name: String,
    pub candidate_count: usize,
    pub matching_candidate_count: usize,
    pub selected_pid: Option<u32>,
    pub selected_cgroup_path: Option<String>,
    pub selected_systemd_scope: Option<String>,
    pub identity_ready: bool,
    pub live_apply_allowed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub public_cli_exposed: bool,
    pub proc_scan_performed: bool,
    pub cgroup_read_performed: bool,
    pub systemd_query_performed: bool,
    pub cgroup_mutation_performed: bool,
    pub process_mutation_performed: bool,
    pub persistence_performed: bool,
    pub fake_identity_success_detected: bool,
    pub ambiguous_identity_detected: bool,
    pub findings: Vec<String>,
}

fn safe_base_proof() -> BraveIdentityScopeProof {
    BraveIdentityScopeProof {
        phase: "I-33".into(),
        status: BraveIdentityScopeStatus::Draft,
        decision: BraveIdentityDecision::Stop,
        confidence: BraveIdentityConfidence::None,
        target_name: String::new(),
        candidate_count: 0,
        matching_candidate_count: 0,
        selected_pid: None,
        selected_cgroup_path: None,
        selected_systemd_scope: None,
        identity_ready: false,
        live_apply_allowed: false,
        release_allowed: false,
        must_remain_experimental: true,
        public_cli_exposed: false,
        proc_scan_performed: false,
        cgroup_read_performed: false,
        systemd_query_performed: false,
        cgroup_mutation_performed: false,
        process_mutation_performed: false,
        persistence_performed: false,
        fake_identity_success_detected: false,
        ambiguous_identity_detected: false,
        findings: Vec::new(),
    }
}

/// Returns a safe default input for the identity scope proof.
#[rustfmt::skip]
pub fn default_brave_identity_scope_proof_input() -> BraveIdentityScopeProofInput {
    BraveIdentityScopeProofInput {
        target_name: "brave".into(),
        candidates: Vec::new(),
        explicit_dry_run: true,
        explicit_live_apply: false,
        public_cli_requested: false,
        allow_proc_scan: false,
        allow_cgroup_read: false,
        allow_systemd_query: false,
        allow_cgroup_mutation: false,
        allow_process_mutation: false,
        allow_persistence: false,
    }
}

/// Check whether a candidate process name matches Brave.
fn is_brave_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "brave" || n == "brave-browser"
}

/// Check whether an executable path matches Brave.
fn is_brave_executable(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("brave") || l.contains("brave-browser")
}

/// Check whether a cgroup path matches Brave.
fn is_brave_cgroup(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("brave") || l.contains("brave-browser")
}

/// Build the brave identity scope proof from the given input.
///
/// Model-only. No /proc scan, no cgroup read, no systemd query,
/// no process mutation, no enforcement.
pub fn build_brave_identity_scope_proof(
    input: &BraveIdentityScopeProofInput,
) -> BraveIdentityScopeProof {
    let mut proof = safe_base_proof();
    let mut findings: Vec<String> = Vec::new();
    let mut blocked = false;
    // Target name check
    let is_brave_target = is_brave_name(&input.target_name);
    if !is_brave_target {
        proof.decision = BraveIdentityDecision::RejectNoTarget;
        proof.status = BraveIdentityScopeStatus::Blocked;
        proof.confidence = BraveIdentityConfidence::None;
        findings.push("target_name must be brave or brave-browser".into());
        blocked = true;
    }
    proof.target_name = input.target_name.clone();
    // Public CLI rejection
    if input.public_cli_requested {
        proof.decision = BraveIdentityDecision::RejectPublicCli;
        proof.status = BraveIdentityScopeStatus::Blocked;
        proof.public_cli_exposed = true;
        findings.push("public CLI is not exposed in I-33".into());
        blocked = true;
    }
    // Live apply rejection
    if input.explicit_live_apply {
        proof.decision = BraveIdentityDecision::RejectLiveApply;
        proof.status = BraveIdentityScopeStatus::LiveApplyForbidden;
        findings.push("live apply is forbidden in I-33".into());
        blocked = true;
    }
    // Mutation/system-read allowance rejections
    if input.allow_proc_scan {
        findings.push("allow_proc_scan is rejected in I-33".into());
        blocked = true;
    }
    if input.allow_cgroup_read {
        findings.push("allow_cgroup_read is rejected in I-33".into());
        blocked = true;
    }
    if input.allow_systemd_query {
        findings.push("allow_systemd_query is rejected in I-33".into());
        blocked = true;
    }
    if input.allow_cgroup_mutation {
        findings.push("cgroup mutation is rejected in I-33".into());
        blocked = true;
    }
    if input.allow_process_mutation {
        findings.push("process mutation is rejected in I-33".into());
        blocked = true;
    }
    if input.allow_persistence {
        findings.push("persistence is rejected in I-33".into());
        blocked = true;
    }
    if blocked {
        proof.findings = findings;
        return proof;
    }
    // Match candidates
    proof.candidate_count = input.candidates.len();
    let matching: Vec<&BraveProcessCandidate> = input
        .candidates
        .iter()
        .filter(|c| c.matches_brave_name || c.matches_brave_executable || c.matches_brave_cgroup)
        .collect();
    proof.matching_candidate_count = matching.len();
    // Multiple matching → Ambiguous
    if matching.len() > 1 {
        proof.status = BraveIdentityScopeStatus::Ambiguous;
        proof.decision = BraveIdentityDecision::RejectAmbiguousTarget;
        proof.confidence = BraveIdentityConfidence::Ambiguous;
        proof.identity_ready = false;
        proof.ambiguous_identity_detected = true;
        findings.push(format!(
            "multiple matching candidates ({}) — identity is ambiguous",
            matching.len()
        ));
        proof.findings = findings;
        return proof;
    }
    // Zero matching → Blocked/Candidate
    if matching.is_empty() {
        proof.status = BraveIdentityScopeStatus::Candidate;
        proof.decision = BraveIdentityDecision::RequirePidEvidence;
        proof.confidence = BraveIdentityConfidence::None;
        proof.identity_ready = false;
        findings.push("no matching Brave candidate found".into());
        proof.findings = findings;
        return proof;
    }
    // Exactly one matching candidate
    let c = matching[0];
    let has_pid = c.pid.is_some();
    let has_cgroup = c.cgroup_path.is_some();
    let has_name = c.matches_brave_name;
    let has_exec = c.matches_brave_executable;
    // Confidence determination
    if has_pid && has_cgroup && (has_name || has_exec) {
        proof.confidence = BraveIdentityConfidence::High;
    } else if has_pid && has_name {
        proof.confidence = BraveIdentityConfidence::Medium;
    } else {
        proof.confidence = BraveIdentityConfidence::Low;
    }
    // Check readiness: need PID + cgroup + name/exec match
    let ready = has_pid && has_cgroup && (has_name || has_exec);
    if ready {
        proof.status = BraveIdentityScopeStatus::Ready;
        proof.decision = BraveIdentityDecision::AcceptReadyScope;
        proof.identity_ready = true;
        proof.selected_pid = c.pid;
        proof.selected_cgroup_path = c.cgroup_path.clone();
        proof.selected_systemd_scope = c.systemd_scope.clone();
    } else {
        proof.status = BraveIdentityScopeStatus::Candidate;
        proof.identity_ready = false;
        if !has_pid {
            proof.decision = BraveIdentityDecision::RequirePidEvidence;
            findings.push("matching candidate found but PID is unknown".into());
        } else if !has_cgroup {
            proof.decision = BraveIdentityDecision::RequireCgroupEvidence;
            findings.push("matching candidate found but cgroup_path is unknown".into());
        } else {
            proof.decision = BraveIdentityDecision::AcceptCandidate;
            findings.push("candidate accepted with partial evidence".into());
        }
    }
    proof.findings = findings;
    proof
}

/// Validate a brave identity scope proof.
///
/// Rejects any proof that violates I-33 safety invariants.
pub fn validate_brave_identity_scope_proof(proof: &BraveIdentityScopeProof) -> Result<(), String> {
    if proof.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-33"))
        } else {
            Ok(())
        }
    };
    deny(proof.live_apply_allowed, "live_apply_allowed")?;
    deny(proof.release_allowed, "release_allowed")?;
    deny(!proof.must_remain_experimental, "must_remain_experimental")?;
    deny(proof.public_cli_exposed, "public_cli_exposed")?;
    deny(proof.proc_scan_performed, "proc_scan_performed")?;
    deny(proof.cgroup_read_performed, "cgroup_read_performed")?;
    deny(proof.systemd_query_performed, "systemd_query_performed")?;
    deny(proof.cgroup_mutation_performed, "cgroup_mutation_performed")?;
    deny(
        proof.process_mutation_performed,
        "process_mutation_performed",
    )?;
    deny(proof.persistence_performed, "persistence_performed")?;
    deny(
        proof.fake_identity_success_detected,
        "fake_identity_success_detected",
    )?;
    // identity_ready with Ready status requires selected PID and cgroup
    if proof.identity_ready && proof.selected_pid.is_none() {
        return Err("identity_ready requires selected_pid".to_string());
    }
    if proof.identity_ready && proof.selected_cgroup_path.is_none() {
        return Err("identity_ready requires selected_cgroup_path".to_string());
    }
    // ambiguous_identity_detected must be false when status is Ready
    if proof.ambiguous_identity_detected && proof.status == BraveIdentityScopeStatus::Ready {
        return Err("ambiguous_identity_detected must be false when status is Ready".to_string());
    }
    Ok(())
}

/// Map identity source to label.
pub fn brave_identity_source_label(source: BraveIdentitySource) -> &'static str {
    source.as_str()
}

/// Map confidence to label.
pub fn brave_identity_confidence_label(confidence: BraveIdentityConfidence) -> &'static str {
    confidence.as_str()
}

/// Map scope status to label.
pub fn brave_identity_scope_status_label(status: BraveIdentityScopeStatus) -> &'static str {
    status.as_str()
}

/// Map identity decision to label.
pub fn brave_identity_decision_label(decision: BraveIdentityDecision) -> &'static str {
    decision.as_str()
}
