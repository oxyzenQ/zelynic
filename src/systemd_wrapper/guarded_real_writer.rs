// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Guarded Real Writer Seam: a narrow code seam for the future guarded real
//! writer that will perform the first live PID move.
//!
//! Phase 5d is seam-only: no live PID move, no real cgroup.procs write, no
//! limiter attach, no nftables/tc/Zelynic state mutation, and no persistent
//! state write. The seam models the future real writer boundary without
//! performing any writes. Every call returns a blocked/not-implemented result
//! with explicit deny lines.
//!
//! This module is inspired by the phase 5c implementation design document
//! (`docs/v2.8-phase-5c-guarded-real-move-implementation-design.md`) and
//! introduces the input/result models, gate validation, and rendering that
//! a future live implementation phase will use as the entry point.

#![allow(dead_code)]

use super::render::push_line;

/// Phase label used in rendered output.
const PHASE_LABEL: &str = "5d guarded-real-writer seam";

/// Zelynic cgroup namespace root.
const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

/// Input parameters for the guarded real writer plan.
///
/// Models the gate inputs that a future live implementation would consume.
/// This struct is pure data — no I/O, no filesystem access, no /proc access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedRealWriterInput {
    /// PID to be moved (single PID only; zero means invalid).
    pub pid: u32,
    /// Original cgroup path (where the PID currently resides).
    pub original_cgroup_path: Option<String>,
    /// Target cgroup path (where the PID would be moved to).
    pub target_cgroup_path: String,
    /// Whether the caller is root (euid == 0).
    pub is_root: bool,
    /// Whether the PID is in system scope (not user.slice).
    pub is_system_scope: bool,
    /// Whether rollback consent is present (--rollback-required).
    pub rollback_consent_present: bool,
}

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

/// PID location label following the canonical taxonomy from phase 4a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardedPidLocation {
    /// PID was never written to any cgroup.procs.
    NotMoved,
    /// Move succeeded and verification confirmed PID in target.
    VerifiedTarget,
    /// Rollback succeeded and verification confirmed PID restored.
    Restored,
    /// PID location cannot be determined.
    Unknown,
}

impl GuardedPidLocation {
    fn label(self) -> &'static str {
        match self {
            Self::NotMoved => "not moved",
            Self::VerifiedTarget => "verified target",
            Self::Restored => "restored",
            Self::Unknown => "unknown",
        }
    }
}

/// The result of building a guarded real writer plan.
///
/// Every field is hardcoded to reflect the seam's hard-blocked status:
/// no operations are performed, no mutations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedRealWriterResult {
    /// Plan phase label.
    pub phase: String,
    /// Plan type label.
    pub plan_type: String,
    /// Overall status — always "blocked" in this phase.
    pub status: String,
    /// Human-readable reason for the blocked status.
    pub reason: String,
    /// PID location after the (non-)operation — always NotMoved.
    pub pid_location: GuardedPidLocation,
    /// Whether rollback was attempted — always false.
    pub rollback_attempted: bool,
    /// Whether cleanup was attempted — always false.
    pub cleanup_attempted: bool,
    /// Whether any cgroup.procs writes were performed — always false.
    pub cgroup_procs_writes_performed: bool,
    /// Whether any limiter attach was performed — always false.
    pub limiter_attach_performed: bool,
    /// Whether any nft/tc/state mutation was performed — always false.
    pub nft_tc_state_mutation_performed: bool,
    /// Gate validation results (individual gates checked).
    pub gates: Vec<GuardedWriterGateResult>,
    /// Canonical deny lines that must appear in all output.
    pub deny_lines: Vec<String>,
}

impl GuardedRealWriterResult {
    /// Returns true if the result status is "blocked".
    #[cfg(test)]
    pub(crate) fn is_blocked(&self) -> bool {
        self.status == "blocked"
    }
}

// ---------------------------------------------------------------------------
// Gate result model
// ---------------------------------------------------------------------------

/// Status of an individual gate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardedWriterGateStatus {
    /// Gate condition passed.
    Ok,
    /// Gate condition failed (blocks the operation).
    Blocked,
}

impl GuardedWriterGateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Blocked => "blocked",
        }
    }
}

/// Result of evaluating a single gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedWriterGateResult {
    /// Gate name.
    pub name: String,
    /// Gate value (what was checked).
    pub value: String,
    /// Gate status (ok or blocked).
    pub status: GuardedWriterGateStatus,
}

// ---------------------------------------------------------------------------
// Canonical deny lines
// ---------------------------------------------------------------------------

/// The 7 canonical deny lines that MUST appear in every rendered output from
/// the guarded real writer seam. These are always true in phase 5d because
/// the seam never performs any operation.
const CANONICAL_DENY_LINES: &[&str] = &[
    "No live PID move was performed.",
    "No real cgroup.procs write was performed.",
    "No limiter attach was performed.",
    "No nftables, tc, or Zelynic state changes were made.",
    "No persistent state write was performed.",
    "No CLI path for live PID move was enabled.",
    "Guarded real writer seam is hard-blocked.",
];

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/// Builds a guarded real writer plan from the given input.
///
/// Validates all gate conditions and produces a result that is always
/// hard-blocked. Even when every gate passes, the seam returns blocked because
/// live PID move is not implemented in this phase.
///
/// No I/O. No filesystem access. No /proc access. No /sys access.
pub(crate) fn build_guarded_real_writer_plan(
    input: &GuardedRealWriterInput,
) -> GuardedRealWriterResult {
    let mut gates = Vec::new();
    let mut block_reasons = Vec::new();

    // Gate 1: root (euid == 0)
    let root_ok = input.is_root;
    gates.push(GuardedWriterGateResult {
        name: "root".to_string(),
        value: if root_ok { "euid 0" } else { "non-root" }.to_string(),
        status: if root_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !root_ok {
        block_reasons.push("non-root: guarded real writer requires euid == 0".to_string());
    }

    // Gate 2: system scope
    let system_ok = input.is_system_scope;
    gates.push(GuardedWriterGateResult {
        name: "system scope".to_string(),
        value: if system_ok {
            "system scope"
        } else {
            "user scope"
        }
        .to_string(),
        status: if system_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !system_ok {
        block_reasons
            .push("user scope: guarded real writer requires system scope only".to_string());
    }

    // Gate 3: single non-zero PID
    let pid_ok = input.pid > 0;
    gates.push(GuardedWriterGateResult {
        name: "PID".to_string(),
        value: if pid_ok {
            input.pid.to_string()
        } else {
            "zero/invalid".to_string()
        },
        status: if pid_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !pid_ok {
        block_reasons
            .push("zero PID: guarded real writer requires a valid non-zero PID".to_string());
    }

    // Gate 4: original cgroup present and non-empty
    let original_present = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty());
    gates.push(GuardedWriterGateResult {
        name: "original cgroup".to_string(),
        value: if original_present {
            input.original_cgroup_path.clone().unwrap_or_default()
        } else {
            "missing".to_string()
        },
        status: if original_present {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !original_present {
        block_reasons.push("missing original cgroup: capture is required before move".to_string());
    }

    // Gate 5: original cgroup not under /zelynic/
    let original_safe = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty() && !p.contains("/zelynic/"));
    if original_present && !original_safe {
        gates.push(GuardedWriterGateResult {
            name: "original cgroup safety".to_string(),
            value: "zelynic-managed".to_string(),
            status: GuardedWriterGateStatus::Blocked,
        });
        block_reasons
            .push("zelynic-managed original cgroup: refusing move from Zelynic target".to_string());
    } else if original_present {
        gates.push(GuardedWriterGateResult {
            name: "original cgroup safety".to_string(),
            value: "external (safe)".to_string(),
            status: GuardedWriterGateStatus::Ok,
        });
    }

    // Gate 6: target under /sys/fs/cgroup/zelynic/
    let target_safe = is_safe_writer_target(&input.target_cgroup_path);
    gates.push(GuardedWriterGateResult {
        name: "target cgroup".to_string(),
        value: if target_safe {
            input.target_cgroup_path.clone()
        } else {
            "outside /sys/fs/cgroup/zelynic/".to_string()
        },
        status: if target_safe {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !target_safe {
        block_reasons.push("invalid target: must be under /sys/fs/cgroup/zelynic/".to_string());
    }

    // Gate 7: rollback consent present
    let consent_ok = input.rollback_consent_present;
    gates.push(GuardedWriterGateResult {
        name: "rollback consent".to_string(),
        value: if consent_ok { "present" } else { "missing" }.to_string(),
        status: if consent_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !consent_ok {
        block_reasons.push("missing rollback consent: --rollback-required is required".to_string());
    }

    // Phase 5d hard block: even when every gate passes, the seam returns
    // blocked because live PID move is not implemented.
    let reason = if block_reasons.is_empty() {
        "guarded real writer seam is hard-blocked: live PID move is not implemented in phase 5d"
            .to_string()
    } else {
        format!("guarded real writer blocked: {}", block_reasons.join("; "))
    };

    let deny_lines: Vec<String> = CANONICAL_DENY_LINES.iter().map(|s| s.to_string()).collect();

    GuardedRealWriterResult {
        phase: format!("phase {}", PHASE_LABEL),
        plan_type: "guarded real writer seam (model-only)".to_string(),
        status: "blocked".to_string(),
        reason,
        pid_location: GuardedPidLocation::NotMoved,
        rollback_attempted: false,
        cleanup_attempted: false,
        cgroup_procs_writes_performed: false,
        limiter_attach_performed: false,
        nft_tc_state_mutation_performed: false,
        gates,
        deny_lines,
    }
}

/// Renders a guarded real writer plan result as structured text output.
///
/// The output always includes the phase label, gate results, deny lines,
/// and explicit non-mutation statements. No claim of PID movement, cgroup
/// write, limiter attach, bandwidth limiting, or nft/tc/state mutation is
/// ever present in the output.
pub(crate) fn render_guarded_real_writer_plan(result: &GuardedRealWriterResult) -> String {
    let mut output = String::new();

    push_line(
        &mut output,
        &format!("    Guarded real writer seam (phase {}):", PHASE_LABEL),
    );
    push_line(
        &mut output,
        &format!("      plan type: {}", result.plan_type),
    );
    push_line(&mut output, &format!("      status: {}", result.status));
    push_line(&mut output, &format!("      reason: {}", result.reason));
    push_line(
        &mut output,
        &format!("      pid location: {}", result.pid_location.label()),
    );
    push_line(
        &mut output,
        &format!("      rollback attempted: {}", result.rollback_attempted),
    );
    push_line(
        &mut output,
        &format!("      cleanup attempted: {}", result.cleanup_attempted),
    );
    push_line(
        &mut output,
        &format!(
            "      cgroup.procs writes performed: {}",
            result.cgroup_procs_writes_performed
        ),
    );
    push_line(
        &mut output,
        &format!(
            "      limiter attach performed: {}",
            result.limiter_attach_performed
        ),
    );
    push_line(
        &mut output,
        &format!(
            "      nft/tc/state mutation performed: {}",
            result.nft_tc_state_mutation_performed
        ),
    );
    push_line(&mut output, "      gates:");
    for gate in &result.gates {
        push_line(
            &mut output,
            &format!(
                "        {}: {} ({})",
                gate.name,
                gate.value,
                gate.status.label()
            ),
        );
    }
    push_line(&mut output, "      deny lines:");
    for deny in &result.deny_lines {
        push_line(&mut output, &format!("        {}", deny));
    }

    output
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates that a target path is safe for the guarded real writer:
/// must be under the Zelynic cgroup namespace with no path traversal.
fn is_safe_writer_target(path: &str) -> bool {
    path.starts_with(&format!("{ZELYNIC_CGROUP_ROOT}/"))
        && !path.contains("..")
        && path.len() > ZELYNIC_CGROUP_ROOT.len() + 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid input for testing — all gates pass.
    fn valid_input() -> GuardedRealWriterInput {
        GuardedRealWriterInput {
            pid: 12345,
            original_cgroup_path: Some("/sys/fs/cgroup/user.slice/session-2.scope".to_string()),
            target_cgroup_path: "/sys/fs/cgroup/zelynic/target_sleep".to_string(),
            is_root: true,
            is_system_scope: true,
            rollback_consent_present: true,
        }
    }

    /// Returns true if a gate with the given name has Ok status.
    fn gate_ok(result: &GuardedRealWriterResult, name: &str) -> bool {
        result
            .gates
            .iter()
            .find(|g| g.name == name)
            .is_some_and(|g| g.status == GuardedWriterGateStatus::Ok)
    }

    /// Renders a plan result to text.
    fn rendered(input: &GuardedRealWriterInput) -> String {
        let result = build_guarded_real_writer_plan(input);
        render_guarded_real_writer_plan(&result)
    }

    // ---- seam always blocked ----

    #[test]
    fn seam_always_returns_blocked_even_when_all_gates_are_valid() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert!(result.is_blocked());
        assert_eq!(result.status, "blocked");
        // All individual gates pass
        assert!(result
            .gates
            .iter()
            .all(|g| g.status == GuardedWriterGateStatus::Ok));
        // But seam is still hard-blocked
        assert!(result.reason.contains("hard-blocked"));
        assert!(result.reason.contains("not implemented"));
    }

    // ---- gate blocking tests ----

    #[test]
    fn non_root_blocks() {
        let mut input = valid_input();
        input.is_root = false;
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "root"));
        assert!(result.reason.contains("non-root"));
    }

    #[test]
    fn user_scope_blocks() {
        let mut input = valid_input();
        input.is_system_scope = false;
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "system scope"));
        assert!(result.reason.contains("user scope"));
    }

    #[test]
    fn zero_pid_blocks() {
        let mut input = valid_input();
        input.pid = 0;
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "PID"));
        assert!(result.reason.contains("zero PID"));
    }

    #[test]
    fn multi_pid_blocks_if_represented() {
        // The guarded real writer input model uses a single PID field.
        // A future multi-PID representation would be blocked by design.
        // For now, verify that a valid single PID doesn't bypass the hard block.
        let mut input = valid_input();
        input.pid = 1; // valid single PID is fine for gates
        let result = build_guarded_real_writer_plan(&input);
        // Still blocked because the seam is hard-blocked
        assert!(result.is_blocked());
    }

    #[test]
    fn missing_original_cgroup_blocks() {
        let mut input = valid_input();
        input.original_cgroup_path = None;
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "original cgroup"));
        assert!(result.reason.contains("missing original cgroup"));
    }

    #[test]
    fn zelynic_managed_original_cgroup_blocks() {
        let mut input = valid_input();
        input.original_cgroup_path = Some("/sys/fs/cgroup/zelynic/target_previous".to_string());
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "original cgroup safety"));
        assert!(result.reason.contains("zelynic-managed"));
    }

    #[test]
    fn target_outside_zelynic_blocks() {
        let mut input = valid_input();
        input.target_cgroup_path = "/sys/fs/cgroup/system.slice/example.scope".to_string();
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "target cgroup"));
        assert!(result.reason.contains("invalid target"));
    }

    #[test]
    fn missing_rollback_consent_blocks() {
        let mut input = valid_input();
        input.rollback_consent_present = false;
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "rollback consent"));
        assert!(result.reason.contains("rollback consent"));
    }

    // ---- result model field correctness ----

    #[test]
    fn result_fields_are_always_non_mutating() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert_eq!(result.pid_location, GuardedPidLocation::NotMoved);
        assert!(!result.rollback_attempted);
        assert!(!result.cleanup_attempted);
        assert!(!result.cgroup_procs_writes_performed);
        assert!(!result.limiter_attach_performed);
        assert!(!result.nft_tc_state_mutation_performed);
    }

    #[test]
    fn result_fields_are_always_non_mutating_even_with_invalid_gates() {
        let mut input = valid_input();
        input.is_root = false;
        input.pid = 0;
        let result = build_guarded_real_writer_plan(&input);
        assert_eq!(result.pid_location, GuardedPidLocation::NotMoved);
        assert!(!result.rollback_attempted);
        assert!(!result.cleanup_attempted);
        assert!(!result.cgroup_procs_writes_performed);
        assert!(!result.limiter_attach_performed);
        assert!(!result.nft_tc_state_mutation_performed);
    }

    // ---- deny line presence tests ----

    #[test]
    fn rendered_output_includes_all_deny_lines() {
        let output = rendered(&valid_input());
        for deny in CANONICAL_DENY_LINES {
            assert!(output.contains(deny), "missing deny line: {}", deny);
        }
    }

    #[test]
    fn result_includes_all_deny_lines() {
        let result = build_guarded_real_writer_plan(&valid_input());
        for deny in CANONICAL_DENY_LINES {
            assert!(
                result.deny_lines.iter().any(|d| d == deny),
                "missing deny line in result: {}",
                deny
            );
        }
    }

    #[test]
    fn rendered_output_includes_all_deny_lines_for_non_root() {
        let mut input = valid_input();
        input.is_root = false;
        let output = rendered(&input);
        for deny in CANONICAL_DENY_LINES {
            assert!(
                output.contains(deny),
                "non-root missing deny line: {}",
                deny
            );
        }
    }

    #[test]
    fn rendered_output_includes_all_deny_lines_for_user_scope() {
        let mut input = valid_input();
        input.is_system_scope = false;
        let output = rendered(&input);
        for deny in CANONICAL_DENY_LINES {
            assert!(
                output.contains(deny),
                "user scope missing deny line: {}",
                deny
            );
        }
    }

    // ---- forbidden claim tests ----

    #[test]
    fn rendered_output_never_claims_pid_moved() {
        let output = rendered(&valid_input());
        assert!(!output.contains("PID was moved"));
        assert!(!output.contains("PID moved"));
        assert!(!output.contains("pid moved"));
        assert!(!output.contains("pid was moved"));
    }

    #[test]
    fn rendered_output_never_claims_cgroup_procs_write() {
        let output = rendered(&valid_input());
        assert!(!output.contains("cgroup.procs written"));
        assert!(!output.contains("cgroup.procs was written"));
        assert!(!output.contains("cgroup.procs write performed"));
    }

    #[test]
    fn rendered_output_never_claims_rollback_performed() {
        let output = rendered(&valid_input());
        assert!(!output.contains("rollback performed"));
        assert!(!output.contains("rollback was performed"));
        assert!(!output.contains("PID was restored"));
    }

    #[test]
    fn rendered_output_never_claims_limiter_attach() {
        let output = rendered(&valid_input());
        assert!(!output.contains("limiter attached"));
        assert!(!output.contains("Limiter attached"));
        assert!(!output.contains("limiter was attached"));
    }

    #[test]
    fn rendered_output_never_claims_bandwidth_limiting_active() {
        let output = rendered(&valid_input());
        assert!(!output.contains("bandwidth limiting active"));
        assert!(!output.contains("Bandwidth limiting active"));
        assert!(!output.contains("bandwidth limiting is active"));
    }

    #[test]
    fn rendered_output_never_claims_nft_tc_state_mutation() {
        let output = rendered(&valid_input());
        assert!(!output.contains("nftables rules were"));
        assert!(!output.contains("tc qdisc"));
        assert!(!output.contains("state was mutated"));
        assert!(!output.contains("state changes performed"));
    }

    #[test]
    fn rendered_output_says_hard_blocked_or_not_implemented() {
        let output = rendered(&valid_input());
        assert!(output.contains("hard-blocked") || output.contains("not implemented"));
        assert!(output.contains("blocked"));
    }

    // ---- negative-path comprehensive mutation sweep ----

    #[test]
    #[allow(clippy::type_complexity)]
    fn negative_path_outputs_never_claim_mutation() {
        let scenarios: Vec<(&str, fn(&mut GuardedRealWriterInput))> = vec![
            ("non-root", |i| i.is_root = false),
            ("user scope", |i| i.is_system_scope = false),
            ("zero PID", |i| i.pid = 0),
            ("missing original cgroup", |i| i.original_cgroup_path = None),
            ("zelynic-managed original", |i| {
                i.original_cgroup_path = Some("/sys/fs/cgroup/zelynic/target_old".to_string())
            }),
            ("invalid target", |i| {
                i.target_cgroup_path = "/sys/fs/cgroup/system.slice/x.scope".to_string()
            }),
            ("missing rollback consent", |i| {
                i.rollback_consent_present = false
            }),
        ];
        for (label, modify) in scenarios {
            let mut input = valid_input();
            modify(&mut input);
            let output = rendered(&input);
            assert!(
                !output.contains("PID was moved"),
                "{}: must not claim PID moved",
                label
            );
            assert!(
                !output.contains("cgroup.procs written"),
                "{}: must not claim cgroup.procs written",
                label
            );
            assert!(
                !output.contains("limiter attached"),
                "{}: must not claim limiter attached",
                label
            );
            assert!(
                !output.contains("bandwidth limiting active"),
                "{}: must not claim bandwidth limiting active",
                label
            );
            assert!(
                !output.contains("rollback performed"),
                "{}: must not claim rollback performed",
                label
            );
            assert!(
                !output.contains("state was mutated"),
                "{}: must not claim state mutation",
                label
            );
        }
    }

    // ---- phase label tests ----

    #[test]
    fn result_says_phase_5d() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert!(result.phase.contains("5d"));
        assert!(result.plan_type.contains("guarded real writer"));
    }

    #[test]
    fn rendered_output_contains_phase_5d_label() {
        let output = rendered(&valid_input());
        assert!(output.contains("phase 5d"));
        assert!(output.contains("Guarded real writer seam"));
    }

    // ---- render structure tests ----

    #[test]
    fn rendered_output_contains_all_sections() {
        let output = rendered(&valid_input());
        assert!(output.contains("Guarded real writer seam"));
        assert!(output.contains("plan type:"));
        assert!(output.contains("status:"));
        assert!(output.contains("reason:"));
        assert!(output.contains("pid location:"));
        assert!(output.contains("rollback attempted:"));
        assert!(output.contains("cleanup attempted:"));
        assert!(output.contains("cgroup.procs writes performed:"));
        assert!(output.contains("limiter attach performed:"));
        assert!(output.contains("nft/tc/state mutation performed:"));
        assert!(output.contains("gates:"));
        assert!(output.contains("deny lines:"));
    }

    #[test]
    fn rendered_output_shows_false_for_all_mutation_flags() {
        let output = rendered(&valid_input());
        assert!(output.contains("rollback attempted: false"));
        assert!(output.contains("cleanup attempted: false"));
        assert!(output.contains("cgroup.procs writes performed: false"));
        assert!(output.contains("limiter attach performed: false"));
        assert!(output.contains("nft/tc/state mutation performed: false"));
    }

    // ---- gate ordering tests ----

    #[test]
    fn gates_are_in_correct_order() {
        let result = build_guarded_real_writer_plan(&valid_input());
        let names: Vec<&str> = result.gates.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "root",
                "system scope",
                "PID",
                "original cgroup",
                "original cgroup safety",
                "target cgroup",
                "rollback consent",
            ]
        );
    }

    // ---- is_safe_writer_target helper tests ----

    #[test]
    fn safe_writer_target_rejects_empty() {
        assert!(!is_safe_writer_target(""));
    }

    #[test]
    fn safe_writer_target_rejects_outside_namespace() {
        assert!(!is_safe_writer_target("/sys/fs/cgroup/system.slice/foo"));
    }

    #[test]
    fn safe_writer_target_rejects_parent_traversal() {
        assert!(!is_safe_writer_target(
            "/sys/fs/cgroup/zelynic/target_test/../etc/passwd"
        ));
    }

    #[test]
    fn safe_writer_target_rejects_bare_root() {
        assert!(!is_safe_writer_target(ZELYNIC_CGROUP_ROOT));
    }

    #[test]
    fn safe_writer_target_accepts_valid_target() {
        assert!(is_safe_writer_target("/sys/fs/cgroup/zelynic/target_sleep"));
    }

    #[test]
    fn safe_writer_target_accepts_subdirectory() {
        assert!(is_safe_writer_target(
            "/sys/fs/cgroup/zelynic/experiment/target_curl"
        ));
    }

    // ---- whitespace-only original cgroup edge case ----

    #[test]
    fn whitespace_only_original_cgroup_blocks() {
        let mut input = valid_input();
        input.original_cgroup_path = Some("   ".to_string());
        let result = build_guarded_real_writer_plan(&input);
        assert!(!gate_ok(&result, "original cgroup"));
        assert!(result.reason.contains("missing original cgroup"));
    }

    // ---- determinism tests ----

    #[test]
    fn same_input_produces_same_result() {
        let input = valid_input();
        let r1 = build_guarded_real_writer_plan(&input);
        let r2 = build_guarded_real_writer_plan(&input);
        assert_eq!(r1, r2);
    }

    #[test]
    fn same_input_produces_same_rendered_output() {
        let input = valid_input();
        let o1 = rendered(&input);
        let o2 = rendered(&input);
        assert_eq!(o1, o2);
    }

    // ---- PID location label tests ----

    #[test]
    fn pid_location_not_moved_label() {
        assert_eq!(GuardedPidLocation::NotMoved.label(), "not moved");
    }

    #[test]
    fn pid_location_verified_target_label() {
        assert_eq!(
            GuardedPidLocation::VerifiedTarget.label(),
            "verified target"
        );
    }

    #[test]
    fn pid_location_restored_label() {
        assert_eq!(GuardedPidLocation::Restored.label(), "restored");
    }

    #[test]
    fn pid_location_unknown_label() {
        assert_eq!(GuardedPidLocation::Unknown.label(), "unknown");
    }

    // ---- deny line count test ----

    #[test]
    fn deny_lines_has_correct_count() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert_eq!(result.deny_lines.len(), CANONICAL_DENY_LINES.len());
        assert_eq!(result.deny_lines.len(), 7);
    }

    // ---- explicit hard-block denial test ----

    #[test]
    fn deny_lines_include_hard_blocked_statement() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert!(result
            .deny_lines
            .iter()
            .any(|d| d.contains("Guarded real writer seam is hard-blocked")));
    }

    #[test]
    fn deny_lines_include_no_cli_path_statement() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert!(result
            .deny_lines
            .iter()
            .any(|d| d.contains("No CLI path for live PID move was enabled")));
    }

    #[test]
    fn deny_lines_include_no_persistent_state_statement() {
        let result = build_guarded_real_writer_plan(&valid_input());
        assert!(result
            .deny_lines
            .iter()
            .any(|d| d.contains("No persistent state write was performed")));
    }
}
