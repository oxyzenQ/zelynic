// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Move Executor Seam: model-only seam for a future single-PID cgroup move
//! and immediate rollback experiment.
//!
//! This module provides the executor seam — the structural bridge between the
//! gate checklist and the future live write path. Phase 3c is executor-seam
//! only: no live PID move, no cgroup.procs write, no limiter attach, no
//! nftables/tc/Zelynic state mutation, and no persistent state write.
//!
//! The seam validates all hard gates and always returns a blocked result.
//! When a future phase implements live PID movement, this seam will be the
//! point where gate validation passes and the executor begins.

use super::plan::ScopeMode;
use super::render::push_line;

const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";
const PHASE_LABEL: &str = "3c executor-seam";

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MoveExecutorInput {
    pub pids: Vec<u32>,
    pub target_cgroup_path: String,
    pub original_cgroup_path: Option<String>,
    pub is_root: bool,
    pub scope_mode: ScopeMode,
    pub consent_all_present: bool,
}

// ---------------------------------------------------------------------------
// Gate result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeamGateStatus {
    Ok,
    Blocked,
}

impl SeamGateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeamGateResult {
    pub name: String,
    pub value: String,
    pub status: SeamGateStatus,
}

// ---------------------------------------------------------------------------
// Executor result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MoveExecutorResult {
    pub phase: String,
    pub executor_type: String,
    pub status: String,
    pub execution: String,
    pub gates: Vec<SeamGateResult>,
    pub blocked_reasons: Vec<String>,
    pub disclaimers: Vec<String>,
}

impl MoveExecutorResult {
    #[cfg(test)]
    pub(crate) fn is_blocked(&self) -> bool {
        self.status == "blocked"
    }
}

// ---------------------------------------------------------------------------
// Seam evaluation
// ---------------------------------------------------------------------------

pub(crate) fn evaluate_move_executor_seam(input: &MoveExecutorInput) -> MoveExecutorResult {
    let mut gates = Vec::new();
    let mut blocked_reasons = Vec::new();

    // Gate 1: root (euid == 0)
    let root_ok = input.is_root;
    gates.push(SeamGateResult {
        name: "root".to_string(),
        value: if root_ok { "euid 0" } else { "non-root" }.to_string(),
        status: if root_ok {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !root_ok {
        blocked_reasons.push("non-root: executor requires euid == 0".to_string());
    }

    // Gate 2: system scope only
    let system_ok = input.scope_mode == ScopeMode::System;
    gates.push(SeamGateResult {
        name: "scope mode".to_string(),
        value: if system_ok { "system" } else { "user" }.to_string(),
        status: if system_ok {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !system_ok {
        blocked_reasons.push("user scope: executor requires system scope only".to_string());
    }

    // Gate 3: single PID
    let single_pid_ok = input.pids.len() == 1;
    gates.push(SeamGateResult {
        name: "PID count".to_string(),
        value: input.pids.len().to_string(),
        status: if single_pid_ok {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !single_pid_ok {
        blocked_reasons.push("multi-PID: executor requires exactly one PID".to_string());
    }

    // Gate 4: original cgroup present and non-empty
    let original_present = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty());
    gates.push(SeamGateResult {
        name: "original cgroup".to_string(),
        value: if original_present {
            input.original_cgroup_path.clone().unwrap_or_default()
        } else {
            "missing".to_string()
        },
        status: if original_present {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !original_present {
        blocked_reasons.push("missing original cgroup: capture is required".to_string());
    }

    // Gate 5: original cgroup not under /zelynic/ (restoring into Zelynic-
    // managed target would be unsafe — the PID would be in an operation-owned
    // cgroup with no controller)
    let original_safe = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty() && !p.contains("/zelynic/"));
    if original_present && !original_safe {
        gates.push(SeamGateResult {
            name: "original cgroup safety".to_string(),
            value: "zelynic-managed".to_string(),
            status: SeamGateStatus::Blocked,
        });
        blocked_reasons
            .push("zelynic-managed original cgroup: refusing move from Zelynic target".to_string());
    } else if original_present {
        gates.push(SeamGateResult {
            name: "original cgroup safety".to_string(),
            value: "external (safe)".to_string(),
            status: SeamGateStatus::Ok,
        });
    }

    // Gate 6: target under /sys/fs/cgroup/zelynic/target_<name>
    let target_safe = is_safe_target(&input.target_cgroup_path);
    gates.push(SeamGateResult {
        name: "target cgroup".to_string(),
        value: if target_safe {
            input.target_cgroup_path.clone()
        } else {
            "outside /sys/fs/cgroup/zelynic/".to_string()
        },
        status: if target_safe {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !target_safe {
        blocked_reasons.push("invalid target: must be under /sys/fs/cgroup/zelynic/".to_string());
    }

    // Gate 7: rollback consent present
    let consent_ok = input.consent_all_present;
    gates.push(SeamGateResult {
        name: "rollback consent".to_string(),
        value: if consent_ok { "present" } else { "missing" }.to_string(),
        status: if consent_ok {
            SeamGateStatus::Ok
        } else {
            SeamGateStatus::Blocked
        },
    });
    if !consent_ok {
        blocked_reasons
            .push("missing rollback consent: --rollback-required is required".to_string());
    }

    // Phase 3c hard block: even when every gate passes, the executor returns
    // blocked because live PID move is not implemented in this phase.
    if blocked_reasons.is_empty() {
        blocked_reasons
            .push("live PID move is not implemented: phase 3c is executor-seam only".to_string());
    }

    let disclaimers = vec![
        format!("phase {} is executor-seam only", PHASE_LABEL),
        "live PID move is not implemented".to_string(),
        "no cgroup.procs write was performed".to_string(),
        "no PID was moved".to_string(),
        "no limiter attach was performed".to_string(),
        "no nftables/tc/Zelynic state changes were made".to_string(),
        "no persistent state write was performed".to_string(),
        "Experimental PID move is not implemented yet.".to_string(),
        "Bandwidth limiting is not active from this command yet.".to_string(),
    ];

    MoveExecutorResult {
        phase: format!("phase {}", PHASE_LABEL),
        executor_type: "model-only executor seam".to_string(),
        status: "blocked".to_string(),
        execution: "not implemented".to_string(),
        gates,
        blocked_reasons,
        disclaimers,
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render_move_executor_seam_section(output: &mut String, result: &MoveExecutorResult) {
    push_line(output, "");
    push_line(output, "    Move executor seam:");
    push_line(output, &format!("      phase: {}", result.phase));
    push_line(
        output,
        &format!("      executor type: {}", result.executor_type),
    );
    push_line(output, &format!("      status: {}", result.status));
    push_line(output, &format!("      execution: {}", result.execution));
    push_line(output, "      gates:");
    for gate in &result.gates {
        push_line(
            output,
            &format!(
                "        {}: {} ({})",
                gate.name,
                gate.value,
                gate.status.label()
            ),
        );
    }
    if !result.blocked_reasons.is_empty() {
        push_line(output, "      blocked reasons:");
        for (index, reason) in result.blocked_reasons.iter().enumerate() {
            push_line(output, &format!("        {}. {}", index + 1, reason));
        }
    }
    push_line(output, "      disclaimers:");
    for disclaimer in &result.disclaimers {
        push_line(output, &format!("        {}", disclaimer));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates that a target path is safe: must be under the Zelynic cgroup
/// namespace with a `target_` prefix and no path traversal.
fn is_safe_target(path: &str) -> bool {
    let Some(remainder) = path.strip_prefix(&format!("{ZELYNIC_CGROUP_ROOT}/")) else {
        return false;
    };
    !remainder.is_empty()
        && !remainder.contains("..")
        && path.starts_with(&format!("{ZELYNIC_CGROUP_ROOT}/target_"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> MoveExecutorInput {
        MoveExecutorInput {
            pids: vec![12345],
            target_cgroup_path: "/sys/fs/cgroup/zelynic/target_sleep".to_string(),
            original_cgroup_path: Some("/sys/fs/cgroup/user.slice/session-2.scope".to_string()),
            is_root: true,
            scope_mode: ScopeMode::System,
            consent_all_present: true,
        }
    }

    fn ok_gate(result: &MoveExecutorResult, name: &str) -> bool {
        result
            .gates
            .iter()
            .find(|g| g.name == name)
            .is_some_and(|g| g.status == SeamGateStatus::Ok)
    }

    fn rendered_text(result: &MoveExecutorResult) -> String {
        let mut output = String::new();
        render_move_executor_seam_section(&mut output, result);
        output
    }

    // ---- hard gate tests ----

    #[test]
    fn non_root_is_blocked() {
        let mut input = valid_input();
        input.is_root = false;
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "root"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("non-root")));
    }

    #[test]
    fn user_scope_is_blocked() {
        let mut input = valid_input();
        input.scope_mode = ScopeMode::User;
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "scope mode"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("user scope")));
    }

    #[test]
    fn multi_pid_is_blocked() {
        let mut input = valid_input();
        input.pids = vec![12345, 12346];
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "PID count"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("multi-PID")));
    }

    #[test]
    fn missing_original_cgroup_is_blocked() {
        let mut input = valid_input();
        input.original_cgroup_path = None;
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "original cgroup"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("missing original cgroup")));
    }

    #[test]
    fn invalid_empty_original_cgroup_is_blocked() {
        let mut input = valid_input();
        input.original_cgroup_path = Some(String::new());
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "original cgroup"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("missing original cgroup")));
    }

    #[test]
    fn zelynic_managed_original_cgroup_is_blocked() {
        let mut input = valid_input();
        input.original_cgroup_path = Some("/sys/fs/cgroup/zelynic/target_previous".to_string());
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "original cgroup safety"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("zelynic-managed")));
    }

    #[test]
    fn invalid_target_outside_zelynic_is_blocked() {
        let mut input = valid_input();
        input.target_cgroup_path = "/sys/fs/cgroup/system.slice/example.scope".to_string();
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "target cgroup"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("invalid target")));
    }

    #[test]
    fn missing_rollback_consent_is_blocked() {
        let mut input = valid_input();
        input.consent_all_present = false;
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "rollback consent"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("rollback consent")));
    }

    // ---- executor always blocked ----

    #[test]
    fn executor_always_returns_blocked_even_with_all_valid_inputs() {
        let result = evaluate_move_executor_seam(&valid_input());
        assert!(result.is_blocked());
        assert_eq!(result.status, "blocked");
        assert_eq!(result.execution, "not implemented");
        // All individual gates pass but executor is still hard-blocked
        assert!(result.gates.iter().all(|g| g.status == SeamGateStatus::Ok));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("not implemented")));
    }

    // ---- output honesty tests ----

    #[test]
    fn rendered_output_never_claims_attached_limited_or_enforced() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }

    #[test]
    fn rendered_output_contains_no_cgroup_procs_write_was_performed() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("no cgroup.procs write was performed"));
    }

    // ---- disclaimer presence tests ----

    #[test]
    fn result_includes_all_required_disclaimers() {
        let result = evaluate_move_executor_seam(&valid_input());
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("executor-seam only")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("live PID move is not implemented")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no cgroup.procs write was performed")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no PID was moved")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no limiter attach was performed")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no nftables/tc/Zelynic state changes were made")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no persistent state write was performed")));
    }

    #[test]
    fn rendered_output_includes_explicit_denials() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("no PID was moved"));
        assert!(output.contains("no limiter attach was performed"));
        assert!(output.contains("no cgroup.procs write was performed"));
        assert!(output.contains("no nftables/tc/Zelynic state changes were made"));
        assert!(output.contains("no persistent state write was performed"));
    }

    // ---- phase and type label tests ----

    #[test]
    fn result_says_phase_3c_executor_seam() {
        let result = evaluate_move_executor_seam(&valid_input());
        assert!(result.phase.contains("3c"));
        assert!(result.executor_type.contains("executor seam"));
    }

    // ---- rendered structure tests ----

    #[test]
    fn rendered_output_contains_gates_and_disclaimers_sections() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("Move executor seam"));
        assert!(output.contains("gates:"));
        assert!(output.contains("disclaimers:"));
        assert!(output.contains("blocked reasons:"));
    }

    #[test]
    fn rendered_output_shows_phase_and_status() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("phase: phase 3c"));
        assert!(output.contains("executor type: model-only executor seam"));
        assert!(output.contains("status: blocked"));
        assert!(output.contains("execution: not implemented"));
    }

    // ---- gate ordering tests ----

    #[test]
    fn gates_are_in_correct_order() {
        let result = evaluate_move_executor_seam(&valid_input());
        let names: Vec<&str> = result.gates.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "root",
                "scope mode",
                "PID count",
                "original cgroup",
                "original cgroup safety",
                "target cgroup",
                "rollback consent",
            ]
        );
    }

    // ---- is_safe_target helper tests ----

    #[test]
    fn safe_target_rejects_empty() {
        assert!(!is_safe_target(""));
    }

    #[test]
    fn safe_target_rejects_outside_namespace() {
        assert!(!is_safe_target("/sys/fs/cgroup/system.slice/foo"));
    }

    #[test]
    fn safe_target_rejects_parent_traversal() {
        assert!(!is_safe_target(
            "/sys/fs/cgroup/zelynic/target_test/../etc/passwd"
        ));
    }

    #[test]
    fn safe_target_rejects_no_target_prefix() {
        assert!(!is_safe_target("/sys/fs/cgroup/zelynic/something"));
    }

    #[test]
    fn safe_target_accepts_valid_target() {
        assert!(is_safe_target("/sys/fs/cgroup/zelynic/target_sleep"));
    }

    #[test]
    fn safe_target_accepts_target_with_suffix() {
        assert!(is_safe_target("/sys/fs/cgroup/zelynic/target_curl_123"));
    }

    // ---- zero PID edge case ----

    #[test]
    fn zero_pids_is_blocked() {
        let mut input = valid_input();
        input.pids = vec![];
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "PID count"));
        assert!(result
            .blocked_reasons
            .iter()
            .any(|r| r.contains("multi-PID") || r.contains("exactly one PID")));
    }

    // ---- whitespace-only original cgroup ----

    #[test]
    fn whitespace_only_original_cgroup_is_blocked() {
        let mut input = valid_input();
        input.original_cgroup_path = Some("   ".to_string());
        let result = evaluate_move_executor_seam(&input);
        assert!(!ok_gate(&result, "original cgroup"));
    }

    // ---- phase 3d: canonical deny-line tests ----

    #[test]
    fn rendered_output_includes_experimental_pid_move_not_implemented_yet() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("Experimental PID move is not implemented yet."));
    }

    #[test]
    fn rendered_output_includes_bandwidth_limiting_not_active() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(output.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn rendered_output_never_claims_bandwidth_active() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(!output.contains("bandwidth limiting is active"));
        assert!(!output.contains("Bandwidth limiting active"));
        assert!(!output.contains("limiting is active from this command"));
    }

    #[test]
    fn rendered_output_never_claims_rollback_performed() {
        let output = rendered_text(&evaluate_move_executor_seam(&valid_input()));
        assert!(!output.contains("rollback performed"));
        assert!(!output.contains("rollback was performed"));
        assert!(!output.contains("PID was restored"));
    }

    #[test]
    fn rendered_non_root_output_includes_all_canonical_deny_lines() {
        let mut input = valid_input();
        input.is_root = false;
        let output = rendered_text(&evaluate_move_executor_seam(&input));
        assert!(output.contains("no PID was moved"));
        assert!(output.contains("no cgroup.procs write was performed"));
        assert!(output.contains("no limiter attach was performed"));
        assert!(output.contains("no nftables/tc/Zelynic state changes were made"));
        assert!(output.contains("no persistent state write was performed"));
        assert!(output.contains("Experimental PID move is not implemented yet."));
        assert!(output.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn rendered_user_scope_output_includes_all_canonical_deny_lines() {
        let mut input = valid_input();
        input.scope_mode = ScopeMode::User;
        let output = rendered_text(&evaluate_move_executor_seam(&input));
        assert!(output.contains("no PID was moved"));
        assert!(output.contains("no cgroup.procs write was performed"));
        assert!(output.contains("no limiter attach was performed"));
        assert!(output.contains("no nftables/tc/Zelynic state changes were made"));
        assert!(output.contains("no persistent state write was performed"));
        assert!(output.contains("Experimental PID move is not implemented yet."));
        assert!(output.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn rendered_multi_pid_output_includes_all_canonical_deny_lines() {
        let mut input = valid_input();
        input.pids = vec![12345, 12346];
        let output = rendered_text(&evaluate_move_executor_seam(&input));
        assert!(output.contains("no PID was moved"));
        assert!(output.contains("no cgroup.procs write was performed"));
        assert!(output.contains("no limiter attach was performed"));
        assert!(output.contains("no nftables/tc/Zelynic state changes were made"));
        assert!(output.contains("no persistent state write was performed"));
        assert!(output.contains("Experimental PID move is not implemented yet."));
        assert!(output.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn rendered_missing_original_cgroup_includes_all_canonical_deny_lines() {
        let mut input = valid_input();
        input.original_cgroup_path = None;
        let output = rendered_text(&evaluate_move_executor_seam(&input));
        assert!(output.contains("no PID was moved"));
        assert!(output.contains("no cgroup.procs write was performed"));
        assert!(output.contains("no limiter attach was performed"));
        assert!(output.contains("no nftables/tc/Zelynic state changes were made"));
        assert!(output.contains("no persistent state write was performed"));
        assert!(output.contains("Experimental PID move is not implemented yet."));
        assert!(output.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn all_canonical_deny_lines_present_in_result_disclaimers() {
        let result = evaluate_move_executor_seam(&valid_input());
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no PID was moved")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no cgroup.procs write was performed")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no limiter attach was performed")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no nftables/tc/Zelynic state changes were made")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("no persistent state write was performed")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("Experimental PID move is not implemented yet")));
        assert!(result
            .disclaimers
            .iter()
            .any(|d| d.contains("Bandwidth limiting is not active from this command yet")));
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn negative_path_outputs_never_claim_mutation() {
        let scenarios: Vec<(&str, fn(&mut MoveExecutorInput))> = vec![
            ("non-root", |i| i.is_root = false),
            ("user scope", |i| i.scope_mode = ScopeMode::User),
            ("multi-PID", |i| i.pids = vec![1, 2]),
            ("missing original cgroup", |i| i.original_cgroup_path = None),
            ("missing consent", |i| i.consent_all_present = false),
        ];
        for (label, modify) in scenarios {
            let mut input = valid_input();
            modify(&mut input);
            let output = rendered_text(&evaluate_move_executor_seam(&input));
            assert!(
                !output.contains("PID was moved."),
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
                !output.contains("state changes were made")
                    || output.contains("no nftables/tc/Zelynic state changes were made"),
                "{}: must not claim positive state mutation",
                label
            );
            assert!(
                !output.contains("rollback performed"),
                "{}: must not claim rollback performed",
                label
            );
        }
    }
}
