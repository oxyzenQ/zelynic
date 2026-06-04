// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Experimental Attach Gate: pure checklist model for a future single-PID
//! move-only attach experiment.
//!
//! This module is model/rendering only. It does not move PIDs, create cgroups,
//! write cgroup.procs, call nftables/tc, write Zelynic state, or call the
//! limiter attach execution path.

use super::attach_preview::AttachPreview;
use super::move_transaction::{
    build_move_transaction_skeleton, render_move_transaction_skeleton_section, MoveTransaction,
};
use super::original_cgroup_preview::OriginalCgroupCaptureStatus;
use super::pid_safety::{LivenessStatus, SelfProtectionStatus};
use super::plan::ScopeMode;
use super::render::push_line;

pub(crate) const EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED: &str =
    "Experimental PID move is not implemented yet. This build only supports live probe, safety checks, and attach/rollback planning.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ExperimentalAttachConsent {
    pub experimental_single_pid_attach: bool,
    pub i_understand_this_moves_pids: bool,
    pub rollback_required: bool,
}

impl ExperimentalAttachConsent {
    pub(crate) fn all_present(&self) -> bool {
        self.experimental_single_pid_attach
            && self.i_understand_this_moves_pids
            && self.rollback_required
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExperimentalAttachGateInput {
    pub execute: bool,
    pub scope_mode: ScopeMode,
    pub probe_live: bool,
    pub attach_live: bool,
    pub is_root: bool,
    pub consent: ExperimentalAttachConsent,
    pub discovered_pids: Vec<u32>,
    pub discovered_pid_count: usize,
    pub original_cgroup_capture_valid: bool,
    pub pid_liveness_alive: bool,
    pub self_protection_allowed: bool,
    pub transaction_model_only: bool,
    pub mutation_mode_move_only: bool,
    pub nft_tc_state_disabled: bool,
    pub target_cgroup_path: String,
    pub original_rollback_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateCheckStatus {
    Ok,
    Missing,
    Blocked,
}

impl GateCheckStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateCheck {
    pub name: String,
    pub value: String,
    pub status: GateCheckStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExperimentalAttachGateChecklist {
    pub checks: Vec<GateCheck>,
    pub mutation_mode: String,
    pub nft_tc_state: String,
    pub move_transaction: MoveTransaction,
    pub final_status: String,
    pub reason: String,
}

pub(crate) fn build_gate_input_from_preview(
    preview: &AttachPreview,
    execute: bool,
    scope_mode: ScopeMode,
    probe_live: bool,
    attach_live: bool,
    is_root: bool,
    consent: ExperimentalAttachConsent,
) -> ExperimentalAttachGateInput {
    let safety = &preview.safety_preflight;
    let original_cgroup_capture_valid = safety.original_cgroup_previews.len() == 1
        && safety.original_cgroup_previews.iter().all(|preview| {
            matches!(
                preview.status,
                OriginalCgroupCaptureStatus::CapturedLive
                    | OriginalCgroupCaptureStatus::CapturedFromSample
            ) && preview.rollback_target_path.is_some()
        });

    let pid_liveness_alive = safety.pid_safety_checks.len() == 1
        && safety
            .pid_safety_checks
            .iter()
            .all(|check| check.liveness == LivenessStatus::Alive);

    let self_protection_allowed = safety.pid_safety_checks.len() == 1
        && safety
            .pid_safety_checks
            .iter()
            .all(|check| check.self_protection == SelfProtectionStatus::Allowed);

    let transaction_model_only = safety.attach_transaction_plan.status
        == "model only; not executed"
        && safety.attach_transaction_plan.execution == "blocked";
    let original_rollback_path = safety
        .original_cgroup_previews
        .first()
        .and_then(|preview| preview.rollback_target_path.clone());

    ExperimentalAttachGateInput {
        execute,
        scope_mode,
        probe_live,
        attach_live,
        is_root,
        consent,
        discovered_pids: preview.pids.clone(),
        discovered_pid_count: preview.pids.len(),
        original_cgroup_capture_valid,
        pid_liveness_alive,
        self_protection_allowed,
        transaction_model_only,
        mutation_mode_move_only: true,
        nft_tc_state_disabled: true,
        target_cgroup_path: preview.future_target_cgroup.clone(),
        original_rollback_path,
    }
}

pub(crate) fn evaluate_experimental_attach_gate(
    input: ExperimentalAttachGateInput,
) -> ExperimentalAttachGateChecklist {
    let move_transaction = build_move_transaction_skeleton(
        &input.discovered_pids,
        &input.target_cgroup_path,
        input.original_rollback_path.as_deref(),
    );
    let checks = vec![
        bool_check("execute", input.execute),
        scope_mode_check(input.scope_mode),
        bool_check("probe-live", input.probe_live),
        bool_check("attach-live", input.attach_live),
        root_check(input.is_root),
        bool_check(
            "experimental-single-pid-attach",
            input.consent.experimental_single_pid_attach,
        ),
        bool_check(
            "i-understand-this-moves-pids",
            input.consent.i_understand_this_moves_pids,
        ),
        bool_check("rollback-required", input.consent.rollback_required),
        discovered_pid_count_check(input.discovered_pid_count),
        bool_blocking_check(
            "original cgroup capture",
            input.original_cgroup_capture_valid,
        ),
        bool_blocking_check("PID safety", input.pid_liveness_alive),
        bool_blocking_check("self-protection", input.self_protection_allowed),
        bool_blocking_check("transaction plan", input.transaction_model_only),
        bool_blocking_check(
            "move-only executor skeleton",
            move_transaction.blocked_reasons.is_empty(),
        ),
        bool_blocking_check("mutation mode", input.mutation_mode_move_only),
        bool_blocking_check("nft/tc/state", input.nft_tc_state_disabled),
    ];

    ExperimentalAttachGateChecklist {
        checks,
        mutation_mode: "move-only".to_string(),
        nft_tc_state: "disabled".to_string(),
        move_transaction,
        final_status: "blocked".to_string(),
        reason: "experimental PID move is not implemented yet".to_string(),
    }
}

pub(crate) fn render_experimental_attach_gate_section(
    output: &mut String,
    checklist: &ExperimentalAttachGateChecklist,
) {
    push_line(output, "");
    push_line(output, "  Experimental attach gate:");
    for check in &checklist.checks {
        push_line(
            output,
            &format!(
                "    {}: {}: {}",
                check.name,
                check.value,
                check.status.label()
            ),
        );
    }
    push_line(
        output,
        &format!("    mutation mode: {}", checklist.mutation_mode),
    );
    push_line(
        output,
        &format!("    nft/tc/state: {}", checklist.nft_tc_state),
    );
    render_move_transaction_skeleton_section(output, &checklist.move_transaction);
    push_line(output, &format!("    final: {}", checklist.final_status));
    push_line(output, &format!("    reason: {}", checklist.reason));
}

fn bool_check(name: &str, present: bool) -> GateCheck {
    GateCheck {
        name: name.to_string(),
        value: if present { "present" } else { "missing" }.to_string(),
        status: if present {
            GateCheckStatus::Ok
        } else {
            GateCheckStatus::Missing
        },
    }
}

fn bool_blocking_check(name: &str, ok: bool) -> GateCheck {
    GateCheck {
        name: name.to_string(),
        value: if ok { "ok" } else { "blocked" }.to_string(),
        status: if ok {
            GateCheckStatus::Ok
        } else {
            GateCheckStatus::Blocked
        },
    }
}

fn root_check(is_root: bool) -> GateCheck {
    GateCheck {
        name: "root".to_string(),
        value: if is_root { "euid 0" } else { "non-root" }.to_string(),
        status: if is_root {
            GateCheckStatus::Ok
        } else {
            GateCheckStatus::Blocked
        },
    }
}

fn scope_mode_check(scope_mode: ScopeMode) -> GateCheck {
    GateCheck {
        name: "scope mode".to_string(),
        value: match scope_mode {
            ScopeMode::System => "system".to_string(),
            ScopeMode::User => "user".to_string(),
        },
        status: if scope_mode == ScopeMode::System {
            GateCheckStatus::Ok
        } else {
            GateCheckStatus::Blocked
        },
    }
}

fn discovered_pid_count_check(count: usize) -> GateCheck {
    GateCheck {
        name: "discovered PID count".to_string(),
        value: count.to_string(),
        status: if count == 1 {
            GateCheckStatus::Ok
        } else {
            GateCheckStatus::Blocked
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_consent() -> ExperimentalAttachConsent {
        ExperimentalAttachConsent {
            experimental_single_pid_attach: true,
            i_understand_this_moves_pids: true,
            rollback_required: true,
        }
    }

    fn ok_input() -> ExperimentalAttachGateInput {
        ExperimentalAttachGateInput {
            execute: true,
            scope_mode: ScopeMode::System,
            probe_live: true,
            attach_live: true,
            is_root: true,
            consent: ok_consent(),
            discovered_pids: vec![12345],
            discovered_pid_count: 1,
            original_cgroup_capture_valid: true,
            pid_liveness_alive: true,
            self_protection_allowed: true,
            transaction_model_only: true,
            mutation_mode_move_only: true,
            nft_tc_state_disabled: true,
            target_cgroup_path: "/sys/fs/cgroup/zelynic/target_sleep".to_string(),
            original_rollback_path: Some("/sys/fs/cgroup/user.slice/session-2.scope".to_string()),
        }
    }

    fn status_for(checklist: &ExperimentalAttachGateChecklist, name: &str) -> GateCheckStatus {
        checklist
            .checks
            .iter()
            .find(|check| check.name == name)
            .expect("check present")
            .status
    }

    #[test]
    fn missing_experimental_single_pid_attach_blocks() {
        let mut input = ok_input();
        input.consent.experimental_single_pid_attach = false;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "experimental-single-pid-attach"),
            GateCheckStatus::Missing
        );
        assert_eq!(checklist.final_status, "blocked");
    }

    #[test]
    fn missing_i_understand_this_moves_pids_blocks() {
        let mut input = ok_input();
        input.consent.i_understand_this_moves_pids = false;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "i-understand-this-moves-pids"),
            GateCheckStatus::Missing
        );
    }

    #[test]
    fn missing_rollback_required_blocks() {
        let mut input = ok_input();
        input.consent.rollback_required = false;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "rollback-required"),
            GateCheckStatus::Missing
        );
    }

    #[test]
    fn multiple_discovered_pids_block() {
        let mut input = ok_input();
        input.discovered_pid_count = 2;
        input.discovered_pids = vec![12345, 12346];
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "discovered PID count"),
            GateCheckStatus::Blocked
        );
    }

    #[test]
    fn missing_original_cgroup_capture_blocks() {
        let mut input = ok_input();
        input.original_cgroup_capture_valid = false;
        input.original_rollback_path = None;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "original cgroup capture"),
            GateCheckStatus::Blocked
        );
    }

    #[test]
    fn stale_or_missing_pid_liveness_blocks() {
        let mut input = ok_input();
        input.pid_liveness_alive = false;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "PID safety"),
            GateCheckStatus::Blocked
        );
    }

    #[test]
    fn self_protection_block_blocks() {
        let mut input = ok_input();
        input.self_protection_allowed = false;
        let checklist = evaluate_experimental_attach_gate(input);

        assert_eq!(
            status_for(&checklist, "self-protection"),
            GateCheckStatus::Blocked
        );
    }

    #[test]
    fn all_gate_inputs_ok_still_returns_hard_blocked_not_implemented() {
        let checklist = evaluate_experimental_attach_gate(ok_input());

        assert!(checklist
            .checks
            .iter()
            .all(|check| check.status == GateCheckStatus::Ok));
        assert_eq!(checklist.final_status, "blocked");
        assert_eq!(
            checklist.reason,
            "experimental PID move is not implemented yet"
        );
        assert_eq!(
            checklist.move_transaction.status,
            "skeleton only; not executed"
        );
        assert_eq!(checklist.move_transaction.execution, "blocked");
    }

    #[test]
    fn gate_output_includes_disabled_state_without_footer_duplication() {
        let checklist = evaluate_experimental_attach_gate(ok_input());
        let mut output = String::new();

        render_experimental_attach_gate_section(&mut output, &checklist);

        assert!(output.contains("Experimental attach gate"));
        assert!(output.contains("nft/tc/state: disabled"));
        assert!(output.contains("Move-only executor skeleton"));
        assert!(output.contains("execution: blocked"));
        assert!(!output.contains("No PID was moved."));
        assert!(!output.contains("No limiter attach was performed."));
        assert!(!output.contains("No nftables, tc, Zelynic cgroup, or state changes were made."));
    }

    #[test]
    fn gate_output_does_not_claim_attached_limited_or_enforced() {
        let checklist = evaluate_experimental_attach_gate(ok_input());
        let mut output = String::new();

        render_experimental_attach_gate_section(&mut output, &checklist);

        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }
}
