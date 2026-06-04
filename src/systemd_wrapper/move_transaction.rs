// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Move Transaction: pure skeleton for a future single-PID cgroup move and
//! immediate rollback experiment.
//!
//! This module models the future write sequence only. It does not create
//! directories, write cgroup.procs, read cgroup.procs, call nftables/tc, write
//! Zelynic state, execute commands, or call the limiter attach path.
//!
//! Phase 3b aligned the 10-step transaction model with the phase 3a design
//! document. All steps remain "planned" / model-only / execution-blocked.

use super::operation_journal::{
    build_operation_journal_preview, render_operation_journal_preview_section,
    OperationJournalPreview,
};
use super::render::push_line;
use super::target_cgroup_preflight::{
    build_target_cgroup_preflight, render_target_cgroup_preflight_section, TargetCgroupPreflight,
};

const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MoveTransaction {
    pub status: String,
    pub mode: String,
    pub pid_count: usize,
    pub pids: Vec<u32>,
    pub target_cgroup_path: String,
    pub original_cgroup_path: Option<String>,
    pub operations: Vec<MoveOperation>,
    pub rollback: Vec<RollbackOperation>,
    pub writes_modelled: Vec<String>,
    pub operation_journal: OperationJournalPreview,
    pub target_cgroup_preflight: TargetCgroupPreflight,
    pub execution: String,
    pub blocked_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MoveOperation {
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RollbackOperation {
    pub description: String,
}

pub(crate) fn build_move_transaction_skeleton(
    pids: &[u32],
    target_cgroup_path: &str,
    original_cgroup_path: Option<&str>,
) -> MoveTransaction {
    let mut blocked_reasons = Vec::new();
    let target_cgroup_preflight =
        build_target_cgroup_preflight(target_cgroup_path, original_cgroup_path);
    let target_name = target_name_from_cgroup(target_cgroup_path);
    let operation_journal = build_operation_journal_preview(
        &target_name,
        target_cgroup_path,
        original_cgroup_path,
        pids,
    );

    if pids.len() != 1 {
        blocked_reasons.push("exactly one discovered PID is required".to_string());
    }

    if !is_safe_zelynic_target_cgroup(target_cgroup_path) {
        blocked_reasons.push("target cgroup must be under /sys/fs/cgroup/zelynic/".to_string());
    }

    let original_cgroup_path = match original_cgroup_path {
        Some(path) if !path.trim().is_empty() => Some(path.to_string()),
        _ => {
            blocked_reasons.push("original cgroup capture is required".to_string());
            None
        }
    };

    MoveTransaction {
        status: "skeleton only; not executed".to_string(),
        mode: "move-only: single PID cgroup move + immediate rollback".to_string(),
        pid_count: pids.len(),
        pids: pids.to_vec(),
        target_cgroup_path: target_cgroup_path.to_string(),
        original_cgroup_path,
        operations: vec![
            op("1. planned: re-evaluate all safety gates at move time"),
            op("2. planned: PID liveness recheck (/proc/<pid> exists)"),
            op("3. planned: original cgroup validation (safe path, not under /zelynic/)"),
            op("4. planned write: create/prepare target cgroup directory"),
            op("5. planned write: write PID into target cgroup cgroup.procs"),
            op("6. planned verify: PID appears in target cgroup.procs"),
            op("7. planned: record move success (in-memory model update only)"),
            op("8. planned rollback: write PID back into original cgroup cgroup.procs"),
            op("9. planned verify: PID restored to original cgroup"),
            op("10. planned cleanup: remove target cgroup only if safe/empty"),
        ],
        rollback: vec![
            rollback("write PID back to original cgroup.procs"),
            rollback("verify PID restored to original cgroup"),
            rollback("remove target cgroup only if safe and empty"),
        ],
        writes_modelled: vec![
            "create/prepare target cgroup directory".to_string(),
            "write PID into target cgroup.procs".to_string(),
            "verify PID in target cgroup.procs".to_string(),
            "record move success (in-memory)".to_string(),
            "write PID back into original cgroup.procs (rollback)".to_string(),
            "verify PID restored in original cgroup".to_string(),
            "remove target cgroup if empty/operation-owned".to_string(),
        ],
        operation_journal,
        target_cgroup_preflight,
        execution: "blocked".to_string(),
        blocked_reasons,
    }
}

pub(crate) fn render_move_transaction_skeleton_section(
    output: &mut String,
    transaction: &MoveTransaction,
) {
    push_line(output, "");
    push_line(output, "    Move-only executor skeleton:");
    push_line(output, &format!("      status: {}", transaction.status));
    push_line(output, &format!("      mode: {}", transaction.mode));
    push_line(output, "      transaction steps:");
    for op_step in &transaction.operations {
        push_line(output, &format!("        {}", op_step.description));
    }
    push_line(output, "      rollback steps:");
    for rb in &transaction.rollback {
        push_line(output, &format!("        {}", rb.description));
    }
    push_line(output, "      writes modelled:");
    for (index, item) in transaction.writes_modelled.iter().enumerate() {
        push_line(output, &format!("        {}. {}", index + 1, item));
    }
    if !transaction.blocked_reasons.is_empty() {
        push_line(
            output,
            &format!(
                "      blocked reason: {}",
                transaction.blocked_reasons.join("; ")
            ),
        );
    }
    render_operation_journal_preview_section(output, &transaction.operation_journal);
    render_target_cgroup_preflight_section(output, &transaction.target_cgroup_preflight);
    push_line(
        output,
        &format!("      execution: {}", transaction.execution),
    );
    push_line(output, "      pid movement: not performed");
    push_line(output, "      cgroup.procs writes: not performed");
    push_line(output, "      phase: 3b skeleton alignment");
}

fn is_safe_zelynic_target_cgroup(path: &str) -> bool {
    let Some(remainder) = path.strip_prefix(&format!("{ZELYNIC_CGROUP_ROOT}/")) else {
        return false;
    };

    !remainder.is_empty()
        && !remainder.contains("..")
        && path.starts_with(&format!("{ZELYNIC_CGROUP_ROOT}/target_"))
}

fn op(description: &str) -> MoveOperation {
    MoveOperation {
        description: description.to_string(),
    }
}

fn rollback(description: &str) -> RollbackOperation {
    RollbackOperation {
        description: description.to_string(),
    }
}

fn target_name_from_cgroup(path: &str) -> String {
    path.rsplit('/')
        .next()
        .and_then(|name| name.strip_prefix("target_"))
        .filter(|name| !name.is_empty())
        .unwrap_or("target")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_transaction() -> MoveTransaction {
        build_move_transaction_skeleton(
            &[12345],
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
        )
    }

    fn operation_text(transaction: &MoveTransaction) -> String {
        transaction
            .operations
            .iter()
            .map(|operation| operation.description.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn skeleton_includes_prepare_target_cgroup_operation() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("create/prepare target cgroup directory"));
    }

    #[test]
    fn skeleton_includes_write_pid_to_target_cgroup_procs_operation() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("write PID into target cgroup cgroup.procs"));
    }

    #[test]
    fn skeleton_includes_verify_pid_in_target_cgroup_operation() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("PID appears in target cgroup.procs"));
    }

    #[test]
    fn skeleton_includes_rollback_write_to_original_cgroup_procs_operation() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("write PID back into original cgroup cgroup.procs"));
    }

    #[test]
    fn skeleton_includes_verify_restored_operation() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("PID restored to original cgroup"));
    }

    #[test]
    fn skeleton_says_skeleton_only_not_executed() {
        let transaction = valid_transaction();
        assert_eq!(transaction.status, "skeleton only; not executed");
    }

    #[test]
    fn skeleton_says_execution_blocked() {
        let transaction = valid_transaction();
        assert_eq!(transaction.execution, "blocked");
    }

    #[test]
    fn skeleton_includes_target_cgroup_preflight() {
        let transaction = valid_transaction();
        assert_eq!(
            transaction.target_cgroup_preflight.target_cgroup,
            "/sys/fs/cgroup/zelynic/target_sleep"
        );
        assert_eq!(
            transaction
                .target_cgroup_preflight
                .target_cgroup_procs
                .as_deref(),
            Some("/sys/fs/cgroup/zelynic/target_sleep/cgroup.procs")
        );
    }

    #[test]
    fn invalid_target_path_outside_zelynic_is_blocked() {
        let transaction = build_move_transaction_skeleton(
            &[12345],
            "/sys/fs/cgroup/system.slice/example.scope",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
        );

        assert!(transaction
            .blocked_reasons
            .contains(&"target cgroup must be under /sys/fs/cgroup/zelynic/".to_string()));
        assert!(transaction
            .target_cgroup_preflight
            .blocked_reasons
            .contains(&"target cgroup must be under /sys/fs/cgroup/zelynic/".to_string()));
    }

    #[test]
    fn missing_original_cgroup_capture_is_blocked() {
        let transaction =
            build_move_transaction_skeleton(&[12345], "/sys/fs/cgroup/zelynic/target_sleep", None);

        assert!(transaction
            .blocked_reasons
            .contains(&"original cgroup capture is required".to_string()));
    }

    #[test]
    fn multiple_pid_input_is_blocked() {
        let transaction = build_move_transaction_skeleton(
            &[12345, 12346],
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
        );

        assert!(transaction
            .blocked_reasons
            .contains(&"exactly one discovered PID is required".to_string()));
    }

    #[test]
    fn skeleton_includes_operation_journal_preview() {
        let transaction = valid_transaction();
        assert_eq!(transaction.operation_journal.owner, "zelynic-scope-runner");
        assert_eq!(transaction.operation_journal.mode, "move-only");
        assert_eq!(transaction.operation_journal.pids, vec![12345]);
    }

    #[test]
    fn rendered_output_does_not_claim_moved_attached_limited_or_enforced() {
        let mut output = String::new();
        render_move_transaction_skeleton_section(&mut output, &valid_transaction());

        assert!(!output.contains("moved"));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }

    // ---- phase 3b alignment tests ----

    #[test]
    fn skeleton_includes_pid_liveness_recheck_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("PID liveness"));
    }

    #[test]
    fn skeleton_includes_original_cgroup_validation_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("original cgroup validation"));
    }

    #[test]
    fn skeleton_includes_record_move_success_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("record move success"));
    }

    #[test]
    fn skeleton_includes_immediate_rollback_step() {
        let transaction = valid_transaction();
        assert!(!transaction.rollback.is_empty());
        assert!(transaction
            .rollback
            .iter()
            .any(|r| r.description.contains("write PID back")));
        assert!(transaction
            .rollback
            .iter()
            .any(|r| r.description.contains("verify PID restored")));
        assert!(transaction
            .rollback
            .iter()
            .any(|r| r.description.contains("remove target cgroup")));
    }

    #[test]
    fn skeleton_includes_target_cleanup_boundary() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("safe/empty"));
    }

    #[test]
    fn skeleton_operations_count_is_ten() {
        let transaction = valid_transaction();
        assert_eq!(transaction.operations.len(), 10);
    }

    #[test]
    fn skeleton_writes_modelled_count_is_seven() {
        let transaction = valid_transaction();
        assert_eq!(transaction.writes_modelled.len(), 7);
    }

    #[test]
    fn skeleton_rollback_count_is_three() {
        let transaction = valid_transaction();
        assert_eq!(transaction.rollback.len(), 3);
    }

    #[test]
    fn rendered_output_explicitly_says_cgroup_procs_not_performed() {
        let mut output = String::new();
        render_move_transaction_skeleton_section(&mut output, &valid_transaction());
        assert!(output.contains("cgroup.procs writes: not performed"));
        assert!(output.contains("pid movement: not performed"));
    }

    #[test]
    fn rendered_output_says_phase_3b_skeleton_model_only() {
        let mut output = String::new();
        render_move_transaction_skeleton_section(&mut output, &valid_transaction());
        assert!(output.contains("phase: 3b skeleton alignment"));
        assert!(output.contains("skeleton only; not executed"));
    }

    #[test]
    fn rendered_output_includes_transaction_steps() {
        let mut output = String::new();
        render_move_transaction_skeleton_section(&mut output, &valid_transaction());
        assert!(output.contains("transaction steps:"));
        assert!(output.contains("re-evaluate all safety gates"));
        assert!(output.contains("PID liveness recheck"));
        assert!(output.contains("record move success"));
    }

    #[test]
    fn rendered_output_includes_rollback_steps() {
        let mut output = String::new();
        render_move_transaction_skeleton_section(&mut output, &valid_transaction());
        assert!(output.contains("rollback steps:"));
        assert!(output.contains("write PID back to original cgroup.procs"));
        assert!(output.contains("verify PID restored to original cgroup"));
        assert!(output.contains("remove target cgroup only if safe and empty"));
    }

    #[test]
    fn skeleton_blocks_empty_original_cgroup_string() {
        let transaction = build_move_transaction_skeleton(
            &[12345],
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some(""),
        );
        assert!(transaction
            .blocked_reasons
            .contains(&"original cgroup capture is required".to_string()));
    }
}
