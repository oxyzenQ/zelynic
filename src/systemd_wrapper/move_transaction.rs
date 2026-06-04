// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Move Transaction: pure skeleton for a future single-PID cgroup move and
//! immediate rollback experiment.
//!
//! This module models the future write sequence only. It does not create
//! directories, write cgroup.procs, read cgroup.procs, call nftables/tc, write
//! Zelynic state, execute commands, or call the limiter attach path.

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
    pub target_cgroup_path: String,
    pub original_cgroup_path: Option<String>,
    pub operations: Vec<MoveOperation>,
    pub rollback: Vec<RollbackOperation>,
    pub writes_modelled: Vec<String>,
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
    pid_count: usize,
    target_cgroup_path: &str,
    original_cgroup_path: Option<&str>,
) -> MoveTransaction {
    let mut blocked_reasons = Vec::new();
    let target_cgroup_preflight =
        build_target_cgroup_preflight(target_cgroup_path, original_cgroup_path);

    if pid_count != 1 {
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
        mode: "single PID cgroup move + rollback".to_string(),
        pid_count,
        target_cgroup_path: target_cgroup_path.to_string(),
        original_cgroup_path,
        operations: vec![
            op("1. verify gate checklist is still valid"),
            op("2. verify exactly one PID"),
            op("3. verify source/original cgroup path captured"),
            op("4. verify target cgroup path is under /sys/fs/cgroup/zelynic/"),
            op("5. future write: create/prepare target cgroup directory"),
            op("6. future write: write PID into target cgroup cgroup.procs"),
            op("7. future verify: PID appears in target cgroup.procs"),
            op("8. future rollback: write PID back into original cgroup cgroup.procs"),
            op("9. future verify: PID restored to original cgroup"),
            op("10. future cleanup: remove target cgroup only if safe/empty"),
        ],
        rollback: vec![
            rollback("write PID back to original cgroup.procs"),
            rollback("verify PID restored to original cgroup"),
            rollback("remove target cgroup only if safe and empty"),
        ],
        writes_modelled: vec![
            "prepare Zelynic target cgroup".to_string(),
            "write PID to target cgroup.procs".to_string(),
            "verify PID in target cgroup".to_string(),
            "write PID back to original cgroup.procs".to_string(),
            "verify PID restored".to_string(),
        ],
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
    render_target_cgroup_preflight_section(output, &transaction.target_cgroup_preflight);
    push_line(
        output,
        &format!("      execution: {}", transaction.execution),
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_transaction() -> MoveTransaction {
        build_move_transaction_skeleton(
            1,
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
            1,
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
            build_move_transaction_skeleton(1, "/sys/fs/cgroup/zelynic/target_sleep", None);

        assert!(transaction
            .blocked_reasons
            .contains(&"original cgroup capture is required".to_string()));
    }

    #[test]
    fn multiple_pid_input_is_blocked() {
        let transaction = build_move_transaction_skeleton(
            2,
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
        );

        assert!(transaction
            .blocked_reasons
            .contains(&"exactly one discovered PID is required".to_string()));
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
}
