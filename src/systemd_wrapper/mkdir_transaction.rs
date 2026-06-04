// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Mkdir Transaction: pure skeleton for a future cgroup mkdir-only experiment
//! (v2.8 phase 2a).
//!
//! This module models the future mkdir-only write sequence only. It does not
//! create directories, write cgroup.procs, call mkdir/create_dir/create_dir_all,
//! move PIDs, call nftables/tc, write Zelynic state, execute commands, or call
//! the limiter attach path.

use super::render::push_line;

const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MkdirTransaction {
    pub status: String,
    pub mode: String,
    pub parent_namespace: String,
    pub target_cgroup_path: String,
    pub writes_modelled: Vec<String>,
    pub pid_movement: String,
    pub cgroup_procs_writes: String,
    pub nft_tc_state: String,
    pub execution: String,
    pub blocked_reasons: Vec<String>,
}

pub(crate) fn build_mkdir_transaction_skeleton(target_cgroup_path: &str) -> MkdirTransaction {
    let mut blocked_reasons = Vec::new();

    if !is_safe_zelynic_target_cgroup(target_cgroup_path) {
        blocked_reasons.push("target cgroup must be under /sys/fs/cgroup/zelynic/".to_string());
    }

    MkdirTransaction {
        status: "skeleton only; not executed".to_string(),
        mode: "cgroup mkdir-only".to_string(),
        parent_namespace: ZELYNIC_CGROUP_ROOT.to_string(),
        target_cgroup_path: target_cgroup_path.to_string(),
        writes_modelled: vec![
            format!("create/prepare {}", ZELYNIC_CGROUP_ROOT),
            format!("create/prepare {}", target_cgroup_path),
            format!("verify {} exists", target_cgroup_path),
            format!(
                "cleanup {} only if operation-owned and empty",
                target_cgroup_path
            ),
        ],
        pid_movement: "disabled".to_string(),
        cgroup_procs_writes: "disabled".to_string(),
        nft_tc_state: "disabled".to_string(),
        execution: "blocked".to_string(),
        blocked_reasons,
    }
}

pub(crate) fn render_mkdir_transaction_skeleton_section(
    output: &mut String,
    transaction: &MkdirTransaction,
) {
    push_line(output, "");
    push_line(output, "    Mkdir-only executor skeleton:");
    push_line(output, &format!("      status: {}", transaction.status));
    push_line(output, &format!("      mode: {}", transaction.mode));
    push_line(output, "      future writes modelled:");
    for (index, item) in transaction.writes_modelled.iter().enumerate() {
        push_line(output, &format!("        {}. {}", index + 1, item));
    }
    push_line(
        output,
        &format!("      pid movement: {}", transaction.pid_movement),
    );
    push_line(
        output,
        &format!(
            "      cgroup.procs writes: {}",
            transaction.cgroup_procs_writes
        ),
    );
    push_line(
        output,
        &format!("      nft/tc/state: {}", transaction.nft_tc_state),
    );
    if !transaction.blocked_reasons.is_empty() {
        push_line(
            output,
            &format!(
                "      blocked reason: {}",
                transaction.blocked_reasons.join("; ")
            ),
        );
    }
    push_line(
        output,
        &format!("      execution: {}", transaction.execution),
    );
    push_line(output, "      first real write: not enabled in this build");
}

fn is_safe_zelynic_target_cgroup(path: &str) -> bool {
    let Some(remainder) = path.strip_prefix(&format!("{ZELYNIC_CGROUP_ROOT}/")) else {
        return false;
    };

    !remainder.is_empty()
        && !remainder.contains("..")
        && path.starts_with(&format!("{ZELYNIC_CGROUP_ROOT}/target_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_transaction() -> MkdirTransaction {
        build_mkdir_transaction_skeleton("/sys/fs/cgroup/zelynic/target_sleep")
    }

    fn operation_text(transaction: &MkdirTransaction) -> String {
        let mut lines = Vec::new();
        for item in &transaction.writes_modelled {
            lines.push(item.clone());
        }
        lines.join("\n")
    }

    #[test]
    fn skeleton_includes_parent_namespace_create_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("create/prepare /sys/fs/cgroup/zelynic"));
    }

    #[test]
    fn skeleton_includes_target_cgroup_create_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("create/prepare /sys/fs/cgroup/zelynic/target_sleep"));
    }

    #[test]
    fn skeleton_includes_verify_target_exists_step() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains("verify /sys/fs/cgroup/zelynic/target_sleep exists"));
    }

    #[test]
    fn skeleton_includes_cleanup_only_if_operation_owned_and_empty() {
        let text = operation_text(&valid_transaction());
        assert!(text.contains(
            "cleanup /sys/fs/cgroup/zelynic/target_sleep only if operation-owned and empty"
        ));
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
    fn skeleton_says_first_real_write_not_enabled() {
        let mut output = String::new();
        render_mkdir_transaction_skeleton_section(&mut output, &valid_transaction());
        assert!(output.contains("first real write: not enabled in this build"));
    }

    #[test]
    fn skeleton_says_pid_movement_disabled() {
        let transaction = valid_transaction();
        assert_eq!(transaction.pid_movement, "disabled");
    }

    #[test]
    fn skeleton_says_cgroup_procs_writes_disabled() {
        let transaction = valid_transaction();
        assert_eq!(transaction.cgroup_procs_writes, "disabled");
    }

    #[test]
    fn skeleton_says_nft_tc_state_disabled() {
        let transaction = valid_transaction();
        assert_eq!(transaction.nft_tc_state, "disabled");
    }

    #[test]
    fn skeleton_mode_is_cgroup_mkdir_only() {
        let transaction = valid_transaction();
        assert_eq!(transaction.mode, "cgroup mkdir-only");
    }

    #[test]
    fn invalid_target_path_outside_zelynic_is_blocked() {
        let transaction =
            build_mkdir_transaction_skeleton("/sys/fs/cgroup/system.slice/example.scope");

        assert!(transaction
            .blocked_reasons
            .iter()
            .any(|r| r.contains("target cgroup must be under /sys/fs/cgroup/zelynic/")));
    }

    #[test]
    fn rendered_output_does_not_claim_created_written_moved_attached_limited_enforced() {
        let mut output = String::new();
        render_mkdir_transaction_skeleton_section(&mut output, &valid_transaction());

        assert!(!output.contains("created"));
        assert!(!output.contains("written"));
        assert!(!output.contains("moved"));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }

    #[test]
    fn rendered_output_includes_all_required_fields() {
        let mut output = String::new();
        render_mkdir_transaction_skeleton_section(&mut output, &valid_transaction());

        assert!(output.contains("Mkdir-only executor skeleton"));
        assert!(output.contains("skeleton only; not executed"));
        assert!(output.contains("cgroup mkdir-only"));
        assert!(output.contains("pid movement: disabled"));
        assert!(output.contains("cgroup.procs writes: disabled"));
        assert!(output.contains("nft/tc/state: disabled"));
        assert!(output.contains("execution: blocked"));
        assert!(output.contains("first real write: not enabled in this build"));
    }

    #[test]
    fn parent_namespace_is_zelynic_root() {
        let transaction = valid_transaction();
        assert_eq!(transaction.parent_namespace, "/sys/fs/cgroup/zelynic");
    }

    #[test]
    fn blocked_reason_rendered_when_present() {
        let transaction =
            build_mkdir_transaction_skeleton("/sys/fs/cgroup/system.slice/example.scope");
        let mut output = String::new();
        render_mkdir_transaction_skeleton_section(&mut output, &transaction);

        assert!(output.contains("blocked reason"));
    }

    #[test]
    fn no_blocked_reason_when_path_valid() {
        let transaction = valid_transaction();
        assert!(transaction.blocked_reasons.is_empty());
    }
}
