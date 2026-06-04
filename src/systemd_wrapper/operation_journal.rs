// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Operation Journal: pure model for future move-only operation ownership and
//! rollback boundaries.
//!
//! This module creates deterministic preview IDs and renders planned journal
//! events. It does not persist state, write files, create cgroups, write
//! cgroup.procs, move PIDs, call nftables/tc, execute commands, or call the
//! limiter attach path.
//!
//! Phase 3b aligned the planned events with the 10-step transaction model
//! from the phase 3a design document.

use super::render::push_line;

pub(crate) const JOURNAL_OWNER: &str = "zelynic-scope-runner";
pub(crate) const JOURNAL_MODE: &str = "move-only";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperationJournalPreview {
    pub status: String,
    pub operation_id: String,
    pub owner: String,
    pub mode: String,
    pub target_name: String,
    pub target_cgroup: String,
    pub original_cgroup: Option<String>,
    pub pids: Vec<u32>,
    pub planned_events: Vec<JournalEvent>,
    pub rollback_boundary: String,
    pub rollback_target: String,
    pub external_state_policy: String,
    pub state_writes: String,
    pub execution: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JournalEvent {
    pub name: String,
}

pub(crate) fn build_operation_journal_preview(
    target_name: &str,
    target_cgroup: &str,
    original_cgroup: Option<&str>,
    pids: &[u32],
) -> OperationJournalPreview {
    OperationJournalPreview {
        status: "model only; not persisted".to_string(),
        operation_id: build_operation_id(target_name, pids, JOURNAL_MODE),
        owner: JOURNAL_OWNER.to_string(),
        mode: JOURNAL_MODE.to_string(),
        target_name: target_name.to_string(),
        target_cgroup: target_cgroup.to_string(),
        original_cgroup: original_cgroup.map(ToString::to_string),
        pids: pids.to_vec(),
        planned_events: planned_events(),
        rollback_boundary: "operation-owned state only".to_string(),
        rollback_target: original_cgroup
            .map(ToString::to_string)
            .unwrap_or_else(|| "pending captured original cgroup".to_string()),
        external_state_policy: "external/non-owned state must not be removed".to_string(),
        state_writes: "blocked".to_string(),
        execution: "blocked".to_string(),
    }
}

pub(crate) fn render_operation_journal_preview_section(
    output: &mut String,
    journal: &OperationJournalPreview,
) {
    push_line(output, "");
    push_line(output, "      Operation journal preview:");
    push_line(output, &format!("        status: {}", journal.status));
    push_line(
        output,
        &format!("        operation id: {}", journal.operation_id),
    );
    push_line(output, &format!("        owner: {}", journal.owner));
    push_line(output, &format!("        mode: {}", journal.mode));
    push_line(output, "        planned events:");
    for (index, event) in journal.planned_events.iter().enumerate() {
        push_line(output, &format!("          {}. {}", index + 1, event.name));
    }
    push_line(
        output,
        &format!("        rollback boundary: {}", journal.rollback_boundary),
    );
    push_line(
        output,
        &format!("        state writes: {}", journal.state_writes),
    );
    push_line(output, &format!("        execution: {}", journal.execution));
}

fn build_operation_id(target_name: &str, pids: &[u32], mode: &str) -> String {
    let seed = format!(
        "{}|{}|{}",
        sanitize_id_component(target_name),
        format_pid_component(pids),
        mode
    );
    format!("op-{:016x}", fnv1a64(seed.as_bytes()))
}

fn sanitize_id_component(input: &str) -> String {
    let mut out = String::new();
    let mut last_separator = false;

    for ch in input.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_separator = false;
        } else if !last_separator {
            out.push('_');
            last_separator = true;
        }
    }

    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed
    }
}

fn format_pid_component(pids: &[u32]) -> String {
    if pids.is_empty() {
        "no_pid".to_string()
    } else {
        pids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("_")
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn planned_events() -> Vec<JournalEvent> {
    [
        "planned",
        "gates_re_evaluated",
        "pid_liveness_rechecked",
        "original_cgroup_validated",
        "target_cgroup_prepared",
        "pid_move_planned",
        "pid_verification_planned",
        "move_success_recorded",
        "rollback_pid_restore_planned",
        "rollback_verification_planned",
        "target_cleanup_planned",
        "blocked_not_executed",
    ]
    .into_iter()
    .map(|name| JournalEvent {
        name: name.to_string(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_journal() -> OperationJournalPreview {
        build_operation_journal_preview(
            "sleep",
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
            &[12345],
        )
    }

    #[test]
    fn operation_id_is_stable_for_same_inputs() {
        let first = sample_journal();
        let second = sample_journal();

        assert_eq!(first.operation_id, second.operation_id);
    }

    #[test]
    fn operation_id_changes_for_different_pid_or_target() {
        let first = sample_journal();
        let different_pid = build_operation_journal_preview(
            "sleep",
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
            &[12346],
        );
        let different_target = build_operation_journal_preview(
            "helium",
            "/sys/fs/cgroup/zelynic/target_helium",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
            &[12345],
        );

        assert_ne!(first.operation_id, different_pid.operation_id);
        assert_ne!(first.operation_id, different_target.operation_id);
    }

    #[test]
    fn owner_is_zelynic_scope_runner() {
        assert_eq!(sample_journal().owner, "zelynic-scope-runner");
    }

    #[test]
    fn journal_includes_planned_events_in_order() {
        let journal = sample_journal();
        let names = journal
            .planned_events
            .iter()
            .map(|event| event.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "planned",
                "gates_re_evaluated",
                "pid_liveness_rechecked",
                "original_cgroup_validated",
                "target_cgroup_prepared",
                "pid_move_planned",
                "pid_verification_planned",
                "move_success_recorded",
                "rollback_pid_restore_planned",
                "rollback_verification_planned",
                "target_cleanup_planned",
                "blocked_not_executed",
            ]
        );
    }

    #[test]
    fn rollback_boundary_is_operation_owned_state_only() {
        let journal = sample_journal();

        assert_eq!(journal.rollback_boundary, "operation-owned state only");
        assert_eq!(
            journal.external_state_policy,
            "external/non-owned state must not be removed"
        );
    }

    #[test]
    fn state_writes_are_blocked() {
        assert_eq!(sample_journal().state_writes, "blocked");
    }

    #[test]
    fn execution_is_blocked() {
        assert_eq!(sample_journal().execution, "blocked");
    }

    #[test]
    fn output_says_model_only_not_persisted() {
        let mut output = String::new();
        render_operation_journal_preview_section(&mut output, &sample_journal());

        assert!(output.contains("status: model only; not persisted"));
    }

    #[test]
    fn output_does_not_claim_persisted_written_moved_attached_limited_or_enforced() {
        let mut output = String::new();
        render_operation_journal_preview_section(&mut output, &sample_journal());

        assert!(!output.contains("persisted to"));
        assert!(!output.contains("written"));
        assert!(!output.contains("moved"));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }
}
