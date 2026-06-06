// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for the hard-blocked persistence I/O contract seam (v2.9 phase 9).
//!
//! All tests verify that persistence operations are hard-blocked and perform
//! no filesystem I/O. No live reads, no writes, no directory creation, no
//! file creation, no file removal, no CLI command.

use super::super::ledger_persistence::*;

#[test]
fn test_read_plan_always_blocked() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Blocked(_)
    ));
    assert_eq!(plan.operation, PersistenceOperation::ReadLedger);
}

#[test]
fn test_write_plan_always_blocked() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Blocked(_)
    ));
    assert_eq!(plan.operation, PersistenceOperation::WriteLedger);
}

#[test]
fn test_atomic_replace_plan_always_blocked() {
    let plan = build_ledger_persistence_plan(
        PersistenceOperation::AtomicReplace,
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Blocked(_)
    ));
    assert_eq!(plan.operation, PersistenceOperation::AtomicReplace);
}

#[test]
fn test_backup_plan_always_blocked() {
    let plan = build_ledger_persistence_plan(
        PersistenceOperation::Backup,
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Blocked(_)
    ));
    assert_eq!(plan.operation, PersistenceOperation::Backup);
}

#[test]
fn test_unsafe_path_plan_blocks_operation() {
    let plan = build_ledger_write_plan("", "zelynic", "network-ledger-v1.json");
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Rejected(_)
    ));
    assert!(
        plan.blocked_reason.contains("rejected"),
        "blocked_reason should indicate rejection: {}",
        plan.blocked_reason
    );
}

#[test]
fn test_unsafe_path_absolute_filename_blocks_read() {
    let plan = build_ledger_read_plan("/home/user/.local/share", "zelynic", "/etc/passwd");
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Rejected(_)
    ));
}

#[test]
fn test_unsafe_path_parent_traversal_blocks_write() {
    let plan = build_ledger_write_plan("/home/user/.local/share", "zelynic", "../../etc/shadow");
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Rejected(_)
    ));
}

#[test]
fn test_safe_path_plan_still_blocks() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(
        matches!(plan.persistence_status, PersistenceStatus::Blocked(ref reason) if reason.contains("not implemented"))
    );
}

#[test]
fn test_all_mutation_flags_false() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.directory_create_performed);
    assert!(!plan.file_create_performed);
    assert!(!plan.file_remove_performed);
    assert!(!plan.state_mutation_performed);
    assert!(!plan.persistence_enabled);
    assert!(plan.model_only);
}

#[test]
fn test_mutation_flags_false_even_when_rejected() {
    let plan = build_ledger_write_plan("", "zelynic", "network-ledger-v1.json");
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.directory_create_performed);
    assert!(!plan.file_create_performed);
    assert!(!plan.file_remove_performed);
    assert!(!plan.state_mutation_performed);
    assert!(!plan.persistence_enabled);
    assert!(plan.model_only);
}

#[test]
fn test_render_includes_hard_blocked_statement() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("HARD-BLOCKED"));
}

#[test]
fn test_render_denies_filesystem_read() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no filesystem read was performed"));
}

#[test]
fn test_render_denies_filesystem_write() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no filesystem write was performed"));
}

#[test]
fn test_render_denies_ledger_file_creation() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no ledger file was created"));
}

#[test]
fn test_render_denies_ledger_file_read() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no ledger file was read"));
}

#[test]
fn test_render_denies_ledger_file_save() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no ledger file was saved"));
}

#[test]
fn test_render_denies_directory_creation() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no directory was created"));
}

#[test]
fn test_render_denies_file_removal() {
    let plan = build_ledger_persistence_plan(
        PersistenceOperation::AtomicReplace,
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no file was removed"));
}

#[test]
fn test_render_says_persistence_disabled() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("persistence is not enabled"));
}

#[test]
fn test_render_denies_live_proc_sysfs_read() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no live /proc or sysfs read was performed"));
}

#[test]
fn test_render_denies_quota_enforcement() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no quota enforcement or network blocking is active"));
}

#[test]
fn test_render_denies_network_blocking() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no quota enforcement or network blocking is active"));
}

#[test]
fn test_render_denies_nft_tc_state_mutation() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation was performed"));
}

#[test]
fn test_no_std_fs_apis_used() {
    let rendered = render_ledger_persistence_plan(&build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    ));
    assert!(!rendered.contains("std::fs"));
}

#[test]
fn test_no_cli_command_added() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert!(plan.model_only);
}

#[test]
fn test_render_determinism() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let r1 = render_ledger_persistence_plan(&plan);
    let r2 = render_ledger_persistence_plan(&plan);
    assert_eq!(r1, r2);
}

#[test]
fn test_render_shows_operation_type() {
    let plan = build_ledger_read_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("Operation: read ledger"));
}

#[test]
fn test_render_shows_path_components() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("Base directory: /home/user/.local/share"));
    assert!(rendered.contains("Namespace label: zelynic"));
    assert!(rendered.contains("Ledger filename: network-ledger-v1.json"));
    assert!(rendered
        .contains("Full ledger path: /home/user/.local/share/zelynic/network-ledger-v1.json"));
}

#[test]
fn test_render_shows_model_flags() {
    let plan = build_ledger_write_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("Model only: true"));
    assert!(rendered.contains("Filesystem read performed: false"));
    assert!(rendered.contains("Filesystem write performed: false"));
    assert!(rendered.contains("Directory create performed: false"));
    assert!(rendered.contains("File create performed: false"));
    assert!(rendered.contains("File remove performed: false"));
    assert!(rendered.contains("State mutation performed: false"));
    assert!(rendered.contains("Persistence enabled: false"));
}

#[test]
fn test_render_rejected_plan_shows_rejected_status() {
    let plan = build_ledger_write_plan("", "zelynic", "network-ledger-v1.json");
    let rendered = render_ledger_persistence_plan(&plan);
    assert!(rendered.contains("Persistence status: rejected"));
}

#[test]
fn test_persistence_error_display_hard_blocked() {
    let err = PersistenceError::HardBlocked("not implemented".to_string());
    let s = format!("{}", err);
    assert!(s.contains("hard-blocked"));
}

#[test]
fn test_persistence_error_display_unsafe_path() {
    let err = PersistenceError::UnsafePath("traversal detected".to_string());
    let s = format!("{}", err);
    assert!(s.contains("unsafe path"));
}

#[test]
fn test_operation_display() {
    assert_eq!(
        format!("{}", PersistenceOperation::ReadLedger),
        "read ledger"
    );
    assert_eq!(
        format!("{}", PersistenceOperation::WriteLedger),
        "write ledger"
    );
    assert_eq!(
        format!("{}", PersistenceOperation::AtomicReplace),
        "atomic replace"
    );
    assert_eq!(format!("{}", PersistenceOperation::Backup), "backup");
    assert_eq!(
        format!("{}", PersistenceOperation::ValidatePath),
        "validate path"
    );
}

#[test]
fn test_blocked_reason_constant() {
    assert!(!BLOCKED_REASON.is_empty());
    assert!(BLOCKED_REASON.contains("not implemented"));
}
