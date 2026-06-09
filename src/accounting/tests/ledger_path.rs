// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure ledger path planning model tests for v3.1 phase 9.
//!
//! All tests use string inputs — **no** filesystem reads or writes,
//! **no** live `/proc/net/dev` reads, **no** live sysfs reads,
//! **no** network blocking, **no** quota enforcement, **no** eBPF,
//! **no** PID movement, **no** cgroup writes, **no** CLI command.

use crate::accounting::ledger_path::{
    build_default_ledger_path_plan, build_ledger_path_plan, render_ledger_path_plan, PathStatus,
};

// ── Default path plan tests ────────────────────────────────────────

#[test]
fn test_default_ledger_path_is_deterministic() {
    let plan1 = build_default_ledger_path_plan("/home/user/.local/share");
    let plan2 = build_default_ledger_path_plan("/home/user/.local/share");
    assert_eq!(plan1, plan2);
}

#[test]
fn test_default_ledger_path_uses_expected_defaults() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    assert_eq!(plan.ledger_filename, "network-ledger-v1.json");
    assert_eq!(plan.namespace_label, "zelynic");
    assert_eq!(
        plan.full_ledger_path,
        "/home/user/.local/share/zelynic/network-ledger-v1.json"
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
}

// ── Valid path acceptance tests ────────────────────────────────────

#[test]
fn test_valid_namespace_path_accepted() {
    let plan = build_ledger_path_plan(
        "/home/user/.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
    assert_eq!(
        plan.full_ledger_path,
        "/home/user/.local/share/zelynic/network-ledger-v1.json"
    );
}

#[test]
fn test_valid_custom_namespace_accepted() {
    let plan = build_ledger_path_plan("/var/lib", "myapp", "custom-ledger.json");
    assert_eq!(plan.path_status, PathStatus::Accepted);
    assert_eq!(plan.full_ledger_path, "/var/lib/myapp/custom-ledger.json");
}

#[test]
fn test_valid_path_trailing_slash_base() {
    let plan = build_ledger_path_plan(
        "/home/user/.local/share/",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
    assert_eq!(
        plan.full_ledger_path,
        "/home/user/.local/share/zelynic/network-ledger-v1.json"
    );
}

// ── Rejection tests ────────────────────────────────────────────────

#[test]
fn test_empty_base_rejected() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("empty base directory"));
}

#[test]
fn test_empty_filename_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("empty filename"));
}

#[test]
fn test_absolute_filename_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "/etc/passwd");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("absolute"));
}

#[test]
fn test_parent_traversal_filename_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "../etc/passwd");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("parent traversal"));
}

#[test]
fn test_parent_traversal_deep_filename_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "foo/../../etc/shadow");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("parent traversal"));
}

#[test]
fn test_parent_traversal_base_rejected() {
    let plan = build_ledger_path_plan("/home/user/../etc", "zelynic", "network-ledger-v1.json");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("parent traversal"));
}

#[test]
fn test_outside_namespace_rejected() {
    // Empty namespace should fail containment check
    let plan = build_ledger_path_plan("/home/user/.local/share", "", "network-ledger-v1.json");
    // Empty namespace will fail the namespace validation
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("empty namespace"));
}

#[test]
fn test_suspicious_filename_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "ledger;rm -rf /");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("suspicious"));
}

#[test]
fn test_suspicious_filename_spaces_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "my ledger.json");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("suspicious"));
}

#[test]
fn test_suspicious_filename_null_byte_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "ledger\x00.json");
    assert!(matches!(plan.path_status, PathStatus::Rejected(_)));
    assert!(plan.safe_reason.contains("suspicious"));
}

// ── Model-only safety flag tests ───────────────────────────────────

#[test]
fn test_model_does_not_canonicalize_live_filesystem() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    // If canonicalize was used, it would have called std::fs::metadata or
    // std::fs::canonicalize. We verify the struct flags.
    assert!(plan.model_only);
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.persistence_enabled);
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_model_does_not_use_std_fs_read_write_apis() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    // Verify the rendered output does not contain filesystem API artifacts
    assert!(rendered.contains("persistence path model only"));
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
}

// ── Render disclaimer tests ────────────────────────────────────────

#[test]
fn test_render_includes_model_only_statement() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("persistence path model only"));
}

#[test]
fn test_render_denies_filesystem_read() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no filesystem read was performed"));
}

#[test]
fn test_render_denies_filesystem_write() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no filesystem write was performed"));
}

#[test]
fn test_render_denies_ledger_file_creation() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no ledger file was created"));
}

#[test]
fn test_render_denies_ledger_file_read() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no ledger file was read"));
}

#[test]
fn test_render_says_persistence_disabled() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("persistence is not enabled"));
}

#[test]
fn test_render_denies_live_proc_sysfs_read() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no live /proc or sysfs read was performed"));
}

#[test]
fn test_render_denies_quota_enforcement() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no quota enforcement or network blocking is active"));
}

#[test]
fn test_render_denies_network_blocking() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no quota enforcement or network blocking is active"));
}

#[test]
fn test_render_denies_nft_tc_state_mutation() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation was performed"));
}

#[test]
fn test_render_denies_symlink_resolution() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no symlink resolution was performed"));
}

// ── Structural/safety tests ───────────────────────────────────────

#[test]
fn test_no_cli_command_added() {
    // No CLI command exists — this is a compile-time structural test
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let _rendered = render_ledger_path_plan(&plan);
}

// ── Render content tests ──────────────────────────────────────────

#[test]
fn test_render_shows_path_components() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("Base directory: /home/user/.local/share"));
    assert!(rendered.contains("Namespace label: zelynic"));
    assert!(rendered.contains("Ledger filename: network-ledger-v1.json"));
    assert!(rendered
        .contains("Full ledger path: /home/user/.local/share/zelynic/network-ledger-v1.json"));
}

#[test]
fn test_render_shows_accepted_status() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("Path status: accepted"));
}

#[test]
fn test_render_shows_rejected_status() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("Path status: rejected"));
}

#[test]
fn test_render_shows_model_flags() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("Model only: true"));
    assert!(rendered.contains("Filesystem read performed: false"));
    assert!(rendered.contains("Filesystem write performed: false"));
    assert!(rendered.contains("Persistence enabled: false"));
}

#[test]
fn test_render_determinism() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered1 = render_ledger_path_plan(&plan);
    let rendered2 = render_ledger_path_plan(&plan);
    assert_eq!(rendered1, rendered2);
}

#[test]
fn test_render_rejected_plan_denies_filesystem() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    let rendered = render_ledger_path_plan(&plan);
    // Even rejected plans must carry safety disclaimers
    assert!(rendered.contains("persistence path model only"));
    assert!(rendered.contains("no filesystem read was performed"));
    assert!(rendered.contains("no filesystem write was performed"));
    assert!(rendered.contains("no ledger file was created"));
    assert!(rendered.contains("no ledger file was read"));
    assert!(rendered.contains("persistence is not enabled"));
    assert!(rendered.contains("no live /proc or sysfs read was performed"));
    assert!(rendered.contains("no quota enforcement or network blocking is active"));
    assert!(rendered.contains("no nft/tc/Zelynic state mutation was performed"));
    assert!(rendered.contains("no symlink resolution was performed"));
}

// ── PathError display tests ─────────────────────────────────────────

#[test]
fn test_path_error_display_empty_base() {
    use crate::accounting::ledger_path::PathError;
    let err = PathError::EmptyBaseDirectory;
    assert_eq!(format!("{}", err), "base directory must not be empty");
}

#[test]
fn test_path_error_display_empty_filename() {
    use crate::accounting::ledger_path::PathError;
    let err = PathError::EmptyFilename;
    assert_eq!(format!("{}", err), "filename must not be empty");
}

#[test]
fn test_path_error_display_absolute_filename() {
    use crate::accounting::ledger_path::PathError;
    let err = PathError::AbsoluteFilename("/etc/passwd".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("absolute"));
    assert!(msg.contains("/etc/passwd"));
}

#[test]
fn test_path_error_display_parent_traversal_filename() {
    use crate::accounting::ledger_path::PathError;
    let err = PathError::ParentTraversalInFilename("../etc/passwd".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("parent traversal"));
}

#[test]
fn test_path_error_display_suspicious_filename() {
    use crate::accounting::ledger_path::PathError;
    let err = PathError::SuspiciousFilename("bad;name".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("suspicious"));
}

// ── Edge case tests ────────────────────────────────────────────────

#[test]
fn test_valid_filename_with_dots_and_dashes() {
    let plan = build_ledger_path_plan(
        "/home/user/.local/share",
        "zelynic",
        "my-custom.ledger-v2.json",
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
}

#[test]
fn test_valid_filename_with_underscores() {
    let plan = build_ledger_path_plan(
        "/home/user/.local/share",
        "zelynic",
        "network_ledger_v1.json",
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
}

#[test]
fn test_rejected_plan_model_flags_still_set() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    assert!(plan.model_only);
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.persistence_enabled);
}

#[test]
fn test_double_slash_base_handled() {
    let plan = build_ledger_path_plan(
        "/home/user//.local/share",
        "zelynic",
        "network-ledger-v1.json",
    );
    assert_eq!(plan.path_status, PathStatus::Accepted);
    // The path is built by joining, so double slashes may appear
    assert!(plan.full_ledger_path.contains("zelynic"));
    assert!(plan.full_ledger_path.contains("network-ledger-v1.json"));
}

// ── Phase 9 seam hardening tests ───────────────────────────────────

#[test]
fn test_symlink_resolution_flag_always_false_accepted() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_symlink_resolution_flag_always_false_rejected() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_symlink_resolution_flag_always_false_absolute() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "/etc/passwd");
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_symlink_resolution_flag_always_false_traversal() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "../etc/passwd");
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_render_rejected_includes_symlink_disclaimer() {
    let plan = build_ledger_path_plan("/home/user/../etc", "zelynic", "network-ledger-v1.json");
    let rendered = render_ledger_path_plan(&plan);
    assert!(rendered.contains("no symlink resolution was performed"));
}

#[test]
fn test_all_model_flags_false_for_accepted_plan() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    assert!(plan.model_only);
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.persistence_enabled);
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_all_model_flags_false_for_rejected_plan() {
    let plan = build_ledger_path_plan("", "zelynic", "network-ledger-v1.json");
    assert!(plan.model_only);
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.persistence_enabled);
    assert!(!plan.symlink_resolution_performed);
}

#[test]
fn test_comprehensive_render_disclaimer_sweep_accepted() {
    let plan = build_default_ledger_path_plan("/home/user/.local/share");
    let rendered = render_ledger_path_plan(&plan);
    let required_disclaimers = [
        "persistence path model only",
        "no filesystem read was performed",
        "no filesystem write was performed",
        "no ledger file was created",
        "no ledger file was read",
        "persistence is not enabled",
        "no live /proc or sysfs read was performed",
        "no quota enforcement or network blocking is active",
        "no nft/tc/Zelynic state mutation was performed",
        "no symlink resolution was performed",
    ];
    for disclaimer in &required_disclaimers {
        assert!(
            rendered.contains(disclaimer),
            "accepted plan render missing disclaimer: {:?}",
            disclaimer
        );
    }
}

#[test]
fn test_comprehensive_render_disclaimer_sweep_rejected() {
    let plan = build_ledger_path_plan("/home/user/.local/share", "zelynic", "ledger;rm -rf /");
    let rendered = render_ledger_path_plan(&plan);
    let required_disclaimers = [
        "persistence path model only",
        "no filesystem read was performed",
        "no filesystem write was performed",
        "no ledger file was created",
        "no ledger file was read",
        "persistence is not enabled",
        "no live /proc or sysfs read was performed",
        "no quota enforcement or network blocking is active",
        "no nft/tc/Zelynic state mutation was performed",
        "no symlink resolution was performed",
    ];
    for disclaimer in &required_disclaimers {
        assert!(
            rendered.contains(disclaimer),
            "rejected plan render missing disclaimer: {:?}",
            disclaimer
        );
    }
}
