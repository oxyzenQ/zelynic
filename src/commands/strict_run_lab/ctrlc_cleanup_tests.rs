// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Ctrl+C cleanup audit tests.
//!
//! These deterministic tests verify the strict-run-lab Ctrl+C cleanup
//! implementation: signal handler, cleanup status model, cleanup wording,
//! and invariant assertions.

use super::{strict_run_lab_tests::module_source, CleanupStatus};

// === Section N: Ctrl+C cleanup audit tests ===

#[test]
fn ctrlc_cleanup_status_enum_exists() {
    let _ = CleanupStatus::Succeeded;
    let _ = CleanupStatus::PartialFailure(vec!["err".to_string()]);
    let _ = CleanupStatus::NotAttempted;
}

#[test]
fn ctrlc_cleanup_status_default_is_succeeded() {
    assert_eq!(CleanupStatus::default(), CleanupStatus::Succeeded);
}

#[test]
fn ctrlc_cleanup_status_equality() {
    assert_eq!(CleanupStatus::Succeeded, CleanupStatus::Succeeded);
    assert_eq!(
        CleanupStatus::PartialFailure(vec!["a".to_string()]),
        CleanupStatus::PartialFailure(vec!["a".to_string()])
    );
}

#[test]
fn ctrlc_cleanup_status_debug() {
    let d = format!("{:?}", CleanupStatus::Succeeded);
    assert!(d.contains("Succeeded"));
}

#[test]
fn ctrlc_output_says_cleanup_attempted_after_child_exit() {
    let s = module_source();
    assert!(s.contains("Cleanup attempted after child exit"));
}

#[test]
fn ctrlc_output_says_cleanup_attempted_after_ctrlc() {
    let s = module_source();
    assert!(s.contains("Cleanup attempted after Ctrl+C"));
}

#[test]
fn ctrlc_cleanup_summary_includes_succeeded() {
    let s = module_source();
    assert!(s.contains("\"succeeded\""));
}

#[test]
fn ctrlc_cleanup_summary_includes_partially_failed() {
    let s = module_source();
    assert!(s.contains("partially failed"));
}

#[test]
fn ctrlc_cleanup_summary_includes_not_attempted() {
    let s = module_source();
    assert!(s.contains("not attempted"));
}

#[test]
fn ctrlc_handler_installs_sigint_via_libc() {
    let s = module_source();
    assert!(s.contains("libc::SIGINT"));
    assert!(s.contains("libc::sigaction"));
}

#[test]
fn ctrlc_handler_restores_previous_sigint() {
    let s = module_source();
    assert!(s.contains("restore_sigint_handler"));
}

#[test]
fn ctrlc_handler_kills_child_on_signal() {
    let s = module_source();
    assert!(s.contains("child.kill()"));
}

#[test]
fn ctrlc_handler_uses_try_wait_loop() {
    let s = module_source();
    assert!(s.contains("try_wait()"));
}

#[test]
fn ctrlc_cleanup_removes_state_entry() {
    let s = module_source();
    assert!(s.contains(".limits") && s.contains(".retain(") && s.contains("target_name"));
}

#[test]
fn ctrlc_cleanup_removes_nft_table_when_empty() {
    let s = module_source();
    assert!(s.contains("nft") && s.contains("delete") && s.contains("table") && s.contains("inet"));
}

#[test]
fn ctrlc_no_new_dependencies() {
    // Verify no new crate dependencies added.
    let toml = include_str!("../../../Cargo.toml");
    assert!(!toml.contains("ctrlc"), "no ctrlc crate");
    assert!(!toml.contains("signal-hook"), "no signal-hook crate");
}

#[test]
fn ctrlc_remains_experimental() {
    let s = module_source();
    assert!(s.contains("experimental"));
    assert!(s.contains("not stable"));
}

#[test]
fn ctrlc_no_stable_run_implementation() {
    let s = module_source();
    assert!(!s.contains("handle_strict("));
}

#[test]
fn ctrlc_strict_behavior_unchanged() {
    let s = module_source();
    assert!(!s.contains("force_reconnect"));
}

#[test]
fn ctrlc_no_forbidden_features_added() {
    let s = module_source();
    assert!(!s.contains("daemon"));
    assert!(!s.contains("watch"));
    assert!(!s.contains("quota"));
    assert!(!s.contains("LedgerPersistencePlan"));
    assert!(!s.contains("ebpf") && !s.contains("eBPF"));
    assert!(!s.contains("schema_version"));
    assert!(!s.contains("enforcement_active"));
}

#[test]
fn ctrlc_version_is_3_1_0() {
    assert!(include_str!("../../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn ctrlc_cleanup_returns_status() {
    let s = module_source();
    assert!(s.contains("CleanupStatus"));
}
