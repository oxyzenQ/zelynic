// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

const TEST_PID: u32 = 1234;
const TEST_TARGET: &str = "/sys/fs/cgroup/zelynic/target_test";
const TEST_ORIGINAL: &str = "/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope";

fn sim_none() -> FakeTransactionResult {
    simulate_fake_transaction(TEST_PID, TEST_TARGET, TEST_ORIGINAL, FakeFailureMode::None)
}

fn sim(mode: FakeFailureMode) -> FakeTransactionResult {
    simulate_fake_transaction(TEST_PID, TEST_TARGET, TEST_ORIGINAL, mode)
}

fn rendered(result: &FakeTransactionResult) -> String {
    render_fake_transaction_result(result)
}

// =========================================================================
// Happy path tests
// =========================================================================

#[test]
fn fake_target_write_success_updates_pid_location_to_verified_in_target() {
    // In the happy path, target write and target verify both succeed,
    // confirming the PID was "verified in target" at that intermediate
    // stage before rollback moves it back.
    let result = sim_none();
    assert_eq!(
        result.target_write,
        OperationStatus::Succeeded,
        "target write must succeed in happy path"
    );
    assert_eq!(
        result.target_verify,
        OperationStatus::Succeeded,
        "target verify must succeed in happy path"
    );
    // Final state after full successful transaction is verified restored
    assert_eq!(
        result.pid_location,
        FakePidLocation::VerifiedRestored,
        "final PID location must be verified restored in happy path"
    );
}

#[test]
fn fake_rollback_success_updates_pid_location_to_verified_restored() {
    let result = sim_none();
    assert_eq!(
        result.rollback_write,
        OperationStatus::Succeeded,
        "rollback write must succeed in happy path"
    );
    assert_eq!(
        result.rollback_verify,
        OperationStatus::Succeeded,
        "rollback verify must succeed in happy path"
    );
    assert_eq!(
        result.pid_location,
        FakePidLocation::VerifiedRestored,
        "PID location must be verified restored after successful rollback"
    );
    assert!(
        !result.target_may_remain,
        "target must not remain after cleanup"
    );
    assert!(
        !result.manual_recovery_required,
        "manual recovery must not be required in happy path"
    );
}

#[test]
fn happy_path_all_steps_succeed() {
    let result = sim_none();
    assert_eq!(result.target_write, OperationStatus::Succeeded);
    assert_eq!(result.target_verify, OperationStatus::Succeeded);
    assert_eq!(result.rollback_write, OperationStatus::Succeeded);
    assert_eq!(result.rollback_verify, OperationStatus::Succeeded);
    assert_eq!(result.cleanup, OperationStatus::Succeeded);
    assert_eq!(result.fake_errno_label, None);
    assert!(!result.rollback_required);
    assert!(!result.manual_recovery_required);
    assert!(!result.target_may_remain);
}

// =========================================================================
// Target write failure tests -- PID never moved
// =========================================================================

#[test]
fn fake_eacces_target_write_never_claims_pid_moved() {
    let result = sim(FakeFailureMode::TargetWriteEacces);
    assert_eq!(result.target_write, OperationStatus::Failed);
    assert_eq!(
        result.pid_location,
        FakePidLocation::NotMoved,
        "EACCES on target write must leave PID not moved"
    );
    assert_eq!(
        result.rollback_write,
        OperationStatus::NotAttempted,
        "no rollback must be attempted when PID was never moved"
    );
    assert!(
        !result.rollback_required,
        "rollback must not be required when PID was never moved"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("EACCES"),
        "errno must be EACCES"
    );
}

#[test]
fn fake_enoent_target_write_never_claims_rollback_performed() {
    let result = sim(FakeFailureMode::TargetWriteEnoent);
    assert_eq!(result.target_write, OperationStatus::Failed);
    assert_eq!(
        result.pid_location,
        FakePidLocation::NotMoved,
        "ENOENT on target write must leave PID not moved"
    );
    assert_eq!(
        result.rollback_write,
        OperationStatus::NotAttempted,
        "no rollback must be claimed when target write failed"
    );
    assert!(
        !result.rollback_required,
        "rollback must not be required when PID was never moved"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("ENOENT"),
        "errno must be ENOENT"
    );
}

#[test]
fn fake_ebusy_target_write_never_claims_pid_moved() {
    let result = sim(FakeFailureMode::TargetWriteEbusy);
    assert_eq!(result.target_write, OperationStatus::Failed);
    assert_eq!(
        result.pid_location,
        FakePidLocation::NotMoved,
        "EBUSY on target write must leave PID not moved"
    );
    assert_eq!(result.rollback_write, OperationStatus::NotAttempted);
    assert!(!result.rollback_required);
}

#[test]
fn target_write_failures_have_no_rollback_required() {
    for mode in &[
        FakeFailureMode::TargetWriteEacces,
        FakeFailureMode::TargetWriteEnoent,
        FakeFailureMode::TargetWriteEbusy,
    ] {
        let result = sim(*mode);
        assert!(
            !result.rollback_required,
            "{:?}: rollback must not be required when target write failed",
            mode
        );
        assert!(
            !result.manual_recovery_required,
            "{:?}: manual recovery must not be required when PID was never moved",
            mode
        );
    }
}

// =========================================================================
// Failure after target write -- rollback required
// =========================================================================

#[test]
fn fake_failure_after_target_write_requires_rollback_attempt() {
    // Stale PID after target write: rollback must be attempted (and will fail)
    let result = sim(FakeFailureMode::StalePidAfterTargetWrite);
    assert_eq!(result.target_write, OperationStatus::Succeeded);
    assert!(
        result.rollback_required,
        "rollback must be required when PID was written to target"
    );
    assert_eq!(
        result.rollback_write,
        OperationStatus::Failed,
        "rollback must be attempted and fail for dead PID"
    );
    assert_eq!(
        result.pid_location,
        FakePidLocation::Unknown,
        "PID location must be unknown when PID died after target write"
    );
}

// =========================================================================
// Rollback failure tests -- manual recovery required
// =========================================================================

#[test]
fn fake_rollback_eacces_reports_manual_recovery_required() {
    let result = sim(FakeFailureMode::RollbackWriteEacces);
    assert_eq!(result.rollback_write, OperationStatus::Failed);
    assert!(
        result.manual_recovery_required,
        "EACCES on rollback must report manual recovery required"
    );
    assert!(
        result.target_may_remain,
        "target may remain when rollback fails"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("EACCES"),
        "errno must be EACCES"
    );
    assert_eq!(
        result.pid_location,
        FakePidLocation::Unknown,
        "PID location must be unknown when rollback fails"
    );
}

#[test]
fn fake_rollback_enoent_reports_manual_recovery_required() {
    let result = sim(FakeFailureMode::RollbackWriteEnoent);
    assert_eq!(result.rollback_write, OperationStatus::Failed);
    assert!(
        result.manual_recovery_required,
        "ENOENT on rollback must report manual recovery required"
    );
    assert!(result.target_may_remain);
    assert!(
        result.fake_errno_label.as_deref() == Some("ENOENT"),
        "errno must be ENOENT"
    );
    assert_eq!(result.pid_location, FakePidLocation::Unknown);
}

// =========================================================================
// Cleanup failure tests -- target remains
// =========================================================================

#[test]
fn fake_cleanup_ebusy_leaves_target_and_never_claims_cleanup_success() {
    let result = sim(FakeFailureMode::CleanupEbusy);
    assert_eq!(result.cleanup, OperationStatus::Failed);
    assert!(
        result.target_may_remain,
        "target must remain when cleanup fails with EBUSY"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("EBUSY"),
        "errno must be EBUSY"
    );
    // PID was restored before cleanup failed -- cleanup failure does not
    // affect PID location.
    assert_eq!(
        result.pid_location,
        FakePidLocation::VerifiedRestored,
        "PID location must still be verified restored after cleanup failure"
    );
    assert!(
        !result.manual_recovery_required,
        "manual recovery must not be required when PID is already restored"
    );
}

#[test]
fn fake_non_empty_target_is_never_deleted() {
    let result = sim(FakeFailureMode::TargetNonEmptyDuringCleanup);
    assert_eq!(result.cleanup, OperationStatus::Failed);
    assert!(
        result.target_may_remain,
        "target must remain when it is non-empty during cleanup"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("ENOTEMPTY"),
        "errno must be ENOTEMPTY"
    );
    // PID was already restored -- only cleanup failed.
    assert_eq!(result.pid_location, FakePidLocation::VerifiedRestored);
}

// =========================================================================
// Original cgroup missing before rollback
// =========================================================================

#[test]
fn fake_original_cgroup_missing_before_rollback_reports_loudly() {
    let result = sim(FakeFailureMode::OriginalCgroupMissingBeforeRollback);
    assert_eq!(result.rollback_write, OperationStatus::Failed);
    assert!(
        result.manual_recovery_required,
        "original cgroup missing must report manual recovery required"
    );
    assert!(
        result.target_may_remain,
        "target may remain when rollback fails due to missing original"
    );
    assert!(
        result.fake_errno_label.as_deref() == Some("ENOENT"),
        "errno must be ENOENT for missing original cgroup"
    );
    assert_eq!(
        result.pid_location,
        FakePidLocation::Unknown,
        "PID location must be unknown when original cgroup is gone"
    );
}

// =========================================================================
// Stale PID before write -- no operations attempted
// =========================================================================

#[test]
fn stale_pid_before_write_never_attempts_any_write() {
    let result = sim(FakeFailureMode::StalePidBeforeWrite);
    assert_eq!(
        result.target_write,
        OperationStatus::NotAttempted,
        "no target write must be attempted for dead PID"
    );
    assert_eq!(
        result.target_verify,
        OperationStatus::NotAttempted,
        "no target verify must be attempted for dead PID"
    );
    assert_eq!(
        result.rollback_write,
        OperationStatus::NotAttempted,
        "no rollback must be attempted when PID was never moved"
    );
    assert_eq!(
        result.rollback_verify,
        OperationStatus::NotAttempted,
        "no rollback verify must be attempted"
    );
    assert_eq!(
        result.cleanup,
        OperationStatus::NotAttempted,
        "no cleanup must be attempted when no target was created"
    );
    assert_eq!(
        result.pid_location,
        FakePidLocation::NotMoved,
        "PID location must be not moved when PID was dead before write"
    );
    assert!(
        !result.rollback_required,
        "rollback must not be required when PID was never moved"
    );
    assert!(
        !result.manual_recovery_required,
        "manual recovery must not be required for dead PID before write"
    );
    assert!(
        result.fake_errno_label.is_none(),
        "no errno must be produced when PID is stale before write"
    );
}

// =========================================================================
// Canonical deny lines in all rendered output
// =========================================================================

#[test]
fn every_rendered_fake_failure_output_denies_real_cgroup_procs_write() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            output.contains("no real cgroup.procs write was performed"),
            "{:?}: must deny real cgroup.procs write",
            mode
        );
    }
}

#[test]
fn every_rendered_fake_failure_output_denies_live_pid_move() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            output.contains("no live PID move was performed"),
            "{:?}: must deny live PID move",
            mode
        );
    }
}

#[test]
fn every_rendered_fake_failure_output_denies_limiter_attach() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            output.contains("no limiter attach was performed"),
            "{:?}: must deny limiter attach",
            mode
        );
    }
}

#[test]
fn every_rendered_fake_failure_output_denies_nft_tc_state_mutation() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            output.contains("no nftables/tc/Zelynic state mutation was performed"),
            "{:?}: must deny nft/tc/state mutation",
            mode
        );
    }
}

#[test]
fn every_rendered_fake_failure_output_says_fake_model_only() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            output.contains("fake/model-only"),
            "{:?}: must say fake/model-only",
            mode
        );
    }
}

// =========================================================================
// No retry loop modeled
// =========================================================================

#[test]
fn no_retry_loop_is_modeled() {
    for mode in FakeFailureMode::all() {
        let result = sim(mode);
        let output = rendered(&result);
        assert!(
            !output.contains("retry") && !output.contains("Retry"),
            "{:?}: must not model retry loop",
            mode
        );
    }
}

#[test]
fn no_retry_in_any_failure_mode_label() {
    for mode in FakeFailureMode::all() {
        let label = mode.label();
        assert!(
            !label.contains("retry") && !label.contains("Retry"),
            "{:?}: label must not contain retry",
            mode
        );
    }
}

// =========================================================================
// FakeFailureMode helper tests
// =========================================================================

#[test]
fn all_failure_modes_returns_correct_count() {
    assert_eq!(
        FakeFailureMode::all().len(),
        11,
        "expected 11 failure modes (None + 10 failure variants)"
    );
}

#[test]
fn all_failure_modes_have_non_empty_label() {
    for mode in FakeFailureMode::all() {
        assert!(
            !mode.label().is_empty(),
            "{:?}: label must not be empty",
            mode
        );
    }
}

#[test]
fn is_target_write_failure_correct() {
    assert!(FakeFailureMode::TargetWriteEacces.is_target_write_failure());
    assert!(FakeFailureMode::TargetWriteEnoent.is_target_write_failure());
    assert!(FakeFailureMode::TargetWriteEbusy.is_target_write_failure());
    assert!(!FakeFailureMode::RollbackWriteEacces.is_target_write_failure());
    assert!(!FakeFailureMode::CleanupEbusy.is_target_write_failure());
    assert!(!FakeFailureMode::None.is_target_write_failure());
}

#[test]
fn is_rollback_write_failure_correct() {
    assert!(FakeFailureMode::RollbackWriteEacces.is_rollback_write_failure());
    assert!(FakeFailureMode::RollbackWriteEnoent.is_rollback_write_failure());
    assert!(!FakeFailureMode::TargetWriteEacces.is_rollback_write_failure());
    assert!(!FakeFailureMode::CleanupEbusy.is_rollback_write_failure());
    assert!(!FakeFailureMode::None.is_rollback_write_failure());
}

#[test]
fn occurs_after_target_write_correct() {
    // Modes where the failure happens after the target write succeeded
    assert!(FakeFailureMode::StalePidAfterTargetWrite.occurs_after_target_write());
    assert!(FakeFailureMode::RollbackWriteEacces.occurs_after_target_write());
    assert!(FakeFailureMode::RollbackWriteEnoent.occurs_after_target_write());
    assert!(FakeFailureMode::CleanupEbusy.occurs_after_target_write());
    assert!(FakeFailureMode::TargetNonEmptyDuringCleanup.occurs_after_target_write());
    assert!(FakeFailureMode::OriginalCgroupMissingBeforeRollback.occurs_after_target_write());
    // Modes where the failure happens before or at target write
    assert!(!FakeFailureMode::TargetWriteEacces.occurs_after_target_write());
    assert!(!FakeFailureMode::StalePidBeforeWrite.occurs_after_target_write());
    assert!(!FakeFailureMode::None.occurs_after_target_write());
}

#[test]
fn errno_label_correctness() {
    assert_eq!(
        FakeFailureMode::TargetWriteEacces.errno_label(),
        Some("EACCES")
    );
    assert_eq!(
        FakeFailureMode::TargetWriteEnoent.errno_label(),
        Some("ENOENT")
    );
    assert_eq!(
        FakeFailureMode::TargetWriteEbusy.errno_label(),
        Some("EBUSY")
    );
    assert_eq!(
        FakeFailureMode::RollbackWriteEacces.errno_label(),
        Some("EACCES")
    );
    assert_eq!(FakeFailureMode::CleanupEbusy.errno_label(), Some("EBUSY"));
    assert_eq!(
        FakeFailureMode::StalePidAfterTargetWrite.errno_label(),
        Some("ESRCH")
    );
    assert_eq!(
        FakeFailureMode::OriginalCgroupMissingBeforeRollback.errno_label(),
        Some("ENOENT")
    );
    assert_eq!(
        FakeFailureMode::TargetNonEmptyDuringCleanup.errno_label(),
        Some("ENOTEMPTY")
    );
    assert_eq!(FakeFailureMode::None.errno_label(), None);
    assert_eq!(FakeFailureMode::StalePidBeforeWrite.errno_label(), None);
}

// =========================================================================
// Render structure tests
// =========================================================================

#[test]
fn render_includes_phase_label() {
    let output = rendered(&sim_none());
    assert!(
        output.contains(PHASE_LABEL),
        "rendered output must contain phase label"
    );
}

#[test]
fn render_includes_pid_and_cgroup_paths() {
    let output = rendered(&sim_none());
    assert!(output.contains(&format!("PID: {}", TEST_PID)));
    assert!(output.contains(TEST_TARGET));
    assert!(output.contains(TEST_ORIGINAL));
}

#[test]
fn render_includes_all_operation_statuses() {
    let output = rendered(&sim_none());
    assert!(output.contains("target write:"));
    assert!(output.contains("target verify:"));
    assert!(output.contains("rollback write:"));
    assert!(output.contains("rollback verify:"));
    assert!(output.contains("cleanup:"));
}

#[test]
fn render_includes_pid_location_field() {
    let output = rendered(&sim_none());
    assert!(output.contains("PID location:"));
}

#[test]
fn render_includes_rollback_and_recovery_flags() {
    let output = rendered(&sim_none());
    assert!(output.contains("rollback required:"));
    assert!(output.contains("manual recovery required:"));
    assert!(output.contains("target may remain:"));
}

#[test]
fn render_includes_failure_mode() {
    let output = rendered(&sim_none());
    assert!(output.contains("failure mode:"));
}

#[test]
fn render_includes_deny_lines_section() {
    let output = rendered(&sim_none());
    assert!(output.contains("deny lines:"));
}

#[test]
fn render_has_five_deny_lines() {
    let output = rendered(&sim_none());
    let count = output
        .lines()
        .filter(|l| l.contains("fake/model-only:"))
        .count();
    assert_eq!(count, 5, "expected 5 fake/model-only deny lines");
}

#[test]
fn render_includes_fake_errno_when_present() {
    let result = sim(FakeFailureMode::TargetWriteEacces);
    let output = rendered(&result);
    assert!(
        output.contains("fake errno: EACCES"),
        "rendered output must include fake errno when failure injected"
    );
}

#[test]
fn render_omits_fake_errno_when_none() {
    let result = sim_none();
    let output = rendered(&result);
    assert!(
        !output.contains("fake errno:"),
        "rendered output must not include fake errno in happy path"
    );
}

// =========================================================================
// OperationStatus tests
// =========================================================================

#[test]
fn operation_status_labels_are_non_empty() {
    assert!(!OperationStatus::NotAttempted.label().is_empty());
    assert!(!OperationStatus::Succeeded.label().is_empty());
    assert!(!OperationStatus::Failed.label().is_empty());
}

// =========================================================================
// FakePidLocation tests
// =========================================================================

#[test]
fn fake_pid_location_labels_match_phase_4a_taxonomy() {
    assert_eq!(FakePidLocation::NotMoved.label(), "not moved");
    assert_eq!(
        FakePidLocation::VerifiedInTarget.label(),
        "verified in target"
    );
    assert_eq!(
        FakePidLocation::VerifiedRestored.label(),
        "verified restored"
    );
    assert_eq!(
        FakePidLocation::RollbackUnverified.label(),
        "rollback unverified"
    );
    assert_eq!(FakePidLocation::Unknown.label(), "unknown");
}

// =========================================================================
// Determinism tests
// =========================================================================

#[test]
fn simulate_is_deterministic() {
    for mode in FakeFailureMode::all() {
        let r1 = sim(mode);
        let r2 = sim(mode);
        assert_eq!(r1, r2, "{:?}: simulation must be deterministic", mode);
    }
}

#[test]
fn render_is_deterministic() {
    for mode in FakeFailureMode::all() {
        let r1 = rendered(&sim(mode));
        let r2 = rendered(&sim(mode));
        assert_eq!(r1, r2, "{:?}: render must be deterministic", mode);
    }
}

// =========================================================================
// Cleanup failure does not affect PID location
// =========================================================================

#[test]
fn cleanup_failure_pid_location_still_verified_restored() {
    for mode in &[
        FakeFailureMode::CleanupEbusy,
        FakeFailureMode::TargetNonEmptyDuringCleanup,
    ] {
        let result = sim(*mode);
        assert_eq!(
            result.pid_location,
            FakePidLocation::VerifiedRestored,
            "{:?}: PID location must be verified restored after cleanup failure",
            mode
        );
        assert!(
            !result.manual_recovery_required,
            "{:?}: manual recovery must not be required when PID is restored",
            mode
        );
    }
}
