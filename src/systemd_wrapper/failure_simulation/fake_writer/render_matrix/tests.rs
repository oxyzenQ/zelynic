// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

const TEST_PID: u32 = 4321;
const TEST_TARGET: &str = "/sys/fs/cgroup/zelynic/target_render";
const TEST_ORIGINAL: &str = "/sys/fs/cgroup/user.slice/user-4321.slice/session.scope";

fn matrix() -> Vec<RenderMatrixEntry> {
    build_full_render_matrix(TEST_PID, TEST_TARGET, TEST_ORIGINAL)
}

fn entry(mode: FakeFailureMode) -> RenderMatrixEntry {
    render_matrix_entry(TEST_PID, TEST_TARGET, TEST_ORIGINAL, mode)
}

fn rendered(mode: FakeFailureMode) -> String {
    entry(mode).rendered_output.clone()
}

// =========================================================================
// Matrix completeness
// =========================================================================

#[test]
fn matrix_covers_every_fake_failure_mode() {
    let m = matrix();
    assert_eq!(
        m.len(),
        FakeFailureMode::all().len(),
        "matrix must cover all failure modes"
    );
    for mode in FakeFailureMode::all() {
        assert!(
            m.iter().any(|e| e.failure_mode == mode),
            "matrix missing mode: {:?}",
            mode
        );
    }
}

// =========================================================================
// Matrix determinism
// =========================================================================

#[test]
fn matrix_is_deterministic() {
    let m1 = matrix();
    let m2 = matrix();
    assert_eq!(m1.len(), m2.len());
    for (a, b) in m1.iter().zip(m2.iter()) {
        assert_eq!(a, b, "mode {:?}", a.failure_mode);
    }
}

#[test]
fn each_entry_render_is_deterministic() {
    for mode in FakeFailureMode::all() {
        let e1 = entry(mode);
        let e2 = entry(mode);
        assert_eq!(
            e1.rendered_output, e2.rendered_output,
            "{:?}: render must be deterministic",
            mode
        );
    }
}

// =========================================================================
// Phase label
// =========================================================================

#[test]
fn every_rendered_output_includes_phase_label() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("4d"),
            "{:?}: must contain phase 4d marker",
            mode
        );
        assert!(
            output.contains("Fake writer output matrix"),
            "{:?}: must contain 'Fake writer output matrix'",
            mode
        );
    }
}

// =========================================================================
// fake/model-only statement
// =========================================================================

#[test]
fn every_rendered_output_includes_fake_model_only_statement() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("fake/model-only"),
            "{:?}: must contain 'fake/model-only' statement",
            mode
        );
    }
}

#[test]
fn happy_path_still_says_fake_only_and_does_not_imply_real_mutation() {
    let output = rendered(FakeFailureMode::None);
    assert!(output.contains("fake/model-only"));
    // Must not imply any real mutation
    assert!(
        !output.contains("real PID moved"),
        "happy path must not imply real PID move"
    );
}

// =========================================================================
// All 7 canonical deny lines
// =========================================================================

#[test]
fn every_rendered_output_includes_all_canonical_deny_lines() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        for deny in RENDER_MATRIX_DENY_LINES {
            assert!(
                output.contains(deny),
                "{:?}: must contain deny line: '{}'",
                mode,
                deny
            );
        }
    }
}

#[test]
fn every_rendered_output_denies_live_pid_move() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No live PID move was performed"),
            "{:?}: must deny live PID move",
            mode
        );
    }
}

#[test]
fn every_rendered_output_denies_real_cgroup_procs_write() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No real cgroup.procs write was performed"),
            "{:?}: must deny real cgroup.procs write",
            mode
        );
    }
}

#[test]
fn every_rendered_output_denies_limiter_attach() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No limiter attach was performed"),
            "{:?}: must deny limiter attach",
            mode
        );
    }
}

#[test]
fn every_rendered_output_denies_nft_tc_state_mutation() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No nftables, tc, or Zelynic state changes were made"),
            "{:?}: must deny nft/tc/state changes",
            mode
        );
    }
}

#[test]
fn every_rendered_output_denies_persistent_state_write() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No persistent state write was performed"),
            "{:?}: must deny persistent state write",
            mode
        );
    }
}

#[test]
fn every_rendered_output_denies_cli_path_for_live_pid_move() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("No CLI path for live PID move was enabled"),
            "{:?}: must deny CLI path for live PID move",
            mode
        );
    }
}

#[test]
fn every_rendered_output_says_fake_model_only() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("This is fake/model-only output"),
            "{:?}: must say 'This is fake/model-only output'",
            mode
        );
    }
}

// =========================================================================
// Forbidden claims
// =========================================================================

#[test]
fn every_rendered_output_avoids_forbidden_claims() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        for forbidden in FORBIDDEN_CLAIMS {
            assert!(
                !output.contains(forbidden),
                "{:?}: must not contain forbidden claim: '{}'",
                mode,
                forbidden
            );
        }
    }
}

// =========================================================================
// Fake errno label
// =========================================================================

#[test]
fn every_fake_errno_mode_renders_the_errno_label() {
    let errno_modes: Vec<FakeFailureMode> = FakeFailureMode::all()
        .into_iter()
        .filter(|m| m.errno_label().is_some())
        .collect();
    assert!(
        !errno_modes.is_empty(),
        "must have at least one mode with errno"
    );
    for mode in errno_modes {
        let output = rendered(mode);
        let errno = mode.errno_label().unwrap();
        assert!(
            output.contains(&format!("fake errno: {}", errno)),
            "{:?}: must render errno label '{}'",
            mode,
            errno
        );
    }
}

#[test]
fn modes_without_errno_do_not_render_errno_line() {
    let no_errno = [FakeFailureMode::None, FakeFailureMode::StalePidBeforeWrite];
    for mode in &no_errno {
        let output = rendered(*mode);
        assert!(
            !output.contains("fake errno:"),
            "{:?}: must not render errno line when no errno",
            mode
        );
    }
}

// =========================================================================
// Target write failures never claim rollback
// =========================================================================

#[test]
fn target_write_failures_never_claim_rollback_performed() {
    let target_failures = [
        FakeFailureMode::TargetWriteEacces,
        FakeFailureMode::TargetWriteEnoent,
        FakeFailureMode::TargetWriteEbusy,
    ];
    for mode in &target_failures {
        let e = entry(*mode);
        assert!(
            !e.rollback_required(),
            "{:?}: must not claim rollback required when PID was never moved",
            mode
        );
        assert_eq!(
            e.transaction_result.rollback_write,
            OperationStatus::NotAttempted,
            "{:?}: rollback write must not be attempted",
            mode
        );
    }
}

// =========================================================================
// Rollback failures report manual recovery
// =========================================================================

#[test]
fn rollback_failures_report_manual_recovery_required() {
    let rollback_failures = [
        FakeFailureMode::RollbackWriteEacces,
        FakeFailureMode::RollbackWriteEnoent,
    ];
    for mode in &rollback_failures {
        let e = entry(*mode);
        assert!(
            e.manual_recovery_required(),
            "{:?}: must report manual recovery required when rollback fails",
            mode
        );
        assert!(
            e.target_may_remain(),
            "{:?}: target may remain when rollback fails",
            mode
        );
    }
}

// =========================================================================
// Cleanup EBUSY reports target may remain
// =========================================================================

#[test]
fn cleanup_ebusy_reports_target_may_remain() {
    let e = entry(FakeFailureMode::CleanupEbusy);
    assert!(e.cleanup_failed(), "cleanup must have failed for EBUSY");
    assert!(
        e.target_may_remain(),
        "target must remain when cleanup fails with EBUSY"
    );
}

// =========================================================================
// Target non-empty cleanup never claims deletion
// =========================================================================

#[test]
fn target_non_empty_cleanup_never_claims_deletion() {
    let e = entry(FakeFailureMode::TargetNonEmptyDuringCleanup);
    assert!(e.cleanup_failed());
    assert!(e.target_may_remain());
    let output = rendered(FakeFailureMode::TargetNonEmptyDuringCleanup);
    // Must not claim cleanup success
    assert!(
        output.contains("cleanup: failed"),
        "non-empty cleanup must show cleanup: failed"
    );
}

// =========================================================================
// Stale PID before write
// =========================================================================

#[test]
fn stale_pid_before_write_does_not_attempt_target_write() {
    let e = entry(FakeFailureMode::StalePidBeforeWrite);
    assert_eq!(
        e.transaction_result.target_write,
        OperationStatus::NotAttempted,
        "stale PID before write must not attempt target write"
    );
    assert_eq!(
        e.transaction_result.pid_location,
        FakePidLocation::NotMoved,
        "PID location must be not moved for stale PID before write"
    );
    assert!(
        !e.rollback_required(),
        "rollback must not be required for stale PID before write"
    );
}

// =========================================================================
// Stale PID after target write requires rollback or manual recovery
// =========================================================================

#[test]
fn stale_pid_after_target_write_requires_rollback_or_manual_recovery() {
    let e = entry(FakeFailureMode::StalePidAfterTargetWrite);
    assert!(
        e.rollback_required() || e.manual_recovery_required(),
        "stale PID after target write must require rollback or manual recovery"
    );
    assert_eq!(
        e.transaction_result.target_write,
        OperationStatus::Succeeded,
        "target write must have succeeded before PID went stale"
    );
}

// =========================================================================
// PID location label in all modes
// =========================================================================

#[test]
fn render_output_for_all_modes_includes_pid_location_label() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            output.contains("PID location:"),
            "{:?}: must include PID location label",
            mode
        );
        let e = entry(mode);
        assert!(
            !e.pid_location_label().is_empty(),
            "{:?}: PID location label must not be empty",
            mode
        );
    }
}

// =========================================================================
// No retry loop
// =========================================================================

#[test]
fn no_retry_loop_is_rendered_or_modeled() {
    for mode in FakeFailureMode::all() {
        let output = rendered(mode);
        assert!(
            !output.contains("retry") && !output.contains("Retry"),
            "{:?}: must not render or model retry loop",
            mode
        );
    }
}

// =========================================================================
// Render structure: all required fields present
// =========================================================================

#[test]
fn every_entry_has_failure_mode_label() {
    for e in &matrix() {
        assert!(
            !e.failure_mode_label().is_empty(),
            "failure mode label must not be empty"
        );
    }
}

#[test]
fn every_entry_includes_transaction_details() {
    for e in &matrix() {
        let o = &e.rendered_output;
        assert!(o.contains("PID:"), "{:?}", e.failure_mode);
        assert!(o.contains("target cgroup:"), "{:?}", e.failure_mode);
        assert!(o.contains("original cgroup:"), "{:?}", e.failure_mode);
    }
}

#[test]
fn every_entry_includes_all_operation_statuses() {
    for e in &matrix() {
        let o = &e.rendered_output;
        assert!(o.contains("target write:"), "{:?}", e.failure_mode);
        assert!(o.contains("target verification:"), "{:?}", e.failure_mode);
        assert!(o.contains("rollback write:"), "{:?}", e.failure_mode);
        assert!(o.contains("rollback verification:"), "{:?}", e.failure_mode);
        assert!(o.contains("cleanup:"), "{:?}", e.failure_mode);
    }
}

#[test]
fn every_entry_includes_outcome_fields() {
    for e in &matrix() {
        let o = &e.rendered_output;
        assert!(o.contains("rollback required:"), "{:?}", e.failure_mode);
        assert!(
            o.contains("manual recovery required:"),
            "{:?}",
            e.failure_mode
        );
        assert!(o.contains("target may remain:"), "{:?}", e.failure_mode);
    }
}

#[test]
fn every_entry_includes_canonical_deny_lines_section() {
    for e in &matrix() {
        assert!(
            e.rendered_output.contains("canonical deny lines:"),
            "{:?}: must include deny lines section",
            e.failure_mode
        );
    }
}

#[test]
fn every_entry_has_exactly_seven_deny_lines() {
    for e in &matrix() {
        let count = e
            .rendered_output
            .lines()
            .filter(|l| RENDER_MATRIX_DENY_LINES.iter().any(|d| l.contains(d)))
            .count();
        assert_eq!(
            count, 7,
            "{:?}: expected 7 deny lines, got {}",
            e.failure_mode, count
        );
    }
}

// =========================================================================
// Mode-specific correctness assertions
// =========================================================================

#[test]
fn happy_path_entry_is_fully_successful() {
    let e = entry(FakeFailureMode::None);
    assert_eq!(
        e.transaction_result.target_write,
        OperationStatus::Succeeded
    );
    assert_eq!(
        e.transaction_result.target_verify,
        OperationStatus::Succeeded
    );
    assert_eq!(
        e.transaction_result.rollback_write,
        OperationStatus::Succeeded
    );
    assert_eq!(
        e.transaction_result.rollback_verify,
        OperationStatus::Succeeded
    );
    assert_eq!(e.transaction_result.cleanup, OperationStatus::Succeeded);
    assert!(!e.rollback_required());
    assert!(!e.manual_recovery_required());
    assert!(!e.target_may_remain());
    assert_eq!(
        e.transaction_result.pid_location,
        FakePidLocation::VerifiedRestored
    );
}

#[test]
fn stale_pid_before_write_all_operations_not_attempted() {
    let e = entry(FakeFailureMode::StalePidBeforeWrite);
    assert_eq!(
        e.transaction_result.target_write,
        OperationStatus::NotAttempted
    );
    assert_eq!(
        e.transaction_result.target_verify,
        OperationStatus::NotAttempted
    );
    assert_eq!(
        e.transaction_result.rollback_write,
        OperationStatus::NotAttempted
    );
    assert_eq!(
        e.transaction_result.rollback_verify,
        OperationStatus::NotAttempted
    );
    assert_eq!(e.transaction_result.cleanup, OperationStatus::NotAttempted);
}

#[test]
fn cleanup_failure_does_not_affect_pid_location() {
    for mode in &[
        FakeFailureMode::CleanupEbusy,
        FakeFailureMode::TargetNonEmptyDuringCleanup,
    ] {
        let e = entry(*mode);
        assert_eq!(
            e.transaction_result.pid_location,
            FakePidLocation::VerifiedRestored,
            "{:?}: PID must be verified restored after cleanup failure",
            mode
        );
        assert!(
            !e.manual_recovery_required(),
            "{:?}: no manual recovery when PID is restored",
            mode
        );
    }
}

#[test]
fn rollback_failure_pid_location_is_unknown() {
    for mode in &[
        FakeFailureMode::RollbackWriteEacces,
        FakeFailureMode::RollbackWriteEnoent,
        FakeFailureMode::OriginalCgroupMissingBeforeRollback,
        FakeFailureMode::StalePidAfterTargetWrite,
    ] {
        let e = entry(*mode);
        assert_eq!(
            e.transaction_result.pid_location,
            FakePidLocation::Unknown,
            "{:?}: PID location must be unknown when rollback fails",
            mode
        );
    }
}

#[test]
fn target_write_failure_pid_location_is_not_moved() {
    for mode in &[
        FakeFailureMode::TargetWriteEacces,
        FakeFailureMode::TargetWriteEnoent,
        FakeFailureMode::TargetWriteEbusy,
    ] {
        let e = entry(*mode);
        assert_eq!(
            e.transaction_result.pid_location,
            FakePidLocation::NotMoved,
            "{:?}: PID location must be not moved when target write fails",
            mode
        );
    }
}
