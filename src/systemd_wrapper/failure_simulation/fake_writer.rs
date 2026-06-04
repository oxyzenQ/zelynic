// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Hard safety boundary: no live PID move, no real cgroup.procs write,
//! no limiter attach, no nftables/tc/Zelynic state mutation, no persistent
//! state write. All writer simulation is pure fake/in-memory/test-only/model-only.

#![allow(dead_code)]
//!
//! Fake Writer Injection Harness (phase 4c): simulates cgroup.procs write
//! outcomes and transaction failures without touching the real system.
//!
//! This module models fake write operations on cgroup.procs files and their
//! outcomes, allowing injection of specific failure modes (EACCES, ENOENT,
//! EBUSY, stale PID, missing cgroup, non-empty cgroup) at precise transaction
//! step boundaries.
//!
//! **Hard safety boundary**: This module performs no live PID move, no real
//! `cgroup.procs` write, no limiter attach, no nftables/tc/Zelynic state
//! mutation, and no persistent state write. All simulation is pure
//! fake/in-memory/test-only/model-only.

use crate::systemd_wrapper::render::push_line;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const PHASE_LABEL: &str = "4c fake-writer injection harness";

/// Canonical deny lines that MUST appear in every rendered fake writer output.
/// These lines deny any real system mutation and clearly label the output
/// as simulation-only.
const FAKE_WRITER_DENY_LINES: &[&str] = &[
    "fake/model-only: no real cgroup.procs write was performed",
    "fake/model-only: no live PID move was performed",
    "fake/model-only: no limiter attach was performed",
    "fake/model-only: no nftables/tc/Zelynic state mutation was performed",
    "fake/model-only: no persistent state write was performed",
];

// ---------------------------------------------------------------------------
// Fake failure mode
// ---------------------------------------------------------------------------

/// Injectable fake failure modes for the fake writer transaction.
///
/// Each variant represents a specific point in the transaction where a
/// failure can be injected, along with the expected errno or condition.
/// The `None` variant represents the happy path where all operations succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FakeFailureMode {
    /// No failure injection — all operations succeed.
    None,

    /// EACCES on target cgroup.procs write (step 5).
    /// The kernel denies permission to write the PID to the target cgroup.
    TargetWriteEacces,

    /// ENOENT on target cgroup.procs write (step 5).
    /// The target cgroup directory disappeared between creation and write.
    TargetWriteEnoent,

    /// EBUSY on target cgroup.procs write (step 5).
    /// The cgroup subsystem is locked by another process.
    TargetWriteEbusy,

    /// EACCES on rollback cgroup.procs write (step 8).
    /// Permission denied when writing the PID back to the original cgroup.
    RollbackWriteEacces,

    /// ENOENT on rollback cgroup.procs write (step 8).
    /// The original cgroup was removed between capture and rollback.
    RollbackWriteEnoent,

    /// EBUSY on target cleanup (step 10).
    /// The cgroup subsystem has internal references to the target.
    CleanupEbusy,

    /// PID is stale/dead before any write is attempted.
    /// The PID exited between gate re-evaluation and the move moment.
    StalePidBeforeWrite,

    /// PID is stale/dead after target write succeeds.
    /// The PID exits between step 5 (move write) and step 6 (verification).
    StalePidAfterTargetWrite,

    /// Original cgroup missing before rollback.
    /// The original cgroup directory was removed between capture and step 8.
    OriginalCgroupMissingBeforeRollback,

    /// Target cgroup unexpectedly non-empty during cleanup.
    /// An unexpected PID appeared in the target between rollback and cleanup.
    TargetNonEmptyDuringCleanup,
}

impl FakeFailureMode {
    /// Returns the human-readable label for the failure mode.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TargetWriteEacces => "target write EACCES",
            Self::TargetWriteEnoent => "target write ENOENT",
            Self::TargetWriteEbusy => "target write EBUSY",
            Self::RollbackWriteEacces => "rollback write EACCES",
            Self::RollbackWriteEnoent => "rollback write ENOENT",
            Self::CleanupEbusy => "cleanup EBUSY",
            Self::StalePidBeforeWrite => "stale PID before write",
            Self::StalePidAfterTargetWrite => "stale PID after target write",
            Self::OriginalCgroupMissingBeforeRollback => {
                "original cgroup missing before rollback"
            }
            Self::TargetNonEmptyDuringCleanup => "target non-empty during cleanup",
        }
    }

    /// Returns the fake errno label if applicable, or None for modes that
    /// do not produce a specific errno (e.g., None, StalePidBeforeWrite).
    pub(crate) fn errno_label(&self) -> Option<&'static str> {
        match self {
            Self::TargetWriteEacces | Self::RollbackWriteEacces => Some("EACCES"),
            Self::TargetWriteEnoent | Self::RollbackWriteEnoent => Some("ENOENT"),
            Self::TargetWriteEbusy | Self::CleanupEbusy => Some("EBUSY"),
            Self::StalePidAfterTargetWrite => Some("ESRCH"),
            Self::OriginalCgroupMissingBeforeRollback => Some("ENOENT"),
            Self::TargetNonEmptyDuringCleanup => Some("ENOTEMPTY"),
            Self::None | Self::StalePidBeforeWrite => None,
        }
    }

    /// Returns all failure modes in canonical order for iteration in tests.
    pub(crate) fn all() -> Vec<FakeFailureMode> {
        vec![
            Self::None,
            Self::TargetWriteEacces,
            Self::TargetWriteEnoent,
            Self::TargetWriteEbusy,
            Self::RollbackWriteEacces,
            Self::RollbackWriteEnoent,
            Self::CleanupEbusy,
            Self::StalePidBeforeWrite,
            Self::StalePidAfterTargetWrite,
            Self::OriginalCgroupMissingBeforeRollback,
            Self::TargetNonEmptyDuringCleanup,
        ]
    }

    /// Returns true if this failure mode injects a fault at the target write
    /// step (step 5), meaning the PID was never moved.
    pub(crate) fn is_target_write_failure(&self) -> bool {
        matches!(
            self,
            Self::TargetWriteEacces | Self::TargetWriteEnoent | Self::TargetWriteEbusy
        )
    }

    /// Returns true if this failure mode injects a fault at the rollback write
    /// step (step 8), meaning the PID may be stranded in the target.
    pub(crate) fn is_rollback_write_failure(&self) -> bool {
        matches!(
            self,
            Self::RollbackWriteEacces | Self::RollbackWriteEnoent
        )
    }

    /// Returns true if this failure mode occurs after the target write has
    /// succeeded, meaning rollback MUST be attempted.
    pub(crate) fn occurs_after_target_write(&self) -> bool {
        matches!(
            self,
            Self::StalePidAfterTargetWrite
                | Self::RollbackWriteEacces
                | Self::RollbackWriteEnoent
                | Self::CleanupEbusy
                | Self::TargetNonEmptyDuringCleanup
                | Self::OriginalCgroupMissingBeforeRollback
        )
    }
}

// ---------------------------------------------------------------------------
// Operation status
// ---------------------------------------------------------------------------

/// Status of a single fake operation within the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OperationStatus {
    /// The operation was not attempted (e.g., aborted before this step).
    NotAttempted,
    /// The fake operation was performed and succeeded.
    Succeeded,
    /// The fake operation was performed and failed.
    Failed,
}

impl OperationStatus {
    /// Returns the canonical label string for rendering.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NotAttempted => "not attempted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Fake PID location
// ---------------------------------------------------------------------------

/// PID location after a fake writer transaction, matching the phase 4a
/// taxonomy from the failure simulation design document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FakePidLocation {
    /// PID was never written to any cgroup.procs (failure before step 5).
    NotMoved,
    /// Move succeeded and verification confirmed PID in target (step 6).
    VerifiedInTarget,
    /// Rollback succeeded and verification confirmed PID in original (step 9).
    VerifiedRestored,
    /// Rollback write completed but verification was skipped or failed.
    RollbackUnverified,
    /// Move may have occurred but PID location cannot be determined.
    Unknown,
}

impl FakePidLocation {
    /// Returns the canonical label string for rendering.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NotMoved => "not moved",
            Self::VerifiedInTarget => "verified in target",
            Self::VerifiedRestored => "verified restored",
            Self::RollbackUnverified => "rollback unverified",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Fake transaction result
// ---------------------------------------------------------------------------

/// Complete result of a simulated fake writer transaction.
///
/// This struct captures every aspect of the simulated transaction: which
/// operations were attempted, whether they succeeded or failed, what errno
/// was produced, where the PID ended up, and whether cleanup/recovery is
/// needed. All values are determined by pure logic — no real I/O occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeTransactionResult {
    /// PID being simulated.
    pub pid: u32,
    /// Fake target cgroup path.
    pub target_cgroup: String,
    /// Fake original cgroup path.
    pub original_cgroup: String,
    /// Failure mode that was injected for this transaction.
    pub failure_mode: FakeFailureMode,
    /// Whether the target cgroup.procs write was attempted.
    pub target_write: OperationStatus,
    /// Whether the target verification (step 6) was attempted.
    pub target_verify: OperationStatus,
    /// Whether the rollback cgroup.procs write was attempted.
    pub rollback_write: OperationStatus,
    /// Whether the rollback verification (step 9) was attempted.
    pub rollback_verify: OperationStatus,
    /// Whether the target cleanup (step 10) was attempted.
    pub cleanup: OperationStatus,
    /// Fake errno label if a failure was injected (e.g., "EACCES").
    pub fake_errno_label: Option<String>,
    /// PID location after the simulated transaction.
    pub pid_location: FakePidLocation,
    /// Whether rollback was required (PID was moved to target).
    pub rollback_required: bool,
    /// Whether manual recovery is required (rollback failed or PID stranded).
    pub manual_recovery_required: bool,
    /// Whether the target cgroup may remain after the transaction.
    pub target_may_remain: bool,
}

// ---------------------------------------------------------------------------
// Pure function: simulate_fake_transaction
// ---------------------------------------------------------------------------

/// Simulates a fake writer transaction with an optional failure injection.
///
/// This function models the following transaction steps from the phase 3a
/// design document:
///
/// 1. PID liveness check — stale before write → abort
/// 2. Write PID to target cgroup.procs (step 5)
/// 3. Verify PID in target (step 6)
/// 4. Write PID back to original cgroup.procs (step 8, rollback)
/// 5. Verify PID restored (step 9)
/// 6. Cleanup target cgroup (step 10)
///
/// The `failure_mode` parameter determines at which step a failure occurs
/// and what errno or condition is produced. When `FakeFailureMode::None`
/// is used, all operations succeed and the PID is restored to its original
/// cgroup.
///
/// **No retry loops are modeled.** Each write is attempted at most once.
/// **No real I/O occurs.** All operations are pure in-memory simulation.
pub(crate) fn simulate_fake_transaction(
    pid: u32,
    target_cgroup: &str,
    original_cgroup: &str,
    failure_mode: FakeFailureMode,
) -> FakeTransactionResult {
    let mut result = FakeTransactionResult {
        pid,
        target_cgroup: target_cgroup.to_string(),
        original_cgroup: original_cgroup.to_string(),
        failure_mode,
        target_write: OperationStatus::NotAttempted,
        target_verify: OperationStatus::NotAttempted,
        rollback_write: OperationStatus::NotAttempted,
        rollback_verify: OperationStatus::NotAttempted,
        cleanup: OperationStatus::NotAttempted,
        fake_errno_label: None,
        pid_location: FakePidLocation::NotMoved,
        rollback_required: false,
        manual_recovery_required: false,
        target_may_remain: false,
    };

    // -------------------------------------------------------------------
    // Step 1: PID liveness check
    // If the PID is stale/dead before any write, abort cleanly.
    // No rollback needed. No cleanup needed. PID location: not moved.
    // -------------------------------------------------------------------
    if failure_mode == FakeFailureMode::StalePidBeforeWrite {
        result.pid_location = FakePidLocation::NotMoved;
        return result;
    }

    // -------------------------------------------------------------------
    // Step 2: Write PID to target cgroup.procs (step 5)
    // If the write fails, the PID was never moved. No rollback needed.
    // Cleanup may be attempted (target cgroup exists but is empty).
    // -------------------------------------------------------------------
    if failure_mode.is_target_write_failure() {
        result.target_write = OperationStatus::Failed;
        result.fake_errno_label = failure_mode.errno_label().map(str::to_string);
        result.pid_location = FakePidLocation::NotMoved;
        // Target cgroup exists (was created in step 4) but is empty.
        // Cleanup is attempted and succeeds.
        result.cleanup = OperationStatus::Succeeded;
        return result;
    }

    // Target write succeeds.
    result.target_write = OperationStatus::Succeeded;

    // -------------------------------------------------------------------
    // Step 3: Verify PID in target (step 6)
    // If the PID died after the target write, verification is skipped.
    // The PID may be in the target or may have been reaped by the kernel.
    // Rollback MUST be attempted, but will likely fail (ESRCH for reaped).
    // -------------------------------------------------------------------
    if failure_mode == FakeFailureMode::StalePidAfterTargetWrite {
        result.target_verify = OperationStatus::NotAttempted;
        result.pid_location = FakePidLocation::Unknown;
        result.rollback_required = true;
        // Attempt rollback — fails because PID is dead (ESRCH).
        // Single attempt only; no retry.
        result.rollback_write = OperationStatus::Failed;
        result.fake_errno_label = Some("ESRCH".to_string());
        result.manual_recovery_required = true;
        result.target_may_remain = true;
        return result;
    }

    // Target verification succeeds. PID is confirmed in target.
    result.target_verify = OperationStatus::Succeeded;
    result.pid_location = FakePidLocation::VerifiedInTarget;
    result.rollback_required = true;

    // -------------------------------------------------------------------
    // Pre-rollback check: original cgroup still exists?
    // If the original cgroup disappeared, the rollback write will fail
    // with ENOENT. This is reported loudly per phase 4a rule 3.
    // -------------------------------------------------------------------
    if failure_mode == FakeFailureMode::OriginalCgroupMissingBeforeRollback {
        result.rollback_write = OperationStatus::Failed;
        result.fake_errno_label = Some("ENOENT".to_string());
        result.pid_location = FakePidLocation::Unknown;
        result.manual_recovery_required = true;
        result.target_may_remain = true;
        return result;
    }

    // -------------------------------------------------------------------
    // Step 4: Write PID back to original cgroup.procs (step 8, rollback)
    // If the rollback write fails, the PID may be stranded in the target.
    // Manual recovery may be required. No retry.
    // -------------------------------------------------------------------
    if failure_mode.is_rollback_write_failure() {
        result.rollback_write = OperationStatus::Failed;
        result.fake_errno_label = failure_mode.errno_label().map(str::to_string);
        result.pid_location = FakePidLocation::Unknown;
        result.manual_recovery_required = true;
        result.target_may_remain = true;
        return result;
    }

    // Rollback write succeeds.
    result.rollback_write = OperationStatus::Succeeded;

    // -------------------------------------------------------------------
    // Step 5: Verify PID restored (step 9)
    // In this model, rollback verification always succeeds when the
    // rollback write succeeds (no failure injection for this step).
    // -------------------------------------------------------------------
    result.rollback_verify = OperationStatus::Succeeded;
    result.pid_location = FakePidLocation::VerifiedRestored;
    result.rollback_required = false;

    // -------------------------------------------------------------------
    // Step 6: Cleanup target cgroup (step 10)
    // If cleanup fails (EBUSY or non-empty), the target is left in place.
    // The PID has already been restored — cleanup failure does not affect
    // PID location.
    // -------------------------------------------------------------------
    if failure_mode == FakeFailureMode::CleanupEbusy {
        result.cleanup = OperationStatus::Failed;
        result.fake_errno_label = Some("EBUSY".to_string());
        result.target_may_remain = true;
        return result;
    }

    if failure_mode == FakeFailureMode::TargetNonEmptyDuringCleanup {
        result.cleanup = OperationStatus::Failed;
        result.fake_errno_label = Some("ENOTEMPTY".to_string());
        result.target_may_remain = true;
        return result;
    }

    // No failure injection — all operations succeed.
    result.cleanup = OperationStatus::Succeeded;
    result.target_may_remain = false;

    result
}

// ---------------------------------------------------------------------------
// Pure function: render_fake_transaction_result
// ---------------------------------------------------------------------------

/// Renders a fake transaction result as structured text output suitable
/// for diagnostics and test inspection.
///
/// The rendered output includes:
/// - Phase label
/// - PID and cgroup paths
/// - Failure mode
/// - Per-step operation status
/// - Fake errno (if any)
/// - PID location
/// - Rollback / recovery / cleanup flags
/// - Canonical deny lines
pub(crate) fn render_fake_transaction_result(result: &FakeTransactionResult) -> String {
    let mut output = String::new();

    push_line(
        &mut output,
        &format!("  Fake writer transaction (phase {}):", PHASE_LABEL),
    );
    push_line(&mut output, &format!("    PID: {}", result.pid));
    push_line(
        &mut output,
        &format!("    target cgroup: {}", result.target_cgroup),
    );
    push_line(
        &mut output,
        &format!("    original cgroup: {}", result.original_cgroup),
    );
    push_line(
        &mut output,
        &format!("    failure mode: {}", result.failure_mode.label()),
    );
    push_line(
        &mut output,
        &format!("    target write: {}", result.target_write.label()),
    );
    push_line(
        &mut output,
        &format!("    target verify: {}", result.target_verify.label()),
    );
    push_line(
        &mut output,
        &format!("    rollback write: {}", result.rollback_write.label()),
    );
    push_line(
        &mut output,
        &format!("    rollback verify: {}", result.rollback_verify.label()),
    );
    push_line(
        &mut output,
        &format!("    cleanup: {}", result.cleanup.label()),
    );

    if let Some(ref errno) = result.fake_errno_label {
        push_line(&mut output, &format!("    fake errno: {}", errno));
    }

    push_line(
        &mut output,
        &format!("    PID location: {}", result.pid_location.label()),
    );
    push_line(
        &mut output,
        &format!("    rollback required: {}", result.rollback_required),
    );
    push_line(
        &mut output,
        &format!(
            "    manual recovery required: {}",
            result.manual_recovery_required
        ),
    );
    push_line(
        &mut output,
        &format!("    target may remain: {}", result.target_may_remain),
    );
    push_line(&mut output, "    deny lines:");
    for deny in FAKE_WRITER_DENY_LINES {
        push_line(&mut output, &format!("      {}", deny));
    }

    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
