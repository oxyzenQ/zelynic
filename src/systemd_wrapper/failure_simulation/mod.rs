// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Hard safety boundary: no live PID move, no real cgroup.procs write,
//! no limiter attach, no nftables/tc/Zelynic state mutation, no persistent
//! state write. All simulation is pure model/fake-only.

#![allow(dead_code)]
//!
//! Failure Simulation Model: pure model for the 12 failure scenarios defined in
//! the phase 4a design document (`docs/v2.8-phase-4a-failure-simulation-design.md`).
//!
//! Phase 4b implements the design as pure Rust model code and tests. This module
//! contains:
//! - An enum for the 12 failure scenarios (F1–F12).
//! - PID location status taxonomy.
//! - Rollback decision model.
//! - Cleanup decision model.
//! - Simulation result struct with canonical deny lines.
//! - Pure functions to build the matrix, simulate each scenario, and render output.
//!
//! **Hard safety boundary**: This module performs no live PID move, no real
//! `cgroup.procs` write, no limiter attach, no nftables/tc/Zelynic state
//! mutation, and no persistent state write. All simulation is pure model/fake-only.

use super::render::push_line;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const PHASE_LABEL: &str = "4b failure-simulation model";

/// Canonical deny lines that MUST appear in every rendered failure simulation
/// output. These are the same deny lines from phase 3d/4a but phrased for the
/// simulation context.
const CANONICAL_DENY_LINES: &[&str] = &[
    "simulation/model-only: no live PID move was performed",
    "simulation/model-only: no real cgroup.procs write was performed",
    "simulation/model-only: no limiter attach was performed",
    "simulation/model-only: no nftables/tc/Zelynic state mutation was performed",
    "simulation/model-only: no persistent state write was performed",
    "simulation/model-only: Bandwidth limiting is not active from this command yet.",
    "simulation/model-only: Experimental PID move is not implemented yet.",
];

// ---------------------------------------------------------------------------
// Failure scenario enum
// ---------------------------------------------------------------------------

/// The 12 failure scenarios from the phase 4a design document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FailureScenario {
    /// F1: Failure before target cgroup creation (steps 1–3).
    /// Gate failure, PID dead, or original cgroup invalid.
    FailureBeforeTargetCgroupCreation,

    /// F2: Failure after target cgroup creation but before PID move (step 4→5).
    /// Target mkdir succeeded but PID exits or unexpected error prevents step 5.
    FailureAfterTargetCreationBeforePidMove,

    /// F3: Failure after PID move but before target verification (step 5→6).
    /// Move write succeeded but verification cannot proceed.
    FailureAfterPidMoveBeforeVerification,

    /// F4: Failure after target verification but before rollback (step 6→8).
    /// Verification succeeded but rollback cannot proceed.
    FailureAfterVerificationBeforeRollback,

    /// F5: Failure during rollback write (step 8).
    /// Rollback cgroup.procs write fails with EACCES/ENOENT/EBUSY/ESRCH.
    FailureDuringRollbackWrite,

    /// F6: Failure after rollback write but before rollback verification (step 8→9).
    /// Rollback write succeeded but verification cannot proceed.
    FailureAfterRollbackWriteBeforeVerification,

    /// F7: Failure during target cleanup (step 10).
    /// Target cgroup removal fails with EBUSY/ENOTEMPTY/EACCES.
    FailureDuringTargetCleanup,

    /// F8: Stale/dead PID during transaction.
    /// PID exits or becomes zombie at any point during the transaction.
    StaleDeadPidDuringTransaction,

    /// F9: Original cgroup disappears during transaction.
    /// Original cgroup directory removed or becomes inaccessible.
    OriginalCgroupDisappearsDuringTransaction,

    /// F10: Target cgroup becomes non-empty unexpectedly.
    /// Target cgroup.procs contains PIDs not written by this operation.
    TargetCgroupBecomesNonEmptyUnexpectedly,

    /// F11: Permission denied on cgroup.procs write.
    /// cgroup.procs write returns EACCES (move or rollback).
    PermissionDeniedOnCgroupProcsWrite,

    /// F12: Unexpected EBUSY / ENOENT / EACCES behavior.
    /// Kernel returns unexpected errno not covered by specific scenarios.
    UnexpectedErrnoBehavior,
}

impl FailureScenario {
    /// Returns the canonical scenario ID (e.g., "F1", "F12").
    pub(crate) fn id(&self) -> &'static str {
        match self {
            Self::FailureBeforeTargetCgroupCreation => "F1",
            Self::FailureAfterTargetCreationBeforePidMove => "F2",
            Self::FailureAfterPidMoveBeforeVerification => "F3",
            Self::FailureAfterVerificationBeforeRollback => "F4",
            Self::FailureDuringRollbackWrite => "F5",
            Self::FailureAfterRollbackWriteBeforeVerification => "F6",
            Self::FailureDuringTargetCleanup => "F7",
            Self::StaleDeadPidDuringTransaction => "F8",
            Self::OriginalCgroupDisappearsDuringTransaction => "F9",
            Self::TargetCgroupBecomesNonEmptyUnexpectedly => "F10",
            Self::PermissionDeniedOnCgroupProcsWrite => "F11",
            Self::UnexpectedErrnoBehavior => "F12",
        }
    }

    /// Returns the canonical scenario name for display.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::FailureBeforeTargetCgroupCreation => "failure before target cgroup creation",
            Self::FailureAfterTargetCreationBeforePidMove => {
                "failure after target creation but before PID move"
            }
            Self::FailureAfterPidMoveBeforeVerification => {
                "failure after PID move but before verification"
            }
            Self::FailureAfterVerificationBeforeRollback => {
                "failure after verification but before rollback"
            }
            Self::FailureDuringRollbackWrite => "failure during rollback write",
            Self::FailureAfterRollbackWriteBeforeVerification => {
                "failure after rollback write but before verification"
            }
            Self::FailureDuringTargetCleanup => "failure during target cleanup",
            Self::StaleDeadPidDuringTransaction => "stale/dead PID during transaction",
            Self::OriginalCgroupDisappearsDuringTransaction => {
                "original cgroup disappears during transaction"
            }
            Self::TargetCgroupBecomesNonEmptyUnexpectedly => {
                "target cgroup becomes non-empty unexpectedly"
            }
            Self::PermissionDeniedOnCgroupProcsWrite => "permission denied on cgroup.procs write",
            Self::UnexpectedErrnoBehavior => "unexpected EBUSY/ENOENT/EACCES behavior",
        }
    }

    /// Returns the failure point description (which transaction step boundary).
    pub(crate) fn failure_point(&self) -> &'static str {
        match self {
            Self::FailureBeforeTargetCgroupCreation => "steps 1-3 (pre-move gates)",
            Self::FailureAfterTargetCreationBeforePidMove => {
                "step 4→5 boundary (after mkdir, before move)"
            }
            Self::FailureAfterPidMoveBeforeVerification => {
                "step 5→6 boundary (after move, before verify)"
            }
            Self::FailureAfterVerificationBeforeRollback => {
                "step 6→8 boundary (after verify, before rollback)"
            }
            Self::FailureDuringRollbackWrite => "step 8 (rollback write)",
            Self::FailureAfterRollbackWriteBeforeVerification => {
                "step 8→9 boundary (after rollback write, before verify)"
            }
            Self::FailureDuringTargetCleanup => "step 10 (cleanup rmdir)",
            Self::StaleDeadPidDuringTransaction => "variable (any step in 1-10)",
            Self::OriginalCgroupDisappearsDuringTransaction => "variable (step 3 or step 8)",
            Self::TargetCgroupBecomesNonEmptyUnexpectedly => "variable (step 6 or step 10)",
            Self::PermissionDeniedOnCgroupProcsWrite => "step 5 (move) or step 8 (rollback)",
            Self::UnexpectedErrnoBehavior => "variable (any step)",
        }
    }
}

// ---------------------------------------------------------------------------
// PID location status
// ---------------------------------------------------------------------------

/// PID location taxonomy from phase 4a Rule 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PidLocationStatus {
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

impl PidLocationStatus {
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
// Rollback decision
// ---------------------------------------------------------------------------

/// Rollback decision model: what should the transaction do about rollback?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RollbackDecision {
    /// No rollback needed — no PID was moved.
    NotNeeded,
    /// Rollback must be attempted exactly once.
    AttemptOnce,
    /// Rollback was attempted and succeeded.
    AttemptedAndSucceeded,
    /// Rollback was attempted and failed.
    AttemptedAndFailed,
    /// Manual recovery required — rollback failed and PID may be stranded.
    ManualRecoveryRequired,
}

impl RollbackDecision {
    /// Returns the canonical label string for rendering.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NotNeeded => "not needed",
            Self::AttemptOnce => "attempt once",
            Self::AttemptedAndSucceeded => "attempted and succeeded",
            Self::AttemptedAndFailed => "attempted and failed",
            Self::ManualRecoveryRequired => "manual recovery required",
        }
    }
}

// ---------------------------------------------------------------------------
// Cleanup decision
// ---------------------------------------------------------------------------

/// Cleanup decision model: what should the transaction do about the target cgroup?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CleanupDecision {
    /// No cleanup needed — no target was created.
    NotNeeded,
    /// Remove empty operation-owned target cgroup.
    RemoveEmptyOperationOwned,
    /// Leave target because it is non-empty.
    LeaveBecauseNonEmpty,
    /// Leave target because removal is unsafe.
    LeaveBecauseUnsafe,
    /// Manual cleanup required — target left in place, operator must inspect.
    ManualCleanupRequired,
}

impl CleanupDecision {
    /// Returns the canonical label string for rendering.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NotNeeded => "not needed",
            Self::RemoveEmptyOperationOwned => "remove empty operation-owned target",
            Self::LeaveBecauseNonEmpty => "leave target because non-empty",
            Self::LeaveBecauseUnsafe => "leave target because unsafe",
            Self::ManualCleanupRequired => "manual cleanup required",
        }
    }

    /// Returns true if the cleanup decision explicitly leaves the target in place.
    pub(crate) fn leaves_target(&self) -> bool {
        matches!(
            self,
            Self::LeaveBecauseNonEmpty | Self::LeaveBecauseUnsafe | Self::ManualCleanupRequired
        )
    }
}

// ---------------------------------------------------------------------------
// Simulation result
// ---------------------------------------------------------------------------

/// The complete result of simulating a single failure scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SimulationResult {
    /// Scenario identifier (e.g., "F1").
    pub scenario_id: String,
    /// Scenario name (e.g., "failure before target cgroup creation").
    pub scenario_name: String,
    /// Failure point description.
    pub failure_point: String,
    /// PID location status after the failure.
    pub pid_location: PidLocationStatus,
    /// Rollback decision for this scenario.
    pub rollback_decision: RollbackDecision,
    /// Cleanup decision for this scenario.
    pub cleanup_decision: CleanupDecision,
    /// Whether the target cgroup may remain after the failure.
    pub target_may_remain: bool,
    /// Whether manual recovery is required.
    pub manual_recovery_required: bool,
    /// Canonical deny lines that must appear in output.
    pub deny_lines: Vec<String>,
    /// Specific output honesty requirements for this scenario.
    pub honesty_lines: Vec<String>,
    /// Phrases that must NEVER appear in the output for this scenario.
    pub forbidden_claims: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/// Builds the full failure simulation matrix — one `SimulationResult` for each
/// of the 12 scenarios defined in phase 4a.
pub(crate) fn build_failure_simulation_matrix() -> Vec<SimulationResult> {
    FailureScenario::all()
        .into_iter()
        .map(simulate_failure_scenario)
        .collect()
}

/// Simulates a single failure scenario, returning the complete model result.
pub(crate) fn simulate_failure_scenario(scenario: FailureScenario) -> SimulationResult {
    let deny_lines: Vec<String> = CANONICAL_DENY_LINES.iter().map(|s| s.to_string()).collect();

    match scenario {
        FailureScenario::FailureBeforeTargetCgroupCreation => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::NotMoved,
            rollback_decision: RollbackDecision::NotNeeded,
            cleanup_decision: CleanupDecision::NotNeeded,
            target_may_remain: false,
            manual_recovery_required: false,
            deny_lines,
            honesty_lines: vec![
                "Operation aborted: pre-move gate or PID liveness failure.".to_string(),
                "No PID was moved.".to_string(),
                "No cgroup.procs write was performed.".to_string(),
                "No target cgroup was created.".to_string(),
                format!("PID location: {}", PidLocationStatus::NotMoved.label()),
            ],
            forbidden_claims: vec![
                "Rollback was performed.".to_string(),
                "PID was moved.".to_string(),
                "Target cgroup was created.".to_string(),
                "cgroup.procs was written.".to_string(),
                "Limiter was attached.".to_string(),
            ],
        },

        FailureScenario::FailureAfterTargetCreationBeforePidMove => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::NotMoved,
            rollback_decision: RollbackDecision::NotNeeded,
            cleanup_decision: CleanupDecision::RemoveEmptyOperationOwned,
            target_may_remain: true,
            manual_recovery_required: false,
            deny_lines,
            honesty_lines: vec![
                "Target cgroup created.".to_string(),
                "PID move not attempted.".to_string(),
                "No PID was moved.".to_string(),
                "No cgroup.procs write was performed.".to_string(),
                format!("PID location: {}", PidLocationStatus::NotMoved.label()),
            ],
            forbidden_claims: vec![
                "Rollback was performed.".to_string(),
                "PID was moved.".to_string(),
                "cgroup.procs was written.".to_string(),
                "Limiter was attached.".to_string(),
                "PID was restored.".to_string(),
                "Target was force-removed.".to_string(),
            ],
        },

        FailureScenario::FailureAfterPidMoveBeforeVerification => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptOnce,
            cleanup_decision: CleanupDecision::RemoveEmptyOperationOwned,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "PID written to target cgroup.".to_string(),
                "Target verification skipped.".to_string(),
                "Rollback attempted.".to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
            ],
            forbidden_claims: vec![
                "PID was successfully restored.".to_string(),
                "Limiter was attached.".to_string(),
                "Bandwidth limiting is active.".to_string(),
                "PID location verified.".to_string(),
                "Target was force-removed.".to_string(),
            ],
        },

        FailureScenario::FailureAfterVerificationBeforeRollback => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptOnce,
            cleanup_decision: CleanupDecision::RemoveEmptyOperationOwned,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "PID verified in target cgroup.".to_string(),
                "Rollback attempted.".to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
            ],
            forbidden_claims: vec![
                "PID was successfully restored.".to_string(),
                "Alternative restore target used.".to_string(),
                "Original cgroup was created.".to_string(),
                "Target was force-removed.".to_string(),
            ],
        },

        FailureScenario::FailureDuringRollbackWrite => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptedAndFailed,
            cleanup_decision: CleanupDecision::LeaveBecauseUnsafe,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "ROLLBACK FAILURE: cgroup.procs write to original cgroup failed.".to_string(),
                "No further rollback attempts. Single attempt was the maximum.".to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
            ],
            forbidden_claims: vec![
                "PID was restored.".to_string(),
                "Rollback succeeded.".to_string(),
                "Alternative restore target used.".to_string(),
                "Retry will be attempted.".to_string(),
            ],
        },

        FailureScenario::FailureAfterRollbackWriteBeforeVerification => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::RollbackUnverified,
            rollback_decision: RollbackDecision::AttemptedAndSucceeded,
            cleanup_decision: CleanupDecision::RemoveEmptyOperationOwned,
            target_may_remain: true,
            manual_recovery_required: false,
            deny_lines,
            honesty_lines: vec![
                "PID rollback write completed.".to_string(),
                "Rollback verification skipped.".to_string(),
                format!(
                    "PID location: {}",
                    PidLocationStatus::RollbackUnverified.label()
                ),
            ],
            forbidden_claims: vec![
                "PID was successfully restored and verified.".to_string(),
                "PID location verified.".to_string(),
                "Verification confirmed restoration.".to_string(),
                "Target was force-removed.".to_string(),
            ],
        },

        FailureScenario::FailureDuringTargetCleanup => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::VerifiedRestored,
            rollback_decision: RollbackDecision::NotNeeded,
            cleanup_decision: CleanupDecision::LeaveBecauseUnsafe,
            target_may_remain: true,
            manual_recovery_required: false,
            deny_lines,
            honesty_lines: vec![
                "Target cleanup failed.".to_string(),
                "Leftover target cgroup.".to_string(),
                "PID restoration: already completed.".to_string(),
                format!(
                    "PID location: {}",
                    PidLocationStatus::VerifiedRestored.label()
                ),
            ],
            forbidden_claims: vec![
                "Cleanup succeeded.".to_string(),
                "Target was removed.".to_string(),
                "All operation-owned state was cleaned up.".to_string(),
            ],
        },

        FailureScenario::StaleDeadPidDuringTransaction => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::NotMoved,
            rollback_decision: RollbackDecision::NotNeeded,
            cleanup_decision: CleanupDecision::RemoveEmptyOperationOwned,
            target_may_remain: true,
            manual_recovery_required: false,
            deny_lines,
            honesty_lines: vec![
                "PID liveness: dead at gate.".to_string(),
                format!("PID location: {}", PidLocationStatus::NotMoved.label()),
            ],
            forbidden_claims: vec![
                "PID was moved.".to_string(),
                "PID was restored.".to_string(),
                "PID is alive.".to_string(),
                "Rollback was performed.".to_string(),
                "Target was force-removed.".to_string(),
            ],
        },

        FailureScenario::OriginalCgroupDisappearsDuringTransaction => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptedAndFailed,
            cleanup_decision: CleanupDecision::LeaveBecauseUnsafe,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "ROLLBACK FAILURE: Original cgroup no longer exists at rollback time.".to_string(),
                "No alternative restore target will be used.".to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
            ],
            forbidden_claims: vec![
                "Original cgroup was recreated.".to_string(),
                "Alternative restore path was used.".to_string(),
                "PID was safely restored.".to_string(),
                "Rollback succeeded.".to_string(),
            ],
        },

        FailureScenario::TargetCgroupBecomesNonEmptyUnexpectedly => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptOnce,
            cleanup_decision: CleanupDecision::LeaveBecauseNonEmpty,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "Unexpected PID(s) in target cgroup.".to_string(),
                "Target cleanup skipped: target cgroup is not empty.".to_string(),
                "Leftover target cgroup.".to_string(),
            ],
            forbidden_claims: vec![
                "Target was cleaned up.".to_string(),
                "All PIDs were removed from target.".to_string(),
                "Target was force-removed.".to_string(),
                "Cleanup succeeded.".to_string(),
            ],
        },

        FailureScenario::PermissionDeniedOnCgroupProcsWrite => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptedAndFailed,
            cleanup_decision: CleanupDecision::LeaveBecauseUnsafe,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "cgroup.procs write failed: permission denied (EACCES).".to_string(),
                "ROLLBACK FAILURE: cgroup.procs write to original cgroup failed: EACCES."
                    .to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
            ],
            forbidden_claims: vec![
                "Write succeeded.".to_string(),
                "PID was moved.".to_string(),
                "PID was restored.".to_string(),
                "Rollback succeeded.".to_string(),
            ],
        },

        FailureScenario::UnexpectedErrnoBehavior => SimulationResult {
            scenario_id: scenario.id().to_string(),
            scenario_name: scenario.name().to_string(),
            failure_point: scenario.failure_point().to_string(),
            pid_location: PidLocationStatus::Unknown,
            rollback_decision: RollbackDecision::AttemptOnce,
            cleanup_decision: CleanupDecision::LeaveBecauseUnsafe,
            target_may_remain: true,
            manual_recovery_required: true,
            deny_lines,
            honesty_lines: vec![
                "Unexpected error at step.".to_string(),
                format!("PID location: {}", PidLocationStatus::Unknown.label()),
                "ROLLBACK FAILURE: unexpected errno.".to_string(),
            ],
            forbidden_claims: vec![
                "Operation succeeded.".to_string(),
                "All steps completed normally.".to_string(),
                "No errors occurred.".to_string(),
            ],
        },
    }
}

/// Renders a failure simulation result as a structured text output suitable
/// for diagnostics and test inspection.
pub(crate) fn render_failure_simulation_result(result: &SimulationResult) -> String {
    let mut output = String::new();

    push_line(
        &mut output,
        &format!(
            "  Failure simulation [{}] {} (phase {}):",
            result.scenario_id, result.scenario_name, PHASE_LABEL
        ),
    );
    push_line(
        &mut output,
        &format!("    failure point: {}", result.failure_point),
    );
    push_line(
        &mut output,
        &format!("    PID location: {}", result.pid_location.label()),
    );
    push_line(
        &mut output,
        &format!(
            "    rollback decision: {}",
            result.rollback_decision.label()
        ),
    );
    push_line(
        &mut output,
        &format!("    cleanup decision: {}", result.cleanup_decision.label()),
    );
    push_line(
        &mut output,
        &format!("    target may remain: {}", result.target_may_remain),
    );
    push_line(
        &mut output,
        &format!(
            "    manual recovery required: {}",
            result.manual_recovery_required
        ),
    );
    push_line(&mut output, "    output honesty requirements:");
    for line in &result.honesty_lines {
        push_line(&mut output, &format!("      {}", line));
    }
    push_line(&mut output, "    forbidden claims:");
    for claim in &result.forbidden_claims {
        push_line(&mut output, &format!("      {}", claim));
    }
    push_line(&mut output, "    deny lines:");
    for deny in &result.deny_lines {
        push_line(&mut output, &format!("      {}", deny));
    }

    output
}

// ---------------------------------------------------------------------------
// FailureScenario iteration
// ---------------------------------------------------------------------------

impl FailureScenario {
    /// Returns all 12 failure scenarios in canonical order.
    pub(crate) fn all() -> Vec<FailureScenario> {
        vec![
            Self::FailureBeforeTargetCgroupCreation,
            Self::FailureAfterTargetCreationBeforePidMove,
            Self::FailureAfterPidMoveBeforeVerification,
            Self::FailureAfterVerificationBeforeRollback,
            Self::FailureDuringRollbackWrite,
            Self::FailureAfterRollbackWriteBeforeVerification,
            Self::FailureDuringTargetCleanup,
            Self::StaleDeadPidDuringTransaction,
            Self::OriginalCgroupDisappearsDuringTransaction,
            Self::TargetCgroupBecomesNonEmptyUnexpectedly,
            Self::PermissionDeniedOnCgroupProcsWrite,
            Self::UnexpectedErrnoBehavior,
        ]
    }

    /// Returns true if the failure occurs before the PID move (step 5).
    /// In these scenarios, rollback must NOT be claimed.
    pub(crate) fn is_before_pid_move(&self) -> bool {
        matches!(
            self,
            Self::FailureBeforeTargetCgroupCreation | Self::FailureAfterTargetCreationBeforePidMove
        )
    }

    /// Returns true if the failure occurs at or after the PID move attempt,
    /// meaning rollback MUST be attempted.
    pub(crate) fn requires_rollback_attempt(&self) -> bool {
        !self.is_before_pid_move()
    }
}

#[cfg(test)]
mod tests;
