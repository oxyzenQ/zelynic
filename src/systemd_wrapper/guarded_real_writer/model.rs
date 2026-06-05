// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Input/result models for the guarded real writer seam.

#![allow(dead_code)]

/// Phase label used in rendered output.
pub(crate) const PHASE_LABEL: &str = "5d guarded-real-writer seam";

/// Zelynic cgroup namespace root.
pub(crate) const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

/// Input parameters for the guarded real writer plan.
///
/// Models the gate inputs that a future live implementation would consume.
/// This struct is pure data — no I/O, no filesystem access, no /proc access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedRealWriterInput {
    /// PID to be moved (single PID only; zero means invalid).
    pub pid: u32,
    /// Original cgroup path (where the PID currently resides).
    pub original_cgroup_path: Option<String>,
    /// Target cgroup path (where the PID would be moved to).
    pub target_cgroup_path: String,
    /// Whether the caller is root (euid == 0).
    pub is_root: bool,
    /// Whether the PID is in system scope (not user.slice).
    pub is_system_scope: bool,
    /// Whether rollback consent is present (--rollback-required).
    pub rollback_consent_present: bool,
}

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

/// PID location label following the canonical taxonomy from phase 4a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardedPidLocation {
    /// PID was never written to any cgroup.procs.
    NotMoved,
    /// Move succeeded and verification confirmed PID in target.
    VerifiedTarget,
    /// Rollback succeeded and verification confirmed PID restored.
    Restored,
    /// PID location cannot be determined.
    Unknown,
}

impl GuardedPidLocation {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotMoved => "not moved",
            Self::VerifiedTarget => "verified target",
            Self::Restored => "restored",
            Self::Unknown => "unknown",
        }
    }
}

/// The result of building a guarded real writer plan.
///
/// Every field is hardcoded to reflect the seam's hard-blocked status:
/// no operations are performed, no mutations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedRealWriterResult {
    /// Plan phase label.
    pub phase: String,
    /// Plan type label.
    pub plan_type: String,
    /// Overall status — always "blocked" in this phase.
    pub status: String,
    /// Human-readable reason for the blocked status.
    pub reason: String,
    /// PID location after the (non-)operation — always NotMoved.
    pub pid_location: GuardedPidLocation,
    /// Whether rollback was attempted — always false.
    pub rollback_attempted: bool,
    /// Whether cleanup was attempted — always false.
    pub cleanup_attempted: bool,
    /// Whether any cgroup.procs writes were performed — always false.
    pub cgroup_procs_writes_performed: bool,
    /// Whether any limiter attach was performed — always false.
    pub limiter_attach_performed: bool,
    /// Whether any nft/tc/state mutation was performed — always false.
    pub nft_tc_state_mutation_performed: bool,
    /// Gate validation results (individual gates checked).
    pub gates: Vec<GuardedWriterGateResult>,
    /// Canonical deny lines that must appear in all output.
    pub deny_lines: Vec<String>,
}

impl GuardedRealWriterResult {
    /// Returns true if the result status is "blocked".
    #[cfg(test)]
    pub(crate) fn is_blocked(&self) -> bool {
        self.status == "blocked"
    }
}

// ---------------------------------------------------------------------------
// Gate result model
// ---------------------------------------------------------------------------

/// Status of an individual gate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardedWriterGateStatus {
    /// Gate condition passed.
    Ok,
    /// Gate condition failed (blocks the operation).
    Blocked,
}

impl GuardedWriterGateStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Blocked => "blocked",
        }
    }
}

/// Result of evaluating a single gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedWriterGateResult {
    /// Gate name.
    pub name: String,
    /// Gate value (what was checked).
    pub value: String,
    /// Gate status (ok or blocked).
    pub status: GuardedWriterGateStatus,
}

// ---------------------------------------------------------------------------
// Canonical deny lines
// ---------------------------------------------------------------------------

/// The 7 canonical deny lines that MUST appear in every rendered output from
/// the guarded real writer seam. These are always true in phase 5d because
/// the seam never performs any operation.
pub(crate) const CANONICAL_DENY_LINES: &[&str] = &[
    "No live PID move was performed.",
    "No real cgroup.procs write was performed.",
    "No limiter attach was performed.",
    "No nftables, tc, or Zelynic state changes were made.",
    "No persistent state write was performed.",
    "No CLI path for live PID move was enabled.",
    "Guarded real writer seam is hard-blocked.",
];
