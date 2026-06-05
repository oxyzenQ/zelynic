// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Hard safety boundary: no live PID move, no real cgroup.procs write,
//! no limiter attach, no nftables/tc/Zelynic state mutation, no persistent
//! state write. All render matrix output is pure fake/model-only/render-only.

#![allow(dead_code)]
//!
//! Fake Writer Render/Output Matrix (phase 4d): canonical output matrix for
//! every fake writer failure mode. Every possible fake transaction outcome
//! has honest, deterministic, non-mutating rendered output with 7 canonical
//! deny lines and explicit forbidden-claim checking.
//!
//! **Hard safety boundary**: This module performs no live PID move, no real
//! `cgroup.procs` write, no limiter attach, no nftables/tc/Zelynic state
//! mutation, and no persistent state write. All output is pure
//! fake/model-only/render-only.

#[cfg(test)]
use super::FakePidLocation;
use super::{simulate_fake_transaction, FakeFailureMode, FakeTransactionResult, OperationStatus};
use crate::systemd_wrapper::render::push_line;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const PHASE_LABEL: &str = "4d fake-writer output matrix";

/// Canonical deny lines that MUST appear in every render matrix entry.
/// These 7 lines deny any real system mutation and clearly label the
/// output as fake/model-only.
pub(crate) const RENDER_MATRIX_DENY_LINES: &[&str] = &[
    "No live PID move was performed.",
    "No real cgroup.procs write was performed.",
    "No limiter attach was performed.",
    "No nftables, tc, or Zelynic state changes were made.",
    "No persistent state write was performed.",
    "No CLI path for live PID move was enabled.",
    "This is fake/model-only output.",
];

/// Forbidden claim substrings that must NEVER appear in any render matrix output.
pub(crate) const FORBIDDEN_CLAIMS: &[&str] = &[
    "real PID moved",
    "real cgroup.procs written",
    "real rollback performed",
    "limiter attached",
    "bandwidth limiting active",
    "nft/tc/state mutation performed",
];

// ---------------------------------------------------------------------------
// Render matrix entry
// ---------------------------------------------------------------------------

/// A single entry in the fake writer render/output matrix.
///
/// Each entry represents the canonical rendered output for one
/// `FakeFailureMode`, produced by simulating the transaction and rendering
/// the result with the 7 canonical deny lines and no forbidden claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenderMatrixEntry {
    /// The failure mode this entry covers.
    pub failure_mode: FakeFailureMode,
    /// The simulated transaction result.
    pub transaction_result: FakeTransactionResult,
    /// The full rendered output string for this failure mode.
    pub rendered_output: String,
}

impl RenderMatrixEntry {
    /// Returns the fake failure mode label.
    pub fn failure_mode_label(&self) -> &'static str {
        self.failure_mode.label()
    }

    /// Returns the PID location label from the transaction result.
    pub fn pid_location_label(&self) -> &'static str {
        self.transaction_result.pid_location.label()
    }

    /// Returns the fake errno label if applicable.
    pub fn fake_errno_label(&self) -> Option<&str> {
        self.transaction_result.fake_errno_label.as_deref()
    }

    /// Returns true if rollback was required for this entry.
    pub fn rollback_required(&self) -> bool {
        self.transaction_result.rollback_required
    }

    /// Returns true if manual recovery is required.
    pub fn manual_recovery_required(&self) -> bool {
        self.transaction_result.manual_recovery_required
    }

    /// Returns true if the target cgroup may remain.
    pub fn target_may_remain(&self) -> bool {
        self.transaction_result.target_may_remain
    }

    /// Returns true if cleanup failed (operation status is Failed).
    pub fn cleanup_failed(&self) -> bool {
        self.transaction_result.cleanup == OperationStatus::Failed
    }

    /// Returns true if cleanup succeeded.
    pub fn cleanup_succeeded(&self) -> bool {
        self.transaction_result.cleanup == OperationStatus::Succeeded
    }
}

// ---------------------------------------------------------------------------
// Pure function: render_matrix_entry
// ---------------------------------------------------------------------------

/// Simulates a fake transaction for the given failure mode and renders
/// the result as a canonical output matrix entry with the 7 deny lines.
///
/// This is the primary rendering function for the phase 4d output matrix.
/// It produces deterministic, honest, non-mutating output for every fake
/// failure mode.
pub(crate) fn render_matrix_entry(
    pid: u32,
    target_cgroup: &str,
    original_cgroup: &str,
    failure_mode: FakeFailureMode,
) -> RenderMatrixEntry {
    let transaction_result =
        simulate_fake_transaction(pid, target_cgroup, original_cgroup, failure_mode);

    let rendered_output = render_matrix_output(&transaction_result, PHASE_LABEL);

    RenderMatrixEntry {
        failure_mode,
        transaction_result,
        rendered_output,
    }
}

// ---------------------------------------------------------------------------
// Pure function: render_matrix_output
// ---------------------------------------------------------------------------

/// Renders a fake transaction result with the phase 4d canonical deny lines.
///
/// This function differs from `render_fake_transaction_result` (phase 4c)
/// in that it uses the expanded set of 7 canonical deny lines required by
/// phase 4d, and includes the explicit "fake/model-only" banner.
pub(crate) fn render_matrix_output(result: &FakeTransactionResult, phase_label: &str) -> String {
    let mut output = String::new();

    push_line(
        &mut output,
        &format!("  Fake writer output matrix (v2.8 phase {}):", phase_label),
    );
    push_line(&mut output, "    status: fake/model-only");

    // Transaction details
    push_line(&mut output, &format!("    PID: {}", result.pid));
    push_line(
        &mut output,
        &format!("    target cgroup: {}", result.target_cgroup),
    );
    push_line(
        &mut output,
        &format!("    original cgroup: {}", result.original_cgroup),
    );

    // Failure mode and errno
    push_line(
        &mut output,
        &format!("    failure mode: {}", result.failure_mode.label()),
    );
    if let Some(ref errno) = result.fake_errno_label {
        push_line(&mut output, &format!("    fake errno: {}", errno));
    }

    // Per-step operation statuses
    push_line(
        &mut output,
        &format!("    target write: {}", result.target_write.label()),
    );
    push_line(
        &mut output,
        &format!("    target verification: {}", result.target_verify.label()),
    );
    push_line(
        &mut output,
        &format!("    rollback write: {}", result.rollback_write.label()),
    );
    push_line(
        &mut output,
        &format!(
            "    rollback verification: {}",
            result.rollback_verify.label()
        ),
    );
    push_line(
        &mut output,
        &format!("    cleanup: {}", result.cleanup.label()),
    );

    // Outcome fields
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

    // Canonical deny lines
    push_line(&mut output, "    canonical deny lines:");
    for deny in RENDER_MATRIX_DENY_LINES {
        push_line(&mut output, &format!("      {}", deny));
    }

    output
}

// ---------------------------------------------------------------------------
// Pure function: build_full_render_matrix
// ---------------------------------------------------------------------------

/// Builds the complete render/output matrix for all `FakeFailureMode`
/// variants. Returns one `RenderMatrixEntry` per mode, in canonical order.
pub(crate) fn build_full_render_matrix(
    pid: u32,
    target_cgroup: &str,
    original_cgroup: &str,
) -> Vec<RenderMatrixEntry> {
    FakeFailureMode::all()
        .into_iter()
        .map(|mode| render_matrix_entry(pid, target_cgroup, original_cgroup, mode))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
