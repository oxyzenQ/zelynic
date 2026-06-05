// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Guarded Real Writer Seam: a narrow code seam for the future guarded real
//! writer that will perform the first live PID move.
//!
//! Phase 5d is seam-only: no live PID move, no real cgroup.procs write, no
//! limiter attach, no nftables/tc/Zelynic state mutation, and no persistent
//! state write. The seam models the future real writer boundary without
//! performing any writes. Every call returns a blocked/not-implemented result
//! with explicit deny lines.
//!
//! This module is inspired by the phase 5c implementation design document
//! (`docs/v2.8-phase-5c-guarded-real-move-implementation-design.md`) and
//! introduces the input/result models, gate validation, and rendering that
//! a future live implementation phase will use as the entry point.

#![allow(dead_code, unused_imports)]

mod model;
mod render;
#[cfg(test)]
mod tests;

// Re-export all public items from submodules for crate compatibility.
pub(crate) use model::*;
pub(crate) use render::render_guarded_real_writer_plan;

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/// Builds a guarded real writer plan from the given input.
///
/// Validates all gate conditions and produces a result that is always
/// hard-blocked. Even when every gate passes, the seam returns blocked because
/// live PID move is not implemented in this phase.
///
/// No I/O. No filesystem access. No /proc access. No /sys access.
pub(crate) fn build_guarded_real_writer_plan(
    input: &GuardedRealWriterInput,
) -> GuardedRealWriterResult {
    let mut gates = Vec::new();
    let mut block_reasons = Vec::new();

    // Gate 1: root (euid == 0)
    let root_ok = input.is_root;
    gates.push(GuardedWriterGateResult {
        name: "root".to_string(),
        value: if root_ok { "euid 0" } else { "non-root" }.to_string(),
        status: if root_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !root_ok {
        block_reasons.push("non-root: guarded real writer requires euid == 0".to_string());
    }

    // Gate 2: system scope
    let system_ok = input.is_system_scope;
    gates.push(GuardedWriterGateResult {
        name: "system scope".to_string(),
        value: if system_ok {
            "system scope"
        } else {
            "user scope"
        }
        .to_string(),
        status: if system_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !system_ok {
        block_reasons
            .push("user scope: guarded real writer requires system scope only".to_string());
    }

    // Gate 3: single non-zero PID
    let pid_ok = input.pid > 0;
    gates.push(GuardedWriterGateResult {
        name: "PID".to_string(),
        value: if pid_ok {
            input.pid.to_string()
        } else {
            "zero/invalid".to_string()
        },
        status: if pid_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !pid_ok {
        block_reasons
            .push("zero PID: guarded real writer requires a valid non-zero PID".to_string());
    }

    // Gate 4: original cgroup present and non-empty
    let original_present = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty());
    gates.push(GuardedWriterGateResult {
        name: "original cgroup".to_string(),
        value: if original_present {
            input.original_cgroup_path.clone().unwrap_or_default()
        } else {
            "missing".to_string()
        },
        status: if original_present {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !original_present {
        block_reasons.push("missing original cgroup: capture is required before move".to_string());
    }

    // Gate 5: original cgroup not under /zelynic/
    let original_safe = input
        .original_cgroup_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty() && !p.contains("/zelynic/"));
    if original_present && !original_safe {
        gates.push(GuardedWriterGateResult {
            name: "original cgroup safety".to_string(),
            value: "zelynic-managed".to_string(),
            status: GuardedWriterGateStatus::Blocked,
        });
        block_reasons
            .push("zelynic-managed original cgroup: refusing move from Zelynic target".to_string());
    } else if original_present {
        gates.push(GuardedWriterGateResult {
            name: "original cgroup safety".to_string(),
            value: "external (safe)".to_string(),
            status: GuardedWriterGateStatus::Ok,
        });
    }

    // Gate 6: target under /sys/fs/cgroup/zelynic/
    let target_safe = is_safe_writer_target(&input.target_cgroup_path);
    gates.push(GuardedWriterGateResult {
        name: "target cgroup".to_string(),
        value: if target_safe {
            input.target_cgroup_path.clone()
        } else {
            "outside /sys/fs/cgroup/zelynic/".to_string()
        },
        status: if target_safe {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !target_safe {
        block_reasons.push("invalid target: must be under /sys/fs/cgroup/zelynic/".to_string());
    }

    // Gate 7: rollback consent present
    let consent_ok = input.rollback_consent_present;
    gates.push(GuardedWriterGateResult {
        name: "rollback consent".to_string(),
        value: if consent_ok { "present" } else { "missing" }.to_string(),
        status: if consent_ok {
            GuardedWriterGateStatus::Ok
        } else {
            GuardedWriterGateStatus::Blocked
        },
    });
    if !consent_ok {
        block_reasons.push("missing rollback consent: --rollback-required is required".to_string());
    }

    // Phase 5d hard block: even when every gate passes, the seam returns
    // blocked because live PID move is not implemented.
    let reason = if block_reasons.is_empty() {
        "guarded real writer seam is hard-blocked: live PID move is not implemented in phase 5d"
            .to_string()
    } else {
        format!("guarded real writer blocked: {}", block_reasons.join("; "))
    };

    let deny_lines: Vec<String> = CANONICAL_DENY_LINES.iter().map(|s| s.to_string()).collect();

    GuardedRealWriterResult {
        phase: format!("phase {}", PHASE_LABEL),
        plan_type: "guarded real writer seam (model-only)".to_string(),
        status: "blocked".to_string(),
        reason,
        pid_location: GuardedPidLocation::NotMoved,
        rollback_attempted: false,
        cleanup_attempted: false,
        cgroup_procs_writes_performed: false,
        limiter_attach_performed: false,
        nft_tc_state_mutation_performed: false,
        gates,
        deny_lines,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates that a target path is safe for the guarded real writer:
/// must be under the Zelynic cgroup namespace with no path traversal.
fn is_safe_writer_target(path: &str) -> bool {
    path.starts_with(&format!("{ZELYNIC_CGROUP_ROOT}/"))
        && !path.contains("..")
        && path.len() > ZELYNIC_CGROUP_ROOT.len() + 1
}
