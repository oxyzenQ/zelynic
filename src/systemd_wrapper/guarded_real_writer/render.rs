// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Rendering for the guarded real writer seam.

#![allow(dead_code)]

use super::super::render::push_line;

use super::model::*;

/// Renders a guarded real writer plan result as structured text output.
///
/// The output always includes the phase label, gate results, deny lines,
/// and explicit non-mutation statements. No claim of PID movement, cgroup
/// write, limiter attach, bandwidth limiting, or nft/tc/state mutation is
/// ever present in the output.
pub(crate) fn render_guarded_real_writer_plan(result: &GuardedRealWriterResult) -> String {
    let mut output = String::new();

    push_line(
        &mut output,
        &format!("    Guarded real writer seam (phase {}):", PHASE_LABEL),
    );
    push_line(
        &mut output,
        &format!("      plan type: {}", result.plan_type),
    );
    push_line(&mut output, &format!("      status: {}", result.status));
    push_line(&mut output, &format!("      reason: {}", result.reason));
    push_line(
        &mut output,
        &format!("      pid location: {}", result.pid_location.label()),
    );
    push_line(
        &mut output,
        &format!("      rollback attempted: {}", result.rollback_attempted),
    );
    push_line(
        &mut output,
        &format!("      cleanup attempted: {}", result.cleanup_attempted),
    );
    push_line(
        &mut output,
        &format!(
            "      cgroup.procs writes performed: {}",
            result.cgroup_procs_writes_performed
        ),
    );
    push_line(
        &mut output,
        &format!(
            "      limiter attach performed: {}",
            result.limiter_attach_performed
        ),
    );
    push_line(
        &mut output,
        &format!(
            "      nft/tc/state mutation performed: {}",
            result.nft_tc_state_mutation_performed
        ),
    );
    push_line(&mut output, "      gates:");
    for gate in &result.gates {
        push_line(
            &mut output,
            &format!(
                "        {}: {} ({})",
                gate.name,
                gate.value,
                gate.status.label()
            ),
        );
    }
    push_line(&mut output, "      deny lines:");
    for deny in &result.deny_lines {
        push_line(&mut output, &format!("        {}", deny));
    }

    output
}
