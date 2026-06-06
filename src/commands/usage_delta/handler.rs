// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Delta handler: two-sample read-only delta computation for `usage --sample --delta`.
//!
//! This module contains the entry point and core logic for the two-sample delta
//! CLI. It reads `/proc/net/dev` exactly twice, waits a bounded duration between
//! samples, computes per-interface deltas, and delegates rendering to the
//! render module.

use std::thread;

use anyhow::Result;

use crate::accounting::{
    build_session_delta, build_usage_delta_from_session_delta, read_live_proc_net_dev,
};
use crate::commands::usage::DEFAULT_DELTA_WAIT_DURATION;

use super::render::render_usage_delta_live;

/// Handle the `zelynic usage --sample --delta` command.
///
/// Reads `/proc/net/dev` exactly twice with a bounded wait between samples,
/// computes per-interface deltas using the existing `SessionDelta` model,
/// and renders honest interface-level delta text output.
///
/// # Flow
///
/// 1. Read `/proc/net/dev` (first sample)
/// 2. If read/parse fails: report error, exit (no delta computation)
/// 3. Wait for the default delta duration (1 second)
/// 4. Read `/proc/net/dev` (second sample)
/// 5. If read/parse fails: report error, exit (no partial delta)
/// 6. Compute `SessionDelta` from both snapshots
/// 7. Build `UsageDeltaOutput` and render live delta text
/// 8. Print and exit
///
/// # Errors
///
/// Returns an error if any read or render fails (but never mutates state).
pub fn handle_usage_delta() -> Result<()> {
    let rendered = run_delta_live()?;
    println!("{}", rendered);
    Ok(())
}

/// Run the two-sample delta computation with live `/proc/net/dev` reads.
///
/// This function performs exactly two live reads of `/proc/net/dev`,
/// separated by a bounded sleep, and returns the rendered delta text.
fn run_delta_live() -> Result<String> {
    // First read
    let plan1 = read_live_proc_net_dev();
    let snapshot1 = extract_snapshot_from_plan(&plan1)?;

    // Wait between samples
    thread::sleep(DEFAULT_DELTA_WAIT_DURATION);

    // Second read
    let plan2 = read_live_proc_net_dev();
    let snapshot2 = extract_snapshot_from_plan(&plan2)?;

    // Compute delta
    let session_delta = build_session_delta(&snapshot1, &snapshot2);
    let usage_delta_output = build_usage_delta_from_session_delta(&session_delta);

    // Render live delta output
    Ok(render_usage_delta_live(&usage_delta_output))
}

/// Extract a parsed snapshot from a `LiveProcNetDevReadPlan`.
///
/// Returns the snapshot on success, or an appropriate error message
/// distinguishing read errors from parse errors.
fn extract_snapshot_from_plan(
    plan: &crate::accounting::LiveProcNetDevReadPlan,
) -> Result<crate::accounting::InterfaceCounterSnapshot> {
    match &plan.read_status {
        crate::accounting::LiveReadStatus::Success => {
            if let Some(ref snapshot) = plan.snapshot {
                Ok(snapshot.clone())
            } else {
                anyhow::bail!("read error: no snapshot available after successful read")
            }
        }
        crate::accounting::LiveReadStatus::Error(msg) => anyhow::bail!("{}", msg),
        crate::accounting::LiveReadStatus::Planned => {
            anyhow::bail!("read error: read was planned but never executed")
        }
    }
}
