// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Delta handler: two-sample read-only delta computation for `usage --sample --delta`.
//!
//! This module contains the entry point and core logic for the two-sample delta
//! CLI. It reads `/proc/net/dev` exactly twice, waits a bounded duration between
//! samples, computes per-interface deltas, and delegates rendering to the
//! render module. In JSON mode (phase 15), it produces machine-readable JSON
//! output using the frozen phase 14 pure model.
//!
//! # Safety
//!
//! - Reads only `/proc/net/dev` -- path is hardcoded, not configurable.
//! - Exactly two reads, then exit. No loop, no watch, no daemon.
//! - Does not write anything.
//! - Does not mutate system state.
//! - Does not block, throttle, or enforce quotas.
//! - Does not attach limiters.
//! - Does not load/attach eBPF.
//! - Does not mutate nftables/tc rules.
//! - Does not move PIDs or write cgroup.procs.
//! - Does not read sysfs.
//! - Does not implement interval sampling (wait duration is hardcoded).
//! - No filesystem persistence, no ledger file read/write.
//! - CLI remains finite and single-shot.

use std::thread;

use anyhow::Result;

use crate::accounting::{
    build_delta_json_first_read_error, build_delta_json_second_read_error,
    build_delta_json_success, build_session_delta, build_usage_delta_from_session_delta,
    read_live_proc_net_dev, serialize_delta_json, DeltaJsonErrorType,
};
use crate::commands::usage::DEFAULT_DELTA_WAIT_DURATION;

use super::render::render_usage_delta_live;

/// Handle the `zelynic usage --sample --delta` command (text output).
///
/// Reads `/proc/net/dev` exactly twice with a bounded wait between samples,
/// computes per-interface deltas using the existing `SessionDelta` model,
/// and renders honest interface-level delta text output.
pub fn handle_usage_delta() -> Result<()> {
    let rendered = run_delta_live()?;
    println!("{}", rendered);
    Ok(())
}

/// Handle the `zelynic usage --sample --delta --json` command (JSON output).
///
/// Reads `/proc/net/dev` exactly twice with a bounded wait between samples,
/// computes per-interface deltas, and produces machine-readable JSON output
/// using the frozen phase 14 pure model. Outputs valid JSON only -- no human
/// text before or after the JSON.
pub fn handle_usage_delta_json() -> Result<()> {
    let json_str = run_delta_live_json()?;
    println!("{}", json_str);
    Ok(())
}

/// Run the two-sample delta computation with live `/proc/net/dev` reads (text).
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

/// Run the two-sample delta computation with live `/proc/net/dev` reads (JSON).
///
/// This function performs exactly two live reads of `/proc/net/dev`,
/// separated by a bounded sleep, and returns the serialized delta JSON string.
/// Error scenarios produce valid JSON with appropriate error objects.
fn run_delta_live_json() -> Result<String> {
    // First read
    let plan1 = read_live_proc_net_dev();
    let snapshot1 = match extract_snapshot_from_plan(&plan1) {
        Ok(s) => s,
        Err(e) => {
            let (error_type, message) = classify_error(&e.to_string());
            let output = build_delta_json_first_read_error(error_type, &message);
            return Ok(serialize_delta_json(&output)?);
        }
    };

    // Wait between samples
    thread::sleep(DEFAULT_DELTA_WAIT_DURATION);

    // Second read
    let plan2 = read_live_proc_net_dev();
    let snapshot2 = match extract_snapshot_from_plan(&plan2) {
        Ok(s) => s,
        Err(e) => {
            let (error_type, message) = classify_error(&e.to_string());
            let output = build_delta_json_second_read_error(&snapshot1, error_type, &message);
            return Ok(serialize_delta_json(&output)?);
        }
    };

    // Compute delta JSON
    let output = build_delta_json_success(&snapshot1, &snapshot2);
    Ok(serialize_delta_json(&output)?)
}

/// Classify an error message into a `DeltaJsonErrorType` and the original message.
///
/// The `extract_snapshot_from_plan` function prefixes errors with "read error:"
/// or "parse error:". This function classifies accordingly.
fn classify_error(msg: &str) -> (DeltaJsonErrorType, String) {
    if msg.starts_with("read error:") {
        (DeltaJsonErrorType::Read, msg.to_string())
    } else if msg.starts_with("parse error:") {
        (DeltaJsonErrorType::Parse, msg.to_string())
    } else {
        // Default to read error for unrecognized prefixes.
        (DeltaJsonErrorType::Read, msg.to_string())
    }
}

/// Extract a parsed snapshot from a `LiveProcNetDevReadPlan`.
///
/// Returns the snapshot on success, or an appropriate error message
/// distinguishing read errors from parse errors.
pub(crate) fn extract_snapshot_from_plan(
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
