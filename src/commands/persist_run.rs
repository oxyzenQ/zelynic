// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The persistence lane's surviving verb (night-during's LOC-cap
//! split of persist.rs, reworked by NIGHT-improve-55): the snapshot
//! DUMP is retired — the owner's live-test verdict was that
//! remembering to dump before a reboot is a workflow the operator's
//! own script already owns, so the write half went with it. What
//! stays is `zelynic restore`: the state file
//! /var/lib/zelynic/limits.json is the operator's hand-maintained
//! desired state (kept in git, edited by hand — the "GitOps for
//! bandwidth" half that earned its keep), and the handler re-applies
//! every entry through the strict family's own machinery.

use anyhow::{Context, Result};

use super::persist::{
    restore_plan, validate_persisted_windows, SnapshotDoc, STATE_FILE, STATE_SCHEMA,
};
use crate::ebpf::limiter::{Limiter, Target};

/// Handle `zelynic restore`: read the state file, derive the plan,
/// apply it step by step, and report honestly (applied legs, names
/// not running yet — the strict-all best-effort contract, never an
/// abort for the fleet). Idempotent: re-running picks up late
/// starters without disturbing applied legs (an apply over an
/// existing limit is the documented supersede).
#[cfg(feature = "ebpf")]
pub fn handle_restore(json: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "restore re-applies policies from the state file — run with sudo (the strict family's privilege ladder)"
        );
    }
    let doc: SnapshotDoc = read_state_file()?;
    // The window-kind gate BEFORE the plan (night-during-7's honesty
    // catch): an unreadable auto-expire promise refuses the restore
    // naming its row — the plan's and_then would otherwise swallow it
    // into "no window", the forever-limit inversion the design brief
    // forbids (the unknown-TAG posture, one entry over).
    validate_persisted_windows(&doc)?;
    let plan = restore_plan(&doc);

    let _lock = crate::ebpf::lock::acquire()?;

    // The lifecycle ladder every strict-* rides: attach IS the
    // reuse/migration/cleanup contract (hunt-21), and a fresh boot
    // has no pins at all — this is the load that materializes them.
    Limiter::attach(false)?;

    let mut limiter = Limiter::open_pinned(false)?;
    let mut applied = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    for step in &plan {
        let targets: Vec<Target> = step
            .names
            .iter()
            .map(|n| Target::ProcessName(n.clone()))
            .collect();
        // apply's own return is the resolution verdict: zero legs
        // means nothing resolved (the name is not running) — the
        // step lands in the report, the fleet carries on.
        // night-during (schema v23): the window re-applies in its
        // WALL form through a fresh bridge — auto-expire survives
        // the reboot it was born for, never converting into forever.
        let n = if step.names.len() == 1 {
            limiter.apply_single(
                &targets[0],
                &step.rates,
                step.per_socket,
                // improve-40 (schema v24) / improve-40-b: the
                // snapshot's per-direction bracket, each leg's own
                // pair read verbatim off its entries.
                &step.bracket,
                step.during.as_ref(),
            )?
        } else {
            limiter.apply_group(&targets, &step.rates, &step.bracket, step.during.as_ref())?
        };
        if n == 0 {
            unresolved.extend(step.names.iter().cloned());
        } else {
            applied += n;
        }
    }

    if json {
        crate::output::print_json(&RestoreReportJson {
            steps: plan.len(),
            applied,
            unresolved: unresolved.clone(),
        });
        return Ok(());
    }
    println_safe!(
        "{}",
        crate::output::ok(&format!(
            "restore: {applied} policy leg(s) applied across {} step(s)",
            plan.len()
        ))
    );
    if !unresolved.is_empty() {
        eprintln_safe!(
            "{}",
            crate::output::warn_bold(&format!(
                "{} name(s) not running yet (skipped — re-run restore after they start): {}",
                unresolved.len(),
                unresolved.join(", ")
            ))
        );
    }
    Ok(())
}

/// The `restore --print-json` document.
#[cfg(feature = "ebpf")]
#[derive(serde::Serialize)]
struct RestoreReportJson {
    steps: usize,
    applied: usize,
    unresolved: Vec<String>,
}

// ── The file lane (thin, honest errors) ────────────────────────────

/// Read the state file and refuse schema drift loudly (the tag ride:
/// a newer zelynic's file names its own version; a best-guess parse
/// would apply the wrong shape's policies). The file is the
/// operator's hand-maintained desired state since NIGHT-improve-55
/// retired the dump verb — the fix for a drifted tag is the
/// operator's own edit, never a re-dump.
pub(crate) fn read_state_file() -> Result<SnapshotDoc> {
    let body =
        std::fs::read_to_string(STATE_FILE).with_context(|| format!("reading {STATE_FILE}"))?;
    let doc: SnapshotDoc = serde_json::from_str(&body).context("parsing the state file")?;
    if doc.schema != STATE_SCHEMA {
        anyhow::bail!(
            "state file schema v{} != expected v{STATE_SCHEMA} — a newer or older zelynic wrote it; fix the schema tag or re-create the file",
            doc.schema
        );
    }
    Ok(doc)
}
