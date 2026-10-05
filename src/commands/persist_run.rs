// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The persistence pair's verbs (night-during's LOC-cap split of
//! persist.rs: the --during wall-form fields pushed the parent past
//! the 500-line owner cap; the house precedent moves one cohesive
//! concern out — the snapshot/restore handlers and the state-file
//! I/O, unchanged, the document and the plan staying with their
//! pins).

use anyhow::{Context, Result};
use std::path::Path;

use super::persist::{restore_plan, SnapshotDoc, STATE_FILE, STATE_SCHEMA};
use crate::ebpf::limiter::{Direction, Limiter, Target};

#[cfg(feature = "ebpf")]
pub fn handle_snapshot(json: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::types::POLICY_FLAG_PER_SOCKET;

    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "snapshot writes the policy state file ({STATE_FILE}) — run with sudo (the strict family's privilege ladder)"
        );
    }
    let _lock = crate::ebpf::lock::acquire()?;

    let limiter = Limiter::open_pinned(false)?;
    let dl = limiter.read_policies_public(Direction::Download)?;
    let ul = limiter.read_policies_public(Direction::Upload)?;

    // The identity join: one walk, both directions.
    let mut identity = IdentityMap::new();
    identity.refresh();
    let join = |id: u32| -> Option<String> {
        identity
            .all()
            .into_iter()
            .find(|e| e.cgroup_id == id)
            .map(|e| e.comm.clone())
    };

    // night-during (schema v23): the window census — one read, both
    // directions' rows join it (the row is per root, not per leg),
    // serialized in the WALL form with the clocks read once.
    let windows = limiter.read_policy_windows_all().unwrap_or_default();
    let (wall_now, mono_now) = (
        crate::ebpf::limiter::wall_now_ns(),
        crate::ebpf::limiter::monotonic_ns(),
    );

    let mut skip = Vec::new();
    let mut doc = SnapshotDoc::from_rows(
        Direction::Download,
        &dl,
        &join,
        POLICY_FLAG_PER_SOCKET,
        &windows,
        wall_now,
        mono_now,
        &mut skip,
    );
    let mut ul_skip = Vec::new();
    let ul_doc = SnapshotDoc::from_rows(
        Direction::Upload,
        &ul,
        &join,
        POLICY_FLAG_PER_SOCKET,
        &windows,
        wall_now,
        mono_now,
        &mut ul_skip,
    );
    doc.entries.extend(ul_doc.entries);
    skip.extend(ul_skip);
    doc.captured_at_unix = unix_now_secs();

    // The honest-capture report: census rows that no longer have a
    // running process are named on stderr (the partial-census note
    // pattern), never silently dropped.
    if !skip.is_empty() {
        let ids: Vec<String> = skip.iter().map(|id| format!("cg:{id}")).collect();
        eprintln_safe!(
            "{}",
            crate::output::warn_bold(&format!(
                "{} policy leg(s) skipped: cgroup id(s) {} no longer resolve to a process — they cannot be restored by name",
                skip.len(),
                ids.join(", ")
            ))
        );
    }

    write_state_file(&doc)?;

    if json {
        crate::output::print_json(&doc);
        return Ok(());
    }
    let names: std::collections::BTreeSet<&str> =
        doc.entries.iter().map(|e| e.name.as_str()).collect();
    println_safe!(
        "{}",
        crate::output::ok(&format!(
            "snapshot: {} policy leg(s) across {} name(s) -> {STATE_FILE}",
            doc.entries.len(),
            names.len()
        ))
    );
    Ok(())
}

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
                step.during.as_ref(),
            )?
        } else {
            limiter.apply_group(&targets, &step.rates, step.during.as_ref())?
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

/// Write the document to the state path: create the parent (first
/// run on a fresh install), then the atomic write (temp + rename, so
/// a crash mid-write never leaves a half-serialized policy fleet).
pub(crate) fn write_state_file(doc: &SnapshotDoc) -> Result<()> {
    let path = Path::new(STATE_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating state directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(doc).context("serializing the snapshot document")?;
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("installing {STATE_FILE}"))?;
    Ok(())
}

/// Read the state file and refuse schema drift loudly (the tag ride:
/// a newer zelynic's file names its own version; a best-guess parse
/// would apply the wrong shape's policies).
pub(crate) fn read_state_file() -> Result<SnapshotDoc> {
    let body =
        std::fs::read_to_string(STATE_FILE).with_context(|| format!("reading {STATE_FILE}"))?;
    let doc: SnapshotDoc = serde_json::from_str(&body).context("parsing the state file")?;
    if doc.schema != STATE_SCHEMA {
        anyhow::bail!(
            "state file schema v{} != expected v{STATE_SCHEMA} — a newer or older zelynic wrote it; re-run snapshot to refresh it",
            doc.schema
        );
    }
    Ok(doc)
}

/// Unix seconds, std only (the no-chrono discipline; the value is a
/// capture stamp, not a formatted clock).
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
