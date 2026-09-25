// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The eagle-eyes --depth handler (NIGHT-master-1) — the one-shot
//! deep inspection surface.
//!
//! The live monitor answers "who is eating bandwidth RIGHT NOW" in a
//! TUI; the owner's depth question is the next click: a cg:1234 row
//! from `list-apps` or the leaderboard is often just a number — WHAT
//! process is that, launched by which user, from which binary, is it
//! a script, what permissions does it carry, how long has it run, and
//! is anything enforcing it right now. `--depth` prints that report
//! once and exits: no TUI, no interactive-stdio gate (pipe-friendly),
//! `--print-json` for scripts, the same '/'-separated target grammar
//! and autodetection the live monitor already owns.
//!
//! Assembly is three walks and a map read: the identity depth walk
//! (identity/depth.rs, per-process facts), the connection walk
//! (socket census + endpoints), the majority-vote identity map (the
//! package-name ladder's first rung), and the pinned policy maps (the
//! enforcement verdict, the status contract's honest-read discipline:
//! nothing pinned is honestly "unlimited", a failed read is an error,
//! never a fabricated verdict).

use anyhow::Result;

use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::{depth, pid_cgroup_id, pid_comm, IdentityMap};
use crate::ebpf::limiter::{
    pin_dir_has_files, terminal_width, Direction, Limiter, PolicyRaw, Target,
};
use crate::ebpf::render::{
    depth_doc_json, depth_report_lines, package_name, DepthReport, Enforcement,
};
use crate::output::{grey, print_json};

/// Parse the '/'-separated TARGETS spec (the grammar both eagle-eyes
/// modes share, NIGHT-boost-1): each token autodetects per
/// [`Target::parse`] — digits (bare or cg:-prefixed) are cgroup IDs,
/// anything else a process name. A spec that reduces to nothing is a
/// usage error, surfaced BEFORE the root guard like every parse
/// validation in this CLI.
pub(crate) fn parse_target_spec(spec: &str) -> Result<Vec<Target>> {
    let tokens: Vec<Target> = spec
        .split('/')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(Target::parse)
        .collect();
    if tokens.is_empty() {
        anyhow::bail!(
            "No targets in '{spec}' — pass process names or cgroup IDs \
             separated by '/' (e.g., 'zelynic eagle-eyes brave/firefox')"
        );
    }
    Ok(tokens)
}

/// Resolve one name token to its live cgroup ids: the /proc walk the
/// limiter's resolve_target owns, on the same canonical boundaries
/// (NIGHT-optimized-1) — pid_comm + pid_cgroup_id — with the same
/// lowercase exact-match semantics, so a name resolves identically
/// here and under `zelynic ss <name>`.
fn resolve_name(name: &str) -> Vec<u32> {
    let name_lower = name.to_lowercase();
    let mut ids: Vec<u32> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return ids;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(comm) = pid_comm(pid) else {
            continue;
        };
        if comm.to_lowercase() != name_lower {
            continue;
        }
        if let Some(id) = pid_cgroup_id(pid) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

/// Open the pinned enforcement state when anything is pinned,
/// mirroring the status handler's ladder: no pin files anywhere is
/// honestly `None` (every target unlimited), pins that exist but
/// cannot be opened are the stale-pins error with its recover tip —
/// never a fabricated "unlimited".
fn open_enforcement(verbose: bool) -> Result<Option<Limiter>> {
    if !pin_dir_has_files() {
        return Ok(None);
    }
    if !Limiter::is_pinned() {
        anyhow::bail!("stale pins detected\n  tip: run 'zelynic recover'");
    }
    Ok(Some(Limiter::open_pinned(verbose)?))
}

/// The enforcement verdict for one cgroup from the pinned policy
/// maps. Read failures propagate (the NIGHT-hunt-22 status contract:
/// this is a report surface — a fabricated verdict is the exact lie
/// the audit removed).
fn enforcement_for(limiter: Option<&Limiter>, cgroup_id: u32) -> Result<Enforcement> {
    let Some(limiter) = limiter else {
        return Ok(Enforcement::Unlimited);
    };
    let lookup = |direction: Direction| -> Result<Option<PolicyRaw>> {
        let rows = limiter.read_policies_public(direction)?;
        Ok(rows
            .iter()
            .find(|(key, _)| *key == cgroup_id)
            .map(|(_, policy)| *policy))
    };
    let download = lookup(Direction::Download)?;
    let upload = lookup(Direction::Upload)?;
    Ok(match (download, upload) {
        (None, None) => Enforcement::Unlimited,
        (download, upload) => Enforcement::Limited { download, upload },
    })
}

/// Handle `zelynic eagle-eyes <targets> --depth` — print the deep
/// report and exit. `--print-json` emits the typed document; the
/// interval flag never reaches here (the dispatcher notes and drops
/// it for the one-shot mode).
pub(crate) fn handle_eagle_eyes_depth(
    targets: Option<&str>,
    json: bool,
    verbose: bool,
) -> Result<()> {
    // Parse-before-execute ladder (no privileges needed): a missing
    // target and a spec that reduces to nothing both surface BEFORE
    // the root guard, the same fail-fast order as the live monitor.
    let Some(spec) = targets else {
        anyhow::bail!(
            "eagle-eyes --depth needs a TARGET — pass a cgroup ID or app name\n  \
             tip: e.g. 'zelynic ee 12345 --depth' (find ids with 'zelynic list-apps')"
        );
    };
    let tokens = parse_target_spec(spec)?;

    super::ensure_root()?;

    // One walk each feeds every target: the majority-vote identity
    // map (the name ladder's first rung), the connection census, and
    // the pinned policy maps.
    let mut identity = IdentityMap::new();
    identity.refresh();
    let mut conns = ConnectionMap::new();
    conns.refresh();
    let limiter = open_enforcement(verbose)?;

    let mut reports: Vec<DepthReport> = Vec::new();
    let mut misses: Vec<(String, String)> = Vec::new();
    for token in &tokens {
        let ids = match token {
            Target::CgroupId(id) => vec![*id],
            Target::ProcessName(name) => resolve_name(name),
        };
        if ids.is_empty() {
            let name = match token {
                Target::CgroupId(id) => format!("cg:{id}"),
                Target::ProcessName(name) => name.clone(),
            };
            misses.push((name, "no live cgroup matches".to_string()));
            continue;
        }
        if verbose {
            eprintln_safe!(
                "[eagle-eyes] {} -> {} cgroup(s)",
                match token {
                    Target::CgroupId(id) => format!("cg:{id}"),
                    Target::ProcessName(name) => name.clone(),
                },
                ids.len()
            );
        }
        for id in ids {
            let target = match token {
                Target::CgroupId(_) => format!("cg:{id}"),
                Target::ProcessName(name) => name.clone(),
            };
            let facts = depth::deep_collect(id);
            let comm = identity.get(id).map(|entry| entry.comm.clone());
            let name = package_name(comm.as_deref(), facts.rel_path.as_deref());
            let enforcement = enforcement_for(limiter.as_ref(), id)?;
            let conns_view = conns.get(id).cloned();
            reports.push(DepthReport {
                target,
                cgroup_id: id,
                name,
                depth: facts,
                enforcement,
                conns: conns_view,
            });
        }
    }

    // A spec that resolved to NOTHING is an error the owner can act
    // on; a partial miss (multi-target) renders alongside the hits.
    if reports.is_empty() {
        let names: Vec<String> = misses.iter().map(|(t, _)| format!("'{t}'")).collect();
        anyhow::bail!(
            "no live cgroup matches {}\n  tip: find ids with 'zelynic list-apps'",
            names.join(", ")
        );
    }

    if json {
        print_json(&depth_doc_json(&reports, &misses));
    } else {
        for line in depth_report_lines(&reports, terminal_width()) {
            println_safe!("{line}");
        }
        for (target, reason) in &misses {
            println_safe!("{}", grey(&format!("  {target}: {reason}")));
        }
    }
    Ok(())
}

// The depth handler pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the monitor pins.
#[cfg(test)]
#[path = "../../test/commands/eagle_depth_tests.rs"]
mod tests;
