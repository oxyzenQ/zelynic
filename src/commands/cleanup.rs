// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Cleanup command handlers — unstrict, unstrict-multi, unstrict-all,
//! recover.

use anyhow::Result;

#[cfg(feature = "ebpf")]
pub fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
    }

    let mut limiter = crate::ebpf::limiter::Limiter::open_pinned(verbose)?;
    let removed = remove_limits(&mut limiter, &[target_str])?;

    if removed == 0 {
        eprintln_safe!("No active limits found for '{target_str}'");
    } else {
        eprintln_safe!(
            "Removed {removed} {} for '{target_str}'",
            if removed == 1 { "policy" } else { "policies" }
        );
    }

    // NIGHT-hunt-10 honesty note: a name-based unstrict that removed
    // nothing while other policies are still live is exactly the
    // "limit not works" trap the owner hit — the limits live under
    // other names or dead cgroups. Point at the surfaces that tell the
    // truth instead of leaving the impression that nothing is limited.
    let remaining = count_remaining_policies(&limiter);
    if removed == 0 && remaining > 0 {
        eprintln_safe!(
            "Note: {remaining} other {} remain active — 'zelynic status' lists them; \
             'zelynic recover' removes dead-cgroup orphans",
            if remaining == 1 {
                "policy is"
            } else {
                "policies are"
            }
        );
    }

    unpin_if_no_policies(&limiter, verbose)?;

    Ok(())
}

/// Handle `zelynic unstrict-multi <a:b:c>` — remove limits from several
/// targets in one shot (NIGHT-hunt-10: mirrors strict-multi's colon
/// syntax; previously the unstrict family had no multi form).
#[cfg(feature = "ebpf")]
pub fn handle_unstrict_multi(targets_str: &str, verbose: bool) -> Result<()> {
    // Same parsing contract as strict-multi: trim each part, drop
    // empties, and fail with an example instead of silently resolving
    // an empty-name target.
    let targets: Vec<&str> = targets_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "No targets specified. Use colon-separated list.\n\
             Example: zelynic unstrict-multi brave:curl:pacman"
        ));
    }

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
    }

    let mut limiter = crate::ebpf::limiter::Limiter::open_pinned(verbose)?;
    let removed = remove_limits(&mut limiter, &targets)?;

    if removed == 0 {
        eprintln_safe!("No active limits found for any target in '{targets_str}'");
    } else {
        eprintln_safe!(
            "Removed {removed} {} across {} target{} from '{}'",
            if removed == 1 { "policy" } else { "policies" },
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            targets_str
        );
    }

    // Same honesty note as handle_unstrict: leftovers under other
    // names or dead cgroups are the classic "limit not works" trap.
    let remaining = count_remaining_policies(&limiter);
    if removed == 0 && remaining > 0 {
        eprintln_safe!(
            "Note: {remaining} other {} remain active — 'zelynic status' lists them; \
             'zelynic recover' removes dead-cgroup orphans",
            if remaining == 1 {
                "policy is"
            } else {
                "policies are"
            }
        );
    }

    unpin_if_no_policies(&limiter, verbose)?;

    Ok(())
}

/// Shared removal core for the unstrict family: resolve each target
/// string and delete its policies. Returns the number of POLICIES
/// removed (dl + ul counted separately) — the same unit strict-single
/// reports in "(N policies, active in background)", so apply and remove
/// sides of the CLI now count identically (NIGHT-hunt-10: the old
/// per-cgroup counting here printed "Removed 1 limit" while strict
/// had said "4 policies" for the same state).
#[cfg(feature = "ebpf")]
fn remove_limits(limiter: &mut crate::ebpf::limiter::Limiter, targets: &[&str]) -> Result<usize> {
    use crate::ebpf::limiter::Target;

    let mut removed = 0usize;
    for target_str in targets {
        let target = Target::parse(target_str);
        removed += limiter.unstrict(&target)?;
    }
    Ok(removed)
}

/// Count policies still live in both direction maps (for the honesty
/// note and the unpin decision).
#[cfg(feature = "ebpf")]
fn count_remaining_policies(limiter: &crate::ebpf::limiter::Limiter) -> usize {
    let dl = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Download)
        .unwrap_or_default();
    let ul = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Upload)
        .unwrap_or_default();
    dl.len() + ul.len()
}

/// If no policies remain, unpin all BPF programs (no residue).
#[cfg(feature = "ebpf")]
fn unpin_if_no_policies(limiter: &crate::ebpf::limiter::Limiter, verbose: bool) -> Result<()> {
    if count_remaining_policies(limiter) == 0 {
        super::unpin_all_bpf()?;
        if verbose {
            eprintln_safe!("[limiter] No policies remain — BPF unpinned, no residue");
        }
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
pub fn handle_unstrict_all(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::pin_dir_has_files;

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    // Check if pin directory has any files. Can't rely on is_pinned()
    // because partial states that fail the operational check (stale pins
    // from old versions, or a crash between program and link pinning —
    // NIGHT-hunt-19) still need cleanup.
    if !pin_dir_has_files() {
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
    }

    // NIGHT-hunt-9: verbose lists exactly which pin files are being torn
    // down before the wipe — the same evidence recover() prints for its
    // stale-state branch. Previously this handler discarded the flag.
    if verbose {
        if let Ok(entries) = std::fs::read_dir(crate::ebpf::limiter::PIN_DIR) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    eprintln_safe!("  - {name}");
                }
            }
        }
    }

    super::unpin_all_bpf()?;
    eprintln_safe!("All limits removed, no residue.");
    Ok(())
}

/// Handle `zelynic recover` — crash recovery cleanup.
/// Detects orphaned/stale BPF pin files and removes them.
/// Differs from `unstrict-all` in that it's diagnostic: reports what
/// it found before cleaning. Safe to run anytime.
#[cfg(feature = "ebpf")]
pub fn handle_recover(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{pin_dir_has_files, unpin_all, Limiter};

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    eprintln_safe!("━━━ zelynic Crash Recovery ━━━");

    if !pin_dir_has_files() {
        eprintln_safe!("  State: clean (no pin files found)");
        eprintln_safe!("  Action: nothing to recover");
        return Ok(());
    }

    // Check if state is valid (all 4 critical pins present).
    let is_valid = Limiter::is_pinned();

    if is_valid {
        // BPF is valid — check for orphan policies (cgroup dead, policy remains).
        eprintln_safe!("  State: valid (enforcement pins intact)");
        eprintln_safe!("  Checking for orphan policies...");

        let mut limiter = Limiter::open_pinned(verbose)?;
        limiter.refresh_identity();

        let dl_policies = limiter
            .read_policies_public(crate::ebpf::limiter::Direction::Download)
            .unwrap_or_default();
        let ul_policies = limiter
            .read_policies_public(crate::ebpf::limiter::Direction::Upload)
            .unwrap_or_default();

        // Collect all cgroup IDs that have policies.
        use std::collections::HashSet;
        let mut policy_cgroup_ids: HashSet<u32> = HashSet::new();
        for (id, _) in &dl_policies {
            policy_cgroup_ids.insert(*id);
        }
        for (id, _) in &ul_policies {
            policy_cgroup_ids.insert(*id);
        }

        // Check which cgroup IDs are still alive (exist in identity map).
        let alive_ids: HashSet<u32> = limiter
            .identity()
            .all()
            .iter()
            .map(|e| e.cgroup_id)
            .collect();

        let orphan_ids: Vec<u32> = policy_cgroup_ids
            .iter()
            .filter(|id| !alive_ids.contains(id))
            .copied()
            .collect();

        if orphan_ids.is_empty() {
            eprintln_safe!(
                "  Orphans: none (all {} policies have live cgroups)",
                policy_cgroup_ids.len()
            );
            eprintln_safe!("  Action: nothing to recover — use 'unstrict-all' to remove limits");
            return Ok(());
        }

        eprintln_safe!(
            "  Orphans: {} policy cgroup(s) no longer exist:",
            orphan_ids.len()
        );
        for id in &orphan_ids {
            eprintln_safe!("    - cg:{id}");
        }
        eprintln_safe!("  Action: removing orphan policies...");

        // Remove orphan policies from BPF maps.
        for id in &orphan_ids {
            let _ = limiter.delete_policy(*id, crate::ebpf::limiter::Direction::Download);
            let _ = limiter.delete_policy(*id, crate::ebpf::limiter::Direction::Upload);
        }

        eprintln_safe!("  Result: removed {} orphan policy(ies)", orphan_ids.len());
        return Ok(());
    }

    // Stale state detected — count orphaned pins.
    let pin_dir = std::path::Path::new(crate::ebpf::limiter::PIN_DIR);
    let pin_count = std::fs::read_dir(pin_dir).map(|d| d.count()).unwrap_or(0);

    eprintln_safe!("  State: STALE ({pin_count} orphaned pin file(s) detected)");
    eprintln_safe!("  Cause: likely crash, SIGKILL, OOM, or partial upgrade");
    eprintln_safe!("  Action: removing all pin files...");

    if verbose {
        if let Ok(entries) = std::fs::read_dir(pin_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    eprintln_safe!("    - {name}");
                }
            }
        }
    }

    unpin_all()?;
    eprintln_safe!("  Result: recovered ({pin_count} file(s) removed)");
    eprintln_safe!("  Next: run 'zelynic strict-single <target> <rate>' to re-apply limits");
    Ok(())
}
