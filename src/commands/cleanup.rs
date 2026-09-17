// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Cleanup command handlers — unstrict, unstrict-all, recover.

use anyhow::Result;

#[cfg(feature = "ebpf")]
pub fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
    }

    let target = Target::parse(target_str);
    let mut limiter = Limiter::open_pinned(verbose)?;
    let removed = limiter.unstrict(&target)?;

    if removed == 0 {
        eprintln_safe!("No active limits found for '{target_str}'");
    } else {
        eprintln_safe!(
            "Removed {removed} limit{} for '{target_str}'",
            if removed == 1 { "" } else { "s" }
        );
    }

    // If no policies remain, unpin all BPF programs (no residue).
    let dl = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Download)
        .unwrap_or_default();
    let ul = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Upload)
        .unwrap_or_default();
    if dl.is_empty() && ul.is_empty() {
        super::unpin_all_bpf()?;
        if verbose {
            eprintln_safe!("[limiter] No policies remain — BPF unpinned, no residue");
        }
    }

    Ok(())
}

#[cfg(feature = "ebpf")]
pub fn handle_unstrict_all(_verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::pin_dir_has_files;

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    // Check if pin directory has any files. Can't rely on is_pinned() because
    // stale pins from old versions (before link pinning) fail the 4-file check
    // but still need cleanup.
    if !pin_dir_has_files() {
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
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
        eprintln_safe!("  State: valid (BPF programs + links pinned)");
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
