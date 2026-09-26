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
    // NIGHT-hunt-20: the claim is only made from a VERIFIED count — an
    // unreadable map prints no claim (the unpin decision below warns).
    if removed == 0 {
        if let Ok(remaining) = count_remaining_policies(&limiter) {
            if remaining > 0 {
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
        }
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
    // Same verified-count rule (NIGHT-hunt-20): no claim from a read
    // that failed — unpin_if_no_policies prints the warning instead.
    if removed == 0 {
        if let Ok(remaining) = count_remaining_policies(&limiter) {
            if remaining > 0 {
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
        }
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
/// note and the unpin decision). Read errors PROPAGATE
/// (NIGHT-hunt-20): a failed read used to count as zero via
/// `unwrap_or_default`, and zero is the unpin trigger — a transient
/// read failure could tear down ALL enforcement while the user had
/// asked to remove one target's limits.
#[cfg(feature = "ebpf")]
fn count_remaining_policies(limiter: &crate::ebpf::limiter::Limiter) -> Result<usize> {
    let dl = limiter.read_policies_public(crate::ebpf::limiter::Direction::Download)?;
    let ul = limiter.read_policies_public(crate::ebpf::limiter::Direction::Upload)?;
    Ok(dl.len() + ul.len())
}

/// If no policies remain, unpin all BPF programs (no residue).
/// The zero must be VERIFIED (NIGHT-hunt-20): on a read failure the
/// pins stay — unpinning on "couldn't read" is how a transient error
/// tears down all enforcement mid-remove. The warning names the
/// residue risk and the repair tool; the command still exits 0
/// because the removal the user asked for did succeed.
#[cfg(feature = "ebpf")]
fn unpin_if_no_policies(limiter: &crate::ebpf::limiter::Limiter, verbose: bool) -> Result<()> {
    match count_remaining_policies(limiter) {
        Ok(0) => {
            super::unpin_all_bpf()?;
            if verbose {
                eprintln_safe!("[limiter] No policies remain — BPF unpinned, no residue");
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln_safe!(
                "Warning: policy maps unreadable ({e}) — leaving BPF pins in place; \
                 run 'zelynic recover' to repair"
            );
            Ok(())
        }
    }
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
///
/// NIGHT-master-4 hardening: every verdict this command prints is
/// verified — map reads propagate (no fabricated "Orphans: none"),
/// the removed counts come from the operations' own results, and an
/// incomplete recovery exits 1 so scripts retry instead of trusting
/// a success the filesystem did not grant.
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

        // NIGHT-master-4 (the honesty audit): the orphan scan's reads
        // PROPAGATE. The former unwrap_or_default() here folded a
        // failed map read into zero policies — and zero policies
        // renders "Orphans: none", the exact fabricated verdict the
        // NIGHT-hunt-20/22 contract forbids everywhere else (the
        // unstrict ladder, status). A transient read failure must
        // error out of recover, never report a clean board it never
        // saw.
        let dl_policies =
            limiter.read_policies_public(crate::ebpf::limiter::Direction::Download)?;
        let ul_policies = limiter.read_policies_public(crate::ebpf::limiter::Direction::Upload)?;

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

        // Remove orphan policies from BPF maps. NIGHT-hunt-20: the
        // result reports what was ACTUALLY removed — the old code
        // discarded every delete result and printed the orphan-CGROUP
        // count as if it were the removed-POLICY count, so a failed
        // delete was invisible and the number was wrong even on
        // success (each cgroup carries up to two policies, dl + ul).
        //
        // NIGHT-improve-10: a dead cgroup's bucket and stats entries
        // are unreachable forever — reclaim them alongside the
        // policies so the 1024-slot maps stay proportional to live
        // cgroups (an orphan that keeps its slot is the same LTS leak
        // a normal unstrict now reclaims).
        let mut orphans_removed = 0usize;
        let mut state_reclaimed = 0usize;
        let mut failed: Vec<String> = Vec::new();
        for id in &orphan_ids {
            // Both directions must be confirmed gone (deleted or
            // ENOENT) before the state reclaim — an uncertain delete
            // keeps the state, conservative like unstrict.
            let mut dl_gone = false;
            let mut ul_gone = false;
            for direction in [
                crate::ebpf::limiter::Direction::Download,
                crate::ebpf::limiter::Direction::Upload,
            ] {
                let is_dl = matches!(direction, crate::ebpf::limiter::Direction::Download);
                match limiter.delete_policy(*id, direction) {
                    Ok(true) => {
                        orphans_removed += 1;
                        if is_dl {
                            dl_gone = true;
                        } else {
                            ul_gone = true;
                        }
                    }
                    Ok(false) => {
                        if is_dl {
                            dl_gone = true;
                        } else {
                            ul_gone = true;
                        }
                    }
                    Err(e) => failed.push(format!("cg:{id}: {e}")),
                }
            }
            if dl_gone && ul_gone {
                state_reclaimed += limiter.reclaim_cgroup_state(*id, true, true, true);
            }
        }

        if failed.is_empty() {
            eprintln_safe!(
                "  Result: removed {orphans_removed} orphan policy(ies), \
                 reclaimed {state_reclaimed} stale state {}",
                if state_reclaimed == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            // NIGHT-master-4: the no-residue ladder the unstrict
            // family already owns. When the orphan sweep took the
            // LAST policies, the enforcement skeleton (programs,
            // links, maps) stays pinned over empty maps — the same
            // residue unstrict refuses to leave behind. The verified
            // zero unpins it; a read failure keeps it (the warning
            // names the repair tool); a leftover survivor errors the
            // command (the verified unpin's own contract).
            unpin_if_no_policies(&limiter, verbose)?;
            return Ok(());
        } else {
            eprintln_safe!(
                "  Result: removed {orphans_removed} orphan policy(ies), \
                 reclaimed {state_reclaimed} stale state entries; {} could not \
                 be removed: {}",
                failed.len(),
                failed.join(", ")
            );
            // NIGHT-master-4: an incomplete recovery is a runtime
            // failure, not a quiet success. The exit-code contract
            // (docs/USAGE.md) words code 1 as "stale state" — a
            // scripted recover that leaves orphans behind must say
            // so through the exit code too, or the retry never
            // happens and the next status honestly reports the
            // orphans the script believes it removed.
            return Err(anyhow::anyhow!(
                "recover incomplete — {} orphan policy(ies) could not be removed\n  \
                 tip: retry 'zelynic recover', or 'zelynic unstrict-all' to force-clear",
                failed.len()
            ));
        }
    }

    // Stale state detected — count orphaned pins. NIGHT-master-4:
    // an unreadable directory reports NO count (the former
    // unwrap_or(0) printed "STALE (0 orphaned pin file(s))" — a
    // fabricated zero on a state we just proved non-empty); the
    // verified unpin below is the removal's source of truth either
    // way.
    let pin_dir = std::path::Path::new(crate::ebpf::limiter::PIN_DIR);
    let detected = std::fs::read_dir(pin_dir).map(|d| d.count()).ok();
    match detected {
        Some(n) => {
            eprintln_safe!("  State: STALE ({n} orphaned pin file(s) detected)");
        }
        None => {
            eprintln_safe!("  State: STALE (orphaned pin files detected)");
        }
    }
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

    let removed = unpin_all()?;
    // NIGHT-master-4: the count is the VERIFIED unlink count from
    // the teardown itself — the pre-scan's number only ever guessed,
    // and a refused removal printed it anyway ("recovered (N
    // file(s) removed)" while the files stood). Leftover survivors
    // error out of unpin_all before this line can lie.
    eprintln_safe!("  Result: recovered ({removed} file(s) removed)");
    eprintln_safe!("  Next: run 'zelynic strict-single <target> <rate>' to re-apply limits");
    Ok(())
}
