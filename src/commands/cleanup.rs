// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Cleanup command handlers — the one `unstrict` verb's two lanes
//! (NIGHT-improve-53, the masterclass unification: the former
//! unstrict-single and unstrict-multi handlers are the single and
//! list lanes, reached through the [`handle_unstrict`] router), plus
//! unstrict's --all reset (recover moved to its own module by NIGHT-dinner-11's
//! LOC-cap push — a different concern from user-initiated removal).

use anyhow::Result;

use crate::commands::target_grammar::{target_is_list, validate_multi_targets};

/// NIGHT-improve-53 (the masterclass unification): the one
/// `unstrict` verb's router — same routing law as strict: a '::'
/// anywhere in the target means the list lane, everything else is
/// the single lane. The lanes are the former unstrict-single /
/// unstrict-multi handlers, unchanged.
#[cfg(feature = "ebpf")]
pub fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    if target_is_list(target_str) {
        handle_unstrict_multi(target_str, verbose)
    } else {
        handle_unstrict_single(target_str, verbose)
    }
}

/// Remove the rate limit from one app — the single lane.
#[cfg(feature = "ebpf")]
fn handle_unstrict_single(target_str: &str, verbose: bool) -> Result<()> {
    // NIGHT-dinner-16: the single-target input boundary — an empty
    // target dies before the root ask (the parse-before-execute
    // ladder), instead of reading as a no-match with an invisible
    // target name after privileges were already granted.
    super::safety::validate_single_target(target_str, "zelynic unstrict brave")?;

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        // NIGHT-dinner-11: the named-target no-match contract —
        // nothing is limited at all, so the target the user NAMED
        // cannot match. (the --all reset keeps its clean-state exit 0;
        // that sweep names no target.)
        return Err(super::target_no_match_error(
            format!("No active limits — nothing to remove for '{target_str}'"),
            &[super::TIP_STATUS.to_string()],
        ));
    }

    let mut limiter = crate::ebpf::limiter::Limiter::open_pinned(verbose)?;
    let removed = remove_limits(&mut limiter, &[target_str])?;

    if removed > 0 {
        eprintln_safe!(
            "Removed {removed} {} for '{target_str}'",
            if removed == 1 { "policy" } else { "policies" }
        );
    }

    // NIGHT-hunt-10 honesty note, promoted onto the error's tip line
    // (dinner-11): a name-based unstrict that removed nothing while
    // other policies are still live is exactly the "limit not works"
    // trap the owner hit — the limits live under other names or dead
    // cgroups, and the tip points at the surfaces that tell the
    // truth instead of leaving the impression that nothing is
    // limited. NIGHT-hunt-20: the claim is only made from a VERIFIED
    // count — an unreadable map prints no claim (the unpin decision
    // below warns).
    let mut tip = super::TIP_STATUS.to_string();
    if removed == 0
        && let Ok(remaining) = count_remaining_policies(&limiter)
        && remaining > 0
    {
        tip = format!(
            "{remaining} other {} still active — 'zelynic status' lists them; \
                     'zelynic recover' removes dead-cgroup orphans",
            if remaining == 1 {
                "policy is"
            } else {
                "policies are"
            }
        );
    }

    // The no-residue ladder runs BEFORE the no-match verdict
    // (dinner-11 move: the old early return skipped it) — a walk
    // that removed nothing may still have emptied the maps, and an
    // empty-but-pinned skeleton is residue.
    unpin_if_no_policies(&limiter, verbose)?;

    if removed == 0 {
        // NIGHT-dinner-11: the no-match hard error.
        return Err(super::target_no_match_error(
            format!("No active limits found for '{target_str}'"),
            &[tip],
        ));
    }

    Ok(())
}

/// Remove limits from several targets in one shot — the list lane
/// (NIGHT-hunt-10: the unstrict family previously had no list form;
/// NIGHT-improve-53: the '::' grammar, same law as strict).
#[cfg(feature = "ebpf")]
fn handle_unstrict_multi(targets_str: &str, verbose: bool) -> Result<()> {
    // Same parsing contract as strict's group lane — and
    // NIGHT-blade-18: the list grammar (validate_multi_targets), so a
    // malformed removal list is refused with the same wording
    // instead of silently dropping the broken member. Removal is the
    // safe direction, so there is no danger loop here — only the
    // grammar.
    let segments = validate_multi_targets(targets_str, "zelynic unstrict brave::curl::pacman")?;
    let targets: Vec<&str> = segments.iter().map(|s| s.as_str()).collect();

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        // NIGHT-dinner-11: the named-target no-match contract (see
        // handle_unstrict — the --all reset owns the clean-state exit 0).
        return Err(super::target_no_match_error(
            format!("No active limits — nothing to remove for any target in '{targets_str}'"),
            &[super::TIP_STATUS.to_string()],
        ));
    }

    let mut limiter = crate::ebpf::limiter::Limiter::open_pinned(verbose)?;
    let removed = remove_limits(&mut limiter, &targets)?;

    if removed > 0 {
        eprintln_safe!(
            "Removed {removed} {} across {} target{} from '{}'",
            if removed == 1 { "policy" } else { "policies" },
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            targets_str
        );
    }

    // Same honesty tip as handle_unstrict (hunt-10/20): leftovers
    // under other names or dead cgroups are the classic "limit not
    // works" trap; the verified remaining count rides the error's
    // white tip line, and no claim comes from a read that failed —
    // unpin_if_no_policies prints the warning instead.
    let mut tip = super::TIP_STATUS.to_string();
    if removed == 0
        && let Ok(remaining) = count_remaining_policies(&limiter)
        && remaining > 0
    {
        tip = format!(
            "{remaining} other {} still active — 'zelynic status' lists them; \
                     'zelynic recover' removes dead-cgroup orphans",
            if remaining == 1 {
                "policy is"
            } else {
                "policies are"
            }
        );
    }

    // The no-residue ladder before the verdict (dinner-11 move, same
    // as handle_unstrict).
    unpin_if_no_policies(&limiter, verbose)?;

    if removed == 0 {
        // NIGHT-dinner-11: the no-match hard error.
        return Err(super::target_no_match_error(
            format!("No active limits found for any target in '{targets_str}'"),
            &[tip],
        ));
    }

    Ok(())
}

/// Shared removal core for the unstrict family: resolve the target
/// list and delete its policies. Returns the number of POLICIES
/// removed (dl + ul counted separately) — the same unit the
/// strict single lane reports in "(N policies, active in background)", so apply and remove
/// sides of the CLI now count identically (NIGHT-hunt-10: the old
/// per-cgroup counting here printed "Removed 1 limit" while strict
/// had said "4 policies" for the same state).
///
/// NIGHT-hunt-29: the whole list resolves in ONE /proc walk and
/// removes per target (`Limiter::unstrict_multi`, the walker
/// hunt-28 built). The single spelling rides the same path (one
/// name, one walk — the cost it always paid); the multi spelling
/// drops the per-name walks hunt-28's shard boundary named. Abort
/// semantics, per-target removal cadence, and every output line
/// are the loop's own, verbatim.
#[cfg(feature = "ebpf")]
fn remove_limits(limiter: &mut crate::ebpf::limiter::Limiter, targets: &[&str]) -> Result<usize> {
    use crate::ebpf::limiter::Target;

    let parsed: Vec<Target> = targets.iter().map(|s| Target::parse(s)).collect();
    limiter.unstrict_multi(&parsed)
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
///
/// pub(crate) since NIGHT-dinner-11's module split: the recover
/// handler (commands/recover.rs) runs the same ladder after an
/// orphan sweep that took the last policies.
#[cfg(feature = "ebpf")]
pub(crate) fn unpin_if_no_policies(
    limiter: &crate::ebpf::limiter::Limiter,
    verbose: bool,
) -> Result<()> {
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

/// The `u --all` emergency reset — remove EVERY limit on the
/// machine (the former unstrict-all verb, NIGHT-improve-54);
/// exits 0 on an already-clean system.
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
        // NIGHT-dinner-11: the clean-state carve-out. The --all reset
        // names NO target — it asks for a clean system, and an
        // already-clean system IS that state, so this stays the
        // exit-0 success `recover`'s clean path owns. The forms that
        // NAME a target (unstrict, either lane) error on a miss;
        // this sweep never can.
        eprintln_safe!("No active limits. Nothing to remove.");
        return Ok(());
    }

    // NIGHT-hunt-9: verbose lists exactly which pin files are being torn
    // down before the wipe — the same evidence recover() prints for its
    // stale-state branch. Previously this handler discarded the flag.
    if verbose && let Ok(entries) = std::fs::read_dir(crate::ebpf::limiter::PIN_DIR) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                eprintln_safe!("  - {name}");
            }
        }
    }

    super::unpin_all_bpf()?;
    eprintln_safe!("All limits removed, no residue.");
    Ok(())
}
