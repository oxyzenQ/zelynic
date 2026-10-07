// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Crash-recovery handler — `zelynic recover`.
//!
//! Split from the cleanup module by NIGHT-dinner-11's LOC-cap push
//! (the unstrict family's no-match hard errors grew that file past
//! the 500-line policy): recover is a different concern from
//! user-initiated removal — it repairs crash residue (orphaned pin
//! files, dead-cgroup policies), reports what it found before
//! cleaning, and is safe to run anytime.
//!
//! NIGHT-dinner-23 (the style-consistency audit): the report joins
//! the "━━━" diagnostic family's render contract — the banner in
//! bold brand purple (the BRANDING 2.1 surface list always named
//! this banner bold; the code never honored it), State verdict
//! words in the doctor's bold semantic tier (ok_bold for clean /
//! valid, warn_bold for STALE), orphan findings in warn yellow,
//! affirmative Result values in status green with partial-failure
//! results in warn, and every quoted runnable command in the
//! suggestion white tier (the status stale-frame contract). The
//! data side sharpened with it: the none-branch verdict now counts
//! policies AND cgroups from the maps it just read — the old line
//! printed the cgroup count under the noun "policies" ("all 1
//! policies" on a box carrying two dl+ul policies), wrong on the
//! number and the noun at once.

use anyhow::Result;

// The no-residue ladder the unstrict family owns (a verified zero
// unpins; a read failure keeps the pins and warns) — recover runs
// it after an orphan sweep that took the last policies.
use super::cleanup::unpin_if_no_policies;

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

    eprintln_safe!(
        "{}",
        crate::output::brand_bold("━━━ zelynic Crash Recovery ━━━")
    );

    if !pin_dir_has_files() {
        eprintln_safe!(
            "  State: {} (no pin files found)",
            crate::output::ok_bold("clean")
        );
        eprintln_safe!("  Action: nothing to recover");
        return Ok(());
    }

    // Check if state is valid (all 4 critical pins present).
    let is_valid = Limiter::is_pinned();

    if is_valid {
        // BPF is valid — check for orphan policies (cgroup dead, policy remains).
        eprintln_safe!(
            "  State: {} (enforcement pins intact)",
            crate::output::ok_bold("valid")
        );
        eprintln_safe!("  Checking for orphan policies...");

        let mut limiter = Limiter::open_pinned(verbose)?;
        limiter.refresh_identity();

        // NIGHT-hunt-30 (the session's core find): the window-death
        // pass runs BEFORE the orphan scan — an expired `--during`
        // row is not crash residue (its cgroup is alive, its window
        // is over), but it used to ride the scan as a "live" policy
        // and read "nothing to recover" while stale rows waited for
        // a manual unstrict (the same visit-sweep law status now
        // owns; recover holds the lock already). Window-death first,
        // crash-residue second: the orphan census below then counts
        // only rows whose clock still stands, and the doctor's own
        // report names what the window pass collected. The sweep
        // stays best-effort (its own contract): a failed read warns
        // and the orphan scan below still propagates ITS reads —
        // the honest ladder, each surface its own verdict.
        let swept = match limiter.sweep_expired_windows() {
            Ok(n) => n,
            Err(e) => {
                eprintln_safe!("[limiter] window sweep skipped: {e}");
                0
            }
        };
        if swept > 0 {
            eprintln_safe!(
                "  Windows: {} expired row(s) swept (window-death, not crash residue)",
                crate::output::ok(&swept.to_string())
            );
        }

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
                "{}",
                orphans_none_line(
                    dl_policies.len(),
                    ul_policies.len(),
                    policy_cgroup_ids.len(),
                )
            );
            // The command suggestion rides the status stale-frame
            // contract (suggestion white, quoted, runnable) — the
            // same actionable-accent tier 'zelynic recover' gets
            // from the status stale lines.
            eprintln_safe!(
                "  Action: nothing to recover — use {} to remove limits",
                crate::output::suggestion("'zelynic unstrict-all'")
            );
            return Ok(());
        }

        // NIGHT-dinner-23: the finding renders in warn yellow — the
        // status stale-frame contract for a state the operator must
        // act on (plain "Orphans: " label, colored finding value).
        eprintln_safe!(
            "  Orphans: {}",
            crate::output::warn(&format!(
                "{} policy cgroup(s) no longer exist:",
                orphan_ids.len()
            ))
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
        // The group capture (NIGHT-dinner-6, the unstrict lts-7
        // pattern mirrored): each orphan's group id is read BEFORE
        // the delete makes it unrecoverable, so the sweep below can
        // return a dead group's shared-bucket slots once the last
        // policy that referenced it is gone.
        let mut captured_groups: Vec<u32> = Vec::new();
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
                // Capture read-before-delete: an Err keeps the
                // bucket (the conservative direction — a leaked
                // slot never bricks enforcement).
                if let Ok(Some(group)) = limiter.read_policy_group(*id, direction) {
                    captured_groups.push(group);
                }
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

        // The dead-group sweep (NIGHT-dinner-6): recover now owns the
        // lts-7 contract's recover half — a captured group no live
        // policy references returns its dl+ul shared-bucket slots,
        // keeping the 256-slot group maps proportional to LIVE groups
        // across container-churn recoveries. Runs before the
        // failure check: the live-reference sweep reads the maps'
        // CURRENT state, so a group whose delete failed simply stays
        // live and keeps its buckets (fail-closed, same posture as
        // the unstrict path's uncertain directions).
        let groups_reclaimed = limiter.reclaim_dead_groups(&captured_groups);

        if failed.is_empty() {
            // NIGHT-dinner-23: the affirmative Result value rides
            // the status-green tier (the whole verdict, one glance),
            // and the policy noun goes singular/plural aware — the
            // entry/entries pattern two lines below always had it.
            eprintln_safe!(
                "  Result: {}",
                crate::output::ok(&format!(
                    "removed {} orphan {}, reclaimed {} stale state {} and {} group bucket {}",
                    orphans_removed,
                    if orphans_removed == 1 {
                        "policy"
                    } else {
                        "policies"
                    },
                    state_reclaimed,
                    if state_reclaimed == 1 {
                        "entry"
                    } else {
                        "entries"
                    },
                    groups_reclaimed,
                    if groups_reclaimed == 1 {
                        "slot"
                    } else {
                        "slots"
                    },
                ))
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
            // NIGHT-dinner-23: a partial-failure Result renders in
            // warn yellow — the mixed verdict the red error block
            // that follows completes (exit 1 carries the failure,
            // the Result line carries what DID succeed).
            eprintln_safe!(
                "  Result: {}",
                crate::output::warn(&format!(
                    "removed {} orphan {}, reclaimed {} stale state entries and {} \
                     group bucket slots; {} could not be removed: {}",
                    orphans_removed,
                    if orphans_removed == 1 {
                        "policy"
                    } else {
                        "policies"
                    },
                    state_reclaimed,
                    groups_reclaimed,
                    failed.len(),
                    failed.join(", ")
                ))
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
            eprintln_safe!(
                "  State: {} ({n} orphaned pin file(s) detected)",
                crate::output::warn_bold("STALE")
            );
        }
        None => {
            eprintln_safe!(
                "  State: {} (orphaned pin files detected)",
                crate::output::warn_bold("STALE")
            );
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
    eprintln_safe!(
        "  Result: {} ({removed} file(s) removed)",
        crate::output::ok_bold("recovered")
    );
    eprintln_safe!(
        "  Next: run {} to re-apply limits",
        crate::output::suggestion("'zelynic strict-single <target> <rate>'")
    );
    Ok(())
}

/// The none-branch verdict line (NIGHT-dinner-23, the count-honesty
/// fix): the orphan-free board rendered with both dimensions the
/// maps just reported. Pure so the wording is unit-pinnable (the
/// `apply_success_lines` precedent) — the old line printed the
/// cgroup count under the noun "policies" ("all 1 policies" on a
/// box carrying two dl+ul policies on one cgroup), wrong on the
/// number and the noun at once. Singular/plural aware on both axes,
/// the entry/entries contract this file already owns; the
/// zero-policies arm names the empty skeleton for what it is
/// instead of the blunt "0 across 0, all live".
#[cfg(feature = "ebpf")]
#[must_use]
pub(crate) fn orphans_none_line(dl_policies: usize, ul_policies: usize, cgroups: usize) -> String {
    let total = dl_policies + ul_policies;
    if total == 0 {
        return format!(
            "  Orphans: {} (no policies pinned)",
            crate::output::ok_bold("none")
        );
    }
    format!(
        "  Orphans: {} ({} {} across {} cgroup{}, all live)",
        crate::output::ok_bold("none"),
        total,
        if total == 1 { "policy" } else { "policies" },
        cgroups,
        if cgroups == 1 { "" } else { "s" },
    )
}

// NIGHT-dinner-23: the count-honesty pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// census and eagle depth pins.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/recover_tests.rs"]
mod recover_tests;
