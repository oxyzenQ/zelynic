// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Atomic multi-target apply — the transactional strict-multi
//! (NIGHT-upgrade-charger-core-2, TIER A #6).
//!
//! The old contract was best-effort: a colon-list member that
//! resolved to nothing was silently skipped, the rest were enforced,
//! and the epilogue read OK — a script had no way to see it had just
//! configured half the fleet. The new contract is transactional in
//! two phases:
//!
//! - PRE-FLIGHT: every segment resolves BEFORE the first map write.
//!   One miss aborts the whole invocation with nothing limited —
//!   the error names the missed segments, how many were resolvable,
//!   and that zero policies were applied.
//! - ROLLBACK: a mid-flight write failure restores each mutated
//!   policy to its PRE-APPLY raw value (the NIGHT-hunt-20 rollback
//!   deleted what this invocation wrote, which stripped an EXISTING
//!   limit it should have restored — a `sm brave:curl 1mb` failing
//!   mid-flight left brave unlimited instead of at its old rate).
//!
//! `strict-all` deliberately keeps the best-effort sweep
//! (`apply_group`): its target list is a snapshot of list-apps, and
//! an app exiting between snapshot and write must not abort the
//! fleet's limits. The atomic contract belongs to the explicit
//! colon list, where every segment is the operator's own claim.
//!
//! The mutation ledger's restore half lives here; the capture half
//! (the both-directions snapshot) rides `write_policies_for_cgroup`
//! in policy.rs, shared by apply_single and apply_group so the
//! rollback upgrade is uniform across the apply family.

use anyhow::{anyhow, Result};

use super::policy::{group_apply_lines, partial_apply_failure_line, policy_survivor_line};
use super::types::{group_id_from, Direction, PolicyRaw, RateSpec, Target};

/// One policy mutation this invocation made, carrying the leg's
/// PRE-APPLY state so the rollback can restore it exactly.
#[derive(Debug, Clone)]
pub(super) struct PolicyMutation {
    pub(super) cgroup_id: u32,
    pub(super) direction: Direction,
    /// The raw policy the map held before this invocation touched
    /// the leg: `Some(raw)` restores it verbatim (rate, burst, group
    /// id — the value came FROM the map, so no re-derivation is
    /// honest); `None` means the leg was absent (a fresh limit), so
    /// the rollback removes what the apply wrote.
    pub(super) previous: Option<PolicyRaw>,
}

impl PolicyMutation {
    /// The mutation as a (cgroup, direction) pair — the shape the
    /// survivor line and the verbose rollback trace print.
    pub(super) fn key(&self) -> (u32, Direction) {
        (self.cgroup_id, self.direction)
    }
}

/// The pure restore decision (unit-pinned): what the rollback does
/// with one mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RestoreAction {
    /// Re-insert the pre-apply raw verbatim.
    Restore(PolicyRaw),
    /// The leg had no policy before — delete what the apply wrote.
    Remove,
}

/// Pure: the restore decision for one mutation.
pub(super) fn restore_action(mutation: &PolicyMutation) -> RestoreAction {
    match mutation.previous {
        Some(raw) => RestoreAction::Restore(raw),
        None => RestoreAction::Remove,
    }
}

/// One segment's pre-flight resolution: the display label the
/// operator typed, and the cgroup ids the /proc walk (or direct id)
/// resolved it to.
#[derive(Debug, Clone)]
pub(super) struct SegmentResolution {
    pub(super) label: String,
    pub(super) ids: Vec<u32>,
}

/// Pure: the pre-flight verdict (unit-pinned). Every segment must
/// resolve to at least one cgroup — one miss aborts the transaction
/// with the missed labels; the resolvable ids are returned only when
/// the whole list holds.
pub(super) fn preflight(resolutions: &[SegmentResolution]) -> Result<Vec<u32>, Vec<String>> {
    let mut misses: Vec<String> = Vec::new();
    let mut ids: Vec<u32> = Vec::new();
    for r in resolutions {
        if r.ids.is_empty() {
            misses.push(r.label.clone());
        } else {
            ids.extend(r.ids.iter().copied());
        }
    }
    if misses.is_empty() {
        Ok(ids)
    } else {
        Err(misses)
    }
}

/// The abort error's head line (unit-pinned): names the missed
/// segments, states the atomic contract, and reports the untouched
/// resolvable remainder — a "nothing was limited" verdict that also
/// says how much WOULD have been configured, so a script's error
/// review sees the whole transaction at a glance.
pub(super) fn multi_no_match_line(failed: &[String], resolvable: usize) -> String {
    let subject = if failed.len() == 1 {
        format!("target '{}'", failed[0])
    } else {
        let quoted: Vec<String> = failed.iter().map(|f| format!("'{f}'")).collect();
        format!("targets {}", quoted.join(", "))
    };
    format!(
        "{subject} resolved to no cgroup — strict-multi is atomic, nothing was limited \
         ({resolvable} of {} targets were resolvable, 0 applied)\n  \
         tip: try 'zelynic list-apps' to see live targets",
        failed.len() + resolvable
    )
}

impl super::Limiter {
    /// Apply strict-multi atomically (charger-core-2, TIER A #6):
    /// pre-flight resolution, then the group write with the
    /// snapshot/restore mutation ledger. Returns the number of
    /// policies written, exactly like `apply_group`.
    pub fn apply_group_atomic(&mut self, targets: &[Target], rates: &RateSpec) -> Result<usize> {
        // Phase 1 — resolve EVERY segment before the first map
        // write. resolve_target prints its own verbose trace per
        // segment (the /proc walk evidence), so the pre-flight
        // error rides on traces the operator can already read.
        let mut resolutions: Vec<SegmentResolution> = Vec::with_capacity(targets.len());
        for target in targets {
            let ids = self.resolve_target(target)?;
            resolutions.push(SegmentResolution {
                label: target.label(),
                ids,
            });
        }

        let all_ids = preflight(&resolutions).map_err(|misses| {
            anyhow!(
                "{}",
                multi_no_match_line(&misses, resolutions.len() - misses.len())
            )
        })?;
        if all_ids.is_empty() {
            // Unreachable past validate_multi_targets (all-empty
            // lists die at the grammar), kept as the belt the
            // apply family owns: never a vacuous success.
            return Ok(0);
        }

        // Dedup across targets, first-seen order (the depthbore-1
        // contract apply_group owns — one cgroup, one write, one
        // count).
        let mut seen_cgroups = std::collections::HashSet::new();
        let all_cgroup_ids: Vec<u32> = all_ids
            .into_iter()
            .filter(|id| seen_cgroups.insert(*id))
            .collect();

        // Group id: the NIGHT-master-3 mixer, shared with
        // apply_group.
        let group_id = group_id_from(
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );

        // Phase 2 — the writes, with the mutation ledger capturing
        // each leg's pre-apply state (write_policies_for_cgroup
        // snapshots both directions before the first mutation).
        let mut mutations: Vec<PolicyMutation> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                group_id,
                &mut mutations,
                &mut superseded,
            ) {
                Ok(n) => applied += n,
                Err(cause) => {
                    // The rollback RESTORES each mutation's
                    // pre-apply raw (the charger-core-2 upgrade over
                    // the hunt-20 delete-only shape); the AMMSP
                    // generation bump runs after the restore's
                    // mutations land, covering every state change
                    // this invocation made — the same
                    // once-per-invocation tail the family owns.
                    let rolled_back = self.rollback_mutations(&mutations, cause);
                    self.ammsp_memo_invalidate_best_effort();
                    return Err(rolled_back);
                }
            }
        }
        self.reclaim_dead_groups(&superseded);
        self.ammsp_memo_invalidate_best_effort();

        if self.verbose {
            for line in group_apply_lines(group_id, rates, all_cgroup_ids.len()) {
                eprintln_safe!("{line}");
            }
        }

        Ok(applied)
    }

    /// Roll the mutation ledger back to the pre-apply state: each
    /// mutation's `previous` raw is re-inserted verbatim (an
    /// existing limit comes back at its own rate, burst, and group),
    /// a fresh leg is removed. A restore that itself fails leaves
    /// that policy enforced — its error is printed for the record
    /// and the policy is named in the returned error, never hidden
    /// (the hunt-20 contract; the line formatters are unchanged so
    /// their pins hold).
    pub(super) fn rollback_mutations(
        &mut self,
        mutations: &[PolicyMutation],
        cause: anyhow::Error,
    ) -> anyhow::Error {
        let mut survivors: Vec<String> = Vec::new();
        let mut rolled_back = 0usize;
        for mutation in mutations {
            let (cgroup_id, direction) = mutation.key();
            match restore_action(mutation) {
                RestoreAction::Restore(raw) => {
                    match self.restore_policy(cgroup_id, direction, raw) {
                        Ok(()) => {
                            rolled_back += 1;
                            if self.verbose {
                                eprintln_safe!(
                                    "[limiter] rolled back cg:{cgroup_id} {} (pre-apply policy restored)",
                                    direction.label()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln_safe!(
                                "[limiter] rollback failed: cg:{cgroup_id} {}: {e}",
                                direction.label()
                            );
                            survivors.push(policy_survivor_line(cgroup_id, direction));
                        }
                    }
                }
                RestoreAction::Remove => match self.delete_policy(cgroup_id, direction) {
                    Ok(_) => {
                        rolled_back += 1;
                        if self.verbose {
                            eprintln_safe!(
                                "[limiter] rolled back cg:{cgroup_id} {} (was absent before this apply)",
                                direction.label()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln_safe!(
                            "[limiter] rollback failed: cg:{cgroup_id} {}: {e}",
                            direction.label()
                        );
                        survivors.push(policy_survivor_line(cgroup_id, direction));
                    }
                },
            }
        }
        anyhow!(
            "{}",
            partial_apply_failure_line(&cause.to_string(), rolled_back, &survivors)
        )
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the policy pins.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/atomic_tests.rs"]
mod atomic_tests;
