// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The unstrict family (NIGHT-hunt-29's LOC-cap split of
//! reclaim.rs: the one-walk batch pushed the parent past the
//! 500-line owner cap the limiter family observes, and the house
//! precedent moves one cohesive concern out — the removal family:
//! resolve the target, then delete its policies and reclaim the
//! state. The reclamation machinery stays in reclaim.rs; this file
//! owns the resolve-plus-remove half, unchanged in behavior, the
//! multi lane now resolving through the one-walk batcher).

use anyhow::{Result, anyhow};

use super::policy_lines::policy_survivor_line;
use super::reclaim::unstrict_partial_failure_line;
use super::types::{Direction, Target};

impl super::Limiter {
    /// Remove policy for a target (unstrict).
    ///
    /// Returns the number of POLICIES removed — each direction (dl/ul)
    /// counts separately, the same unit `apply_single`/`apply_group`
    /// report as "(N policies, active in background)". NIGHT-hunt-10:
    /// the old per-cgroup counting printed "Removed 1 limit" for the
    /// same state strict-single had just described as "4 policies".
    ///
    /// NIGHT-hunt-20: removal is best-effort across cgroups and
    /// directions, but never silent — a delete that FAILS (as opposed
    /// to ENOENT "absent") is recorded and reported.
    ///
    /// NIGHT-improve-10: every direction confirmed gone (deleted or
    /// ENOENT-absent) also reclaims the per-cgroup bucket and stats
    /// entries — see [`Self::reclaim_cgroup_state`].
    pub fn unstrict(&mut self, target: &Target) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        self.remove_ids(&cgroup_ids)
    }

    /// NIGHT-hunt-29 (hunt-28's named shard, owner-called): the
    /// multi lane's batched removal — ONE /proc walk for the whole
    /// name population (`resolve_target_list`, the walker hunt-28
    /// built), then the per-target removal with the EXACT
    /// per-target semantics the remove_limits loop owned: each
    /// target's removal carries its own failed list, superseded
    /// ledger, dead-group sweep, and memo bump (the cadence the
    /// shard's boundary documented), and the first partial
    /// failure aborts the remaining targets with the same Err the
    /// per-target unstrict returned. The single-name cost is
    /// unchanged (one walk, one removal); a thousand-name `um`
    /// drops from a thousand walks to one.
    pub fn unstrict_multi(&mut self, targets: &[Target]) -> Result<usize> {
        let ids_per_target = self.resolve_target_list(targets)?;
        let mut removed = 0usize;
        for ids in ids_per_target {
            removed += self.remove_ids(&ids)?;
        }
        Ok(removed)
    }

    /// The removal body split from `unstrict` (NIGHT-hunt-29): the
    /// resolve walk and the per-cgroup removal are separate
    /// concerns — the single lane resolves one target then removes;
    /// the multi lane resolves the whole list once then removes per
    /// target. The body itself is the verbatim unstrict loop: the
    /// per-cgroup walk, the superseded capture, the failure ledger,
    /// the tail sweep — nothing moved but the resolve that used to
    /// sit above it.
    fn remove_ids(&mut self, cgroup_ids: &[u32]) -> Result<usize> {
        let mut removed = 0usize;
        let mut failed: Vec<String> = Vec::new();
        // The groups whose policies this removal takes (NIGHT-lts-7):
        // captured read-before-delete, swept once after the loop —
        // the LAST reference hands the group's shared-bucket slots
        // back (the 256-entry budget's previously-missing half).
        let mut superseded: Vec<u32> = Vec::new();

        for cgroup_id in cgroup_ids {
            let label = self.identity.label(*cgroup_id);
            let mut found = false;
            // Per-direction gone tracking (NIGHT-improve-10): a
            // direction is gone when its policy was deleted here OR
            // was already ENOENT-absent — only a real failure leaves
            // it uncertain, and an uncertain direction keeps its
            // state (conservative: state may still be reachable).
            let mut dl_gone = false;
            let mut ul_gone = false;

            // Remove from dl + ul policy maps — each deleted direction
            // is one policy removed. A failed delete (not ENOENT) is
            // reported per direction and summed into the final error.
            // The group capture (NIGHT-lts-7) reads BEFORE the delete:
            // after it the old group id is unrecoverable.
            for direction in [Direction::Download, Direction::Upload] {
                if let Ok(Some(group)) = self.read_policy_group(*cgroup_id, direction) {
                    superseded.push(group);
                }
                match self.delete_policy(*cgroup_id, direction) {
                    Ok(true) => {
                        found = true;
                        removed += 1;
                        match direction {
                            Direction::Download => dl_gone = true,
                            Direction::Upload => ul_gone = true,
                        }
                    }
                    Ok(false) => match direction {
                        Direction::Download => dl_gone = true,
                        Direction::Upload => ul_gone = true,
                    },
                    Err(e) => {
                        eprintln_safe!(
                            "[limiter] Unstrict: cg:{cgroup_id} {} not removed: {e}",
                            direction.label()
                        );
                        failed.push(policy_survivor_line(*cgroup_id, direction));
                    }
                }
            }

            // Reclaim the state the removal leaves behind: buckets
            // for gone directions, stats when both are gone. Runs even
            // when this invocation removed nothing — an ENOENT-only
            // walk is exactly the crashed-removal case whose residue
            // the LTS budget needs back.
            if dl_gone || ul_gone {
                let reclaimed =
                    self.reclaim_cgroup_state(*cgroup_id, dl_gone, ul_gone, dl_gone && ul_gone);
                self.print_reclaim_trace(*cgroup_id, reclaimed);
            }

            if found {
                eprintln_safe!("[limiter] Unstrict: {label} — limits removed");
            }
        }

        if !failed.is_empty() {
            // NIGHT-private-research-2 / perf-0: removals are the
            // mutation the datapath's stale-detect already covers,
            // but the generation bump still runs before the
            // partial-failure error returns — the deletes that DID
            // land are a mutation like any other, and the
            // belt-and-suspenders pair (stamp + stale-detect) is
            // cheaper than reasoning about which half of it a given
            // removal needed.
            self.mmspa_memo_invalidate_best_effort();
            return Err(anyhow!(
                "{}",
                unstrict_partial_failure_line(removed, &failed)
            ));
        }

        // The dead-group sweep (NIGHT-lts-7): once every requested
        // removal has landed, a captured group no live policy
        // references returns its shared-bucket slots. Runs after the
        // per-cgroup state reclaim so one unstrict hands back both
        // halves of the endurance budget.
        self.reclaim_dead_groups(&superseded);

        // MMSPA memo invalidation (NIGHT-private-research-2,
        // generation-stamped by NIGHT-perf-0): a removed root leaves
        // cached resolutions pointing at a policy that no longer
        // exists — the datapath's stale-detect re-walks them per
        // packet, and this bump retires the whole stale generation
        // in one word so the re-walk cost is paid once, not per
        // packet, per leaf.
        self.mmspa_memo_invalidate_best_effort();

        Ok(removed)
    }
}
