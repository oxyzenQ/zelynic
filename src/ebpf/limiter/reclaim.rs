// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! State reclamation — the generic u32-keyed map plumbing, the
//! bucket/stats reclaim path that keeps the 1024-slot maps
//! proportional to live policies (NIGHT-improve-10, the LTS
//! endurance budget), and the REMOVE path itself: unstrict landed
//! here with NIGHT-improve-29's 500-LOC split (the apply path grew
//! the unset-direction removal that honors the -d/-u-only
//! contract), so the whole removal family — delete, partial-
//! failure honesty, reclamation — lives in one file.
//!
//! Split from policy.rs to hold the modules under the 500-LOC cap
//! (check-loc policy): apply/write semantics stay in policy.rs,
//! the map-access plumbing, the removal, and the reclamation they
//! share live here.

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData, MapError};

use super::policy::policy_survivor_line;
use super::types::{BucketRaw, Direction, LimiterStatsRaw, PolicyRaw, Target};
use crate::ebpf::pin::{
    self, PIN_MAP_BUCKET_DL, PIN_MAP_BUCKET_UL, PIN_MAP_GROUP_BUCKET_DL, PIN_MAP_GROUP_BUCKET_UL,
    PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL, PIN_MAP_STATS,
};

/// NIGHT-hunt-20 (error-path audit): a failed map delete means
/// "key absent" ONLY for ENOENT — every other errno means the delete
/// did NOT happen and the entry is still live. Conflating the two is
/// how a remove path reports "nothing to remove" while state stays
/// behind. Pure so it is unit-pinned in the policy tests.
pub(super) fn map_remove_means_absent(err: &MapError) -> bool {
    matches!(
        err,
        MapError::SyscallError(e) if e.io_error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Verbose trace line for one state reclaim (NIGHT-improve-10): the
/// per-cgroup bucket/stats slots an unstrict or recover handed back
/// to the maps. Pure formatting so the wording is unit-pinned below.
fn reclaim_trace_line(cgroup_id: u32, reclaimed: usize) -> String {
    format!(
        "[limiter] cg:{cgroup_id} reclaimed {reclaimed} stale state {} — \
         bucket/stats slots returned to the 1024-entry LTS budget",
        if reclaimed == 1 { "entry" } else { "entries" }
    )
}

/// Verbose trace line for one dead-group reclaim (NIGHT-lts-7): the
/// shared bucket slots a group's last reference handed back. Pure
/// formatting so the wording is unit-pinned below.
fn group_reclaim_trace_line(group_id: u32, reclaimed: usize) -> String {
    format!(
        "[limiter] group:{group_id} reclaimed {reclaimed} shared-bucket {} — \
         the group's last reference is gone, slots returned to the 256-entry budget",
        if reclaimed == 1 { "slot" } else { "slots" }
    )
}

/// The dead-group decision core (NIGHT-lts-7, pure so it is
/// unit-pinned): from the group ids CAPTURED at removal/overwrite
/// time (read before the map write made them unrecoverable) minus
/// the group ids every LIVE policy still references, the groups
/// whose shared buckets have no reason to stay. `0` is the
/// individual-bucket sentinel, never a group; duplicates collapse
/// (an apply overwriting many members of one old group must not
/// double-count it); the result is sorted for deterministic traces.
fn dead_groups(captured: &[u32], live_group_refs: &[u32]) -> Vec<u32> {
    let mut unique: Vec<u32> = captured.iter().copied().filter(|gid| *gid != 0).collect();
    unique.sort_unstable();
    unique.dedup();
    unique.retain(|gid| !live_group_refs.contains(gid));
    unique
}

/// The error an unstrict returns when some deletes failed (NIGHT-
/// hunt-20): removal is best-effort across cgroups and directions, but
/// never silent — this reports what WAS removed and names what stayed
/// enforced. Pure so the wording is unit-pinned.
fn unstrict_partial_failure_line(removed: usize, failed: &[String]) -> String {
    let n = failed.len();
    let unit = if removed == 1 { "policy" } else { "policies" };
    let verb = if n == 1 { "is" } else { "are" };
    format!(
        "removed {removed} {unit}, but {n} {verb} still enforced: {} — \
         run 'zelynic recover' if this persists",
        failed.join(", ")
    )
}
impl super::Limiter {
    /// Generic u32-keyed limiter map access in whichever mode is live
    /// (NIGHT-improve-10). `op` runs against the ephemeral object's
    /// map when one is loaded, or the pinned map otherwise;
    /// acquisition errors keep their per-mode wording exactly like
    /// the former policy-only path. The ONE acquisition path for
    /// every u32-keyed limiter map: NIGHT-hunt-20 introduced it for
    /// policies, this widened it to the bucket and stats maps the
    /// reclaim path touches.
    pub(super) fn with_u32_map<V, R>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        op: impl FnOnce(&mut BpfHashMap<&mut MapData, u32, V>) -> Result<R>,
    ) -> Result<R>
    where
        V: aya::Pod,
    {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_ref = bpf
                .map_mut(map_name)
                .context(format!("{map_name} not found"))?;
            let mut map: BpfHashMap<&mut MapData, u32, V> =
                BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
            op(&mut map)
        } else {
            let mut map_obj = pin::open_pinned_hash_map(pin_path)?;
            let mut map: BpfHashMap<&mut MapData, u32, V> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            op(&mut map)
        }
    }

    /// Delete one u32 key from a limiter map in whichever mode is
    /// live. `Ok(true)` deleted, `Ok(false)` ENOENT (genuinely
    /// absent), `Err` when the delete could not be performed — the
    /// tri-state contract `delete_policy` exposes, factored once so
    /// the bucket/stats reclaim path shares it verbatim.
    fn remove_map_entry<V: aya::Pod>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        key: u32,
    ) -> Result<bool> {
        self.with_u32_map::<V, bool>(map_name, pin_path, |map| match map.remove(&key) {
            Ok(()) => Ok(true),
            Err(e) if map_remove_means_absent(&e) => Ok(false),
            Err(e) => Err(anyhow!("failed to delete key {key} from {map_name}: {e}")),
        })
    }

    /// Reclaim the per-cgroup enforcement state a removal leaves
    /// behind (NIGHT-improve-10, the LTS endurance budget). The
    /// individual bucket and stats maps hold hard 1024 slots, and a
    /// removed policy that keeps its bucket leaks a slot — at 1024
    /// distinct limited cgroups over a long-lived host (container and
    /// session churn renumber cgroup ids), `get_bucket_ptr`'s insert
    /// starts failing and BPF silently returns UNLIMITED (fail-open,
    /// by design: a full bookkeeping map must never brick the
    /// network). Reclaiming on removal keeps the maps proportional
    /// to live policies, not to history.
    ///
    /// Deletes `cgroup_bucket_dl/ul[cgroup_id]` per requested
    /// direction and the combined stats entry when asked. The shared
    /// group buckets are deliberately untouched: their entries are
    /// referenced by every cgroup of a strict-multi group, and no
    /// single removal may decide that lifecycle. Failures warn and
    /// never fail the surrounding removal — reclamation is
    /// bookkeeping, and the policies (the enforced contract) are
    /// already gone. Returns the number of entries actually deleted.
    pub fn reclaim_cgroup_state(
        &mut self,
        cgroup_id: u32,
        reclaim_dl_bucket: bool,
        reclaim_ul_bucket: bool,
        reclaim_stats: bool,
    ) -> usize {
        let mut reclaimed = 0usize;
        let mut failures: Vec<String> = Vec::new();

        if reclaim_dl_bucket {
            match self.remove_map_entry::<BucketRaw>(
                "cgroup_bucket_dl",
                PIN_MAP_BUCKET_DL,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("bucket dl: {e}")),
            }
        }
        if reclaim_ul_bucket {
            match self.remove_map_entry::<BucketRaw>(
                "cgroup_bucket_ul",
                PIN_MAP_BUCKET_UL,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("bucket ul: {e}")),
            }
        }
        if reclaim_stats {
            match self.remove_map_entry::<LimiterStatsRaw>(
                "cgroup_limiter_stats",
                PIN_MAP_STATS,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("stats: {e}")),
            }
        }

        if !failures.is_empty() {
            eprintln_safe!(
                "[limiter] Unstrict: cg:{cgroup_id} state reclaim failed: {}",
                failures.join(", ")
            );
        }
        reclaimed
    }

    /// Verbose trace for the reclaim above — pub(super) so the
    /// unstrict loop in policy.rs prints it through this module's
    /// pure formatter.
    pub(super) fn print_reclaim_trace(&self, cgroup_id: u32, reclaimed: usize) {
        if reclaimed > 0 && self.verbose {
            eprintln_safe!("{}", reclaim_trace_line(cgroup_id, reclaimed));
        }
    }

    /// Read the group id of an existing policy (NIGHT-lts-7): the
    /// capture-before-write half of the dead-group reclaim — the
    /// write paths in policy.rs and the unstrict loop here call it
    /// BEFORE the write/delete makes the old group id unrecoverable.
    /// Returns Ok(None) when the cgroup has no policy in that
    /// direction (fresh apply — nothing superseded) and Err only
    /// when the map could not be read (the caller skips the capture:
    /// a bucket may then outlive its group, the conservative
    /// direction — a leaked slot never bricks enforcement).
    pub(super) fn read_policy_group(
        &mut self,
        cgroup_id: u32,
        direction: Direction,
    ) -> Result<Option<u32>> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let pin_path = self.pinned_policy_path(direction);
        self.with_u32_map::<PolicyRaw, Option<u32>>(&map_name, &pin_path, |map| {
            match map.get(&cgroup_id, 0) {
                Ok(raw) => Ok(Some(raw.group_id)),
                Err(e) if map_remove_means_absent(&e) => Ok(None),
                Err(e) => Err(anyhow!(
                    "failed to read cg:{cgroup_id} {} policy: {e}",
                    direction.label()
                )),
            }
        })
    }

    /// Reclaim the shared buckets of DEAD groups (NIGHT-lts-7, the
    /// ultra-long-endurance budget's missing half). The group maps
    /// hold hard 256 slots, every strict-multi invocation banks a
    /// FRESH quasi-random group id, and until now nothing ever
    /// deleted a group entry — the improve-10 reclaim deliberately
    /// skipped them ("no single removal may decide that
    /// lifecycle"), so ~256 strict-multi invocations on a
    /// long-lived host filled the maps and the 257th's members
    /// silently enforced UNLIMITED (the fail-open bucket lookup).
    /// The lifecycle decision now sits where it belongs: with the
    /// LAST reference. `captured` carries the group ids read from
    /// policies being removed or overwritten (read before the
    /// write); a group whose id no LIVE policy references has its
    /// dl+ul shared-bucket slots returned. Failures warn and never
    /// fail the surrounding operation — the policies (the enforced
    /// contract) are already gone or replaced.
    pub(super) fn reclaim_dead_groups(&mut self, captured: &[u32]) -> usize {
        // The live-reference sweep: the group ids every remaining
        // policy still points at (both directions, both maps).
        let mut live: Vec<u32> = Vec::new();
        for (map_name, pin_path) in [
            ("cgroup_policy_dl", PIN_MAP_POLICY_DL),
            ("cgroup_policy_ul", PIN_MAP_POLICY_UL),
        ] {
            let Ok(refs) = self.with_u32_map::<PolicyRaw, Vec<u32>>(map_name, pin_path, |map| {
                Ok(map
                    .iter()
                    .filter_map(|entry| entry.ok().map(|(_, p)| p.group_id))
                    .collect())
            }) else {
                // An unreadable policy map cannot prove any group
                // dead — keep every captured bucket (fail-closed
                // for reclamation, the same conservative posture as
                // the per-cgroup reclaim's uncertain directions).
                return 0;
            };
            live.extend(refs);
        }
        let mut reclaimed = 0usize;
        for gid in dead_groups(captured, &live) {
            let mut failures: Vec<String> = Vec::new();
            // NIGHT-master-3: the trace counts THIS group's slots, not
            // the running total — the old line printed the cumulative
            // sum, so the second dead group of a sweep reported the
            // first group's slots as its own (verbose-only accounting
            // drift; the returned total stays the sum).
            let mut reclaimed_this_group = 0usize;
            for (map_name, pin_path) in [
                ("group_bucket_dl", PIN_MAP_GROUP_BUCKET_DL),
                ("group_bucket_ul", PIN_MAP_GROUP_BUCKET_UL),
            ] {
                match self.remove_map_entry::<BucketRaw>(map_name, pin_path, gid) {
                    Ok(true) => {
                        reclaimed += 1;
                        reclaimed_this_group += 1;
                    }
                    Ok(false) => {}
                    Err(e) => failures.push(format!("group bucket: {e}")),
                }
            }
            if !failures.is_empty() {
                eprintln_safe!(
                    "[limiter] group:{gid} shared-bucket reclaim failed: {}",
                    failures.join(", ")
                );
            }
            if self.verbose {
                eprintln_safe!("{}", group_reclaim_trace_line(gid, reclaimed_this_group));
            }
        }
        reclaimed
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
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
        let mut removed = 0usize;
        let mut failed: Vec<String> = Vec::new();
        // The groups whose policies this removal takes (NIGHT-lts-7):
        // captured read-before-delete, swept once after the loop —
        // the LAST reference hands the group's shared-bucket slots
        // back (the 256-entry budget's previously-missing half).
        let mut superseded: Vec<u32> = Vec::new();

        for cgroup_id in &cgroup_ids {
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

        Ok(removed)
    }
}

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/reclaim_tests.rs"]
mod reclaim_tests;
