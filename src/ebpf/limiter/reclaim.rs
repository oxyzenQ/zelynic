// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! State reclamation — the bucket/ring/stats reclaim path that
//! keeps the 1024-slot maps proportional to live policies
//! (NIGHT-improve-10, the LTS endurance budget; NIGHT-hunt-Z4
//! added the rings — the delivered-rate series was the one
//! census-bounded family unstrict never handed back, so a
//! months-LTS host's ring maps filled with dead roots' 128 B
//! entries until later roots' rings silently failed to create),
//! and the REMOVE path itself: unstrict landed here with
//! NIGHT-improve-29's 500-LOC split (the apply path grew the
//! unset-direction removal that honors the -d/-u-only contract),
//! so the whole removal family — delete, partial-failure honesty,
//! reclamation — lives in one
//! file.
//!
//! Split from policy.rs to hold the modules under the 500-LOC cap
//! (check-loc policy): apply/write semantics stay in policy.rs,
//! the map-access plumbing moved one split further to lanes.rs
//! (NIGHT-perf-0 — the Array twin of the acquisition family pushed
//! this file past the cap again), and the removal and reclamation
//! semantics stay here.

use std::collections::HashSet;

use anyhow::{anyhow, Result};

use super::lanes::map_error_means_absent;
use super::rate_ring::RateRingRaw;
use super::types::{BucketRaw, Direction, LimiterStatsRaw, PolicyRaw, PolicyWindowRaw};
use crate::ebpf::pin::{
    PIN_MAP_BUCKET_DL, PIN_MAP_BUCKET_UL, PIN_MAP_GROUP_BUCKET_DL, PIN_MAP_GROUP_BUCKET_UL,
    PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL, PIN_MAP_POLICY_WINDOW, PIN_MAP_RATE_RING_DL,
    PIN_MAP_RATE_RING_UL, PIN_MAP_STATS,
};

/// Verbose trace line for one state reclaim (NIGHT-improve-10): the
/// per-cgroup bucket/ring/stats slots an unstrict or recover handed
/// back to the maps. Pure formatting so the wording is unit-pinned
/// below.
fn reclaim_trace_line(cgroup_id: u32, reclaimed: usize) -> String {
    format!(
        "[limiter] cg:{cgroup_id} reclaimed {reclaimed} stale state {} — \
         bucket/ring/stats slots returned to the 1024-entry LTS budget",
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

/// Which policy legs a census-bounded family's liveness rides
/// (NIGHT-hunt-34): the per-direction state maps (bucket, ring)
/// gate on their OWN direction's row — a `-d`-only removal kills
/// the dl state and leaves the ul state standing — while the
/// combined maps (stats, window) ride either leg, exactly the
/// gates [`Self::reclaim_cgroup_state`] applies root by root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CensusLeg {
    Download,
    Upload,
    Either,
}

/// The orphan-census decision core (NIGHT-hunt-34, pure so it is
/// unit-pinned): from one family map's keys and the live policy
/// keys per direction, the keys whose policy rows are all gone —
/// the state a failed or interrupted reclaim left behind. The
/// gates mirror `reclaim_cgroup_state`'s own per-family flags
/// verbatim, so the sweep can never remove state a live leg still
/// owns. The result is sorted for deterministic traces.
fn census_orphans(
    keys: &[u32],
    dl_live: &HashSet<u32>,
    ul_live: &HashSet<u32>,
    leg: CensusLeg,
) -> Vec<u32> {
    let live = |k: &u32| match leg {
        CensusLeg::Download => dl_live.contains(k),
        CensusLeg::Upload => ul_live.contains(k),
        CensusLeg::Either => dl_live.contains(k) || ul_live.contains(k),
    };
    let mut orphans: Vec<u32> = keys.iter().copied().filter(|k| !live(k)).collect();
    orphans.sort_unstable();
    orphans
}

/// Verbose trace line for one census family's orphan sweep
/// (NIGHT-hunt-34): pure formatting so the wording is unit-pinned
/// beside its siblings.
fn census_sweep_trace_line(map_name: &str, reclaimed: usize) -> String {
    format!(
        "[limiter] {map_name}: reclaimed {reclaimed} orphaned {} — no policy row names it, \
         slot returned to the census budget",
        if reclaimed == 1 { "entry" } else { "entries" }
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
/// enforced. Pure so the wording is unit-pinned. NIGHT-hunt-29:
/// `pub(super)` for the unstrict family's move to its own file
/// (reclaim.rs's LOC-cap split).
pub(super) fn unstrict_partial_failure_line(removed: usize, failed: &[String]) -> String {
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
    /// referenced by every cgroup of a group-lane invocation, and no
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
            // NIGHT-hunt-Z4: the direction's delivered-rate series is
            // the same dead state its bucket is — a root whose policy
            // is gone has no reader for its ring, and the ring maps
            // are census-bounded (1024 pinned, never LRU), so an
            // unreclaimed ring stays resident until the map fills and
            // every later root's ring silently fails to create (the
            // fail-open observability loss: enforcement unaffected,
            // the status series missing).
            match self.remove_map_entry::<RateRingRaw>(
                "rate_ring_dl",
                PIN_MAP_RATE_RING_DL,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("ring dl: {e}")),
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
            // NIGHT-hunt-Z4: the upload ring rides the same per-direction
            // gate as its bucket (the dl arm's note above carries the why).
            match self.remove_map_entry::<RateRingRaw>(
                "rate_ring_ul",
                PIN_MAP_RATE_RING_UL,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("ring ul: {e}")),
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
            // night-during (schema v23): the row's window rides the
            // row's death — the stats gate is exactly "both legs
            // gone", and a window row without its policy is dead
            // census weight (the map is census-bounded: every window
            // row rides a policy row's root). An ended span reaches
            // this same removal through the sweep; an unstrict
            // reaches it directly. Best-effort beside its siblings:
            // a failed removal warns, never fails the reclaim.
            match self.remove_map_entry::<PolicyWindowRaw>(
                "policy_window",
                PIN_MAP_POLICY_WINDOW,
                cgroup_id,
            ) {
                Ok(true) => reclaimed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("window: {e}")),
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
    /// write paths in policy.rs, the unstrict loop here, and the
    /// commands-side recover handler (NIGHT-dinner-6) call it
    /// BEFORE the write/delete makes the old group id unrecoverable.
    /// Returns Ok(None) when the cgroup has no policy in that
    /// direction (fresh apply — nothing superseded) and Err only
    /// when the map could not be read (the caller skips the capture:
    /// a bucket may then outlive its group, the conservative
    /// direction — a leaked slot never bricks enforcement).
    pub fn read_policy_group(
        &mut self,
        cgroup_id: u32,
        direction: Direction,
    ) -> Result<Option<u32>> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let pin_path = self.pinned_policy_path(direction);
        self.with_u32_map::<PolicyRaw, Option<u32>>(&map_name, &pin_path, |map| {
            match map.get(&cgroup_id, 0) {
                Ok(raw) => Ok(Some(raw.group_id)),
                Err(e) if map_error_means_absent(&e) => Ok(None),
                Err(e) => Err(anyhow!(
                    "failed to read cg:{cgroup_id} {} policy: {e}",
                    direction.label()
                )),
            }
        })
    }

    /// Read a cgroup's full policy raw — the charger-core-2
    /// transactional snapshot's read half. Returns `None` when the
    /// leg is absent (fresh apply) AND when the map cannot be read
    /// (the conservative degrade: an unreadable map will refuse the
    /// writes too, and a None snapshot rolls back to a delete — the
    /// NIGHT-hunt-20 behavior, never a silent restore of invented
    /// state). Split from `read_policy_group` because the atomic
    /// snapshot needs the WHOLE raw (rate, burst, group id), not the
    /// group id alone.
    pub fn read_policy_raw(&mut self, cgroup_id: u32, direction: Direction) -> Option<PolicyRaw> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let pin_path = self.pinned_policy_path(direction);
        self.with_u32_map::<PolicyRaw, Option<PolicyRaw>>(&map_name, &pin_path, |map| {
            match map.get(&cgroup_id, 0) {
                Ok(raw) => Ok(Some(raw)),
                Err(e) if map_error_means_absent(&e) => Ok(None),
                Err(e) => Err(anyhow!(
                    "failed to read cg:{cgroup_id} {} policy: {e}",
                    direction.label()
                )),
            }
        })
        .ok()
        .flatten()
    }

    /// Sweep the census-bounded families' orphaned state
    /// (NIGHT-hunt-34, the baseline panel's retire_dead). The four
    /// per-policy-root state families — the dl/ul buckets, the dl/ul
    /// rate rings, the stats ledger, the window rows — are plain
    /// 1024-slot HashMaps whose occupancy claim is "bounded by the
    /// policy census": every removal path reclaims its own rows
    /// ([`Self::reclaim_cgroup_state`], NIGHT-hunt-Z4's rings
    /// included), but a reclaim that FAILS (best-effort by
    /// contract, a warned delete) or a crash between the policy
    /// delete and the state delete leaves the row behind with no
    /// policy naming it — invisible to every existing sweep
    /// (`recover` walks orphan POLICIES; a ring whose policy is
    /// already gone has no row to walk). The residue then does two
    /// things: it renders as a permanent ghost row on the
    /// eagle-eyes baseline panel (the TUI lane folds every key the
    /// ring read carries; the status JSON joins by policy row, the
    /// TUI does not), and it holds a 1024-slot until fresh roots'
    /// rings silently fail to create — the userspace leaderboard
    /// freeze mitigate-1 closed, un-mitigated on the kernel side.
    ///
    /// The sweep reads the policy census (both directions), then
    /// walks each family for keys no live leg owns and deletes
    /// them under the family's own gate. Fail-closed on proof: an
    /// unreadable POLICY map proves nothing dead and stands the
    /// whole sweep down (the `reclaim_dead_groups` posture); an
    /// unreadable family map only skips that family — the sweep
    /// warns and the next visit retries. Delete failures warn and
    /// never fail the caller: the sweep rides apply-family tails,
    /// the status visit, and recover, all under the operation
    /// lock. Returns the number of entries actually deleted.
    pub fn sweep_census_orphans(&mut self) -> usize {
        // The census itself: an unreadable direction proves nothing
        // orphan — keep every family's state (fail-closed for
        // reclamation, the same conservative posture as the
        // dead-group sweep's unreadable policy maps).
        let (dl, ul) = (
            self.read_policies_public(Direction::Download),
            self.read_policies_public(Direction::Upload),
        );
        let (Ok(dl), Ok(ul)) = (dl, ul) else {
            return 0;
        };
        let dl_live: HashSet<u32> = dl.iter().map(|(id, _)| *id).collect();
        let ul_live: HashSet<u32> = ul.iter().map(|(id, _)| *id).collect();

        let mut reclaimed = 0usize;
        reclaimed += self.sweep_census_family::<BucketRaw>(
            "cgroup_bucket_dl",
            PIN_MAP_BUCKET_DL,
            CensusLeg::Download,
            &dl_live,
            &ul_live,
        );
        reclaimed += self.sweep_census_family::<BucketRaw>(
            "cgroup_bucket_ul",
            PIN_MAP_BUCKET_UL,
            CensusLeg::Upload,
            &dl_live,
            &ul_live,
        );
        reclaimed += self.sweep_census_family::<RateRingRaw>(
            "rate_ring_dl",
            PIN_MAP_RATE_RING_DL,
            CensusLeg::Download,
            &dl_live,
            &ul_live,
        );
        reclaimed += self.sweep_census_family::<RateRingRaw>(
            "rate_ring_ul",
            PIN_MAP_RATE_RING_UL,
            CensusLeg::Upload,
            &dl_live,
            &ul_live,
        );
        reclaimed += self.sweep_census_family::<LimiterStatsRaw>(
            "cgroup_limiter_stats",
            PIN_MAP_STATS,
            CensusLeg::Either,
            &dl_live,
            &ul_live,
        );
        reclaimed += self.sweep_census_family::<PolicyWindowRaw>(
            "policy_window",
            PIN_MAP_POLICY_WINDOW,
            CensusLeg::Either,
            &dl_live,
            &ul_live,
        );
        reclaimed
    }

    /// One family's half of the orphan-census sweep: read the keys,
    /// hand them the pure decision core, delete what it names.
    /// Read and delete both ride the ONE acquisition lane
    /// (`with_u32_map` / `remove_map_entry` — the same lanes every
    /// other reclaim in this file flows through). A delete miss
    /// (`Ok(false)`, ENOENT) counts as landed-nothing: the state
    /// was already gone, which is all the sweep ever wanted.
    fn sweep_census_family<V: aya::Pod>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        leg: CensusLeg,
        dl_live: &HashSet<u32>,
        ul_live: &HashSet<u32>,
    ) -> usize {
        let keys: Vec<u32> = match self.with_u32_map::<V, Vec<u32>>(map_name, pin_path, |map| {
            Ok(map.iter().flatten().map(|(key, _)| key).collect())
        }) {
            Ok(keys) => keys,
            Err(e) => {
                // An unreadable family map cannot name its
                // orphans — skip it, warn, let the next visit
                // retry (best-effort beside every sweep sibling).
                eprintln_safe!("[limiter] census sweep skipped {map_name}: {e}");
                return 0;
            }
        };
        let orphans = census_orphans(&keys, dl_live, ul_live, leg);
        if orphans.is_empty() {
            return 0;
        }
        let mut landed = 0usize;
        for id in &orphans {
            match self.remove_map_entry::<V>(map_name, pin_path, *id) {
                Ok(true) => landed += 1,
                Ok(false) => {}
                Err(e) => {
                    eprintln_safe!("[limiter] census sweep: {map_name} key {id} delete failed: {e}")
                }
            }
        }
        if self.verbose && landed > 0 {
            eprintln_safe!("{}", census_sweep_trace_line(map_name, landed));
        }
        landed
    }

    /// Reclaim the shared buckets of DEAD groups (NIGHT-lts-7, the
    /// ultra-long-endurance budget's missing half). The group maps
    /// hold hard 256 slots, every group-lane invocation banks a
    /// FRESH quasi-random group id, and until now nothing ever
    /// deleted a group entry — the improve-10 reclaim deliberately
    /// skipped them ("no single removal may decide that
    /// lifecycle"), so ~256 group-lane invocations on a
    /// long-lived host filled the maps and the 257th's members
    /// silently enforced UNLIMITED (the fail-open bucket lookup).
    /// The lifecycle decision now sits where it belongs: with the
    /// LAST reference. `captured` carries the group ids read from
    /// policies being removed or overwritten (read before the
    /// write); a group whose id no LIVE policy references has its
    /// dl+ul shared-bucket slots returned. Failures warn and never
    /// fail the surrounding operation — the policies (the enforced
    /// contract) are already gone or replaced.
    ///
    /// NIGHT-dinner-6: `pub` for the third caller — the commands-side
    /// recover handler captures its orphans' group ids
    /// read-before-delete and sweeps here too (the lts-7 contract's
    /// recover half, previously missing).
    pub fn reclaim_dead_groups(&mut self, captured: &[u32]) -> usize {
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
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/reclaim_tests.rs"]
mod reclaim_tests;
