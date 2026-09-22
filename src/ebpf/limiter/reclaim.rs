// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! State reclamation — the generic u32-keyed map plumbing and the
//! bucket/stats reclaim path that keeps the 1024-slot maps
//! proportional to live policies (NIGHT-improve-10, the LTS
//! endurance budget).
//!
//! Split from policy.rs to hold the module under the 500-LOC cap
//! (check-loc policy): apply/remove semantics stay in policy.rs,
//! the map-access plumbing and reclamation they share live here.

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData, MapError};

use super::types::{BucketRaw, LimiterStatsRaw};
use crate::ebpf::pin::{self, PIN_MAP_BUCKET_DL, PIN_MAP_BUCKET_UL, PIN_MAP_STATS};

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
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/reclaim_tests.rs"]
mod reclaim_tests;
