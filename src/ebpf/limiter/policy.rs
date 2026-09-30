// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Policy operations — apply, resolve, write, and delete token-bucket
//! policies in the BPF maps (ephemeral and pinned modes).

use anyhow::{anyhow, Result};
use aya::maps::{HashMap as BpfHashMap, MapData};

// NIGHT-depthbore-1: the pure line formatters (trace wording, the
// rollback error shape, the resolution trace) live in the
// policy_lines sibling — split from here when the depthbore-1 dedup
// fix pushed this file past the 500-LOC owner cap. Re-exported so
// the pins in policy_tests (use super::*) and reclaim.rs
// (use super::policy::policy_survivor_line) see the same paths as
// before the split.
pub(super) use super::policy_lines::{
    group_apply_lines, partial_apply_failure_line, policy_survivor_line, policy_write_line,
    resolution_trace_line,
};

use super::atomic::PolicyMutation;
use super::format::default_burst;
use super::lanes::map_remove_means_absent;
use super::types::{
    group_id_from, Direction, PolicyRaw, RateSpec, Target, MAX_ENFORCABLE_BURST,
    POLICY_FLAG_PER_SOCKET,
};
use crate::ebpf::pin::{PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL};

// The hunt-20 ENOENT classification lives in reclaim.rs; the hunt-9
// trace/rollback line formatters in policy_lines.rs (re-exported above).

impl super::Limiter {
    /// Apply strict-single: individual policy per cgroup.
    /// `target` is resolved to cgroup IDs. Each gets its own token bucket.
    pub fn apply_single(
        &mut self,
        target: &Target,
        rates: &RateSpec,
        per_socket: bool,
    ) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        if cgroup_ids.is_empty() {
            return Ok(0);
        }

        // NIGHT-hunt-20: strict all-or-nothing — every mutation of
        // THIS invocation is recorded so a mid-flight failure (map
        // full at 1024, ENOMEM, ...) rolls the whole apply back,
        // never an enforced prefix. The superseded-group ledger
        // (NIGHT-lts-7) rides the same lifecycle; charger-core-2:
        // the ledger carries each leg's PRE-APPLY raw, so the
        // rollback RESTORES an overwritten limit.
        let mut mutations: Vec<PolicyMutation> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                0,
                if per_socket {
                    POLICY_FLAG_PER_SOCKET
                } else {
                    0
                },
                &mut mutations,
                &mut superseded,
            ) {
                Ok(n) => applied += n,
                Err(cause) => {
                    // research-2 / perf-0: the rollback still
                    // MUTATED the maps, and the generation bump is
                    // the memo's only addition-side invalidation —
                    // it runs AFTER the restorations land (writes
                    // AND rollback, one stamp), never failing the
                    // rollback verdict.
                    let rolled_back = self.rollback_mutations(&mutations, cause);
                    self.ammsp_memo_invalidate_best_effort();
                    return Err(rolled_back);
                }
            }
        }
        self.reclaim_dead_groups(&superseded);

        // AMMSP memo invalidation (research-2 / perf-0): the fresh
        // policies may cover leaves whose cached resolution is
        // stale — the walk sees only the live map, so the generation
        // bump makes the addition visible; once per invocation.
        self.ammsp_memo_invalidate_best_effort();

        Ok(applied)
    }

    /// Apply strict-multi: all cgroups share one group token bucket
    /// (a random group_id; every policy points at it).
    pub fn apply_group(&mut self, targets: &[Target], rates: &RateSpec) -> Result<usize> {
        // Resolve all targets to cgroup IDs (resolve_target prints
        // its own trace, so an unresolved target needs no second skip line).
        let mut all_cgroup_ids: Vec<u32> = Vec::new();
        for target in targets {
            let ids = self.resolve_target(target)?;
            if ids.is_empty() {
                continue;
            }
            all_cgroup_ids.extend(ids);
        }

        // NIGHT-depthbore-1 (the end-to-end depth audit): dedup across
        // targets, first-seen order. Two targets can name the SAME
        // cgroup by different spellings (`sm brave:brave`, or
        // `sm cg:123/12345` where brave lives in cg:123) — the old
        // loop wrote every duplicate twice: harmless on the map key,
        // but it inflated the applied-policy count, double-pushed the
        // superseded-group ledger, and double-printed the trace.
        // One cgroup, one write, one count.
        let mut seen_cgroups = std::collections::HashSet::new();
        all_cgroup_ids.retain(|id| seen_cgroups.insert(*id));

        if all_cgroup_ids.is_empty() {
            return Ok(0);
        }

        // Generate group_id: the NIGHT-master-3 mixer (types.rs —
        // splitmix64 over (pid, nanos), unit-pinned; the old
        // pid*1000+nanos%1000 banded same-pid ids into 1000 and
        // collided on pid wrap: two groups then shared ONE bucket,
        // and the mix never yields the 0 individual sentinel).
        let group_id = group_id_from(
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );

        // Same rollback ledger as apply_single (NIGHT-hunt-20): a
        // group with a partial member list would point at a bucket
        // some members never share, so a mid-flight failure must not
        // leave group orphans behind. The superseded-group ledger
        // (NIGHT-lts-7) is why this path matters most: every
        // strict-multi invocation banks a FRESH group id, so the
        // overwritten members' OLD groups die here — without the
        // sweep the 256-slot group maps filled irreversibly and the
        // 257th invocation silently enforced unlimited. The
        // charger-core-2 mutation ledger upgrades the rollback to
        // RESTORE each leg's pre-apply raw.
        let mut mutations: Vec<PolicyMutation> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                group_id,
                0,
                &mut mutations,
                &mut superseded,
            ) {
                Ok(n) => applied += n,
                Err(cause) => {
                    // Same NIGHT-private-research-2 / perf-0 contract
                    // as apply_single's error path: the rollback
                    // still mutated, so the bump runs after its
                    // restorations.
                    let rolled_back = self.rollback_mutations(&mutations, cause);
                    self.ammsp_memo_invalidate_best_effort();
                    return Err(rolled_back);
                }
            }
        }
        self.reclaim_dead_groups(&superseded);

        // AMMSP memo invalidation (NIGHT-private-research-2,
        // generation-stamped by NIGHT-perf-0) — same
        // once-per-invocation tail as apply_single's.
        self.ammsp_memo_invalidate_best_effort();

        if self.verbose {
            for line in group_apply_lines(group_id, rates, all_cgroup_ids.len()) {
                eprintln_safe!("{line}");
            }
        }

        Ok(applied)
    }

    /// Resolve a target to cgroup IDs. Process names do a DIRECT
    /// /proc walk (not the identity cache) to find all PIDs matching
    /// the name, then their cgroup IDs — the fix for aria2c sharing
    /// a cgroup with alacritty (first-pid-wins lied).
    pub(super) fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => {
                if self.verbose {
                    eprintln_safe!("[limiter] cg:{id} targeted directly (no /proc walk)");
                }
                Ok(vec![*id])
            }
            Target::Container(c) => {
                // charger-core-2 (TIER A #5): resolve-only — the URI
                // becomes the workload's cgroup id, the rest is the
                // strict-single machinery (specific infrastructure errors,
                // never the generic no-match; the trace is resolve's own).
                crate::ebpf::identity::container::resolve(c, self.verbose)
            }
            Target::ProcessName(name) => {
                // Direct /proc walk: find all PIDs whose comm matches.
                let name_lower = name.to_lowercase();
                let mut cgroup_ids = Vec::new();
                let mut seen = std::collections::HashSet::new();
                // Verbose evidence (NIGHT-hunt-9): every (pid,
                // cgroup) pair the walk accepted, including multiple
                // pids sharing one cgroup (NIGHT-hunt-8's lie).
                let mut matched: Vec<(u32, u32)> = Vec::new();

                let proc_entries = match std::fs::read_dir("/proc") {
                    Ok(e) => e,
                    Err(_) => return Ok(Vec::new()),
                };

                for entry in proc_entries.flatten() {
                    let pid_str = entry.file_name();
                    let pid_str = match pid_str.to_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    let pid: u32 = match pid_str.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // Read comm through the canonical boundary
                    // (NIGHT-optimized-1): pid_comm() sanitizes, so
                    // matching operates on the same canonical label
                    // list-apps displays — a prctl-spoofed comm can
                    // never display one thing and match another.
                    let Some(comm) = crate::ebpf::identity::pid_comm(pid) else {
                        continue;
                    };
                    let comm = comm.to_lowercase();

                    if comm != name_lower {
                        continue;
                    }

                    // Cgroup membership through the same canonical
                    // boundary (NIGHT-optimized-1): one pid-to-cgroup
                    // resolution shared with the identity walk and the
                    // connection walk.
                    let Some(cgroup_id) = crate::ebpf::identity::pid_cgroup_id(pid) else {
                        continue;
                    };

                    matched.push((pid, cgroup_id));
                    if seen.insert(cgroup_id) {
                        cgroup_ids.push(cgroup_id);
                    }
                }

                if self.verbose {
                    eprintln_safe!("{}", resolution_trace_line(name, &matched));
                }

                // Also refresh identity map for display purposes.
                self.identity.maybe_refresh();

                Ok(cgroup_ids)
            }
        }
    }

    /// Write the dl + ul policies for one cgroup, recording each
    /// successful write in `written` — the rollback ledger
    /// (NIGHT-hunt-20) — and the group id of every policy this call
    /// OVERWRITES or removes in `superseded` (NIGHT-lts-7: the
    /// capture-before-write half of the dead-group reclaim — read
    /// here, because after the write the old group id is
    /// unrecoverable). Returns how many policies this cgroup received.
    pub(super) fn write_policies_for_cgroup(
        &mut self,
        cgroup_id: u32,
        rates: &RateSpec,
        group_id: u32,
        flags: u32,
        mutations: &mut Vec<PolicyMutation>,
        superseded: &mut Vec<u32>,
    ) -> Result<usize> {
        let mut applied = 0usize;

        // charger-core-2 (TIER A #6): the transactional snapshot —
        // BOTH directions read before the first mutation of this
        // cgroup, so a mid-flight failure restores the exact
        // pre-apply state (an overwritten limit comes back at its
        // own rate and group) instead of the hunt-20 delete-only
        // rollback that stripped earlier limits. The superseded-group
        // capture rides the same reads; an absent OR unreadable leg
        // snapshots as None (None rolls back to a delete, the
        // pre-2 behavior).
        let previous = [
            self.read_policy_raw(cgroup_id, Direction::Download),
            self.read_policy_raw(cgroup_id, Direction::Upload),
        ];

        if let Some(dl_rate) = rates.download {
            if let Some(old) = previous[0] {
                superseded.push(old.group_id);
            }
            self.write_policy(cgroup_id, dl_rate, group_id, flags, Direction::Download)?;
            mutations.push(PolicyMutation {
                cgroup_id,
                direction: Direction::Download,
                previous: previous[0],
            });
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(cgroup_id, Direction::Download, dl_rate)
                );
            }
            applied += 1;
        }

        if let Some(ul_rate) = rates.upload {
            if let Some(old) = previous[1] {
                superseded.push(old.group_id);
            }
            self.write_policy(cgroup_id, ul_rate, group_id, flags, Direction::Upload)?;
            mutations.push(PolicyMutation {
                cgroup_id,
                direction: Direction::Upload,
                previous: previous[1],
            });
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(cgroup_id, Direction::Upload, ul_rate)
                );
            }
            applied += 1;
        }

        // NIGHT-improve-29 (the floor run's hunt find): a direction
        // the spec leaves unset is REMOVED, not left stale — the old
        // shape silently kept the already-enforced leg (`ss brave
        // 100kb` then `ss brave -d 1mb` left upload at 100kb),
        // violating "-d ... limits download only" (USAGE.md) and
        // doubling the depth-battery window on the 5.15 floor run
        // (ledger 200.7% of client bytes — the 2x signature).
        // The removals run AFTER the writes on purpose: a failed
        // write rolls back only what THIS invocation wrote, the
        // hunt-20 all-or-nothing contract. A failed removal is
        // best-effort, never silent: the survivor is named on
        // stderr, visible in `status`.
        for (unset, (direction, prev)) in [
            (rates.download.is_none(), (Direction::Download, previous[0])),
            (rates.upload.is_none(), (Direction::Upload, previous[1])),
        ] {
            if !unset {
                continue;
            }
            // The unset-leg removal is also a group supersession
            // (NIGHT-lts-7): capture before the delete, the same
            // read-before-write the fresh writes above carry.
            if let Some(old) = prev {
                superseded.push(old.group_id);
            }
            // charger-core-2: the mutation is recorded BEFORE the
            // delete — the delete destroys the pre-apply value the
            // rollback restores.
            mutations.push(PolicyMutation {
                cgroup_id,
                direction,
                previous: prev,
            });
            match self.delete_policy(cgroup_id, direction) {
                Ok(_) => {
                    // Gone — deleted here or already ENOENT-absent.
                    // Reclaim the bucket (and the stats entry when
                    // both directions are gone — unreachable from
                    // the CLI, which rejects no-rate applies, but
                    // correct for any future caller): the same
                    // NIGHT-improve-10 reclamation the unstrict path
                    // runs, so an apply can never strand state the
                    // remove path would have reclaimed.
                    let (dl_gone, ul_gone) = match direction {
                        Direction::Download => (true, rates.upload.is_none()),
                        Direction::Upload => (rates.download.is_none(), true),
                    };
                    let reclaimed =
                        self.reclaim_cgroup_state(cgroup_id, dl_gone, ul_gone, dl_gone && ul_gone);
                    if reclaimed != 0 {
                        self.print_reclaim_trace(cgroup_id, reclaimed);
                    }
                }
                Err(e) => {
                    eprintln_safe!(
                        "[limiter] Apply: cg:{cgroup_id} stale {} leg not removed: {e}",
                        direction.label()
                    );
                }
            }
        }

        Ok(applied)
    }

    /// Re-insert one pre-apply policy VERBATIM — the atomic
    /// rollback's restore half (charger-core-2). The raw came FROM
    /// the map (rate, burst, group id — the exact enforced state the
    /// snapshot read), so no re-derivation is honest: the restored
    /// limit is byte-identical to the pre-apply state. The mutation
    /// ledger and the rollback loop live in atomic.rs (the TIER A #6
    /// split, holding this file under the owner cap).
    pub(super) fn restore_policy(
        &mut self,
        cgroup_id: u32,
        direction: Direction,
        raw: PolicyRaw,
    ) -> Result<()> {
        self.with_policy_map(direction, |map| {
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to restore policy: {e}"))
        })
    }

    /// Access the policy map for `direction` in whichever mode is
    /// live and run `op` on it — delegates to `with_u32_map` in
    /// reclaim.rs (the ONE acquisition path for every u32-keyed
    /// limiter map; hunt-20 introduced it for policies, improve-10
    /// widened it to bucket + stats).
    fn with_policy_map<R>(
        &mut self,
        direction: Direction,
        op: impl FnOnce(&mut BpfHashMap<&mut MapData, u32, PolicyRaw>) -> Result<R>,
    ) -> Result<R> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let pin_path = self.pinned_policy_path(direction);
        self.with_u32_map::<PolicyRaw, R>(&map_name, &pin_path, op)
    }

    /// Write a policy to the appropriate BPF map.
    ///
    /// Write-side half of the security-3 contract: `default_burst`
    /// clamps to 100 MB today; a future burst source must not write
    /// past the bound the BPF side clamps at (the shared mirror).
    fn write_policy(
        &mut self,
        cgroup_id: u32,
        rate_bps: u64,
        group_id: u32,
        flags: u32,
        direction: Direction,
    ) -> Result<()> {
        let burst = default_burst(rate_bps).min(MAX_ENFORCABLE_BURST);
        let raw = PolicyRaw {
            rate_bps,
            burst_bytes: burst,
            group_id,
            flags,
        };
        self.with_policy_map(direction, |map| {
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))
        })
    }

    /// Delete a policy from BPF map.
    ///
    /// Returns `Ok(true)` if deleted, `Ok(false)` if the cgroup has no
    /// policy in that map (ENOENT — genuinely absent), and `Err` when
    /// the delete could not be performed (map open failure, or a
    /// non-ENOENT syscall error). An errored delete means the policy
    /// may still be enforced, so callers must surface it — never count
    /// it as "not found" (NIGHT-hunt-20).
    pub fn delete_policy(&mut self, cgroup_id: u32, direction: Direction) -> Result<bool> {
        self.with_policy_map(direction, |map| match map.remove(&cgroup_id) {
            Ok(()) => Ok(true),
            Err(e) if map_remove_means_absent(&e) => Ok(false),
            Err(e) => Err(anyhow!(
                "failed to delete cg:{cgroup_id} {} policy: {e}",
                direction.label()
            )),
        })
    }

    /// Get the pin path for a policy map.
    pub(super) fn pinned_policy_path(&self, direction: Direction) -> String {
        match direction {
            Direction::Download => PIN_MAP_POLICY_DL.to_string(),
            Direction::Upload => PIN_MAP_POLICY_UL.to_string(),
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired (Pattern C).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/policy_tests.rs"]
mod policy_tests;
