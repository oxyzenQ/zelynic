// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Policy operations — apply, resolve, and delete token-bucket
//! policies in the BPF maps (ephemeral and pinned modes). The
//! WRITE family (the per-cgroup leg writer `write_policies_for_cgroup`
//! and the row writer it bottoms out in) lives in the policy_write
//! sibling — split from here when the improve-40 guarantee bracket
//! (schema v24) pushed this file past the 500-LOC owner cap, the
//! policy_lines/during_map discipline.

use anyhow::{anyhow, Result};

// NIGHT-depthbore-1: the pure line formatters (trace wording, the
// rollback error shape, the resolution trace) live in the
// policy_lines sibling — split from here when the depthbore-1 dedup
// fix pushed this file past the 500-LOC owner cap. Re-exported so
// the pins in policy_tests (use super::*) and reclaim.rs
// (use super::policy::policy_survivor_line) see the same paths as
// before the split.
pub(super) use super::policy_lines::{
    group_apply_lines, partial_apply_failure_line, policy_survivor_line,
};

use super::atomic::PolicyMutation;
use super::during_map::{translate_now, WindowMutation};
use super::during_parse::DuringSpec;
use super::lanes::map_error_means_absent;
use super::types::{
    group_id_from, Direction, PolicyRaw, PolicyWindowRaw, RateSpec, Target, POLICY_FLAG_PER_SOCKET,
};
use crate::ebpf::pin::{PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL};

// The hunt-20 ENOENT classification lives in reclaim.rs; the hunt-9
// trace/rollback line formatters in policy_lines.rs (re-exported above).

impl super::Limiter {
    /// Apply strict-single: individual policy per cgroup.
    /// `target` is resolved to cgroup IDs. Each gets its own token bucket.
    /// `during` (night-during, schema v23): the row's time window —
    /// `Some(spec)` writes the window beside the legs, `None`
    /// removes any existing one (the improve-29 law one level up:
    /// a fresh forever-row must never inherit a dead deadline).
    pub fn apply_single(
        &mut self,
        target: &Target,
        rates: &RateSpec,
        per_socket: bool,
        floor_bps: u64,
        ceil_bps: u64,
        during: Option<&DuringSpec>,
    ) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        if cgroup_ids.is_empty() {
            return Ok(0);
        }

        // night-during: the bridge stamps FIRST (a fresh daily row
        // must evaluate against a fresh offset), then the window —
        // translated once per invocation, every cgroup row shares
        // it. The stamp rides EVERY apply-family mutation: the CLI
        // visit IS the refresh channel (the design brief's drift
        // residue, re-zeroed here).
        self.stamp_wall_clock_offset()?;
        let window: Option<PolicyWindowRaw> = during.map(translate_now);

        // NIGHT-hunt-20: strict all-or-nothing — every mutation of
        // THIS invocation is recorded so a mid-flight failure (map
        // full at 1024, ENOMEM, ...) rolls the whole apply back,
        // never an enforced prefix. The superseded-group ledger
        // (NIGHT-lts-7) rides the same lifecycle; charger-core-2:
        // the ledger carries each leg's PRE-APPLY raw, so the
        // rollback RESTORES an overwritten limit.
        let mut mutations: Vec<PolicyMutation> = Vec::new();
        let mut window_mutations: Vec<WindowMutation> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                floor_bps,
                ceil_bps,
                0,
                if per_socket {
                    POLICY_FLAG_PER_SOCKET
                } else {
                    0
                },
                &mut mutations,
                &mut superseded,
                window.as_ref(),
                &mut window_mutations,
            ) {
                Ok(n) => applied += n,
                Err(cause) => {
                    // research-2 / perf-0: the rollback still
                    // MUTATED the maps, and the generation bump is
                    // the memo's only addition-side invalidation —
                    // it runs AFTER the restorations land (writes
                    // AND rollback, one stamp), never failing the
                    // rollback verdict.
                    let rolled_back = self.rollback_mutations(&mutations, &window_mutations, cause);
                    self.ammsp_memo_invalidate_best_effort();
                    return Err(rolled_back);
                }
            }
        }
        self.reclaim_dead_groups(&superseded);

        // night-during (schema v23): the lazy sweep — every
        // apply-family mutation drives ended spans through the
        // unstrict machinery (the CLI visit IS the daemon's clock).
        // Before the memo bump on purpose: the sweep's deletions
        // retire under the same generation stamp.
        self.sweep_expired_windows_best_effort();

        // AMMSP memo invalidation (research-2 / perf-0): the fresh
        // policies may cover leaves whose cached resolution is
        // stale — the walk sees only the live map, so the generation
        // bump makes the addition visible; once per invocation.
        self.ammsp_memo_invalidate_best_effort();

        Ok(applied)
    }

    /// Apply strict-multi: all cgroups share one group token bucket
    /// (a random group_id; every policy points at it). `during` is
    /// the row's window (night-during, schema v23) — every member
    /// root carries the same window row.
    pub fn apply_group(
        &mut self,
        targets: &[Target],
        rates: &RateSpec,
        floor_bps: u64,
        ceil_bps: u64,
        during: Option<&DuringSpec>,
    ) -> Result<usize> {
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

        // night-during: the same per-invocation shape apply_single
        // owns — stamp the bridge, translate the window once, share
        // it across every member root.
        self.stamp_wall_clock_offset()?;
        let window: Option<PolicyWindowRaw> = during.map(translate_now);

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
        let mut window_mutations: Vec<WindowMutation> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                floor_bps,
                ceil_bps,
                group_id,
                0,
                &mut mutations,
                &mut superseded,
                window.as_ref(),
                &mut window_mutations,
            ) {
                Ok(n) => applied += n,
                Err(cause) => {
                    // Same NIGHT-private-research-2 / perf-0 contract
                    // as apply_single's error path: the rollback
                    // still mutated, so the bump runs after its
                    // restorations.
                    let rolled_back = self.rollback_mutations(&mutations, &window_mutations, cause);
                    self.ammsp_memo_invalidate_best_effort();
                    return Err(rolled_back);
                }
            }
        }
        self.reclaim_dead_groups(&superseded);

        // night-during: the lazy sweep (apply_single's note).
        self.sweep_expired_windows_best_effort();

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

    /// The sweep's best-effort wrapper: the apply family calls this
    /// AFTER its own writes land, so a sweep failure warns and never
    /// fails the apply that triggered it (sweep_expired_windows'
    /// contract, one call-site shape).
    pub(super) fn sweep_expired_windows_best_effort(&mut self) {
        if let Err(e) = self.sweep_expired_windows() {
            eprintln_safe!("[limiter] window sweep skipped: {e}");
        }
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
            Err(e) if map_error_means_absent(&e) => Ok(false),
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
