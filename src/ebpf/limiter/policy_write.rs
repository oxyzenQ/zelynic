// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The policy WRITE family — the per-cgroup leg writer and the map
//! acquisition it routes through, split from policy.rs when the
//! improve-40 guarantee bracket (schema v24: floor_bps/ceil_bps
//! riding the row) pushed the parent past the 500-LOC owner cap —
//! the same split discipline that produced policy_lines and
//! during_map before it. The apply family (the transactional
//! orchestration that calls `write_policies_for_cgroup`) stays in
//! policy.rs; everything here is one rung lower: shape the raw row,
//! route the map, record the mutation ledger entries.

use anyhow::{Result, anyhow};
use aya::maps::{HashMap as BpfHashMap, MapData};

use super::atomic::PolicyMutation;
use super::during_map::WindowMutation;
use super::format::default_burst;
use super::policy_lines::policy_write_line;
use super::types::{
    BracketSpec, Direction, MAX_ENFORCABLE_BURST, PolicyRaw, PolicyWindowRaw, RateSpec,
};

impl super::Limiter {
    /// Write the dl + ul policies for one cgroup, recording each
    /// successful write in `written` — the rollback ledger
    /// (NIGHT-hunt-20) — and the group id of every policy this call
    /// OVERWRITES or removes in `superseded` (NIGHT-lts-7: the
    /// capture-before-write half of the dead-group reclaim — read
    /// here, because after the write the old group id is
    /// unrecoverable). Returns how many policies this cgroup received.
    /// `window` (night-during, schema v23): the row's window state
    /// this invocation sets — `Some(raw)` writes it beside the legs,
    /// `None` removes any existing entry (the improve-29 law one
    /// level up), the pre-apply row captured into
    /// `window_mutations` for the atomic rollback.
    /// `bracket` (improve-40, schema v24; improve-40-b the
    /// per-direction shape): the guarantee pair each direction's leg
    /// carries — its OWN pair, so the asymmetric link's spellings
    /// land per leg (the one-flag law's both-pairs when `--floor`
    /// set both).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_policies_for_cgroup(
        &mut self,
        cgroup_id: u32,
        rates: &RateSpec,
        bracket: &BracketSpec,
        group_id: u32,
        flags: u32,
        mutations: &mut Vec<PolicyMutation>,
        superseded: &mut Vec<u32>,
        window: Option<&PolicyWindowRaw>,
        window_mutations: &mut Vec<WindowMutation>,
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
            self.write_policy(
                cgroup_id,
                dl_rate,
                bracket.download.floor_bps,
                bracket.download.ceil_bps,
                group_id,
                flags,
                Direction::Download,
            )?;
            mutations.push(PolicyMutation {
                cgroup_id,
                direction: Direction::Download,
                previous: previous[0],
            });
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(
                        cgroup_id,
                        Direction::Download,
                        dl_rate,
                        bracket.download.floor_bps,
                        bracket.download.ceil_bps,
                    )
                );
            }
            applied += 1;
        }

        if let Some(ul_rate) = rates.upload {
            if let Some(old) = previous[1] {
                superseded.push(old.group_id);
            }
            self.write_policy(
                cgroup_id,
                ul_rate,
                bracket.upload.floor_bps,
                bracket.upload.ceil_bps,
                group_id,
                flags,
                Direction::Upload,
            )?;
            mutations.push(PolicyMutation {
                cgroup_id,
                direction: Direction::Upload,
                previous: previous[1],
            });
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(
                        cgroup_id,
                        Direction::Upload,
                        ul_rate,
                        bracket.upload.floor_bps,
                        bracket.upload.ceil_bps,
                    )
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

        // night-during (schema v23): the row's window, set wholesale
        // by THIS invocation the way the legs above are — `Some`
        // writes the row beside them, `None` removes any existing
        // entry so a fresh forever-row never inherits a dead
        // deadline. AFTER the legs on purpose: a failed leg write
        // rolls back before the window is ever touched, and the
        // mutation capture below rides only what actually landed
        // (a failed window write leaves the pre-apply row intact,
        // so no rollback entry exists to need).
        let previous_window = self.read_policy_window(cgroup_id)?;
        match window {
            Some(raw) => self.write_policy_window(cgroup_id, *raw)?,
            None => {
                self.remove_policy_window(cgroup_id)?;
            }
        }
        window_mutations.push(WindowMutation {
            cgroup_id,
            previous: previous_window,
        });

        Ok(applied)
    }

    /// Access the policy map for `direction` in whichever mode is
    /// live and run `op` on it — delegates to `with_u32_map` in
    /// reclaim.rs (the ONE acquisition path for every u32-keyed
    /// limiter map; hunt-20 introduced it for policies, improve-10
    /// widened it to bucket + stats). The write family's own rung:
    /// policy.rs's delete/restore reach it from one module over.
    pub(super) fn with_policy_map<R>(
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
    // improve-40 (schema v24): the bracket pair joins the rate
    // family's travel — the same too-many-arguments posture
    // write_policies_for_cgroup carries one rung up.
    #[allow(clippy::too_many_arguments)]
    fn write_policy(
        &mut self,
        cgroup_id: u32,
        rate_bps: u64,
        floor_bps: u64,
        ceil_bps: u64,
        group_id: u32,
        flags: u32,
        direction: Direction,
    ) -> Result<()> {
        let burst = default_burst(rate_bps).min(MAX_ENFORCABLE_BURST);
        let raw = PolicyRaw {
            rate_bps,
            burst_bytes: burst,
            floor_bps,
            ceil_bps,
            group_id,
            flags,
        };
        self.with_policy_map(direction, |map| {
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))
        })
    }
}
