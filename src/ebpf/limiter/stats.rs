// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Status readers — policy/stats/watchdog map access, status printing
//! (human + JSON), and identity accessors.

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as BpfArray, HashMap as BpfHashMap};

use super::types::{Direction, LimiterStatsRaw, PolicyRaw};
use crate::ebpf::pin::{self, PIN_MAP_STATS, PIN_MAP_WATCHDOG};

impl super::Limiter {
    /// Print status: active limits + watchdog.
    ///
    /// NIGHT-hunt-22: read failures PROPAGATE. Callers gate on
    /// `is_pinned()` first, so a failed map read here is an anomaly —
    /// rendering "Active limits: none" from it would fabricate the
    /// exact opposite of the enforced truth on the one surface owners
    /// use to check it.
    pub fn print_status(&self) -> Result<()> {
        let dl = self.read_policies(Direction::Download)?;
        let ul = self.read_policies(Direction::Upload)?;
        let stats = self.read_stats()?;
        let wd = self.read_watchdog()?;
        crate::ebpf::display::print_status(&dl, &ul, &stats, &self.identity, wd);
        Ok(())
    }

    /// Print status as JSON (for --print-json).
    ///
    /// Same contract as `print_status` (NIGHT-hunt-22): the JSON
    /// surface feeds scripts, so a failed read must exit non-zero
    /// instead of emitting `{"active_limits": 0, "limits": []}` —
    /// automation would read that as "nothing is limited".
    pub fn print_status_json(&self) -> Result<()> {
        let dl = self.read_policies(Direction::Download)?;
        let ul = self.read_policies(Direction::Upload)?;
        let stats = self.read_stats()?;
        let wd = self.read_watchdog()?;
        crate::ebpf::display::print_status_json(&dl, &ul, &stats, &self.identity, wd)
    }

    /// Read all policies from a direction map.
    fn read_policies(&self, direction: Direction) -> Result<Vec<(u32, PolicyRaw)>> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf
                .map(&map_name)
                .context(format!("{map_name} not found"))?,
            None => {
                pinned = pin::open_pinned_hash_map(&self.pinned_policy_path(direction))?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, PolicyRaw> =
            BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read enforcement stats.
    fn read_stats(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf
                .map("cgroup_limiter_stats")
                .context("cgroup_limiter_stats not found")?,
            None => {
                pinned = pin::open_pinned_hash_map(PIN_MAP_STATS)?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, LimiterStatsRaw> =
            BpfHashMap::try_from(map_ref).context("Failed to access cgroup_limiter_stats")?;
        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read current watchdog deadline.
    ///
    /// `Ok(None)` is kept for the display contract (rendered the same
    /// as deadline 0, "not armed"). NIGHT-hunt-22: a failed read is an
    /// `Err`, never a fabricated "absent" — the old `Err(_) => Ok(None)`
    /// turned an unreadable watchdog into "Watchdog: not set", the
    /// display-side twin of the hunt-20 delete conflation.
    pub fn read_watchdog(&self) -> Result<Option<u64>> {
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf
                .map("watchdog_deadline")
                .context("watchdog_deadline not found")?,
            None => {
                pinned = pin::open_pinned_array_map(PIN_MAP_WATCHDOG)?;
                &pinned
            }
        };
        let map: BpfArray<_, u64> =
            BpfArray::try_from(map_ref).context("Failed to access watchdog_deadline")?;
        let index: u32 = 0;
        map.get(&index, 0)
            .map(Some)
            .map_err(|e| anyhow!("watchdog_deadline read: {e}"))
    }

    /// Read all policies from a direction map (public for status display).
    pub fn read_policies_public(&self, direction: Direction) -> Result<Vec<(u32, PolicyRaw)>> {
        self.read_policies(direction)
    }

    /// Read enforcement stats (public for the eagle-eyes --depth
    /// accounting verdict, NIGHT-blade-5): the per-cgroup ledger the
    /// kernel books under enforcement — packets/bytes allowed and
    /// dropped. Same honest-read contract as every public reader
    /// here: a failed map read propagates, never a fabricated zero.
    pub fn read_stats_public(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        self.read_stats()
    }

    /// Borrow identity map.
    pub fn identity(&self) -> &crate::ebpf::identity::IdentityMap {
        &self.identity
    }

    /// Force-refresh identity map. Returns number of cgroups resolved.
    pub fn refresh_identity(&mut self) -> usize {
        self.identity.refresh()
    }
}
