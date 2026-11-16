// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Status readers — policy/stats/watchdog map access, status printing
//! (human + JSON), and identity accessors.

use anyhow::{Context, Result, anyhow};
use aya::maps::{Array as BpfArray, HashMap as BpfHashMap};

use aya::maps::PerCpuArray as BpfPerCpuArray;

use super::hist::HistRowRaw;
use super::selfcost::{SelfCostFolded, SelfCostRowRaw, fold_self_cost};
use super::types::{BucketRaw, Direction, LimiterStatsRaw, PolicyRaw};
use crate::ebpf::display::recwn_lane;
use crate::ebpf::pin::{
    self, PIN_MAP_BUCKET_DL, PIN_MAP_BUCKET_UL, PIN_MAP_DEPTH_HIST_DL, PIN_MAP_DEPTH_HIST_UL,
    PIN_MAP_SELF_COST, PIN_MAP_STATS, PIN_MAP_WATCHDOG, PIN_PROG_RECWN,
};

impl super::Limiter {
    /// Print status: active limits + watchdog.
    ///
    /// NIGHT-hunt-22: read failures PROPAGATE. Callers gate on
    /// `is_pinned()` first, so a failed map read here is an anomaly —
    /// rendering "Active limits: none" from it would fabricate the
    /// exact opposite of the enforced truth on the one surface owners
    /// use to check it.
    pub fn print_status(&self) -> Result<()> {
        let started = std::time::Instant::now();
        let dl = self.read_policies(Direction::Download)?;
        let ul = self.read_policies(Direction::Upload)?;
        let stats = self.read_stats()?;
        let wd = self.read_watchdog()?;
        // night-during (schema v23): the window join rides the same
        // read pass — an absent-lens read (missing pin reads as
        // empty, the row renders without its lifetime line, never a
        // failed status for a monitor-only map).
        let windows = self.read_policy_windows_all().unwrap_or_default();
        // night-spark-2 (RECWN, schema v25): the lane's derivation
        // rides the same read pass — planted is the sock_ops
        // program pin's existence (is_pinned's own lane check), and
        // the window comes from the download census already in hand.
        let recwn = recwn_lane(
            &dl,
            &stats,
            std::path::PathBuf::from(PIN_PROG_RECWN).exists(),
        );
        // night-ux-2: the -v read summary — the counts the read pass
        // just produced, traced before the table (the identity walk's
        // size, the policy census and the cgroups it spans, the
        // read's own cost). Two or three informative lines, not a
        // datapath trace — status is a read-only surface. Read
        // failures propagate above (NIGHT-hunt-22): the error
        // surfaces named through the CLI error lane, and the trace
        // only ever prints what it actually read.
        if crate::output::verbose::enabled() {
            let mut cgroups = std::collections::BTreeSet::new();
            for (id, _) in &dl {
                cgroups.insert(*id);
            }
            for (id, _) in &ul {
                cgroups.insert(*id);
            }
            crate::output::verbose::vlog!(
                "status",
                "identity walk: {} live cgroups",
                self.identity.len()
            );
            crate::output::verbose::vlog!(
                "status",
                "policy read: {} rows across {} cgroups",
                dl.len() + ul.len(),
                cgroups.len()
            );
            crate::output::verbose::vlog!(
                "status",
                "read pass: {} ms",
                crate::ebpf::trace::ms(started.elapsed())
            );
        }
        crate::ebpf::display::print_status(&dl, &ul, &stats, &self.identity, wd, &windows, &recwn);
        Ok(())
    }

    /// Print status as JSON (for --print-json).
    ///
    /// Same contract as `print_status` (NIGHT-hunt-22): the JSON
    /// surface feeds scripts, so a failed read must exit non-zero
    /// instead of emitting `{"active_limits": 0, "limits": []}` —
    /// automation would read that as "nothing is limited". The
    /// RING read is the one deliberate exception (charger-core-3a):
    /// it rides the absent-lens contract (rate_ring.rs) — an
    /// unreadable ring is a missing lens on truth that stays true,
    /// not a failed read of enforced state.
    pub fn print_status_json(&self) -> Result<()> {
        let dl = self.read_policies(Direction::Download)?;
        let ul = self.read_policies(Direction::Upload)?;
        let stats = self.read_stats()?;
        let wd = self.read_watchdog()?;
        let rings = self.read_rate_rings();
        // night-during: the absent-lens window join (print_status's
        // own note owns the why).
        let windows = self.read_policy_windows_all().unwrap_or_default();
        // night-spark-2 (RECWN): the lane derivation, print_status's
        // own read pass — one census, both surfaces.
        let recwn = recwn_lane(
            &dl,
            &stats,
            std::path::PathBuf::from(PIN_PROG_RECWN).exists(),
        );
        crate::ebpf::display_json::print_status_json(
            &dl,
            &ul,
            &stats,
            &self.identity,
            wd,
            &rings,
            &windows,
            &recwn,
        )
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

    /// Read the DRR pool's current token count for one policy root
    /// and direction (NIGHT-hunt-Z7, the verify block's budget-truth
    /// read): the bucket the datapath actually draws from, so the
    /// probe's report can say what the bucket HELD when the window
    /// opened instead of only the nominal burst. `Ok(None)` is the
    /// honest absence (no bucket entry yet — a fresh pin with idle
    /// traffic, the same posture as an absent stats row); `Err` means
    /// unreadable, and the caller skips the diagnostic clause — a
    /// best-effort read must never fail the probe it decorates.
    pub fn read_pool_tokens(&self, root: u32, direction: Direction) -> Result<Option<u64>> {
        let (map_name, pin_path) = match direction {
            Direction::Download => ("cgroup_bucket_dl", PIN_MAP_BUCKET_DL),
            Direction::Upload => ("cgroup_bucket_ul", PIN_MAP_BUCKET_UL),
        };
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf.map(map_name).context(format!("{map_name} not found"))?,
            None => {
                pinned = pin::open_pinned_hash_map(pin_path)?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, BucketRaw> =
            BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
        match map.get(&root, 0) {
            Ok(bucket) => Ok(Some(bucket.tokens)),
            Err(e) if super::lanes::map_error_means_absent(&e) => Ok(None),
            Err(e) => Err(anyhow!("{map_name} read: {e}")),
        }
    }

    /// Read one cgroup's depth-histogram row (night-frontier-2B,
    /// schema v34) — the ee --depth distribution read. `Ok(None)` is
    /// the honest absence (no row yet — a fresh pin, idle traffic,
    /// or a cgroup under the 1/1024 sampling resolution; the same
    /// posture read_pool_tokens rides); `Err` means unreadable. The
    /// CALLER gates on the pinned schema version first: a pre-v34
    /// pin has no hist maps at all, and the version is the one
    /// gate distinguishing "no samples yet" from "no such lane" —
    /// this read must never be asked the un-gated question.
    pub fn read_hist_public(&self, id: u32, direction: Direction) -> Result<Option<HistRowRaw>> {
        let (map_name, pin_path) = match direction {
            Direction::Download => ("depth_hist_dl", PIN_MAP_DEPTH_HIST_DL),
            Direction::Upload => ("depth_hist_ul", PIN_MAP_DEPTH_HIST_UL),
        };
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf.map(map_name).context(format!("{map_name} not found"))?,
            None => {
                pinned = pin::open_pinned_hash_map(pin_path)?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, HistRowRaw> =
            BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
        match map.get(&id, 0) {
            Ok(row) => Ok(Some(row)),
            Err(e) if super::lanes::map_error_means_absent(&e) => Ok(None),
            Err(e) => Err(anyhow!("{map_name} read: {e}")),
        }
    }

    /// Read the mirror's per-CPU cost row, folded machine-wide
    /// (night-frontier-Z6, schema v36) — the ee --depth self-cost
    /// read. `Ok(None)` is the honest absence (a fresh pin no packet
    /// has sampled yet — the same posture read_hist_public rides);
    /// `Err` means unreadable. The CALLER gates on the pinned schema
    /// version first: a pre-v36 pin has no self_cost map at all, and
    /// the version is the one gate distinguishing "no samples yet"
    /// from "no such lane" — this read must never be asked the
    /// un-gated question.
    pub fn read_self_cost_public(&self) -> Result<Option<SelfCostFolded>> {
        // The self_cost row rides the OBSERVER object (night-frontier-Z6:
        // the always-on lane's own tax — the C77 forensic leg measured the
        // enforcer's walk budget full, and the observer is the estate's
        // headroom king), so the read is PIN-ONLY: a monitor session pins
        // the map, a monitor-less host answers the honest absence. A
        // missing pin is ENOENT (no observer session ever ran) — Ok(None),
        // the same posture read_hist_public's absent row rides; any other
        // read failure is an anomaly and propagates.
        // The architecture law: every pinned-map open flows through
        // the pin helpers (architecture_pins's own test). ENOENT = no
        // observer session ever pinned the map (the honest absence);
        // the io error rides anyhow's source chain, so the downcast
        // looks through the helper's context.
        let pinned_map: aya::maps::Map = match pin::open_pinned_per_cpu_array_map(PIN_MAP_SELF_COST)
        {
            Ok(map) => map,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let map: BpfPerCpuArray<_, SelfCostRowRaw> =
            BpfPerCpuArray::try_from(&pinned_map).context("Failed to access self_cost")?;
        match map.get(&0u32, 0) {
            Ok(values) => {
                let folded = fold_self_cost(&values);
                // The honest absence: no CPU has sampled yet (a fresh
                // pin, idle traffic under the 1/1024 resolution) —
                // None, never a zero dressed as a measurement.
                if super::selfcost::self_cost_samples(&folded) == 0 {
                    Ok(None)
                } else {
                    Ok(Some(folded))
                }
            }
            Err(e) => Err(anyhow!("self_cost read: {e}")),
        }
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
