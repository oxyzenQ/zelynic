// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Policy operations — apply, resolve, write, and delete token-bucket
//! policies in the BPF maps (ephemeral and pinned modes).

use anyhow::{anyhow, Result};
use aya::maps::{HashMap as BpfHashMap, MapData};

use super::format::{default_burst, format_bytes, format_rate};
use super::reclaim::map_remove_means_absent;
use super::types::{group_id_from, Direction, PolicyRaw, RateSpec, Target, MAX_ENFORCABLE_BURST};
use crate::ebpf::pin::{PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL};

/// Verbose trace line for one policy write (NIGHT-hunt-9): the exact
/// cgroup, direction, rate, and token-bucket burst handed to the BPF
/// map — the facts an owner needs when a limit "doesn't feel right".
/// Pure formatting so the wording is unit-pinned below.
fn policy_write_line(cgroup_id: u32, direction: Direction, rate_bps: u64) -> String {
    format!(
        "[limiter] cg:{cgroup_id} {} → {} (burst {})",
        direction.label(),
        format_rate(rate_bps),
        format_bytes(default_burst(rate_bps))
    )
}

// The hunt-20 ENOENT classification lives in reclaim.rs (imported above).

/// One policy that survived a failed rollback or unstrict delete:
/// cgroup + direction, still enforced (cg: trace style, pinned).
pub(super) fn policy_survivor_line(cgroup_id: u32, direction: Direction) -> String {
    format!("cg:{cgroup_id} {}", direction.label())
}

/// The error a strict apply returns after a mid-flight write failure
/// (NIGHT-hunt-20): either the rollback removed every policy this
/// invocation had written (strict all-or-nothing held — no residue),
/// or it names the exact survivors. A bare cause that hides partial
/// enforcement is the inverse of the hunt-19 trap: a command that
/// "failed" while silently limiting. Pure so both outcomes are
/// unit-pinned.
fn partial_apply_failure_line(cause: &str, rolled_back: usize, survivors: &[String]) -> String {
    if survivors.is_empty() {
        let unit = if rolled_back == 1 {
            "policy"
        } else {
            "policies"
        };
        format!("{cause} — apply rolled back ({rolled_back} partial {unit}), no residue")
    } else {
        format!(
            "{cause} — rollback incomplete, still enforced: {}; \
             run 'zelynic unstrict' to clear",
            survivors.join(", ")
        )
    }
}

/// Verbose trace line for a /proc target resolution (NIGHT-hunt-9):
/// which cgroups a process name landed in and how many PIDs each
/// hosts. This is the diagnostic the alacritty-hosting-curl confusion
/// (NIGHT-hunt-8 lineage) always needed — the walk's decision, not
/// just its count. `matched` carries (pid, cgroup_id) pairs.
fn resolution_trace_line(name: &str, matched: &[(u32, u32)]) -> String {
    if matched.is_empty() {
        format!("[limiter] '{name}': no process matched in /proc walk — try 'zelynic list-apps'")
    } else {
        let mut per_cgroup: std::collections::BTreeMap<u32, usize> =
            std::collections::BTreeMap::new();
        for (_, cg) in matched {
            *per_cgroup.entry(*cg).or_default() += 1;
        }
        let parts: Vec<String> = per_cgroup
            .iter()
            .map(|(cg, n)| format!("cg:{cg} ({n} pid{})", if *n == 1 { "" } else { "s" }))
            .collect();
        format!("[limiter] '{name}' resolved: {}", parts.join(", "))
    }
}

impl super::Limiter {
    /// Apply strict-single: individual policy per cgroup.
    /// `target` is resolved to cgroup IDs. Each gets its own token bucket.
    pub fn apply_single(&mut self, target: &Target, rates: &RateSpec) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        if cgroup_ids.is_empty() {
            return Ok(0);
        }

        // NIGHT-hunt-20: strict all-or-nothing — every write of THIS
        // invocation is recorded so a mid-flight failure (map full at
        // 1024 entries, ENOMEM, ...) rolls the whole apply back
        // instead of leaving an enforced prefix behind. The
        // superseded-group ledger (NIGHT-lts-7) rides the same
        // lifecycle: captured by the writes, swept once after — a
        // failed apply's rollback deletes the written policies, and
        // the sweep's live-reference check keeps any group another
        // policy still holds.
        let mut written: Vec<(u32, Direction)> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                0,
                &mut written,
                &mut superseded,
            ) {
                Ok(n) => applied += n,
                Err(cause) => return Err(self.rollback_partial_apply(&written, cause)),
            }
        }
        self.reclaim_dead_groups(&superseded);

        Ok(applied)
    }

    /// Apply strict-multi: all cgroups share one group token bucket.
    /// A random group_id is generated. All cgroups get policy pointing to it.
    pub fn apply_group(&mut self, targets: &[Target], rates: &RateSpec) -> Result<usize> {
        // Resolve all targets to cgroup IDs. resolve_target prints its
        // own verbose trace (matched pids → cgroups, or the empty-walk
        // reason), so an unresolved target no longer needs a second
        // skip line here.
        let mut all_cgroup_ids: Vec<u32> = Vec::new();
        for target in targets {
            let ids = self.resolve_target(target)?;
            if ids.is_empty() {
                continue;
            }
            all_cgroup_ids.extend(ids);
        }

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
        // 257th invocation silently enforced unlimited.
        let mut written: Vec<(u32, Direction)> = Vec::new();
        let mut superseded: Vec<u32> = Vec::new();
        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            match self.write_policies_for_cgroup(
                *cgroup_id,
                rates,
                group_id,
                &mut written,
                &mut superseded,
            ) {
                Ok(n) => applied += n,
                Err(cause) => return Err(self.rollback_partial_apply(&written, cause)),
            }
        }
        self.reclaim_dead_groups(&superseded);

        let group_label = format!("group:{}", group_id);
        if self.verbose {
            if let Some(dl_rate) = rates.download {
                eprintln_safe!(
                    "[limiter] {} download → {} (shared by {} cgroups)",
                    group_label,
                    format_rate(dl_rate),
                    all_cgroup_ids.len()
                );
            }
            if let Some(ul_rate) = rates.upload {
                eprintln_safe!(
                    "[limiter] {} upload → {} (shared by {} cgroups)",
                    group_label,
                    format_rate(ul_rate),
                    all_cgroup_ids.len()
                );
            }
        }

        Ok(applied)
    }

    /// Resolve a target to cgroup IDs.
    ///
    /// For process names, does a DIRECT /proc walk (not identity map cache)
    /// to find all PIDs matching the name, then resolves their cgroup IDs.
    /// This avoids the "first-pid-wins" issue where aria2c shares a cgroup
    /// with alacritty — direct lookup finds aria2c's PID directly.
    pub(super) fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => {
                if self.verbose {
                    eprintln_safe!("[limiter] cg:{id} targeted directly (no /proc walk)");
                }
                Ok(vec![*id])
            }
            Target::ProcessName(name) => {
                // Direct /proc walk: find all PIDs whose comm matches.
                let name_lower = name.to_lowercase();
                let mut cgroup_ids = Vec::new();
                let mut seen = std::collections::HashSet::new();
                // Verbose evidence (NIGHT-hunt-9): every (pid, cgroup)
                // pair the walk accepted, so the trace shows the
                // decision — including multiple pids sharing one
                // cgroup, the NIGHT-hunt-8 discovery-stage lie.
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
    fn write_policies_for_cgroup(
        &mut self,
        cgroup_id: u32,
        rates: &RateSpec,
        group_id: u32,
        written: &mut Vec<(u32, Direction)>,
        superseded: &mut Vec<u32>,
    ) -> Result<usize> {
        let mut applied = 0usize;

        if let Some(dl_rate) = rates.download {
            if let Ok(Some(old_group)) = self.read_policy_group(cgroup_id, Direction::Download) {
                superseded.push(old_group);
            }
            self.write_policy(cgroup_id, dl_rate, group_id, Direction::Download)?;
            written.push((cgroup_id, Direction::Download));
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(cgroup_id, Direction::Download, dl_rate)
                );
            }
            applied += 1;
        }

        if let Some(ul_rate) = rates.upload {
            if let Ok(Some(old_group)) = self.read_policy_group(cgroup_id, Direction::Upload) {
                superseded.push(old_group);
            }
            self.write_policy(cgroup_id, ul_rate, group_id, Direction::Upload)?;
            written.push((cgroup_id, Direction::Upload));
            if self.verbose {
                eprintln_safe!(
                    "{}",
                    policy_write_line(cgroup_id, Direction::Upload, ul_rate)
                );
            }
            applied += 1;
        }

        // NIGHT-improve-29 (the floor run's hunt find): a direction
        // the spec leaves unset is REMOVED, not left stale. The old
        // shape silently kept whatever was already enforced —
        // `zelynic ss brave 100kb` then `zelynic ss brave -d 1mb`
        // left the upload leg at the old 100kb with no indication,
        // violating the documented contract ("-d ... limits download
        // only", USAGE.md) and doubling the first depth-battery
        // accounting window on the 5.15 floor run (both hooks policed
        // one loopback stream: bpf ledger 200.7% of the client bytes
        // — the exact 2x signature). The removals run AFTER the
        // writes on purpose: a failed write rolls back only what THIS
        // invocation wrote, so the pre-apply state survives whole —
        // the NIGHT-hunt-20 all-or-nothing contract. A failed removal
        // is best-effort and never silent (the unstrict precedent):
        // the survivor is named on stderr and visible in `status`,
        // while the freshly written legs stand.
        for (unset, direction) in [
            (rates.download.is_none(), Direction::Download),
            (rates.upload.is_none(), Direction::Upload),
        ] {
            if !unset {
                continue;
            }
            // The unset-leg removal is also a group supersession
            // (NIGHT-lts-7): capture before the delete, the same
            // read-before-write the fresh writes above carry.
            if let Ok(Some(old_group)) = self.read_policy_group(cgroup_id, direction) {
                superseded.push(old_group);
            }
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

    /// Roll back every policy written by the failed invocation
    /// (NIGHT-hunt-20). A delete that itself fails leaves that policy
    /// enforced — its error is printed for the record and the policy
    /// is named in the returned error instead of hidden behind a bare
    /// cause.
    fn rollback_partial_apply(
        &mut self,
        written: &[(u32, Direction)],
        cause: anyhow::Error,
    ) -> anyhow::Error {
        let mut survivors: Vec<String> = Vec::new();
        for (cgroup_id, direction) in written {
            match self.delete_policy(*cgroup_id, *direction) {
                Ok(_) => {
                    if self.verbose {
                        eprintln_safe!(
                            "[limiter] rolled back cg:{cgroup_id} {}",
                            direction.label()
                        );
                    }
                }
                Err(e) => {
                    eprintln_safe!(
                        "[limiter] rollback failed: cg:{cgroup_id} {}: {e}",
                        direction.label()
                    );
                    survivors.push(policy_survivor_line(*cgroup_id, *direction));
                }
            }
        }
        let rolled_back = written.len().saturating_sub(survivors.len());
        anyhow!(
            "{}",
            partial_apply_failure_line(&cause.to_string(), rolled_back, &survivors)
        )
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
    /// clamps to 100 MB today, but a future burst source must not be
    /// able to write past the bound the BPF side clamps at — the
    /// mirror constant is the one number both halves share.
    fn write_policy(
        &mut self,
        cgroup_id: u32,
        rate_bps: u64,
        group_id: u32,
        direction: Direction,
    ) -> Result<()> {
        let burst = default_burst(rate_bps).min(MAX_ENFORCABLE_BURST);
        let raw = PolicyRaw {
            rate_bps,
            burst_bytes: burst,
            group_id,
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

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/policy_tests.rs"]
mod policy_tests;
