// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Policy operations — apply, resolve, write, and delete token-bucket
//! policies in the BPF maps (ephemeral and pinned modes).

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData};

use super::format::{default_burst, format_rate};
use super::types::{Direction, PolicyRaw, RateSpec, Target};
use crate::ebpf::pin::{PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL};

impl super::Limiter {
    /// Apply strict-single: individual policy per cgroup.
    /// `target` is resolved to cgroup IDs. Each gets its own token bucket.
    pub fn apply_single(&mut self, target: &Target, rates: &RateSpec) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        if cgroup_ids.is_empty() {
            return Ok(0);
        }

        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            if let Some(dl_rate) = rates.download {
                self.write_policy(*cgroup_id, dl_rate, 0, Direction::Download)?;
                applied += 1;
            }

            if let Some(ul_rate) = rates.upload {
                self.write_policy(*cgroup_id, ul_rate, 0, Direction::Upload)?;
                applied += 1;
            }
        }

        Ok(applied)
    }

    /// Apply strict-multi: all cgroups share one group token bucket.
    /// A random group_id is generated. All cgroups get policy pointing to it.
    pub fn apply_group(&mut self, targets: &[Target], rates: &RateSpec) -> Result<usize> {
        // Resolve all targets to cgroup IDs.
        let mut all_cgroup_ids: Vec<u32> = Vec::new();
        for target in targets {
            let ids = self.resolve_target(target)?;
            if ids.is_empty() {
                if self.verbose {
                    eprintln!("[limiter] no cgroup found for '{:?}' — skipping", target);
                }
                continue;
            }
            all_cgroup_ids.extend(ids);
        }

        if all_cgroup_ids.is_empty() {
            return Ok(0);
        }

        // Generate group_id (use PID + timestamp for uniqueness).
        let group_id = (std::process::id() as u32).wrapping_mul(1000).wrapping_add(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos())
                % 1000,
        );

        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            if let Some(dl_rate) = rates.download {
                self.write_policy(*cgroup_id, dl_rate, group_id, Direction::Download)?;
                applied += 1;
            }

            if let Some(ul_rate) = rates.upload {
                self.write_policy(*cgroup_id, ul_rate, group_id, Direction::Upload)?;
                applied += 1;
            }
        }

        let group_label = format!("group:{}", group_id);
        if self.verbose {
            if let Some(dl_rate) = rates.download {
                eprintln!(
                    "[limiter] {} download → {} (shared by {} cgroups)",
                    group_label,
                    format_rate(dl_rate),
                    all_cgroup_ids.len()
                );
            }
            if let Some(ul_rate) = rates.upload {
                eprintln!(
                    "[limiter] {} upload → {} (shared by {} cgroups)",
                    group_label,
                    format_rate(ul_rate),
                    all_cgroup_ids.len()
                );
            }
        }

        Ok(applied)
    }

    /// Remove policy for a target (unstrict).
    pub fn unstrict(&mut self, target: &Target) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        let mut removed = 0usize;

        for cgroup_id in &cgroup_ids {
            let label = self.identity.label(*cgroup_id);
            let mut found = false;

            // Remove from dl + ul policy maps.
            if let Ok(deleted) = self.delete_policy(*cgroup_id, Direction::Download) {
                if deleted {
                    found = true;
                }
            }
            if let Ok(deleted) = self.delete_policy(*cgroup_id, Direction::Upload) {
                if deleted {
                    found = true;
                }
            }

            if found {
                eprintln!("[limiter] Unstrict: {label} — limits removed");
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Resolve a target to cgroup IDs.
    ///
    /// For process names, does a DIRECT /proc walk (not identity map cache)
    /// to find all PIDs matching the name, then resolves their cgroup IDs.
    /// This avoids the "first-pid-wins" issue where aria2c shares a cgroup
    /// with alacritty — direct lookup finds aria2c's PID directly.
    fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => Ok(vec![*id]),
            Target::ProcessName(name) => {
                // Direct /proc walk: find all PIDs whose comm matches.
                let name_lower = name.to_lowercase();
                let mut cgroup_ids = Vec::new();
                let mut seen = std::collections::HashSet::new();

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

                    // Read comm.
                    let comm = match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                        Ok(s) => s.trim().to_lowercase(),
                        Err(_) => continue,
                    };

                    if comm != name_lower {
                        continue;
                    }

                    // Read cgroup path.
                    let cgroup_content =
                        match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                    let cgroup_path = cgroup_content
                        .lines()
                        .next()
                        .and_then(|line| line.split("::").nth(1))
                        .map(|s| s.trim().to_string());

                    let cgroup_path = match cgroup_path {
                        Some(p) if !p.is_empty() => p,
                        _ => continue,
                    };

                    // Resolve cgroup_id.
                    let full_path = format!("/sys/fs/cgroup{cgroup_path}");
                    let cgroup_id_64 =
                        match crate::ebpf::identity::resolve_cgroup_id_from_path(&full_path) {
                            Some(id) => id,
                            None => continue,
                        };

                    let cgroup_id = cgroup_id_64 as u32;
                    if seen.insert(cgroup_id) {
                        cgroup_ids.push(cgroup_id);
                    }
                }

                // Also refresh identity map for display purposes.
                self.identity.maybe_refresh();

                Ok(cgroup_ids)
            }
        }
    }

    /// Write a policy to the appropriate BPF map.
    fn write_policy(
        &mut self,
        cgroup_id: u32,
        rate_bps: u64,
        group_id: u32,
        direction: Direction,
    ) -> Result<()> {
        let burst = default_burst(rate_bps);
        let raw = PolicyRaw {
            rate_bps,
            burst_bytes: burst,
            group_id,
        };

        if let Some(bpf) = self.bpf.as_mut() {
            // Ephemeral mode: use Ebpf object.
            let map_name = format!("cgroup_policy_{}", direction.suffix());
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
                bpf.map_mut(&map_name)
                    .context(format!("{map_name} not found"))?,
            )
            .context(format!("Failed to access {map_name}"))?;
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))?;
        } else {
            // Pin mode: open pinned map.
            let pin_path = self.pinned_policy_path(direction);
            let map_data = MapData::from_pin(&pin_path)
                .map_err(|e| anyhow!("pinned map {pin_path}: {e:?}"))?;
            let mut map_obj = aya::maps::Map::HashMap(map_data);
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))?;
        }
        Ok(())
    }

    /// Delete a policy from BPF map. Returns Ok(true) if deleted, Ok(false) if not found.
    pub fn delete_policy(&mut self, cgroup_id: u32, direction: Direction) -> Result<bool> {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_name = format!("cgroup_policy_{}", direction.suffix());
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
                bpf.map_mut(&map_name)
                    .context(format!("{map_name} not found"))?,
            )
            .context(format!("Failed to access {map_name}"))?;
            match map.remove(&cgroup_id) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            let pin_path = self.pinned_policy_path(direction);
            let map_data = MapData::from_pin(&pin_path)
                .map_err(|e| anyhow!("pinned map {pin_path}: {e:?}"))?;
            let mut map_obj = aya::maps::Map::HashMap(map_data);
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            match map.remove(&cgroup_id) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }

    /// Get the pin path for a policy map.
    pub(super) fn pinned_policy_path(&self, direction: Direction) -> String {
        match direction {
            Direction::Download => PIN_MAP_POLICY_DL.to_string(),
            Direction::Upload => PIN_MAP_POLICY_UL.to_string(),
        }
    }
}
