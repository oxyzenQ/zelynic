// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Target resolution (night-during's LOC-cap split of policy.rs: the
//! --during threading pushed the parent past the 500-line owner cap;
//! the house precedent moves one cohesive concern out — the resolve
//! walk, unchanged, its callers' paths updated).

use anyhow::Result;

use super::policy_lines::resolution_trace_line;
use super::types::Target;

impl super::Limiter {
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
}
