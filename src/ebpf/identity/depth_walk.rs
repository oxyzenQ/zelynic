// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The depth walk layer (NIGHT-hunt-30's LOC-cap split of depth.rs,
//! and the set-walk closure of the quadratic class improve-50 /
//! hunt-28 / hunt-29 closed): the eagle-eyes depth report resolved
//! N cgroups then walked ALL of /proc per id — the membership reads
//! alone were N x processes, so a multi-cgroup target (brave's ~30)
//! or a fleet-scale spec paid minutes of pure membership overhead
//! before the report's own data reads ran. The walk lives here now,
//! and it answers a SET of cgroups in ONE pass; the per-pid facts
//! layer (the parsers and probes the pins own) stays in depth.rs.

use std::collections::{HashMap, HashSet};
use std::fs;

use super::depth::{
    boot_epoch, clock_ticks, process_facts, uptime_secs, CgroupDepth, CgroupResources,
};
use super::pid_cgroup_id;

/// Walk /proc ONCE and collect the deep facts for every process
/// living in any of `ids`, plus each cgroup's own v2 path and
/// controller resources. Membership routes through the ONE
/// canonical pid-to-cgroup boundary (NIGHT-optimized-1) — the same
/// resolver the identity, connection, and target-match walks use,
/// so boundary fixes land here too. A pid outside the wanted set
/// costs its cgroup read and nothing more (the same
/// short-circuit the single-id walk always owned); an id with no
/// live members yields NO entry — callers own the empty-members
/// default `deep_collect` always returned. The clock reads (hz,
/// uptime, boot epoch) happen once for the whole set, not once
/// per id.
pub fn deep_collect_set(ids: &[u32]) -> HashMap<u32, CgroupDepth> {
    let wanted: HashSet<u32> = ids.iter().copied().collect();
    let mut out: HashMap<u32, CgroupDepth> = HashMap::with_capacity(wanted.len());
    if wanted.is_empty() {
        return out;
    }
    let hz = clock_ticks();
    let uptime = uptime_secs();
    let btime = boot_epoch();

    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(cgroup_id) = pid_cgroup_id(pid) else {
            continue;
        };
        if !wanted.contains(&cgroup_id) {
            continue;
        }
        let slot = out.entry(cgroup_id).or_default();
        if slot.rel_path.is_none() {
            slot.rel_path = pid_cgroup_rel_path(pid);
        }
        slot.procs.push(process_facts(pid, hz, uptime, btime));
    }
    // The controller's own resource view (NIGHT-blade-5) per
    // resolved path — a cgroup with live members but an
    // unresolvable path still reports the census, just without the
    // controller layer (best-effort, the family contract).
    for depth in out.values_mut() {
        depth.resources = cgroup_resources(depth.rel_path.as_deref());
    }
    out
}

/// Walk /proc once and collect deep facts for every process living
/// in `cgroup_id`, plus the cgroup's own v2 path. The single-id
/// spelling over the set walk (pathwalk's first arm and any future
/// single caller): one id, one walk — the cost it always paid.
pub fn deep_collect(cgroup_id: u32) -> CgroupDepth {
    deep_collect_set(&[cgroup_id])
        .remove(&cgroup_id)
        .unwrap_or_default()
}

/// Read the cgroup controller's own resource facts for one resolved
/// v2 path (NIGHT-blade-5). Pure plumbing over two best-effort file
/// reads; the parsers are pure and pinned separately (depth.rs's
/// own pins).
pub fn cgroup_resources(rel_path: Option<&str>) -> CgroupResources {
    let Some(rel) = rel_path else {
        return CgroupResources::default();
    };
    let dir = format!("/sys/fs/cgroup{rel}");
    CgroupResources {
        memory_current_bytes: fs::read_to_string(format!("{dir}/memory.current"))
            .ok()
            .and_then(|c| super::depth::parse_memory_current(&c)),
        cpu_usage_usec: fs::read_to_string(format!("{dir}/cpu.stat"))
            .ok()
            .and_then(|c| super::depth::parse_cpu_usage_usec(&c)),
    }
}

/// The cgroup v2 path from a member's /proc/<pid>/cgroup line (the
/// "0::<path>" shape), first line, trimmed — None when the line
/// parses to an empty path (the hybrid-v1 controller-line shape
/// included).
fn pid_cgroup_rel_path(pid: u32) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = content.lines().next()?.split("::").nth(1)?.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

// NIGHT-hunt-30: the set walk's own pins — the empty-set no-walk
// contract, the live walk against the test process itself (guarded
// the improve-50 way for the hybrid-v1 runner class), and the
// single-vs-set agreement that holds the no-drift law.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/depth_walk_tests.rs"]
mod tests;
