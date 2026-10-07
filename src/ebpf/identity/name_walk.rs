// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The one-walk name-set resolver (NIGHT-hunt-28: hunt-27's named
//! residual #1 closed — the name-list lane's O(N x /proc) class,
//! the same quadratic improve-50 closed for numeric ids). Every
//! name-list consumer in the estate resolves through this file:
//! the strict/block multi applies, the root-catch-all guard, the
//! eagle-eyes depth report, and the single-name spellings through
//! the thin wrappers their callers own. One walker, three
//! reductions, no per-site drift class.

use std::collections::{HashMap, HashSet};
use std::fs;

use super::{pid_cgroup_id, pid_comm};

/// Resolve a SET of process names in ONE /proc walk: the answer to
/// "strict-multi a:b:c with a thousand names costs a thousand full
/// /proc walks". For every pid the walk reads exactly one comm
/// through the canonical boundary (NIGHT-optimized-1 — `pid_comm`,
/// so a prctl-spoofed comm can never match one thing and display
/// another); a pid whose comm matches a wanted name pays one more
/// read (its cgroup, through the canonical `pid_cgroup_id` boundary
/// the identity walk and connection walk share); every other pid
/// costs nothing further. The walk therefore costs what ONE name's
/// walk always cost, whatever N grows to.
///
/// Returns, per LOWERCASED name, the `(pid, cgroup_id)` pairs the
/// walk accepted, in /proc order — the exact matched-pairs evidence
/// the per-name walk collected (NIGHT-hunt-9's verbose trace input,
/// multiple pids sharing one cgroup included). A name with no live
/// match is simply absent from the map; callers own the empty-case
/// semantics (the graceful no-match lanes they always owned). An
/// empty name list never touches /proc — the pure-id sweep lists
/// ride the guard at zero walk cost, exactly as before.
pub fn resolve_name_set(names: &[String]) -> HashMap<String, Vec<(u32, u32)>> {
    let wanted: HashSet<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let mut out: HashMap<String, Vec<(u32, u32)>> = HashMap::with_capacity(wanted.len());
    if wanted.is_empty() {
        return out;
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(comm) = pid_comm(pid) else {
            continue;
        };
        let comm_lower = comm.to_lowercase();
        if !wanted.contains(&comm_lower) {
            continue;
        }
        let Some(cgroup_id) = pid_cgroup_id(pid) else {
            continue;
        };
        out.entry(comm_lower).or_default().push((pid, cgroup_id));
    }
    out
}

/// Reduce one name's matched `(pid, cgroup_id)` pairs to its
/// cgroup ids, deduped first-seen — the exact reduction the
/// per-name walk owned: two pids sharing one cgroup resolve it
/// once (NIGHT-hunt-8's aria2c/alacritty shape), two names sharing
/// a cgroup is the CALLER's dedup concern (depthbore-1's
/// cross-target retain). Pure over its input, so the dedup and
/// order contracts pin rootlessly.
pub fn matched_pairs_to_ids(pairs: &[(u32, u32)]) -> Vec<u32> {
    let mut ids: Vec<u32> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    for (_, cgroup_id) in pairs {
        if seen.insert(*cgroup_id) {
            ids.push(*cgroup_id);
        }
    }
    ids
}

// NIGHT-hunt-28: the walker's own pins — the pure reduction, the
// live walk against the test process itself, and the empty-list
// no-walk contract — #[path]-wired across trees (cosmostrix
// Pattern C), exactly like the identity pins one mod up.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/name_walk_tests.rs"]
mod tests;
