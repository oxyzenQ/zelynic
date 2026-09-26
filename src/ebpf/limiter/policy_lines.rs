// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The policy surface's pure line formatters (NIGHT-depthbore-1) —
//! the verbose trace and error-wording helpers policy.rs owns, split
//! to their own sibling when the depthbore-1 dedup fix pushed the
//! parent past the 500-LOC owner cap (the same split discipline that
//! produced depth_json.rs from report.rs). Every helper here is PURE:
//! string composition only, no map access, no io — the pins in
//! test/ebpf/limiter/policy_tests.rs drive them through policy.rs's
//! re-export, exactly as before the split.

use super::format::{default_burst, format_bytes, format_rate};
use super::types::Direction;

/// Verbose trace line for one policy write (NIGHT-hunt-9): the exact
/// cgroup, direction, rate, and token-bucket burst handed to the BPF
/// map — the facts an owner needs when a limit "doesn't feel right".
/// Pure formatting so the wording is unit-pinned.
pub(super) fn policy_write_line(cgroup_id: u32, direction: Direction, rate_bps: u64) -> String {
    format!(
        "[limiter] cg:{cgroup_id} {} → {} (burst {})",
        direction.label(),
        format_rate(rate_bps),
        format_bytes(default_burst(rate_bps))
    )
}

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
pub(super) fn partial_apply_failure_line(
    cause: &str,
    rolled_back: usize,
    survivors: &[String],
) -> String {
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
pub(super) fn resolution_trace_line(name: &str, matched: &[(u32, u32)]) -> String {
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
