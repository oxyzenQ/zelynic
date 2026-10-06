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

use super::format::{default_burst, format_bytes_exact, format_rate_exact};
use super::types::{Direction, RateSpec};

/// Verbose trace line for one policy write (NIGHT-hunt-9): the exact
/// cgroup, direction, rate, and token-bucket burst handed to the BPF
/// map — the facts an owner needs when a limit "doesn't feel right".
/// Pure formatting so the wording is unit-pinned.
///
/// improve-40 (schema v24): a bracket the row carries joins the
/// trace — the floor/ceil pair the DRR pool's leaves police under,
/// rendered only when a side is set (the zero sentinel stays
/// silent, the trace stays lean for the rows that carry none).
///
/// NIGHT-hunt-Z7: the rate and burst render through the EXACT twins —
/// a configured `100.51kb` must trace as "100.51 KB/s", never the
/// one-decimal "100.5 KB/s" that hid 10 B/s of the owner's own
/// number (what the trace prints is what the map carries).
pub(super) fn policy_write_line(
    cgroup_id: u32,
    direction: Direction,
    rate_bps: u64,
    floor_bps: u64,
    ceil_bps: u64,
) -> String {
    let bracket_tail = if floor_bps != 0 || ceil_bps != 0 {
        let floor_half = if floor_bps != 0 {
            format!("floor {} ", format_rate_exact(floor_bps))
        } else {
            String::new()
        };
        let ceil_half = if ceil_bps != 0 {
            format!("ceil {}", format_rate_exact(ceil_bps))
        } else {
            String::new()
        };
        format!(", {}", format!("{floor_half}{ceil_half}").trim())
    } else {
        String::new()
    };
    format!(
        "[limiter] cg:{cgroup_id} {} → {} (burst {}{bracket_tail})",
        direction.label(),
        format_rate_exact(rate_bps),
        format_bytes_exact(default_burst(rate_bps))
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

/// Verbose trace lines for one group apply (NIGHT-hunt-9, deduped
/// by charger-core-2 when apply_group_atomic grew the same block):
/// the group label, the per-direction rate, and the member count —
/// shared by both group-apply paths so the wording cannot drift.
/// Pure formatting so the pins in policy_tests hold for both.
pub(super) fn group_apply_lines(group_id: u32, rates: &RateSpec, members: usize) -> Vec<String> {
    let group_label = format!("group:{group_id}");
    let mut lines = Vec::new();
    if let Some(dl_rate) = rates.download {
        lines.push(format!(
            "[limiter] {group_label} download → {} (shared by {members} cgroups)",
            format_rate_exact(dl_rate)
        ));
    }
    if let Some(ul_rate) = rates.upload {
        lines.push(format!(
            "[limiter] {group_label} upload → {} (shared by {members} cgroups)",
            format_rate_exact(ul_rate)
        ));
    }
    lines
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
