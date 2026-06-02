// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::Result;
use colored::Colorize;
use std::collections::HashSet;
use std::process::Command;

use super::cgroup::{remove_cgroup, remove_target_cgroup_if_empty};
use super::nft::refresh_nft_ip_rules;
use super::process::sanitize_target_name;
use super::state::ZelynicState;
use super::tc::target_class_id;

/// Remove existing state and tc objects for a target before applying a new strict limit.
pub(super) fn auto_clean_existing_limits(
    target: &str,
    pids: &[u32],
    sanitized: &str,
) -> Result<()> {
    if let Ok(mut state) = ZelynicState::load() {
        let target_lower = target.to_lowercase();
        let existing: Vec<usize> = state
            .limits
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let rec_lower = r.target.to_lowercase();
                pids.contains(&r.pid)
                    || rec_lower == target_lower
                    || rec_lower.contains(&target_lower)
                    || target_lower.contains(&rec_lower)
            })
            .map(|(i, _)| i)
            .collect();

        if existing.is_empty() {
            return Ok(());
        }

        let removed_ifaces: HashSet<String> = existing
            .iter()
            .map(|&i| state.limits[i].interface.clone())
            .collect();

        for &idx in existing.iter().rev() {
            let _ = remove_cgroup(state.limits[idx].pid);
            state.limits.remove(idx);
        }
        state.save()?;

        let remaining_targets: HashSet<String> = state
            .limits
            .iter()
            .map(|r| sanitize_target_name(&r.target))
            .collect();

        if !remaining_targets.contains(sanitized) {
            remove_target_tc_objects(sanitized, &removed_ifaces);
            let _ = remove_target_cgroup_if_empty(sanitized);
        }

        if let Err(e) = refresh_nft_ip_rules(&state.limits) {
            eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
        }

        println!(
            "  {} Auto-cleaned {} previous limit(s) for '{}'",
            "Info:".dimmed(),
            existing.len(),
            target
        );
    }

    Ok(())
}

fn remove_target_tc_objects(sanitized: &str, removed_ifaces: &HashSet<String>) {
    let tid = target_class_id(sanitized);
    let target_class_id_str = format!("1:{:04x}", tid);

    for iface in removed_ifaces {
        let _ = Command::new("tc")
            .args([
                "class",
                "del",
                "dev",
                iface,
                "classid",
                &target_class_id_str,
            ])
            .output();
        let _ = Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                iface,
                "parent",
                "1:0",
                "protocol",
                "ip",
                "prio",
                "100",
                "handle",
                &tid.to_string(),
                "fw",
            ])
            .output();
        let _ = Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                iface,
                "parent",
                "1:0",
                "protocol",
                "ipv6",
                "prio",
                "100",
                "handle",
                &tid.to_string(),
                "fw",
            ])
            .output();
    }
}
