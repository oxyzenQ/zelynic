// SPDX-License-Identifier: GPL-3.0-only
use anyhow::Result;
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::cgroup::{
    check_root, list_interfaces, remove_cgroup, remove_target_cgroup, setup_cgroup,
};
use super::nft::refresh_nft_ip_rules;
use super::process::{get_process_name, resolve_pids, sanitize_target_name};
use super::state::ZelynicState;
use super::tc::target_class_id;
use super::{
    CGROUP_BASE, LEGACY_CGROUP_BASE, LEGACY_NFT_TABLE, LEGACY_STATE_DIR, NFT_TABLE, STATE_DIR,
};

fn live_pids_in_cgroup(path: &Path) -> Vec<u32> {
    let procs_path = path.join("cgroup.procs");
    fs::read_to_string(procs_path)
        .ok()
        .map(|content| {
            content
                .lines()
                .filter_map(|pid| pid.trim().parse::<u32>().ok())
                .filter(|pid| Path::new(&format!("/proc/{}", pid)).exists())
                .collect()
        })
        .unwrap_or_default()
}

fn remove_legacy_cgroup_if_safe(path: &Path, verbose: bool) -> bool {
    if !path.exists() {
        return true;
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() {
                remove_legacy_cgroup_if_safe(&child, verbose);
            }
        }
    }

    let live_pids = live_pids_in_cgroup(path);
    if !live_pids.is_empty() {
        if verbose {
            eprintln!(
                "{}: legacy cgroup {} still contains live PID(s): {:?}; leaving it in place",
                "WARNING".yellow(),
                path.display(),
                live_pids
            );
        }
        return false;
    }

    match fs::remove_dir(path) {
        Ok(()) => true,
        Err(e) => {
            if verbose && path.exists() {
                eprintln!(
                    "{}: could not remove legacy cgroup {}: {}",
                    "WARNING".yellow(),
                    path.display(),
                    e
                );
            }
            false
        }
    }
}

pub(super) fn cleanup_legacy_runtime_namespace(verbose: bool) {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", LEGACY_NFT_TABLE])
        .output();

    let legacy_state = Path::new(LEGACY_STATE_DIR);
    if legacy_state.exists() {
        match fs::remove_dir_all(legacy_state) {
            Ok(()) => {
                if verbose {
                    eprintln!(
                        "{} Removed legacy runtime directory {}",
                        "Info:".yellow(),
                        LEGACY_STATE_DIR
                    );
                }
            }
            Err(e) if verbose => eprintln!(
                "{}: could not remove legacy runtime directory {}: {}",
                "WARNING".yellow(),
                LEGACY_STATE_DIR,
                e
            ),
            Err(_) => {}
        }
    }

    remove_legacy_cgroup_if_safe(Path::new(LEGACY_CGROUP_BASE), verbose);
}

// ---------------------------------------------------------------------------
// Main: remove_limit
// ---------------------------------------------------------------------------

/// Remove all bandwidth limits (unstrict) from a target process.
pub fn remove_limit(target: &str) -> Result<()> {
    check_root()?;
    cleanup_legacy_runtime_namespace(true);

    let mut state = ZelynicState::load()?;
    let target_lower = target.to_lowercase();
    let mut removed_count = 0;
    let mut to_remove = Vec::new();

    // Strategy 1: Match by target name in state file (works even if process has exited).
    // This is the primary lookup — it ensures cleanup always works regardless of
    // whether the target process is still running.
    for (idx, record) in state.limits.iter().enumerate() {
        let rec_lower = record.target.to_lowercase();
        let matches = rec_lower == target_lower
            || rec_lower.contains(&target_lower)
            || target_lower.contains(&rec_lower);

        if matches {
            to_remove.push(idx);
        }
    }

    // Strategy 2: If no name match, try matching by numeric PID.
    if to_remove.is_empty() {
        if let Ok(pid) = target.parse::<u32>() {
            for (idx, record) in state.limits.iter().enumerate() {
                if record.pid == pid {
                    to_remove.push(idx);
                }
            }
        }
    }

    // Strategy 3: Try resolving running processes by name (for running processes
    // whose binary name differs from the stored target string).
    if to_remove.is_empty() {
        if let Ok(pids) = resolve_pids(target) {
            for (idx, record) in state.limits.iter().enumerate() {
                if pids.contains(&record.pid) {
                    to_remove.push(idx);
                }
            }
        }
    }

    if to_remove.is_empty() {
        println!(
            "{} No active bandwidth limits found for '{}'.",
            "Info:".yellow(),
            target
        );
        return Ok(());
    }

    // Collect interfaces for cleanup
    let removed_ifaces: Vec<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Collect sanitized target names of records being removed
    let removed_targets: HashSet<String> = to_remove
        .iter()
        .map(|&idx| sanitize_target_name(&state.limits[idx].target))
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        // Remove per-PID cgroup for this PID (v1/hybrid)
        remove_cgroup(record.pid)?;

        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Clean up per-target tc objects for targets that no longer have any limits.
    // Compute remaining sanitized target names after removal.
    let remaining_targets: HashSet<String> = state
        .limits
        .iter()
        .map(|r| sanitize_target_name(&r.target))
        .collect();

    for san_name in &removed_targets {
        if !remaining_targets.contains(san_name) {
            let tid = target_class_id(san_name);
            let target_class_id_str = format!("1:{:04x}", tid);
            for iface in &removed_ifaces {
                // Remove per-target HTB class
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
                // Remove per-target fw filter (IPv4)
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
                // Remove per-target fw filter (IPv6)
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
                        "101",
                        "handle",
                        &tid.to_string(),
                        "fw",
                    ])
                    .output();
            }

            // Remove per-target cgroup
            let _ = remove_target_cgroup(san_name);
        }
    }

    // Refresh nft rules (removes marking for removed processes)
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
    }

    // Clean up if no limits remain
    if state.limits.is_empty() {
        for iface in &removed_ifaces {
            // Remove the v1/hybrid cgroup filter (no-op if not present)
            let _ = Command::new("tc")
                .args([
                    "filter", "del", "dev", iface, "parent", "1:0", "protocol", "ip", "prio", "1",
                    "cgroup",
                ])
                .output();
            let _ = Command::new("tc")
                .args([
                    "filter", "del", "dev", iface, "parent", "1:0", "protocol", "ipv6", "prio",
                    "1", "cgroup",
                ])
                .output();
        }

        // Clean up all per-target cgroups
        for san_name in &removed_targets {
            let _ = remove_target_cgroup(san_name);
        }

        // Clean up all nftables tables
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .output();
    }

    println!(
        "{}",
        "zelynic unstrict: bandwidth limits removed".green().bold()
    );
    println!();
    println!("  Target:    {}", target);
    println!("  Removed:   {} limit(s)", removed_count);
    println!(
        "  {} All bandwidth restrictions for '{}' have been lifted.",
        "Info:".yellow(),
        target
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Main: list_active_limits
// ---------------------------------------------------------------------------

/// List all currently active bandwidth limits.
pub fn list_active_limits() -> Result<()> {
    let _ = check_respawns();

    let state = ZelynicState::load()?;

    if state.limits.is_empty() {
        println!("{} No active bandwidth limits.", "Info:".yellow());
        return Ok(());
    }

    println!("{}", "Active Bandwidth Limits:".green().bold());
    println!();

    for record in &state.limits {
        let process_name = get_process_name(record.pid);
        println!("  Target:    {} (PID: {})", record.target, record.pid);
        println!("  Process:   {}", process_name);
        if let Some(ref dl) = record.download_display {
            println!("  Download:  {} (nftables policer)", dl);
        } else {
            println!("  Download:  {}", "unlimited".dimmed());
        }
        if let Some(ref ul) = record.upload_display {
            println!("  Upload:    {} (HTB)", ul);
        } else {
            println!("  Upload:    {}", "unlimited".dimmed());
        }
        println!("  Interface: {}", record.interface);
        println!("  Class ID:  1:{:04x}", record.class_id);
        println!("  Since:     {}", record.applied_at);
        println!();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Orphan cleanup & respawn handling
// ---------------------------------------------------------------------------

/// Clean up orphaned bandwidth limits for processes that have exited.
pub fn clean_orphans() -> Result<()> {
    check_root()?;
    cleanup_legacy_runtime_namespace(true);

    let mut state = ZelynicState::load()?;

    if state.limits.is_empty() {
        println!("{} No active bandwidth limits to clean.", "Info:".yellow());
        return Ok(());
    }

    let mut removed_count = 0;
    let mut kept_count = 0;

    let mut to_remove = Vec::new();

    for (idx, record) in state.limits.iter().enumerate() {
        let proc_path = format!("/proc/{}", record.pid);
        let is_alive = std::path::Path::new(&proc_path).exists();

        if is_alive {
            kept_count += 1;
        } else {
            to_remove.push(idx);
        }
    }

    if to_remove.is_empty() {
        println!(
            "{} All {} limit(s) are for running processes. No cleanup needed.",
            "Info:".yellow(),
            kept_count
        );
        return Ok(());
    }

    println!(
        "{} Found {} orphaned limit(s) to clean up...",
        "Cleaning:".cyan(),
        to_remove.len()
    );

    // Collect sanitized target names of records being removed
    let removed_targets: HashSet<String> = to_remove
        .iter()
        .map(|&idx| sanitize_target_name(&state.limits[idx].target))
        .collect();

    // Collect interfaces for cleanup
    let removed_ifaces: HashSet<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        println!(
            "  Removing stale rules for {} (PID: {}, class: 1:{:04x})...",
            record.target, record.pid, record.class_id
        );

        // Remove cgroup
        let _ = remove_cgroup(record.pid);

        // Remove from state
        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Clean up per-target tc objects for targets that no longer have any limits.
    let remaining_targets: HashSet<String> = state
        .limits
        .iter()
        .map(|r| sanitize_target_name(&r.target))
        .collect();

    for san_name in &removed_targets {
        if !remaining_targets.contains(san_name) {
            let tid = target_class_id(san_name);
            let target_class_id_str = format!("1:{:04x}", tid);
            for iface in &removed_ifaces {
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
                // Remove IPv4 fw filter
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
                // Remove IPv6 fw filter
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
                        "101",
                        "handle",
                        &tid.to_string(),
                        "fw",
                    ])
                    .output();
            }

            // Remove per-target cgroup
            let _ = remove_target_cgroup(san_name);
        }
    }

    // Refresh nft rules
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
    }

    println!();
    println!(
        "{}",
        "zelynic clean: orphaned limits removed".green().bold()
    );
    println!();
    println!("  Removed:   {} orphaned limit(s)", removed_count);
    println!("  Remaining: {} active limit(s)", kept_count);
    println!();
    println!(
        "  {} Run 'zelynic status' to see current active limits.",
        "Info:".yellow()
    );

    Ok(())
}

/// Emergency cleanup: remove ALL Zelynic state, nftables rules, tc objects, and cgroups.
///
/// This is the "nuclear option" for when normal unstrict fails — for example,
/// when the target process has exited and the system's cgroup delegation has
/// been corrupted by writing PIDs to the root cgroup.
///
/// Call with: `zelynic clean --all`
pub fn emergency_cleanup() -> Result<()> {
    check_root()?;
    cleanup_legacy_runtime_namespace(true);

    println!(
        "{}",
        "zelynic clean: performing full emergency cleanup..."
            .yellow()
            .bold()
    );

    // 1. Remove nftables inet zelynic table (stops all packet marking/rate limiting)
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .output();
    println!("  {} Removed nftables inet zelynic table", "✓".green());

    // 2. Remove HTB qdisc and all Zelynic classes/filters on all interfaces
    let interfaces = list_interfaces();
    for iface in &interfaces {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "root", "handle", "1:"])
            .output();
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "ingress"])
            .output();
    }
    println!(
        "  {} Removed tc qdiscs on {} interface(s)",
        "✓".green(),
        interfaces.len()
    );

    // 3. Remove all zelynic cgroups (per-target and per-PID)
    let zelynic_base = Path::new(CGROUP_BASE);
    if zelynic_base.exists() {
        // Remove all sub-cgroups (target_* and pid_*)
        if let Ok(entries) = fs::read_dir(zelynic_base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Evict any living processes to parent Zelynic cgroup (NOT root)
                    let procs_path = path.join("cgroup.procs");
                    if procs_path.exists() {
                        if let Ok(content) = fs::read_to_string(&procs_path) {
                            for pid_str in content.lines() {
                                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                                    // Skip dead processes
                                    if !std::path::Path::new(&format!("/proc/{}", proc_pid))
                                        .exists()
                                    {
                                        continue;
                                    }
                                    // Move to parent Zelynic cgroup, NOT system root
                                    let parent_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                                    if Path::new(&parent_procs).exists() {
                                        let _ = fs::write(&parent_procs, proc_pid.to_string());
                                    }
                                }
                            }
                        }
                    }
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }
        // Remove the base zelynic cgroup itself
        let _ = fs::remove_dir(CGROUP_BASE);
        println!("  {} Removed all zelynic cgroups", "✓".green());
    } else {
        println!("  {} No zelynic cgroups found", "✓".dimmed());
    }

    // 4. Remove state files
    if Path::new(STATE_DIR).exists() {
        let _ = fs::remove_dir_all(STATE_DIR);
        println!("  {} Removed state directory {}", "✓".green(), STATE_DIR);
    } else {
        println!("  {} No state directory found", "✓".dimmed());
    }

    println!();
    println!(
        "{}",
        "zelynic clean: all state has been removed".green().bold()
    );
    println!(
        "  {} System should now be fully restored.",
        "Info:".yellow()
    );

    Ok(())
}

/// Generate a human-readable timestamp string for the applied_at field.
pub(super) fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let datetime = time::OffsetDateTime::from(now);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        datetime.year(),
        datetime.month() as u8,
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

/// Check for process respawns and re-apply limits to new PIDs.
pub fn check_respawns() -> Result<()> {
    check_root()?;
    cleanup_legacy_runtime_namespace(true);

    let mut state = ZelynicState::load()?;

    if state.limits.is_empty() {
        return Ok(());
    }

    let mut respawned: Vec<(usize, Vec<u32>)> = Vec::new();

    // Check each limit for process death and potential respawn
    for (idx, record) in state.limits.iter().enumerate() {
        let proc_path = format!("/proc/{}", record.pid);
        let is_alive = std::path::Path::new(&proc_path).exists();

        if !is_alive {
            // Process died - look for respawned instances with same name
            let current_pids = resolve_pids(&record.target)?;

            if !current_pids.is_empty() {
                respawned.push((idx, current_pids));
            }
        }
    }

    if respawned.is_empty() {
        return Ok(());
    }

    println!(
        "{}",
        "zelynic: detected process respawn(s), re-applying limits..."
            .yellow()
            .bold()
    );
    println!();

    // Re-apply limits to respawned processes
    for (idx, new_pids) in respawned {
        let record = &state.limits[idx];

        println!(
            "  Target '{}' (PID: {} -> new PID(s): {:?})",
            record.target, record.pid, new_pids
        );

        // Get first PID and update record
        let first_pid = new_pids[0];

        for &new_pid in &new_pids {
            // Always try per-target cgroup first (v2 approach works on hybrid too)
            if let Some(ref tcg_path) = record.target_cgroup_path {
                let procs_path = format!("{}/cgroup.procs", tcg_path);
                if Path::new(&procs_path).exists() {
                    let _ = fs::write(&procs_path, new_pid.to_string());
                }
            } else {
                // v1 fallback: per-PID cgroups
                let (cgroup_path, _) = setup_cgroup(new_pid, record.class_id)?;
                let procs_path = format!("{}/cgroup.procs", cgroup_path);
                if Path::new(&procs_path).exists() {
                    let _ = fs::write(&procs_path, new_pid.to_string());
                }
            }
        }

        // Update record with first new PID as primary
        state.limits[idx].pid = first_pid;
        state.limits[idx].applied_at = chrono_now();

        println!("  {} Re-applied limits to PID {}", "✓".green(), first_pid);
    }

    // Save updated state
    state.save()?;

    // Refresh nft rules to pick up new cgroup memberships
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!(
            "{}: Failed to refresh nft rules after respawn: {}",
            "WARNING".yellow(),
            e
        );
    }

    println!();
    println!("{}", "zelynic: respawn handling complete".green().bold());

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_cleanup_targets_v2_runtime_namespace() {
        assert_eq!(super::super::LEGACY_STATE_DIR, "/run/oxy");
        assert_eq!(super::super::LEGACY_CGROUP_BASE, "/sys/fs/cgroup/oxy");
        assert_eq!(super::super::LEGACY_NFT_TABLE, "oxy");
    }
}
