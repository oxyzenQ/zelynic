// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;

use super::cgroup::{
    check_root, current_cgroup_v2_absolute_path, get_default_interface,
    move_pid_to_cgroup_with_verify, verify_pid_in_cgroup,
};
use super::cleanup::chrono_now;
use super::process::resolve_pids;
use super::state::{LimitRecord, ZelynicState};

fn pid_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn target_matches_record(record: &LimitRecord, target: &str) -> bool {
    if let Ok(pid) = target.parse::<u32>() {
        return record.pid == pid || record.target == target;
    }

    let target_lower = target.to_lowercase();
    let record_lower = record.target.to_lowercase();
    record_lower == target_lower
        || record_lower.contains(&target_lower)
        || target_lower.contains(&record_lower)
}

fn find_refresh_template(state: &ZelynicState, target: &str) -> Option<LimitRecord> {
    state
        .limits
        .iter()
        .find(|record| target_matches_record(record, target))
        .cloned()
}

fn record_exists_for_pid(state: &ZelynicState, target: &str, pid: u32) -> bool {
    state
        .limits
        .iter()
        .any(|record| target_matches_record(record, target) && record.pid == pid)
}

fn prune_stale_target_records<F>(state: &mut ZelynicState, target: &str, is_alive: F) -> usize
where
    F: Fn(u32) -> bool,
{
    let before = state.limits.len();
    state
        .limits
        .retain(|record| !target_matches_record(record, target) || is_alive(record.pid));
    before - state.limits.len()
}

fn append_refreshed_record(
    state: &mut ZelynicState,
    template: &LimitRecord,
    pid: u32,
    original_cgroup_path: Option<String>,
) -> bool {
    if record_exists_for_pid(state, &template.target, pid) {
        return false;
    }

    state.limits.push(LimitRecord {
        target: template.target.clone(),
        pid,
        download_bytes_per_sec: template.download_bytes_per_sec,
        upload_bytes_per_sec: template.upload_bytes_per_sec,
        download_display: template.download_display.clone(),
        upload_display: template.upload_display.clone(),
        interface: template.interface.clone(),
        class_id: template.class_id,
        applied_at: chrono_now(),
        ingress_handle: template.ingress_handle,
        cgroup_id: template.cgroup_id,
        target_cgroup_path: template.target_cgroup_path.clone(),
        original_cgroup_path,
        uid: template.uid,
    });
    true
}

fn interface_mismatch(stored_interface: &str, current_default: Option<&str>) -> bool {
    current_default
        .map(|current| current != stored_interface)
        .unwrap_or(false)
}

fn format_pid_list(pids: &[u32]) -> String {
    if pids.is_empty() {
        "none".to_string()
    } else {
        pids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Refresh an existing strict limit by moving newly discovered PIDs into the
/// already configured target cgroup.
pub fn refresh_limit(target: &str) -> Result<()> {
    let mut state = ZelynicState::load()?;
    let Some(template) = find_refresh_template(&state, target) else {
        println!(
            "No active limit found for '{}'. Run zelynic strict first.",
            target
        );
        return Ok(());
    };

    check_root()?;

    let target_cgroup_path = template.target_cgroup_path.clone().with_context(|| {
        format!(
            "active limit for '{}' does not include a target cgroup path; run zelynic strict again",
            template.target
        )
    })?;

    let procs_path = Path::new(&target_cgroup_path).join("cgroup.procs");
    if !procs_path.exists() {
        bail!(
            "active limit for '{}' references missing cgroup '{}'; run zelynic strict again",
            template.target,
            target_cgroup_path
        );
    }

    let stale_removed = prune_stale_target_records(&mut state, target, pid_exists);
    if stale_removed > 0 {
        state.save()?;
    }

    let discovered = resolve_pids(target)?;
    let mut already_limited = Vec::new();
    let mut newly_moved = Vec::new();
    let mut failed = Vec::new();

    for pid in &discovered {
        if verify_pid_in_cgroup(*pid, &target_cgroup_path) {
            if !record_exists_for_pid(&state, target, *pid) {
                append_refreshed_record(&mut state, &template, *pid, None);
            }
            already_limited.push(*pid);
            continue;
        }

        let original_cgroup_path = current_cgroup_v2_absolute_path(*pid);
        let outcome = move_pid_to_cgroup_with_verify(*pid, &target_cgroup_path);

        if outcome.verified {
            append_refreshed_record(&mut state, &template, *pid, original_cgroup_path);
            newly_moved.push(*pid);
        } else {
            failed.push((
                *pid,
                outcome
                    .error
                    .unwrap_or_else(|| outcome.cgroup_line.to_string()),
            ));
        }
    }

    state.save()?;

    let current_default = get_default_interface().ok();
    let iface_mismatch = interface_mismatch(&template.interface, current_default.as_deref());

    println!("{}", "zelynic refresh complete".green().bold());
    println!("  Target: {}", template.target.cyan());
    println!("  Interface: {}", template.interface.cyan());
    println!(
        "  Discovered current PIDs: {}",
        format_pid_list(&discovered)
    );
    println!(
        "  Already limited PIDs: {}",
        format_pid_list(&already_limited)
    );
    println!("  Newly moved PIDs: {}", format_pid_list(&newly_moved));
    println!("  Stale/dead records removed: {}", stale_removed);

    if !failed.is_empty() {
        println!("  Failed moves:");
        for (pid, reason) in failed {
            println!("    {}: {}", pid, reason);
        }
    }

    if iface_mismatch {
        if let Some(current) = current_default {
            println!();
            println!(
                "{} Stored interface differs from the current default route.",
                "Warning:".yellow().bold()
            );
            println!("  Stored limit interface: {}", template.interface.cyan());
            println!("  Current default interface: {}", current.cyan());
            println!(
                "  Refresh keeps the existing tc attachment. Run 'sudo zelynic unstrict {}' and re-apply strict to migrate interfaces.",
                template.target
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(target: &str, pid: u32) -> LimitRecord {
        LimitRecord {
            target: target.to_string(),
            pid,
            download_bytes_per_sec: Some(62_500),
            upload_bytes_per_sec: Some(62_500),
            download_display: Some("500 Kbit/s".to_string()),
            upload_display: Some("500 Kbit/s".to_string()),
            interface: "wlp1s0".to_string(),
            class_id: 100,
            applied_at: "test".to_string(),
            ingress_handle: None,
            cgroup_id: Some(42),
            target_cgroup_path: Some("/sys/fs/cgroup/zelynic/target_brave".to_string()),
            original_cgroup_path: Some(
                "/sys/fs/cgroup/user.slice/user-1000.slice/session.scope".to_string(),
            ),
            uid: None,
        }
    }

    #[test]
    fn refresh_after_unstrict_has_no_active_target_state() {
        let state = ZelynicState { limits: vec![] };
        assert!(find_refresh_template(&state, "brave").is_none());
    }

    #[test]
    fn stale_dead_pid_records_are_removed() {
        let mut state = ZelynicState {
            limits: vec![record("brave", 10), record("firefox", 20)],
        };

        let removed = prune_stale_target_records(&mut state, "brave", |pid| pid != 10);

        assert_eq!(removed, 1);
        assert_eq!(state.limits.len(), 1);
        assert_eq!(state.limits[0].target, "firefox");
    }

    #[test]
    fn already_limited_pid_is_not_duplicated() {
        let template = record("brave", 10);
        let mut state = ZelynicState {
            limits: vec![template.clone()],
        };

        let inserted = append_refreshed_record(
            &mut state,
            &template,
            10,
            Some("/sys/fs/cgroup/user.slice/test.scope".to_string()),
        );

        assert!(!inserted);
        assert_eq!(state.limits.len(), 1);
    }

    #[test]
    fn newly_discovered_pid_gets_state_record() {
        let template = record("brave", 10);
        let mut state = ZelynicState {
            limits: vec![template.clone()],
        };

        let inserted = append_refreshed_record(
            &mut state,
            &template,
            11,
            Some("/sys/fs/cgroup/user.slice/test.scope".to_string()),
        );

        assert!(inserted);
        assert_eq!(state.limits.len(), 2);
        assert!(record_exists_for_pid(&state, "brave", 11));
    }

    #[test]
    fn refreshed_pid_records_original_cgroup_path() {
        let template = record("brave", 10);
        let mut state = ZelynicState {
            limits: vec![template.clone()],
        };

        append_refreshed_record(
            &mut state,
            &template,
            11,
            Some("/sys/fs/cgroup/user.slice/app.scope".to_string()),
        );

        let refreshed = state.limits.iter().find(|record| record.pid == 11).unwrap();
        assert_eq!(
            refreshed.original_cgroup_path.as_deref(),
            Some("/sys/fs/cgroup/user.slice/app.scope")
        );
    }

    #[test]
    fn interface_mismatch_detects_changed_default_route() {
        assert!(interface_mismatch("wlp1s0", Some("eth0")));
        assert!(!interface_mismatch("wlp1s0", Some("wlp1s0")));
        assert!(!interface_mismatch("wlp1s0", None));
    }
}
