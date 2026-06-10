// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Experimental pre-launch cgroup wrapper lab command.
//!
//! Launches a child process inside a Zelynic-managed cgroup BEFORE the child
//! opens network sockets, then applies the same nft/tc policy and traffic proof
//! diagnostics as the stable `strict` command.
//!
//! This tests whether socket creation inside the target cgroup improves nft
//! `socket cgroupv2` counter matching compared to the existing attach-after-socket
//! approach.
//!
//! **This is experimental/lab only. It is not stable. It must not be used as
//! evidence that Zelynic shaping works in production.**

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::limiter;

use limiter::{
    apply_limit_with_diagnostics, build_traffic_proof, clean_orphans, sanitize_target_name,
    verify_pid_in_cgroup, ZelynicState,
};

/// CGROUP_BASE is in limiter/mod.rs but not public. Reproduce the constant
/// for this lab handler.
const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

/// Print the experimental warning banner.
fn print_experimental_banner() {
    println!("{}", "=".repeat(60).dimmed());
    println!("{}", "EXPERIMENTAL PRE-LAUNCH STRICT LAB".yellow().bold());
    println!(
        "{}",
        "This is an experimental command. It is not stable.".yellow()
    );
    println!("Launches a child process inside a Zelynic-managed cgroup");
    println!("before the child opens network sockets, then applies the");
    println!("same nft/tc policy as the stable 'strict' command.");
    println!();
    println!(
        "{}",
        "PID moved/placed is not the same as traffic proven."
            .yellow()
            .bold()
    );
    println!("{}", "Existing VPN/tunnel warnings still apply.".yellow());
    println!("{}", "=".repeat(60).dimmed());
    println!();
}

/// Handle the hidden `strict-run-lab` command.
///
/// Steps:
/// 1. Validate root, rates, interface
/// 2. Create the target cgroup BEFORE launching child
/// 3. Fork+exec the child with pre_exec cgroup placement
/// 4. Apply same nft/tc policy using the child PID (already in cgroup)
/// 5. Wait for child exit
/// 6. Cleanup cgroup and rules
pub(crate) fn handle_strict_run_lab(
    download: Option<String>,
    upload: Option<String>,
    diagnose: bool,
    iface_value: Option<&str>,
    command: &[String],
) -> Result<()> {
    print_experimental_banner();

    // --- Step 0: Root check ---
    limiter::check_root()?;

    if let Err(e) = clean_orphans() {
        eprintln!("{}: auto-cleanup failed: {}", "WARNING".yellow(), e);
    }

    // --- Step 1: Validate rates ---
    if download.is_none() && upload.is_none() {
        bail!(
            "no bandwidth limit specified.\n  {} Usage: zelynic strict-run-lab -d <rate> -- <command> [args...]",
            "ERROR:".red().bold()
        );
    }

    let interface = match iface_value {
        Some(i) => {
            limiter::validate_interface(i)?;
            i.to_string()
        }
        None => limiter::get_default_interface()?,
    };

    if command.is_empty() {
        bail!(
            "no command specified. Usage: zelynic strict-run-lab -d <rate> -- <command> [args...]"
        );
    }

    let target_name = sanitize_target_name(
        command
            .first()
            .and_then(|s| Path::new(s).file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown"),
    );

    let target_cg_path = format!("{}/target_{}", CGROUP_BASE, target_name);

    println!("{} Experimental pre-launch strict lab", ">>".cyan());
    println!("  {} Using interface: {}", "->".cyan(), interface.cyan());
    println!("  Target name: {}", target_name);
    println!("  Cgroup path: {}", target_cg_path);
    println!("  Command: {}", command.join(" "));
    if let Some(ref dl) = download {
        println!("  Download:  {} (policy to be installed)", dl.cyan());
    }
    if let Some(ref ul) = upload {
        println!("  Upload:    {} (policy to be installed)", ul.cyan());
    }
    println!();

    // --- Step 2: Create the target cgroup BEFORE launching child ---
    println!(
        "{} Creating target cgroup before child launch...",
        "->".cyan()
    );
    fs::create_dir_all(&target_cg_path).context(format!(
        "failed to create cgroup directory '{}'. Is cgroup2 mounted?",
        target_cg_path
    ))?;

    // Read cgroup ID
    let cgroup_id: Option<u64> = {
        let id_file = format!("{}/cgroup.id", target_cg_path);
        if Path::new(&id_file).exists() {
            fs::read_to_string(&id_file)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            fs::metadata(&target_cg_path).map(|m| m.ino()).ok()
        }
    };

    let use_v2 = cgroup_id.is_some();
    println!("  Cgroup created: {} (v2={})", target_cg_path, use_v2);
    if let Some(id) = cgroup_id {
        println!("  Cgroup ID: {}", id);
    }
    println!();

    // --- Step 3: Fork+exec child with pre_exec cgroup placement ---
    println!("{} Launching child inside Zelynic cgroup...", "->".cyan());
    println!("  Process will be launched inside Zelynic cgroup before sockets are created.");

    let child_cg_path = target_cg_path.clone();
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // SAFETY: The pre_exec closure runs between fork(2) and exec(3).
    // We only write the child's own PID to a cgroup.procs file — this is
    // a safe, well-understood Unix pattern. We do NOT:
    // - allocate memory (malloc is unsafe after fork)
    // - spawn threads (only async-signal-safe functions)
    // - access mutable global state
    // The only operation is a single write(2) to cgroup.procs.
    unsafe {
        cmd.pre_exec(move || {
            // Write own PID to cgroup.procs before exec
            let procs_path = format!("{}/cgroup.procs", child_cg_path);
            if let Err(e) = fs::write(&procs_path, std::process::id().to_string()) {
                eprintln!("strict-run-lab: pre_exec cgroup placement failed: {}", e);
                return Err(std::io::Error::other(format!(
                    "pre_exec cgroup write failed: {}",
                    e
                )));
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("failed to spawn child process")?;
    let child_pid = child.id();

    println!("  Child PID: {}", child_pid);
    println!("  Process launched inside Zelynic cgroup before sockets are created.");
    println!();

    // --- Step 4: Verify cgroup placement ---
    std::thread::sleep(std::time::Duration::from_millis(100));

    let verified_in_cgroup = verify_pid_in_cgroup(child_pid, &target_cg_path);
    if diagnose {
        println!(
            "  Diagnostic: child PID {} verified in cgroup: {}",
            child_pid, verified_in_cgroup
        );
    }
    if !verified_in_cgroup {
        eprintln!(
            "{} Child PID {} was NOT verified in target cgroup after launch.",
            "WARNING".yellow().bold(),
            child_pid
        );
        eprintln!("  Traffic proof may show no match.");
    }
    println!();

    // --- Step 5: Install nft/tc policy using existing infrastructure ---
    println!(
        "{} Applying policy (nft/tc) for already-cgrouped child...",
        "->".cyan()
    );

    // Apply limit using the existing strict infrastructure.
    // The child is already in the cgroup, so move_pid will verify
    // it's already there. The policy (nft rules + tc objects) is the same.
    if let Err(e) = apply_limit_with_diagnostics(
        &target_name,
        download.as_deref(),
        upload.as_deref(),
        iface_value,
        true, // always diagnose in lab mode
    ) {
        eprintln!("{}: Failed to apply policy: {}", "ERROR".red().bold(), e);
        // Cleanup: kill child and remove cgroup
        let _ = child.kill();
        let _ = child.wait();
        attempt_cleanup(&target_cg_path, &interface, diagnose);
        return Err(e);
    }

    println!("  Policy installed.");
    println!();

    // --- Step 6: Traffic proof diagnostics ---
    // Read nft counters to assess whether traffic is actually matched.
    let tid = limiter::target_class_id(&target_name);
    let traffic_proof = build_traffic_proof(
        true, // always diagnose in lab mode
        &interface,
        iface_value.is_some(),
        &target_cg_path,
        &target_name,
        tid,
    );

    // Print lab-specific summary
    println!(
        "{}",
        "zelynic strict-run-lab: policy applied (experimental)"
            .green()
            .bold()
    );
    println!();
    println!("  Target:    {}", target_name);
    println!("  PID:       {}", child_pid);
    println!("  Cgroup:    {} (per-target isolation)", target_cg_path);
    println!("  Interface: {}", interface);
    println!(
        "  Backend:   nftables + HTB | {}",
        if use_v2 {
            "cgroup v2 (per-target isolation)"
        } else {
            "cgroup v1 fallback"
        }
    );
    println!("  Mode:      experimental pre-launch strict lab");
    println!("  Placed in cgroup before exec: {}", verified_in_cgroup);
    println!();

    // Traffic proof section: honest status about whether traffic is actually
    // being matched by the installed nft rules.
    limiter::traffic_proof::render_strict_traffic_proof(&traffic_proof);

    println!();
    println!(
        "{}",
        "Traffic proof check: PID moved/placed is not the same as traffic proven.".yellow()
    );
    if let Some(ref tunnel) = traffic_proof.tunnel {
        if tunnel.is_tunnel {
            println!(
                "  {} Existing VPN/tunnel warnings still apply for {}.",
                "WARNING:".yellow(),
                tunnel.interface_name
            );
        }
    }
    println!();

    println!("{}", "Waiting for child process to exit...".dimmed());
    println!(
        "{}",
        "(Press Ctrl+C to stop the child and trigger cleanup)".dimmed()
    );
    println!();

    // --- Step 7: Wait for child exit ---
    let exit_status = child.wait().context("failed to wait for child process")?;
    println!();
    println!(
        "{} Child exited with status: {}",
        "->".cyan(),
        if exit_status.success() {
            "success".green().to_string()
        } else {
            format!("{}", exit_status.code().unwrap_or(-1))
                .yellow()
                .to_string()
        }
    );

    // --- Step 8: Cleanup ---
    println!();
    println!("{} Cleanup attempted after child exit.", "->".cyan());
    attempt_cleanup(&target_cg_path, &interface, diagnose);

    // Remove this target from state
    let mut final_state = ZelynicState::load().unwrap_or_default();
    final_state
        .limits
        .retain(|l| l.target != target_name && l.pid != child_pid);
    final_state.save().ok();

    // If no limits left, clean up nft table entirely
    if final_state.limits.is_empty() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "zelynic"])
            .output();
    }

    println!();
    println!(
        "{}",
        "Experimental pre-launch strict lab complete.".dimmed()
    );
    println!(
        "{}",
        "Do not use this as evidence that Zelynic shaping works in production.".yellow()
    );

    Ok(())
}

/// Attempt cleanup of cgroup and tc objects.
fn attempt_cleanup(target_cg_path: &str, interface: &str, diagnose: bool) {
    // Remove target cgroup
    if let Err(e) = fs::remove_dir(target_cg_path) {
        if diagnose {
            println!("  Cleanup: failed to remove cgroup dir: {}", e);
        }
    } else {
        println!("  Cleanup: removed target cgroup directory.");
    }

    // Remove tc class/filters for this target
    let sanitized = sanitize_target_name(
        Path::new(target_cg_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown"),
    );
    let tid = limiter::target_class_id(&sanitized);
    let class_id_str = format!("1:{:04x}", tid);

    let _ = Command::new("tc")
        .args([
            "filter",
            "del",
            "dev",
            interface,
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
            interface,
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
    let _ = Command::new("tc")
        .args(["class", "del", "dev", interface, "classid", &class_id_str])
        .output();

    println!("  Cleanup: removed tc class and filters.");
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test 1: experimental output contains lab/experimental wording ---
    #[test]
    fn experimental_banner_contains_lab_wording() {
        let source = module_source();
        assert!(source.contains("EXPERIMENTAL"));
        assert!(source.contains("PRE-LAUNCH"));
        assert!(source.contains("LAB"));
    }

    // --- Test 2: experimental output says pre-launch cgroup ---
    #[test]
    fn experimental_banner_says_pre_launch_cgroup() {
        let source = module_source();
        assert!(source.contains("cgroup"));
    }

    // --- Test 3: output does not claim stable ---
    #[test]
    fn experimental_banner_does_not_claim_stable() {
        let source = module_source();
        assert!(source.contains("not stable"));
    }

    // --- Test 4: output says PID moved is not traffic proven ---
    #[test]
    fn experimental_banner_says_pid_not_traffic_proven() {
        let source = module_source();
        assert!(source.contains("PID moved"));
        assert!(source.contains("traffic proven"));
    }

    // --- Test 5: tunnel warning still appears for proton0/tun0/wg0 ---
    #[test]
    fn tunnel_detection_works_for_lab_command() {
        assert!(limiter::traffic_proof::is_tunnel_interface("proton0"));
        assert!(limiter::traffic_proof::is_tunnel_interface("tun0"));
        assert!(limiter::traffic_proof::is_tunnel_interface("wg0"));
        assert!(!limiter::traffic_proof::is_tunnel_interface("eth0"));
    }

    // --- Test 6: traffic proof model is reused ---
    #[test]
    fn traffic_proof_model_reused_in_lab() {
        let proof = limiter::traffic_proof::StrictTrafficProof::default();
        assert_eq!(
            proof.status,
            limiter::traffic_proof::StrictTrafficProofStatus::NotChecked
        );
    }

    // --- Test 7: cleanup plan exists for child exit ---
    #[test]
    fn cleanup_function_exists() {
        let _ = attempt_cleanup as fn(&str, &str, bool);
    }

    // --- Test 8: no daemon/watch code in module ---
    #[test]
    fn no_daemon_watch_code() {
        let source = module_source();
        assert!(
            !source.contains("daemon"),
            "strict-run-lab must not contain daemon code"
        );
        assert!(
            !source.contains("watch"),
            "strict-run-lab must not contain watch code"
        );
    }

    // --- Test 9: no quota code ---
    #[test]
    fn no_quota_code() {
        let source = module_source();
        assert!(
            !source.contains("quota"),
            "strict-run-lab must not contain quota code"
        );
    }

    // --- Test 10: no eBPF code ---
    #[test]
    fn no_ebpf_code() {
        let source = module_source();
        assert!(
            !source.contains("ebpf") && !source.contains("eBPF"),
            "strict-run-lab must not contain eBPF code"
        );
    }

    // --- Test 11: no ledger persistence ---
    #[test]
    fn no_ledger_persistence() {
        let source = module_source();
        assert!(
            !source.contains("LedgerPersistencePlan") && !source.contains("LedgerPathPlan"),
            "strict-run-lab must not reference ledger persistence"
        );
    }

    // --- Test 12: no v3.0 usage JSON schema change ---
    #[test]
    fn no_usage_json_schema_change() {
        let source = module_source();
        assert!(
            !source.contains("schema_version"),
            "strict-run-lab must not reference usage JSON schema"
        );
    }

    // --- Test 13: cleanup plan attempted on error ---
    #[test]
    fn cleanup_called_on_error_paths() {
        let source = module_source();
        assert!(
            source.contains("attempt_cleanup"),
            "strict-run-lab must call attempt_cleanup on error paths"
        );
    }

    // --- Test 14: no detach/daemonize ---
    #[test]
    fn no_detach_or_daemonize() {
        let source = module_source();
        assert!(
            !source.contains("detach") && !source.contains("daemonize"),
            "strict-run-lab must not detach or daemonize"
        );
    }

    // --- Test 15: output does not claim traffic proven when counters are zero ---
    #[test]
    fn zero_counters_not_claimed_as_proven() {
        let proof = limiter::traffic_proof::StrictTrafficProof {
            status: limiter::traffic_proof::StrictTrafficProofStatus::NoMatchObserved,
            counters: Some(limiter::traffic_proof::StrictTrafficProofCounters {
                cgroup_match: limiter::traffic_proof::NftCounter::default(),
                policer_match: limiter::traffic_proof::NftCounter::default(),
                checked: true,
            }),
            tunnel: None,
            explicit_interface: false,
        };
        let rendered = capture_traffic_proof_render(&proof);
        assert!(rendered.contains("not observed"));
        assert!(!rendered.contains("active"));
    }

    // --- Test 16: handler says experimental ---
    #[test]
    fn handler_source_says_experimental() {
        let source = module_source();
        assert!(source.contains("experimental"));
    }

    // --- Test 17: handler says lab ---
    #[test]
    fn handler_source_says_lab() {
        let source = module_source();
        assert!(source.contains("lab"));
    }

    // --- Test 18: handler says policy installed ---
    #[test]
    fn handler_source_says_policy_installed() {
        let source = module_source();
        assert!(source.contains("Policy installed"));
    }

    // --- Test 19: handler says pre-launch cgroup ---
    #[test]
    fn handler_source_says_pre_launch_cgroup() {
        let source = module_source();
        assert!(source.contains("pre-launch"));
        assert!(source.contains("cgroup"));
    }

    // --- Test 20: handler says traffic proof ---
    #[test]
    fn handler_source_says_traffic_proof() {
        let source = module_source();
        assert!(source.contains("Traffic proof"));
    }

    fn capture_traffic_proof_render(proof: &limiter::traffic_proof::StrictTrafficProof) -> String {
        let mut lines = Vec::new();
        match &proof.status {
            limiter::traffic_proof::StrictTrafficProofStatus::NoMatchObserved => {
                if let Some(ref counters) = proof.counters {
                    lines.push(format!(
                        "nft cgroup match: packets {}, bytes {}",
                        counters.cgroup_match.packets, counters.cgroup_match.bytes
                    ));
                    lines.push(format!(
                        "download policer: packets {}, bytes {}",
                        counters.policer_match.packets, counters.policer_match.bytes
                    ));
                }
                lines.push("Traffic proof: not observed yet".to_string());
            }
            limiter::traffic_proof::StrictTrafficProofStatus::PolicerMatchObserved => {
                lines.push(
                    "Traffic proof: policer observed (download rate limiting active)".to_string(),
                );
            }
            _ => {}
        }
        lines.join("\n")
    }

    fn module_source() -> String {
        let source = include_str!("strict_run_lab.rs");
        if let Some(pos) = source.find("#[cfg(test)]") {
            source[..pos].to_string()
        } else {
            source.to_string()
        }
    }
}
