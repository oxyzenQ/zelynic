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
use std::sync::atomic::{AtomicBool, Ordering};

use crate::limiter;

use limiter::{
    apply_limit_with_diagnostics, build_traffic_proof, clean_orphans, sanitize_target_name,
    verify_pid_in_cgroup, ZelynicState,
};

/// CGROUP_BASE is in limiter/mod.rs but not public. Reproduce the constant
/// for this lab handler.
const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Cleanup status model
// ---------------------------------------------------------------------------

/// Result of an attempt to clean up strict-run-lab state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CleanupStatus {
    /// All cleanup steps succeeded.
    #[default]
    Succeeded,
    /// Some cleanup steps failed; details are in the vector.
    PartialFailure(Vec<String>),
    /// Cleanup was not attempted (e.g., child vanished before policy applied).
    NotAttempted,
}

// ---------------------------------------------------------------------------
// Ctrl+C signal handler (libc-based, no extra nix feature required)
// ---------------------------------------------------------------------------

/// Global flag set to true when SIGINT is received.
/// This is the only data the signal handler writes to — lock-free and
/// async-signal-safe.
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigint_handler(_signo: std::ffi::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::Release);
}

/// Install a SIGINT handler that sets `SIGINT_RECEIVED`.
/// Returns the previous `sigaction` struct so it can be restored.
fn install_sigint_handler() -> Result<libc::sigaction> {
    unsafe {
        let mut old_sa: libc::sigaction = std::mem::zeroed();
        let mut new_sa: libc::sigaction = std::mem::zeroed();
        new_sa.sa_sigaction = sigint_handler as *const () as libc::sighandler_t;
        new_sa.sa_flags = libc::SA_RESTART;
        libc::sigaddset(&mut new_sa.sa_mask, libc::SIGINT);
        if libc::sigaction(libc::SIGINT, &new_sa, &mut old_sa) != 0 {
            bail!("sigaction failed: {}", std::io::Error::last_os_error());
        }
        Ok(old_sa)
    }
}

/// Restore the previous SIGINT handler.
fn restore_sigint_handler(prev_sa: &libc::sigaction) {
    unsafe {
        let mut discarded: libc::sigaction = std::mem::zeroed();
        let _ = libc::sigaction(libc::SIGINT, prev_sa, &mut discarded);
    }
    SIGINT_RECEIVED.store(false, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Pure model types for validation freeze
// ---------------------------------------------------------------------------

/// Outcome of the strict-run-lab experiment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum StrictRunLabOutcome {
    Launched {
        child_pid: u32,
        verified_in_cgroup: bool,
    },
    PolicyApplied {
        child_pid: u32,
        verified_in_cgroup: bool,
        proof_state: StrictRunLabProofState,
    },
    Completed {
        child_pid: u32,
        verified_in_cgroup: bool,
        proof_state: StrictRunLabProofState,
        exit_success: bool,
        cleanup_attempted: bool,
    },
    #[default]
    ErrorBeforeLaunch,
    ErrorAfterLaunch {
        child_pid: u32,
        cleanup_attempted: bool,
    },
}

/// Proof state observed from nft counters during a lab run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StrictRunLabProofState {
    pub checked: bool,
    pub cgroup_match_observed: bool,
    pub policer_match_observed: bool,
    pub drop_observed: bool,
    pub is_tunnel: bool,
    pub placed_before_exec: bool,
}

impl StrictRunLabProofState {
    /// Build a proof state from the shared traffic proof model and lab context.
    pub fn from_traffic_proof(
        proof: &limiter::traffic_proof::StrictTrafficProof,
        placed_before_exec: bool,
    ) -> Self {
        let (cgroup_match_observed, policer_match_observed) =
            if let Some(ref counters) = proof.counters {
                (
                    counters.cgroup_match.packets > 0,
                    counters.policer_match.packets > 0,
                )
            } else {
                (false, false)
            };
        Self {
            checked: proof.counters.is_some(),
            cgroup_match_observed,
            policer_match_observed,
            drop_observed: policer_match_observed,
            is_tunnel: proof.tunnel.as_ref().map(|t| t.is_tunnel).unwrap_or(false),
            placed_before_exec,
        }
    }

    /// Honest classification: traffic proof is active only when cgroup match
    /// AND policer match are both observed with nonzero counters.
    pub fn is_traffic_proof_active(&self) -> bool {
        self.checked && self.cgroup_match_observed && self.policer_match_observed
    }
}

/// Render a lab proof summary to stdout.
pub fn render_lab_proof_summary(proof: &StrictRunLabProofState, interface: &str) {
    println!("{}", "--- strict-run-lab proof summary ---".dimmed());
    println!(
        "  Child placed in cgroup before sockets created: {}",
        if proof.placed_before_exec {
            "yes".green().to_string()
        } else {
            "no".red().to_string()
        }
    );
    println!(
        "  Traffic proof checked: {}",
        if proof.checked {
            "yes".to_string()
        } else {
            "no".dimmed().to_string()
        }
    );
    println!(
        "  nft socket cgroupv2 match observed: {}",
        if proof.cgroup_match_observed {
            "yes (packets > 0)".green().to_string()
        } else {
            "no (0 packets)".yellow().to_string()
        }
    );
    println!(
        "  nft download policer match observed: {}",
        if proof.policer_match_observed {
            "yes (packets > 0)".green().to_string()
        } else {
            "no (0 packets)".yellow().to_string()
        }
    );
    println!(
        "  nft drop counter observed: {}",
        if proof.drop_observed {
            "yes (packets > 0)".green().to_string()
        } else {
            "no (0 packets)".yellow().to_string()
        }
    );
    if proof.is_tunnel {
        println!(
            "  Interface {} is a VPN/tunnel interface.",
            interface.yellow()
        );
        println!("  {}", "WARNING: VPN/tunnel cases may still vary.".yellow());
    }
    println!();
    println!(
        "  Proof conclusion: {}",
        if proof.is_traffic_proof_active() {
            "traffic proof observed -- shaping appears active in this run"
                .green()
                .to_string()
        } else if proof.checked && !proof.cgroup_match_observed {
            "no traffic proof observed -- counters remain at zero"
                .yellow()
                .to_string()
        } else if proof.checked && proof.cgroup_match_observed && !proof.policer_match_observed {
            "partial proof -- cgroup match observed but policer did not trigger"
                .yellow()
                .to_string()
        } else {
            "traffic proof not checked".dimmed().to_string()
        }
    );
    println!();
    println!(
        "  {}",
        "IMPORTANT: attach-after-socket limitation remains for stable 'strict'.".yellow()
    );
    println!(
        "  {}",
        "This experiment is not stable. Do not promote based on a single run.".yellow()
    );
    println!("{}", "--- end proof summary ---".dimmed());
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

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
    println!(
        "{}",
        "Attach-after-socket limitation remains for stable 'strict'.".yellow()
    );
    println!("{}", "=".repeat(60).dimmed());
    println!();
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the hidden `strict-run-lab` command.
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
    // We only write the child's own PID to a cgroup.procs file.
    unsafe {
        cmd.pre_exec(move || {
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

    if let Err(e) = apply_limit_with_diagnostics(
        &target_name,
        download.as_deref(),
        upload.as_deref(),
        iface_value,
        true, // always diagnose in lab mode
    ) {
        eprintln!("{}: Failed to apply policy: {}", "ERROR".red().bold(), e);
        let _ = child.kill();
        let _ = child.wait();
        attempt_cleanup(&target_cg_path, &interface, &target_name, diagnose);
        return Err(e);
    }

    println!("  Policy installed.");
    println!();

    // --- Step 6: Traffic proof diagnostics ---
    let tid = limiter::target_class_id(&target_name);
    let traffic_proof = build_traffic_proof(
        true, // always diagnose in lab mode
        &interface,
        iface_value.is_some(),
        &target_cg_path,
        &target_name,
        tid,
    );

    let lab_proof_state =
        StrictRunLabProofState::from_traffic_proof(&traffic_proof, verified_in_cgroup);

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

    // Traffic proof section
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

    // Lab proof summary with detailed counter breakdown
    render_lab_proof_summary(&lab_proof_state, &interface);

    println!("{}", "Waiting for child process to exit...".dimmed());
    println!(
        "{}",
        "(Press Ctrl+C to stop the child and trigger cleanup)".dimmed()
    );
    println!();

    // --- Step 7: Wait for child exit (with Ctrl+C handling) ---
    let prev_sa = install_sigint_handler().context("failed to install SIGINT handler")?;

    // Wait in a loop so we can check the signal flag.
    // On SIGINT, our handler sets SIGINT_RECEIVED, and we break out
    // to kill the child and run cleanup.
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if SIGINT_RECEIVED.load(Ordering::Acquire) {
                    eprintln!(
                        "{} Ctrl+C received, stopping child (PID {})...",
                        "SIGINT".yellow().bold(),
                        child_pid
                    );
                    let _ = child.kill();
                    // Wait for child after kill so we reap it.
                    match child.wait() {
                        Ok(s) => break Ok(s),
                        Err(e) => break Err(e),
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => break Err(e),
        }
    }
    .context("failed to wait for child process")?;

    // Restore default signal handling after child is reaped.
    restore_sigint_handler(&prev_sa);
    let interrupted = SIGINT_RECEIVED.load(Ordering::Acquire);
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
    if interrupted {
        eprintln!("{} Cleanup attempted after Ctrl+C.", "->".cyan());
    } else {
        println!("{} Cleanup attempted after child exit.", "->".cyan());
    }
    let cleanup_status = attempt_cleanup(&target_cg_path, &interface, &target_name, diagnose);

    // Remove state entry for this target/pid.
    let mut final_state = ZelynicState::load().unwrap_or_default();
    final_state
        .limits
        .retain(|l| l.target != target_name && l.pid != child_pid);
    final_state.save().ok();

    // Remove nft table if no limits remain.
    // Note: The lab manages a single target, so after removing its state entry,
    // the table should be empty. If other limits exist, their rules remain
    // untouched (they were not modified by this lab run).
    if final_state.limits.is_empty() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "zelynic"])
            .output();
    }

    // Print cleanup summary.
    match &cleanup_status {
        CleanupStatus::Succeeded => {
            println!("  Cleanup: {}", "succeeded".green());
        }
        CleanupStatus::PartialFailure(errors) => {
            println!("  Cleanup: {}", "partially failed".yellow().bold());
            for e in errors.iter().take(5) {
                println!("    {}", e);
            }
        }
        CleanupStatus::NotAttempted => {
            println!("  Cleanup: {}", "not attempted".dimmed());
        }
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
    println!(
        "{}",
        "Attach-after-socket limitation remains for stable 'strict'.".yellow()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Attempt cleanup of cgroup and tc objects. Returns a CleanupStatus.
fn attempt_cleanup(
    target_cg_path: &str,
    interface: &str,
    target_name: &str,
    diagnose: bool,
) -> CleanupStatus {
    let mut errors = Vec::new();

    // 1. Remove target cgroup directory.
    if let Err(e) = fs::remove_dir(target_cg_path) {
        let msg = format!("failed to remove cgroup dir: {}", e);
        if diagnose {
            println!("  Cleanup: {}", msg);
        }
        errors.push(msg);
    } else {
        println!("  Cleanup: removed target cgroup directory.");
    }

    // 2. Remove tc filters and HTB class.
    let sanitized = sanitize_target_name(
        Path::new(target_cg_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(target_name),
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

    if errors.is_empty() {
        CleanupStatus::Succeeded
    } else {
        CleanupStatus::PartialFailure(errors)
    }
}

#[cfg(test)]
mod ctrlc_cleanup_tests;
#[cfg(test)]
mod strict_run_lab_tests;
