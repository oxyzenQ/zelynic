// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use colored::Colorize;

use super::traffic_proof::render_strict_traffic_proof;
use super::traffic_proof::StrictTrafficProof;

pub(crate) struct StrictApplySummary<'a> {
    pub target: &'a str,
    pub discovered_count: usize,
    pub moved_count: usize,
    pub verified_count: usize,
    pub vanished_count: usize,
    pub failed_count: usize,
    pub pids: &'a [u32],
    pub download_display: Option<&'a str>,
    pub upload_display: Option<&'a str>,
    pub interface: &'a str,
    pub use_v2: bool,
    pub target_cg_path: &'a str,
    pub applied_count: usize,
    pub traffic_proof: &'a StrictTrafficProof,
}

pub(crate) fn print_strict_apply_summary(summary: &StrictApplySummary<'_>) {
    if summary.applied_count == 0 {
        println!(
            "{}",
            "zelynic strict: no bandwidth limits were applied"
                .yellow()
                .bold()
        );
        return;
    }

    println!(
        "{}",
        "zelynic strict: bandwidth limit applied".green().bold()
    );
    println!();
    println!("  Target:    {}", summary.target);
    println!("  Discovered PIDs: {}", summary.discovered_count);
    println!("  Moved PIDs:      {}", summary.moved_count);
    println!("  Verified PIDs:   {}", summary.verified_count);
    println!("  Vanished PIDs:   {}", summary.vanished_count);
    println!("  Failed PIDs:     {}", summary.failed_count);
    println!(
        "  PIDs:      {}",
        summary
            .pids
            .iter()
            .map(|p| format!("{}", p))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Honesty wording: "policy installed" not "limited".
    // "PID moved and verified" does NOT prove traffic is being shaped.
    // The nft/tc policy is installed, but traffic matching is proven only
    // when nft counters are non-zero (inspected via --diagnose).
    if let Some(dl) = summary.download_display {
        println!(
            "  Download:  {} (policy installed, nftables policer)",
            dl.cyan()
        );
    } else {
        println!("  Download:  {}", "unlimited".dimmed());
    }

    if let Some(ul) = summary.upload_display {
        println!("  Upload:    {} (policy installed, HTB)", ul.cyan());
    } else {
        println!("  Upload:    {}", "unlimited".dimmed());
    }

    println!("  Interface: {}", summary.interface);
    println!(
        "  Backend:   nftables + HTB | {}",
        if summary.use_v2 {
            "cgroup v2 (per-target isolation)"
        } else {
            "cgroup v1 fallback"
        }
    );
    println!("  Applied:   {} process(es)", summary.applied_count);

    if summary.use_v2 {
        println!(
            "  Cgroup:    {} (per-target isolation)",
            summary.target_cg_path
        );
    }

    // Traffic proof section: honest status about whether traffic is actually
    // being matched by the installed nft rules. Only populated when --diagnose
    // is used (reads nft counters), otherwise shows "not checked".
    render_strict_traffic_proof(summary.traffic_proof);

    println!();
    println!(
        "  {} Use 'zelynic unstrict {}' to remove limits.",
        "Info:".yellow(),
        summary.target
    );
}
