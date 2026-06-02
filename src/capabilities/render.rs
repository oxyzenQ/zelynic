// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use colored::Colorize;

use super::types::{BackendDoctorReport, CapabilityStatus, ToolInfo};

pub(super) fn print_backend_doctor_report(report: &BackendDoctorReport) {
    println!("{}", "Zelynic Backend Doctor".bold());
    println!();

    println!("{}", "System:".bold());
    println!("  Kernel: {}", report.system.kernel);
    println!("  cgroup: {}", report.system.cgroup_mode);
    println!(
        "  cgroup2 mount: {}",
        report
            .system
            .cgroup2_mount_path
            .as_deref()
            .unwrap_or("not found")
    );
    println!(
        "  cgroup2 flags: {}",
        if report.system.cgroup2_mount_flags.is_empty() {
            "unknown".to_string()
        } else {
            report.system.cgroup2_mount_flags.join(",")
        }
    );
    println!("  nftables: {}", tool_display(&report.system.nftables));
    println!("  tc/iproute2: {}", tool_display(&report.system.tc));
    println!("  systemd: {}", tool_display(&report.system.systemd));
    println!(
        "  systemd-run: {}",
        tool_display(&report.system.systemd_run)
    );
    println!();

    println!("{}", "Capabilities:".bold());
    println!("  cgroup v2: {}", report.capabilities.cgroup_v2);
    println!(
        "  nft socket cgroupv2: {}",
        report.capabilities.nft_socket_cgroupv2
    );
    println!("  tc HTB: {}", report.capabilities.tc_htb);
    println!("  fw filter: {}", report.capabilities.fw_filter);
    println!("  conntrack mark: {}", report.capabilities.conntrack_mark);
    println!("  BPF filesystem: {}", report.capabilities.bpf_fs_mounted);
    println!("  eBPF: {}", ebpf_display(report.capabilities.ebpf));
    println!(
        "  transient scope wrapper: {}",
        report.capabilities.transient_scope_wrapper
    );
    println!("  recommended for v2.2 run mode: experimental/future");
    println!();

    println!("{}", "Backend candidates:".bold());
    for candidate in &report.backend_candidates {
        println!(
            "  {}: {}, confidence {}%",
            candidate.name, candidate.status, candidate.confidence
        );
        if !candidate.missing_requirements.is_empty() {
            println!("    missing: {}", candidate.missing_requirements.join(", "));
        }
        if !candidate.risk_notes.is_empty() {
            println!("    risks: {}", candidate.risk_notes.join("; "));
        }
    }
    println!();

    println!("{}", "Recommended:".bold());
    println!(
        "  {}",
        report
            .recommended_backend
            .as_deref()
            .unwrap_or("no available backend")
    );
    println!();

    println!("{}", "Notes:".bold());
    for note in &report.notes {
        println!("  - {}", note);
    }
    for warning in &report.warnings {
        println!("  - {}", warning);
    }
}

fn tool_display(tool: &ToolInfo) -> String {
    if tool.available {
        tool.version.clone()
    } else {
        "not found".to_string()
    }
}

fn ebpf_display(status: CapabilityStatus) -> String {
    match status {
        CapabilityStatus::Yes => "supported but not implemented".to_string(),
        CapabilityStatus::RequiresRoot => {
            "likely supported; requires root to verify capability".to_string()
        }
        other => format!("{}; not implemented", other),
    }
}
