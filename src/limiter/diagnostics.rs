// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use colored::Colorize;
use std::fs;
use std::process::Command;

use super::cgroup::{cgroup2_mount_info, cgroup_mode_label};
use super::STATE_FILE;

fn diagnostic_command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            format!(
                "status={} stdout={} stderr={}",
                output.status,
                if stdout.is_empty() {
                    "(empty)"
                } else {
                    &stdout
                },
                if stderr.is_empty() {
                    "(empty)"
                } else {
                    &stderr
                }
            )
        }
        Err(e) => format!("failed to run: {}", e),
    }
}
pub(super) fn print_strict_diagnostic_header(
    target: &str,
    pids: &[u32],
    target_cg_path: &str,
    relative_cg_path: &str,
    level: u32,
) {
    println!("{}", "Strict backend diagnostics".bold());
    println!("  target: {}", target);
    println!("  kernel: {}", diagnostic_command_output("uname", &["-r"]));
    println!(
        "  nft: {}",
        diagnostic_command_output("nft", &["--version"])
    );
    println!("  tc: {}", diagnostic_command_output("tc", &["-V"]));
    println!("  cgroup mode: {}", cgroup_mode_label());
    println!("  cgroup2 mount info:\n{}", cgroup2_mount_info());
    println!("  target PIDs: {:?}", pids);
    println!("  target cgroup absolute path: {}", target_cg_path);
    println!("  target cgroup nft relative path: {}", relative_cg_path);
    println!("  computed cgroup level: {}", level);
}

pub(super) fn print_state_file_diagnostic() {
    println!("strict diagnostic: state file path: {}", STATE_FILE);
    match fs::read_to_string(STATE_FILE) {
        Ok(content) => println!("strict diagnostic: state file contents:\n{}", content),
        Err(e) => println!("strict diagnostic: failed to read state file: {}", e),
    }
}
