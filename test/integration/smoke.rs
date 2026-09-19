// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end surface checks: the binary runs, reports its version,
//! and the strict/unstrict lifecycle works (root-gated cases are
//! `#[ignore]`d so the default run needs no privileges).

use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::zelynic_cmd;

/// Test that doctor works
#[test]
fn test_doctor() {
    let output = zelynic_cmd()
        .arg("doctor")
        .output()
        .expect("Failed to execute zelynic doctor");

    assert!(
        output.status.success(),
        "zelynic doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zelynic doctor produced no output");
}

/// Test that list-apps works (requires root + eBPF feature)
#[test]
#[ignore = "requires root + eBPF feature"]
fn test_list_apps() {
    let output = zelynic_cmd()
        .arg("list-apps")
        .output()
        .expect("Failed to execute zelynic list-apps");

    assert!(
        output.status.success(),
        "zelynic list-apps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zelynic list-apps produced no output");
}

/// Test that invalid rate produces error
#[test]
#[ignore = "requires root + eBPF feature"]
fn test_rate_parse() {
    let output = zelynic_cmd()
        .args(["strict-single", "sleep", "-d", "invalid"])
        .output()
        .expect("Failed to execute zelynic strict-single");

    assert!(!output.status.success(), "Invalid rate should fail");
}

/// Test strict-single -> unstrict cycle
#[test]
#[ignore = "requires root + eBPF feature"]
#[allow(clippy::zombie_processes)]
fn test_strict_unstrict_cycle() {
    // Start a sleep process
    let mut sleep_cmd = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("Failed to start sleep process");

    let _pid = sleep_cmd.id();

    thread::sleep(Duration::from_millis(100));

    // Apply limit (lowercase rate units; per-direction flag)
    let output = zelynic_cmd()
        .args(["strict-single", "sleep", "-d", "1mb"])
        .output()
        .expect("Failed to apply limit");

    assert!(
        output.status.success(),
        "Failed to apply limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Remove limit
    let output = zelynic_cmd()
        .args(["unstrict", "sleep"])
        .output()
        .expect("Failed to remove limit");

    assert!(
        output.status.success(),
        "Failed to remove limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = sleep_cmd.kill();
}

/// Test version output (-V report: brand header + build facts)
#[test]
fn test_version() {
    let output = zelynic_cmd()
        .arg("--version")
        .output()
        .expect("Failed to get version");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zelynic: v")
            && stdout.contains("Architecture: Dragon")
            && stdout.contains("Build: ")
            && stdout.contains("License: GPL-3.0-only")
            && stdout.contains("Source: https://github.com/oxyzenQ/zelynic"),
        "Version report must contain the full zelynic metadata, got:\n{stdout}"
    );
}
