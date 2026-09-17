// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Integration tests for zelynic (Dragon Architecture — pure eBPF)
//!
//! These tests require root privileges and a Linux system.
//! Run with: sudo cargo test --test integration_test

use std::process::Command;
use std::thread;
use std::time::Duration;

/// Test helper to run zelynic commands
fn zelynic_cmd() -> Command {
    let binary = env!("CARGO_BIN_EXE_zelynic");
    let mut cmd = Command::new(binary);
    cmd.env("NO_COLOR", "1");
    cmd
}

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

/// NIGHT-hunt-5: the --no-color flag is gone — purple is branding and
/// branding has no CLI opt-out. Color control is env-only (NO_COLOR /
/// CLICOLOR / CLICOLOR_FORCE), exactly like cosmostrix.
#[test]
fn test_no_color_flag_is_rejected() {
    let output = zelynic_cmd()
        .args(["--no-color", "doctor"])
        .output()
        .expect("Failed to execute zelynic --no-color");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--no-color must be a usage error (exit 2)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "must report the unknown flag, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("--no-color'\n  tip"),
        "no self-suggestion for the removed flag"
    );
}

/// Typo suggestions are flagship: a near-miss subcommand must produce
/// clap's did-you-mean tip with the right exit code.
#[test]
fn test_typo_subcommand_gets_suggestion() {
    let output = zelynic_cmd()
        .arg("strict-singl")
        .output()
        .expect("Failed to execute zelynic strict-singl");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tip:"),
        "typo must carry a suggestion tip, got:\n{stderr}"
    );
    assert!(
        stderr.contains("strict-single"),
        "tip must point at strict-single, got:\n{stderr}"
    );
}

/// Case-variant flag typos are rescued: clap's own did-you-mean engine
/// is case-sensitive, so `--VERBOS` would render tip-less without the
/// case-insensitive fallback in cli::ux (NIGHT-hunt-5).
#[test]
fn test_case_variant_flag_typo_gets_rescued() {
    let output = zelynic_cmd()
        .args(["--VERBOS", "doctor"])
        .output()
        .expect("Failed to execute zelynic --VERBOS");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--verbose"),
        "case-variant typo must suggest --verbose, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Usage: zelynic"),
        "error must carry the real usage line, got:\n{stderr}"
    );
}

/// Piping into a short reader must not panic: the safe print macros
/// discard EPIPE instead of aborting with exit 101 (verified live
/// before NIGHT-hunt-5: `zelynic --help-all | head -2` panicked).
#[test]
fn test_help_all_pipe_to_head_does_not_panic() {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut child = zelynic_cmd()
        .arg("--help-all")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn zelynic --help-all");

    // Read a sliver, then drop the pipe handle — the reader end closes
    // while the child is still producing output, so its remaining
    // writes hit EPIPE. (If the child finishes first the test passes
    // trivially; either way a panic-exit-101 regression fails it.)
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = [0u8; 16];
        let _ = stdout.read(&mut buf);
        drop(stdout);
    }

    let status = child.wait().expect("Failed to wait for zelynic --help-all");
    assert!(
        status.success(),
        "EPIPE must truncate silently, not panic: {status}"
    );
}
