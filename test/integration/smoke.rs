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

/// NIGHT-boost-3: `--print-json` is the machine-first contract — one
/// compact single-line JSON document per invocation. doctor runs
/// unprivileged, so it pins the unified output::print_json writer
/// end-to-end: no pretty-print indentation, exactly one line, and
/// the line parses as one JSON document with the field contract
/// intact.
#[test]
fn test_doctor_print_json_is_one_compact_line() {
    let output = zelynic_cmd()
        .args(["doctor", "--print-json"])
        .output()
        .expect("Failed to execute zelynic doctor --print-json");

    assert!(
        output.status.success(),
        "zelynic doctor --print-json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one output line, got: {stdout}");
    let doc = lines[0];
    assert!(
        doc.starts_with('{') && doc.ends_with('}'),
        "a compact JSON object, got: {doc}"
    );
    assert!(
        !doc.contains("  "),
        "no pretty-print indentation, got: {doc}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(doc).expect("the line must parse as one JSON document");
    assert!(
        parsed.get("system").is_some() && parsed.get("ebpf_supported").is_some(),
        "field contract intact, got: {doc}"
    );
    // The honoring side of the NIGHT-boost-24 contract: doctor is a
    // JSON surface, so no ignored-note may ride stderr — the flag did
    // its job, silence is the honest answer.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--print-json ignored"),
        "a JSON surface must not warn about the flag, got: {stderr}"
    );
}

/// NIGHT-boost-24: `--print-json` on a non-JSON surface answers with
/// exactly one stderr note naming the honoring surfaces — stdout and
/// the exit code are untouched. `-V` runs unprivileged and renders the
/// version report, so this pins the honesty contract end-to-end on
/// the default path: the note fires in `main` before the early
/// return, and dispatch is never reached — one note, never two.
#[test]
fn test_print_json_ignored_note_rides_stderr_on_version() {
    let output = zelynic_cmd()
        .args(["--print-json", "--version"])
        .output()
        .expect("Failed to execute zelynic --print-json --version");

    assert!(
        output.status.success(),
        "the ignored note must not change the exit code, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--print-json ignored (JSON surface: "),
        "the note must name the surfaces, got: {stderr}"
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|l| l.contains("--print-json ignored"))
            .count(),
        1,
        "exactly one ignored note per invocation, got: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zelynic: v"),
        "the version report itself is unchanged, got: {stdout}"
    );
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
            && stdout.contains("Architecture: Cosmic Dragon")
            && stdout.contains("Build: ")
            && stdout.contains("License: GPL-3.0-only")
            && stdout.contains("Source: https://github.com/oxyzenQ/zelynic"),
        "Version report must contain the full zelynic metadata, got:\n{stdout}"
    );
}
