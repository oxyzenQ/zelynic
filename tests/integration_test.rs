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

/// NIGHT-hunt-9: -v/--verbose is a real global flag — it must parse on
/// any command path (here: doctor, which never touches eBPF) without
/// changing the exit contract. Pins the global=true wiring so a future
/// refactor cannot silently demote it to a per-command flag.
#[test]
fn test_verbose_flag_parses_globally() {
    let output = zelynic_cmd()
        .args(["--verbose", "doctor"])
        .output()
        .expect("Failed to execute zelynic --verbose doctor");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--verbose must be accepted globally, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Piping into a short reader must not panic: the safe print macros
/// discard EPIPE instead of aborting with exit 101 (verified live
/// before NIGHT-hunt-5: `zelynic --help | head -2` panicked — then the
/// flag was still --help-all; merged into --help by NIGHT-improve-3).
#[test]
fn test_help_pipe_to_head_does_not_panic() {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut child = zelynic_cmd()
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn zelynic --help");

    // Read a sliver, then drop the pipe handle — the reader end closes
    // while the child is still producing output, so its remaining
    // writes hit EPIPE. (If the child finishes first the test passes
    // trivially; either way a panic-exit-101 regression fails it.)
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = [0u8; 16];
        let _ = stdout.read(&mut buf);
        drop(stdout);
    }

    let status = child.wait().expect("Failed to wait for zelynic --help");
    assert!(
        status.success(),
        "EPIPE must truncate silently, not panic: {status}"
    );
}

/// NIGHT-improve-3: --help is the single end-to-end reference (the
/// former --help-all merged in). Every CLI surface command must appear
/// in it — this is the drift pin between the Commands enum and the
/// curated reference. Extend the list when the CLI surface grows.
#[test]
fn test_help_lists_every_command() {
    const KNOWN_COMMANDS: [&str; 17] = [
        "strict-single",
        "strict-multi",
        "limit-all",
        "block-single",
        "block-multi",
        "block-all",
        "unstrict",
        "unstrict-multi",
        "unstrict-single",
        "unstrict-all",
        "recover",
        "status",
        "list-apps",
        "observe",
        "top",
        "doctor",
        "strict",
    ];

    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0), "--help exits 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for section in ["Commands:", "Global flags:", "Rate formats:", "Examples:"] {
        assert!(stdout.contains(section), "--help must carry {section}");
    }
    for cmd in KNOWN_COMMANDS {
        assert!(
            stdout.contains(cmd),
            "--help must document the '{cmd}' command"
        );
    }
    // NIGHT-hunt-12: the removed `man` subcommand must NOT be
    // documented anymore — --help is the only reference surface.
    assert!(
        !stdout.contains("zelynic man"),
        "--help must not document the removed 'man' command, got:\n{stdout}"
    );
}

/// NIGHT-improve-5: the reference groups commands by verb — strict,
/// limit, block, unstrict (owner's grouping), plus monitor and system —
/// so the command surface scans as six chunks. Pins the group
/// headings in --help (NIGHT-hunt-12: the man page renderer is gone,
/// so --help is the only pinned surface).
#[test]
fn test_help_groups_commands_by_verb() {
    const GROUPS: [&str; 6] = [
        "strict — apply rate limits",
        "limit — bulk rate limits",
        "block — cut internet access",
        "unstrict — remove limits & recover",
        "monitor — traffic visibility",
        "system — support",
    ];

    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for g in GROUPS {
        assert!(
            stdout.contains(g),
            "--help must carry the '{g}' group heading"
        );
    }
}

/// Bare invocation prints the same single reference as --help (exit 0,
/// stdout) — the old clap auto-help path is gone with the single-tier
/// help surface.
#[test]
fn test_bare_invocation_prints_reference() {
    let output = zelynic_cmd()
        .output()
        .expect("Failed to execute bare zelynic");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Commands:"),
        "bare zelynic prints the end-to-end reference, got:\n{stdout}"
    );
}

/// NIGHT-improve-3 owner contract: --help typed after a subcommand is a
/// usage error (exit 2) whose tip points at the one help authority —
/// `zelynic --help` — with the real usage line and exactly one
/// canonical footer.
#[test]
fn test_subcommand_help_errors_with_suggestion() {
    let output = zelynic_cmd()
        .args(["strict-single", "brave", "--help"])
        .output()
        .expect("Failed to execute zelynic strict-single brave --help");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--help'"),
        "must name the rejected flag, got:\n{stderr}"
    );
    assert!(
        stderr.contains("'zelynic --help'"),
        "tip must point at the top-level help authority, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Usage: zelynic"),
        "error must carry the real usage line, got:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("For more information, try '--help'.")
            .count(),
        1,
        "exactly one canonical footer, got:\n{stderr}"
    );
}

/// The removed --help-all flag must land users on the merged surface:
/// usage error with a --help suggestion (old muscle memory, new path).
#[test]
fn test_removed_help_all_flag_suggests_help() {
    let output = zelynic_cmd()
        .arg("--help-all")
        .output()
        .expect("Failed to execute zelynic --help-all");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--help-all'"),
        "must name the removed flag, got:\n{stderr}"
    );
    assert!(
        stderr.contains("--help"),
        "must suggest the merged --help flag, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: `strict` is the bare-verb shorthand for
/// strict-single — the owner's `zelynic strict brave` used to die with
/// an unrecognized-subcommand error. Missing <target> must be a usage
/// error (exit 2) about the required positional <TARGET>, proving the
/// alias is wired to a real command instead of rejected outright.
#[test]
fn test_strict_shorthand_is_strict_single() {
    let output = zelynic_cmd()
        .arg("strict")
        .output()
        .expect("Failed to execute zelynic strict");

    assert_eq!(
        output.status.code(),
        Some(2),
        "strict without a target must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
        "error must name the missing strict-single positional, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: the strict shorthand must reach strict-single's
/// validation ladder — an invalid rate surfaces its did-you-mean tip
/// BEFORE the root guard, so this pins the dispatch without requiring
/// root or eBPF state. ebpf-gated: the rate ladder lives in the
/// feature-gated handler (the default build answers "eBPF not compiled").
#[cfg(feature = "ebpf")]
#[test]
fn test_strict_shorthand_reaches_rate_validation() {
    let output = zelynic_cmd()
        .args(["strict", "brave", "1MB"])
        .output()
        .expect("Failed to execute zelynic strict brave 1MB");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid rate '1MB'"),
        "strict must route into strict-single's rate validation, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: unstrict-multi exists and takes a colon-separated
/// target list — missing <targets> is a usage error naming the required
/// positional.
#[test]
fn test_unstrict_multi_requires_targets() {
    let output = zelynic_cmd()
        .arg("unstrict-multi")
        .output()
        .expect("Failed to execute zelynic unstrict-multi");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unstrict-multi without targets must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("<TARGETS>"),
        "error must name the missing unstrict-multi positional, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: unstrict-single is the alias mirroring the
/// strict-single/strict-multi pair — missing <target> is a usage error
/// about the same required positional as `unstrict` itself.
#[test]
fn test_unstrict_single_alias_is_unstrict() {
    let output = zelynic_cmd()
        .arg("unstrict-single")
        .output()
        .expect("Failed to execute zelynic unstrict-single");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unstrict-single without a target must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
        "error must name the missing unstrict positional, got:\n{stderr}"
    );
}

/// NIGHT-hunt-12: the `man` subcommand is removed totally — it must
/// be an unrecognized subcommand (exit 2), not a silent success. The
/// release tarballs no longer ship man/zelynic.1; `--help` is the one
/// reference surface.
#[test]
fn test_removed_man_command_is_rejected() {
    let output = zelynic_cmd()
        .arg("man")
        .output()
        .expect("Failed to execute zelynic man");

    assert_eq!(
        output.status.code(),
        Some(2),
        "removed 'man' must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand 'man'"),
        "error must name the removed subcommand, got:\n{stderr}"
    );
}

/// NIGHT-hunt-12: the monitor family is always-live — `--live` and
/// `--duration` are removed from observe/top, so both must fail as
/// unknown arguments (exit 2) instead of silently changing behavior.
#[test]
fn test_removed_monitor_timer_flags_are_rejected() {
    for argv in [
        vec!["observe", "--live", "3m"],
        vec!["top", "--live", "0"],
        vec!["top", "--duration", "30s"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed timer flag {argv:?} must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "error must name the rejected flag, got:\n{stderr}"
        );
    }
}

/// Effective uid from /proc/self/status (no nix dependency needed in
/// the default feature build): "Uid:\t<real>\t<effective>\t...".
fn euid_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.to_string())
        })
        .and_then(|l| l.split_whitespace().nth(1).map(|u| u.to_string()))
        .and_then(|u| u.parse::<u32>().ok())
        == Some(0)
}

/// NIGHT-hunt-13: the unprivileged contract. Every enforcement
/// surface must refuse cleanly as non-root: exit 1 (not a clap usage
/// error, not a panic), the branded "root required" wording, and the
/// actionable sudo tip. Pinned by scripts/nonroot-depth-test.sh for
/// the full 70-case matrix; this test keeps the core of it inside
/// `cargo test`. No-ops under root (sudo cargo test) where the
/// contract cannot hold.
#[cfg(feature = "ebpf")]
#[test]
fn test_enforcement_commands_refuse_non_root_cleanly() {
    if euid_is_root() {
        return; // contract only observable as unprivileged user
    }
    const ENFORCEMENT_ARGV: [&[&str]; 12] = [
        &["strict-single", "brave", "100kb"],
        &["strict", "brave", "100kb"],
        &["strict-multi", "brave:curl", "1mb"],
        &["limit-all", "500kb"],
        &["block-single", "brave"],
        &["block-all"],
        &["unstrict", "brave"],
        &["unstrict-all"],
        &["recover"],
        &["status"],
        &["observe"],
        &["top"],
    ];
    for argv in ENFORCEMENT_ARGV {
        let output = zelynic_cmd()
            .args(argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "enforcement {argv:?} must refuse with exit 1 as non-root"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("root required") && stderr.contains("tip: re-run with sudo"),
            "refusal must carry the branded wording + sudo tip for {argv:?}, got:\n{stderr}"
        );
        assert!(
            !stderr.contains("panicked"),
            "refusal must never panic for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13, default (no-ebpf) build: enforcement surfaces
/// answer "eBPF not compiled" with the rebuild tip — same clean exit 1
/// contract, wording pinned so the fallback binary stays honest too.
#[cfg(not(feature = "ebpf"))]
#[test]
fn test_enforcement_commands_report_missing_feature_cleanly() {
    if euid_is_root() {
        return; // wording identical under root; matrix pinned as non-root
    }
    for argv in [
        vec!["strict-single", "brave", "100kb"],
        vec!["status"],
        vec!["unstrict-all"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "no-ebpf build must exit 1 for {argv:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("eBPF not compiled") && stderr.contains("cargo build --features ebpf"),
            "no-ebpf build must carry the rebuild tip for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13: the fail-fast ladder is uid-independent — input
/// validation fires BEFORE the root guard, so a typo reports the typo
/// whether the user can sudo or not. Works under both uids (root also
/// sees the validation error first; the ladder is ordered in code).
/// ebpf-gated: the rate/interval parsers live behind the feature.
#[cfg(feature = "ebpf")]
#[test]
fn test_input_validation_precedes_privilege_guard() {
    const CASES: [(&[&str], &str); 4] = [
        (&["strict-single", "brave", "1MB"], "Invalid rate '1MB'"),
        (&["strict-single", "brave", "1b"], "below minimum"),
        (&["strict-single", "brave", "101gb"], "above maximum"),
        (&["observe", "--interval", "61s"], "between 1s and 60s"),
    ];
    for (argv, expected) in CASES {
        let output = zelynic_cmd()
            .args(argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "validation case {argv:?} must exit 1"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "case {argv:?} must lead with '{expected}', got:\n{stderr}"
        );
        assert!(
            !stderr.contains("root required"),
            "validation must precede the root guard for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13 edge pins: hostile-looking inputs must degrade into
/// ordinary validation/root-guard errors, never a panic (exit 101).
#[test]
fn test_edge_targets_never_panic() {
    for argv in [
        vec!["strict-single", "", "100kb"],
        vec!["strict-single", "99999999999999999999", "100kb"],
        vec!["strict-single", "../../etc", "100kb"],
        vec!["strict-single", "two words", "100kb"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_ne!(
            output.status.code(),
            Some(101),
            "edge input {argv:?} must never panic"
        );
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !all.contains("panicked"),
            "no backtrace for {argv:?}:\n{all}"
        );
    }
}
