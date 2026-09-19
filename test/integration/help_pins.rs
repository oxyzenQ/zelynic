// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! --help reference drift pins: the single-tier help surface is the
//! one reference, and these tests pin its shape — every command
//! documented, verb grouping, canonical synopses, the q-only quit
//! contract, and the error paths that land users back on --help.

use crate::zelynic_cmd;

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

/// NIGHT-hunt-16: the unstrict family reads symmetrically with the
/// strict family — the CANONICAL single-target command is
/// `unstrict-single` (synopsis line in --help) and `unstrict` is the
/// shorthand, exactly mirroring `strict-single` / `strict`. A bare
/// `zelynic unstrict <target>` synopsis line is the inconsistency the
/// owner flagged and must never come back.
#[test]
fn test_help_unstrict_synopsis_is_canonical() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zelynic unstrict-single <target>"),
        "--help must show the canonical unstrict-single synopsis, got:\n{stdout}"
    );
    assert!(
        stdout.contains("('unstrict' is the shorthand)"),
        "--help must label unstrict as the shorthand, mirroring strict, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("zelynic unstrict <target>"),
        "--help must NOT present bare 'unstrict' as the canonical synopsis (NIGHT-hunt-16), got:\n{stdout}"
    );
    // The strict family pin (same symmetry, pre-existing contract).
    assert!(
        stdout.contains("zelynic strict-single <target> [rate]"),
        "--help must show the canonical strict-single synopsis, got:\n{stdout}"
    );
}

/// NIGHT-hunt-16: 'q' is the ONLY documented monitor quit key. The
/// reference must carry the q-only exit contract and must never again
/// advertise Ctrl+C (or ESC) as a quit path.
#[test]
fn test_help_monitor_quit_contract_is_q_only() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Exit with q (the only quit key)"),
        "--help must state the q-only exit contract, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Ctrl+C"),
        "--help must NOT advertise Ctrl+C as a monitor quit key (NIGHT-hunt-16), got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Ctrl-C") && !stdout.contains("ESC quit"),
        "--help must NOT advertise any non-q quit key (NIGHT-hunt-16), got:\n{stdout}"
    );
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
