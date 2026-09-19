// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Flag and error UX contract pins: rejected flags name themselves,
//! typos get did-you-mean tips, global flags parse globally, and a
//! short pipe reader never turns EPIPE into a panic.

use crate::zelynic_cmd;

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
