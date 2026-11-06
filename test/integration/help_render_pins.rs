// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! --help render pins: how the reference presents, beyond the plain
//! vocabulary — the example blocks' annotation-above layout and their
//! status-green render tier (with the NO_COLOR escape-free contract
//! and the NIGHT-netrunner-9 COLORTERM hermeticity), the depth mode's
//! section lines, and the removed --help-all flag's redirect UX.
//! Split from help_pins.rs (NIGHT-netrunner-10): the reference pins
//! stay there; the render surface owns this file.

use crate::zelynic_cmd;

/// NIGHT-boost-4: example annotations sit on their OWN line above the
/// command — no example line may carry a trailing right-side comment
/// (the misaligned inline notes the owner flagged as messy) — and
/// every runnable example line renders in status green when color is
/// on, staying plain when piped.
/// NIGHT-netrunner-9 hermeticity: COLORTERM joins the removal list —
/// the runner's truecolor terminal must not upgrade the pinned 256 depth.
#[test]
fn test_help_examples_annotate_above_and_render_green() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Layout pin: a command line never carries its '#' note on the
    // right side — notes are standalone lines above the command.
    for line in stdout.lines() {
        assert!(
            !(line.contains("zelynic") && line.contains(" # ")),
            "example notes must sit on their own line above the command, got: {line}"
        );
    }
    assert!(
        stdout.lines().any(|l| l.trim_start().starts_with('#')),
        "the reference must carry '#'-annotated examples"
    );
    // Pipe-safety pin: with NO_COLOR set the reference carries zero
    // escape bytes — the green tier must ride the capability layer,
    // never leak into piped output.
    assert!(
        !stdout.contains('\x1b'),
        "NO_COLOR help must be escape-free, got: {stdout}"
    );

    // Color pin: with color forced at 256-color depth, the example
    // command line under its note renders in the status-green tier
    // (index 84, the documented cube match for #50FA7B).
    let mut cmd = zelynic_cmd();
    cmd.arg("--help")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("COLORTERM")
        .env("CLICOLOR_FORCE", "1")
        .env("TERM", "xterm-256color");
    let colored = cmd
        .output()
        .expect("Failed to execute zelynic --help (color run)");
    assert_eq!(colored.status.code(), Some(0));
    let colored_stdout = String::from_utf8_lossy(&colored.stdout);
    let lines: Vec<&str> = colored_stdout.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.trim() == "# download only")
        .expect("the '# download only' note must exist");
    let cmd_line = lines
        .get(idx + 1)
        .expect("the note must be followed by its command line");
    assert!(
        cmd_line.contains("\x1b[38;5;84m") && cmd_line.contains("zelynic strict brave -d 100kb"),
        "the example command line must render status green, got: {cmd_line}"
    );
    // The note line itself stays uncolored — green is the command
    // tier only, the annotation rides the default color.
    assert!(
        !lines[idx].contains('\x1b'),
        "the note line must stay uncolored, got: {}",
        lines[idx]
    );
}

/// NIGHT-master-1: the reference documents the depth mode — the
/// one-shot inspection flag on the monitor surface, its single
/// spelling (the --info alias retired in NIGHT-blade-4), and a
/// runnable example (the depth report is also a --print-json
/// surface, so the global-flags line names it).
#[test]
fn test_help_documents_the_depth_mode() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "One-shot deep inspection: --depth",
        "--depth is the only spelling",
        "sudo zelynic ee cg:1234 --depth",
        "sudo zelynic ee 12345 --depth --print-json",
        "--print-json     JSON output for status, list-apps, eagle-eyes --depth, doctor",
    ] {
        assert!(
            stdout.contains(needle),
            "--help must document the depth mode ('{needle}'), got:\n{stdout}"
        );
    }
    // NIGHT-total-lts-9: the retired restore verb left the JSON
    // surface line whole — the list is exactly the four the scope
    // contract names (cli/scope.rs JSON_SURFACE_COMMANDS), with no
    // trailing-comma continuation naming a retired verb.
    assert!(
        !stdout.contains("doctor,\n"),
        "the --print-json surface line must end at doctor (restore is retired), got:\n{stdout}"
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
