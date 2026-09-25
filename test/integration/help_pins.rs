// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! --help reference drift pins: the single-tier help surface is the
//! one reference, and these tests pin its shape — every command
//! documented, verb grouping, canonical synopses, the q-only quit
//! contract, and the error paths that land users back on --help.

use crate::zelynic_cmd;

/// NIGHT-improve-3: --help is the single end-to-end reference (the
/// former --help-all merged in). Every CLI surface name must appear
/// in it — this is the drift pin between the Commands enum and the
/// curated reference. Extend the list when the CLI surface grows.
/// NIGHT-improve-25: the short aliases are part of the surface and
/// ride the same pin; the retired singular 'eagle-eye' is gone (one
/// canonical name, one short form). NIGHT-blade-2: limit-all/la is
/// renamed strict-all/sa — the retired spellings must NOT appear
/// (the redirect table owns them now, exit 2 with the successor tip).
#[test]
fn test_help_lists_every_command() {
    const KNOWN_COMMANDS: [&str; 26] = [
        "strict-single",
        "strict-multi",
        "strict-all",
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
        "eagle-eyes",
        "ee",
        "doctor",
        "strict",
        // NIGHT-improve-25: the ten two-letter aliases (NIGHT-blade-2:
        // 'sa' replaces 'la' in the strict-family rename).
        "ss",
        "sm",
        "sa",
        "bs",
        "bm",
        "ba",
        "us",
        "um",
        "ua",
    ];

    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0), "--help exits 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for section in [
        "Commands:",
        "Short aliases:",
        "Global flags:",
        "Rate formats:",
        "Examples:",
    ] {
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
    // NIGHT-boost-1: the merged monitor is documented as ONE surface
    // — the retired observe/top synopses must not linger.
    assert!(
        !stdout.contains("zelynic observe") && !stdout.contains("zelynic top "),
        "--help must not document the merged observe/top commands, got:\n{stdout}"
    );
    // NIGHT-blade-2: the retired limit-all/la spellings must not
    // linger on the reference — the redirect table owns them now.
    assert!(
        !stdout.contains("limit-all"),
        "--help must not document the removed 'limit-all' command (NIGHT-blade-2), got:\n{stdout}"
    );
    // NIGHT-improve-25: the singular 'eagle-eye' alias is removed —
    // its retired shorthand wording must not linger (a bare
    // substring check cannot be used: 'eagle-eyes' contains it).
    assert!(
        !stdout.contains("'eagle-eye' is the shorthand"),
        "--help must not present the removed 'eagle-eye' alias (NIGHT-improve-25), got:\n{stdout}"
    );
}

/// NIGHT-boost-29 (tidy data): the Short aliases block renders one
/// pair per line in the explicit `alias = canonical` form. The old
/// three-column packing carried no separator — the eye had to count
/// alignment gaps to bind a short form to its verb (the owner's
/// "asymmetric tidy data" audit). The pin holds the form so a future
/// edit cannot pack the pairs back into separator-less columns.
#[test]
fn test_help_short_aliases_use_equals_pairing() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    const PAIRS: [&str; 10] = [
        "ss = strict-single",
        "sm = strict-multi",
        "sa = strict-all",
        "bs = block-single",
        "bm = block-multi",
        "ba = block-all",
        "us = unstrict-single",
        "um = unstrict-multi",
        "ua = unstrict-all",
        "ee = eagle-eyes",
    ];
    for pair in PAIRS {
        assert!(
            stdout.contains(pair),
            "--help must render the tidy '{pair}' alias pairing, got:\n{stdout}"
        );
    }
    // The retired separator-less packing must not come back: a packed
    // row would put two pairs on one line with bare-space separation.
    assert!(
        !stdout.contains("ss strict-single"),
        "--help must not regress to the separator-less alias packing, got:\n{stdout}"
    );
}

/// NIGHT-improve-5: the reference groups commands by verb — strict,
/// block, unstrict (owner's grouping), plus monitor and system — so
/// the command surface scans as chunks. Pins the group headings in
/// --help (NIGHT-hunt-12: the man page renderer is gone, so --help is
/// the only pinned surface). NIGHT-blade-2: the one-command "limit"
/// group is dissolved — limit-all joined the strict family as
/// strict-all, so the strict group now carries single/multi/all and
/// the retired heading must not linger.
#[test]
fn test_help_groups_commands_by_verb() {
    const GROUPS: [&str; 5] = [
        "strict — apply rate limits",
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
    assert!(
        !stdout.contains("limit — bulk rate limits"),
        "--help must not carry the dissolved 'limit' group heading (NIGHT-blade-2), got:\n{stdout}"
    );
}

/// NIGHT-boost-4: example annotations sit on their OWN line above the
/// command — no example line may carry a trailing right-side comment
/// (the misaligned inline notes the owner flagged as messy) — and
/// every runnable example line renders in status green when color is
/// on, staying plain when piped.
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
        cmd_line.contains("\x1b[38;5;84m")
            && cmd_line.contains("zelynic strict-single brave -d 100kb"),
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

/// NIGHT-master-1: the reference documents the depth mode — the
/// one-shot inspection flag on the monitor surface, its alias
/// spelling, and a runnable example (the depth report is also a
/// --print-json surface, so the global-flags line names it).
#[test]
fn test_help_documents_the_depth_mode() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "One-shot deep inspection (NIGHT-master-1): --depth",
        "--info is the alias spelling",
        "sudo zelynic ee cg:1234 --depth",
        "sudo zelynic ee 12345 --depth --print-json",
        "--print-json     JSON output for status, list-apps, eagle-eyes --depth, doctor",
    ] {
        assert!(
            stdout.contains(needle),
            "--help must document the depth mode ('{needle}'), got:\n{stdout}"
        );
    }
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
