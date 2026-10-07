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
/// NIGHT-improve-53 (the masterclass unification): strict-single +
/// strict-multi, block-single + block-multi, unstrict-single +
/// unstrict-multi are ONE verb per family — the twelve retired
/// spellings must NOT appear on the reference (the redirect table
/// owns every one of them). The one-letter short forms (s/b/u) are
/// pinned by the alias-pairing test below, not here — a bare
/// contains() on a single letter proves nothing.
#[test]
fn test_help_lists_every_command() {
    const KNOWN_COMMANDS: [&str; 17] = [
        "strict",
        "strict-all",
        "block",
        "block-all",
        "unstrict",
        "unstrict-all",
        "recover",
        // NIGHT-private-research-4: the persistence pair — the
        // reboot-survival verbs (snapshot writes the state file,
        // restore re-applies it).
        "snapshot",
        "restore",
        "status",
        "list-apps",
        "eagle-eyes",
        "ee",
        "doctor",
        // The short aliases that survive the masterclass merge
        // (NIGHT-improve-53): the -all sweeps and the monitor.
        "sa",
        "ba",
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
        "Pro mode:",
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
    // NIGHT-improve-53: the twelve masterclass retirees — every
    // -single/-multi spelling is gone from the reference (each lands
    // on the redirect tip at runtime). The substring checks are
    // safe in both directions: 'unstrict-single' contains
    // 'strict-single', and both are gone together.
    for retired in [
        "strict-single",
        "strict-multi",
        "block-single",
        "block-multi",
        "unstrict-single",
        "unstrict-multi",
    ] {
        assert!(
            !stdout.contains(retired),
            "--help must not document the removed '{retired}' command (NIGHT-improve-53), got:\n{stdout}"
        );
    }
    // The retired two-letter short forms — pinned by their alias
    // pairing and example-line shapes, the only two renderings the
    // reference ever gave them.
    for retired in [
        "ss = ",
        "sm = ",
        "bs = ",
        "bm = ",
        "us = ",
        "um = ",
        "zelynic ss",
        "zelynic sm",
        "zelynic bs",
        "zelynic bm",
        "zelynic us",
        "zelynic um",
    ] {
        assert!(
            !stdout.contains(retired),
            "--help must not carry the retired '{retired}' short-form spelling (NIGHT-improve-53), got:\n{stdout}"
        );
    }
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
    const PAIRS: [&str; 7] = [
        "s = strict",
        "b = block",
        "u = unstrict",
        "sa = strict-all",
        "ba = block-all",
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

/// NIGHT-dinner-10: the Target formats section documents ALL THREE
/// accepted forms. The `cg:` display prefix is a real targeting form
/// (NIGHT-boost-37's round-trip contract: every output surface prints
/// cgroups as `cg:73386`, and the eagle-eyes footer's suggested
/// command carries it verbatim), so the grammar section must list
/// what the tool itself tells users to paste — the owner hit exactly
/// this ambiguity when the section named only two of the three forms.
#[test]
fn test_help_documents_every_target_form() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Target formats:",
        "  <process_name>  e.g., brave, firefox, curl",
        "  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)",
        "  cg:<cgroup_id>  the display prefix every surface prints (cg:73386) —",
        "                  paste it back: the same direct target as the bare ID",
        // NIGHT-improve-53: the masterclass list law rides the
        // grammar section — the '::' separator and the reason it
        // doubles (the single ':' belongs to the prefix grammar).
        "  <a>::<b>[::...]  list members for the group lane — the '::' separator",
        "                  cannot collide with the single ':' the cg: prefix and",
        "                  the container URIs own",
    ] {
        assert!(
            stdout.contains(needle),
            "--help must document the target form ('{needle}'), got:\n{stdout}"
        );
    }
}

/// NIGHT-dinner-11: the status section documents the allowed/dropped
/// ledger pair (the owner read "allowed 3.4gb / dropped 4.4 mb" as a
/// mystery — the columns' semantics belong on the surface he was
/// looking at: cumulative bytes since the limit was set, cleared on
/// removal), and Target formats names the no-match contract — a
/// target that resolves to nothing is a hard error, exit 1, never a
/// silent no-op (with the one documented carve-out: unstrict-all on
/// an already-clean system).
#[test]
fn test_help_documents_status_ledger_and_no_match_contract() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "allowed / dropped: cumulative BYTES per cgroup since the limit",
        "was set — allowed passed the budget, dropped exceeded it (the",
        "sender retries); removing the limit clears both.",
        "A target that matches nothing is a hard error (exit 1) — never a",
        "silent no-op; unstrict-all on an already-clean system exits 0.",
    ] {
        assert!(
            stdout.contains(needle),
            "--help must document the contract line ('{needle}'), got:\n{stdout}"
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
}

/// NIGHT-improve-3 owner contract: --help typed after a subcommand is a
/// usage error (exit 2) whose tip points at the one help authority —
/// `zelynic --help` — with the real usage line and exactly one
/// canonical footer.
#[test]
fn test_subcommand_help_errors_with_suggestion() {
    let output = zelynic_cmd()
        .args(["strict", "brave", "--help"])
        .output()
        .expect("Failed to execute zelynic strict brave --help");

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

/// NIGHT-improve-45: the Pro mode drift pin — every hidden and
/// advanced flag the CLI owns must appear on the --help reference,
/// spelled exactly as the parser accepts it. Before the section
/// landed, the --during grammar and the guarantee brackets carried
/// ZERO mentions on the reference (hidden flags by omission); this
/// pin holds the complete surface so a future flag cannot ship
/// hidden: add its spelling here the same hour it joins the enum.
#[test]
fn test_help_pro_mode_documents_every_advanced_flag() {
    const ADVANCED_FLAGS: [&str; 13] = [
        // Time windows (strict family + block family).
        "--during",
        // The guarantee bracket family (strict family).
        "--floor",
        "--ceil",
        "--floor-download",
        "--floor-upload",
        "--ceil-download",
        "--ceil-upload",
        // Enforcement shape (strict-single).
        "--per-socket",
        "--no-probe",
        // Guard override (strict family + block family).
        "--force-this",
        // Deep inspection (eagle-eyes).
        "--focus",
        "--depth",
        "--interval",
    ];

    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0), "--help exits 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Pro mode:"),
        "the Pro mode section heading must be present, got:\n{stdout}"
    );
    for flag in ADVANCED_FLAGS {
        assert!(
            stdout.contains(flag),
            "--help must document the '{flag}' flag in Pro mode, got:\n{stdout}"
        );
    }
    // The one grammar law worth its own line on the reference: the
    // duration-only revision refuses the removed shapes by name.
    // NIGHT-improve-52 tightened the law line to a standalone
    // sentence ("Duration only, one shape, no schedules.") — the
    // needle matches the rendered case exactly.
    assert!(
        stdout.contains("Duration only"),
        "the --during duration-only law must be stated, got:\n{stdout}"
    );
    // NIGHT-improve-52: the retired window/date shapes (09:00-17:00,
    // 2026-10-15) no longer appear on the reference — naming dead
    // grammar by example reads as stale data; the law line above is
    // the whole contract now.
    assert!(
        !stdout.contains("09:00-17:00") && !stdout.contains("2026-10-15"),
        "the retired window/date shape examples must not linger, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("--info alias is retired"),
        "the retired --info spelling's history note must not linger, got:\n{stdout}"
    );
    // NIGHT-improve-52: every Pro mode flag family now carries a
    // runnable example — the section was spelling-complete but
    // example-empty (zero copyable lines for the hidden family).
    // These pins hold the discovery path so a future edit cannot
    // strip the examples back out.
    for example_line in [
        "sudo zelynic s brave 1mb --during 2h",
        "sudo zelynic b brave::curl --during 30m",
        "sudo zelynic s firefox 1mb --floor 100kb",
        "sudo zelynic s curl 1mb --floor-download 50kb --ceil-upload 200kb",
        "sudo zelynic s nginx 500kb --no-probe",
    ] {
        assert!(
            stdout.contains(example_line),
            "--help's Pro mode must carry the example '{example_line}', got:\n{stdout}"
        );
    }
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
