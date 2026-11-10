// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! --help reference drift pins: the single-tier help surface is the
//! one reference, and these tests pin its shape — every command
//! documented, verb grouping, canonical synopses, and the q-only quit
//! contract. The render-side pins (example layout, green tier, depth
//! lines, the --help-all redirect) live in help_render_pins.rs.

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
    // NIGHT-improve-54: 9 commands — the -all sweeps retired into
    // the family verbs' --all lanes (sa/ba/ua with their verbs),
    // on top of improve-55 retiring the persistence pair whole
    // (snapshot's dump went first, restore's apply lane followed —
    // the owner's live-test verdict was that neither half earned
    // its keep).
    const KNOWN_COMMANDS: [&str; 9] = [
        "strict",
        "block",
        "unstrict",
        "recover",
        "status",
        "list-apps",
        "eagle-eyes",
        "ee",
        "doctor",
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
        "Global options:",
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
    const PAIRS: [&str; 4] = ["s = strict", "b = block", "u = unstrict", "ee = eagle-eyes"];
    // NIGHT-improve-54: the sweep aliases died with their verbs —
    // sa/ba/ua are redirects now, never reference vocabulary.
    const RETIRED_PAIRS: [&str; 3] = ["sa = strict-all", "ba = block-all", "ua = unstrict-all"];
    for pair in PAIRS {
        assert!(
            stdout.contains(pair),
            "--help must render the tidy '{pair}' alias pairing, got:\n{stdout}"
        );
    }
    for pair in RETIRED_PAIRS {
        assert!(
            !stdout.contains(pair),
            "--help must not present the retired '{pair}' alias (NIGHT-improve-54), got:\n{stdout}"
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
/// strict-all, so the strict group carried single/multi/all that
/// era (improve-53/54 later merged the spellings into one `strict`
/// verb with the `--all` lane) and the retired heading must not
/// linger.
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
        // NIGHT-hunt-35: the token re-spells to the concrete
        // three-member shape so it sits in the section's one
        // description column (the symmetry law).
        "  <a>::<b>::<c>   list members for the group lane — the '::' separator",
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
/// silent no-op (with the one documented carve-out: `u --all` on
/// an already-clean system).
#[test]
fn test_help_documents_status_ledger_and_no_match_contract() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // night-ux-6: the status block rides the LIVE footer's own
    // sentences (display_lines::counters_footer_lines, the
    // night-docs-1 wording) — the reference may not contradict the
    // surface it describes. The pre-night-docs-1 phrasing ("allowed
    // passed the budget, dropped exceeded it") is retired here with
    // the source.
    for needle in [
        "allowed / dropped: cumulative since apply. Small dropped = the saver",
        "lanes working; ingress drops burn quota, egress drops save it.",
        "(unstrict clears both)",
        "A target that matches nothing is a hard error (exit 1) — never a",
        "silent no-op; the --all reset on an already-clean system exits 0.",
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

/// Night-netrunner-5 owner contract: --help typed after a subcommand
/// is a help REQUEST — the subcommand answers with its own local help
/// (its synopsis, its arguments) on stdout, exit 0. The old verdict
/// (exit 2 with a tip pointing at the top-level authority) was the
/// single-tier law's dead end; the local help is the way out.
#[test]
fn test_subcommand_help_renders_local_help() {
    let output = zelynic_cmd()
        .args(["strict", "brave", "--help"])
        .output()
        .expect("Failed to execute zelynic strict brave --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: zelynic strict"),
        "the local help must carry the subcommand's own usage, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--per-socket"),
        "the local help must carry the command's own options, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "a help request is not an error, stderr must stay clean, got:\n{stderr}"
    );
}

/// The -h short form rides the same door: local help on stdout,
/// exit 0, and the root reference stays untouched on the top level.
#[test]
fn test_subcommand_short_help_renders_local_help() {
    let output = zelynic_cmd()
        .args(["status", "-h"])
        .output()
        .expect("Failed to execute zelynic status -h");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: zelynic status"),
        "the local help must carry the subcommand's own usage, got:\n{stdout}"
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
    const ADVANCED_FLAGS: [&str; 14] = [
        // Fleet sweeps (strict + block + unstrict) — NIGHT-improve-54.
        "--all",
        // Time windows (strict family + block family).
        "--during",
        // The guarantee bracket family (strict family).
        "--floor",
        "--ceil",
        "--floor-download",
        "--floor-upload",
        "--ceil-download",
        "--ceil-upload",
        // Enforcement shape (strict family).
        "--per-socket",
        "--no-test",
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
    // NIGHT-improve-54: the retired --no-probe spelling must not
    // linger as living vocabulary on the reference (the redirect
    // note beside --no-test is the only legal mention).
    assert!(
        !stdout.contains("--no-probe     "),
        "the retired --no-probe flag line must not linger, got:\n{stdout}"
    );
    for example_line in [
        "sudo zelynic s --all 500kb",
        "sudo zelynic b --all",
        "sudo zelynic u --all",
        "sudo zelynic s brave 1mb --during 2h",
        "sudo zelynic b brave::curl --during 30m",
        "sudo zelynic s firefox 1mb --floor 100kb",
        "sudo zelynic s curl 1mb --floor-download 50kb --ceil-upload 200kb",
        "sudo zelynic s nginx 500kb --no-test",
    ] {
        assert!(
            stdout.contains(example_line),
            "--help's Pro mode must carry the example '{example_line}', got:\n{stdout}"
        );
    }
}
