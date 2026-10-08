// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Masterclass surface pins (NIGHT-improve-53): the one-verb-per-
//! family unification's own reference contracts — the canonical
//! synopses (strict / unstrict carry the '::' list lane on the same
//! spelling), the flag-completeness fence carried over the merge,
//! and the list grammar's discovery path. Split from help_pins.rs
//! at the 600-line cap (one theme, one file — the usage_tests
//! discipline). NIGHT-hunt-35 (the masterclass tidy) re-based the
//! first two contracts on the synopsis law (both lanes + the
//! `[flags — see Pro mode]` pointer on one line) and added the
//! grey-tier pin here — the tidy's own contracts live together.
//! NIGHT-hunt-39 (the flag tier) added its pin beside them: every
//! flag spelling renders the grey grammar tier, span-exact, with
//! the one computed description column (19) across both flag
//! tables and their continuations.

use crate::zelynic_cmd;

/// NIGHT-improve-53 (the masterclass unification) + NIGHT-hunt-35
/// (the synopsis law): `unstrict` IS the canonical verb now — and
/// the synopsis carries the WHOLE grammar on one line: both lanes
/// of the target (`<target> or <target::target::target>`) plus the
/// ONE pointer token `[flags — see Pro mode]` (the owner's
/// compactness mandate — the old in-synopsis flag enumeration was
/// neither complete nor simple; Pro mode owns every spelling). The
/// retired `unstrict-single`/`unstrict-multi` spellings appear
/// nowhere, and the strict family reads the same way. The old
/// hunt-16 symmetry contract (canonical carries the -single
/// suffix) dissolved with the merge; this pin holds the new shape.
#[test]
fn test_help_unstrict_synopsis_is_canonical() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zelynic unstrict <target> or <target::target::target>"),
        "--help must show the canonical unstrict synopsis (both lanes, the pointer), got:\n{stdout}"
    );
    assert!(
        !stdout.contains("unstrict-single") && !stdout.contains("unstrict-multi"),
        "--help must not present the retired unstrict spellings (NIGHT-improve-53), got:\n{stdout}"
    );
    // The strict family pin (same masterclass shape).
    assert!(
        stdout.contains("zelynic strict <target> or <target::target::target>"),
        "--help must show the canonical strict synopsis (both lanes, the pointer), got:\n{stdout}"
    );
}

/// NIGHT-total-lts-3 find 2, carried over the masterclass merge
/// (improve-53), the sweep merge (improve-54), and re-based on the
/// hunt-35 synopsis law: the synopsis must not drift from the live
/// parse surface — but the completeness contract moved one section
/// down. The synopsis carries the ONE pointer token
/// (`[flags — see Pro mode]`) instead of enumerating flags (the
/// owner's compactness mandate: the old `[--per-socket]`-only
/// enumeration was neither complete nor simple); Pro mode owns
/// every flag's spelling, and the help_pins ADVANCED_FLAGS fence
/// holds that completeness. This pin fences the pointer law: the
/// token rides exactly the four flag-owning verbs (strict, block,
/// unstrict, eagle-eyes — recover/status/list-apps/doctor own
/// none), Pro mode documents the strict shape flags, and the
/// per-socket example keeps its discovery path.
#[test]
fn test_help_strict_flags_are_complete() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[flags — see Pro mode]"),
        "the strict synopsis must carry the Pro mode pointer token, got:\n{stdout}"
    );
    assert_eq!(
        stdout.matches("[flags — see Pro mode]").count(),
        4,
        "exactly the four flag-owning verbs carry the pointer (strict, block, unstrict, eagle-eyes), got:\n{stdout}"
    );
    assert!(
        stdout.contains("skips the post-apply verification loop"),
        "Pro mode must document --no-test, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--per-socket 500kb"),
        "--help must show a per-socket example (the server shape's discovery path), got:\n{stdout}"
    );
}

/// NIGHT-hunt-35 (the synopsis tier): every command synopsis
/// renders in the calm-grey subordinate tier — the owner's
/// eye-strain call (white usage lines under purple headings
/// strained the eyes; grey says "grammar, not prose") — while the
/// group headings keep the bold brand purple. Pinned at 256-color
/// depth: grey = index 245 (the #8B8B8B cube match), brand bold
/// purple = index 135. The NO_COLOR escape-free contract is pinned
/// in help_pins (the green-tier test); this pin holds the tier
/// split in the colored run. Lives HERE (NIGHT-hunt-35): the tier
/// law is part of the masterclass tidy's own contracts, and
/// help_pins rode the 600-line cap the moment this pin landed
/// (one theme, one file — the usage_tests discipline).
#[test]
fn test_help_synopsis_lines_render_grey_under_purple_headings() {
    let mut cmd = zelynic_cmd();
    cmd.arg("--help")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env("CLICOLOR_FORCE", "1")
        .env("TERM", "xterm-256color");
    let colored = cmd
        .output()
        .expect("Failed to execute zelynic --help (grey-tier run)");
    assert_eq!(colored.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&colored.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // The synopsis under the block heading renders grey (245) — one
    // tier below the heading, the grammar-not-content law.
    let synopsis = lines
        .iter()
        .find(|l| l.contains("zelynic block <target> or"))
        .expect("the block synopsis must exist");
    assert!(
        synopsis.contains("\x1b[38;5;245m"),
        "the block synopsis must render calm grey (245), got: {synopsis}"
    );
    // The group heading above it keeps the bold brand purple (135).
    let heading = lines
        .iter()
        .find(|l| l.contains("block — cut internet access"))
        .expect("the block group heading must exist");
    assert!(
        heading.contains("\x1b[1;38;5;135m"),
        "the group heading must stay bold brand purple (135), got: {heading}"
    );
    // The tier split is real: no bleed in either direction.
    assert!(
        !synopsis.contains("\x1b[1;38;5;135m") && !heading.contains("\x1b[38;5;245m"),
        "the grey synopsis and purple heading tiers must not bleed into each other"
    );
}

/// NIGHT-hunt-39 (the flag tier, owner mandate): every flag
/// spelling on the reference renders in the calm-grey grammar tier
/// — the flag tables' spelling columns AND the inline prose
/// mentions (flags are grammar, the same tier the synopses ride,
/// token-wise). Pinned at 256-color depth: grey = index 245, the
/// span covering the spelling exactly (padding after the reset
/// stays default; prose around an inline mention stays default).
/// The description column is ONE law: 19 — the --reset-terminal /
/// --interval SEC width, honored by the rows AND their
/// continuations (hunt-35's one-column claim was 18/19-mixed in
/// the rendered truth, three rows one wide of their own
/// continuations; the column is computed in flag_row now, and
/// this pin holds it closed). Boundaries: the example lines keep
/// the solid green tier — zero grey bleed into boost-4's "this is
/// what you type" tier. The NO_COLOR escape-free contract stays
/// pinned in help_pins (the green-tier test).
#[test]
fn test_help_flag_spellings_render_grey_across_tables_and_prose() {
    let mut cmd = zelynic_cmd();
    cmd.arg("--help")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env("CLICOLOR_FORCE", "1")
        .env("TERM", "xterm-256color");
    let colored = cmd
        .output()
        .expect("Failed to execute zelynic --help (flag-tier run)");
    assert_eq!(colored.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&colored.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let grey = "\x1b[38;5;245m";
    let reset = "\x1b[0m";

    // The owner's own --all row: the grey span wraps the spelling
    // exactly; the padding after the reset stays default.
    let all_row = lines
        .iter()
        .find(|l| l.contains("the lane that owns every user app"))
        .expect("the --all row must exist");
    assert!(
        all_row.contains(&format!("{grey}--all{reset}")),
        "the --all spelling must render calm grey (245), got: {all_row}"
    );
    // A Global flags row rides the same tier — the two tables
    // share the law, and -h, --help carries both spellings in one
    // span.
    let help_row = lines
        .iter()
        .find(|l| l.contains("This end-to-end reference"))
        .expect("the -h, --help row must exist");
    assert!(
        help_row.contains(&format!("{grey}-h, --help{reset}")),
        "the -h, --help spelling must render calm grey (245), got: {help_row}"
    );
    // Inline prose mentions ride the tier too — the safety
    // bullet's --force-this, mid-sentence, prose default on both
    // sides of the span.
    let safety = lines
        .iter()
        .find(|l| l.contains("One flag lifts every guard"))
        .expect("the safety guard bullet must exist");
    assert!(
        safety.contains(&format!("guard: {grey}--force-this{reset}")),
        "the inline --force-this mention must render calm grey, got: {safety}"
    );
    // The pure-spelling row (the per-direction family) greys its
    // whole flag list — one span, four spellings, no prose.
    let flag_list = lines
        .iter()
        .find(|l| l.contains("--floor-download"))
        .expect("the per-direction spelling list must exist");
    assert!(
        flag_list.contains(&format!(
            "{grey}--floor-download, --floor-upload, --ceil-download, --ceil-upload{reset}"
        )),
        "the pure spelling list must render as one grey span, got: {flag_list}"
    );
    // The column law: ONE description column across BOTH flag
    // tables and their continuations — 19, computed by flag_row.
    let col_after = |line: &str, token: &str| -> usize {
        let stripped = strip_csi(line);
        let start = stripped.find(token).expect("token present") + token.len();
        start + (stripped[start..].len() - stripped[start..].trim_start_matches(' ').len())
    };
    let first_col = |line: &str| -> usize {
        let stripped = strip_csi(line);
        stripped.len() - stripped.trim_start_matches(' ').len()
    };
    let interval_row = lines
        .iter()
        .find(|l| l.contains("live monitor refresh"))
        .expect("the --interval SEC row must exist");
    assert_eq!(
        col_after(all_row, "--all"),
        19,
        "the --all description column must be 19, got: {all_row}"
    );
    assert_eq!(
        col_after(interval_row, "--interval SEC"),
        19,
        "the --interval SEC description column must be 19, got: {interval_row}"
    );
    assert_eq!(
        col_after(help_row, "-h, --help"),
        19,
        "the Global table rides the same description column, got: {help_row}"
    );
    let pro_cont = lines
        .iter()
        .find(|l| l.contains("them all, block them all"))
        .expect("the --all continuation must exist");
    assert_eq!(
        first_col(pro_cont),
        19,
        "the Pro mode continuation must sit at the description column, got: {pro_cont}"
    );
    let global_cont = lines
        .iter()
        .find(|l| l.contains("a kill -9 TUI death"))
        .expect("the --reset-terminal continuation must exist");
    assert_eq!(
        first_col(global_cont),
        19,
        "the Global continuation must sit at the description column, got: {global_cont}"
    );
    // No bleed: the green example tier stays solid — the Pro mode
    // --all example line carries green and zero grey.
    let example_line = lines
        .iter()
        .find(|l| l.contains("sudo zelynic s --all 500kb") && l.contains('\x1b'))
        .expect("the --all example must exist");
    assert!(
        example_line.contains("\x1b[38;5;84m") && !example_line.contains(grey),
        "the example command stays the solid green tier, got: {example_line}"
    );
}

/// Strip ANSI CSI SGR sequences (`\x1b[...m`) from one line — the
/// flag-tier pin measures the DESCRIPTION COLUMN of colored rows,
/// and the escapes would skew the count. Private to this file's
/// tier pins (the hunt-35 synopsis pin matches spans directly and
/// needs no stripping).
fn strip_csi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.next() == Some('[') {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// NIGHT-improve-53: the masterclass grammar's discovery path — the
/// strict block demonstrates the '::' list beside the single-target
/// examples (the group-sharing example and the cgroup-id list
/// example), so both lanes of the one verb are copy-paste
/// discoverable from the single reference.
#[test]
fn test_help_documents_the_masterclass_list_grammar() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "'::'-separated list",
        "sudo zelynic s brave::curl::pacman 1mb",
        "sudo zelynic s cg:1234::1245 100kb",
        "sudo zelynic b brave::curl::pacman",
        "sudo zelynic u brave::curl::pacman",
    ] {
        assert!(
            stdout.contains(needle),
            "--help must demonstrate the masterclass grammar ('{needle}'), got:\n{stdout}"
        );
    }
}
