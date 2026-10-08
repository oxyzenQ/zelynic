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
