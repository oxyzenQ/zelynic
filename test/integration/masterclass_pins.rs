// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Masterclass surface pins (NIGHT-improve-53): the one-verb-per-
//! family unification's own reference contracts — the canonical
//! synopses (strict / unstrict carry the '::' list lane on the same
//! spelling), the flag-completeness fence carried over the merge,
//! and the list grammar's discovery path. Split from help_pins.rs
//! at the 600-line cap (one theme, one file — the usage_tests
//! discipline).

use crate::zelynic_cmd;

/// NIGHT-improve-53 (the masterclass unification): `unstrict` IS
/// the canonical verb now — the synopsis line reads `zelynic
/// unstrict <target>`, the retired `unstrict-single`/`unstrict-multi`
/// spellings appear nowhere, and the strict family reads the same
/// way (`zelynic strict <target> [rate]`). The old hunt-16 symmetry
/// contract (canonical carries the -single suffix) dissolved with
/// the merge; this pin holds the new shape.
#[test]
fn test_help_unstrict_synopsis_is_canonical() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zelynic unstrict <target>"),
        "--help must show the canonical unstrict synopsis, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("unstrict-single") && !stdout.contains("unstrict-multi"),
        "--help must not present the retired unstrict spellings (NIGHT-improve-53), got:\n{stdout}"
    );
    // The strict family pin (same masterclass shape).
    assert!(
        stdout.contains("zelynic strict <target> [rate]"),
        "--help must show the canonical strict synopsis, got:\n{stdout}"
    );
}

/// NIGHT-total-lts-3 find 2, carried over the masterclass merge:
/// the strict synopsis must not drift from the live parse surface
/// — `--per-socket` (charger-core-3b) and `--no-probe`
/// (charger-core-1-b) parse, are USAGE.md-documented, and are
/// argv_tests-pinned, so the curated --help must carry them too.
/// This pin fences the drift class at flag level: the synopsis must
/// carry --per-socket (matching USAGE.md's own synopsis line) and
/// the strict block must name both flags.
#[test]
fn test_help_strict_flags_are_complete() {
    let output = zelynic_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute zelynic --help");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[--per-socket]"),
        "--help's strict synopsis must carry --per-socket (USAGE.md parity), got:\n{stdout}"
    );
    assert!(
        stdout.contains("--no-probe skips the"),
        "--help's strict block must document --no-probe, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--per-socket 500kb"),
        "--help must show a per-socket example (the server shape's discovery path), got:\n{stdout}"
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
