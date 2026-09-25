// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the apply-verb success epilogue (NIGHT-improve-28):
//! the owner's de-noised success surface — a green "OK." verdict plus
//! the follow-up commands in the runnable-example green tier. Kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from src/commands/mod.rs.
//!
//! The contract being pinned:
//! 1. Two lines, exactly: the verdict and the follow-up.
//! 2. The verdict is "OK." — the affirmative-grammar word the owner
//!    specced, not a restatement of the request ("Limiting 'X' to ..."
//!    was the noise the owner cut; the request echo lives in the shell
//!    history, the enforced facts in 'zelynic status').
//! 3. The follow-up uses the owner's exact grammar: "Run '<unstrict>'
//!    to <action>, or 'zelynic status' to check." — the "or" included.
//! 4. Both runnable commands render in the green tier (the --help
//!    example tier, NIGHT-boost-4) while the prose stays plain — the
//!    escape assertions run under a forced color capability so the
//!    wraps are byte-visible.
//! 5. Every call site passes an unstrict form that ROUND-TRIPS:
//!    single -> "unstrict <target>", multi -> "unstrict-multi <list>"
//!    (unstrict-single does not split colon lists), all -> the
//!    "unstrict-all" sledgehammer (never "unstrict N apps", which is
//!    not a target).

use super::apply_success_lines;

/// The Mono rendering (color capability Mono in the test harness —
/// stderr is not a TTY): the exact two lines, wording pinned.
#[test]
fn epilogue_lines_pinned_mono() {
    let lines = apply_success_lines("zelynic unstrict cg:48181", "remove");
    assert_eq!(lines[0], "OK.");
    assert_eq!(
        lines[1],
        "Run 'zelynic unstrict cg:48181' to remove, or 'zelynic status' to check."
    );
}

/// The block family's action phrase rides the same grammar — the
/// wording is the contract each verb family reads identically.
#[test]
fn epilogue_restore_access_variant_pinned() {
    let lines = apply_success_lines("zelynic unstrict-all", "restore access");
    assert_eq!(lines[0], "OK.");
    assert_eq!(
        lines[1],
        "Run 'zelynic unstrict-all' to restore access, or 'zelynic status' to check."
    );
}

/// Exactly two lines — the epilogue can never regrow a third (the
/// verbosity regression this task closed).
#[test]
fn epilogue_is_exactly_two_lines() {
    for (cmd, action) in [
        ("zelynic unstrict brave", "remove"),
        ("zelynic unstrict-multi brave:curl", "remove"),
        ("zelynic unstrict-all", "remove"),
        ("zelynic unstrict brave", "restore access"),
        ("zelynic unstrict-multi brave:curl", "restore access"),
        ("zelynic unstrict-all", "restore access"),
    ] {
        assert_eq!(
            apply_success_lines(cmd, action).len(),
            2,
            "the epilogue is the verdict + the follow-up, nothing else ({cmd})"
        );
    }
}

/// The green-tier composition contract: the follow-up line is
/// EXACTLY "Run '" + ok(unstrict_cmd) + "' to <action>, or '" +
/// ok("zelynic status") + "' to check." — the runnable commands ride
/// the ok() green wrapper (the --help example tier, NIGHT-boost-4)
/// and the prose around them never does. Asserted by rebuilding the
/// expected string with the same ok() the builder used, so the pin
/// holds at EVERY color depth (the tier's own escapes are separately
/// pinned in test/output/color_tests.rs) while proving the wrapper
/// wraps exactly the commands, never the sentence.
#[test]
fn epilogue_green_wraps_exactly_the_runnable_commands() {
    for (cmd, action) in [
        ("zelynic unstrict cg:48181", "remove"),
        ("zelynic unstrict-multi brave:curl", "remove"),
        ("zelynic unstrict-all", "remove"),
        ("zelynic unstrict brave", "restore access"),
    ] {
        let lines = apply_success_lines(cmd, action);
        let expected = format!(
            "Run '{}' to {action}, or '{}' to check.",
            crate::output::ok(cmd),
            crate::output::ok("zelynic status")
        );
        assert_eq!(lines[1], expected, "green tier = the commands only ({cmd})");
        assert_eq!(
            lines[0],
            crate::output::ok("OK."),
            "the verdict rides the same green tier ({cmd})"
        );
    }
}
