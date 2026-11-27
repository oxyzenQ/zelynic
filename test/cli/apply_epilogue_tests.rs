// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! Unit pins for the apply-verb success epilogue (NIGHT-improve-28):
//! the owner's de-noised success surface — a green "OK." verdict plus
//! the follow-up commands in the runnable-example green tier. Kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from src/commands/mod.rs.
//!
//! The contract being pinned:
//! 1. Two lines without a resolved fact, exactly: the verdict and the
//!    follow-up (night-cafe-1 F15: a non-empty `resolved_line` books
//!    ONE grey fact line between them — the single lanes' resolved
//!    cgroups; the multi/sweep lanes keep the two-line shape).
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
//!    single -> "unstrict <target>", list -> "unstrict <a>::<b>"
//!    (NIGHT-improve-53: the same verb carries the list lane now —
//!    the '::' separator routes it), the --all sweep -> the "u --all"
//!    sledgehammer (never "unstrict N apps", which is not a target).

use super::apply_success_lines;

/// The Mono rendering (color capability Mono in the test harness —
/// stderr is not a TTY): the exact two lines, wording pinned.
#[test]
fn epilogue_lines_pinned_mono() {
    let lines = apply_success_lines("zelynic unstrict cg:48181", "remove", "", None);
    assert_eq!(lines[0], "OK.");
    assert_eq!(
        lines[1],
        "Run 'zelynic unstrict cg:48181' to remove, or 'zelynic status' to check."
    );
}

/// night-cafe-1 (F15): the epilogue names the rows the apply just
/// wrote — one grey fact line between the verdict and the follow-up,
/// the identity walk's own `cg:<id> (<comm>)` form, the state-changing
/// side's half of the naming asymmetry.
#[test]
fn epilogue_names_the_resolved_rows() {
    let lines = apply_success_lines(
        "zelynic unstrict sleep",
        "remove",
        "limited cg:8981 (alacritty)",
        None,
    );
    assert_eq!(lines.len(), 3, "verdict, the resolved fact, the follow-up");
    assert_eq!(lines[0], "OK.");
    assert_eq!(lines[1], "limited cg:8981 (alacritty)");
    assert_eq!(
        lines[2],
        "Run 'zelynic unstrict sleep' to remove, or 'zelynic status' to check."
    );
}

/// The block family's action phrase rides the same grammar — the
/// wording is the contract each verb family reads identically.
#[test]
fn epilogue_restore_access_variant_pinned() {
    let lines = apply_success_lines("zelynic u --all", "restore access", "", None);
    assert_eq!(lines[0], "OK.");
    assert_eq!(
        lines[1],
        "Run 'zelynic u --all' to restore access, or 'zelynic status' to check."
    );
}

/// Exactly two lines without a resolved fact — the epilogue can never
/// regrow a third (the verbosity regression this task closed); the
/// sanctioned extras are exactly TWO: the resolved-fact booking (F15,
/// the pin above) and the --during window echo (night-dragon-fly-1
/// rev 5, the pin below) — each only when its fact exists.
#[test]
fn epilogue_is_exactly_two_lines() {
    for (cmd, action) in [
        ("zelynic unstrict brave", "remove"),
        ("zelynic unstrict brave::curl", "remove"),
        ("zelynic u --all", "remove"),
        ("zelynic unstrict brave", "restore access"),
        ("zelynic unstrict brave::curl", "restore access"),
        ("zelynic u --all", "restore access"),
    ] {
        assert_eq!(
            apply_success_lines(cmd, action, "", None).len(),
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
        ("zelynic unstrict brave::curl", "remove"),
        ("zelynic u --all", "remove"),
        ("zelynic unstrict brave", "restore access"),
    ] {
        let lines = apply_success_lines(cmd, action, "", None);
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

/// The window echo (night-dragon-fly-1 rev 5): a --during apply
/// books ONE grey fact line between the resolved rows and the
/// follow-up — the wall instant the row lifts itself plus the
/// duration, the same facts the status table's lifetime line keeps
/// current. Absent rides as None, never an empty string.
#[test]
fn epilogue_window_echo_rides_between_the_facts() {
    let lines = apply_success_lines(
        "zelynic unstrict sleep",
        "remove",
        "limited cg:8801 (sudo)",
        Some("window: lifts itself at 2026-11-27 18:17:00 UTC (30m)"),
    );
    assert_eq!(lines.len(), 4, "verdict, rows, the window, the follow-up");
    assert_eq!(lines[0], "OK.");
    assert_eq!(lines[1], "limited cg:8801 (sudo)");
    assert_eq!(
        lines[2],
        "window: lifts itself at 2026-11-27 18:17:00 UTC (30m)"
    );
    assert_eq!(
        lines[3],
        "Run 'zelynic unstrict sleep' to remove, or 'zelynic status' to check."
    );
}
