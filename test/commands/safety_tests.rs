// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the dangerous-target guard (NIGHT-depthbore-1): the
//! family-aware match rule, the two real-world name shapes it closes,
//! and the check_dangerous_target verdict ladder. The blocklist is a
//! SAFETY NET for system stability — every pin here fails in the safe
//! direction (an over-blocked innocent costs one --force-this; a
//! missed daemon costs the system).

use super::*;

/// The exact spellings stay blocked — the rule is a superset of the
/// old exact match, so nothing that was guarded before can slip now.
#[test]
fn exact_blocklist_names_stay_dangerous() {
    for name in [
        "root",
        "sshd",
        "systemd",
        "systemd-resolve",
        "systemd-journal",
        "NetworkManager",
        "gnome-shell",
        "plasmashell",
        "Xorg",
    ] {
        assert!(
            is_dangerous_target(name),
            "the exact blocklist name '{name}' must stay dangerous"
        );
    }
}

/// THE TRUNCATED TWIN (NIGHT-depthbore-1's find): the display-name
/// enrichment (NIGHT-engrave-7) restores the full daemon name from
/// argv[0] while the blocklist carried the kernel's 15-byte truncated
/// forms — list-apps showed "systemd-resolved", the guard compared
/// against "systemd-resolve", and the copy-pasted target (and the
/// strict-all sweep, which matches the same enriched comms) sailed
/// past with no --force-this. Every enriched twin must be dangerous.
#[test]
fn enriched_daemon_names_are_dangerous() {
    for name in [
        "systemd-resolved",
        "systemd-journald",
        "systemd-timesyncd",
        "systemd-hostnamed",
        "systemd-machined",
        "systemd-user-sessions",
    ] {
        assert!(
            is_dangerous_target(name),
            "the enriched daemon name '{name}' must be dangerous — \
             strict-all sweeps these comms"
        );
    }
}

/// THE SPLIT-DAEMON SUFFIX: OpenSSH 9.8+ runs each connection's
/// process as "sshd-session" — a fresh name the exact list never
/// carried, so a strict-all sweep rate-limited every active SSH
/// session (the exact hazard this list exists to prevent).
#[test]
fn split_daemon_siblings_are_dangerous() {
    assert!(is_dangerous_target("sshd-session"));
    assert!(is_dangerous_target("sshd-auth"));
    // The same family rule across case and the truncated spelling a
    // user might type from an old listing.
    assert!(is_dangerous_target("SSHD-Session"));
    assert!(is_dangerous_target("gnome-session-b"));
    assert!(is_dangerous_target("KWin_Waylandx"));
}

/// Ordinary apps stay clean — the prefix rule must not leak into the
/// names owners actually limit (the fail-safe direction only costs
/// --force-this, but the common set must stay friction-free).
#[test]
fn ordinary_app_names_stay_clean() {
    for name in [
        "brave",
        "firefox",
        "chrome",
        "curl",
        "wget",
        "pacman",
        "steam",
        "transmission",
        "my-app",
        // An INCOMPLETE prefix is not the entry: "pipewir" does not
        // extend "pipewire".
        "pipewir",
        "ssh",
        "system",
    ] {
        assert!(
            !is_dangerous_target(name),
            "the ordinary name '{name}' must stay clean"
        );
    }
}

/// The verdict ladder: the enriched spelling refuses without the
/// override and passes with it; numeric cgroup IDs bypass the name
/// guard entirely (the user targets the id deliberately).
#[test]
fn check_dangerous_target_verdict_ladder() {
    let err = check_dangerous_target("systemd-resolved", false)
        .expect_err("the enriched spelling must refuse without the override");
    let msg = format!("{err}");
    assert!(
        msg.contains("'systemd-resolved' is a system process"),
        "the refusal must name the target, got: {msg}"
    );
    assert!(
        msg.contains("--force-this"),
        "the refusal must teach the override, got: {msg}"
    );

    check_dangerous_target("systemd-resolved", true).expect("the override lifts the guard");
    check_dangerous_target("12345", false).expect("numeric ids bypass the name guard");
    check_dangerous_target("brave", false).expect("ordinary names pass");
}

/// The fail-safe direction, pinned as a CONTRACT: a hypothetical
/// innocent app that merely shares a prefix with a blocklist entry
/// ("rootlesskit" extends "root") is blocked — one --force-this is
/// the accepted cost, because the miss direction breaks systems.
#[test]
fn prefix_lookalikes_block_in_the_safe_direction() {
    assert!(is_dangerous_target("rootlesskit"));
    assert!(is_dangerous_target("cronhelper"));
}
