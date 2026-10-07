// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The removed/retired redirect pins (split from surface_pins.rs at
//! the 600-line owner cap, NIGHT-improve-54 — the same one-theme-
//! one-file discipline that gave masterclass_pins.rs its home at
//! improve-53): every retired spelling — the man page lane, the
//! monitor flag retirees, observe/top, the masterclass twelve, the
//! -all sweeps, and the singular eagle-eye alias — must land on its
//! successor's tip, never a dead end.

use super::zelynic_cmd;

/// NIGHT-hunt-12: the `man` subcommand is removed totally — it must
/// be an unrecognized subcommand (exit 2), not a silent success. The
/// release tarballs no longer ship man/zelynic.1; `--help` is the one
/// reference surface.
#[test]
fn test_removed_man_command_is_rejected() {
    let output = zelynic_cmd()
        .arg("man")
        .output()
        .expect("Failed to execute zelynic man");

    assert_eq!(
        output.status.code(),
        Some(2),
        "removed 'man' must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand 'man'"),
        "error must name the removed subcommand, got:\n{stderr}"
    );
}

/// NIGHT-hunt-12: the monitor family is always-live — `--live` and
/// `--duration` are removed from the eagle-eyes monitor (NIGHT-boost-1
/// merged observe/top into it), so both must fail as unknown
/// arguments (exit 2) instead of silently changing behavior.
#[test]
fn test_removed_monitor_timer_flags_are_rejected() {
    for argv in [
        vec!["eagle-eyes", "--live", "3m"],
        vec!["eagle-eyes", "--duration", "30s"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed timer flag {argv:?} must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "error must name the rejected flag, got:\n{stderr}"
        );
    }
}

/// NIGHT-boost-1: observe and top are removed as subcommands (merged
/// into eagle-eyes) — both must fail as unrecognized subcommands
/// (exit 2) whose tip redirects to the successor, never a silent
/// success and never a dead end.
#[test]
fn test_removed_observe_and_top_redirect_to_eagle_eyes() {
    for gone in ["observe", "top"] {
        let output = zelynic_cmd()
            .arg(gone)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {gone}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed '{gone}' must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("unrecognized subcommand '{gone}'")),
            "error must name the removed subcommand, got:\n{stderr}"
        );
        assert!(
            stderr.contains("eagle-eyes"),
            "removed '{gone}' must redirect to eagle-eyes, got:\n{stderr}"
        );
    }
}

/// NIGHT-boost-1: the retired monitor flags (--cgroup on observe,
/// --limit on top) must not ride on eagle-eyes — the target filter is
/// the positional TARGETS spec now, and the row budget is the
/// terminal height. Both must fail as unknown arguments.
#[test]
fn test_removed_monitor_filter_flags_are_rejected() {
    for argv in [
        vec!["eagle-eyes", "--cgroup", "8066"],
        vec!["eagle-eyes", "--limit", "20"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed filter flag {argv:?} must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "error must name the rejected flag, got:\n{stderr}"
        );
    }
}

/// NIGHT-improve-53 (the masterclass unification): the twelve
/// retired spellings — the -single/-multi long forms and their
/// two-letter shorts — must land users on the family successor:
/// unrecognized subcommand (exit 2) whose tip redirects to strict /
/// block / unstrict, the exact contract observe/top, limit-all/la,
/// and eagle-eye carry. Every redirect is exact-match (a fuzzy
/// near-miss never supplements it).
#[test]
fn test_removed_masterclass_spellings_redirect_to_their_verb() {
    for (gone, successor) in [
        ("strict-single", "strict"),
        ("strict-multi", "strict"),
        ("ss", "strict"),
        ("sm", "strict"),
        ("block-single", "block"),
        ("block-multi", "block"),
        ("bs", "block"),
        ("bm", "block"),
        ("unstrict-single", "unstrict"),
        ("unstrict-multi", "unstrict"),
        ("us", "unstrict"),
        ("um", "unstrict"),
    ] {
        let output = zelynic_cmd()
            .arg(gone)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {gone}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed '{gone}' must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("unrecognized subcommand '{gone}'")),
            "error must name the removed spelling, got: {stderr}"
        );
        assert!(
            stderr.contains(successor),
            "removed '{gone}' must redirect to {successor}, got: {stderr}"
        );
    }
}

/// NIGHT-blade-2/improve-54: the removed limit-all/la spellings
/// (renamed strict-all/sa by blade-2, retired into strict's --all
/// lane by improve-54) must land users on the runnable successor —
/// unrecognized subcommand (exit 2) whose tip redirects to the
/// verb + flag spelling, the exact contract observe/top/eagle-eye
/// carry. ux_tests pins the same table through the render bridge;
/// this pin drives the real binary end to end.
#[test]
fn test_removed_sweep_spellings_redirect_to_the_all_lanes() {
    for (gone, successor) in [
        ("limit-all", "strict --all"),
        ("la", "strict --all"),
        ("strict-all", "strict --all"),
        ("sa", "strict --all"),
        ("block-all", "block --all"),
        ("ba", "block --all"),
        ("unstrict-all", "unstrict --all"),
        ("ua", "unstrict --all"),
    ] {
        let output = zelynic_cmd()
            .arg(gone)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {gone}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "removed '{gone}' must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("unrecognized subcommand '{gone}'")),
            "error must name the removed spelling, got: {stderr}"
        );
        assert!(
            stderr.contains(successor),
            "removed '{gone}' must redirect to '{successor}', got: {stderr}"
        );
    }
}

/// NIGHT-improve-25: the singular 'eagle-eye' alias is removed (one
/// canonical name, one short form 'ee') — it must fail as an
/// unrecognized subcommand whose tip redirects to eagle-eyes, the
/// exact contract observe/top carry.
#[test]
fn test_removed_eagle_eye_alias_redirects_to_eagle_eyes() {
    let output = zelynic_cmd()
        .arg("eagle-eye")
        .output()
        .expect("Failed to execute zelynic eagle-eye");

    assert_eq!(
        output.status.code(),
        Some(2),
        "removed 'eagle-eye' must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand 'eagle-eye'"),
        "error must name the removed alias, got: {stderr}"
    );
    assert!(
        stderr.contains("eagle-eyes"),
        "removed 'eagle-eye' must redirect to eagle-eyes, got: {stderr}"
    );
}
