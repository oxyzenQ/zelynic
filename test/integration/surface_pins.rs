// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command-surface wiring pins: aliases route to their canonical
//! commands' validation ladders, and removed surfaces fail loudly as
//! usage errors instead of silently changing behavior.

use crate::zelynic_cmd;

/// NIGHT-hunt-10: `strict` is the bare-verb shorthand for
/// strict-single — the owner's `zelynic strict brave` used to die with
/// an unrecognized-subcommand error. Missing <target> must be a usage
/// error (exit 2) about the required positional <TARGET>, proving the
/// alias is wired to a real command instead of rejected outright.
#[test]
fn test_strict_shorthand_is_strict_single() {
    let output = zelynic_cmd()
        .arg("strict")
        .output()
        .expect("Failed to execute zelynic strict");

    assert_eq!(
        output.status.code(),
        Some(2),
        "strict without a target must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
        "error must name the missing strict-single positional, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: the strict shorthand must reach strict-single's
/// validation ladder — an invalid rate surfaces its did-you-mean tip
/// BEFORE the root guard, so this pins the dispatch without requiring
/// root or eBPF state. ebpf-gated: the rate ladder lives in the
/// feature-gated handler (the default build answers "eBPF not compiled").
#[cfg(feature = "ebpf")]
#[test]
fn test_strict_shorthand_reaches_rate_validation() {
    let output = zelynic_cmd()
        .args(["strict", "brave", "1MB"])
        .output()
        .expect("Failed to execute zelynic strict brave 1MB");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid rate '1MB'"),
        "strict must route into strict-single's rate validation, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10: unstrict-multi exists and takes a colon-separated
/// target list — missing <targets> is a usage error naming the required
/// positional.
#[test]
fn test_unstrict_multi_requires_targets() {
    let output = zelynic_cmd()
        .arg("unstrict-multi")
        .output()
        .expect("Failed to execute zelynic unstrict-multi");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unstrict-multi without targets must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided") && stderr.contains("<TARGETS>"),
        "error must name the missing unstrict-multi positional, got:\n{stderr}"
    );
}

/// NIGHT-hunt-10 introduced the alias; NIGHT-hunt-16 flipped the
/// canonical to unstrict-single (strict/unstrict symmetry: canonical
/// carries the -single suffix, shorthand drops it). Missing <target>
/// is a usage error naming the required positional — for BOTH the
/// canonical and the shorthand invocation.
#[test]
fn test_unstrict_single_alias_is_unstrict() {
    for form in ["unstrict-single", "unstrict"] {
        let output = zelynic_cmd()
            .arg(form)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {form}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "{form} without a target must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
            "error must name the missing {form} positional, got:\n{stderr}"
        );
    }
}

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
/// `--duration` are removed from observe/top, so both must fail as
/// unknown arguments (exit 2) instead of silently changing behavior.
#[test]
fn test_removed_monitor_timer_flags_are_rejected() {
    for argv in [
        vec!["observe", "--live", "3m"],
        vec!["top", "--live", "0"],
        vec!["top", "--duration", "30s"],
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
