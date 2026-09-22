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

// ── Short aliases (NIGHT-improve-25) ────────────────────────────────────────

/// NIGHT-improve-25: the ten two-letter aliases route to their
/// canonical commands. The routing discriminator is the
/// unrecognized-subcommand error an unwired name would produce:
/// every alias invocation must NOT end in "unrecognized subcommand"
/// — the six positional verbs land in clap's required-argument usage
/// error instead, and the proof below pins that stronger error per
/// verb. Safe on any uid: a missing positional never reaches a
/// handler.
#[test]
fn test_short_aliases_route_to_canonical_commands() {
    for alias in ["ss", "sm", "la", "bs", "bm", "ba", "us", "um", "ua", "ee"] {
        let output = zelynic_cmd()
            .arg(alias)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {alias}: {e}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains(&format!("unrecognized subcommand '{alias}'")),
            "short alias '{alias}' must route to its canonical command, got: {stderr}"
        );
    }
}

/// NIGHT-improve-25: the six positional-carrying short aliases land in
/// their canonical command's required-argument usage error (exit 2,
/// naming the missing positional) — the exact ladder the bare-verb
/// shorthands (strict, unstrict) ride in the tests above.
#[test]
fn test_short_aliases_with_positionals_hit_usage_errors() {
    for (alias, positional) in [
        ("ss", "<TARGET>"),
        ("sm", "<TARGETS>"),
        ("bs", "<TARGET>"),
        ("bm", "<TARGETS>"),
        ("us", "<TARGET>"),
        ("um", "<TARGETS>"),
    ] {
        let output = zelynic_cmd()
            .arg(alias)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {alias}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "'{alias}' without its positional must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required arguments were not provided") && stderr.contains(positional),
            "'{alias}' must name its canonical positional {positional}, got: {stderr}"
        );
    }
}

/// NIGHT-improve-25: the owner's exact invocations must parse through
/// to the handler ladder. ebpf-gated (the rate validation and the
/// monitor ladder live in the feature-gated handlers) and skipped
/// under root: past the root guard these would enforce for real —
/// the same reason the strict-shorthand rate test above carries the
/// same pair of gates.
#[cfg(feature = "ebpf")]
#[test]
fn test_owner_short_alias_invocations_reach_handlers() {
    if crate::euid_is_root() {
        return; // past the root guard these would enforce for real
    }
    for argv in [
        vec!["ss", "brave", "100kb"],
        vec!["ee", "brave", "--interval", "1s"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(1),
            "'{argv:?}' must reach the handler and stop at the root guard"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("root required"),
            "'{argv:?}' must be inside its canonical handler (root guard), got: {stderr}"
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
