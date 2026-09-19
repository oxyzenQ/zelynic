// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The unprivileged contract (NIGHT-hunt-13): every enforcement
//! surface refuses cleanly as non-root, input validation precedes the
//! privilege guard, and hostile-looking inputs degrade into ordinary
//! errors — never a panic.

use crate::{euid_is_root, zelynic_cmd};

/// NIGHT-hunt-13: the unprivileged contract. Every enforcement
/// surface must refuse cleanly as non-root: exit 1 (not a clap usage
/// error, not a panic), the branded "root required" wording, and the
/// actionable sudo tip. Pinned by scripts/nonroot-depth-test.sh for
/// the full 70-case matrix; this test keeps the core of it inside
/// `cargo test`. No-ops under root (sudo cargo test) where the
/// contract cannot hold.
#[cfg(feature = "ebpf")]
#[test]
fn test_enforcement_commands_refuse_non_root_cleanly() {
    if euid_is_root() {
        return; // contract only observable as unprivileged user
    }
    const ENFORCEMENT_ARGV: [&[&str]; 12] = [
        &["strict-single", "brave", "100kb"],
        &["strict", "brave", "100kb"],
        &["strict-multi", "brave:curl", "1mb"],
        &["limit-all", "500kb"],
        &["block-single", "brave"],
        &["block-all"],
        &["unstrict", "brave"],
        &["unstrict-all"],
        &["recover"],
        &["status"],
        &["observe"],
        &["top"],
    ];
    for argv in ENFORCEMENT_ARGV {
        let output = zelynic_cmd()
            .args(argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "enforcement {argv:?} must refuse with exit 1 as non-root"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("root required") && stderr.contains("tip: re-run with sudo"),
            "refusal must carry the branded wording + sudo tip for {argv:?}, got:\n{stderr}"
        );
        assert!(
            !stderr.contains("panicked"),
            "refusal must never panic for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13, default (no-ebpf) build: enforcement surfaces
/// answer "eBPF not compiled" with the rebuild tip — same clean exit 1
/// contract, wording pinned so the fallback binary stays honest too.
#[cfg(not(feature = "ebpf"))]
#[test]
fn test_enforcement_commands_report_missing_feature_cleanly() {
    if euid_is_root() {
        return; // wording identical under root; matrix pinned as non-root
    }
    for argv in [
        vec!["strict-single", "brave", "100kb"],
        vec!["status"],
        vec!["unstrict-all"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "no-ebpf build must exit 1 for {argv:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("eBPF not compiled") && stderr.contains("cargo build --features ebpf"),
            "no-ebpf build must carry the rebuild tip for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13: the fail-fast ladder is uid-independent — input
/// validation fires BEFORE the root guard, so a typo reports the typo
/// whether the user can sudo or not. Works under both uids (root also
/// sees the validation error first; the ladder is ordered in code).
/// ebpf-gated: the rate/interval parsers live behind the feature.
#[cfg(feature = "ebpf")]
#[test]
fn test_input_validation_precedes_privilege_guard() {
    const CASES: [(&[&str], &str); 4] = [
        (&["strict-single", "brave", "1MB"], "Invalid rate '1MB'"),
        (&["strict-single", "brave", "1b"], "below minimum"),
        (&["strict-single", "brave", "2tb"], "above maximum"),
        (&["observe", "--interval", "61s"], "between 1s and 60s"),
    ];
    for (argv, expected) in CASES {
        let output = zelynic_cmd()
            .args(argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "validation case {argv:?} must exit 1"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "case {argv:?} must lead with '{expected}', got:\n{stderr}"
        );
        assert!(
            !stderr.contains("root required"),
            "validation must precede the root guard for {argv:?}, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-13 edge pins: hostile-looking inputs must degrade into
/// ordinary validation/root-guard errors, never a panic (exit 101).
#[test]
fn test_edge_targets_never_panic() {
    for argv in [
        vec!["strict-single", "", "100kb"],
        vec!["strict-single", "99999999999999999999", "100kb"],
        vec!["strict-single", "../../etc", "100kb"],
        vec!["strict-single", "two words", "100kb"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_ne!(
            output.status.code(),
            Some(101),
            "edge input {argv:?} must never panic"
        );
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !all.contains("panicked"),
            "no backtrace for {argv:?}:\n{all}"
        );
    }
}
