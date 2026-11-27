// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The single-target grammar rung's own pins (night-cafe-1, F5):
//! the input boundary refuses the shapes that can never resolve —
//! the cg: display prefix over a non-id and a container URI its own
//! scheme refuses — at the privilege-free rung, the parse-before-
//! execute law the rate family owns. Split from safety_tests.rs at
//! the 600-LOC cap pressure — one theme, one file, the target_grammar
//! lineage.

use super::*;

// ── night-cafe-1 (F5): the grammar rung owns what can never resolve ──────

/// `cg:` over a non-id (or nothing) is a grammar crime: the display
/// prefix names a cgroup id, and no kernel comm carries ':' — the
/// refusal teaches both exits at the privilege-free rung instead of
/// dying as a late no-match behind the root gate.
#[cfg(all(test, feature = "ebpf"))]
#[test]
fn single_target_refuses_cg_prefix_over_a_non_id() {
    for bad in ["cg:abc", "cg:"] {
        let err = validate_single_target(bad, "zelynic strict brave 100kb")
            .expect_err("a non-id cg: spelling must refuse");
        let msg = format!("{err}");
        assert!(
            msg.contains("the cg: id prefix over a non-id"),
            "the prefix crime is named: {msg}"
        );
        assert!(
            msg.contains("a process name takes no prefix"),
            "the name exit is taught: {msg}"
        );
    }
    // The valid spellings pass the rung untouched.
    for good in ["cg:12345", "12345", "brave", "docker://nginx"] {
        validate_single_target(good, "zelynic strict brave 100kb")
            .unwrap_or_else(|e| panic!("'{good}' must pass the grammar rung: {e}"));
    }
}

/// A container URI the grammar refuses dies at the input boundary
/// with the scheme's own law named — never behind the root gate.
#[cfg(all(test, feature = "ebpf"))]
#[test]
fn single_target_refuses_malformed_container_uris() {
    for (bad, law) in [
        ("docker://", "needs a container name"),
        ("docker://a/b", "no '/' or ':'"),
        ("k8s://prod", "exactly one '/'"),
        ("k8s://prod/", "exactly one '/'"),
        ("netns://", "needs a namespace name"),
        ("iface://", "needs a VRF domain name"),
    ] {
        let err = validate_single_target(bad, "zelynic strict brave 100kb")
            .expect_err("a malformed URI must refuse");
        let msg = format!("{err}");
        assert!(
            msg.contains("malformed container URI"),
            "the URI crime is named for '{bad}': {msg}"
        );
        assert!(
            msg.contains(law),
            "the scheme's own law is named for '{bad}': {msg}"
        );
        assert!(
            msg.contains("docker://<name>, k8s://<namespace>/<pod>"),
            "the grammar tip rides for '{bad}': {msg}"
        );
    }
}
