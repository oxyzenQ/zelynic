// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the no-match hard-error builder (NIGHT-dinner-11,
//! the eBPF-verifier lineage applied to the CLI surface: a target
//! that resolves to nothing is REJECTED, never soft-exited). Kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from src/commands/mod.rs.
//!
//! The contract being pinned:
//! 1. The head line carries the verdict verbatim — first line, no
//!    decoration. main's labeled renderer adds the bold red `error:`
//!    label and the per-line colors; this payload is the message
//!    alone, so the shape is testable rootlessly at every color
//!    depth (the renderer itself is pinned in test/output/).
//! 2. Every tip rides its own indented `tip:` line, in order — the
//!    line-aware renderer paints exactly those lines (white for
//!    passive tips, green when the tip quotes a command to run —
//!    NIGHT-dinner-12); a tip
//!    that lost its prefix would render red and the did-you-mean
//!    grammar the CLI owns would break.
//! 3. A tipless refusal is the bare head — no dangling decoration.

use super::target_no_match_error;

/// The owner's exact transcript case (`ss cg8401`): the singular
/// wording with one discovery tip.
#[test]
fn no_match_error_head_and_one_tip() {
    let e = target_no_match_error(
        "No cgroup found for 'cg8401' — nothing was limited".to_string(),
        &["try 'zelynic list-apps' to see live targets".to_string()],
    );
    assert_eq!(
        format!("{e}"),
        "No cgroup found for 'cg8401' — nothing was limited\n  \
         tip: try 'zelynic list-apps' to see live targets"
    );
}

/// Stacked tips keep their order — the specific routing hint first,
/// the generic discovery tip after (the call sites' contract).
#[test]
fn no_match_error_stacks_tips_in_order() {
    // NIGHT-improve-53: the list tip teaches the '::' separator now
    // (single ':' is the prefix grammar's byte) — the builder is
    // payload-agnostic; the wording is the call site's own.
    let e = target_no_match_error(
        "No cgroup found for 'brave:curl' — nothing was limited".to_string(),
        &[
            "list members separate with '::' (single ':' is the cg: prefix and container grammar)"
                .to_string(),
            "try 'zelynic list-apps' to see live targets".to_string(),
        ],
    );
    let msg = format!("{e}");
    assert_eq!(
        msg,
        "No cgroup found for 'brave:curl' — nothing was limited\n  \
         tip: list members separate with '::' (single ':' is the cg: prefix and container grammar)\n  \
         tip: try 'zelynic list-apps' to see live targets"
    );
}

/// The -all sweeps' two-tip shape (discovery + the force flag).
#[test]
fn no_match_error_all_sweep_shape() {
    let e = target_no_match_error(
        "No apps found to limit".to_string(),
        &[
            "try 'zelynic list-apps' to see live targets".to_string(),
            "system apps need --force-this".to_string(),
        ],
    );
    let msg = format!("{e}");
    assert!(msg.starts_with("No apps found to limit\n  tip: "));
    assert!(msg.ends_with("tip: system apps need --force-this"));
}

/// A tipless refusal is the bare head — byte-identical, no newline
/// games (the renderer must never see a stray empty line).
#[test]
fn no_match_error_without_tips_is_the_bare_head() {
    let e = target_no_match_error("No apps to block".to_string(), &[]);
    assert_eq!(format!("{e}"), "No apps to block");
}
