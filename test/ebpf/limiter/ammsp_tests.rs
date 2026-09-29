// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-private-research-2 (AMMSP): precision pins for the eBPF
//! resolution core (ebpf/src/ammsp.rs — the same file the BPF object
//! builds). The walk state machine, the cache decision table, and
//! the depth bound are every decision the kernel-side plumbing
//! makes; these pins make them provable rootlessly, the
//! NIGHT-depthbore-1 math_tests discipline applied to the resolver.
//!
//! Every pin maps to a documented contract:
//!
//!  * nearest-root selection — ascending feed order makes the LAST
//!    match the nearest root (the nested-root verdict: a strict on A
//!    and a stricter strict on B, B under A, give a socket under B
//!    the B budget);
//!  * the walk's zero-match root — 0 means unlimited, and 0 is
//!    unreachable as a real cgroup id (kernfs ids start at 1);
//!  * the cache decision table — negative memos allow, positive
//!    memos enforce only while the policy map agrees, everything
//!    else re-walks;
//!  * the depth bound — 32 levels, a ceiling not a cost (the early
//!    break makes a depth-6 socket pay ~8 queries, not 32), and the
//!    one documented compromise beyond it.

// The production resolution core, compiled into this test module:
// the SAME file the BPF object builds (ebpf/src/bin/limiter.rs wires
// it with its own #[path]). Only the test tree reaches across trees
// — src/ wirings stay under test/ (the gate-tree discipline).
#[path = "../../../ebpf/src/ammsp.rs"]
pub(super) mod ebpf_ammsp;

use self::ebpf_ammsp::{
    cache_verdict, memo_value, walk_queries, AmmspWalk, CacheVerdict, AMMSP_MAX_DEPTH,
};

/// The nearest-root contract, straight case: one policy on the chain
/// resolves to that cgroup's id.
#[test]
fn walk_single_match_resolves_to_that_root() {
    let mut w = AmmspWalk::new();
    // Ascending feed: root (100), level 1 (200), level 2 (300).
    w.note(100, false);
    w.note(200, true);
    w.note(300, false);
    assert_eq!(w.root(), 200, "the one match is the root");
}

/// The nested-root verdict: two policies on one chain (A at level 1,
/// B at level 2 — B a DESCENDANT of A), the LAST ascending match
/// wins because it is the NEAREST root to the leaf.
#[test]
fn walk_nested_roots_pick_the_nearest() {
    let mut w = AmmspWalk::new();
    w.note(100, false); // cgroup root
    w.note(200, true); // A: the outer strict
    w.note(300, true); // B: the inner, nearer strict
    w.note(400, false);
    assert_eq!(w.root(), 300, "nearest root wins — B budgets its subtree");
}

/// Order independence in the application sense: whichever strict was
/// applied FIRST, the feed order (ascending levels) decides — the
/// nearer root wins whether it was the first or the second policy
/// written. Pinned by feeding the SAME chain with the same matches:
/// the verdict cannot depend on write order because it only depends
/// on level order.
#[test]
fn walk_verdict_depends_on_level_order_not_write_order() {
    // The same chain as the nested pin — the state machine never
    // sees write order, only feed order.
    let mut w = AmmspWalk::new();
    w.note(100, false);
    w.note(200, true);
    w.note(300, true);
    w.note(400, false);
    assert_eq!(w.root(), 300);
}

/// The zero-match root: nothing on the chain carries a policy, so
/// the socket is unlimited and the root is the 0 sentinel.
#[test]
fn walk_no_match_resolves_unlimited() {
    let mut w = AmmspWalk::new();
    w.note(100, false);
    w.note(200, false);
    w.note(300, false);
    assert_eq!(w.root(), 0, "no match = unlimited = 0");
}

/// A fresh walk (the caller crashed before feeding anything, or the
/// chain was empty) is unlimited, never a stale id.
#[test]
fn fresh_walk_resolves_unlimited() {
    assert_eq!(AmmspWalk::new().root(), 0);
    assert_eq!(AmmspWalk::default().root(), 0);
}

/// The leaf itself is never fed to the walk (the caller checks the
/// leaf's own policy first — a policy at the socket's own cgroup is
/// the nearest possible root). Pinned by the shape that matters: a
/// walk fed ONLY ancestors still resolves correctly when one of them
/// carries the policy.
#[test]
fn walk_fed_ancestors_only_resolves() {
    let mut w = AmmspWalk::new();
    w.note(111, false);
    w.note(222, true);
    assert_eq!(w.root(), 222, "ancestor matches are the walk's whole job");
}

/// Later non-matches after a match must NOT erase it — the state
/// machine keeps the last MATCH, not the last note.
#[test]
fn walk_keeps_last_match_through_trailing_misses() {
    let mut w = AmmspWalk::new();
    w.note(100, false);
    w.note(200, true);
    w.note(300, false);
    w.note(400, false);
    assert_eq!(w.root(), 200);
}

/// The cache decision table, exhaustive: every (cached, alive) pair
/// lands on its documented verdict.
#[test]
fn cache_verdict_table_is_exhaustive() {
    // Absent memo: walk.
    assert_eq!(cache_verdict(None, false), CacheVerdict::Walk);
    assert_eq!(cache_verdict(None, true), CacheVerdict::Walk);
    // Cached negative: allow, unconditionally (removals cannot
    // create coverage; additions flush).
    assert_eq!(cache_verdict(Some(0), false), CacheVerdict::Allow);
    assert_eq!(cache_verdict(Some(0), true), CacheVerdict::Allow);
    // Cached root, policy alive: enforce that root.
    assert_eq!(cache_verdict(Some(7), true), CacheVerdict::Enforce(7));
    // Cached root, policy gone: stale — walk.
    assert_eq!(cache_verdict(Some(7), false), CacheVerdict::Walk);
}

/// The negative-memo value contract: the memo stores the walk result
/// verbatim — a root id when one matched, 0 (the same sentinel the
/// walk returns) when none did.
#[test]
fn memo_value_is_the_walk_result_verbatim() {
    assert_eq!(memo_value(0), 0, "unlimited memoizes as 0");
    assert_eq!(memo_value(12345), 12345, "a root memoizes as itself");
}

/// The depth bound: 32 is the ceiling — deep enough to triple every
/// real hierarchy (systemd ~6, containers ~4, Kubernetes <10),
/// shallow enough that the walk's worst case is bounded even on a
/// hostile chain.
#[test]
fn depth_bound_is_32() {
    assert_eq!(AMMSP_MAX_DEPTH, 32);
}

/// The walk cost contract: queries scale with the socket's real
/// depth (plus the one past-the-depth query that breaks the loop),
/// never with the bound itself — and a socket at or past the bound
/// clamps at it, which is the documented compromise (unlimited
/// beyond 32 levels, USAGE.md honest limitations).
#[test]
fn walk_queries_scale_with_depth_not_the_bound() {
    // A depth-2 socket (cgroup root + 2): root, parent, then the
    // break query — 4 total, not 32.
    assert_eq!(walk_queries(2), 4);
    // Depth 6 (systemd user session shape): 8 total.
    assert_eq!(walk_queries(6), 8);
    // Depth 10 (Kubernetes pod shape): 12 total.
    assert_eq!(walk_queries(10), 12);
    // At and past the bound: clamped — the loop cannot exceed it.
    assert_eq!(walk_queries(30), 32);
    assert_eq!(walk_queries(31), 32);
    assert_eq!(walk_queries(1000), 32);
}
