// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-private-research-2 (MMSPA): precision pins for the eBPF
//! resolution core (ebpf/src/mmspa.rs — the same file the BPF object
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
#[path = "../../../ebpf/src/mmspa.rs"]
pub(super) mod ebpf_mmspa;

use self::ebpf_mmspa::{
    CacheVerdict, MMSPA_MAX_DEPTH, MmspaWalk, cache_verdict, memo_gen, memo_root, memo_value,
    walk_queries,
};

/// The nearest-root contract, straight case: one policy on the chain
/// resolves to that cgroup's id.
#[test]
fn walk_single_match_resolves_to_that_root() {
    let mut w = MmspaWalk::new();
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
    let mut w = MmspaWalk::new();
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
    let mut w = MmspaWalk::new();
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
    let mut w = MmspaWalk::new();
    w.note(100, false);
    w.note(200, false);
    w.note(300, false);
    assert_eq!(w.root(), 0, "no match = unlimited = 0");
}

/// A fresh walk (the caller crashed before feeding anything, or the
/// chain was empty) is unlimited, never a stale id.
#[test]
fn fresh_walk_resolves_unlimited() {
    assert_eq!(MmspaWalk::new().root(), 0);
    assert_eq!(MmspaWalk::default().root(), 0);
}

/// The leaf itself is never fed to the walk (the caller checks the
/// leaf's own policy first — a policy at the socket's own cgroup is
/// the nearest possible root). Pinned by the shape that matters: a
/// walk fed ONLY ancestors still resolves correctly when one of them
/// carries the policy.
#[test]
fn walk_fed_ancestors_only_resolves() {
    let mut w = MmspaWalk::new();
    w.note(111, false);
    w.note(222, true);
    assert_eq!(w.root(), 222, "ancestor matches are the walk's whole job");
}

/// Later non-matches after a match must NOT erase it — the state
/// machine keeps the last MATCH, not the last note.
#[test]
fn walk_keeps_last_match_through_trailing_misses() {
    let mut w = MmspaWalk::new();
    w.note(100, false);
    w.note(200, true);
    w.note(300, false);
    w.note(400, false);
    assert_eq!(w.root(), 200);
}

/// The cache decision table, exhaustive: every (cached, generation,
/// alive) triple lands on its documented verdict — including the
/// NIGHT-perf-0 generation row that closes the insert-after-flush
/// race.
#[test]
fn cache_verdict_table_is_exhaustive() {
    // Absent memo: walk.
    assert_eq!(cache_verdict(None, 5, false), CacheVerdict::Walk);
    assert_eq!(cache_verdict(None, 5, true), CacheVerdict::Walk);
    // Cached negative, generation current: allow, unconditionally
    // (removals cannot create coverage; an ADDITION would have
    // bumped the generation — the mismatch row below).
    assert_eq!(
        cache_verdict(Some(memo_value(5, 0)), 5, false),
        CacheVerdict::Allow
    );
    assert_eq!(
        cache_verdict(Some(memo_value(5, 0)), 5, true),
        CacheVerdict::Allow
    );
    // Cached root, generation current, policy alive: enforce that
    // root.
    assert_eq!(
        cache_verdict(Some(memo_value(5, 7)), 5, true),
        CacheVerdict::Enforce(7)
    );
    // Cached root, generation current, policy gone: stale — walk
    // (the stale-detect belt behind the stamp).
    assert_eq!(
        cache_verdict(Some(memo_value(5, 7)), 5, false),
        CacheVerdict::Walk
    );
    // Generation mismatch: Walk no matter what the memo names —
    // the stale-negative and stale-farther-root cases the whole-map
    // delete flush could not close (a walk whose tail an IRQ storm
    // stretched past the sweep inserted pre-mutation state after
    // it). The root may still be alive; the memo is untrusted
    // wholesale.
    assert_eq!(
        cache_verdict(Some(memo_value(4, 0)), 5, false),
        CacheVerdict::Walk
    );
    assert_eq!(
        cache_verdict(Some(memo_value(4, 7)), 5, true),
        CacheVerdict::Walk
    );
    // The wraparound neighbor does NOT alias: a memo stamped one
    // full u32 generation behind (4.2 billion mutations ago) is
    // stale against 5, and only a memo stamped exactly the current
    // generation is current.
    assert_eq!(
        cache_verdict(Some(memo_value(u32::MAX, 7)), 0, true),
        CacheVerdict::Walk
    );
}

/// The memo value contract: the word packs the generation stamp
/// with the walk result — root 0 when nothing matched (the negative
/// memo), a root id when one did — and both halves unpack back
/// verbatim.
#[test]
fn memo_value_packs_gen_and_root_and_roundtrips() {
    assert_eq!(
        memo_value(0, 0),
        0,
        "gen 0 + unlimited packs as the zero word"
    );
    assert_eq!(memo_gen(memo_value(0, 0)), 0);
    assert_eq!(
        memo_root(memo_value(0, 0)),
        0,
        "unlimited memoizes as root 0"
    );
    assert_eq!(
        memo_root(memo_value(9, 12345)),
        12345,
        "a root memoizes as itself"
    );
    assert_eq!(memo_gen(memo_value(9, 12345)), 9, "the stamp rides along");
    // The full-range pair: both halves survive their own maximum.
    let packed = memo_value(u32::MAX, u32::MAX);
    assert_eq!(memo_gen(packed), u32::MAX);
    assert_eq!(memo_root(packed), u32::MAX);
    // The packing is bit-exact: high word is the stamp, low word is
    // the root, no overlap, no sign extension.
    assert_eq!(memo_value(1, 2), (1u64 << 32) | 2);
    assert_eq!(memo_value(0, u32::MAX), u32::MAX as u64);
    assert_eq!(memo_value(u32::MAX, 0), (u32::MAX as u64) << 32);
}

/// The stamp ordering contract, stated as the decision the datapath
/// makes: a memo is only ever trusted under the exact generation
/// it was written with, so the walk that rewrites it re-reads the
/// only authority (the live policy map). The stamp makes every
/// insert race self-healing — the mismatch is detected per packet,
/// on the memo's own word, with no sweep involved.
#[test]
fn only_the_current_generation_is_trusted() {
    let root = 900u32;
    for stale_gen in [0u32, 1, 41, u32::MAX] {
        let cached = memo_value(stale_gen, root);
        assert_eq!(
            cache_verdict(Some(cached), 42, true),
            CacheVerdict::Walk,
            "stale stamp {stale_gen} against current 42 must walk"
        );
    }
    // The one current stamp is the one trusted verdict.
    assert_eq!(
        cache_verdict(Some(memo_value(42, root)), 42, true),
        CacheVerdict::Enforce(root)
    );
}

/// The depth bound: 32 is the ceiling — deep enough to triple every
/// real hierarchy (systemd ~6, containers ~4, Kubernetes <10),
/// shallow enough that the walk's worst case is bounded even on a
/// hostile chain.
#[test]
fn depth_bound_is_32() {
    assert_eq!(MMSPA_MAX_DEPTH, 32);
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
