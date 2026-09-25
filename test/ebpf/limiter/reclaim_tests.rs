// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the reclaim surface — kept in the repo's single test/
//! tree (NIGHT-hunt-17, cosmostrix Pattern C) and #[path]-wired from
//! reclaim.rs. Covers the NIGHT-improve-10 trace wording; the
//! ENOENT-vs-failure classification of the shared tri-state delete
//! contract is pinned once in policy_tests.rs (map_remove_means_absent
//! moved to reclaim.rs, its pin tests travel with the contract's
//! consumers, not the definition — the glob from policy.rs keeps
//! them running against the moved definition).

use super::*;
// The unstrict partial-failure pin (moved with its subject from
// policy_tests.rs, NIGHT-improve-29's 500-LOC split): the survivor
// lines come from the policy module (pub(super) there), the
// direction type from the shared types module.
use super::super::policy::policy_survivor_line;
use super::super::types::Direction;

/// NIGHT-improve-10 drift pins: the reclaim trace wording names the
/// LTS budget explicitly — it is the diagnostic surface that tells an
/// owner why unstrict now touches three extra maps.

#[test]
fn reclaim_trace_line_singular_and_plural() {
    assert_eq!(
        reclaim_trace_line(42, 1),
        "[limiter] cg:42 reclaimed 1 stale state entry — \
         bucket/stats slots returned to the 1024-entry LTS budget"
    );
    assert_eq!(
        reclaim_trace_line(7, 3),
        "[limiter] cg:7 reclaimed 3 stale state entries — \
         bucket/stats slots returned to the 1024-entry LTS budget"
    );
}

#[test]
fn unstrict_partial_failure_line_reports_removed_and_survivors() {
    assert_eq!(
        unstrict_partial_failure_line(3, &[policy_survivor_line(73386, Direction::Download)]),
        "removed 3 policies, but 1 is still enforced: cg:73386 download — \
         run 'zelynic recover' if this persists"
    );
    assert_eq!(
        unstrict_partial_failure_line(
            1,
            &[
                policy_survivor_line(73386, Direction::Download),
                policy_survivor_line(73390, Direction::Upload),
            ]
        ),
        "removed 1 policy, but 2 are still enforced: cg:73386 download, \
         cg:73390 upload — run 'zelynic recover' if this persists"
    );
}

// ── the NIGHT-lts-7 dead-group reclaim (the 256-slot budget) ───────────────

/// The decision core: a captured group dies only when no live policy
/// references it. The sentinel 0 (individual buckets) never counts;
/// duplicates collapse (one old group overwritten across many member
/// policies is ONE dead group); the result is sorted for
/// deterministic verbose traces.
#[test]
fn dead_groups_keeps_referenced_groups_and_drops_the_rest() {
    // Two dead groups, one survivor, one sentinel, one duplicate.
    let captured = [500, 300, 0, 500];
    let live = [400, 300, 0];
    assert_eq!(dead_groups(&captured, &live), vec![500]);
    // Nothing live: every real captured group dies, sorted, once.
    assert_eq!(dead_groups(&[900, 100, 900, 0], &[]), vec![100, 900]);
    // Everything still referenced: nothing dies.
    assert_eq!(dead_groups(&[300, 400], &[400, 300]), Vec::<u32>::new());
    // Empty capture: the sweep is a no-op.
    assert_eq!(dead_groups(&[], &[42]), Vec::<u32>::new());
}

/// The group reclaim's verbose trace names the 256-slot budget — the
/// diagnostic that tells an owner why an unstrict after a strict-multi
/// touches the shared-bucket maps (NIGHT-lts-7).
#[test]
fn group_reclaim_trace_line_singular_and_plural() {
    assert_eq!(
        group_reclaim_trace_line(1234, 1),
        "[limiter] group:1234 reclaimed 1 shared-bucket slot — \
         the group's last reference is gone, slots returned to the 256-entry budget"
    );
    assert_eq!(
        group_reclaim_trace_line(99, 2),
        "[limiter] group:99 reclaimed 2 shared-bucket slots — \
         the group's last reference is gone, slots returned to the 256-entry budget"
    );
}
