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
