// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Panel retirement pins (NIGHT-hunt-34, the render twin): the
//! display-only retire_dead's contract — the 3-frame grace (a row
//! hides only past it), the flap guard (a live frame clears the
//! streak), the empty-identity signal guard (a failed walk stands
//! the pass down), the state-survival law (the hidden row's
//! learned EMA stays — the ring read re-seeds a deleted key, so the
//! filter hides rather than deletes), and the streak map's own
//! retain law (a key whose ring row left the read takes its streak
//! with it). One file per contract (the session tree's own split
//! discipline, session_retire_tests the precedent). `super::`
//! reaches the lane through the #[path] wiring in
//! src/ebpf/render/baseline.rs.

use super::*;
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::limiter::rate_ring::{RateRingRaw, RATE_RING_SLOTS, RATE_RING_WINDOW_NS};

/// Identity map naming exactly the given ids (every other cgroup is
/// identity-absent — the miss shape the retirement discriminates).
fn identity_of(ids: &[u32]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for &id in ids {
        identity.insert(ProcessIdentity {
            cgroup_id: id,
            uid: 1000,
            comm: format!("app{id}"),
        });
    }
    identity
}

/// A lane holding dl state for exactly the given roots — one
/// fold_direction call carrying every root (the fold's retain law
/// keeps exactly the keys the read names, so per-root seeding calls
/// would each wipe their siblings' state).
fn lane_of(roots: &[u32]) -> BaselineLane {
    let rows: Vec<(u32, RateRingRaw)> = roots
        .iter()
        .map(|&root| {
            let mut raw = RateRingRaw::default();
            let slot = &mut raw.slots[94 % RATE_RING_SLOTS];
            slot.window = 94;
            slot.bytes = 98_000;
            (root, raw)
        })
        .collect();
    // Read mid-window after 94 — the seed seam's own clock.
    let now = (94 + 1) * RATE_RING_WINDOW_NS + 500_000_000;
    let mut lane = BaselineLane::new();
    BaselineLane::fold_direction(&mut lane.dl, Some(&rows), now);
    lane
}

/// The panel's key set, sorted (the row order the weight sort
/// re-arranges; only membership matters to the retirement).
fn panel_keys(lane: &BaselineLane) -> Vec<u32> {
    let mut keys: Vec<u32> = lane.panel_rows().into_iter().map(|(k, _, _)| k).collect();
    keys.sort_unstable();
    keys
}

/// The grace itself: two dead frames keep the row on the panel,
/// the third hides it — and only the dead root hides (the live
/// sibling never flaps).
#[test]
fn retire_dead_hides_only_past_the_grace() {
    let mut lane = lane_of(&[7, 9]);
    let live = identity_of(&[7]);
    // Frame one and two: the streak builds, the panel holds both.
    lane.retire_dead(&live);
    lane.retire_dead(&live);
    assert_eq!(
        panel_keys(&lane),
        vec![7, 9],
        "two dead frames stay inside the grace"
    );
    // Frame three: the streak reaches the grace, the dead root
    // hides, the live one never does.
    lane.retire_dead(&live);
    assert_eq!(
        panel_keys(&lane),
        vec![7],
        "the third dead frame retires the row"
    );
}

/// The flap guard: a live frame inside the grace clears the
/// streak, so a refresh hiccup that briefly loses a live root's
/// entry never compounds toward retirement.
#[test]
fn retire_dead_live_frame_clears_the_streak() {
    let mut lane = lane_of(&[9]);
    // Two dead frames (the walk names some other cgroup), then the
    // root returns: the streak resets to zero.
    let others = identity_of(&[8]);
    lane.retire_dead(&others);
    lane.retire_dead(&others);
    lane.retire_dead(&identity_of(&[9]));
    // Two dead frames after the flap: streak 2, still inside the
    // grace — the row survives what would have been the third and
    // fourth had the streak compounded across the live frame.
    lane.retire_dead(&others);
    lane.retire_dead(&others);
    assert_eq!(
        panel_keys(&lane),
        vec![9],
        "the flap reset keeps a live root on the panel"
    );
}

/// The signal guard: an EMPTY identity map is a failed walk, never
/// proof that every root died — the pass stands down, no streak
/// builds, the panel keeps every row.
#[test]
fn retire_dead_empty_identity_stands_down() {
    let mut lane = lane_of(&[7, 9]);
    let failed_walk = IdentityMap::new();
    for _ in 0..6 {
        lane.retire_dead(&failed_walk);
    }
    assert_eq!(
        panel_keys(&lane),
        vec![7, 9],
        "a failed walk retires nothing"
    );
}

/// The state-survival law: the retirement is display-only. The
/// hidden row's learned state stays (a deleted key would re-seed
/// from the ring read the very next frame and churn back as
/// `learning 1/8`), and a root that returns inside the lane's key
/// set re-renders with its EMA intact.
#[test]
fn retire_dead_hides_without_deleting_the_state() {
    let mut lane = lane_of(&[9]);
    let others = identity_of(&[8]);
    for _ in 0..3 {
        lane.retire_dead(&others);
    }
    assert_eq!(
        panel_keys(&lane),
        Vec::<u32>::new(),
        "past the grace the row hides"
    );
    assert!(
        lane.dl.contains_key(&9),
        "the hidden row's learned state stays — display-only by design"
    );
    // The root returns (a live frame): the streak clears and the
    // row re-renders with the state it kept, not a fresh learn.
    lane.retire_dead(&identity_of(&[9]));
    assert_eq!(
        panel_keys(&lane),
        vec![9],
        "a returning root re-renders immediately"
    );
}

/// The streak map's own retain law: a key whose ring row left the
/// read (the zombie sweep collected it, or the pin epoch changed)
/// takes its streak with it — the map never outlives the rows it
/// judges.
#[test]
fn retire_dead_streak_rides_the_lane_key_set() {
    let mut lane = lane_of(&[9]);
    let others = identity_of(&[8]);
    for _ in 0..3 {
        lane.retire_dead(&others);
    }
    assert!(
        lane.retire_streaks.contains_key(&9),
        "the streak built with the row"
    );
    // The ring row leaves the read — the lane's fold drops the
    // state, and the next pass drops the streak with it.
    lane.dl.remove(&9);
    lane.retire_dead(&others);
    assert!(
        lane.retire_streaks.is_empty(),
        "a key whose ring row left takes its streak with it"
    );
}
