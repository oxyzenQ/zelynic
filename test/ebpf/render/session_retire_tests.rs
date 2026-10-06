// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Session retirement pins (NIGHT-mitigate-1, the mitigate-1 audit's
//! finding B): the freeze lifter's contract — the cap gate (the pass
//! engages only at a full board, where a freed slot is the entire
//! point), the grace window, the slot-freeing, the identity signal
//! guard, the streak reset (the flap guard), and the
//! traffic-without-identity liveness that mirrors `board_rows`' own
//! predicate. One file per contract (the footer tree's split
//! discipline): the retirement family pushed the session pins past
//! the owner's LOC cap, so they take their own file beside
//! session_tests.rs, wired the same Pattern C way. `super::` reaches
//! the session module through the #[path] wiring in
//! src/ebpf/render/session.rs.

use super::*;
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::CgroupDelta;

fn delta(cg: u32, bytes: u64) -> CounterSummary {
    CounterSummary {
        total_packets: 1,
        total_bytes: bytes,
        total_ingress_packets: 0,
        total_ingress_bytes: 0,
        cgroups: vec![CgroupDelta {
            cgroup_id: cg,
            packets: 1,
            bytes,
            total_bytes: bytes,
            ingress_packets: 0,
            ingress_bytes: 0,
            ingress_total_bytes: 0,
        }],
    }
}

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

/// Fill a board to the cap with filler rows beside the ids under
/// test, returning the session and the full id list (every pin
/// then builds the identity map its scenario needs — the gate only
/// engages a full board, so every pin starts here, exactly the
/// dense-host shape the mitigation exists for).
fn fill_to_cap(under_test: &[u32]) -> (SessionState, Vec<u32>) {
    let mut session = SessionState::new();
    let mut ids: Vec<u32> = under_test.to_vec();
    let mut next = 2_000_000u32;
    while ids.len() < MAX_TRACKED_CGROUPS {
        ids.push(next);
        next += 1;
    }
    for &id in &ids {
        session.absorb(&delta(id, 1));
    }
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "the board starts at cap"
    );
    (session, ids)
}

/// The gate: below the cap the pass stays out of the render path
/// entirely — the frame bench's 24-row board must pay nothing. The
/// clear() on the closed gate also pins the era rule: a gated-off
/// era never carries a stale streak into the next one.
#[test]
fn below_the_cap_the_pass_stays_gated() {
    let mut session = SessionState::new();
    session.absorb(&delta(1, 100));
    let stranger = identity_of(&[999]);
    // Dead frames below cap: no retirement (nothing needs freeing),
    // no error, no cost.
    for _ in 0..RETIRE_GRACE_FRAMES * 5 {
        session.retire_dead(&stranger, &CounterSummary::default());
    }
    assert_eq!(session.len(), 1, "the gated pass retires nothing below cap");
}

/// The freeze lifter — the mitigation's own pin: a full board with
/// DEAD rows admits the fresh cgroup the old freeze refused, because
/// retirement frees the slots the dead were holding. The
/// pre-mitigate-1 behavior this pin retires: the first 4096 own the
/// board forever.
#[test]
fn retirement_frees_slots_for_fresh_cgroups() {
    let mut session = SessionState::new();
    // Fill the board to cap: cgroup 1 stays LIVE (identity holds
    // it), cgroups 2..=cap are the churned dead (identity never
    // names them — the fleet that came and went).
    let cap = u32::try_from(MAX_TRACKED_CGROUPS).expect("cap fits u32");
    for id in 1..=cap {
        session.absorb(&delta(id, 1));
    }
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS);
    // The freeze shape (the old behavior): a fresh cgroup refused.
    session.absorb(&delta(u32::MAX, 50));
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "the pre-retirement board is full"
    );
    // The retirement pass: the identity walk names ONLY cgroup 1,
    // so every other row walks the grace and frees its slot.
    let live = identity_of(&[1]);
    for _ in 0..RETIRE_GRACE_FRAMES {
        session.retire_dead(&live, &CounterSummary::default());
    }
    assert_eq!(
        session.len(),
        1,
        "the churned dead retire; the live row keeps its slot"
    );
    // The fresh cgroup boards now — the 10-year blindness retired.
    session.absorb(&delta(u32::MAX, 50));
    assert_eq!(session.len(), 2, "the fresh cgroup finds a slot");
    assert!(
        session.ranked().iter().any(|(id, _)| *id == u32::MAX),
        "the fresh cgroup ranks"
    );
}

/// The grace contract at a full board: the dead row survives two
/// dead frames and retires on the third — and the LIVE rows (the
/// identity map names them) never retire, however many quiet
/// frames pass (the session-leaderboard contract itself: rank by
/// what an app ate this session, an idle app keeps its row).
#[test]
fn dead_rows_retire_after_the_grace_window() {
    // The identity names everything EXCEPT row 2 (its cgroup left
    // the host between frames); row 2 is the one going dead.
    let (mut session, ids) = fill_to_cap(&[1, 2]);
    let live = identity_of(&ids.into_iter().filter(|id| *id != 2).collect::<Vec<u32>>());
    // Two dead frames: the streak builds, every row survives.
    session.retire_dead(&live, &CounterSummary::default());
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS, "grace frame 1");
    session.retire_dead(&live, &CounterSummary::default());
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS, "grace frame 2");
    // The third dead frame: the dead row retires, the live hold.
    session.retire_dead(&live, &CounterSummary::default());
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS - 1,
        "the dead row retires on the grace's third frame"
    );
    let board = session.ranked();
    assert!(board.iter().all(|(id, _)| *id != 2), "the dead row is gone");
    assert!(
        board.iter().any(|(id, _)| *id == 1),
        "the live row survives"
    );
    let one = board.into_iter().find(|(id, _)| *id == 1);
    assert_eq!(
        one.map(|(_, a)| a.ul),
        Some(1),
        "the live row keeps its history"
    );
}

/// The signal guard: an EMPTY identity map is a failed walk, not
/// proof of universal death — no row retires at a full board,
/// however many frames pass. A procfs hiccup must not wipe the
/// leaderboard's history.
#[test]
fn an_identity_signal_loss_retires_nothing() {
    let (mut session, _ids) = fill_to_cap(&[7, 8]);
    let dead_walk = IdentityMap::new();
    for _ in 0..RETIRE_GRACE_FRAMES * 5 {
        session.retire_dead(&dead_walk, &CounterSummary::default());
    }
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "a failed identity walk retires nothing — the signal guard"
    );
    // And the board still folds while the guard holds.
    session.absorb(&delta(7, 300));
    let board = session.ranked();
    assert_eq!(
        board.iter().find(|(id, _)| *id == 7).map(|(_, a)| a.ul),
        Some(301),
        "the folds continue under the guard"
    );
}

/// The flap guard: a live frame RESETS the streak. A row that goes
/// dead-dead-live (the identity walk briefly missing a live row,
/// its traffic still arriving) must not carry its old streak —
/// three separate one-frame misses never accumulate into a
/// retirement. The streak counts CONSECUTIVE dead frames only.
#[test]
fn a_live_frame_resets_the_streak() {
    // A full board where row 9 is the only identity-absent row and
    // every filler is live: retirement, when it comes, can only
    // touch row 9, so the board stays at cap through the whole
    // flap sequence (the gate never closes mid-pin).
    let (mut session, ids) = fill_to_cap(&[9]);
    let miss = identity_of(&ids.into_iter().filter(|id| *id != 9).collect::<Vec<u32>>());
    // dead, dead (row 9 streak 2).
    session.retire_dead(&miss, &CounterSummary::default());
    session.retire_dead(&miss, &CounterSummary::default());
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS);
    // The live frame: traffic without identity — window_active
    // names the row, the streak clears.
    session.retire_dead(&miss, &delta(9, 100));
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "traffic keeps the row live"
    );
    // dead, dead again (streak 2, restarted from zero) — still
    // short of the grace.
    session.retire_dead(&miss, &CounterSummary::default());
    session.retire_dead(&miss, &CounterSummary::default());
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "the reset streak must not carry the pre-liveness frames"
    );
    // The third CONSECUTIVE dead frame retires.
    session.retire_dead(&miss, &CounterSummary::default());
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS - 1,
        "three consecutive dead frames retire"
    );
}

/// The liveness predicate mirrors `board_rows` exactly: traffic
/// WITHOUT identity keeps the row (a cookie-less cgroup still
/// moving bytes renders — the display filter's own OR). The
/// retirement must never be stricter than the filter it mirrors,
/// or the board would retire rows the frame still renders.
#[test]
fn traffic_without_identity_keeps_the_row() {
    // A full board of live fillers with row 11 identity-absent but
    // MOVING: the window's active set keeps it boarded frame after
    // frame, exactly as the display filter would.
    let (mut session, ids) = fill_to_cap(&[11]);
    let stranger = identity_of(&ids.into_iter().filter(|id| *id != 11).collect::<Vec<u32>>());
    for _ in 0..RETIRE_GRACE_FRAMES * 3 {
        let frame = delta(11, 50);
        session.absorb(&frame);
        session.retire_dead(&stranger, &frame);
    }
    assert_eq!(
        session.len(),
        MAX_TRACKED_CGROUPS,
        "a moving cgroup stays boarded without identity — the \
         board filter's own OR, mirrored"
    );
    let board = session.ranked();
    assert_eq!(
        board.iter().find(|(id, _)| *id == 11).map(|(_, a)| a.ul),
        Some(1 + 50 * 9),
        "the folds continue unimpeded"
    );
}
