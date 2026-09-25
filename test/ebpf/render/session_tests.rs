// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Session leaderboard pins (NIGHT-boost-5 lineage): the owner's
//! accumulated-total ranking contract (A eats 10 GB and stops; B
//! overtakes on 11 GB), the quiet-frame persistence, the session
//! packet accumulator (NIGHT-engrave-4), the tie-break discipline,
//! the boost-16 saturation and growth-bound pins, and the
//! NIGHT-engrave-6 session-peak pins (the footer speed pair's
//! running maxima: the watched-scope, empty-watch-list, and
//! admission-bound contracts). Split from session.rs's inline tests
//! at NIGHT-engrave-6 when the peak pins pushed the module past the
//! owner's LOC cap — the cosmostrix Pattern C wiring every render
//! module already uses (one file per contract, the single test/
//! tree). `super::` reaches the session module through the #[path]
//! wiring in src/ebpf/render/session.rs.

use super::*;
use crate::ebpf::loader::CgroupDelta;

fn frame(cg: u32, dl: u64, ul: u64) -> CounterSummary {
    CounterSummary {
        total_packets: 1,
        total_bytes: ul,
        total_ingress_packets: 1,
        total_ingress_bytes: dl,
        cgroups: vec![CgroupDelta {
            cgroup_id: cg,
            packets: 1,
            bytes: ul,
            total_bytes: ul,
            ingress_packets: 1,
            ingress_bytes: dl,
            ingress_total_bytes: dl,
        }],
    }
}

/// The owner's exact scenario: A accumulates 10 GB and stops; B
/// keeps eating; when B's session total passes A's, B takes rank 1
/// and A slides to rank 2 — ranking by accumulated total, never
/// by the last frame's delta.
#[test]
fn leaderboard_ranks_by_accumulated_total() {
    let mut session = SessionState::new();
    session.absorb(&frame(1, 10_000_000_000, 0)); // A eats 10 GB

    // A goes quiet, B starts: B is the live eater but A holds
    // rank 1 on the accumulated total.
    session.absorb(&frame(2, 5_000_000_000, 0));
    let board = session.ranked();
    assert_eq!(board[0].0, 1, "A holds rank 1 while quiet");
    assert_eq!(board[1].0, 2);

    // B overtakes: 5 GB + 6 GB > A's 10 GB.
    session.absorb(&frame(2, 6_000_000_000, 0));
    let board = session.ranked();
    assert_eq!(board[0].0, 2, "B takes rank 1 on 11 GB");
    assert_eq!(board[1].0, 1, "A slides to rank 2");
    assert_eq!(board[0].1.total(), 11_000_000_000);
}

/// A quiet frame folds nothing: the board holds every row it
/// ever ranked (no more collapsing to "waiting for traffic…").
#[test]
fn quiet_frame_keeps_the_board() {
    let mut session = SessionState::new();
    session.absorb(&frame(7, 100, 200));
    session.absorb(&CounterSummary::default());
    assert!(!session.is_empty());
    // The frame() helper carries 1 packet per direction: the
    // session packet counter holds BOTH through the quiet frame
    // (NIGHT-engrave-4 — same persistence as the byte legs).
    assert_eq!(
        session.ranked(),
        vec![(
            7,
            SessionAcc {
                dl: 100,
                ul: 200,
                pkt: 2,
            }
        )]
    );
}

/// The session packet accumulator (NIGHT-engrave-4): every
/// frame's per-direction packets fold into ONE session figure —
/// the census line's horizon matches the byte legs' exactly,
/// where the pre-engrave-3 census mixed horizons.
#[test]
fn session_packets_accumulate_both_directions() {
    let mut session = SessionState::new();
    session.absorb(&frame(7, 100, 200));
    session.absorb(&frame(7, 50, 25));
    let board = session.ranked();
    // (1 ul + 1 dl) + (1 + 1) = 4 — the counter never resets on
    // a quiet second and never mixes in a per-frame figure.
    assert_eq!(board[0].1.pkt, 4);
    // Saturating, like every accumulation surface: a saturated
    // packet counter stays saturated (no wrap, no panic).
    let saturated = CounterSummary {
        total_packets: u64::MAX,
        total_bytes: 0,
        total_ingress_packets: u64::MAX,
        total_ingress_bytes: 0,
        cgroups: vec![CgroupDelta {
            cgroup_id: 7,
            packets: u64::MAX,
            bytes: 0,
            total_bytes: 0,
            ingress_packets: u64::MAX,
            ingress_bytes: 0,
            ingress_total_bytes: 0,
        }],
    };
    session.absorb(&saturated);
    session.absorb(&frame(7, 0, 0));
    assert_eq!(session.ranked()[0].1.pkt, u64::MAX);
}

/// Census: empty session is empty; every talked cgroup counts.
/// (The TOTAL row sums its own filtered board — a grand-total
/// helper has no surface, so the pin stays on the census.)
#[test]
fn census_counts_every_talked_cgroup() {
    let mut session = SessionState::new();
    assert!(session.is_empty());
    assert_eq!(session.len(), 0);
    session.absorb(&frame(7, 100, 200));
    session.absorb(&frame(8, 1, 2));
    assert!(!session.is_empty());
    assert_eq!(session.len(), 2);
    let board = session.ranked();
    assert_eq!(board.iter().map(|(_, a)| a.dl).sum::<u64>(), 101);
    assert_eq!(board.iter().map(|(_, a)| a.ul).sum::<u64>(), 202);
}

/// Ties break by cgroup ID: the board must not reshuffle between
/// frames on equal accumulated totals.
#[test]
fn ties_break_by_cgroup_id() {
    let mut session = SessionState::new();
    session.absorb(&frame(30, 500, 500));
    session.absorb(&frame(10, 500, 500));
    session.absorb(&frame(20, 500, 500));
    let board = session.ranked();
    let ids: Vec<u32> = board.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![10, 20, 30]);
}

// ── NIGHT-boost-16 / safety-security-1: accumulate-explosion pins ──

/// Saturation, not panic or wrap: both legs at u64::MAX must
/// total to u64::MAX. A debug build used to panic here (`dl +
/// ul` overflows), a release build wrapped to a small number —
/// the leaderboard would have crowned a wrap-around winner.
#[test]
fn saturated_totals_read_as_maximum() {
    let acc = SessionAcc {
        dl: u64::MAX,
        ul: u64::MAX,
        pkt: u64::MAX,
    };
    assert_eq!(acc.total(), u64::MAX);
    // One leg saturated, one leg free: the total still reads as
    // the ceiling (18.4 EB this session is saturation).
    assert_eq!(
        SessionAcc {
            dl: u64::MAX,
            ul: 1,
            pkt: 0,
        }
        .total(),
        u64::MAX
    );
}

/// The fold saturates and STAYS saturated: an accumulator at
/// u64::MAX absorbs further traffic without wrap — the honest
/// shape of a counter that has simply run out of bits.
#[test]
fn absorb_saturates_and_stays_saturated() {
    let mut session = SessionState::new();
    session.absorb(&frame(1, u64::MAX, 0));
    session.absorb(&frame(1, 10_000_000, 0));
    let board = session.ranked();
    assert_eq!(
        board[0].1.dl,
        u64::MAX,
        "saturated download stays saturated"
    );
    assert_eq!(board[0].1.ul, 0);
    // The ranking key survives the saturation (no wrap panic).
    assert_eq!(board[0].1.total(), u64::MAX);
}

/// Growth bound (MAX_TRACKED_CGROUPS): the board mirrors the
/// kernel's own 4096-entry counter-map ceiling (NIGHT-improve-31,
/// the dense-host raise) — a 4097th
/// distinct cgroup cannot rank, while every tracked cgroup
/// keeps updating inside the bound.
#[test]
fn leaderboard_growth_is_bounded_at_the_map_ceiling() {
    let mut session = SessionState::new();
    for id in 1..=u32::try_from(MAX_TRACKED_CGROUPS).expect("cap fits u32") {
        session.absorb(&frame(id, 1, 1));
    }
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS);
    // A fresh cgroup past the bound: not admitted.
    session.absorb(&frame(u32::MAX, 100, 100));
    assert_eq!(session.len(), MAX_TRACKED_CGROUPS, "no 4097th entry");
    assert!(session.ranked().iter().all(|(id, _)| *id != u32::MAX));
    // A tracked cgroup inside the bound: still updates.
    session.absorb(&frame(1, 1000, 0));
    let one = session.ranked().into_iter().find(|(id, _)| *id == 1);
    assert_eq!(
        one.map(|(_, a)| a.dl),
        Some(1001),
        "existing entries keep folding inside the bound"
    );
}

/// The ranked walk over saturated values is panic-free in debug:
/// sort_by over u64::MAX totals with a tie broken by ID.
#[test]
fn ranked_walks_saturated_values_without_panic() {
    let mut session = SessionState::new();
    session.absorb(&frame(9, u64::MAX, u64::MAX));
    session.absorb(&frame(2, u64::MAX, u64::MAX));
    let board = session.ranked();
    // Saturated tie: ID order decides, no arithmetic panic.
    assert_eq!(board[0].0, 2);
    assert_eq!(board[1].0, 9);
}

// ── NIGHT-engrave-6: the session-peak pins (the footer's speed
// pair) ──

/// A two-cgroup frame helper for the watched-set pins.
fn two(cg_a: u32, dl_a: u64, ul_a: u64, cg_b: u32, dl_b: u64, ul_b: u64) -> CounterSummary {
    CounterSummary {
        total_packets: 2,
        total_bytes: ul_a + ul_b,
        total_ingress_packets: 2,
        total_ingress_bytes: dl_a + dl_b,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: cg_a,
                packets: 1,
                bytes: ul_a,
                total_bytes: ul_a,
                ingress_packets: 1,
                ingress_bytes: dl_a,
                ingress_total_bytes: dl_a,
            },
            CgroupDelta {
                cgroup_id: cg_b,
                packets: 1,
                bytes: ul_b,
                total_bytes: ul_b,
                ingress_packets: 1,
                ingress_bytes: dl_b,
                ingress_total_bytes: dl_b,
            },
        ],
    }
}

/// The peaks are the running max of the per-frame aggregate
/// deltas — never a sum (the sum is the totals' job), never the
/// last frame's figure (a quiet frame must not drag the peak
/// down), and never reset (the session horizon, like the totals).
#[test]
fn peaks_track_the_running_max_of_frame_deltas() {
    let mut session = SessionState::new();
    session.absorb(&frame(7, 100, 200));
    session.note_frame(&frame(7, 100, 200), None);
    session.absorb(&frame(7, 500, 50));
    session.note_frame(&frame(7, 500, 50), None);
    session.absorb(&frame(7, 10, 5));
    session.note_frame(&frame(7, 10, 5), None);
    assert_eq!(session.peaks(), (500, 200));
    // A quiet frame notes nothing and drags nothing down.
    session.absorb(&CounterSummary::default());
    session.note_frame(&CounterSummary::default(), None);
    assert_eq!(session.peaks(), (500, 200));
}

/// A filtered frame's peaks are the watched set's own: unwatched
/// traffic cannot raise them, matching the filtered grand the
/// same footer paragraph renders — one story, one scope.
#[test]
fn peaks_follow_the_watched_set_not_the_whole_machine() {
    let mut session = SessionState::new();
    let summary = two(7, 100, 20, 8, 1000, 2000);
    session.absorb(&summary);
    session.note_frame(&summary, None);
    assert_eq!(session.peaks(), (1100, 2020), "unfiltered: all cgroups");
    // A fresh session watching only cg 7: cg 8's heavy traffic
    // is invisible to the peaks, exactly as it is to the board.
    let mut watched_session = SessionState::new();
    watched_session.absorb(&summary);
    watched_session.note_frame(&summary, Some(&[7]));
    assert_eq!(
        watched_session.peaks(),
        (100, 20),
        "the watched set's own aggregate, not the machine's"
    );
}

/// A watch list that resolved to nothing is a FILTER, not the
/// absence of one (the board renders empty; the peaks must not
/// silently widen to the whole machine).
#[test]
fn an_unresolved_watch_set_notes_nothing() {
    let mut session = SessionState::new();
    let summary = two(7, 100, 20, 8, 1000, 2000);
    session.absorb(&summary);
    session.note_frame(&summary, Some(&[]));
    assert_eq!(session.peaks(), (0, 0), "an empty watch list notes nothing");
}

/// The bound rides the peak note (the `admits` contract): past
/// MAX_TRACKED_CGROUPS a fresh cgroup's delta cannot fold into
/// the leaderboard — and cannot raise the peak either, so the
/// max line can never claim traffic the grand total cannot
/// account for.
#[test]
fn peaks_respect_the_admission_bound() {
    let mut session = SessionState::new();
    for id in 1..=u32::try_from(MAX_TRACKED_CGROUPS).expect("cap fits u32") {
        session.absorb(&frame(id, 1, 1));
    }
    session.note_frame(&frame(1, 1, 1), None);
    assert_eq!(session.peaks(), (1, 1));
    // A fresh cgroup past the bound: huge delta, no fold, no peak.
    let outsider = frame(u32::MAX, 10_000_000, 10_000_000);
    session.absorb(&outsider);
    session.note_frame(&outsider, None);
    assert_eq!(
        session.peaks(),
        (1, 1),
        "an unadmitted delta cannot raise the peak"
    );
    // A tracked cgroup inside the bound still raises it.
    let insider = frame(1, 500, 0);
    session.absorb(&insider);
    session.note_frame(&insider, None);
    assert_eq!(session.peaks(), (500, 1));
}
