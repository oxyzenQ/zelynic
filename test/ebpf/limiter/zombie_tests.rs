// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the zombie-policy sweep (NIGHT-hunt-43) — kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from zombie.rs. The pure surfaces pinned here:
//! the two-signal decision core (identity hit vetoes; every
//! policed direction must PROVE silence — traffic or an unprovable
//! lens vetoes, with the cgroupfs death proof as the absent lens's
//! one rescue), the ring census's three-state verdict (traffic /
//! silent / unknown from live stamps, present rows, and absent
//! lenses), and the verbose trace wording. The map-walking sweep
//! itself rides the same lanes every reclaim already exercises
//! (`with_u32_map` / `remove_map_entry`), pinned through the
//! family's existing contract trees.

use std::collections::HashSet;

use super::*;
use crate::ebpf::limiter::rate_ring::{RateRingRaw, RateSlotRaw, RATE_RING_SLOTS};

const SEC: u64 = crate::ebpf::limiter::rate_ring::RATE_RING_WINDOW_NS;

/// One ring with a single LIVE stamp — a root that delivered bytes
/// inside the horizon (traffic, the retirement's veto).
fn live_ring(window: u64, bytes: u64) -> RateRingRaw {
    let mut raw = RateRingRaw::default();
    raw.slots[(window % RATE_RING_SLOTS as u64) as usize] = RateSlotRaw { window, bytes };
    raw
}

/// One ring whose stamps have all rotated OUT of the horizon — a
/// root that delivered nothing for the full 8s window set (silence,
/// proven).
fn stale_ring(old_window: u64) -> RateRingRaw {
    let mut raw = RateRingRaw::default();
    for i in 0..RATE_RING_SLOTS {
        raw.slots[i] = RateSlotRaw {
            window: old_window,
            bytes: 4096,
        };
    }
    raw
}

// ── the two-signal decision core ───────────────────────────────────

/// The law itself: a root retires only when no identity entry
/// stands AND every direction it holds a policy in PROVED ring
/// silence. Each leg of the matrix pinned by name.
#[test]
fn zombie_requires_identity_miss_plus_proven_silence() {
    // The live root: identity says alive, silence irrelevant.
    assert!(!zombie(
        true,
        Some(RingProof::Silent),
        Some(RingProof::Silent),
        true
    ));
    // The textbook zombie: no identity, both directions proven silent.
    assert!(zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Silent),
        false
    ));
    // One-leg zombie: only the policed direction constrains.
    assert!(zombie(false, None, Some(RingProof::Silent), false));
    assert!(zombie(false, Some(RingProof::Silent), None, false));
}

/// The belt: kernel-side traffic vetoes retirement even when
/// identity cannot see the root — the alive-but-unresolvable shape
/// (a process that entered a cgroup namespace after its policy was
/// applied) keeps its enforcement. The belt holds even against the
/// cgroupfs death proof: a Traffic leg vetoes unconditionally.
#[test]
fn zombie_traffic_vetoes_even_without_identity() {
    assert!(!zombie(
        false,
        Some(RingProof::Traffic),
        Some(RingProof::Silent),
        false
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Traffic),
        false
    ));
    // Traffic in a direction the root holds no policy in is census
    // residue's own traffic, not the root's life signal — the leg
    // is None and does not constrain.
    assert!(zombie(false, None, Some(RingProof::Silent), false));
    // The belt outranks the death proof too: the readable leg says
    // the root DELIVERS (pre-death residue at worst — the belt
    // cannot know), so the root waits a visit.
    assert!(!zombie(
        false,
        Some(RingProof::Traffic),
        Some(RingProof::Unknown),
        true
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Traffic),
        true
    ));
}

/// Fail-closed for reclamation: an unprovable silence (the absent
/// LENS — a stale pin epoch the reader cannot open) vetoes
/// retirement — silence must be READ, never assumed. The absent
/// ROW is not this pin's subject: the lazy-creation law makes it
/// the never-delivered verdict (Silent), pinned below.
#[test]
fn zombie_unknown_silence_vetoes_retirement() {
    assert!(!zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Silent),
        false
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Unknown),
        false
    ));
    assert!(!zombie(false, Some(RingProof::Unknown), None, false));
    // A root no direction polices is not the sweep's subject at
    // all — the defensive floor (even the death proof cannot
    // reach it — no leg, no retirement).
    assert!(!zombie(false, None, None, true));
    // ... and identity alone cannot reach it either.
    assert!(!zombie(true, None, None, true));
    // The identity belt outranks the death proof: a stale identity
    // entry (the map's 10s TTL) keeps the root until the next
    // visit's refresh — conservative in every direction.
    assert!(!zombie(
        true,
        Some(RingProof::Unknown),
        Some(RingProof::Unknown),
        true
    ));
}

/// The absent lens's one rescue (the owner-approved absent-lens
/// residual): a root the cgroupfs census PROVED gone — its
/// directory absent from a COMPLETE walk — retires without the
/// silence read, because death is the stronger verdict (the
/// kernel destroys a cgroup only after its last process left;
/// nothing can deliver from it ever again). The rescue needs the
/// proof bit: without it (no census, an inconclusive walk, or the
/// directory still standing) the veto holds verbatim.
#[test]
fn zombie_absent_lens_rescue_requires_the_fs_death_proof() {
    // The residual's own shape: both lenses absent, root proven gone.
    assert!(zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Unknown),
        true
    ));
    // Same shape without the proof bit: the veto holds (an
    // inconclusive census, or the directory still standing).
    assert!(!zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Unknown),
        false
    ));
    // Mixed lenses: the readable leg proved silence, the absent
    // leg rides the death proof.
    assert!(zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Silent),
        true
    ));
    assert!(zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Unknown),
        true
    ));
    // One-leg shapes ride the rescue too.
    assert!(zombie(false, None, Some(RingProof::Unknown), true));
    assert!(zombie(false, Some(RingProof::Unknown), None, true));
}

/// The block lane's shape (the design's own find, caught before
/// the stage ever ran it): a rate-0 direction delivers nothing by
/// contract, so its ring row never exists — the absent row reads
/// as the never-delivered SILENCE, and a blocked-then-dead root
/// retires like any other zombie (a no-row veto would have frozen
/// every block-lane ghost and every one-way stream's quiet leg
/// forever).
#[test]
fn zombie_block_lane_never_delivered_still_retires() {
    // Both legs present, neither ring ever existed: the
    // never-delivered zombie retires.
    assert!(zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Silent),
        false
    ));
    // Traffic in ANY policed direction still vetoes — the belt
    // holds for the direction that IS delivering (the ring stamps
    // while packets flow, row or no row in the quiet leg).
    assert!(!zombie(
        false,
        Some(RingProof::Traffic),
        Some(RingProof::Silent),
        false
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Traffic),
        false
    ));
}

// ── the ring census (the three-state verdict) ──────────────────────

/// The census derives the traffic set from live stamps: a row
/// with a stamp inside the horizon is TRAFFIC, a row whose stamps
/// rotated out is SILENT, a root with no row at all is SILENT TOO
/// (the lazy-creation law — the ring exists only after a first
/// delivered packet, so an absent row is the never-delivered
/// verdict, the block lane's own shape), and an absent lens (None
/// census) is UNKNOWN for every root.
#[test]
fn ring_census_separates_traffic_silent_and_unknown() {
    // Mid window 100: windows 93..100 are the horizon.
    let now = 100 * SEC + 500_000_000;
    let rows = vec![
        (7, live_ring(100, 512)), // live stamp in the current window
        (8, live_ring(97, 128)),  // live stamp inside the horizon
        (9, stale_ring(50)),      // every stamp far outside the horizon
    ];
    let census = ring_census(Some(rows.as_slice()), now).expect("present census must resolve");

    let traffic: HashSet<u32> = [7u32, 8].into_iter().collect();
    assert_eq!(census, traffic);

    // The verdicts, one line each.
    assert_eq!(ring_proof(Some(&census), 7), RingProof::Traffic);
    assert_eq!(ring_proof(Some(&census), 9), RingProof::Silent);
    // No row at all: the never-delivered verdict, not an unknown
    // (the block lane retires like any other zombie).
    assert_eq!(ring_proof(Some(&census), 42), RingProof::Silent);
    // The absent lens proves nothing about any root.
    assert_eq!(ring_proof(None, 7), RingProof::Unknown);
    assert_eq!(ring_census(None, now), None);
}

/// The horizon boundary itself: a stamp at the OLDEST window the
/// series still describes is live (the 8s grace is exactly the
/// ring's rotation — a root that died mid-traffic is skipped until
/// its last delivered second rotates out).
#[test]
fn ring_census_oldest_live_window_is_still_traffic() {
    // Mid window 100: window 93 is the oldest in the horizon.
    let now = 100 * SEC + 500_000_000;
    let rows = vec![(7, live_ring(93, 64))];
    let census = ring_census(Some(rows.as_slice()), now).expect("present census must resolve");
    assert_eq!(ring_proof(Some(&census), 7), RingProof::Traffic);
    // One second older has rotated out: silence.
    let rows = vec![(7, live_ring(92, 64))];
    let census = ring_census(Some(rows.as_slice()), now).expect("present census must resolve");
    assert_eq!(ring_proof(Some(&census), 7), RingProof::Silent);
}

// ── the verbose trace wording ──────────────────────────────────────

/// The trace names both axes singular/plural aware and its
/// EVIDENCE honestly — the silence clause for the rows the lens
/// read, the death-proof clause for the rows the census proved,
/// never one wearing the other's name. The diagnostic surface
/// that tells an owner why a visit retired rows it never asked
/// about.
#[test]
fn zombie_sweep_trace_line_singular_and_plural() {
    assert_eq!(
        zombie_sweep_trace_line(1, 2, 0),
        "[limiter] zombie sweep: retired 1 dead-cgroup policy — \
         no identity entry, no ring traffic for the horizon; 2 state entries \
         returned to the census budget"
    );
    assert_eq!(
        zombie_sweep_trace_line(3, 1, 0),
        "[limiter] zombie sweep: retired 3 dead-cgroup policies — \
         no identity entry, no ring traffic for the horizon; 1 state entry \
         returned to the census budget"
    );
}

/// The death-proof clause: a retirement that rode the cgroupfs
/// census names ITS evidence, not the silence the lens never read
/// — all-fs, mixed, singular and plural.
#[test]
fn zombie_sweep_trace_line_names_the_death_proof_evidence() {
    // Every retirement rode the death proof.
    assert_eq!(
        zombie_sweep_trace_line(2, 2, 2),
        "[limiter] zombie sweep: retired 2 dead-cgroup policies — \
         no identity entry, the cgroupfs death proof — the root's directory gone \
         from a complete walk (the absent lens's own lane); 2 state entries \
         returned to the census budget"
    );
    // One of each class: the visit names both kinds of evidence.
    assert_eq!(
        zombie_sweep_trace_line(2, 1, 1),
        "[limiter] zombie sweep: retired 2 dead-cgroup policies — \
         no identity entry, no ring traffic for the horizon and the cgroupfs \
         death proof; 1 state entry returned to the census budget"
    );
    // The singular death-proof retirement.
    assert_eq!(
        zombie_sweep_trace_line(1, 1, 1),
        "[limiter] zombie sweep: retired 1 dead-cgroup policy — \
         no identity entry, the cgroupfs death proof — the root's directory gone \
         from a complete walk (the absent lens's own lane); 1 state entry \
         returned to the census budget"
    );
}
