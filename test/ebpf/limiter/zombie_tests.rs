// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the zombie-policy sweep (NIGHT-hunt-43) — kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from zombie.rs. The pure surfaces pinned here:
//! the two-signal decision core (identity hit vetoes; every
//! policed direction must PROVE silence — traffic or an unprovable
//! lens vetoes), the ring census's three-state verdict (traffic /
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
        Some(RingProof::Silent)
    ));
    // The textbook zombie: no identity, both directions proven silent.
    assert!(zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Silent)
    ));
    // One-leg zombie: only the policed direction constrains.
    assert!(zombie(false, None, Some(RingProof::Silent)));
    assert!(zombie(false, Some(RingProof::Silent), None));
}

/// The belt: kernel-side traffic vetoes retirement even when
/// identity cannot see the root — the alive-but-unresolvable shape
/// (a process that entered a cgroup namespace after its policy was
/// applied) keeps its enforcement.
#[test]
fn zombie_traffic_vetoes_even_without_identity() {
    assert!(!zombie(
        false,
        Some(RingProof::Traffic),
        Some(RingProof::Silent)
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Traffic)
    ));
    // Traffic in a direction the root holds no policy in is census
    // residue's own traffic, not the root's life signal — the leg
    // is None and does not constrain.
    assert!(zombie(false, None, Some(RingProof::Silent)));
}

/// Fail-closed for reclamation: an unprovable silence (the absent
/// lens, or a ring row that never existed) vetoes retirement —
/// silence must be PROVEN, never assumed.
#[test]
fn zombie_unknown_silence_vetoes_retirement() {
    assert!(!zombie(
        false,
        Some(RingProof::Unknown),
        Some(RingProof::Silent)
    ));
    assert!(!zombie(
        false,
        Some(RingProof::Silent),
        Some(RingProof::Unknown)
    ));
    assert!(!zombie(false, Some(RingProof::Unknown), None));
    // A root no direction polices is not the sweep's subject at
    // all — the defensive floor.
    assert!(!zombie(false, None, None));
    // ... and identity alone cannot reach it either.
    assert!(!zombie(true, None, None));
}

// ── the ring census (the three-state verdict) ──────────────────────

/// The census derives traffic and presence from live stamps: a row
/// with a stamp inside the horizon is TRAFFIC, a row whose stamps
/// rotated out is SILENT, a root with no row is UNKNOWN, and an
/// absent lens (None census) is UNKNOWN for every root.
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
    let present: HashSet<u32> = [7u32, 8, 9].into_iter().collect();
    assert_eq!(census.0, traffic);
    assert_eq!(census.1, present);

    // The three verdicts, one line each.
    assert_eq!(ring_proof(Some(&census), 7), RingProof::Traffic);
    assert_eq!(ring_proof(Some(&census), 9), RingProof::Silent);
    assert_eq!(ring_proof(Some(&census), 42), RingProof::Unknown);
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

/// The trace names both axes singular/plural aware, the diagnostic
/// surface that tells an owner why a visit retired rows it never
/// asked about.
#[test]
fn zombie_sweep_trace_line_singular_and_plural() {
    assert_eq!(
        zombie_sweep_trace_line(1, 2),
        "[limiter] zombie sweep: retired 1 dead-cgroup policy — \
         no identity entry, no ring traffic for the horizon; 2 state entries \
         returned to the census budget"
    );
    assert_eq!(
        zombie_sweep_trace_line(3, 1),
        "[limiter] zombie sweep: retired 3 dead-cgroup policies — \
         no identity entry, no ring traffic for the horizon; 1 state entry \
         returned to the census budget"
    );
}
