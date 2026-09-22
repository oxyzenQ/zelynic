// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Session leaderboard state (NIGHT-boost-5) — the monitor's memory.
//!
//! Owner contract: rank by what an app ATE THIS SESSION, not by what
//! it moved in the last second. The owner's example: A downloads at
//! 1 GB/s for a while, accumulates 10 GB, then stops; the board keeps
//! A at rank 1 with its accumulated total. When B later accumulates
//! 100 GB, B takes rank 1 and A slides to rank 2 — a takeover.
//!
//! The per-frame `CounterSummary` only carries cgroups with traffic
//! in the CURRENT interval (the eBPF map read reports deltas), so a
//! one-second quiet frame used to WIPE the app off the table and
//! collapse the monitor to "waiting for traffic…". The session state
//! fixes both: every frame's deltas fold into a per-cgroup
//! accumulator that lives as long as the monitor does, the ranked
//! table renders FROM the accumulator (idle apps stay on the board
//! with em-dash rates), and ranking sorts by the accumulated total —
//! the "total accumulated" function v10 carried and v11 lost,
//! restored as the TOTAL column.
//!
//! The horizon matches the eBPF counters' own (both start at
//! monitor attach), and a failed poll folds nothing in (the
//! observer's prev-stats are only rewritten on success), so a
//! transient map read never drops or double-counts bytes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::ebpf::loader::CounterSummary;

/// How long a fresh rank-1 row blinks after taking the top spot
/// (owner contract: "unique red color for top 1 blinking 3s"). The
/// blink attribute rides the next render after the window closes —
/// at the default 1s cadence that is the first frame past 3s.
pub(crate) const TAKEOVER_BLINK: Duration = Duration::from_secs(3);

/// Per-cgroup traffic accumulated since the monitor started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionAcc {
    /// Accumulated download bytes.
    pub dl: u64,
    /// Accumulated upload bytes.
    pub ul: u64,
}

impl SessionAcc {
    /// Combined accumulated bytes (the ranking key).
    #[must_use]
    fn total(self) -> u64 {
        self.dl + self.ul
    }
}

/// The leaderboard: per-cgroup accumulated traffic plus the rank-1
/// takeover bookkeeping that drives the champion's blink window.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    acc: HashMap<u32, SessionAcc>,
    rank1: Option<u32>,
    rank1_since: Option<Instant>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Fold one poll's deltas into the leaderboard. An empty summary
    /// (a quiet frame, or the one-frame tolerance for a transient
    /// map-read error) folds nothing — the board holds its rows.
    pub(crate) fn absorb(&mut self, summary: &CounterSummary) {
        for c in &summary.cgroups {
            let entry = self.acc.entry(c.cgroup_id).or_default();
            entry.dl = entry.dl.saturating_add(c.ingress_bytes);
            entry.ul = entry.ul.saturating_add(c.bytes);
        }
    }

    /// The ranked leaderboard: accumulated totals, heaviest first,
    /// ties broken by cgroup ID (HashMap iteration order is random —
    /// the board must not reshuffle between frames on a tie).
    #[must_use]
    pub(crate) fn ranked(&self) -> Vec<(u32, SessionAcc)> {
        let mut board: Vec<(u32, SessionAcc)> = self.acc.iter().map(|(&id, &a)| (id, a)).collect();
        board.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then_with(|| a.0.cmp(&b.0)));
        board
    }

    /// Whether any traffic has been seen since the monitor started.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.acc.is_empty()
    }

    /// How many cgroups the leaderboard carries (the filtered meta
    /// line's census denominator).
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.acc.len()
    }

    /// Record the current rank-1 cgroup; returns whether its row
    /// should still blink. A TAKEOVER (a different cgroup reaching
    /// rank 1) restarts the window; the incumbent holding the spot
    /// does not. `now` is a parameter so the window contract is
    /// unit-pinnable without sleeping.
    pub(crate) fn note_rank1(&mut self, cgroup_id: u32, now: Instant) -> bool {
        if self.rank1 != Some(cgroup_id) {
            self.rank1 = Some(cgroup_id);
            self.rank1_since = Some(now);
        }
        match self.rank1_since {
            Some(since) => now.duration_since(since) < TAKEOVER_BLINK,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(session.ranked(), vec![(7, SessionAcc { dl: 100, ul: 200 })]);
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

    /// Blink window: a takeover restarts the 3s window, the incumbent
    /// holding rank 1 does not, and the window closes after 3s.
    #[test]
    fn blink_window_pins_takeover_semantics() {
        let t0 = Instant::now();
        let mut session = SessionState::new();

        // First ever rank 1: blinks.
        assert!(session.note_rank1(1, t0));
        // Same cgroup one frame later: still inside the window.
        assert!(session.note_rank1(1, t0 + Duration::from_secs(1)));
        // Same cgroup past the window: solid red, no blink.
        assert!(!session.note_rank1(1, t0 + Duration::from_secs(4)));
        // Takeover: the window restarts for the new champion.
        assert!(session.note_rank1(2, t0 + Duration::from_secs(5)));
        assert!(session.note_rank1(2, t0 + Duration::from_secs(6)));
        assert!(!session.note_rank1(2, t0 + Duration::from_secs(9)));
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
}
