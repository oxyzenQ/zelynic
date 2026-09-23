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
//!
//! NIGHT-boost-16 (safety-security-1, the accumulate-explosion
//! audit): every arithmetic surface in the session path is now
//! SATURATING. A debug build used to panic on `dl + ul` the
//! moment both legs approached u64::MAX (and a release build
//! wrapped to a small number — the leaderboard would crown a
//! wrap-around winner); the growth bound below keeps the
//! leaderboard's memory honest on long-uptime monitors.
//!
//! NIGHT-boost-14: the takeover-BLINK bookkeeping is gone — the
//! owner's eye-strain call. A takeover still re-crowns (the rank
//! order moves), but rank 1 reads by its static champion red, never
//! by animation; this struct is now pure bookkeeping, no timing
//! state at all.

use std::collections::HashMap;

use crate::ebpf::loader::CounterSummary;

/// Per-cgroup traffic accumulated since the monitor started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionAcc {
    /// Accumulated download bytes.
    pub dl: u64,
    /// Accumulated upload bytes.
    pub ul: u64,
}

impl SessionAcc {
    /// Combined accumulated bytes (the ranking key). Saturating
    /// (NIGHT-boost-16): both legs near u64::MAX must read as
    /// "saturated maximum", not panic in debug or wrap in release.
    #[must_use]
    fn total(self) -> u64 {
        self.dl.saturating_add(self.ul)
    }
}

/// Session leaderboard growth bound (NIGHT-boost-16, the LTS
/// endurance half of the audit): the observer's two counter maps
/// hold `COUNTER_MAP_MAX_ENTRIES = 1024` slots each, and the kernel
/// silently stops counting cgroups beyond a full map — so deltas
/// can only ever name at most 1024 distinct cgroups. The userspace
/// accumulator mirrors that bound as defense-in-depth: if a future
/// kernel, map type, or bug ever produced more, the monitor's
/// memory stays capped and the honest shape of the board (the
/// kernel's own ceiling) is preserved instead of leaking one
/// HashMap entry per cgroup churn on a months-long monitor.
pub(crate) const MAX_TRACKED_CGROUPS: usize = 1024;

/// The leaderboard: per-cgroup accumulated traffic. Pure data — the
/// rank-1 takeover bookkeeping that drove the champion's blink window
/// was removed by NIGHT-boost-14 (static colors, no animation).
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    acc: HashMap<u32, SessionAcc>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Fold one poll's deltas into the leaderboard. An empty summary
    /// (a quiet frame, or the one-frame tolerance for a transient
    /// map-read error) folds nothing — the board holds its rows. The
    /// fold itself is saturating (an accumulator that reaches
    /// u64::MAX stays there — the SI formatter renders the ceiling
    /// as 18446744.1 TB, saturation not a wrap), and the entry count is bounded by
    /// [`MAX_TRACKED_CGROUPS`] (NIGHT-boost-16): a cgroup the kernel
    /// never counted cannot rank.
    pub(crate) fn absorb(&mut self, summary: &CounterSummary) {
        for c in &summary.cgroups {
            if self.acc.len() >= MAX_TRACKED_CGROUPS && !self.acc.contains_key(&c.cgroup_id) {
                continue;
            }
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
        };
        assert_eq!(acc.total(), u64::MAX);
        // One leg saturated, one leg free: the total still reads as
        // the ceiling (18.4 EB this session is saturation).
        assert_eq!(
            SessionAcc {
                dl: u64::MAX,
                ul: 1
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
    /// kernel's own 1024-entry counter-map ceiling — a 1025th
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
        assert_eq!(session.len(), MAX_TRACKED_CGROUPS, "no 1025th entry");
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
}
