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
//!
//! NIGHT-engrave-6 (the footer's speed pair): the session state also
//! carries the running PEAKS of the watched set's per-frame deltas —
//! the max figure the footer's `total max dl | ul` line renders as a
//! rate. The peaks ride the same session horizon as the totals (they
//! never reset while the monitor lives), the same admission rule (a
//! delta the leaderboard cannot fold cannot raise the peak — the max
//! line can never claim traffic the grand total cannot account for),
//! and the same watched scope the render filter applies that frame
//! (a filtered frame's peaks are the watched set's own, matching the
//! filtered grand the same footer paragraph renders).

use std::collections::HashMap;

use crate::ebpf::loader::CounterSummary;

/// Per-cgroup traffic accumulated since the monitor started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionAcc {
    /// Accumulated download bytes.
    pub dl: u64,
    /// Accumulated upload bytes.
    pub ul: u64,
    /// Accumulated packets, both directions (NIGHT-engrave-4: the
    /// footer's census line counts the SESSION's packets — the same
    /// horizon as the bytes, one accumulator per frame delta, where
    /// the pre-engrave-3 census mixed a per-frame packet count with
    /// a session cgroup count on adjacent words of one line).
    pub pkt: u64,
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
/// was removed by NIGHT-boost-14 (static colors, no animation), and
/// the session peaks (NIGHT-engrave-6) are plain running maxima.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    acc: HashMap<u32, SessionAcc>,
    /// The session's peak per-frame download delta (bytes in one
    /// poll interval, the watched set's aggregate — NIGHT-engrave-6).
    /// The footer converts it to a rate with the interval at render
    /// time; the peak itself is scope- and horizon-honest by
    /// construction (see `note_frame`).
    peak_dl: u64,
    /// The session's peak per-frame upload delta — the mirror leg.
    peak_ul: u64,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether a delta row may fold into the leaderboard (the
    /// bound mirror the userspace accumulator keeps of the kernel's
    /// own map ceiling, NIGHT-boost-16): an existing entry always
    /// updates, a fresh cgroup past [`MAX_TRACKED_CGROUPS`] cannot
    /// join. One rule, two callers — the byte fold and the peak
    /// note — so the two can never drift apart.
    fn admits(&self, id: u32) -> bool {
        self.acc.len() < MAX_TRACKED_CGROUPS || self.acc.contains_key(&id)
    }

    /// Fold one poll's deltas into the leaderboard. An empty summary
    /// (a quiet frame, or the one-frame tolerance for a transient
    /// map-read error) folds nothing — the board holds its rows. The
    /// fold itself is saturating (an accumulator that reaches
    /// u64::MAX stays there — the SI formatter renders the ceiling
    /// as 18.4 EB, saturation not a wrap), and the entry count is bounded by
    /// [`MAX_TRACKED_CGROUPS`] (NIGHT-boost-16): a cgroup the kernel
    /// never counted cannot rank.
    pub(crate) fn absorb(&mut self, summary: &CounterSummary) {
        for c in &summary.cgroups {
            if !self.admits(c.cgroup_id) {
                continue;
            }
            let entry = self.acc.entry(c.cgroup_id).or_default();
            entry.dl = entry.dl.saturating_add(c.ingress_bytes);
            entry.ul = entry.ul.saturating_add(c.bytes);
            // Both directions' packets fold into one session counter
            // (NIGHT-engrave-4) — saturating like every accumulation
            // surface in this path.
            entry.pkt = entry
                .pkt
                .saturating_add(c.packets)
                .saturating_add(c.ingress_packets);
        }
    }

    /// Note one frame's watched-set aggregate into the running
    /// peaks (NIGHT-engrave-6 — the footer's `total max dl | ul`
    /// line). `watched` is `None` on an unfiltered frame (every
    /// cgroup aggregates — the default view's machine-wide scope)
    /// and `Some(ids)` on a filtered one, the exact set the render
    /// filter applies that frame, so the peaks and the filtered
    /// grand the same paragraph renders tell ONE story. A `Some`
    /// set that resolved to nothing (every name unmatched) notes
    /// nothing — an empty watch list is a filter, not the absence
    /// of one. The admission rule rides along (`admits`): a delta
    /// the leaderboard cannot fold cannot raise the peak. Maxima
    /// need no saturating arithmetic — `max` is already the honest
    /// ceiling of the two operands — and like the totals, the
    /// peaks never reset on a quiet frame: the session horizon.
    pub(crate) fn note_frame(&mut self, summary: &CounterSummary, watched: Option<&[u32]>) {
        let mut dl = 0u64;
        let mut ul = 0u64;
        for c in &summary.cgroups {
            if watched.is_some_and(|ids| !ids.contains(&c.cgroup_id)) {
                continue;
            }
            if !self.admits(c.cgroup_id) {
                continue;
            }
            dl = dl.saturating_add(c.ingress_bytes);
            ul = ul.saturating_add(c.bytes);
        }
        self.peak_dl = self.peak_dl.max(dl);
        self.peak_ul = self.peak_ul.max(ul);
    }

    /// The session's peak per-frame deltas, per direction
    /// (NIGHT-engrave-6): raw interval bytes — the footer converts
    /// to a rate with the poll interval at render time, the same
    /// `rate_bps` discipline the table's rate columns use.
    #[must_use]
    pub(crate) fn peaks(&self) -> (u64, u64) {
        (self.peak_dl, self.peak_ul)
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

    /// How many cgroups the leaderboard carries. Pins-only accessor
    /// since NIGHT-engrave-3 (the census denominator was its last
    /// production caller); the bound pins below still need it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.acc.len()
    }
}

// NIGHT-engrave-6: the session pins live under the single test/
// tree (cosmostrix Pattern C), #[path]-wired exactly like the
// footer, eagle, and loading pins — the speed-pair additions pushed
// the inline module past the owner's LOC cap, and the split keeps
// every render-module pin in the one tree.
#[cfg(test)]
#[path = "../../../test/ebpf/render/session_tests.rs"]
mod session_tests;
