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
//! NIGHT-lts-5 (the server long-endurance ask: "harden and robust
//! for future when reach limit of zelynic like possible 1 zettabyte
//! ZB even quettabyte QB"): the byte legs widen to u128. The
//! kernel's per-cgroup counters are u64 by BPF-map contract and
//! WRAP at 18.4 EB (ebpf/src/stats.rs — and the userspace deltas
//! went wrap-coherent with them the same night, loader.rs), so a
//! 1-Tbps-backed cgroup feeding the monitor for ~4.7 years hands
//! the accumulator wrapping deltas forever; the u128 accumulator
//! folds them into a session total whose honest ceiling is now
//! u128's — 3.4e38 bytes, ~340 million QB, ~8.7e21 years of
//! 1-Tbps traffic — past quettabyte, the SI prefix list's end.
//! The packet leg stays u64 (2^64 packets is ~389,000 years at
//! 1.5 Mpps line rate — the byte legs were the only reachable
//! ceiling). The renders run through format_bytes_wide, the u128
//! twin of the SI ladder, so the board and the footer census can
//! SAY "1.0 ZB" — and mean it.
//!
//! NIGHT-boost-14: the takeover-BLINK bookkeeping is gone — the
//! owner's eye-strain call. A takeover still re-crowns (the rank
//! order moves), but rank 1 reads by its static champion red, never
//! by animation; this struct is now pure bookkeeping, no timing
//! state at all.
//!
//! NIGHT-engrave-6 (the footer's speed pair): the session state also
//! carries the running PEAK RATES of the watched set's per-frame
//! aggregates — the max figure the footer's `peak arrival dl | ul` line
//! renders. Since NIGHT-hunt-38 the peaks are tracked as RATES at
//! fold time (each frame's aggregate divided by the span that frame
//! was measured over): the pre-hunt-38 form stored the peak BYTES
//! and converted with the CURRENT frame's span at render time, so a
//! span jitter restated the historical peak — the max line wobbled
//! on frames that set no new peak. The peaks ride the same session
//! horizon as the totals (they never reset while the monitor
//! lives), the same admission rule (a delta the leaderboard cannot
//! fold cannot raise the peak — the max line can never claim
//! traffic the grand total cannot account for), and the same
//! watched scope the render filter applies that frame (a filtered
//! frame's peaks are the watched set's own, matching the filtered
//! grand the same footer paragraph renders).
//!
//! NIGHT-mitigate-1 (the data-explosion endurance audit's finding
//! B): the leaderboard's dead rows now RETIRE. The old freeze —
//! the first 4096 distinct cgroups own the board forever — was the
//! one 10-year ceiling the monitor carried: a churning host
//! (per-job systemd scopes, containers) produces 100k+ distinct
//! cgroup lifetimes per year, and past the cap every fresh cgroup
//! was silently refused a row. The retirement mirrors the frame's
//! own display filter exactly (a row retires only when
//! `board_rows` would hide it that frame anyway — no identity
//! entry and no window traffic), behind a 3-frame grace and a
//! signal guard (an empty identity map is a failed walk, not
//! proof of universal death). Display-neutral, grand-neutral, and
//! memory-neutral by construction; the only thing it changes is
//! that a fresh cgroup finds a slot again. See
//! docs/audits/NIGHT_MITIGATE_1_DATA_EXPLOSION_ENDURANCE_AUDIT_2026-10-07.md
//! section 7 for the full arithmetic and the residual that stays
//! (the kernel LRU's own best-effort under 4096+ live-with-traffic
//! cgroups, USAGE limitation 11).

use std::collections::HashMap;
use std::time::Duration;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::loader::CounterSummary;

use super::rate_bps;

/// Per-cgroup traffic accumulated since the monitor started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionAcc {
    /// Accumulated download bytes (u128 since NIGHT-lts-5 — the
    /// session surface folds the kernel counters' wrap-coherent
    /// deltas into a total that can honestly pass the exabyte;
    /// saturating add per the boost-16 discipline, though u128
    /// saturation needs ~8.7e21 years of 1-Tbps traffic).
    pub dl: u128,
    /// Accumulated upload bytes — the mirror leg, u128 for the
    /// same reason.
    pub ul: u128,
    /// Accumulated packets, both directions (NIGHT-engrave-4: the
    /// footer's census line counts the SESSION's packets — the same
    /// horizon as the bytes, one accumulator per frame delta, where
    /// the pre-engrave-3 census mixed a per-frame packet count with
    /// a session cgroup count on adjacent words of one line). Stays
    /// u64 (NIGHT-lts-5): 2^64 packets is ~389,000 years at 1.5 Mpps
    /// — the byte legs were the only reachable ceiling.
    pub pkt: u64,
}

impl SessionAcc {
    /// Combined accumulated bytes (the ranking key). Saturating
    /// (NIGHT-boost-16): the legs near the ceiling must read as
    /// "saturated maximum", never panic in debug. The u128 widening
    /// (NIGHT-lts-5) moves that ceiling past the quettabyte —
    /// unreachable by ~22 orders of magnitude.
    #[must_use]
    fn total(self) -> u128 {
        self.dl.saturating_add(self.ul)
    }
}

/// Session leaderboard growth bound (NIGHT-boost-16, the LTS
/// endurance half of the audit). At introduction it mirrored the
/// observer maps' HASH ceiling — the kernel silently stopped
/// counting beyond a full map, so deltas named at most 4096
/// distinct cgroups and the accumulator kept the board honest to
/// exactly that. The E1 rider (2026-09-28) moved the counter maps
/// to the LRU lane, and the ceiling this bound mirrored is gone:
/// the kernel now counts any LIVE cgroup (evicting idle entries),
/// so a long churning session can name more than 4096 distinct
/// cgroups. The posture question the freeze left open ("mirror
/// the LRU and retire the least-recently-active row, or keep the
/// freeze") was decided by NIGHT-mitigate-1, more conservatively
/// than the note's own candidate: DEAD rows retire
/// ([`SessionState::retire_dead`] — the board filter's own rule,
/// a grace window, and a signal guard), live rows NEVER do, and
/// the bound now mirrors the kernel LRU lane's semantics instead
/// of freezing on the first 4096 ever seen. The residual is
/// limitation 11's own: more than 4096 concurrently-live-with-
/// traffic cgroups still overflow the kernel maps.
pub(crate) const MAX_TRACKED_CGROUPS: usize = 4096;

/// The retirement grace (NIGHT-mitigate-1): consecutive dead
/// frames a row must survive before its slot frees. Three frames
/// rides the identity walk's own refresh order at the 1s cadence —
/// a refresh hiccup that briefly loses a live row's identity
/// entry lands a frame or two of false deaths, and the grace (with
/// the signal guard below) keeps a live row's session history
/// from flapping away. A row is only "dead" by the board filter's
/// own rule (no identity entry AND no window traffic), so a truly
/// dead cgroup's streak is just the confirmation window.
const RETIRE_GRACE_FRAMES: u32 = 3;

/// The leaderboard: per-cgroup accumulated traffic. Pure data — the
/// rank-1 takeover bookkeeping that drove the champion's blink window
/// was removed by NIGHT-boost-14 (static colors, no animation), the
/// session peaks (NIGHT-engrave-6) are plain running maxima, and the
/// retirement streaks (NIGHT-mitigate-1) are per-row dead-frame
/// counters bounded by the accumulator's own cap.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    acc: HashMap<u32, SessionAcc>,
    /// The session's peak per-frame download RATE in B/s (the
    /// watched set's aggregate, NIGHT-engrave-6; NIGHT-hunt-38 —
    /// tracked as a RATE at fold time, the delta divided by the
    /// span it was measured over, so the footer's max line never
    /// wobbles with the CURRENT frame's span jitter: a peak set
    /// on a slow frame renders at its own slow-frame rate forever,
    /// exactly as loud as it was, and a later calm frame cannot
    /// restate it). Scope- and horizon-honest by construction
    /// (see `note_frame`).
    peak_dl: u64,
    /// The session's peak per-frame upload rate — the mirror leg,
    /// the same span-at-fold discipline.
    peak_ul: u64,
    /// Consecutive dead frames per tracked row (NIGHT-mitigate-1):
    /// an entry exists only while its row is a retirement candidate,
    /// so the map is bounded by the accumulator's own cap and
    /// empties on a fully-live board (a live frame clears the row's
    /// streak — the flap guard the grace window rides on).
    retire_streaks: HashMap<u32, u32>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether a delta row may fold into the leaderboard (the
    /// userspace memory bound, NIGHT-boost-16 — a HASH-ceiling
    /// mirror at introduction, standing on its own since the E1
    /// rider's LRU swap): an existing entry always
    /// updates, a fresh cgroup past [`MAX_TRACKED_CGROUPS`] cannot
    /// join. One rule, two callers — the byte fold and the peak
    /// note — so the two can never drift apart.
    fn admits(&self, id: u32) -> bool {
        self.acc.len() < MAX_TRACKED_CGROUPS || self.acc.contains_key(&id)
    }

    /// Fold one poll's deltas into the leaderboard. An empty summary
    /// (a quiet frame, or the one-frame tolerance for a transient
    /// map-read error) folds nothing — the board holds its rows. The
    /// fold itself is saturating (the byte legs' u128 saturation
    /// ceiling is past the quettabyte — NIGHT-lts-5; the packet leg's
    /// u64 ceiling is ~389,000 years of line rate), and the entry
    /// count is bounded by [`MAX_TRACKED_CGROUPS`] (NIGHT-boost-16;
    /// a userspace bound — a fresh cgroup past the cap carries no
    /// row while the board is full of LIVE rows, since
    /// [`retire_dead`](SessionState::retire_dead) keeps the dead
    /// from holding slots — the dense-session bound limitation 11
    /// documents).
    pub(crate) fn absorb(&mut self, summary: &CounterSummary) {
        for c in &summary.cgroups {
            if !self.admits(c.cgroup_id) {
                continue;
            }
            let entry = self.acc.entry(c.cgroup_id).or_default();
            // The u128 folds (NIGHT-lts-5): the deltas arrive as u64
            // (the kernel counters' width) and widen at the fold —
            // wrap-coherent deltas summed into a total that can
            // pass the exabyte the kernel counters cannot.
            entry.dl = entry.dl.saturating_add(u128::from(c.ingress_bytes));
            entry.ul = entry.ul.saturating_add(u128::from(c.bytes));
            // Both directions' packets fold into one session counter
            // (NIGHT-engrave-4) — saturating like every accumulation
            // surface in this path.
            entry.pkt = entry
                .pkt
                .saturating_add(c.packets)
                .saturating_add(c.ingress_packets);
        }
    }

    /// Retire the board's dead rows so fresh cgroups can board
    /// (NIGHT-mitigate-1, the mitigate-1 audit's finding B — the
    /// freeze lifter). A row is dead ONLY by the frame's own
    /// display rule — `board_rows` would hide it this frame (no
    /// identity entry AND no window traffic; the liveness test is
    /// that filter's exact predicate, the identity lookup first so
    /// the happy path builds no active set) — and only a
    /// [`RETIRE_GRACE_FRAMES`]-frame streak of such frames retires
    /// it, so a transient identity miss flaps nothing. A live
    /// frame (identity, or traffic) clears the streak; a retired
    /// row's slot frees for the next fresh cgroup `admits` names.
    ///
    /// The gate: the pass engages only when the board sits AT its
    /// cap — the one state where a freed slot changes anything.
    /// Below the cap the display filter already hides the dead,
    /// the bound has room for every fresh cgroup, and the memory
    /// the dead hold is bounded by the cap itself, so the walk
    /// would be pure cost (the frame bench measured the ungated
    /// pass at 7.6% of the render path's throughput on its 24-row
    /// board — the gate restores the pre-change fps exactly, and
    /// at the cap the walk's ~4096-row linear pass rides a 1s-plus
    /// poll cadence where it is noise). The gate closing clears
    /// the streaks — an era's counting never carries into the next
    /// one, the same fresh start a live frame gives a row.
    ///
    /// The signal guard: an EMPTY identity map is a failed walk
    /// (procfs unreadable, the refresh family's clear-then-rebuild
    /// mid-failure), never proof that every row died — retirement
    /// stands down entirely, the same direction the footer's
    /// identities-unresolved note takes. The board's display story
    /// is untouched by construction (a retired row was invisible
    /// that frame already), the footer grand is untouched (it sums
    /// the post-filter board), and the memory bound is untouched
    /// (the streak map rides under the accumulator's own cap).
    pub(crate) fn retire_dead(&mut self, identity: &IdentityMap, summary: &CounterSummary) {
        // The gate: below the cap retirement changes nothing the
        // display or the bound can see — the walk would be pure
        // per-frame cost, so it waits for the state that needs it.
        if self.acc.len() < MAX_TRACKED_CGROUPS {
            self.retire_streaks.clear();
            return;
        }
        if identity.is_empty() {
            return;
        }
        // The lazy active set (the board filter's own discipline:
        // the vast majority of rows are live and identity resolves
        // them — the set builds only on the first miss).
        let mut active = None;
        let mut retired: Vec<u32> = Vec::new();
        for &id in self.acc.keys() {
            if identity.get(id).is_some() {
                self.retire_streaks.remove(&id);
                continue;
            }
            if active
                .get_or_insert_with(|| super::focus::window_active(summary))
                .contains(&id)
            {
                self.retire_streaks.remove(&id);
                continue;
            }
            let streak = self.retire_streaks.entry(id).or_insert(0);
            *streak += 1;
            if *streak >= RETIRE_GRACE_FRAMES {
                retired.push(id);
            }
        }
        for id in retired {
            self.acc.remove(&id);
            self.retire_streaks.remove(&id);
        }
    }

    /// Note one frame's watched-set aggregate into the running
    /// peak RATES (NIGHT-engrave-6 — the footer's `peak arrival dl | ul`
    /// line; NIGHT-hunt-38 — the peak tracks the RATE, the delta
    /// divided by the span IT was measured over). `watched` is
    /// `None` on an unfiltered frame (every cgroup aggregates — the
    /// default view's machine-wide scope) and `Some(ids)` on a
    /// filtered one, the exact set the render filter applies that
    /// frame, so the peaks and the filtered grand the same paragraph
    /// renders tell ONE story. A `Some` set that resolved to nothing
    /// (every name unmatched) notes nothing — an empty watch list is
    /// a filter, not the absence of one. The admission rule rides
    /// along (`admits`): a delta the leaderboard cannot fold cannot
    /// raise the peak. A non-positive span notes nothing (the
    /// loading frame's guard — `rate_bps` owns the zero-interval
    /// law) and maxima need no saturating arithmetic — `max` is
    /// already the honest ceiling of the two operands. Like the
    /// totals, the peaks never reset on a quiet frame: the session
    /// horizon.
    pub(crate) fn note_frame(
        &mut self,
        summary: &CounterSummary,
        span: Duration,
        watched: Option<&[u32]>,
    ) {
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
        self.peak_dl = self.peak_dl.max(rate_bps(dl, span));
        self.peak_ul = self.peak_ul.max(rate_bps(ul, span));
    }

    /// The session's peak per-frame watched-set rates in B/s, per
    /// direction (NIGHT-engrave-6; rates at fold since NIGHT-hunt-38):
    /// the footer renders them through the same SI speed ladder the
    /// table's rate columns use, no conversion at render time.
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

// NIGHT-mitigate-1: the retirement pins took their own file when
// they pushed session_tests.rs past the owner's LOC cap — one file
// per contract, the footer tree's own split discipline.
#[cfg(test)]
#[path = "../../../test/ebpf/render/session_retire_tests.rs"]
mod session_retire_tests;
