// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! EAGLE EYES V2 — baseline detection in the live monitor TUI
//! (NIGHT-improve-1a), the purpose the in-kernel time-series ring
//! was built for (charger-core-3a, the owner's approved framing:
//! the ring is the foundation, this lane is what stands on it).
//!
//! The ring keeps the last eight one-second DELIVERED-byte windows
//! per policy root, in the kernel, surviving between userspace
//! polls. This lane reads it every frame, folds each completed
//! window into a per-policy-root running baseline (an integer EMA),
//! and renders the verdict: `learning` until the horizon fills,
//! `steady` with the baseline figure, then `above +N%` / `below -N%`
//! when delivery departs from the baseline long enough to matter —
//! "this policed target is moving 64% more than it usually does",
//! the moment it is true, the same honesty the depth report owns
//! for enforcement state, extended to the traffic's SHAPE.
//!
//! ── The honesty contracts ─────────────────────────────────────────
//!
//! AGGREGATE LAW: the ring is keyed at the RESOLVED POLICY ROOT and
//! books every allowed packet under it, so a verdict describes the
//! POLICY's delivered aggregate — never one leaf's share of it. A
//! `--per-socket` policy's series is the cgroup aggregate (the
//! charger-core-3d rider's law); this lane reads it with the same
//! statement. The focus row joins by EXACT cgroup id only: a cgroup
//! governed by an ANCESTOR's policy gets no row — the aggregate at
//! that ancestor cannot be split back down to the leaf, and an
//! unmarked aggregate would read as the leaf's own rate.
//!
//! THE LENS LIFECYCLE: the lane re-reads the pins every frame (two
//! opens and a schema check — trivial next to the observer poll it
//! rides beside). A read that fails (nothing pinned, maps torn
//! down, a stale pre-v15 object the schema guard refuses) clears
//! the learned state for that direction: enforcement gone means the
//! baseline is gone, and a re-applied policy starts `learning`
//! fresh — a frozen verdict for a dead policy would be a lie. The
//! clear is per direction: one lens failing does not fabricate the
//! other's absence.
//!
//! THE FOLD (pure, integer, rootlessly pinnable): every completed
//! window is judged against the baseline it departs from BEFORE it
//! folds in (judge-then-update — a spike cannot drag the EMA up and
//! then claim it never departed from it); windows are deduped by
//! window NUMBER, so any poll cadence folds each second exactly
//! once, and a gap longer than 8s folds only what the ring kept —
//! the missed seconds are honestly gone (the status JSON's series
//! horizon). A non-live window (idle — the slot never stamped)
//! folds as ZERO: a quiet second is a real sample, and the baseline
//! must learn quiet periods, not skip them.
//!
//! THE VERDICT BANDS (conservative by design, every figure pinned):
//! a window deviates only when its distance from the EMA clears
//! BOTH a ±50% band and a 4 KiB absolute floor (a near-zero
//! baseline never flaps on noise-scale deltas), and a flag renders
//! only after TWO consecutive deviating windows (one burst window
//! is a hiccup, two is a departure). The flag's lifetime is the
//! EMA's convergence horizon (weight 1/8 per window): a sustained
//! step change flags for roughly three windows, then reads as the
//! new steady — the baseline FOLLOWS the traffic, not the past.
//!
//! ── THE PANEL'S RETIRE_DEAD (NIGHT-hunt-34, the render twin) ────
//!
//! A verdict row renders only while its policy root is OBSERVABLY
//! alive: no identity entry AND no window traffic for a 3-frame
//! grace retires the row from the PANEL — display-only, the session
//! board's own retire_dead predicate restated for this lane (a
//! dead cgroup's ghost, the `cg:NNN steady 0 B/s` row the ring
//! read still carries between the death and the next mutation
//! visit's zombie sweep, is the same lie the board's freeze told).
//! The traffic leg is the same belt the board's law rides: an
//! unresolvable-but-delivering root keeps its verdict — identity
//! is one life signal, not the only one. The retirement
//! deliberately does NOT delete the learned state: the ring read
//! re-seeds a dropped key the very next frame (the kernel twin
//! still stands), so a deletion would only reset the ghost's EMA —
//! the hidden row must stay hidden, not churn back as
//! `learning 1/8`.

use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_rate;
use crate::ebpf::limiter::monotonic_ns;
use crate::ebpf::limiter::rate_ring::{
    RATE_RING_SLOTS, RATE_RING_WINDOW_NS, RateRingRaw, read_pinned_rings, ring_series,
};
use crate::ebpf::loader::CounterSummary;
use crate::output::{grey, warn};

// ── The constants (every figure a pinned contract) ─────────────────

/// How many folded windows a direction needs before a baseline is
/// stated (one full ring horizon). Below this the verdict is
/// `learning` — an honest "not enough data yet", never a baseline
/// fabricated from two samples.
pub const BASELINE_MIN_SAMPLES: u32 = 8;

/// The EMA weight as a shift: each window moves the baseline one
/// eighth toward the delivery (the convergence horizon ~3 windows
/// at 2x, ~24 windows from cold — stated in the module header).
const EMA_SHIFT: u32 = 3;

/// A window deviates only beyond this percent of the baseline
/// (either side). 50%: a working policer's steady delivery sits far
/// inside it, so a flag means a real departure, not GSO quantum
/// scatter (the one-quantum transient family the harness pins).
pub const BASELINE_DEV_NUM_PERCENT: u64 = 50;

/// The absolute leg a deviation must ALSO clear: 4 KiB per window.
/// A near-zero baseline (an idle policy waking up) never flags on
/// noise-scale deltas — the ratio leg alone would flag a 1 KiB
/// trickle's every breath.
pub const BASELINE_DEV_FLOOR_BYTES: u64 = 4 * 1024;

/// How many consecutive deviating windows before the flag renders.
/// One burst window is a hiccup; two is a departure. Anti-flap by
/// construction; the flag clears on the first in-band window
/// (flags are rare, clearing is honest — the asymmetry is the
/// conservative side).
pub const BASELINE_SUSTAIN_WINDOWS: u32 = 2;

/// The panel retirement grace (NIGHT-hunt-34): consecutive
/// identity-miss frames a verdict row must survive before it
/// retires from the panel. Three frames mirrors the session
/// board's own RETIRE_GRACE_FRAMES discipline (session.rs, the
/// sibling law one home over): a refresh hiccup that briefly
/// loses a live root's entry lands a frame or two of false
/// deaths, and the grace keeps a live verdict from flapping off.
const BASELINE_RETIRE_GRACE_FRAMES: u32 = 3;
// ── The per-direction learned state (pure) ─────────────────────────

/// One policy root, one direction: the learned baseline. All folds
/// and verdicts are pure functions of this state — rootlessly
/// pinnable, integer-only, no floats anywhere in the lane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BaselineState {
    /// The highest window number already folded (dedupe across any
    /// poll cadence). `None` before the first fold.
    last_folded: Option<u64>,
    /// How many windows have folded (drives `learning` and the
    /// `n/8` progress figure).
    samples: u32,
    /// The running baseline: bytes per one-second window. The
    /// integer EMA (`ema_step`), truncated toward zero like every
    /// integer surface in the estate.
    ema: u64,
    /// Consecutive deviating windows ending at the latest fold.
    streak: u32,
    /// The latest FOLDED window's bytes (the figure a flag's
    /// percent rides; the current still-filling window never
    /// qualifies — it can only grow).
    last_bytes: u64,
}

/// One window deviating from its baseline: BOTH legs must clear
/// (the ±50% band and the 4 KiB floor). Pure; pinned.
fn deviates(bytes: u64, ema: u64) -> bool {
    let delta = bytes.abs_diff(ema);
    delta > BASELINE_DEV_FLOOR_BYTES
        && delta.saturating_mul(100) > ema.saturating_mul(BASELINE_DEV_NUM_PERCENT)
}

/// One EMA step: the baseline moves one eighth toward the delivery.
/// The i64 intermediate is bounded a dozen orders below i64's
/// ceiling (a one-second window cannot move exabytes); truncating
/// division toward zero, deterministic and pinned.
fn ema_step(ema: u64, bytes: u64) -> u64 {
    let e = ema as i64;
    let b = bytes as i64;
    // Truncating division (toward zero), 1/8 via the shift const —
    // deterministic, no float anywhere in the lane.
    let next = e + (b - e) / (1 << EMA_SHIFT);
    next.max(0) as u64
}

impl BaselineState {
    /// Fold one completed window: judge against the PRE-update
    /// baseline (a spike cannot mask itself), then update. The
    /// first sample seeds the EMA (no baseline to judge yet, and
    /// the streak is untouched — the first window never deviates).
    fn fold(&mut self, window: u64, bytes: u64) {
        // Dedupe: a window number already folded (or skipped as
        // pre-boot, which carries no sample) is never folded twice.
        if self.last_folded.is_some_and(|w| window <= w) {
            return;
        }
        if self.samples == 0 {
            self.ema = bytes;
        } else {
            let judged = deviates(bytes, self.ema);
            self.streak = if judged { self.streak + 1 } else { 0 };
            self.ema = ema_step(self.ema, bytes);
        }
        self.samples += 1;
        self.last_bytes = bytes;
        self.last_folded = Some(window);
    }

    /// The verdict this state renders. `None` before the first fold
    /// (no data at all — the caller omits the phrase rather than
    /// fabricating a figure for a lens that never opened).
    fn word(&self) -> Option<BaselineWord> {
        if self.samples == 0 {
            return None;
        }
        if self.samples < BASELINE_MIN_SAMPLES {
            return Some(BaselineWord::Learning {
                samples: self.samples,
            });
        }
        if self.streak >= BASELINE_SUSTAIN_WINDOWS {
            let delta = self.last_bytes.abs_diff(self.ema);
            // checked_div: a percent of zero has no meaning; the
            // phrase drops the figure rather than inventing one.
            let percent = delta.saturating_mul(100).checked_div(self.ema);
            return Some(if self.last_bytes > self.ema {
                BaselineWord::Above {
                    percent,
                    base: self.ema,
                }
            } else {
                BaselineWord::Below {
                    percent,
                    base: self.ema,
                }
            });
        }
        Some(BaselineWord::Steady { bps: self.ema })
    }
}

/// What one direction renders (the pure verdict vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaselineWord {
    /// Filling the horizon: `learning n/8`.
    Learning { samples: u32 },
    /// The baseline is stated: `steady 98.0 KB/s`.
    Steady { bps: u64 },
    /// Departed above: `above +64% (base 12.4 KB/s)`.
    Above { percent: Option<u64>, base: u64 },
    /// Departed below: `below -78% (base 5.4 MB/s)`.
    Below { percent: Option<u64>, base: u64 },
}

// ── The lane (the monitor's memory, SessionState's sibling) ────────

/// The baseline lane: per policy root, per direction, the learned
/// state — plus the re-read that keeps it honest. Owned by the
/// monitor loop (commands/monitor.rs) beside `SessionState`; the
/// renderers take it by reference and never do I/O through it.
#[derive(Debug, Default)]
pub(crate) struct BaselineLane {
    /// Download-direction states, keyed by policy-root cgroup id.
    dl: HashMap<u32, BaselineState>,
    /// Upload-direction states, the mirror leg.
    ul: HashMap<u32, BaselineState>,
    /// Consecutive identity-miss frames per policy root
    /// (NIGHT-hunt-34, the panel's retire_dead): an entry exists
    /// only while its row is a retirement candidate, so the map is
    /// bounded by the lane's own key set and empties on a
    /// fully-live panel (a live frame clears the row's streak).
    retire_streaks: HashMap<u32, u32>,
}

impl BaselineLane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Re-read the pins and fold. Called once per frame by the
    /// monitor loop, before the render. A direction whose read
    /// fails is CLEARED (the lens lifecycle contract in the module
    /// header); a key vanished from a successful read drops its
    /// state the same frame (reappearing starts learning fresh).
    pub(crate) fn refresh(&mut self) {
        let now = monotonic_ns();
        let reads = read_pinned_rings();
        Self::fold_direction(&mut self.dl, reads.dl.as_deref(), now);
        Self::fold_direction(&mut self.ul, reads.ul.as_deref(), now);
    }

    /// One direction's read: fold every ring the read carries, then
    /// retain exactly the keys the read named. `None` clears the
    /// direction whole.
    fn fold_direction(
        states: &mut HashMap<u32, BaselineState>,
        rows: Option<&[(u32, RateRingRaw)]>,
        now: u64,
    ) {
        let rows = match rows {
            Some(rows) => rows,
            None => {
                states.clear();
                return;
            }
        };
        for (key, raw) in rows {
            let series = ring_series(raw, now);
            // w is the CURRENT window; index i is w-(SLOTS-1-i),
            // oldest first — only COMPLETED windows fold (the last
            // slot is still filling; it can only grow).
            let w = now / RATE_RING_WINDOW_NS;
            let state = states.entry(*key).or_default();
            for i in 0..RATE_RING_SLOTS - 1 {
                let offset = (RATE_RING_SLOTS - 1 - i) as u64;
                let win = match w.checked_sub(offset) {
                    Some(v) => v,
                    // Pre-boot window: no sample exists (the series
                    // renders it absent the same way) — never a
                    // fabricated zero the EMA would learn from.
                    None => continue,
                };
                // A non-live window folds as ZERO (a quiet second
                // is a real sample); a live one folds its bytes.
                // The dedupe inside fold() keeps every window once.
                let bytes = series.bytes[i];
                state.fold(win, bytes);
            }
        }
        let live: std::collections::HashSet<u32> = rows.iter().map(|(k, _)| *k).collect();
        states.retain(|k, _| live.contains(k));
    }

    /// Retire the panel's dead rows (NIGHT-hunt-34, the render
    /// twin of the session board's own law — the module header
    /// owns the full contract). A row is dead ONLY by the board
    /// filter's own predicate — no identity entry AND no window
    /// traffic (that filter's exact two signals, the identity
    /// lookup first so the happy path builds no active set) — and
    /// only a [`BASELINE_RETIRE_GRACE_FRAMES`]-frame streak of
    /// such frames hides it; a live frame (identity, or traffic)
    /// clears the streak. The signal guard: an EMPTY identity map
    /// is a failed walk, never proof of universal death — the
    /// pass stands down entirely.
    pub(crate) fn retire_dead(&mut self, identity: &IdentityMap, summary: &CounterSummary) {
        if identity.is_empty() {
            return;
        }
        let mut keys: Vec<u32> = self.dl.keys().chain(self.ul.keys()).copied().collect();
        keys.sort_unstable();
        keys.dedup();
        // The lazy active set (the board filter's own discipline:
        // the vast majority of roots are live and identity resolves
        // them — the set builds only on the first miss).
        let mut active = None;
        for id in keys {
            if identity.get(id).is_some()
                || active
                    .get_or_insert_with(|| super::focus::window_active(summary))
                    .contains(&id)
            {
                self.retire_streaks.remove(&id);
            } else {
                *self.retire_streaks.entry(id).or_insert(0) += 1;
            }
        }
        // The streak map rides the lane's own retain law: a root
        // whose ring row left the read (the zombie sweep collected
        // it, or the pin epoch changed) takes its streak with it.
        self.retire_streaks
            .retain(|k, _| self.dl.contains_key(k) || self.ul.contains_key(k));
    }

    /// cfg(test) pin seam (NIGHT-engrave-10): one read carrying one
    /// live window — a lane whose panel renders `learning 7/8` (the
    /// read folds the whole completed horizon: six quiet windows as
    /// real zero samples plus the live one, the fold's own law),
    /// built through the lane itself for the eagle composition pins.
    #[cfg(test)]
    pub(crate) fn seed_for_pins(&mut self, key: u32, bytes: u64) {
        let mut raw = RateRingRaw::default();
        let slot = &mut raw.slots[94 % RATE_RING_SLOTS];
        slot.window = 94;
        slot.bytes = bytes;
        // Read mid-window after 94 — the fold fixtures' own at().
        let now = (94 + 1) * RATE_RING_WINDOW_NS + 500_000_000;
        Self::fold_direction(&mut self.dl, Some(&[(key, raw)]), now);
    }

    /// The focus pair for one cgroup: (dl, ul) words, exact-id
    /// match only (the AGGREGATE LAW in the module header). `None`
    /// when neither direction holds state for the id.
    pub(crate) fn focus_pair(
        &self,
        cgroup_id: u32,
    ) -> Option<(Option<BaselineWord>, Option<BaselineWord>)> {
        let dl = self.dl.get(&cgroup_id).and_then(BaselineState::word);
        let ul = self.ul.get(&cgroup_id).and_then(BaselineState::word);
        (dl.is_some() || ul.is_some()).then_some((dl, ul))
    }

    /// The panel rows for the ranked view: every policy root the
    /// lane holds, busiest first (dl+ul EMA desc, ties by cgroup id
    /// — the board must not reshuffle between frames on a tie).
    /// Retired roots (NIGHT-hunt-34) render no row: a root whose
    /// identity streak reached the grace is hidden from the panel
    /// while the lane keeps folding its ring (the display filter's
    /// own law — the kernel-side row is the zombie sweep's
    /// subject, not this lane's to delete).
    pub(crate) fn panel_rows(&self) -> Vec<(u32, Option<BaselineWord>, Option<BaselineWord>)> {
        let mut keys: Vec<u32> = self.dl.keys().chain(self.ul.keys()).copied().collect();
        keys.sort_unstable();
        keys.dedup();
        keys.retain(|k| {
            self.retire_streaks
                .get(k)
                .is_none_or(|streak| *streak < BASELINE_RETIRE_GRACE_FRAMES)
        });
        let mut rows: Vec<(u32, Option<BaselineWord>, Option<BaselineWord>)> = keys
            .into_iter()
            .map(|k| {
                (
                    k,
                    self.dl.get(&k).and_then(BaselineState::word),
                    self.ul.get(&k).and_then(BaselineState::word),
                )
            })
            .collect();
        let weight = |dl: &Option<BaselineWord>, ul: &Option<BaselineWord>| {
            let dl_bps = match dl {
                Some(BaselineWord::Steady { bps })
                | Some(BaselineWord::Above { base: bps, .. })
                | Some(BaselineWord::Below { base: bps, .. }) => *bps,
                _ => 0,
            };
            let ul_bps = match ul {
                Some(BaselineWord::Steady { bps })
                | Some(BaselineWord::Above { base: bps, .. })
                | Some(BaselineWord::Below { base: bps, .. }) => *bps,
                _ => 0,
            };
            dl_bps.saturating_add(ul_bps)
        };
        rows.sort_by(|a, b| {
            weight(&b.1, &b.2)
                .cmp(&weight(&a.1, &a.2))
                .then_with(|| a.0.cmp(&b.0))
        });
        rows
    }
}

// ── The phrase vocabulary (pure) ────────────────────────────────────

/// One direction's rendered figure. The zero special case is
/// deliberate: the limiter's formatter renders 0 as BLOCKED (a zero
/// limit's verdict wording), but this lane's zero is LEARNED QUIET
/// — idle since the lens opened is steady at zero, not blocked; the
/// two contexts disagree about zero on purpose.
fn rate_figure(bps: u64) -> String {
    if bps == 0 {
        "0 B/s".to_string()
    } else {
        format_rate(bps)
    }
}

/// One direction's rendered phrase. Learning grey, steady plain,
/// departures warn — the flag color the estate's warn family owns.
fn phrase(word: Option<BaselineWord>) -> String {
    match word {
        None => String::new(),
        Some(BaselineWord::Learning { samples }) => {
            grey(&format!("learning {}/{}", samples, BASELINE_MIN_SAMPLES))
        }
        Some(BaselineWord::Steady { bps }) => format!("steady {}", rate_figure(bps)),
        Some(BaselineWord::Above { percent, base }) => {
            let figure = match percent {
                Some(p) => format!("+{p}% "),
                None => String::new(),
            };
            warn(&format!("above {figure}(base {})", rate_figure(base)))
        }
        Some(BaselineWord::Below { percent, base }) => {
            let figure = match percent {
                Some(p) => format!("-{p}% "),
                None => String::new(),
            };
            warn(&format!("below {figure}(base {})", rate_figure(base)))
        }
    }
}

/// Both directions on one line, ` · ` between when both render.
pub(super) fn pair_phrase(dl: Option<BaselineWord>, ul: Option<BaselineWord>) -> String {
    let dl_phrase = phrase(dl);
    let ul_phrase = phrase(ul);
    match (dl.is_none(), ul.is_none()) {
        (true, true) => String::new(),
        (false, true) => dl_phrase,
        (true, false) => ul_phrase,
        (false, false) => format!("{dl_phrase} · {ul_phrase}"),
    }
}

// ── The renderers (no I/O — the render tree's contract) ────────────

/// The focus view's baseline row: `  baseline  dl … · ul …`, joined
/// to the key/value block after `lifetime` (the same column the
/// block's keys align on). Rendered from the LANE, not the frame's
/// summary — a quiet frame still renders the ring's last windows.
pub(crate) fn render_focus_row(lines: &mut Vec<String>, lane: &BaselineLane, cgroup_id: u32) {
    if let Some((dl, ul)) = lane.focus_pair(cgroup_id) {
        let body = pair_phrase(dl, ul);
        if !body.is_empty() {
            lines.push(format!("  baseline  {body}"));
        }
    }
}

// The lane's pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the session and eagle pins.
// The split the 500-LOC owner cap demanded (the docker_tests
// lineage): the fold/state pins in one tree, the render shapes in
// the sibling beside it.
#[cfg(test)]
#[path = "../../../test/ebpf/render/baseline_tests.rs"]
mod baseline_tests;

// NIGHT-hunt-34: the retirement pins took their own file when the
// panel's retire_dead landed (the session tree's own split
// discipline — one file per contract, session_retire_tests the
// precedent one home over).
#[cfg(test)]
#[path = "../../../test/ebpf/render/baseline_retire_tests.rs"]
mod baseline_retire_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/baseline_render_tests.rs"]
mod baseline_render_tests;
