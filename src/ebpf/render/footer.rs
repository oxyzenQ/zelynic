// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The pinned grip footer (NIGHT-boost-14) — the eagle-eyes frame's
//! bottom block, split from the eagle renderer by the cohesion
//! discipline when the layout work pushed it past the owner's LOC
//! cap. One theme: everything the frame owes the bottom of the
//! terminal.
//!
//! The owner's NIGHT-engrave-4 spec (the dashboard rebuild: the
//! headline, the census, the story, the action, the legend, the
//! stamp — in that exact order), extended by NIGHT-engrave-6 with
//! the session speed pair directly below the story row:
//!
//! ```text
//! ──────────────────────────────────────────  <- purple grid, flush to the rails (engrave-3)
//!   top consumer is curl                     <- grey + brand purple name (engrave-4)
//!   478 packets + 1 cgroups                  <- grey (engrave-4: session horizon)
//!   total usage internet in 1h:20s = 10.2 GB <- grey (engrave-3: `= total`, SI)
//!   peak arrival dl | ul = 20.2 GB/s | 1.0 GB/s <- grey (engrave-6: the session peak)
//!   avg arrival dl | ul = 10.2 GB/s | 1.1 MB/s <- grey (engrave-6: total / uptime)
//!   limit target with 'sudo zelynic s curl 100kb'  <- grey + brand command (engrave-7)
//!
//!   1s realtime - theme netrunner - q quit - t theme  <- grey (engrave-2)
//!
//!   v11.0.0 (a1b2c3d) by <authors>            <- the build stamp (engrave-3;
//!                                                   the authors materialize
//!                                                   from the masked layer,
//!                                                   night-signature-advanced-1)
//! ```
//!
//! The NIGHT-engrave-6 pair (the owner's data-center spec): the MAX
//! line renders the session's peak watched-set rate — the running
//! maximum of the per-frame aggregate deltas, tracked in the session
//! state beside the totals, converted to a rate with the poll
//! interval; the AVG line derives per direction as the session
//! total divided by the session uptime — the same totals and the
//! same clock the total row renders, so the three lines of the
//! paragraph can never disagree. Both render through the honest-zero
//! SI ladder (`0 B/s`, never `BLOCKED` — a policy verdict the
//! observer does not make), both ride the same watched scope as the
//! grand (one paragraph, one story), and both drop with the census
//! family at Minimal — survival outranks statistics.
//!
//! The census composition moved here from the eagle renderer at
//! NIGHT-engrave-4 (the census IS footer data — gathered where it
//! renders): the top consumer is the rank-1 cgroup's busiest process
//! (the NIGHT-hunt-8 autodetect — socket detail first, the label's
//! comm second, the raw label last: the identity-honest name
//! whatever the identity walk knew); the packets line counts the
//! SESSION's packets (the same horizon as the total row's bytes,
//! where the pre-engrave-3 census mixed a per-frame packet count
//! with a session cgroup count on adjacent words of one line); the
//! cgroup count is the board the frame shows — filtered frames tell
//! their own story.
//!
//! NIGHT-engrave-3 lineage (the trim that this pass partially
//! rolls back, at the owner's direction): the census text, the
//! discovery pair, and the second grid retired then are BACK —
//! re-cut to the owner's exact engrave-4 wording (lowercase, the
//! `ss` short alias, the quoted command), and the air survived:
//! one blank above the status line and one above the copyright
//! (the build stamp still reads as its own quiet paragraph).
//!
//! Two contracts live here:
//! - **The tiers**: the compression ladder short terminals walk down
//!   (the blanks first, then the census and the limit suggestion,
//!   then the consumer headline and the roof grid) so the total row,
//!   the status line, and the copyright survive at every height.
//! - **The build**: one pure function assembling the block from the
//!   frame's census data — the MEASURED length of its output is what
//!   pins the footer to the bottom (the rare identities note and an
//!   absent consumer pair ride along and shorten the table's room
//!   without shifting the pin).

use std::time::Duration;

pub(super) use super::footer_grip::build_grip_footer;
use super::{SessionAcc, comm_from_label, label_with_count};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::output::theme;
use crate::output::{ColorCapability, capability, grey_open, reset};

/// Top chrome above the table: the title bar, the NIGHT-boost-14
/// breathing gap below it, the column header, and the purple grid
/// line under the header.
pub(super) const TOP_CHROME: usize = 4;

/// The suggested limit rate for the footer's actionable line
/// (NIGHT-engrave-4, the owner's exact spec:
/// `limit target with 'sudo zelynic s x 100kb'` — the NIGHT-improve-53
/// masterclass short alias; engrave-4's era spelled it 'ss'). A named,
/// documented default — the same discipline as the border
/// gradient's DARK_FACTOR: every dynamic fact on the line (the
/// consumer's name, the packets, the cgroups, the uptime, the
/// grand, the theme, the interval, the version stamp) is derived
/// live; this is the one fixed suggestion VALUE, the owner's
/// engraved default, not a measurement rendered as one.
pub(super) const SUGGESTED_LIMIT: &str = "100kb";

/// Compression tiers for the pinned footer (NIGHT-boost-14;
/// NIGHT-engrave-4 re-cut the ladder for the rebuilt block;
/// NIGHT-engrave-6 grew Full and Compact by the speed pair): short
/// terminals drop the breathing blanks first, then the census and
/// the limit suggestion (with the speed pair), then the consumer
/// headline and the roof grid — the total row, the status line, and
/// the copyright survive in every tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FooterTier {
    /// grid, top consumer, census, total, max, avg, limit, blank,
    /// status, blank, copyright — the owner's engrave-4 spec plus
    /// the engrave-6 speed pair: every line, with the air that
    /// keeps the paragraphs.
    Full,
    /// The blanks drop first — save the owner's gap above the
    /// copyright, which survives to Compact (the engrave-3
    /// paragraph call: the build stamp reads as its own quiet
    /// paragraph as long as there is room for one): grid, top
    /// consumer, census, total, max, avg, limit, status, blank,
    /// copyright.
    Compact,
    /// The census family drops — the speed pair with it (survival
    /// outranks statistics at this height; the total row carries
    /// the one-line story): grid, top consumer, total, status,
    /// copyright.
    Minimal,
    /// The survival floor: total row, status, copyright — the grid
    /// goes too, every row the frame can spare becomes a data row.
    Tiny,
}

impl FooterTier {
    /// Lines the tier occupies at most (the rare identities note and
    /// an absent consumer pair ride unaccounted here — they shorten
    /// the table's room, never the pin: the builder measures the real
    /// block).
    pub(super) fn lines(self) -> usize {
        match self {
            FooterTier::Full => 11,
            FooterTier::Compact => 10,
            FooterTier::Minimal => 5,
            FooterTier::Tiny => 3,
        }
    }
}

/// Pick the richest footer tier the terminal can carry while still
/// showing at least one table row (NIGHT-boost-14): the classic
/// 80x24 gets the full engraved block, a 13-row window drops to
/// Compact, and the survival floor holds from 9 rows down. `extra`
/// accounts for the rare identities-unresolved note that rides the
/// footer.
#[must_use]
pub(super) fn plan_footer_tier(height: usize, extra: usize) -> FooterTier {
    for tier in [
        FooterTier::Full,
        FooterTier::Compact,
        FooterTier::Minimal,
        FooterTier::Tiny,
    ] {
        if height > TOP_CHROME + tier.lines() + extra {
            return tier;
        }
    }
    FooterTier::Tiny
}

/// A full-width purple grid line (NIGHT-boost-14; flush to the rails
/// since NIGHT-engrave-3): the table's border family — under the
/// column header, and roofing the pinned footer block. Same purple
/// as the header text above it, the owner's "same as above"
/// contract. The dashes begin at the content's column 0: the line
/// JOINS the left rail with no gap (the owner's `|---`, never
/// `| ---`) and ends flush against the right one — the frame's
/// horizontals integrate with its border, edge to edge.
///
/// NIGHT-engrave-5: promoted pub(crate) + re-exported from the
/// render root — the status and list-apps tables (the report
/// surfaces outside this module) borrow the exact same grid so
/// every zelynic table answers to one border family.
///
/// NIGHT-engrave-11 (the horizontal masterclass): at the
/// sweep-capable depths the grid paints per column with the SAME
/// chroma method the vertical rails ride ([`super::border::sweep_run`]
/// — the same wave the title bar and the closing floor sweep), so
/// every horizontal line the frame draws speaks the one gradient.
/// The flat rungs keep their exact bytes: Color16's flat brand SGR
/// (sixteen colors cannot ramp within one hue — a flat line beats
/// a noisy one) and Mono's plain glyphs. One trailing reset only:
/// the flank loop re-opens the terminal background after the
/// grid's single trailing reset exactly as it did before the
/// sweep (the wrap row contract, unbroken).
#[must_use]
pub(crate) fn grid_line(width: usize) -> String {
    let mut out = String::new();
    grid_line_into(width, &mut out);
    out
}

/// The into-twin of [`grid_line`] (night-frontier-Z11, the frame
/// render's allocation ladder stage 1): the same bytes into a
/// caller-owned buffer — the frame path pops a pooled row, this
/// writes into it, and the warm buffer takes the grid with zero
/// heap events in steady state. The owned [`grid_line`] stays for
/// the report surfaces' one-shot tables.
pub(crate) fn grid_line_into(width: usize, out: &mut String) {
    out.clear();
    let cap = capability();
    match cap {
        ColorCapability::Mono => out.extend(core::iter::repeat_n('─', width)),
        ColorCapability::Color16 => {
            // NIGHT-engrave-4's flat brand bytes, written in place:
            // the open SGR, the dash run, the reset — the same bytes
            // brand(&"─".repeat(w)) laid down, no owned Strings.
            out.push_str(crate::output::brand_open());
            out.extend(core::iter::repeat_n('─', width));
            out.push_str(crate::output::reset());
        }
        ColorCapability::TrueColor | ColorCapability::Color256 => {
            let theme = theme::active();
            // One anchor derivation for the line (the border wrap's
            // per-frame contract); the legacy rung's None lets
            // rail_rgb derive its own encoded-channel anchor.
            let anchor = (cap == ColorCapability::TrueColor).then(|| {
                crate::output::chroma::scale_lightness(
                    theme.brand_rgb(),
                    super::border::DARK_FACTOR,
                )
            });
            super::sweep::push_sweep_run(out, '─', 0, width, width, theme, anchor, cap);
            out.push_str(super::border::RESET);
        }
    }
}

/// The census data the footer renders (NIGHT-boost-14; slimmed by
/// NIGHT-engrave-3, REBUILT by NIGHT-engrave-4 with the composition
/// moved into the footer module — gathered where it renders; the
/// NIGHT-engrave-6 speed pair's figures joined the census): the
/// consumer headline's name, the session census figures, the grand
/// total with its per-direction legs, the session peaks, the rare
/// identities note's flag, and the uptime horizon the total row
/// annotates.
pub(super) struct FooterCensus {
    /// The compression tier the terminal earned.
    pub tier: FooterTier,
    /// The session leaderboard's grand accumulated total (u128
    /// since NIGHT-lts-5 — the server long-endurance widening: the
    /// session surface sums wrap-coherent deltas past the exabyte).
    pub grand: u128,
    /// The session's accumulated download bytes (NIGHT-engrave-6:
    /// the AVG line's dividend — the same board sum the grand
    /// totals, split by direction).
    pub dl: u128,
    /// The session's accumulated upload bytes — the mirror leg.
    pub ul: u128,
    /// The session's peak per-frame download RATE in B/s
    /// (NIGHT-engrave-6; NIGHT-hunt-38 — the peak is tracked as a
    /// rate at fold time, the delta divided by the span it was
    /// measured over, so the rendered max line never wobbles with
    /// the current frame's span jitter).
    pub peak_dl: u64,
    /// The session's peak per-frame upload rate — the mirror leg.
    pub peak_ul: u64,
    /// The session's accumulated packets (NIGHT-engrave-4: the same
    /// horizon as the bytes — one accumulator in the session state,
    /// both directions).
    pub packets: u64,
    /// How many cgroups the board carries (the frame's own story:
    /// filtered frames count their filtered board).
    pub cgroups: usize,
    /// The rank-1 cgroup's display name (the autodetect's pick);
    /// None only when the board is empty — an idle frame has no
    /// consumer to headline.
    pub top_proc_name: Option<String>,
    /// The rare identities-unresolved note rides along.
    pub identities_unresolved: bool,
    /// The monitor's session uptime (NIGHT-boost-17; folded into the
    /// census row by NIGHT-engrave-1): rendered inside the
    /// `total usage internet in ...` row, in every tier — and the
    /// AVG line's divisor since NIGHT-engrave-6.
    pub uptime: Duration,
}

impl FooterCensus {
    /// Gather the footer's census from the frame's live state
    /// (NIGHT-engrave-4: the composition lives here now, where it
    /// renders — the eagle renderer hands over the board and walks
    /// on). All sums SATURATING (NIGHT-boost-16 lineage): saturated
    /// counters read as their honest ceilings, never panic or wrap.
    /// `peaks` is the session state's running maxima pair
    /// (NIGHT-engrave-6) — RATES at fold since NIGHT-hunt-38, ready
    /// to render with no conversion.
    #[must_use]
    pub(super) fn gather(
        tier: FooterTier,
        board: &[(u32, SessionAcc)],
        identity: &IdentityMap,
        conns: Option<&ConnectionMap>,
        uptime: Duration,
        peaks: (u64, u64),
    ) -> Self {
        // Top consumer (the NIGHT-hunt-8 autodetect, restored):
        // when socket detail is available, name the busiest process
        // INSIDE the champion cgroup — "top consumer is curl"
        // instead of "alacritty". Since NIGHT-dinner-6 "busiest" is
        // byte-ranked (rank::top_consumer over the per-socket join),
        // the walk order standing when the join has no figures.
        // Fallback chain: the label's comm, then the raw label itself
        // (the headline never goes dark over an identity miss).
        let top_proc_name = board.first().map(|(cgroup_id, _)| {
            conns
                .and_then(|cm| super::rank::top_consumer(cm, *cgroup_id))
                .map(|p| p.comm.clone())
                .or_else(|| comm_from_label(&label_with_count(identity, conns, *cgroup_id)))
                .unwrap_or_else(|| label_with_count(identity, conns, *cgroup_id))
        });
        // The census (footer honesty, NIGHT-hunt-15 lineage): every
        // candidate counts, not just the rows the window budget
        // could show — and since NIGHT-engrave-4 every figure on the
        // line rides the SESSION horizon, matching the total row.
        let packets = board
            .iter()
            .map(|(_, a)| a.pkt)
            .fold(0, u64::saturating_add);
        let grand = board
            .iter()
            .map(|(_, a)| a.dl.saturating_add(a.ul))
            .fold(0, u128::saturating_add);
        // The per-direction legs (NIGHT-engrave-6): the same board
        // walk the grand totals, split — the AVG line divides these
        // by the uptime, so the pair and the grand can never
        // disagree (dl + ul saturates to the grand's ceiling — past
        // the quettabyte since NIGHT-lts-5's u128 widening).
        let dl = board
            .iter()
            .map(|(_, a)| a.dl)
            .fold(0, u128::saturating_add);
        let ul = board
            .iter()
            .map(|(_, a)| a.ul)
            .fold(0, u128::saturating_add);
        Self {
            tier,
            grand,
            dl,
            ul,
            peak_dl: peaks.0,
            peak_ul: peaks.1,
            packets,
            cgroups: board.len(),
            top_proc_name,
            identities_unresolved: identity.is_empty(),
            uptime,
        }
    }
}

/// The monitor's status line (NIGHT-engrave-2): the frame's legend,
/// relocated from the title bar to the footer, below the limit
/// suggestion — the owner's exact wording `1s realtime - theme
/// netrunner - q quit - t theme`, grey like the rest of the
/// subordinate block. Rides every tier: it carries the quit key and
/// the active theme's name, and the theme slot makes every `t`
/// press readable — one grey row repaints through the diff engine.
/// night-improve-58 completes the legend with the four arrow keys
/// (the six-key interactive contract: up/down scroll the focused
/// section, left/right switch it) — the whole key map on the row
/// that already owned it, one spelling, the same place the
/// engrave-3 law pinned it (the legend's ONLY home).
/// night-improve-61 (the revert): the section-switch affordance is
/// the `←→` arrow pair again — night-improve-59's `=>` re-spelling
/// landed on the wrong surface (the owner meant the SECTION HEADER
/// gutter marker, not this legend row), so the legend carries its
/// improve-58 spelling back; the `=>` glyph now lives where the
/// owner pointed it, the focused section's header lane.
#[must_use]
pub(super) fn status_line(interval: Duration) -> String {
    let mut out = String::new();
    status_line_into(interval, &mut out);
    out
}

/// The into-twin of [`status_line`] (night-frontier-Z11): the same
/// bytes into a caller-owned buffer — the realtime figure writes
/// via `write!`, the theme name is a `&'static str`, no owned
/// Strings.
pub(super) fn status_line_into(interval: Duration, out: &mut String) {
    use std::fmt::Write as _;
    out.clear();
    out.push_str("  ");
    out.push_str(grey_open());
    if interval.as_secs() >= 1 {
        let _ = write!(out, "{}s realtime", interval.as_secs());
    } else {
        let _ = write!(out, "{:.1}s realtime", interval.as_secs_f64());
    }
    let _ = write!(
        out,
        " - theme {} - q quit - t theme - ↑↓ scroll - ←→ section",
        crate::output::theme::active().name()
    );
    out.push_str(reset());
}

// NIGHT-boost-14: the footer composition pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired across trees
// exactly like the eagle pins. The tier ladder and the rendered tier
// degradation split into their own file at NIGHT-engrave-4 (one file
// per contract, the same discipline that split these pins from the
// eagle pins); the saturation render pin took its own file at
// NIGHT-engrave-6 when the speed-pair pins pushed the composition
// file past the owner's LOC cap.
#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tests.rs"]
mod footer_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tier_tests.rs"]
mod footer_tier_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_safety_tests.rs"]
mod footer_safety_tests;

#[cfg(test)]
// NIGHT-engrave-7: the census-ladder and brand-tier pins took their
// own file when they pushed footer_tests.rs past the owner's LOC cap.
#[path = "../../../test/ebpf/render/footer_census_tests.rs"]
mod footer_census_tests;
