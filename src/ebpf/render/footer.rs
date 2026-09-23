// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The pinned grip footer (NIGHT-boost-14) — the eagle-eyes frame's
//! bottom block, split from the eagle renderer by the cohesion
//! discipline when the layout work pushed it past the owner's LOC
//! cap. One theme: everything the frame owes the bottom of the
//! terminal.
//!
//! The owner's NIGHT-engrave-3 spec (the depth-audit trim: the
//! census text, the discovery pair, and the grid below the total row
//! retired — the rates with them — and every gap re-audited for the
//! leanest block that still reads as paragraphs):
//!
//! ```text
//! ──────────────────────────────────────────  <- purple grid, flush to the left rail (engrave-3)
//!   total usage internet in 1h:20s = 10gb     <- grey (engrave-3: `= total`, the rates retired)
//!
//!   1s realtime - theme netrunner - q quit - t theme  <- grey (engrave-2)
//!
//!   v11.0.0 (a1b2c3d) by oxyzenQ              <- the build stamp (engrave-3: its own paragraph)
//! ```
//!
//! NIGHT-engrave-2: the title-bar legend (the realtime cadence, the
//! active theme's name, the two key hints) relocated to the footer —
//! the owner's exact line, riding EVERY tier like the total row and
//! the copyright: it carries the quit key, and a frame that can teach
//! how to leave is a frame that can always be left. The theme's NAME
//! lives here now, and since engrave-3 this is the legend's ONLY
//! home — the title's top-right hint retired with the census — so
//! cycling with `t` repaints this one grey row through the diff
//! engine.
//!
//! NIGHT-engrave-3: the block lost its middle (the packets+cgroups
//! census, the top-consumer discovery pair, the second grid, and the
//! total row's per-frame rates — the owner's leanest-footer call)
//! and gained air (one blank above the copyright — the build stamp
//! reads as its own quiet paragraph, not the status line's
//! continuation). The compression ladder shrank with it: the blanks
//! drop outside-in first, then the roof grid — the total row, the
//! status line, and the copyright are the survivors, in every tier.
//!
//! Two contracts live here:
//! - **The tiers**: the compression ladder short terminals walk down
//!   (the total-status gap, then the copyright gap, then the grid) so
//!   the total row and the copyright survive at every height.
//! - **The build**: one pure function assembling the block from the
//!   frame's census data — the MEASURED length of its output is what
//!   pins the footer to the bottom (the rare identities note rides
//!   along and shortens the table's room without shifting the pin).

use std::time::Duration;

use super::{format_uptime, FrameGeometry};
use crate::ebpf::limiter::format_bytes;
use crate::output::{brand, grey, signature_footer};

/// Top chrome above the table: the title bar, the NIGHT-boost-14
/// breathing gap below it, the column header, and the purple grid
/// line under the header.
pub(super) const TOP_CHROME: usize = 4;

/// Compression tiers for the pinned footer (NIGHT-boost-14;
/// NIGHT-engrave-3 re-cut the ladder for the trimmed block): short
/// terminals drop the breathing blanks first (the total-status gap,
/// then the owner's copyright gap), then the roof grid — the total
/// row, the status line, and the copyright survive in every tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FooterTier {
    /// grid, total row, blank, status, blank, copyright — the
    /// owner's engrave-3 spec: every gap, the leanest block that
    /// still reads as paragraphs.
    Full,
    /// The total-status gap drops first: grid, total row, status,
    /// blank, copyright.
    Compact,
    /// Blanks gone: grid, total row, status, copyright.
    Minimal,
    /// The survival floor: total row, status, copyright — the grid
    /// goes too, every row the frame can spare becomes a data row.
    Tiny,
}

impl FooterTier {
    /// Lines the tier occupies at most (the rare identities note
    /// rides unaccounted here — it shortens the table's room, never
    /// the pin: the builder measures the real block).
    fn lines(self) -> usize {
        match self {
            FooterTier::Full => 6,
            FooterTier::Compact => 5,
            FooterTier::Minimal => 4,
            FooterTier::Tiny => 3,
        }
    }
}

/// Pick the richest footer tier the terminal can carry while still
/// showing at least one table row (NIGHT-boost-14): the classic
/// 80x24 gets the full grip block, a 14-row window drops to Compact,
/// and the survival floor holds from 9 rows down. `extra` accounts
/// for the rare identities-unresolved note that rides the footer.
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
/// column header, and roofing the pinned TOTAL row. Same purple as
/// the header text above it, the owner's "same as above" contract.
/// The dashes begin at the content's column 0: the line JOINS the
/// left rail with no gap (the owner's `|---`, never `| ---`) and
/// ends flush against the right one — the frame's horizontals
/// integrate with its border, edge to edge.
#[must_use]
pub(super) fn grid_line(width: usize) -> String {
    brand(&"─".repeat(width)).to_string()
}

/// The census data the footer renders (NIGHT-boost-14; slimmed by
/// NIGHT-engrave-3 — the per-frame rates, the packets text, and the
/// discovery inputs retired with their lines): the session grand
/// total the total row carries, the rare identities note's flag, and
/// the uptime horizon the row annotates.
pub(super) struct FooterCensus {
    /// The compression tier the terminal earned.
    pub tier: FooterTier,
    /// The session leaderboard's grand accumulated total.
    pub grand: u64,
    /// The rare identities-unresolved note rides along.
    pub identities_unresolved: bool,
    /// The monitor's session uptime (NIGHT-boost-17; folded into the
    /// census row by NIGHT-engrave-1): rendered inside the
    /// `total usage internet in ...` row, in every tier.
    pub uptime: Duration,
}

/// The monitor's status line (NIGHT-engrave-2): the frame's legend,
/// relocated from the title bar to the footer, below the limit
/// suggestions — the owner's exact wording `1s realtime - theme
/// netrunner - q quit - t theme`, grey like the rest of the
/// subordinate block. Rides every tier: it carries the quit key and
/// the active theme's name, and the theme slot makes every `t`
/// press readable — one grey row repaints through the diff engine.
#[must_use]
pub(super) fn status_line(interval: Duration) -> String {
    let realtime = if interval.as_secs() >= 1 {
        format!("{}s realtime", interval.as_secs())
    } else {
        format!("{:.1}s realtime", interval.as_secs_f64())
    };
    format!(
        "  {}",
        grey(&format!(
            "{realtime} - theme {} - q quit - t theme",
            crate::output::theme::active().name()
        ))
    )
}

/// Assemble the engraved footer (NIGHT-boost-14; re-cut by
/// NIGHT-engrave-3): the total row under its flush roof grid, one
/// blank of air, the status line, the owner's gap, and the purple
/// copyright — grey text, purple grid and stamp. The MEASURED length
/// of the returned block is what the caller pins to the bottom.
#[must_use]
pub(super) fn build_grip_footer(
    census: &FooterCensus,
    geo: FrameGeometry,
    interval: Duration,
) -> Vec<String> {
    let tier = census.tier;
    let mut footer: Vec<String> = Vec::with_capacity(tier.lines());
    // Tiny drops the roof: at survival height every row the frame
    // can spare becomes a data row.
    if tier != FooterTier::Tiny {
        footer.push(grid_line(geo.width));
    }
    // The owner's NIGHT-engrave-3 census row: the session's whole
    // story in one flat grey line — the usage horizon and the grand
    // total ALONE (the two per-frame rates retired at the owner's
    // "only total consume bandwidth" call: `= 10gb`, never the old
    // `2kb/s 2kb/s 100mb` tail).
    footer.push(grey(&format!(
        "  total usage internet in {} = {}",
        format_uptime(census.uptime),
        format_bytes(census.grand)
    )));
    if census.identities_unresolved {
        footer.push(format!(
            "  {}",
            grey("(identities unresolved — labels show raw cgroup IDs)")
        ));
    }
    if tier == FooterTier::Full {
        footer.push(String::new());
    }
    // The status line (NIGHT-engrave-2) rides EVERY tier — and since
    // the engrave-3 title trim it is the legend's only home.
    footer.push(status_line(interval));
    // The owner's NIGHT-engrave-3 gap: one blank line of air above
    // the copyright — the build stamp lands as its own quiet
    // paragraph, never the status line's continuation.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        footer.push(String::new());
    }
    footer.push(format!("  {}", signature_footer()));
    footer
}

// NIGHT-boost-14: the footer composition pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired across trees
// exactly like the eagle pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tests.rs"]
mod footer_tests;
