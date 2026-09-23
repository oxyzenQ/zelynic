// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The pinned grip footer (NIGHT-boost-14) — the eagle-eyes frame's
//! bottom block, split from the eagle renderer by the cohesion
//! discipline when the layout work pushed it past the owner's LOC
//! cap. One theme: everything the frame owes the bottom of the
//! terminal.
//!
//! The owner's exact spec:
//!
//! ```text
//! ──────────────────────────────────────────  <- purple grid
//!       TOTAL          dl     ul     total    <- grey
//! ──────────────────────────────────────────  <- purple grid
//!
//! 12 packets + 1 cgroups                       <- grey
//! ────────────────────────                     <- grey grip
//! Top consumer: example                       <- grey + green
//! ──────────────────                           <- grey grip
//! Limit it: sudo zelynic strict-single example 100kb  <- grey
//! ```
//!
//! NIGHT-boost-17 (improve-27): one more line below the whole block
//! — the monitor's session uptime (`uptime 1m:10s`, grey, formatted
//! by the render root's `format_uptime`). It rides EVERY tier: long
//! endurance is survival information, not decoration, so the
//! compression ladder budgets for it everywhere (each tier's line
//! count grew by one).
//!
//! Three contracts live here:
//! - **The tiers**: the compression ladder short terminals walk down
//!   (blanks drop, then the grips, then the discovery hints) so the
//!   census and the copyright survive at every height.
//! - **The grips**: underlines exactly as wide as the text they hold —
//!   the census grip and the consumer grip frame their own lines,
//!   never the full frame.
//! - **The build**: one pure function assembling the block from the
//!   frame's census data — the MEASURED length of its output is what
//!   pins the footer to the bottom (an absent discovery hint
//!   shortens the block without shifting the pin).

use std::time::Duration;

use super::{format_rate_or_dash, format_uptime, rate_bps, EagleColumns, FrameGeometry};
use crate::ebpf::limiter::format_bytes;
use crate::output::{brand, grey, ok, signature_footer};

/// Top chrome above the table: the title bar, the NIGHT-boost-14
/// breathing gap below it, the column header, and the purple grid
/// line under the header.
pub(super) const TOP_CHROME: usize = 4;

/// Compression tiers for the pinned footer (NIGHT-boost-14; the
/// NIGHT-boost-17 uptime line rides every tier, so each count grew
/// by one). The owner's grip layout in full is 12 lines; short
/// terminals drop the breathing blanks first, then the grips, then
/// the discovery hints and the second TOTAL grid — the census, the
/// copyright, and the uptime are the last three survivors, in every
/// tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FooterTier {
    /// sep, TOTAL, sep, blank, packets, grip, top, grip, limit,
    /// blank, copyright, uptime — the owner's exact spec plus the
    /// boost-17 uptime line.
    Full,
    /// Blanks and grips gone: sep, TOTAL, sep, packets, top, limit,
    /// copyright, uptime.
    Compact,
    /// Discovery hints gone too: sep, TOTAL, sep, packets,
    /// copyright, uptime.
    Minimal,
    /// The survival floor: sep, TOTAL, packets, copyright, uptime.
    Tiny,
}

impl FooterTier {
    /// Lines the tier occupies at most (the top-consumer block is
    /// optional — an absent hint makes the actual footer SHORTER,
    /// which only adds middle padding; the pin stays exact).
    fn lines(self) -> usize {
        match self {
            FooterTier::Full => 12,
            FooterTier::Compact => 8,
            FooterTier::Minimal => 6,
            FooterTier::Tiny => 5,
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

/// A full-width purple grid line (NIGHT-boost-14): the table's border
/// family — under the column header, and framing the pinned TOTAL
/// row. Same purple as the header text above it, the owner's "same
/// as above" contract.
#[must_use]
pub(super) fn grid_line(width: usize) -> String {
    format!("  {}", brand(&"─".repeat(width.saturating_sub(2))))
}

/// A footer grip (NIGHT-boost-14): a grey underline exactly as wide
/// as the text it grips — the owner's spec underlines each footer
/// block with its own width, not the full frame.
#[must_use]
pub(super) fn grip(text: &str) -> String {
    format!("  {}", grey(&"─".repeat(text.chars().count())))
}

/// The census data the grip footer renders (NIGHT-boost-14): the
/// aggregate figures (footer honesty, NIGHT-hunt-15 — every candidate
/// counts, not just the rows the window budget could show), the
/// census line's own text, and the discovery pair's inputs.
pub(super) struct FooterCensus {
    /// The compression tier the terminal earned.
    pub tier: FooterTier,
    /// This frame's summed download delta (all candidates).
    pub dl_sum: u64,
    /// This frame's summed upload delta (all candidates).
    pub ul_sum: u64,
    /// The session leaderboard's grand accumulated total.
    pub grand: u64,
    /// The ready-made census line ("N packets + M cgroups").
    pub census_text: String,
    /// The rare identities-unresolved note rides along.
    pub identities_unresolved: bool,
    /// The rank-1 cgroup's busiest process (the discovery hint).
    pub top_proc_name: Option<String>,
    /// Whether the frame is unfiltered (hints render only there).
    pub unfiltered: bool,
    /// The monitor's session uptime (NIGHT-boost-17) — rendered as
    /// the line BELOW the whole footer block, in every tier.
    pub uptime: Duration,
}

/// Assemble the grip footer (NIGHT-boost-14): TOTAL framed by purple
/// grid lines, the census under its own-width grip, the top consumer
/// under its own, the limit suggestion, and the purple copyright —
/// grey text, purple grids, green consumer name. The MEASURED length
/// of the returned block is what the caller pins to the bottom.
#[must_use]
pub(super) fn build_grip_footer(
    census: &FooterCensus,
    cols: &EagleColumns,
    geo: FrameGeometry,
    interval: Duration,
) -> Vec<String> {
    let tier = census.tier;
    let mut footer: Vec<String> = Vec::with_capacity(tier.lines());
    footer.push(grid_line(geo.width));
    // Column-aligned with the data rows, grey (NIGHT-boost-14 footer
    // tier), blank rank cell.
    if cols.show_total {
        footer.push(grey(&format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$} {:>w3$}",
            "",
            "TOTAL",
            format_rate_or_dash(rate_bps(census.dl_sum, interval)),
            format_rate_or_dash(rate_bps(census.ul_sum, interval)),
            format_bytes(census.grand),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w,
            w3 = cols.dl_w
        )));
    } else {
        footer.push(grey(&format!(
            "  {:>2}  {:<w0$} {:>w1$} {:>w2$}",
            "",
            "TOTAL",
            format_rate_or_dash(rate_bps(census.dl_sum, interval)),
            format_rate_or_dash(rate_bps(census.ul_sum, interval)),
            w0 = cols.label_w,
            w1 = cols.dl_w,
            w2 = cols.ul_w
        )));
    }
    if tier != FooterTier::Tiny {
        footer.push(grid_line(geo.width));
    }
    if tier == FooterTier::Full {
        footer.push(String::new());
    }
    footer.push(format!("  {}", grey(&census.census_text)));
    if tier == FooterTier::Full {
        footer.push(grip(&census.census_text));
    }
    if census.identities_unresolved {
        footer.push(format!(
            "  {}",
            grey("(identities unresolved — labels show raw cgroup IDs)")
        ));
    }
    // The discovery hint (unfiltered frames only): the rank-1
    // cgroup's busiest process plus the exact strict-single command
    // to cap it. The consumer's NAME renders green (the owner's
    // spec) inside the grey footer — the one living thing in the
    // block, and the hint to act on.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        if let Some(proc_name) = census.top_proc_name.clone().filter(|_| census.unfiltered) {
            let top_text = format!("Top consumer: {proc_name}");
            footer.push(format!("  {} {}", grey("Top consumer:"), ok(&proc_name)));
            if tier == FooterTier::Full {
                footer.push(grip(&top_text));
            }
            footer.push(format!(
                "  {}",
                grey(&format!(
                    "Limit it: sudo zelynic strict-single {proc_name} 100kb"
                ))
            ));
        }
    }
    if tier == FooterTier::Full {
        footer.push(String::new());
    }
    footer.push(format!("  {}", signature_footer()));
    // The uptime line (NIGHT-boost-17, improve-27): BELOW the footer,
    // the frame's final row, grey like the rest of the subordinate
    // block. Long-endurance reading: how long this leaderboard's
    // horizon spans. Rides every tier — see the module doc.
    footer.push(format!(
        "  {}",
        grey(&format!("uptime {}", format_uptime(census.uptime)))
    ));
    footer
}

// NIGHT-boost-14: the footer composition pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired across trees
// exactly like the eagle pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tests.rs"]
mod footer_tests;
