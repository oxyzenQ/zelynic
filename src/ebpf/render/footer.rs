// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The pinned grip footer (NIGHT-boost-14) — the eagle-eyes frame's
//! bottom block, split from the eagle renderer by the cohesion
//! discipline when the layout work pushed it past the owner's LOC
//! cap. One theme: everything the frame owes the bottom of the
//! terminal.
//!
//! The owner's NIGHT-engrave-4 spec (the dashboard rebuild: the
//! headline, the census, the story, the action, the legend, the
//! stamp — in that exact order):
//!
//! ```text
//! ──────────────────────────────────────────  <- purple grid, flush to the rails (engrave-3)
//!   top consumer is curl                     <- grey + brand purple name (engrave-4)
//!   478 packets + 1 cgroups                  <- grey (engrave-4: session horizon)
//!   total usage internet in 1h:20s = 10gb    <- grey (engrave-3: `= total`)
//!   limit target with 'sudo zelynic ss curl 100kb'  <- grey + white command (engrave-4)
//!
//!   1s realtime - theme netrunner - q quit - t theme  <- grey (engrave-2)
//!
//!   v11.0.0 (a1b2c3d) by oxyzenQ              <- the build stamp (engrave-3)
//! ```
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

use super::{comm_from_label, format_uptime, label_with_count, FrameGeometry, SessionAcc};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::output::{brand, grey, signature_footer, suggestion};

/// Top chrome above the table: the title bar, the NIGHT-boost-14
/// breathing gap below it, the column header, and the purple grid
/// line under the header.
pub(super) const TOP_CHROME: usize = 4;

/// The suggested limit rate for the footer's actionable line
/// (NIGHT-engrave-4, the owner's exact spec:
/// `limit target with 'sudo zelynic ss x 100kb'`). A named,
/// documented default — the same discipline as the border
/// gradient's DARK_FACTOR: every dynamic fact on the line (the
/// consumer's name, the packets, the cgroups, the uptime, the
/// grand, the theme, the interval, the version stamp) is derived
/// live; this is the one fixed suggestion VALUE, the owner's
/// engraved default, not a measurement rendered as one.
const SUGGESTED_LIMIT: &str = "100kb";

/// Compression tiers for the pinned footer (NIGHT-boost-14;
/// NIGHT-engrave-4 re-cut the ladder for the rebuilt block): short
/// terminals drop the breathing blanks first, then the census and
/// the limit suggestion, then the consumer headline and the roof
/// grid — the total row, the status line, and the copyright survive
/// in every tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FooterTier {
    /// grid, top consumer, census, total, limit, blank, status,
    /// blank, copyright — the owner's engrave-4 spec: every line,
    /// with the air that keeps the paragraphs.
    Full,
    /// The blanks drop first — save the owner's gap above the
    /// copyright, which survives to Compact (the engrave-3
    /// paragraph call: the build stamp reads as its own quiet
    /// paragraph as long as there is room for one): grid, top
    /// consumer, census, total, limit, status, blank, copyright.
    Compact,
    /// The census and the limit suggestion drop: grid, top
    /// consumer, total, status, copyright.
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
    fn lines(self) -> usize {
        match self {
            FooterTier::Full => 9,
            FooterTier::Compact => 8,
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
#[must_use]
pub(crate) fn grid_line(width: usize) -> String {
    brand(&"─".repeat(width)).to_string()
}

/// The census data the footer renders (NIGHT-boost-14; slimmed by
/// NIGHT-engrave-3, REBUILT by NIGHT-engrave-4 with the composition
/// moved into the footer module — gathered where it renders): the
/// consumer headline's name, the session census figures, the grand
/// total, the rare identities note's flag, and the uptime horizon
/// the total row annotates.
pub(super) struct FooterCensus {
    /// The compression tier the terminal earned.
    pub tier: FooterTier,
    /// The session leaderboard's grand accumulated total.
    pub grand: u64,
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
    /// `total usage internet in ...` row, in every tier.
    pub uptime: Duration,
}

impl FooterCensus {
    /// Gather the footer's census from the frame's live state
    /// (NIGHT-engrave-4: the composition lives here now, where it
    /// renders — the eagle renderer hands over the board and walks
    /// on). All sums SATURATING (NIGHT-boost-16 lineage): saturated
    /// counters read as their honest ceilings, never panic or wrap.
    #[must_use]
    pub(super) fn gather(
        tier: FooterTier,
        board: &[(u32, SessionAcc)],
        identity: &IdentityMap,
        conns: Option<&ConnectionMap>,
        uptime: Duration,
    ) -> Self {
        // Top consumer (the NIGHT-hunt-8 autodetect, restored):
        // when socket detail is available, name the busiest process
        // INSIDE the champion cgroup — "top consumer is curl"
        // instead of "alacritty". Fallback chain: the label's comm,
        // then the raw label itself (an unresolved identity's
        // `cg:7001` is still the honest name of the champion — the
        // headline never goes dark over an identity miss).
        let top_proc_name = board.first().map(|(cgroup_id, _)| {
            conns
                .and_then(|cm| cm.get(*cgroup_id))
                .and_then(|d| d.socket_holders.first())
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
            .fold(0, u64::saturating_add);
        Self {
            tier,
            grand,
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
/// NIGHT-engrave-3, REBUILT by NIGHT-engrave-4 to the owner's exact
/// line order): the consumer headline and the census above the total
/// row, the limit suggestion below it, one blank of air, the status
/// line, the owner's gap, and the copyright — grey text, purple grid
/// and stamp, brand-purple consumer name, suggestion-white command.
/// The MEASURED length of the returned block is what the caller pins
/// to the bottom.
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
    // The owner's NIGHT-engrave-4 headline: WHO is eating the
    // network — the champion's name in brand purple inside the grey
    // block (the engrave-1 contract: the consumer is the one living
    // thing in the footer, the hint to act on). Rides every tier
    // down to Minimal; Tiny has no room for headlines.
    if tier != FooterTier::Tiny {
        if let Some(name) = census.top_proc_name.as_deref() {
            footer.push(format!("  {} {}", grey("top consumer is"), brand(name)));
        }
    }
    // The census (Full/Compact): the session's packets and the
    // board's cgroup count, one flat grey line — the frame's scale.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        footer.push(format!(
            "  {}",
            grey(&format!(
                "{} packets + {} cgroups",
                census.packets, census.cgroups
            ))
        ));
    }
    // The owner's NIGHT-engrave-3 census row: the session's whole
    // story in one flat grey line — the usage horizon and the grand
    // total ALONE (the two per-frame rates retired at the owner's
    // "only total consume bandwidth" call: `= 10gb`, never the old
    // `2kb/s 2kb/s 100mb` tail). Rides every tier.
    footer.push(grey(&format!(
        "  total usage internet in {} = {}",
        format_uptime(census.uptime),
        format_bytes(census.grand)
    )));
    // The actionable line (Full/Compact): the owner's exact
    // engrave-4 wording — `limit target with 'sudo zelynic ss x
    // 100kb'` — the command in suggestion crystal white (the color
    // layer's actionable hint), the `ss` short alias the CLI already
    // carries, the name the headline just introduced.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        if let Some(name) = census.top_proc_name.as_deref() {
            footer.push(format!(
                "  {} {}",
                grey("limit target with"),
                suggestion(&format!("'sudo zelynic ss {name} {SUGGESTED_LIMIT}'"))
            ));
        }
    }
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
// exactly like the eagle pins. The tier ladder and the rendered tier
// degradation split into their own file at NIGHT-engrave-4 (one file
// per contract, the same discipline that split these pins from the
// eagle pins).
#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tests.rs"]
mod footer_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/render/footer_tier_tests.rs"]
mod footer_tier_tests;
