// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The grip footer's builder (night-frontier-Z11) — split from
//! footer.rs by the NIGHT-improve-44 LOC law (a pure move, gates
//! green in between): the engraved bottom block's assembly, one
//! pooled row per line, the grey and brand brackets carrying their
//! static opens and resets.

use super::FrameGeometry;
use super::footer::{FooterCensus, FooterTier, SUGGESTED_LIMIT, grid_line_into, status_line_into};
use super::{pooled_line, rate_bps_wide};
use crate::ebpf::limiter::format_count_into;
use crate::output::{brand_open, grey_open, reset, signature_footer};
use std::time::Duration;

/// The into-twin of [`session_rate`] (night-frontier-Z11): the same
/// bytes into a caller-owned buffer, `format_bytes_into` carrying
/// the SI ladder.
fn push_session_rate(out: &mut String, bps: u64) {
    crate::ebpf::limiter::format_bytes_into(bps, out);
    out.push_str("/s");
}

/// Assemble the engraved footer (NIGHT-boost-14; re-cut by
/// NIGHT-engrave-3, REBUILT by NIGHT-engrave-4 to the owner's exact
/// line order; the NIGHT-engrave-6 speed pair seated directly below
/// the total row): the consumer headline and the census above the
/// total row, the max/avg pair under it, the limit suggestion, one
/// blank of air, the status line, the owner's gap, and the copyright
/// — grey text, purple grid and stamp, brand-purple consumer name,
/// suggestion-white command. The MEASURED length of the returned
/// block is what the caller pins to the bottom.
///
/// `interval` is the CONFIGURED cadence (the status line's "1s
/// realtime" identity). The MEASURED poll-to-poll span never
/// reaches this builder anymore: since NIGHT-hunt-38 the MAX
/// figures arrive as RATES at fold time (each peak divided by the
/// span IT was measured over, in the session state's `note_frame`
/// — the honest denominator the table's rate columns divide by,
/// not the nominal interval the beat scheduler only approximates),
/// so the builder renders the stored peaks directly and a later
/// frame's span jitter can never restate a historical peak.
///
/// `top_name` is the rank-1 consumer's display name (night-frontier-
/// Z13 stage 4c: resolved at the render call site into a warm buffer,
/// reaching the builder as a &str — the census's owned Option<String>
/// per frame is gone). The two headline reads (the consumer line and
/// the actionable command) read this param.
#[must_use]
pub(super) fn build_grip_footer(
    census: &FooterCensus,
    geo: FrameGeometry,
    interval: Duration,
    deep: bool,
    top_name: Option<&str>,
) -> Vec<String> {
    let mut footer: Vec<String> = Vec::with_capacity(census.tier.lines());
    build_grip_footer_into(&mut footer, census, geo, interval, deep, top_name);
    footer
}

/// The into-twin of [`build_grip_footer`] (night-frontier-Z13 stage
/// 4c): the same bytes into the caller's capacity-warm buffer — the
/// eagle frame's retained footer block consumes this form, so the
/// fresh Vec per frame is gone. `footer` is cleared first: the
/// builder owns the whole block.
pub(super) fn build_grip_footer_into(
    footer: &mut Vec<String>,
    census: &FooterCensus,
    geo: FrameGeometry,
    interval: Duration,
    deep: bool,
    top_name: Option<&str>,
) {
    footer.clear();
    let tier = census.tier;
    // Tiny drops the roof: at survival height every row the frame
    // can spare becomes a data row.
    if tier != FooterTier::Tiny {
        // night-frontier-Z11: the grid writes into a pooled row (the
        // grid_line_into twin).
        let mut grid = pooled_line();
        grid_line_into(geo.width, &mut grid);
        footer.push(grid);
    }
    // The owner's NIGHT-engrave-4 headline: WHO is eating the
    // network — the champion's name in brand purple inside the grey
    // block (the engrave-1 contract: the consumer is the one living
    // thing in the footer, the hint to act on). Rides every tier
    // down to Minimal; Tiny has no room for headlines.
    if tier != FooterTier::Tiny
        && let Some(name) = top_name
    {
        // night-frontier-Z11: the headline writes into a pooled row
        // - the grey lead and the brand name append around the
        // resets, no owned Strings.
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str("top consumer is");
        line.push_str(reset());
        line.push(' ');
        line.push_str(brand_open());
        line.push_str(name);
        line.push_str(reset());
        footer.push(line);
    }
    // The census (Full/Compact): the session's packets and the
    // board's cgroup count, one flat grey line — the frame's scale.
    // Both counts ride the SI compact ladder (NIGHT-engrave-7, the
    // counter-explosion hardening): the fresh-start "24 packets"
    // stays "24 packets", the eight-hour "2244843 packets" reads
    // "2.2M packets" — no raw u64 ever explodes the line again.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        // night-frontier-Z11: the census row writes into a pooled
        // row, the counts via format_count_into.
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        format_count_into(census.packets, &mut line);
        line.push_str(" packets + ");
        format_count_into(census.cgroups as u64, &mut line);
        line.push_str(" cgroups");
        line.push_str(reset());
        footer.push(line);
    }
    // The owner's NIGHT-engrave-3 census row: the session's whole
    // story in one flat grey line — the usage horizon and the grand
    // total ALONE (the two per-frame rates retired at the owner's
    // "only total consume bandwidth" call: `= 10gb`, never the old
    // `2kb/s 2kb/s 100mb` tail). Rides every tier.
    // night-frontier-Z11: the total row writes into a pooled row,
    // the uptime and the grand total via their into-twins.
    let mut line = pooled_line();
    line.push_str("  ");
    line.push_str(grey_open());
    line.push_str("total usage internet in ");
    super::format_uptime_into(census.uptime, &mut line);
    line.push_str(" = ");
    crate::ebpf::limiter::format_bytes_wide_into(census.grand, &mut line);
    line.push_str(reset());
    footer.push(line);
    // The deep legend (night-netrunner-4, --deep, the netrunner-3
    // design's section 4.3): when the figure family is live and the
    // footer holds the Full tier, one grey line joins the census
    // family, above the speed pair — the three laws the deep figures
    // ride, spelled once (the figures on screen never outrun the
    // space to explain them). Compact/Minimal/Tiny drop it: the tier
    // ladder's own degradation.
    if deep && tier == FooterTier::Full {
        // night-frontier-Z11: pooled row, the legend's own String
        // appended (deep-only, the ranked frame never runs it).
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str(&super::deep::footer_legend_line());
        line.push_str(reset());
        footer.push(line);
    }
    // The NIGHT-engrave-6 speed pair (Full/Compact — the census
    // family; Minimal is survival height, where the total row alone
    // carries the story): the owner's data-center lines, directly
    // below the title row they extend. PEAK is the session's peak
    // watched-set rate — since NIGHT-hunt-38 the session state
    // tracks the peak as a RATE at fold time (the delta over the
    // span IT was measured on), so the line renders the stored
    // figure directly and never wobbles with the current frame's
    // span jitter. AVG derives per direction as the session leg
    // divided by the session uptime — the same legs the grand
    // totals and the same clock the total row renders, so the three
    // lines of the paragraph can never disagree (a sub-second
    // uptime renders honest zeroes via rate_bps_wide's
    // zero-interval guard — the loading frame and the first live
    // frame agree byte-for-byte, the boost-25 morph contract).
    // night-private-research-7: both lines speak the ARRIVAL label —
    // the pair counts what REACHED the interface (pre-verdict,
    // retransmits included), so a peak above the policy is the
    // demand the limit absorbed, not a bypass; the dropped ledger
    // (status) is where the difference went. The owner's transcript
    // read a `max dl = 1.1 MB/s` against a 100 KB/s policy and
    // asked why — the label now answers before the question forms.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        // night-frontier-Z11: the speed pair writes into pooled
        // rows via the session-rate twin.
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str("peak arrival dl | ul = ");
        push_session_rate(&mut line, census.peak_dl);
        line.push_str(" | ");
        push_session_rate(&mut line, census.peak_ul);
        line.push_str(reset());
        footer.push(line);
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str("avg arrival dl | ul = ");
        push_session_rate(&mut line, rate_bps_wide(census.dl, census.uptime));
        line.push_str(" | ");
        push_session_rate(&mut line, rate_bps_wide(census.ul, census.uptime));
        line.push_str(reset());
        footer.push(line);
    }
    // The actionable line (Full/Compact): the owner's exact
    // engrave-4 wording — `limit target with 'sudo zelynic s x
    // 100kb'` — the command riding the ACTIVE theme's brand color
    // (NIGHT-engrave-7, the owner's call: purple under netrunner,
    // each theme's own accent under itself) beside the grey lead,
    // the `s` short alias the CLI already carries, the name the
    // headline just introduced. The command joins the consumer's
    // name in the brand tier — the frame's two living accents, the
    // thing to read and the thing to act on.
    if matches!(tier, FooterTier::Full | FooterTier::Compact)
        && let Some(name) = top_name
    {
        // night-frontier-Z11: the actionable line writes into a
        // pooled row, the command string appended piecewise.
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str("limit target with");
        line.push_str(reset());
        line.push(' ');
        line.push_str(brand_open());
        line.push_str("'sudo zelynic s ");
        line.push_str(name);
        line.push(' ');
        line.push_str(SUGGESTED_LIMIT);
        line.push('\'');
        line.push_str(reset());
        footer.push(line);
    }
    if census.identities_unresolved {
        // night-frontier-Z11: pooled row, the note's own bytes.
        let mut line = pooled_line();
        line.push_str("  ");
        line.push_str(grey_open());
        line.push_str("(identities unresolved — labels show raw cgroup IDs)");
        line.push_str(reset());
        footer.push(line);
    }
    if tier == FooterTier::Full {
        // night-frontier-Z13 stage 4c: the gap row rides the pool — a
        // fresh String::new() forced the border wrap to grow it from
        // zero capacity every frame.
        footer.push(pooled_line());
    }
    // The status line (NIGHT-engrave-2) rides EVERY tier — and since
    // the engrave-3 title trim it is the legend's only home.
    // night-frontier-Z11: the legend row writes into a pooled row
    // (the status_line_into twin).
    let mut line = pooled_line();
    status_line_into(interval, &mut line);
    footer.push(line);
    // The owner's NIGHT-engrave-3 gap: one blank line of air above
    // the copyright — the build stamp lands as its own quiet
    // paragraph, never the status line's continuation.
    if matches!(tier, FooterTier::Full | FooterTier::Compact) {
        // night-frontier-Z13 stage 4c: the gap row rides the pool (the
        // zero-capacity growth the wrap paid per frame is gone).
        footer.push(pooled_line());
    }
    // night-frontier-Z11: pooled row, the engraving's own String
    // appended (its internals are the output layer's identity seat,
    // their own later stage).
    let mut line = pooled_line();
    line.push_str("  ");
    line.push_str(signature_footer());
    footer.push(line);
}
