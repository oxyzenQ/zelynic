// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The status surface's pure line renderers (improve-40, schema
//! v24: split from display.rs when the guarantee bracket's
//! subordinate line pushed the parent past the 500-LOC owner cap —
//! the policy_lines discipline, one family over): the rate cells,
//! the row and header lines, the watchdog/census prose, the
//! duration compactor, and the two subordinate lifetime lines
//! (the --during window's and the guarantee bracket's). Everything
//! here is PURE text shaping — the data family (DisplayData,
//! collect_display_data) and the print assembly stay home.

use super::display::{DisplayData, STATUS_HEADERS};
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::types::{BracketPair, PolicyWindowRaw, WINDOW_KIND_SPAN};
use crate::ebpf::limiter::{format_rate_exact, format_wall_utc, wall_minus_mono, window_state};
use crate::output::{
    brand, colored_display_width, fit_colored_to_width, grey, ok, pad_colored_to_width, warn,
};

/// One rate cell's text: the rate, plus " /socket" when the policy
/// enforces per socket (charger-core-3b — the marker that keeps the
/// table honest about WHICH budget the number names).
///
/// NIGHT-hunt-Z7: the cell renders through the EXACT rate twin — the
/// status table is the surface owners check a configured limit
/// against, and a `100.51kb` policy must read "100.51 KB/s", never
/// the one-decimal rounding that hid the last 10 B/s (the allowed /
/// dropped cells beside it stay on the one-decimal twin: those are
/// MEASURED counters, the approximate display they always carried).
pub(crate) fn cell_rate(bps: u64, per_socket: bool) -> String {
    if per_socket {
        format!("{} /socket", format_rate_exact(bps))
    } else {
        format_rate_exact(bps)
    }
}

/// One status row's display cells (pure, improve-13: extracted for
/// the same reason `status_json` was — the human table's contract is
/// now unit-pinnable without capturing stdout).
///
/// ALLOWED and DROPPED carry BYTES only, one metric per cell: the
/// render engine's own flagship rule (src/ebpf/render.rs module
/// docs) bans per-cell packing ("89 (1.2 MB)") — the status table
/// was the last surface still doing it. Packet counts stay in
/// `--print-json` where automation reads them; the human eye scans
/// magnitudes, and bytes carry the enforcement verdict.
pub(crate) fn status_cells(
    d: &DisplayData,
    identity: &IdentityMap,
) -> (String, String, String, String, String) {
    // night-frontier hardening: a policy row whose cgroup carries no
    // live member is MARKED, never printed as a bare cg: id that
    // reads as a healthy limit (the ghost-row shape the live session
    // caught). One helper, both surfaces — the JSON document rides
    // the same status_label.
    let label = identity.status_label(d.cgroup_id);
    // charger-core-3b: a per-socket policy's rate cell names its own
    // unit — "500.0 KB/s /socket" — because the number IS per socket
    // (the cgroup total is rate x concurrent sockets); an unmarked
    // rate would read as the cgroup cap the policy does not carry.
    let dl = d
        .dl_bps
        .map(|r| cell_rate(r, d.dl_per_socket))
        .unwrap_or_else(|| "—".to_string());
    let ul = d
        .ul_bps
        .map(|r| cell_rate(r, d.ul_per_socket))
        .unwrap_or_else(|| "—".to_string());
    (
        label,
        dl,
        ul,
        format_bytes(d.bytes_allowed),
        format_bytes(d.bytes_dropped),
    )
}

/// The status table's header row (pure, NIGHT-engrave-5): lowercase
/// titles in regular purple — the exact contract the eagle-eyes
/// header row carries (`top process` / `download` / `upload` /
/// `total`, brand-wrapped) — so the two report tables read as one
/// family. Extracted so the wording and alignment are unit-pinnable
/// without capturing stdout.
pub(crate) fn status_header_line(col_widths: &[usize; 5]) -> String {
    brand(&format!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        STATUS_HEADERS[0],
        STATUS_HEADERS[1],
        STATUS_HEADERS[2],
        STATUS_HEADERS[3],
        STATUS_HEADERS[4],
        w0 = col_widths[0],
        w1 = col_widths[1],
        w2 = col_widths[2],
        w3 = col_widths[3],
        w4 = col_widths[4]
    ))
}

/// The v26 CE ledger's subordinate line (night-spark-4, schema
/// v26): the ECN-first lane's own truth under the row that carries
/// it — "CE Marked: N packets (M) — a drop prevented (ECN
/// delivered it)", the volume book_rescue's correction delivered
/// CE-marked. night-ux-1 (the owner's 200kb-on-Brave session): the
/// byte figure rides the same SI ladder every other surface speaks
/// (format_bytes — "127.6 KB", never raw "127581 bytes").
/// night-docs-1: the closing clause names the LANE and the drop
/// story in one breath — the count is a drop PREVENTED, and ECN is
/// the lane that delivered it — so a reader walking the row
/// connects the grey sub-line to the `dropped` column beside it
/// (a marked byte never books there; the old "delivered instead of
/// dropped" shape named the exception but not the lane). Rendered
/// ONLY when the row has actually marked something (the
/// dormant-watchdog precedent: zeros are noise pretending to be
/// information), the window family's grey indent.
pub(crate) fn ce_marked_line(d: &DisplayData) -> Option<String> {
    (d.ce_marked_packets > 0).then(|| {
        grey(&format!(
            "    CE Marked: {} packets ({}) — a drop prevented (ECN delivered it)",
            d.ce_marked_packets,
            format_bytes(d.ce_marked_bytes)
        ))
    })
}

/// The Layer 3 pacing subordinate line (night-spark-5, schema
/// v27): the egress pacing lane's commanded rate under the row
/// that carries it — "Upload Pacing: 100 KB/s (kernel-native)",
/// the rate the sock_ops program pins onto the row's upload
/// sockets via SO_MAX_PACING_RATE (the stack's own pacer, no tc
/// qdisc anywhere). Rendered ONLY when a live upload policy
/// stands (the dormant-watchdog precedent: an unenforcing lane
/// printing state noise is absence pretending to be information),
/// the window family's grey indent; a per-socket upload policy
/// keeps the rate cell's own "/socket" honesty marker (the number
/// IS per socket).
pub(crate) fn pacing_line(d: &DisplayData) -> Option<String> {
    d.ul_bps.filter(|rate| *rate > 0).map(|rate| {
        let shaped = if d.ul_per_socket {
            format!("{} /socket", format_rate_exact(rate))
        } else {
            format_rate_exact(rate)
        };
        grey(&format!("    Upload Pacing: {shaped} (kernel-native)"))
    })
}

/// The quota telemetry's subordinate line (night-spark-7, the quota
/// saver's Layer 4 math — the line night-spark-6's PREP reserved):
/// the three lanes' saved-byte total with its layer split —
/// "Quota Saved: X (counterfactual estimate — ...)", format_bytes'
/// own human shape on every number. night-ux-1 (the owner's
/// 200kb-on-Brave session): the total's line now NAMES what the
/// number IS — the counterfactual booking (the bytes the rate
/// limit prevented), not a wire measurement — and points at the
/// A/B harness that measures the wire truth, because a reader who
/// sees "Quota Saved" must be one line away from the physics, not
/// one whitepaper chapter (docs/QUOTA_SAVER_PHYSICS.md owns the
/// record). The per-lane split stays on its subordinate line, now
/// prefixed with the short form of the same honesty ("est.;") so
/// the breakdown cannot read as a wire ledger either. The total
/// leads (the one number an owner reads at a glance); the split
/// rides underneath so the row can never disagree with itself —
/// the layers name the physics that produced the saving (EDT: the
/// retired pacing word, zero since night-quota-audit retired the
/// kernel booking, schema v29; ECN: the delivered marks, the sole
/// live booking; RECWN: the retired window counterfactual, zero
/// since night-recvn-audit retired the userspace estimate, schema
/// v30 — every live booking is ECN's one-for-one). Rendered ONLY
/// when the total books something (the dormant-watchdog precedent:
/// a zero is absence pretending to be information); the window
/// family's grey indent, one rung under the Upload Pacing line it
/// completes.
///
/// night-ux-2 (the owner's live-run residue): the wide form is a
/// ~130-character line — on most terminals it wraps or truncates,
/// and a WRAPPED honesty label is not an honest label. The narrow
/// form keeps the two facts that make the number honest ("est.",
/// "counterfactual") and points one click away (--help) instead of
/// spelling the physics: `Quota Saved: 5.5 MB (est., counterfactual
/// — see --help)`. The width budget is the caller's terminal width,
/// measured by the canonical display-width twin (output/width.rs —
/// the one place a rendered width is decided); the switch is
/// BINARY — the full form when the total line fits, the narrow form
/// when it does not — never a wrapped or truncated long line. The
/// color layer's single-line law still applies: either form is one
/// line, shorter than the budget it renders in.
pub(crate) fn quota_saved_line(d: &DisplayData, width: usize) -> Option<String> {
    let saved = d
        .bytes_saved_by_edt
        .saturating_add(d.bytes_saved_by_ecn)
        .saturating_add(d.bytes_saved_by_recwn);
    (saved > 0).then(|| {
        // The color layer's own law (night-dragon-maintenance-8):
        // split the lines, wrap each, join — never one grey wrap
        // across a newline.
        let total = format!(
            "    Quota Saved: {} (counterfactual estimate — the bytes the rate limit \
             prevented; wire-measured savings: run scripts/bench/quota-saver-ab.sh)",
            format_bytes(saved)
        );
        if crate::output::display_width(&total) <= width {
            let split = format!(
                "      (est.; EDT: {}, ECN: {}, RECWN: {})",
                format_bytes(d.bytes_saved_by_edt),
                format_bytes(d.bytes_saved_by_ecn),
                format_bytes(d.bytes_saved_by_recwn)
            );
            format!("{}\n{}", grey(&total), grey(&split))
        } else {
            // The narrow form: the honest label holds, the physics
            // pointer collapses to the one-click surface.
            grey(&format!(
                "    Quota Saved: {} (est., counterfactual — see --help)",
                format_bytes(saved)
            ))
        }
    })
}

/// The status table's counter footer (night-ux-1, the owner's
/// 200kb-on-Brave session): the grey lines under the counters that
/// say WHAT the allowed / dropped columns count and WHEN they
/// started — "cumulative since apply", the --help grammar's own
/// contract (src/commands/help.rs, NIGHT-dinner-11) carried onto
/// the surface the owner was actually reading. night-docs-1: the
/// old "a dropped share is the rate limiter working" verdict is
/// gone — true but incomplete, it left the reader unable to tell a
/// wasted drop from a saved one. The two lines state the truths the
/// counters actually carry under the saver lanes: the residual (a
/// SMALL dropped under a policed cgroup is the lanes working —
/// RECWN clamped the sender, ECN marked, EDT paced, so few
/// would-be drops reached the verdict) and the direction law
/// (ingress drops burn quota, egress drops save it). The shape is
/// TWO grey lines instead of one wide line because the frame law
/// (night-ux-5) measures, cuts, and pads ONE line per flank entry:
/// a footer carrying an embedded newline would be measured as a
/// single over-wide line and truncated mid-prose, while two entries
/// ride the frame independently. Each line fits the owner's
/// 80-column budget whole (42 and 76 columns), so the direction
/// clause never truncates at the width a laptop terminal actually
/// is. The apply timestamp itself is NOT trivially available — the
/// stats row is a pinned 8-u64 kernel layout (types.rs
/// LimiterStatsRaw) and no policy row books one — so the footer
/// states the window without inventing a number (adding an
/// apply-time column would be a datapath/schema change, out of a
/// strings-and-layout task's law). PURE text shaping,
/// unit-pinnable without capturing stdout.
pub(crate) fn counters_footer_lines() -> [String; 2] {
    [
        grey("  allowed/dropped: cumulative since apply."),
        grey("  small dropped = saver lanes working; ingress burns quota, egress saves it."),
    ]
}

/// One status data row (pure, NIGHT-engrave-5): the whole row in
/// status green — the eagle table's calm tier (rank 3 and below
/// render the same way). Every row here IS a live, enforced limit —
/// the affirmative state — so the table reads like a calm monitor
/// board, not a white wall of text.
pub(crate) fn status_row_line(
    label: &str,
    row: &(String, String, String, String, String),
    col_widths: &[usize; 5],
) -> String {
    ok(&format!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        label,
        row.1,
        row.2,
        row.3,
        row.4,
        w0 = col_widths[0],
        w1 = col_widths[1],
        w2 = col_widths[2],
        w3 = col_widths[3],
        w4 = col_widths[4]
    ))
}

/// The list-apps table's header row (pure, NIGHT-engrave-5 hunt
/// find): the same eagle-eyes contract as the status header —
/// lowercase purple titles — so the two REPORT tables read as one
/// family. Extracted here (the display module owns table style) so
/// the wording is pinnable next to the status pins.
#[must_use]
pub(crate) fn list_apps_header_line(widths: &[usize; 5]) -> String {
    brand(&format!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        "process",
        "procs",
        "sockets",
        "cgroup id",
        "uid",
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4]
    ))
}

/// The watchdog prose line (pure, NIGHT-engrave-5): grey while the
/// deadline counts down (a subordinate fact — the census family),
/// warn yellow once expired (the enforcement verdict went dark).
pub(crate) fn watchdog_line(remaining_secs: Option<u64>) -> String {
    match remaining_secs {
        Some(secs) => grey(&format!("  watchdog: {secs}s remaining")),
        None => warn("  watchdog: expired (bpf is no-op)"),
    }
}

/// The enforcement census line (pure, NIGHT-engrave-5): grey,
/// lowercase — the same subordinate family the monitor's footer
/// census renders in.
pub(crate) fn active_limits_line(dl: usize, ul: usize) -> String {
    grey(&format!("  active limits: {dl} dl, {ul} ul"))
}

/// A compact human duration for the "(N left)" suffix (pure,
/// night-during): one unit, CEILED — 45s, 47m, 3h, 20d, 5y; the
/// sub-minute shapes print seconds so a short trial reads its own
/// countdown. night-improve-60 (the owner's 5h find): a countdown
/// never understates what remains — a `--during 5h` checked seconds
/// after apply floored to "4h left" and read like an hour had been
/// lost, so every tier now rounds UP to the unit it still holds
/// (4h59m reads "5h", the promise it was set as; an exact 3h reads
/// "3h").
pub(crate) fn format_duration_compact(ns: u64) -> String {
    const S: u64 = 1_000_000_000;
    const M: u64 = 60 * S;
    const H: u64 = 60 * M;
    const D: u64 = 24 * H;
    const Y: u64 = 365 * D;
    /// Ceiling division: the honest countdown rounds the remainder
    /// up, never away (7s of remainder still buys the next unit);
    /// saturating so a u64-extreme input can never panic in debug.
    fn ceil_div(value: u64, unit: u64) -> u64 {
        value.saturating_add(unit - 1) / unit
    }
    if ns < M {
        format!("{}s", ceil_div(ns, S))
    } else if ns < H {
        format!("{}m", ceil_div(ns, M))
    } else if ns < D {
        format!("{}h", ceil_div(ns, H))
    } else if ns < Y {
        format!("{}d", ceil_div(ns, D))
    } else {
        format!("{}y", ceil_div(ns, Y))
    }
}

/// One row's window lifetime line (pure, night-during, schema v23):
/// grey while the row polices or waits (the census family — a
/// subordinate fact under the row it belongs to), warn yellow once
/// the span has ENDED (the enforcement verdict went quiet and the
/// sweep has not collected the row yet — the one state an owner
/// should notice). The span's wall instants are reconstructed
/// through the same offset pair the twin uses; the daily line
/// names its UTC hours.
pub(crate) fn window_lifetime_line(win: &PolicyWindowRaw, wall_now: u64, mono_now: u64) -> String {
    let state = window_state(win, wall_now, mono_now);
    let offset = wall_minus_mono(wall_now, mono_now);
    match (win.kind, state) {
        (WINDOW_KIND_SPAN, "active") => grey(&format!(
            "    window: until {} ({} left)",
            format_wall_utc(win.end_mono_ns.saturating_add(offset)),
            format_duration_compact(win.end_mono_ns.saturating_sub(mono_now))
        )),
        (WINDOW_KIND_SPAN, "dormant") => grey(&format!(
            "    window: sleeps until {}",
            format_wall_utc(win.start_mono_ns.saturating_add(offset))
        )),
        (WINDOW_KIND_SPAN, _) => warn(&format!(
            "    window: expired at {} (awaiting sweep)",
            format_wall_utc(win.end_mono_ns.saturating_add(offset))
        )),
        (_, "active") => grey(&format!(
            "    window: daily {:02}:{:02}-{:02}:{:02} UTC (active)",
            win.start_s / 3600,
            (win.start_s / 60) % 60,
            win.end_s / 3600,
            (win.end_s / 60) % 60
        )),
        (_, _) => grey(&format!(
            "    window: daily {:02}:{:02}-{:02}:{:02} UTC (outside — not policing now)",
            win.start_s / 3600,
            (win.start_s / 60) % 60,
            win.end_s / 3600,
            (win.end_s / 60) % 60
        )),
    }
}

/// One row's guarantee line (pure, improve-40, schema v24;
/// improve-40-b the per-direction shape): grey, the window lifetime
/// line's own subordinate family — the bracket is per-subprocess
/// config under the row it belongs to, "per subprocess" naming the
/// unit the numbers police (the DRR leaves, not the cgroup total
/// the rate cells carry). Rendered only when a side is set; the
/// exact-twin law renders each number. Equal pairs render the
/// one-flag shape unchanged; a SPLIT renders direction-prefixed
/// halves (the asymmetric link's own line, only the set halves
/// named — an unset direction is honestly absent, never a
/// fabricated zero).
pub(crate) fn guarantee_line(download: BracketPair, upload: BracketPair) -> Option<String> {
    if download.is_unset() && upload.is_unset() {
        return None;
    }
    if download == upload {
        let joined = pair_halves(download);
        return Some(grey(&format!("    guarantee: {joined} (per subprocess)")));
    }
    // The split shape: each direction's half carries its own prefix,
    // only the directions that carry a side at all.
    let halves = [("dl", download), ("ul", upload)]
        .into_iter()
        .filter(|(_, pair)| !pair.is_unset())
        .map(|(label, pair)| format!("{label} {}", pair_halves(pair)))
        .collect::<Vec<_>>()
        .join(" / ");
    Some(grey(&format!("    guarantee: {halves} (per subprocess)")))
}

/// One pair's "floor X ceil Y" halves, the set sides only — the
/// exact-twin law's own joiner, shared by the equal and split
/// shapes above.
fn pair_halves(pair: BracketPair) -> String {
    let floor_half = if pair.floor_bps != 0 {
        format!("floor {} ", format_rate_exact(pair.floor_bps))
    } else {
        String::new()
    };
    let ceil_half = if pair.ceil_bps != 0 {
        format!("ceil {}", format_rate_exact(pair.ceil_bps))
    } else {
        String::new()
    };
    format!("{floor_half}{ceil_half}").trim().to_string()
}

// ── the Shape B frame law (night-ux-5) ──────────────────────────────────────

/// Which family of the status output one composed line belongs to —
/// the frame law's only question is the truncation ladder: the
/// footer prose cuts first (the least load-bearing prose for a
/// one-glance read), the table's own lines and the signature stamp
/// never cut. The order of the cut tiers below is the owner's Shape
/// B boundary made code: the sacrifice ladder runs down through the
/// standalone telemetry lines to the per-row subordinate family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusLineKind {
    /// The counter footer's units-and-window prose (night-ux-1).
    FooterProse,
    /// The RECWN lane's window line (night-spark-2).
    Recwn,
    /// The quota telemetry's saved line, narrow form included
    /// (night-spark-7).
    Quota,
    /// The watchdog countdown / expiry line (NIGHT-boost-5).
    Watchdog,
    /// The census line and the empty board's verdict.
    Census,
    /// A row's subordinate lifetime/guarantee/CE/pacing line.
    RowSubordinate,
    /// The table's header, data rows, and the signature stamp —
    /// the load-bearing lines, never truncated.
    Protected,
}

impl StatusLineKind {
    /// The tier's place in the sacrifice ladder — `None` marks the
    /// lines a terminal narrower than the content can never claim.
    fn cut_rank(self) -> Option<usize> {
        match self {
            StatusLineKind::FooterProse => Some(0),
            StatusLineKind::Recwn => Some(1),
            StatusLineKind::Quota => Some(2),
            StatusLineKind::Watchdog => Some(3),
            StatusLineKind::Census => Some(4),
            StatusLineKind::RowSubordinate => Some(5),
            StatusLineKind::Protected => None,
        }
    }
}

/// The status frame, fitted: the grid's two flanks already ordered
/// as print_status prints them, and the frame WIDTH every chrome
/// line (title bar, grid) must span — the widest line the output
/// carries, however humble its family.
pub(crate) struct StatusFrame {
    /// The lines above the grid: watchdog, census, header row.
    pub(crate) above_grid: Vec<String>,
    /// The lines below: data rows, subordinate lines, footer,
    /// RECWN, stamp.
    pub(crate) below_grid: Vec<String>,
    /// The frame's width in rendered columns — the title bar and
    /// the grid compose at exactly this width.
    pub(crate) width: usize,
}

/// The Shape B frame law (night-ux-5, the owner's 2026-11-08 live
/// run): the frame is the CONTENT's own width, never the table's
/// alone. PURE text shaping, unit-pinnable without capturing
/// stdout — the composition (which lines, which order) stays with
/// print_status; this function owns the three passes:
///
/// 1. the CUT pass — a line whose family rides the truncation
///    ladder and whose rendered width exceeds the terminal budget
///    truncates to the budget, ellipsis last (never wrapped; a
///    wrapped honesty label is not an honest label). Protected
///    lines never cut.
/// 2. the WIDTH pass — the frame width is the widest line either
///    flank carries after the cut.
/// 3. the PAD pass — every line pads to exactly that width, so the
///    right edge is one straight column, not ragged.
pub(crate) fn frame_status_output(
    mut above: Vec<(StatusLineKind, String)>,
    mut below: Vec<(StatusLineKind, String)>,
    budget: usize,
) -> StatusFrame {
    let cut = |lines: &mut Vec<(StatusLineKind, String)>| {
        for (kind, line) in lines.iter_mut() {
            if kind.cut_rank().is_some() && colored_display_width(line) > budget {
                *line = fit_colored_to_width(line, budget);
            }
        }
    };
    cut(&mut above);
    cut(&mut below);
    let width = above
        .iter()
        .chain(below.iter())
        .map(|(_, line)| colored_display_width(line))
        .max()
        .unwrap_or(0);
    let pad = |lines: Vec<(StatusLineKind, String)>| {
        lines
            .into_iter()
            .map(|(_, line)| pad_colored_to_width(&line, width))
            .collect::<Vec<_>>()
    };
    StatusFrame {
        above_grid: pad(above),
        below_grid: pad(below),
        width,
    }
}

// night-ux-5: the Shape B frame-law pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// quota pins — split from display_tests.rs, whose own LOC headroom
// the branch-frame pins already spent.
#[cfg(test)]
#[path = "../../test/ebpf/display_frame_tests.rs"]
mod display_frame_tests;
