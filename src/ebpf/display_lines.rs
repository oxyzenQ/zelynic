// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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
use crate::output::{brand, grey, ok, warn};

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
    let label = identity.label(d.cgroup_id);
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
