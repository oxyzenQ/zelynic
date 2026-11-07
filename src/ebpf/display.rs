// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from the limiter core to keep every module under the
//! 500-line cap (scripts/gates/check-loc.sh).

use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::types::{
    BracketPair, POLICY_FLAG_PER_SOCKET, PolicyRaw, PolicyWindowRaw,
};
use crate::ebpf::limiter::{LimiterStatsRaw, monotonic_ns, terminal_width, wall_now_ns};
use crate::ebpf::render::{grid_line, title_bar};
use crate::output::{grey, signature_footer, suggestion, warn};

/// The status table's column titles (NIGHT-engrave-5): lowercase —
/// the eagle-eyes table contract (engrave-1 lowercased the monitor's
/// titles; this surface was the last uppercase holdout the owner
/// caught). Verdict VALUES keep their case (BLOCKED) — titles are
/// furniture, verdicts are states.
pub(super) const STATUS_HEADERS: [&str; 5] = ["cgroup", "download", "upload", "allowed", "dropped"];

/// Combined policy data for display.
pub(crate) struct DisplayData {
    pub(crate) cgroup_id: u32,
    pub(crate) dl_bps: Option<u64>,
    pub(crate) ul_bps: Option<u64>,
    pub(crate) dl_per_socket: bool,
    pub(crate) ul_per_socket: bool,
    pub(crate) packets_allowed: u64,
    pub(crate) packets_dropped: u64,
    pub(crate) bytes_allowed: u64,
    pub(crate) bytes_dropped: u64,
    /// night-spark-4, schema v26 (the CE ledger): the ECN-first
    /// lane's own truth, read off the same stats row — the volume
    /// book_rescue delivered CE-marked. The subordinate CE Marked
    /// line renders it; zeros stay silent (the dormant-watchdog
    /// precedent).
    pub(crate) ce_marked_packets: u64,
    pub(crate) ce_marked_bytes: u64,
    /// night-spark-7, schema v28 (the quota telemetry's math — Layer
    /// 4 of the quota saver): the egress pacing lane's preserved
    /// headroom, read off the stats row's v28 tail — the running
    /// (rate x elapsed) - uploaded the kernel books on the egress
    /// policed path. The Quota Saved line's EDT half.
    pub(crate) bytes_saved_by_edt: u64,
    /// night-spark-7, Layer 4: the RECWN lane's saved volume — the
    /// window-law counterfactual (recwn_saved_bytes below): the
    /// bytes the receive-window clamp kept a sender from sending,
    /// estimated userspace-side against the documented default-window
    /// assumption because the sock_ops clamp carries no observable
    /// default-window column to book against. Zero when the lane is
    /// not planted or the row carries no live download rate.
    pub(crate) bytes_saved_by_recwn: u64,
    /// night-spark-7, Layer 4: the ECN lane's saved volume, read off
    /// the stats row's v28 tail — one-for-one with ce_marked_bytes,
    /// booked by book_rescue beside the raw pair: every delivered
    /// CE-marked byte is a byte that never becomes a
    /// loss-and-retransmission pair.
    pub(crate) bytes_saved_by_ecn: u64,
    /// The row's --during window, when it carries one (night-during,
    /// schema v23) — the lifetime line under the row renders it.
    pub(crate) window: Option<PolicyWindowRaw>,
    /// The row's guarantee bracket (improve-40, schema v24;
    /// improve-40-b the per-direction shape): one pair per
    /// direction, each leg read off its own policy row — the zero
    /// sentinel is unset (most rows carry none, and the subordinate
    /// line renders only when a side is set).
    pub(crate) download: BracketPair,
    pub(crate) upload: BracketPair,
}

// improve-40 (schema v24): the pure line renderers live in the
// display_lines sibling (the policy_lines discipline — this file
// rode the 500-LOC owner cap when the guarantee line joined the
// window family). Re-exported so the pins in display_tests
// (use super::*) and the list-apps surface see the same paths as
// before the split.
pub(crate) use super::display_lines::{
    active_limits_line, ce_marked_line, counters_footer_line, guarantee_line,
    list_apps_header_line, pacing_line, quota_saved_line, recwn_line, status_cells,
    status_header_line, status_row_line, watchdog_line, window_lifetime_line,
};

/// Collect display data from policies + stats (the window join, and
/// the RECWN lane join — night-spark-7: the Layer 4 estimate needs
/// the lane's planted verdict, the same belt the bottom RECWN
/// line's own derivation rides).
pub(super) fn collect_display_data(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    windows: &[(u32, PolicyWindowRaw)],
    recwn: &RecwnLane,
) -> Vec<DisplayData> {
    // The census row: (dl, ul, dl per-socket, ul per-socket, the
    // per-direction guarantee pairs — improve-40-b: each leg's pair
    // read off its own policy row, the one-flag law's equal pairs
    // a special case of the split).
    type CombinedRow = (
        Option<u64>,
        Option<u64>,
        bool,
        bool,
        BracketPair,
        BracketPair,
    );
    let mut combined: HashMap<u32, CombinedRow> = HashMap::new();
    for (id, p) in dl_policies {
        let e = combined.entry(*id).or_default();
        e.0 = Some(p.rate_bps);
        e.2 = p.flags & POLICY_FLAG_PER_SOCKET != 0;
        e.4 = BracketPair {
            floor_bps: p.floor_bps,
            ceil_bps: p.ceil_bps,
        };
    }
    for (id, p) in ul_policies {
        let e = combined.entry(*id).or_default();
        e.1 = Some(p.rate_bps);
        e.3 = p.flags & POLICY_FLAG_PER_SOCKET != 0;
        e.5 = BracketPair {
            floor_bps: p.floor_bps,
            ceil_bps: p.ceil_bps,
        };
    }

    let mut sorted: Vec<_> = combined.into_iter().collect();
    sorted.sort_by_key(|(id, _)| *id);

    sorted
        .iter()
        .map(|(cgroup_id, (dl, ul, dl_ps, ul_ps, download, upload))| {
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            DisplayData {
                cgroup_id: *cgroup_id,
                dl_bps: *dl,
                ul_bps: *ul,
                dl_per_socket: *dl_ps,
                ul_per_socket: *ul_ps,
                packets_allowed: s.map(|(_, s)| s.packets_allowed).unwrap_or(0),
                packets_dropped: s.map(|(_, s)| s.packets_dropped).unwrap_or(0),
                bytes_allowed: s.map(|(_, s)| s.bytes_allowed).unwrap_or(0),
                bytes_dropped: s.map(|(_, s)| s.bytes_dropped).unwrap_or(0),
                ce_marked_packets: s.map(|(_, s)| s.ce_marked_packets).unwrap_or(0),
                ce_marked_bytes: s.map(|(_, s)| s.ce_marked_bytes).unwrap_or(0),
                // night-spark-7 (the quota telemetry's math — Layer
                // 4): the two kernel-booked columns copy straight off
                // the v28 stats tail, and the RECWN estimate runs the
                // window-law counterfactual below — planted lane,
                // live download rate, the row's delivered volume. A
                // row with no stats entry books nothing (the
                // unwrap_or(0) family's own honesty).
                bytes_saved_by_edt: s.map(|(_, s)| s.bytes_saved_by_edt).unwrap_or(0),
                bytes_saved_by_recwn: match (recwn.planted, dl) {
                    (true, Some(rate)) if *rate > 0 => {
                        recwn_saved_bytes(*rate, s.map(|(_, s)| s.bytes_allowed).unwrap_or(0))
                    }
                    _ => 0,
                },
                bytes_saved_by_ecn: s.map(|(_, s)| s.bytes_saved_by_ecn).unwrap_or(0),
                window: windows
                    .iter()
                    .find(|(id, _)| id == cgroup_id)
                    .map(|(_, w)| *w),
                download: *download,
                upload: *upload,
            }
        })
        .collect()
}

/// The RECWN lane's status derivation (night-spark-2, schema v25 —
/// Receive Window Control, the quota saver's Layer 1): what the
/// two status surfaces (human table + --print-json) report about
/// the receive-window lane. `planted` says the sock_ops program's
/// pin stands (the lane rides the limiter object — schema v25's
/// is_pinned covers it); `window_bytes` is the BINDING window the
/// lane currently derives — the smallest window across the active
/// download policies (the single-policy case, the owner's brief's
/// own scenario, reads exactly that policy's window; a multi-
/// policy tree reports the tightest clamp the lane enforces
/// anywhere). Absent when no download policy with a live rate
/// stands (upload-only or block-only rows shape no window).
///
/// night-ux-1: `Default` is the INERT lane (not planted, no window,
/// no binding policies) — the shape every pre-RECWN surface and
/// test helper rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RecwnLane {
    pub(crate) planted: bool,
    pub(crate) window_bytes: Option<u64>,
    /// night-ux-1: the count of ACTIVE download policies (rate > 0)
    /// the binding window derives across — the human line's "binding
    /// across N download policies" names the unit the clamp polices
    /// (the multi-policy tree reports the tightest clamp and the
    /// count it wins across). Derived beside the window in
    /// [`recwn_lane`] so the pair can never drift; the human line is
    /// its only consumer (the JSON twin stays the pinned scripting
    /// shape).
    pub(crate) binding_policies: usize,
}

/// The Layer 1 RTT assumption, microseconds — the userspace twin
/// of ebpf/src/recwn.rs's RECWN_DEFAULT_RTT_US (200 ms, the
/// delivery-cadence estimate the live E2E evidence set — the
/// kernel core's doc owns the full record). The twin discipline
/// default_burst carries: each tree states its own constant, and
/// test/ebpf/limiter/recwn_tests.rs pins the derived windows
/// against the kernel core so the pair can never drift.
pub(crate) const RECWN_RTT_ESTIMATE_US: u32 = 200_000;

/// The window-band clamps — the userspace twins of the kernel
/// core's RECWN_WINDOW_MIN_BYTES / RECWN_WINDOW_MAX_BYTES (2 x MSS
/// and 1 MiB; ebpf/src/recwn.rs owns the law's rationale).
pub(crate) const RECWN_WINDOW_MIN_BYTES: u64 = 2 * 1460;
pub(crate) const RECWN_WINDOW_MAX_BYTES: u64 = 1_048_576;

/// The sanitize guard on the rate input — the userspace twin of
/// ebpf/src/recwn.rs's RECWN_RATE_SANITIZE_CAP (4 GiB/s). The
/// kernel side must ride a plain 64-bit multiply (the BPF ISA has
/// no widening multiply — a saturating one lowers to `__multi3`,
/// which the kernel cannot relocate), so the twin carries the SAME
/// clamp-then-multiply shape and the parity pin holds at every
/// input, not just the sane ones.
pub(crate) const RECWN_RATE_SANITIZE_CAP: u64 = 4_294_967_296;

/// The RECWN window one download rate derives — the userspace twin
/// of the kernel core's layer1_window (rate x RTT / 1e6, clamped
/// to the [2 x MSS, 1 MiB] band). Parity-pinned against the core
/// by test/ebpf/limiter/recwn_tests.rs across the rate matrix.
pub(crate) fn recwn_window_bytes(rate_bps: u64) -> u64 {
    let rate = rate_bps.min(RECWN_RATE_SANITIZE_CAP);
    let raw = rate * u64::from(RECWN_RTT_ESTIMATE_US) / 1_000_000;
    raw.clamp(RECWN_WINDOW_MIN_BYTES, RECWN_WINDOW_MAX_BYTES)
}

/// Derive the RECWN lane's status row from the download policy
/// census and the program pin's existence: the BINDING window is
/// the minimum the active download rates derive (a block verdict —
/// rate 0 — shapes no window: the lane that delivers nothing has
/// no receive window to shape), and a lane that is not planted
/// shapes nothing at all — the window rides the program, not the
/// census (an unplanted tree with stale map rows reports no window,
/// never a phantom clamp).
pub(crate) fn recwn_lane(dl_policies: &[(u32, PolicyRaw)], planted: bool) -> RecwnLane {
    // night-ux-1: the active set derives BOTH the binding window and
    // the count that names it — one filter, one truth, no drift
    // between the clamp and the "across N" the line prints.
    let binding: Vec<u64> = dl_policies
        .iter()
        .filter(|(_, p)| p.rate_bps > 0)
        .map(|(_, p)| recwn_window_bytes(p.rate_bps))
        .collect();
    let window_bytes = planted.then(|| binding.iter().copied().min()).flatten();
    RecwnLane {
        planted,
        window_bytes,
        binding_policies: binding.len(),
    }
}

/// night-spark-7 (the quota telemetry's math — Layer 4 of the quota
/// saver): the RECWN lane's saved-volume estimate — the window-law
/// counterfactual, userspace-side by design (the sock_ops clamp
/// carries no observable default-window column to book against, so
/// the kernel cannot book this lane's saving; the estimate runs
/// where the census already lives). THE LAW, in words: the clamp
/// holds a sender to `clamped` bytes per delivery cadence, so every
/// `clamped` bytes the lane DELIVERED is one full window-cycle —
/// and in that same cycle a sender with the DEFAULT window would
/// have had `default - clamped` more bytes in flight. Scaled over
/// the delivered volume:
///
///     bytes_saved_by_recwn = (bytes_allowed / clamped) x (default - clamped)
///
/// The NAMED ASSUMPTION (the arc doc's math section owns it): the
/// default window is pinned at 128 KiB — the kernel's tcp_rmem[0]
/// initial receive buffer, the window a socket carries BEFORE
/// autotuning grows it. That is deliberately the CONSERVATIVE pole
/// of the assumption band: autotuning grows real defaults toward
/// the MiB scale, so the true saving sits between this bound and
/// the link's own ceiling — the estimate errs LOW, never high, the
/// same direction every honest counter in this house leans. The
/// self-extinguishing edge is the law's own honesty: a rate whose
/// clamped window reaches the default (about 655 KB/s at the 200 ms
/// cadence estimate) books ZERO — the clamp is not the binding
/// constraint there, the policer is, and this column refuses to
/// claim the policer's work as the window's. The one granularity
/// concession, stated: bytes_allowed is the combined dl+ul ledger
/// (the stats map's own shape), so a row policing BOTH directions
/// scales its upload volume into the estimate too — the
/// single-direction row, the RECWN lane's own common shape (a
/// download policy, an unlimited upload), is exact.
pub(crate) const RECWN_SAVED_DEFAULT_WINDOW_BYTES: u64 = 131_072;

/// The Layer 4 RECWN estimate (see
/// [`RECWN_SAVED_DEFAULT_WINDOW_BYTES`]'s law): the bytes a
/// default-window sender would have put in flight beyond the
/// clamp's own volume, over the lane's delivered volume. Integer
/// division floors the cycle count (conservative) and the
/// saturating multiply bounds the extreme tail (a u64-extreme
/// delivered volume cannot panic the estimate in debug builds).
#[must_use]
pub(crate) fn recwn_saved_bytes(rate_bps: u64, bytes_allowed: u64) -> u64 {
    let clamped = recwn_window_bytes(rate_bps);
    if clamped >= RECWN_SAVED_DEFAULT_WINDOW_BYTES {
        // The clamp is not the binding constraint at this rate —
        // the estimate self-extinguishes rather than claim the
        // policer's work as the window's.
        return 0;
    }
    let cycles = bytes_allowed / clamped;
    cycles.saturating_mul(RECWN_SAVED_DEFAULT_WINDOW_BYTES - clamped)
}

/// The clean-state frame (no pins, NIGHT-engrave-5; compacted in
/// NIGHT-private-research-3): the flagship chrome and one grey line
/// — "no active limits" is a verdict, not an absence of output.
/// The title bar spans the terminal width (there is no table to
/// size to). The compact pass retired the breathing-gap fillers on
/// every report surface (the owner's more-compact-and-simple
/// directive): title, verdict, stamp — zero filler lines.
#[must_use]
pub(crate) fn status_clean_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        grey("  no active limits"),
        format!("  {}", signature_footer()),
    ]
}

/// The stale-pins frame (NIGHT-engrave-5; compacted in
/// NIGHT-private-research-3): the flagship chrome with the warning
/// in warn yellow and the recovery command in suggestion white —
/// the same actionable-accent contract the monitor's limit
/// suggestion line carries, zero filler lines.
#[must_use]
pub(crate) fn status_stale_lines(width: usize) -> Vec<String> {
    vec![
        title_bar("zelynic status", width),
        warn("  stale bpf pin files detected (partial enforcement state)"),
        format!(
            "  {} {} {}",
            grey("run"),
            suggestion("'zelynic recover'"),
            grey("to clean up, then re-apply limits")
        ),
        format!("  {}", signature_footer()),
    ]
}

/// Print human-readable status table.
///
/// Flagship engraving (NIGHT-boost-5): the surface opens with the
/// same purple title bar the eagle-eyes monitor carries and signs
/// off with the signature footer — status is not an afterthought
/// table, it is the second flagship surface. The title bar spans
/// the table's own width (content-width table + its gutter), not
/// the full terminal — the status grid sizes to its rows, and a
/// full-width bar would overhang it on wide screens.
///
/// NIGHT-engrave-5 (the eagle-eyes style match, the owner's audit):
/// the table itself answers to the monitor's contract — lowercase
/// purple column headers over a full-width purple grid flush with
/// the left edge, data rows in status green (the calm tier), the
/// watchdog/census prose in grey (warn yellow when the watchdog
/// expires), and a breathing gap under the title bar. The uppercase
/// headers and the plain separator were the last pre-eagle carriers
/// on a flagship surface.
///
/// Watchdog honesty (NIGHT-boost-5): the line appears only when a
/// deadline is actually ARMED. The retired "not set (enforcing)"
/// line read like a state but was the absence of one — a dormant
/// auto-expiry timer printed on every check the owner actually
/// runs, noise pretending to be information. `--print-json` keeps
/// the `"watchdog"` field semantics unchanged (pinned scripting
/// contract, test/ebpf/display_tests.rs).
pub fn print_status(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
    windows: &[(u32, PolicyWindowRaw)],
    recwn: &RecwnLane,
) {
    let data = collect_display_data(dl_policies, ul_policies, stats, windows, recwn);
    let rows: Vec<(String, String, String, String, String)> =
        data.iter().map(|d| status_cells(d, identity)).collect();
    // night-during (schema v23): one clock pair for every lifetime
    // line under the rows that carry windows.
    let (wall_now, mono_now) = (wall_now_ns(), monotonic_ns());

    let term_w = terminal_width().saturating_sub(4);

    let mut col_widths = [0usize; 5];
    for (i, h) in STATUS_HEADERS.iter().enumerate() {
        col_widths[i] = h.len();
    }
    for row in &rows {
        col_widths[0] = col_widths[0].max(row.0.chars().count());
        col_widths[1] = col_widths[1].max(row.1.len());
        col_widths[2] = col_widths[2].max(row.2.len());
        col_widths[3] = col_widths[3].max(row.3.len());
        col_widths[4] = col_widths[4].max(row.4.len());
    }

    let total: usize = col_widths.iter().sum::<usize>() + 4;
    if total > term_w {
        let excess = total - term_w;
        col_widths[0] = col_widths[0].saturating_sub(excess).max(10);
    }

    let sep_len: usize = col_widths.iter().sum::<usize>() + 4;
    // NIGHT-engrave-5 opened the frame with the title bar and a
    // breathing gap; NIGHT-private-research-3 (the owner's
    // compact-and-simple directive) retired the gap on the report
    // surfaces: the frame starts at the title and every following
    // line is content — the watchdog, the census, and the table
    // stack directly under the bar.
    println_safe!("{}", title_bar("zelynic status", sep_len + 2));

    match watchdog_deadline {
        Some(deadline) if deadline > 0 => {
            let now = monotonic_ns();
            let line = if deadline > now {
                watchdog_line(Some((deadline - now) / 1_000_000_000))
            } else {
                watchdog_line(None)
            };
            println_safe!("{line}");
        }
        // Dormant (deadline 0 / None): no line at all — the function
        // docs above hold the why.
        _ => {}
    }

    if dl_policies.is_empty() && ul_policies.is_empty() {
        println_safe!("{}", grey("  active limits: none"));
        println_safe!("  {}", signature_footer());
        return;
    }

    // The census line lands directly above the header row it
    // counts (NIGHT-private-research-3): one table cluster, zero
    // filler between the summary and the columns it summarizes.
    println_safe!(
        "{}",
        active_limits_line(dl_policies.len(), ul_policies.len())
    );
    // NIGHT-engrave-5: the header row and the grid under it are the
    // eagle table contract — lowercase purple titles, then the
    // monitor's own purple grid spanning the full title width and
    // flush with the left edge (the `|---` shape, never `| ---`):
    // one border family across every zelynic table.
    println_safe!("{}", status_header_line(&col_widths));
    println_safe!("{}", grid_line(sep_len + 2));

    for (row, d) in rows.iter().zip(data.iter()) {
        let label = if row.0.chars().count() > col_widths[0] {
            let truncated: String = row
                .0
                .chars()
                .take(col_widths[0].saturating_sub(1))
                .collect();
            format!("{truncated}…")
        } else {
            row.0.clone()
        };
        println_safe!("{}", status_row_line(&label, row, &col_widths));
        // night-during (schema v23): the lifetime line lands directly
        // under its row — one indent deeper than the table, the same
        // grey subordinate family the watchdog prose rides (warn
        // yellow when the span has ended and the sweep has not
        // collected the row yet).
        if let Some(win) = &d.window {
            println_safe!("{}", window_lifetime_line(win, wall_now, mono_now));
        }
        // improve-40 (schema v24): the bracket's own subordinate
        // line, the window family's indent and grey — only the rows
        // that carry a side render one.
        if let Some(line) = guarantee_line(d.download, d.upload) {
            println_safe!("{line}");
        }
        // night-spark-4 (schema v26): the CE ledger's subordinate
        // line — the marking lane's own volume under the row that
        // carries it, the window family's grey; only rows that
        // actually marked traffic render one (absence stays
        // silence, never a zero).
        if let Some(line) = ce_marked_line(d) {
            println_safe!("{line}");
        }
        // night-spark-5 (schema v27): the egress pacing lane's
        // subordinate line — the rate the sock_ops program pins onto
        // the row's upload sockets, the window family's grey; only
        // rows carrying a live upload policy render one (absence
        // stays silence, never a zero).
        if let Some(line) = pacing_line(d) {
            println_safe!("{line}");
        }
        // night-spark-6 (the quota saver's Layer 4 PREP): the quota
        // telemetry's subordinate line — the saved volume the Layer 4
        // columns will book (RECWN + ECN), the window family's grey;
        // the placeholders book nothing yet, so the line stays silent
        // until the v28 tail lands and the math fills it (the
        // dormant-watchdog precedent: a zero is absence, never
        // information). night-ux-2: the terminal's own width is the
        // narrow-form trigger — the wide honesty label never wraps.
        if let Some(line) = quota_saved_line(d, terminal_width()) {
            println_safe!("{line}");
        }
    }

    // night-ux-1 (the owner's 200kb-on-Brave session): the counter
    // footer — the allowed / dropped columns' own units-and-window
    // line, the --help grammar's NIGHT-dinner-11 contract carried
    // onto the surface the owner was actually reading. One grey
    // line under the table it explains.
    println_safe!("{}", counters_footer_line());

    // night-spark-2 (RECWN, schema v25): the receive-window lane's
    // own subordinate line — the watchdog's grey family, one line
    // under the table, rendered ONLY when the lane is actively
    // shaping a window (the dormant-watchdog precedent: an unenforcing
    // lane printing state noise is absence pretending to be
    // information).
    if let Some(line) = recwn_line(recwn) {
        println_safe!("{line}");
    }

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // flush with the last row (NIGHT-private-research-3: the blank
    // line of breathing room above it retired with the rest of the
    // report-surface fillers).
    println_safe!("  {}", signature_footer());
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../test/ebpf/display_tests.rs"]
mod display_tests;

// improve-40-b: the per-direction bracket's read-surface pins,
// split from display_tests.rs at the 500-LOC owner cap (the
// guarantee line's split shapes and the census's per-leg join).
#[cfg(test)]
#[path = "../../test/ebpf/display_bracket_tests.rs"]
mod display_bracket_tests;

// night-spark-6 (the quota saver's Layer 4 PREP): the Quota Saved
// subordinate line's family, split from display_tests.rs at the
// 600-line owner cap (the sibling-split lineage, one family over).
#[cfg(test)]
#[path = "../../test/ebpf/display_quota_tests.rs"]
mod display_quota_tests;
