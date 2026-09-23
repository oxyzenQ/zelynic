// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Responsive render engine for the eagle-eyes monitor
//! (NIGHT-hunt-7; NIGHT-boost-1 merged the former observe/top pair
//! into one surface).
//!
//! Owner contract: "boring but elegant flagship". One purple title
//! bar, one thin header row, right-aligned numerics, no per-cell
//! noise (the old layout packed "89 (1.2 MB)" into single cells).
//! Purple is branding (NIGHT-hunt-5): the title bar renders bold
//! purple and the column headers regular purple — the same #A855F7
//! source of truth as the rest of the output layer.
//!
//! Left-edge contract (NIGHT-boost-5): the title bar carries the same
//! two-column gutter every row, separator, and footer uses, so the
//! frame's left border is one straight line — the old title started
//! at column 0 while the table started at column 2, the "big gap on
//! the left border" the owner reported. Every frame line now shares
//! the 2-column gutter and closes flush at the frame width.
//!
//! Dynamic screen size: the terminal size is re-probed on every
//! frame — ONE TIOCGWINSZ ioctl per frame through the canonical
//! terminal-layer probe (NIGHT-hunt-15: the old path issued two,
//! width and height separately, plus the diff engine's own resize
//! check). Resizing the terminal adapts the layout on the next
//! refresh — and since NIGHT-boost-14 the loop probes the geometry
//! every 50ms wake and renders the change within one wake, not the
//! next refresh tick (up to 60s at `--interval 60`): no SIGWINCH
//! plumbing, no stale geometry, no caches to invalidate. Columns
//! degrade gracefully on narrow terminals (TOTAL drops first, the
//! subprocess detail hides with it — the column ladder IS that
//! threshold since NIGHT-engrave-4, one source of truth), the label
//! column absorbs the remaining width, and the frame is pinned to
//! the FULL terminal height (NIGHT-boost-14): the table floats under
//! the header and the footer stays near the bottom — the grip block
//! never follows the table's length. A short window compresses the
//! footer through a compact ladder (blanks drop, then the grips,
//! then the discovery hints) before the table loses its rows.
//!
//! NIGHT-engrave-4 (symmetric rails): the table's rows end two
//! columns short of the content inset — the RIGHT gutter, mirror of
//! the left — so the TOTAL column's figures never fight the right
//! rail for their column, and the header's process title spans the
//! whole identity region (rank cell + gap + label), starting at the
//! frame's canonical text column instead of floating past the blank
//! rank cell.
//!
//! Realtime interval: callers pass the poll interval so the RATE
//! column converts per-frame deltas into bytes-per-second
//! (`--interval`, clamped 1s..60s at parse time in
//! `parse_monitor_interval`).
//!
//! Module map (mirrors the limiter/ split, owner LOC cap):
//! - [`eagle`] — the ranked eagle-eyes renderer (default + filtered)
//! - [`footer`] — the pinned grip footer: tiers, grips, the build
//!   (NIGHT-boost-14, split from eagle by the cohesion discipline)
//! - [`focus`] — the deep single-target view (autodetected focus)
//! - [`session`] — the session leaderboard: accumulated per-cgroup
//!   totals (NIGHT-boost-5; the blink bookkeeping retired by
//!   NIGHT-boost-14 — static tiers, no animation)
//! - [`border`] — the frame's left-right rails, rounded corners, and
//!   gradient (NIGHT-boost-20, the cosmostrix msg-border lineage)
//! - `bench` (cfg(test)) — the frame A/B benchmark harness (wired in
//!   from `test/ebpf/render/bench.rs`, NIGHT-hunt-17)
//! - this root — geometry probing, column budgets, shared helpers,
//!   and the NIGHT-hunt-8 connection-detail lines (label +N suffix,
//!   the per-process endpoint tree of NIGHT-boost-21 shared by eagle
//!   and focus)

mod border;
mod detail;
mod eagle;
mod focus;
mod footer;
mod loading;
mod session;

#[cfg(test)]
// NIGHT-hunt-17: the A/B frame harness is a test file, so it lives
// under the repo's single test/ tree (cosmostrix Pattern C) and is
// #[path]-wired back here. frame-bench.py still finds it by test
// name (frame_bench_eagle), not by path.
#[path = "../../test/ebpf/render/bench.rs"]
mod bench;

pub use eagle::render_eagle_eyes;

pub(crate) use session::{SessionAcc, SessionState};

pub(crate) use detail::{comm_from_label, detail_lines, full_detail_lines, label_with_count};

// NIGHT-engrave-5: the grid line is every zelynic table's border
// family — the status and list-apps report tables borrow the monitor's
// exact purple grid instead of growing their own separators.
pub(crate) use footer::grid_line;

// NIGHT-boost-25: the monitor's opening frame — the prelude the
// smooth open paints while the BPF load runs.
pub(crate) use loading::loading_frame;

use crate::ebpf::limiter::format_rate;
use crate::output::brand_bold;

// ── Geometry ────────────────────────────────────────────────────────────────

/// Terminal size for one frame. Probed fresh on every render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameGeometry {
    pub width: usize,
    pub height: usize,
}

impl FrameGeometry {
    /// Probe the current terminal size (columns and rows) — one
    /// TIOCGWINSZ call per frame (NIGHT-hunt-15: width and height
    /// ride the same probe the limiter formatters and the diff
    /// engine's resize check use).
    ///
    /// Falls back to 80x24 when stdout is not a TTY (piped output,
    /// tests, benchmark harnesses) — the same fallback contract as
    /// `terminal_width()`.
    #[must_use]
    pub fn probe() -> Self {
        match crate::terminal::winsize() {
            Some((cols, rows)) => Self {
                width: cols as usize,
                height: rows as usize,
            },
            None => Self {
                width: 80,
                height: 24,
            },
        }
    }
}

/// Eagle-eyes column layout derived from the frame width.
///
/// Degradation ladder (6-column rank reserve, 1-column gaps, and
/// the 2-column right gutter of NIGHT-engrave-4):
/// - width >= 53: (rank) | top process | download | upload | total
/// - width >= 42: (rank) | top process | download | upload (total dropped)
/// - width  < 42: (rank) | top process (min 12) | download | upload at 9-wide
///
/// Download and upload carry per-frame RATES (delta / interval —
/// "what is moving right now"); total carries the session-accumulated
/// bytes (NIGHT-boost-5: the v10 "total accumulated" function
/// restored as the ranking key's own column). The old combined RATE
/// column was dl+ul restated — the total column replaces it.
///
/// NIGHT-engrave-4 (the symmetric-rails fix): the table's rows end
/// two columns short of the frame width — the RIGHT gutter, the
/// mirror of the left gutter every frame line starts with. The
/// TOTAL column's figures used to end flush against the right rail
/// (the owner's "too near the border, hard to see" — the digits and
/// the rail glyph fought for the same column); now the rightmost
/// numeric cell closes at the gutter's edge with the same two
/// columns of air the rank enjoys on the left. The label column
/// absorbs the gutter, so a full row still composes to an exact
/// width — just two columns short of the content inset, and the
/// border's fit() pads the rest.
///
/// NIGHT-boost-5: the header rank cell is blank (the owner's "#"
/// header retired) and the absorption math makes every data row end
/// at the right gutter's edge — the label column absorbs exactly what
/// the rank cell, the gaps, the numeric columns, and the right
/// gutter leave. The old reserve formula over-allocated three spare
/// columns, leaving every row 3 short of the separator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EagleColumns {
    pub(crate) label_w: usize,
    pub(crate) dl_w: usize,
    pub(crate) ul_w: usize,
    pub(crate) show_total: bool,
}

/// Plan the eagle-eyes column layout for a given terminal width.
#[must_use]
pub(crate) fn plan_eagle_columns(width: usize) -> EagleColumns {
    const RANK_W: usize = 6; // 2 gutter + 2 rank digits + 2 gap
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;
    // The symmetric right gutter (NIGHT-engrave-4): the two columns
    // of air after the TOTAL column, mirroring the two the left
    // gutter gives the rank. Narrow-floor frames drop it first —
    // survival outranks harmony below the ladder.
    const RIGHT_GUTTER: usize = 2;

    // Full layout: rank + label + 3 numeric columns (dl, ul, total).
    // Reserve = rank cell + 3 x (gap + numeric) + the right gutter:
    // the label absorbs the rest, so a full row ends exactly at the
    // right gutter's edge — never flush against the rail.
    if width >= RANK_W + LABEL_MIN + 3 * (1 + NUM_W) + RIGHT_GUTTER {
        return EagleColumns {
            label_w: width - RANK_W - 3 * (1 + NUM_W) - RIGHT_GUTTER,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: true,
        };
    }

    // TOTAL dropped (the session figure survives in the focus view;
    // the live rates are the realtime sacrifice ladder's first cut):
    // rank + label + 2 numeric columns — the right gutter rides
    // along (the UPLOAD figures close at the gutter's edge too).
    if width >= RANK_W + LABEL_MIN + 2 * (1 + NUM_W) + RIGHT_GUTTER {
        return EagleColumns {
            label_w: width - RANK_W - 2 * (1 + NUM_W) - RIGHT_GUTTER,
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: false,
        };
    }

    // Narrow fallback: tighter numerics, label pinned to the minimum.
    EagleColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        show_total: false,
    }
}

/// Truncate a label to `w` display columns, appending an ellipsis
/// when truncation happens. Handles the ellipsis itself taking a
/// column (same approach as display.rs).
#[must_use]
pub(crate) fn truncate_label(label: &str, w: usize) -> String {
    if label.chars().count() <= w {
        return label.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let take = w.saturating_sub(1);
    let mut out: String = label.chars().take(take).collect();
    out.push('…');
    out
}

/// Convert a per-frame byte delta into a bytes-per-second figure.
///
/// NIGHT-boost-22 overflow audit: the f64 division carries the full
/// u64 range losslessly for display purposes (u64::MAX as f64 stays
/// inside f64's exact-integer range's rounding tolerance for a
/// one-decimal SI figure), and Rust's float-to-int `as` cast
/// SATURATES rather than wrapping — a saturated counter divides,
/// rounds, and casts back to u64::MAX, which the extended
/// format_bytes ladder then renders as the honest "18.4 EB/s".
#[must_use]
pub(crate) fn rate_bps(delta_bytes: u64, interval: std::time::Duration) -> u64 {
    let secs = interval.as_secs_f64();
    if secs <= 0.0 {
        return 0;
    }
    ((delta_bytes as f64) / secs).round() as u64
}

/// Like [`format_rate`] but renders an em dash for zero — "BLOCKED"
/// is a policy verdict, not a traffic observation.
#[must_use]
pub(crate) fn format_rate_or_dash(bps: u64) -> String {
    if bps == 0 {
        "—".to_string()
    } else {
        format_rate(bps)
    }
}

/// Render a monitor uptime (NIGHT-boost-17, improve-27): the two most
/// significant units, auto-scaled — the owner's exact examples
/// `1m:10s`, `1h:1m`, `1d:1h`, no zero padding anywhere (the owner's
/// samples carry natural digit counts, not clock padding).
///
/// Ladder: under a minute `45s`; under an hour `12m:34s`; under a day
/// `3h:7m`; beyond `2d:5h`. The u64 seconds horizon (~585 billion
/// years) cannot be reached by a monitor, so the day tier is the
/// terminal one by construction.
#[must_use]
pub(crate) fn format_uptime(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let rem_secs = secs % 60;
    if days > 0 {
        format!("{days}d:{hours}h")
    } else if hours > 0 {
        format!("{hours}h:{mins}m")
    } else if mins > 0 {
        format!("{mins}m:{rem_secs}s")
    } else {
        format!("{rem_secs}s")
    }
}

/// Render the title bar — the frame's TOP BORDER (NIGHT-boost-20):
/// bold purple brand text, filled to the full frame width, with
/// rounded corners connecting to the bar's own fill (the cosmostrix
/// msg-border look). Identity only since NIGHT-engrave-3: the
/// top-right key hint retired at the owner's call — the legend's
/// only home is the footer's status line, which is why that row
/// rides every compression tier.
///
/// Shape: `╭─── <core> <fill> ─╮` (the corner cap degrades before the
/// bar loses its fill on narrow frames). The two-column gutter
/// behind the core matches every row, separator, and footer line —
/// the frame's left rail is one straight edge (NIGHT-boost-5); the
/// full-width fill is the flagship anchor: the eye locks onto the
/// purple bar and instantly reads the frame width, corners included.
#[must_use]
pub(crate) fn title_bar(core: &str, width: usize) -> String {
    const PREFIX: &str = "╭─── ";
    const CAP: &str = "─╮";
    let prefix_len = PREFIX.chars().count();
    let cap_len = CAP.chars().count();
    let core_len = core.chars().count();

    if width <= prefix_len + core_len + 1 {
        // Degenerate width: core only, no fill, no cap.
        return brand_bold(&format!("{PREFIX}{core}"));
    }

    // The corner cap closes the bar whenever the width can carry it;
    // a tiny frame carries the fill alone, cornerless.
    let tail = if width >= prefix_len + core_len + 1 + cap_len {
        CAP.to_string()
    } else {
        String::new()
    };

    let used = prefix_len + core_len + 1;
    let fill = "─".repeat(width.saturating_sub(used + tail.chars().count()));

    brand_bold(&format!("{PREFIX}{core} {fill}{tail}"))
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Labels truncate with an ellipsis and respect the budget.
    #[test]
    fn truncate_label_shapes() {
        assert_eq!(truncate_label("firefox", 10), "firefox");
        assert_eq!(
            truncate_label("rust-analyzer proc-macro srv", 12),
            "rust-analyz…"
        );
        assert_eq!(truncate_label("ab", 2), "ab");
        assert_eq!(truncate_label("abc", 2), "a…");
    }

    /// Rate conversion: interval-scaling and rounding.
    #[test]
    fn rate_bps_scales_with_interval() {
        assert_eq!(rate_bps(1500, std::time::Duration::from_secs(1)), 1500);
        assert_eq!(rate_bps(1500, std::time::Duration::from_secs(5)), 300);
        // Rounds to nearest, not truncates: 1001/5 = 200.2 -> 200,
        // 1004/5 = 200.8 -> 201.
        assert_eq!(rate_bps(1001, std::time::Duration::from_secs(5)), 200);
        assert_eq!(rate_bps(1004, std::time::Duration::from_secs(5)), 201);
        assert_eq!(rate_bps(999, std::time::Duration::ZERO), 0);
    }

    /// Zero traffic renders an em dash, never "BLOCKED" — the monitor
    /// observes, it does not judge.
    #[test]
    fn zero_rate_renders_dash() {
        assert_eq!(format_rate_or_dash(0), "—");
        assert_eq!(format_rate_or_dash(1000), "1.0 KB/s");
    }

    /// Uptime ladder (NIGHT-boost-17): the owner's exact samples —
    /// `1m:10s`, `1h:1m`, `1d:1h` — plus the tier edges, with NO
    /// zero padding anywhere (natural digit counts, the owner's
    /// wording, not clock formatting).
    #[test]
    fn uptime_ladder_matches_the_owner_samples() {
        use std::time::Duration;
        // The owner's three examples, verbatim.
        assert_eq!(format_uptime(Duration::from_secs(70)), "1m:10s");
        assert_eq!(format_uptime(Duration::from_secs(3_660)), "1h:1m");
        assert_eq!(format_uptime(Duration::from_secs(90_000)), "1d:1h");
        // Tier edges: under a minute, exact minute, exact hour, day.
        assert_eq!(format_uptime(Duration::ZERO), "0s");
        assert_eq!(format_uptime(Duration::from_secs(45)), "45s");
        assert_eq!(format_uptime(Duration::from_secs(59)), "59s");
        assert_eq!(format_uptime(Duration::from_secs(60)), "1m:0s");
        assert_eq!(format_uptime(Duration::from_secs(3_599)), "59m:59s");
        assert_eq!(format_uptime(Duration::from_secs(3_600)), "1h:0m");
        assert_eq!(format_uptime(Duration::from_secs(86_399)), "23h:59m");
        assert_eq!(format_uptime(Duration::from_secs(86_400)), "1d:0h");
        // Sub-second precision truncates to whole seconds (the
        // monitor's own wake granularity is 50ms).
        assert_eq!(format_uptime(Duration::from_millis(1_250)), "1s");
    }

    /// Title bar (NIGHT-boost-20 shape): rounded top border, exact
    /// width, graceful degradation on narrow frames. NIGHT-boost-5
    /// lineage: the bar carries the gutter every other frame line
    /// uses. NIGHT-engrave-1: the hint led with the theme key;
    /// NIGHT-engrave-2: identity only (the legend moved to the
    /// footer's status line); NIGHT-engrave-3: the hint itself
    /// retired — the top-right corner belongs to the fill alone.
    #[test]
    fn title_bar_fills_width() {
        let bar = title_bar("zelynic eagle-eyes", 80);
        // Mono mode (tests run piped): plain text, exact width.
        assert_eq!(bar.chars().count(), 80);
        assert!(bar.starts_with("╭─── zelynic eagle-eyes"));
        assert!(bar.ends_with("───╮"));
        assert!(
            !bar.contains("t theme") && !bar.contains("q quit"),
            "engrave-3: the key hint is gone from the top-right, the\nlegend lives in the footer's status line alone: {bar}"
        );

        // Narrow: core only, still starts with the cornered brand prefix.
        let tiny = title_bar("zelynic eagle-eyes", 10);
        assert!(tiny.starts_with("╭─── zelynic eagle-eyes"));

        // Medium: the fill carries to the corner cap, no hint.
        let mid = title_bar("zelynic eagle-eyes", 40);
        assert!(!mid.contains("t theme"));
        assert!(mid.ends_with('╮'));
        assert_eq!(mid.chars().count(), 40);
    }
}
