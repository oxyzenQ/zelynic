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
//! subprocess detail hides with it), the label column absorbs the
//! remaining width, and the frame is pinned to the FULL terminal
//! height (NIGHT-boost-14): the table floats under the header and
//! the footer stays near the bottom — the grip block never follows
//! the table's length. A short window compresses the footer through
//! a compact ladder (blanks drop, then the grips, then the discovery
//! hints) before the table loses its rows.
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
//! - `bench` (cfg(test)) — the frame A/B benchmark harness (wired in
//!   from `test/ebpf/render/bench.rs`, NIGHT-hunt-17)
//! - this root — geometry probing, column budgets, shared helpers,
//!   and the NIGHT-hunt-8 connection-detail lines (label +N suffix,
//!   per-process endpoint lines shared by eagle and focus)

mod detail;
mod eagle;
mod focus;
mod footer;
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
/// Degradation ladder (6-column rank cell, 1-column gaps):
/// - width >= 51: (rank) | PROCESS | DOWNLOAD | UPLOAD | TOTAL
/// - width >= 40: (rank) | PROCESS | DOWNLOAD | UPLOAD   (TOTAL dropped)
/// - width  < 40: (rank) | PROCESS (min 12) | DOWNLOAD | UPLOAD at 9-wide
///
/// DOWNLOAD and UPLOAD carry per-frame RATES (delta / interval —
/// "what is moving right now"); TOTAL carries the session-accumulated
/// bytes (NIGHT-boost-5: the v10 "total accumulated" function
/// restored as the ranking key's own column). The old combined RATE
/// column was dl+ul restated — the TOTAL column replaces it.
///
/// NIGHT-boost-5: the header rank cell is blank (the owner's "#"
/// header retired) and the absorption math makes every data row end
/// flush at the frame width — the label column absorbs exactly what
/// the rank cell, the gaps, and the numeric columns leave, so the
/// right border (title bar, separators, rows, TOTAL) is one straight
/// edge mirroring the left. The old reserve formula over-allocated
/// three spare columns, leaving every row 3 short of the separator.
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

    // Full layout: rank + label + 3 numeric columns (dl, ul, total).
    // Reserve = rank cell + 3 x (gap + numeric): the label absorbs
    // the rest, so a full row spans exactly the frame width.
    if width >= RANK_W + LABEL_MIN + 3 * (1 + NUM_W) {
        return EagleColumns {
            label_w: width - RANK_W - 3 * (1 + NUM_W),
            dl_w: NUM_W,
            ul_w: NUM_W,
            show_total: true,
        };
    }

    // TOTAL dropped (the session figure survives in the focus view;
    // the live rates are the realtime sacrifice ladder's first cut):
    // rank + label + 2 numeric columns.
    if width >= RANK_W + LABEL_MIN + 2 * (1 + NUM_W) {
        return EagleColumns {
            label_w: width - RANK_W - 2 * (1 + NUM_W),
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

/// Render the title bar: bold purple brand text, em-dash filled to
/// the full frame width, key hint right-aligned when there is room.
///
/// Shape: `  ─── <core> ─────…──── <hint>` (hint omitted on narrow
/// frames). The two-column gutter matches every row, separator, and
/// footer line — the frame's left border is one straight edge
/// (NIGHT-boost-5; the old bar started at column 0 while the table
/// started at column 2, the big left-border gap the owner reported).
/// The full-width fill is the flagship anchor: the eye locks onto the
/// purple bar and instantly reads the frame width.
#[must_use]
pub(crate) fn title_bar(core: &str, hint: &str, width: usize) -> String {
    const PREFIX: &str = "  ─── ";
    let prefix_len = PREFIX.chars().count();
    let core_len = core.chars().count();

    if width <= prefix_len + core_len + 1 {
        // Degenerate width: core only, no fill, no hint.
        return brand_bold(&format!("{PREFIX}{core}"));
    }

    let hint_part = if !hint.is_empty() && width >= prefix_len + core_len + hint.chars().count() + 5
    {
        format!(" {hint}")
    } else {
        String::new()
    };

    // Rendered shape: PREFIX + core + ' ' + fill + hint_part.
    let used = prefix_len + core_len + 1 + hint_part.chars().count();
    let fill = "─".repeat(width.saturating_sub(used));

    brand_bold(&format!("{PREFIX}{core} {fill}{hint_part}"))
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

    /// Title bar: full-width fill, hint right-aligned, graceful
    /// degradation on narrow frames. NIGHT-boost-5: the bar carries
    /// the two-column gutter every other frame line uses — the left
    /// border is one straight edge.
    #[test]
    fn title_bar_fills_width() {
        let bar = title_bar("zelynic eagle-eyes — 1s refresh", "q quit", 80);
        // Mono mode (tests run piped): plain text, exact width.
        assert_eq!(bar.chars().count(), 80);
        assert!(bar.starts_with("  ─── zelynic eagle-eyes — 1s refresh"));
        assert!(bar.ends_with("q quit"));

        // Narrow: core only, still starts with the guttered brand prefix.
        let tiny = title_bar("zelynic eagle-eyes", "", 10);
        assert!(tiny.starts_with("  ─── zelynic eagle-eyes"));

        // Medium: hint suppressed before it would collide with core.
        let mid = title_bar("zelynic eagle-eyes — 1s refresh", "q quit", 40);
        assert!(!mid.contains("q quit"));
        assert_eq!(mid.chars().count(), 40);
    }
}
