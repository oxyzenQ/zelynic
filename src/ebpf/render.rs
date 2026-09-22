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
//! refresh: no SIGWINCH plumbing, no stale geometry, no caches to
//! invalidate. Columns degrade gracefully on narrow terminals (RATE
//! drops first), the label column absorbs the remaining
//! width, and the row count follows the terminal height
//! (NIGHT-boost-1: the former --limit and the hard 20-row cap are
//! gone — the window IS the budget) so a frame never scrolls off
//! the alt screen. The autodetect ladder (NIGHT-boost-5): the
//! chrome reserves 12 lines (title, header, separators, TOTAL row,
//! meta line, discovery hints, signature footer, breathing room),
//! so the owner's windowed 88x32 terminal shows a 20-row list, the
//! classic 80x24 shows 12, and a 22-line window still gets the
//! 10-row flagship floor.
//!
//! Realtime interval: callers pass the poll interval so the RATE
//! column converts per-frame deltas into bytes-per-second
//! (`--interval`, clamped 1s..60s at parse time in
//! `parse_monitor_interval`).
//!
//! Module map (mirrors the limiter/ split, owner LOC cap):
//! - [`eagle`] — the ranked eagle-eyes renderer (default + filtered)
//! - [`focus`] — the deep single-target view (autodetected focus)
//! - [`session`] — the session leaderboard: accumulated per-cgroup
//!   totals, rank-1 takeover blink bookkeeping (NIGHT-boost-5)
//! - `bench` (cfg(test)) — the frame A/B benchmark harness (wired in
//!   from `test/ebpf/render/bench.rs`, NIGHT-hunt-17)
//! - this root — geometry probing, column budgets, shared helpers,
//!   and the NIGHT-hunt-8 connection-detail lines (label +N suffix,
//!   per-process endpoint lines shared by eagle and focus)

mod detail;
mod eagle;
mod focus;
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

/// Vertical budget consumed by everything that is not a data row:
/// title, column header, separator, footer separator, the TOTAL
/// totals row, the packets/cgroups meta line, one blank line of
/// breathing room, the two discovery-hint lines (top consumer + the
/// strict-single tip, unfiltered frames), the signature footer, and
/// one spare row so the footer never sits on the terminal's last
/// line (improve-13: the run-on single footer line became a
/// column-aligned TOTAL row plus a meta line — one more chrome line
/// buys numbers that sit under the columns they sum, the flagship-grid
/// contract the data rows already follow; NIGHT-boost-5 added the
/// signature footer and the hints to the accounting, which pins the
/// owner's windowed 88x32 example at exactly 20 data rows).
pub(crate) const CHROME_LINES: usize = 12;

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

/// Data rows that fit between the chrome. The terminal height is
/// the ONLY budget (NIGHT-boost-1: the former --limit flag and the
/// hard 20-row cap are gone) — a short window shows the top few
/// consumers, a tall one spans the list down to the quiet apps.
/// Autodetect ladder (NIGHT-boost-5, owner contract: "default set
/// 10 if terminal height is enough ... if detect 32 cell 20 list"):
/// chrome reserves 12 lines, so a windowed 88x32 terminal shows a
/// 20-row list, the classic 80x24 shows 12, and a 22-line window
/// still gets the 10-row flagship density.
#[must_use]
pub(crate) fn rows_for_height(height: usize) -> usize {
    height.saturating_sub(CHROME_LINES).max(1)
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

    /// Row budget: chrome reserved, terminal height is the only cap
    /// (NIGHT-boost-1: no --limit, no hard 20-row ceiling).
    /// NIGHT-boost-5 autodetect ladder: 88x32 window -> 20 rows,
    /// classic 80x24 -> 12, the 10-row flagship floor at height 22.
    #[test]
    fn rows_for_height_ladder() {
        assert_eq!(rows_for_height(80), 80 - CHROME_LINES);
        assert_eq!(rows_for_height(32), 20, "owner's windowed 88x32 example");
        assert_eq!(rows_for_height(24), 12);
        assert_eq!(rows_for_height(22), 10, "flagship floor");
        assert_eq!(rows_for_height(12), 1);
        assert_eq!(rows_for_height(5), 1);
    }

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
