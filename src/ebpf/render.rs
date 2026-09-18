// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Responsive render engine for the observe/top monitors (NIGHT-hunt-7).
//!
//! Owner contract: "boring but elegant flagship". One purple title
//! bar, one thin header row, right-aligned numerics, no per-cell
//! noise (the old layout packed "89 (1.2 MB)" into single cells).
//! Purple is branding (NIGHT-hunt-5): the title bar renders bold
//! purple and the column headers regular purple — the same #A855F7
//! source of truth as the rest of the output layer.
//!
//! Dynamic screen size: width AND height are re-probed on every
//! frame (two cheap TIOCGWINSZ ioctls — the same call
//! `terminal_width()` already made per status print). Resizing the
//! terminal adapts the layout on the next refresh: no SIGWINCH
//! plumbing, no stale geometry, no caches to invalidate. Columns
//! degrade gracefully on narrow terminals (RATE drops first, then
//! TOTAL), the label column absorbs the remaining width, and the
//! row count is capped by the available height so a frame never
//! scrolls off the alt screen.
//!
//! Realtime interval: callers pass the poll interval so the RATE
//! column converts per-frame deltas into bytes-per-second
//! (`--interval`, clamped 1s..60s at parse time in
//! `parse_monitor_interval`).
//!
//! Module map (mirrors the limiter/ split, owner LOC cap):
//! - [`observe`] — the aggregate + single-cgroup observe renderers
//! - [`top`] — the top-talkers renderer (live + snapshot)
//! - `bench` (cfg(test)) — the frame A/B benchmark harness
//! - this root — geometry probing, column budgets, shared helpers,
//!   and the NIGHT-hunt-8 connection-detail lines (label +N suffix,
//!   per-process endpoint lines shared by observe and top)

mod detail;
mod observe;
mod top;

#[cfg(test)]
mod bench;

pub use observe::{render_observe_filtered, render_observe_frame};
pub use top::{render_top_table, TopMode};

pub(crate) use detail::{comm_from_label, detail_lines, full_detail_lines, label_with_count};

use crate::ebpf::limiter::{format_rate, terminal_height, terminal_width};
use crate::output::brand_bold;

/// Hard cap on table rows regardless of terminal height (matches the
/// pre-NIGHT-hunt-7 display cap of 20 — above that a monitor stops
/// being a summary and starts being a firehose).
pub(crate) const MAX_ROWS: usize = 20;

/// Vertical budget consumed by everything that is not a data row:
/// title, column header, separator, footer separator, totals line,
/// and one line of breathing room top and bottom.
pub(crate) const CHROME_LINES: usize = 7;

// ── Geometry ────────────────────────────────────────────────────────────────

/// Terminal size for one frame. Probed fresh on every render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameGeometry {
    pub width: usize,
    pub height: usize,
}

impl FrameGeometry {
    /// Probe the current terminal size (columns and rows).
    ///
    /// Falls back to 80x24 when stdout is not a TTY (piped output,
    /// tests, benchmark harnesses) — the same fallback contract as
    /// `terminal_width()`.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            width: terminal_width(),
            height: terminal_height(),
        }
    }
}

/// Data rows that fit between the chrome, clamped to [1, MAX_ROWS].
#[must_use]
pub(crate) fn rows_for_height(height: usize) -> usize {
    height.saturating_sub(CHROME_LINES).clamp(1, MAX_ROWS)
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
/// Shape: `─── <core> ─────…──── <hint>` (hint omitted on narrow
/// frames). The full-width fill is the flagship anchor: the eye
/// locks onto the purple bar and instantly reads the frame width.
#[must_use]
pub(crate) fn title_bar(core: &str, hint: &str, width: usize) -> String {
    const PREFIX: &str = "─── ";
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

    /// Row budget: chrome reserved, clamped to [1, MAX_ROWS].
    #[test]
    fn rows_for_height_ladder() {
        assert_eq!(rows_for_height(80), MAX_ROWS);
        assert_eq!(rows_for_height(24), 24 - CHROME_LINES);
        assert_eq!(rows_for_height(10), 3);
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
    /// degradation on narrow frames.
    #[test]
    fn title_bar_fills_width() {
        let bar = title_bar("zelynic observe — 1s refresh", "q/ESC quit", 80);
        // Mono mode (tests run piped): plain text, exact width.
        assert_eq!(bar.chars().count(), 80);
        assert!(bar.starts_with("─── zelynic observe — 1s refresh"));
        assert!(bar.ends_with("q/ESC quit"));

        // Narrow: core only, still starts with the brand prefix.
        let tiny = title_bar("zelynic top", "", 10);
        assert!(tiny.starts_with("─── zelynic top"));

        // Medium: hint suppressed before it would collide with core.
        let mid = title_bar("zelynic observe — 1s refresh", "q/ESC quit", 40);
        assert!(!mid.contains("q/ESC"));
        assert_eq!(mid.chars().count(), 40);
    }
}
