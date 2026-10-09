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
//! Symmetric-margin contract (NIGHT-engrave-8): the frame composes
//! ONE column inside the terminal — a leading space before the left
//! rail, an unpainted final column after the right rail, both rails
//! exactly one column from the edges (the owner's "both 1px
//! margins"). The unpainted last column is terminal physics, not
//! just looks: painting into it leaves the cursor pending-wrap,
//! where the emission's trailing erase-to-EOL behaves differently
//! per terminal (some eat the just-written right rail) — the frame
//! never touches it, so the right edge renders identically
//! everywhere.
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
//! Realtime interval: callers pass the configured poll cadence (the
//! status line's identity, clamped 1s..60s at parse time in
//! `parse_monitor_interval`) AND the MEASURED poll-to-poll span
//! (NIGHT-lts-3) the RATE columns divide per-frame deltas by — the
//! counters accumulated over the measured span, so bytes-per-second
//! reads exact, not cadence-approximate (the beat scheduler fires on
//! the first 50ms wake past the cadence).
//!
//! Module map (mirrors the limiter/ split, owner LOC cap):
//! - [`eagle`] — the ranked eagle-eyes renderer (default + filtered)
//! - [`footer`] — the pinned grip footer: tiers, grips, the build
//!   (NIGHT-boost-14, split from eagle by the cohesion discipline)
//! - [`rank`] — the footer's top-consumer ranking: the champion
//!   cgroup's hungriest process by joined bytes (NIGHT-dinner-6)
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

mod baseline;
mod baseline_panel;
mod border;
mod bypass;
mod depth_json;
mod depth_traffic;
mod detail;
mod eagle;
mod focus;
mod footer;
mod loading;
mod rank;
mod report;
// night-improve-58: the eagle-eyes scroll state (the six-key
// contract the ranked frame's two sections answer to).
mod scroll;
mod session;
mod targets;

#[cfg(test)]
// NIGHT-hunt-17: the A/B frame harness is a test file, so it lives
// under the repo's single test/ tree (cosmostrix Pattern C) and is
// #[path]-wired back here. frame-bench.py still finds it by test
// name (frame_bench_eagle), not by path.
#[path = "../../test/ebpf/render/bench.rs"]
mod bench;

pub use eagle::render_eagle_eyes;

// night-improve-58: the handler's render closure owns the scroll
// state; the renderers clamp it.
pub(crate) use scroll::ScrollState;

// NIGHT-improve-1a (EAGLE EYES V2): the ring lens + learned state
// the eagle renderer renders (pub(crate) like SessionState).
pub(crate) use baseline::BaselineLane;

// NIGHT-master-1: the eagle-eyes --depth report — composition only,
// pure over assembled facts. NIGHT-blade-5: the JSON half lives in
// the depth_json sibling and keeps its stable scripting shape.
pub use depth_json::depth_doc_json;
pub use report::{
    depth_report_lines, package_name, window_dropped_bytes, DepthReport, Enforcement,
};

// NIGHT-upgrade-charger-core-1-a: the bypass audit's report section
// — the machine-scope shadow verdict the depth handler prints after
// the per-target blocks (pure, fixture-pinned).
pub use bypass::bypass_section;

// NIGHT-private-research-3: the depth report's network-traffic
// focus — the measured window value the handler assembles and the
// report/JSON renderers consume (pure, fixture-pinned).
pub(crate) use depth_traffic::traffic_focus;

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
use crate::output::theme;
use crate::output::{brand_bold, capability, display_width, ColorCapability};

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
/// Degradation ladder (the 7-column rank reserve of night-improve-61
/// — its 3-column `=> ` marker lane — engrave-4's 2-column right gutter):
/// - width >= 54: (rank) | top process | download | upload | total
/// - width >= 43: (rank) | top process | download | upload (total dropped)
/// - width  < 43: (rank) | top process (min 12) | download | upload at 9-wide
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
    const RANK_W: usize = 7; // 3 marker lane + 2 rank digits + 2 gap
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;
    // The symmetric right gutter (NIGHT-engrave-4): the two columns
    // of air after the TOTAL column (the left lane is the `=> `
    // marker's estate since night-improve-61). Narrow-floor frames
    // drop it first — survival outranks harmony below the ladder.
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

/// Truncate a label to `w` DISPLAY columns, appending an ellipsis
/// when truncation happens. NIGHT-lts-1: the budget counts rendered
/// columns (the CJK/fullwidth glyph class paints two per char),
/// routed through the output layer's canonical [`fit_to_width`] —
/// the pre-lts-1 form counted chars, so a five-ideograph name sat
/// inside every budget while painting twice it.
#[must_use]
pub(crate) fn truncate_label(label: &str, w: usize) -> String {
    crate::output::fit_to_width(label, w)
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

/// The u128 twin of [`rate_bps`] (NIGHT-lts-5): the AVG speed pair
/// divides the SESSION legs — u128 since lts-5, honestly summable
/// past the exabyte into zettabyte territory — by the session
/// uptime. The quotient is cast back to u64 (saturating, Rust's
/// `as` discipline): a session AVERAGING above 18.4 EB/s is not a
/// figure any real link produces, and the rate display's own
/// ladder tops out at the u64 domain regardless — the wide
/// integer's job is the dividend's exactness, not a wider rate.
pub(crate) fn rate_bps_wide(delta_bytes: u128, interval: std::time::Duration) -> u64 {
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
/// NIGHT-engrave-11 (the horizontal masterclass): at the
/// sweep-capable depths the bar's furniture (the corner, the flank
/// fills, the closing corner) paints per column with
/// the SAME chroma method the vertical rails ride — the wave runs
/// across the bar (dark edges, glowing center), while the core
/// label stays FLAT bold brand (identity, not furniture: the
/// sweep's dark anchor must never dim the name). The wave's
/// positions advance THROUGH the label's columns, so the fill
/// resumes exactly where the label leaves off. Color16 and Mono
/// keep the exact flat bytes (sixteen colors cannot ramp within
/// one hue; Mono never painted).
///
/// Shape: `╭───…─── <core> ───…───╮` (the flank runs balance around
/// the core; the bar degrades to the plain fill before it loses its
/// corners). NIGHT-engrave-12: the core rides the MIDDLE of the bar
/// — the former fixed `╭─── ` prefix hugged the identity to the
/// top-left corner; the leftover columns now flank it as two
/// balanced dash runs (the floor on the left, the remainder on the
/// right — Rust's own `{:^}` centering convention), one rendered
/// gutter each side. The centering is the bar's own law: every
/// surface that speaks through this composer (eagle, focus, depth
/// report, loading, status, list-apps) centers together.
#[must_use]
pub(crate) fn title_bar(core: &str, width: usize) -> String {
    const CAP: &str = "─╮";
    // NIGHT-lts-1: the core's budget is its RENDERED width — the
    // focus title carries a cgroup's comm, and a CJK name paints
    // two columns per char (the fill math below follows the same
    // measurement; the rails depend on the bar landing exactly on
    // `width` columns).
    //
    // NIGHT-improve-36: the bar ALWAYS lands on exactly `width`
    // columns — the same fit-to-width contract every other frame
    // row carries. The core truncates with an ellipsis before the
    // bar loses its shape; identity degrades gracefully, geometry
    // never breaks.
    let cap_len = display_width(CAP);
    let core_len = display_width(core);

    if width == 0 {
        return String::new();
    }

    // Too narrow to carry a cornered, guttered core (five columns
    // or fewer): the fill carries the bar alone (cornered when the
    // width can carry the cap, plain otherwise). The bar's purple
    // shape still spans the full width so the frame stays
    // rectangular on the narrowest terminals.
    if width <= 5 {
        let tail = if width >= cap_len { CAP } else { "" };
        let glyphs = format!(
            "{}{}",
            "─".repeat(width.saturating_sub(display_width(tail))),
            tail
        );
        if matches!(
            capability(),
            ColorCapability::Mono | ColorCapability::Color16
        ) {
            return brand_bold(&glyphs);
        }
        return swept_bar(&glyphs, None, width);
    }

    // The centered core's budget: two corners, two gutters, and one
    // flank dash a side are reserved; everything else is the core's.
    const RESERVED: usize = 6;
    let budget = width.saturating_sub(RESERVED);
    let fitted = if core_len == 0 || budget == 0 {
        String::new()
    } else if core_len <= budget {
        core.to_string()
    } else {
        truncate_label(core, budget)
    };
    let fitted_len = display_width(&fitted);

    let (glyphs, text) = if fitted_len == 0 {
        // The plain bar (width six, or a core too wide to carry one
        // glyph): corners and fill only — geometry first, identity
        // already yielded everything it had.
        (format!("╭{}╮", "─".repeat(width - 2)), None)
    } else {
        let dashes = width - 4 - fitted_len;
        let left = dashes / 2;
        (
            format!(
                "╭{} {fitted} {}╮",
                "─".repeat(left),
                "─".repeat(dashes - left)
            ),
            Some((left + 2, fitted_len)),
        )
    };
    if matches!(
        capability(),
        ColorCapability::Mono | ColorCapability::Color16
    ) {
        return brand_bold(&glyphs);
    }
    // The label's first column sits one corner + one flank run + one
    // gutter in; its span is the RENDERED width (NIGHT-lts-1 — a
    // CJK name paints two columns per char).
    swept_bar(&glyphs, text, width)
}

/// NIGHT-engrave-11: the swept bar composer. `glyphs` is the bar's
/// one-char-per-column row (corner, flank fill, label, gutter,
/// flank fill, corner — NIGHT-engrave-12 centered the label); the
/// wave runs across the whole `width`, each
/// furniture glyph painted by the chroma method the vertical rails
/// ride ([`border::sweep_run`] at its own column), while the
/// `text` columns (start, rendered length) stay FLAT bold brand —
/// the label is identity, the sweep is furniture. One bold open
/// and one reset for the whole bar: no inner reset ever closes the
/// terminal background the border wrap opens on row 0
/// (NIGHT-boost-26); the per-column fg escapes replace the
/// foreground only. Bare spaces (the prefix gutter, the separator)
/// paint nothing — the background shows through exactly as the
/// flat bar's brand-colored spaces read.
fn swept_bar(glyphs: &str, text: Option<(usize, usize)>, width: usize) -> String {
    let theme = theme::active();
    let cap = capability();
    // One anchor derivation for the whole bar (the border wrap's
    // per-frame contract — the columns share it).
    let anchor = crate::output::chroma::scale_lightness(theme.brand_rgb(), border::DARK_FACTOR);
    let (text_start, text_end) = text.map_or((usize::MAX, usize::MAX), |(s, len)| {
        (s, s.saturating_add(len))
    });
    let mut bar = String::with_capacity(width * 24 + 32);
    // The render tree assembles its own escapes (the NIGHT-boost-20
    // exception — the border gradient family builds its own ramp
    // bytes; the color layer's wrappers stay the CLI surface's
    // whole API). The bold open carries the brand fg the label
    // inherits; the swept columns replace the fg only, so the bold
    // weight spans the whole bar exactly as the flat bar's did.
    bar.push_str(theme::escape(theme::Slot::Brand, true));
    let mut col = 0usize;
    // The furniture composes in BATCHED runs (the hoist's string
    // half): one sweep_run per contiguous same-glyph stretch, not
    // one call per glyph — the sweep's own per-run endpoint hoist
    // only pays when the run is long.
    let mut seg: Option<(usize, char)> = None;
    for g in glyphs.chars() {
        let in_text = col >= text_start && col < text_end;
        let furniture = !in_text && g != ' ';
        if furniture {
            match seg {
                Some((_s, open)) if open == g => {}
                Some((s, open)) => {
                    bar.push_str(&border::sweep_run(
                        open,
                        s,
                        col - s,
                        width,
                        theme,
                        Some(anchor),
                        cap,
                    ));
                    seg = Some((col, g));
                }
                None => seg = Some((col, g)),
            }
        } else {
            if let Some((s, open)) = seg.take() {
                bar.push_str(&border::sweep_run(
                    open,
                    s,
                    col - s,
                    width,
                    theme,
                    Some(anchor),
                    cap,
                ));
            }
            // The label's chars and the bare spaces paint nothing
            // here — the open SGR's bold brand colors the label
            // (identity), the background shows through the spaces.
            bar.push(g);
        }
        // The same rendered-width walk the fit path carries (the
        // ASCII fast path inlined at the call site).
        col += if (g as u32) < 0x0300 {
            1
        } else {
            crate::output::char_width(g)
        };
    }
    if let Some((s, open)) = seg.take() {
        bar.push_str(&border::sweep_run(
            open,
            s,
            col - s,
            width,
            theme,
            Some(anchor),
            cap,
        ));
    }
    bar.push_str(border::RESET);
    bar
}
// NON_LATIN_FIXTURE: the CJK literal in the truncation pin below is
// runtime width-measurement coverage, not prose (the same exemption
// sanitize.rs carries for its passthrough pin).
#[cfg(test)]
mod tests {
    use super::*;

    /// Labels truncate with an ellipsis and respect the budget —
    /// the RENDERED budget (NIGHT-lts-1): a CJK name degrades to
    /// whole ideographs plus the ellipsis inside the column.
    #[test]
    fn truncate_label_shapes() {
        assert_eq!(truncate_label("firefox", 10), "firefox");
        assert_eq!(
            truncate_label("rust-analyzer proc-macro srv", 12),
            "rust-analyz…"
        );
        assert_eq!(truncate_label("ab", 2), "ab");
        assert_eq!(truncate_label("abc", 2), "a…");
        // The width class the char-counting form missed: five
        // ideographs paint ten columns; a 6-column budget holds two
        // ideographs and the ellipsis (5 rendered columns).
        assert_eq!(truncate_label("谷歌浏览器", 6), "谷歌…");
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
    /// width, graceful degradation on narrow frames. NIGHT-engrave-12:
    /// the core rides the MIDDLE of the bar — balanced flank runs,
    /// one gutter each side, the floor left and the remainder right
    /// (the `{:^}` convention). NIGHT-engrave-1: the hint led with
    /// the theme key; NIGHT-engrave-2: identity only (the legend
    /// moved to the footer's status line); NIGHT-engrave-3: the hint
    /// itself retired — the corners belong to the fill alone.
    #[test]
    fn title_bar_fills_width() {
        let bar = title_bar("zelynic eagle-eyes", 80);
        // Mono mode (tests run piped): plain text, exact width. The
        // centered title at 80: (80 - 4 - 18) / 2 = 29 flank dashes
        // a side around one gutter each side.
        assert_eq!(bar.chars().count(), 80);
        assert_eq!(
            bar,
            format!(
                "\u{256d}{} zelynic eagle-eyes {}\u{256e}",
                "─".repeat(29),
                "─".repeat(29)
            ),
            "engrave-12: the title sits dead center, flanks balanced"
        );
        assert!(
            !bar.contains("t theme") && !bar.contains("q quit"),
            "engrave-3: the key hint is gone from the top-right, the\nlegend lives in the footer's status line alone: {bar}"
        );

        // Narrow (NIGHT-improve-36): the core truncates with an
        // ellipsis so the bar lands on EXACTLY `width` columns —
        // no overflow, no wrap, no alignment shift on the narrowest
        // terminals. The centered form keeps one flank dash a side
        // even under the tightest fit (10 - 4 - 4 = 2).
        let tiny = title_bar("zelynic eagle-eyes", 10);
        assert_eq!(tiny.chars().count(), 10);
        assert_eq!(tiny, "╭─ zel… ─╮");

        // Medium: the flanks carry to both corners, no hint.
        let mid = title_bar("zelynic eagle-eyes", 40);
        assert_eq!(
            mid,
            format!(
                "\u{256d}{} zelynic eagle-eyes {}\u{256e}",
                "─".repeat(9),
                "─".repeat(9)
            )
        );
        assert!(!mid.contains("t theme"));
        assert!(mid.ends_with('╮'));
        assert_eq!(mid.chars().count(), 40);
    }

    /// Narrow-width ladder (NIGHT-improve-36): the title bar's
    /// inviolable contract is that it lands on EXACTLY `width`
    /// columns at every width — the bar never overflows, never
    /// wraps, never shifts the rows below it. The full-core shape
    /// holds while the budget carries it; the ellipsis degrades the
    /// identity one glyph at a time below that; the fill-only floor
    /// keeps the bar's purple shape rectangular on the narrowest
    /// terminals. This pin walks the ladder end to end.
    #[test]
    fn title_bar_narrow_never_overflows() {
        let core = "zelynic eagle-eyes";
        // Every width from 0 to 80: the bar is exactly `width` cols
        // (chars().count() == display_width here — ASCII core + box
        // drawing, every glyph one column).
        for w in 0..=80usize {
            let bar = title_bar(core, w);
            assert_eq!(
                bar.chars().count(),
                w,
                "title_bar must land on exactly {w} cols (got {}): {bar:?}",
                bar.chars().count()
            );
        }

        // The identity holds while the budget carries the full core:
        // at width 24 (corners 2 + gutters 2 + core 18 + flanks 2)
        // the full core is intact and cornered, the flanks one dash
        // a side (NIGHT-engrave-12: the centered form carries the
        // full core one column lower than the old left-hugging
        // prefix — no fixed five-column rent on the identity).
        let just_fits = title_bar(core, 24);
        assert_eq!(just_fits.chars().count(), 24);
        assert_eq!(just_fits, "╭─ zelynic eagle-eyes ─╮");

        // One col narrower: the ellipsis takes the first downgrade
        // (the budget drops to 17, the core yields to 16 cols + the
        // ellipsis; the flanks keep one dash a side).
        let ellipsis_floor = title_bar(core, 23);
        assert_eq!(ellipsis_floor.chars().count(), 23);
        assert_eq!(ellipsis_floor, "╭─ zelynic eagle-ey… ─╮");
        assert!(ellipsis_floor.contains('…'));

        // Width six: the core cannot carry one glyph — the plain
        // bar keeps both corners and the fill, rectangular.
        assert_eq!(title_bar(core, 6), "╭────╮");
        // Width seven: the ellipsis alone rides the middle.
        assert_eq!(title_bar(core, 7), "╭─ … ─╮");

        // Below the prefix: the fill carries the bar alone — no
        // prefix, no core, just the purple shape, still rectangular.
        let floor = title_bar(core, 3);
        assert_eq!(floor.chars().count(), 3);
        assert!(floor.chars().all(|c| c == '─' || c == '╮'));

        // Zero width: the empty string (no allocation worth painting).
        assert_eq!(title_bar(core, 0), "");

        // CJK core (NIGHT-lts-1 lineage): two columns per ideograph,
        // the budget counts rendered columns, the bar still lands
        // exactly on `width` (display columns, not code points —
        // chars().count() undercounts CJK by half).
        let cjk = title_bar("谷歌浏览器监控", 16);
        assert_eq!(display_width(&cjk), 16);
    }
}
