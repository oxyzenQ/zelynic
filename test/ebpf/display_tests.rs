// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the status display surface — kept in the repo's
//! single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C) and
//! #[path]-wired from display.rs. The NIGHT-engrave-5 pins hold the
//! eagle-eyes style match (lowercase headers, the line builders'
//! wording and order), the improve-13 one-metric-per-cell contract,
//! and the clean/stale branch chrome — no stdout capture needed.
//! The --print-json contract pins live in display_json_tests.rs
//! with the display_json module (the charger-core-3b split).

use super::super::display_lines::format_duration_compact;
use super::*;

/// improve-13 style pin: the human table's ALLOWED/DROPPED cells carry
/// ONE metric (bytes) — the per-cell packing "421 (1.4 MB)" is
/// retired; packet counts stay in `--print-json`. A missing direction
/// policy renders the em dash, never a zero.
#[test]
fn status_cells_one_metric_per_cell() {
    let d = DisplayData {
        window: None,
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
        cgroup_id: 73386,
        dl_bps: Some(100_000),
        ul_bps: Some(0),
        dl_per_socket: false,
        ul_per_socket: false,
        packets_allowed: 421,
        packets_dropped: 3,
        bytes_allowed: 1_400_000,
        bytes_dropped: 5_200,
    };
    let (label, dl, ul, allowed, dropped) = status_cells(&d, &IdentityMap::new());
    assert_eq!(label, "cg:73386");
    assert_eq!(dl, "100.0 KB/s");
    assert_eq!(ul, "BLOCKED");
    assert_eq!(allowed, "1.4 MB");
    assert_eq!(dropped, "5.2 KB");
    assert!(
        !allowed.contains('(') && !dropped.contains('('),
        "one metric per cell: {allowed} / {dropped}"
    );

    // charger-core-3b: the per-socket marker rides the RATE cells
    // (the number names a per-connection budget, not the cgroup
    // cap) and never the byte cells.
    let per_socket_row = DisplayData {
        window: None,
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
        cgroup_id: 73400,
        dl_bps: Some(500_000),
        ul_bps: Some(500_000),
        dl_per_socket: true,
        ul_per_socket: true,
        packets_allowed: 10,
        packets_dropped: 2,
        bytes_allowed: 5_000,
        bytes_dropped: 1_000,
    };
    let (_, dl, ul, allowed, dropped) = status_cells(&per_socket_row, &IdentityMap::new());
    assert_eq!(dl, "500.0 KB/s /socket");
    assert_eq!(ul, "500.0 KB/s /socket");
    assert_eq!(allowed, "5.0 KB");
    assert_eq!(dropped, "1.0 KB");

    // One-direction limit: the other side is an em dash, not a number.
    let one_sided = DisplayData {
        window: None,
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
        cgroup_id: 73390,
        dl_bps: None,
        ul_bps: Some(1_000_000),
        dl_per_socket: false,
        ul_per_socket: false,
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
    };
    let (_, dl, ul, allowed, dropped) = status_cells(&one_sided, &IdentityMap::new());
    assert_eq!(dl, "—");
    assert_eq!(ul, "1.0 MB/s");
    assert_eq!(allowed, "0 B");
    assert_eq!(dropped, "0 B");
}

/// NIGHT-hunt-Z7 (the owner's `-d 100.51kb` find): the rate cells
/// render through the EXACT twin — a configured 100,510 B/s reads
/// "100.51 KB/s", never the one-decimal "100.5 KB/s" that hid 10
/// B/s of the typed number. The measured ALLOWED/DROPPED cells keep
/// their one-decimal twin (running counters, the approximate display
/// they always carried) — the split is config-exact vs
/// measured-approximate, one rule, both sides.
#[test]
fn status_rate_cells_render_configured_rates_exactly() {
    let d = DisplayData {
        window: None,
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
        cgroup_id: 70896,
        dl_bps: Some(100_510),
        ul_bps: Some(50_000),
        dl_per_socket: false,
        ul_per_socket: false,
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
    };
    let (_, dl, ul, allowed, dropped) = status_cells(&d, &IdentityMap::new());
    assert_eq!(dl, "100.51 KB/s", "the typed rate survives the table");
    assert_eq!(ul, "50.0 KB/s", "a round rate keeps the family shape");
    assert_eq!(allowed, "0 B");
    assert_eq!(dropped, "0 B");
}

// ── NIGHT-engrave-5: the eagle-eyes style match pins ──────────────────
//
// The owner's audit: `sudo zelynic status` did not match the
// eagle-eyes style — uppercase headers, a plain separator, bare
// prose lines. These pins hold the corrected contract through the
// extracted pure builders (mono in the piped test environment — the
// color tier pins live in test/output/color_tests.rs).

/// Both report tables' headers are lowercase — the eagle-eyes table
/// contract (engrave-1 lowercased the monitor's titles; engrave-5
/// caught status and list-apps as the uppercase holdouts). No
/// ASCII uppercase letter may appear in either header row.
#[test]
fn report_table_headers_are_lowercase() {
    let status_header = status_header_line(&[10, 10, 8, 8, 8]);
    for title in ["cgroup", "download", "upload", "allowed", "dropped"] {
        assert!(
            status_header.contains(title),
            "the status header must carry '{title}', got: {status_header}"
        );
    }
    assert!(
        !status_header.chars().any(|c: char| c.is_ascii_uppercase()),
        "no uppercase carriers on the status header, got: {status_header}"
    );

    let list_header = list_apps_header_line(&[30, 7, 8, 10, 8]);
    for title in ["process", "procs", "sockets", "cgroup id", "uid"] {
        assert!(
            list_header.contains(title),
            "the list-apps header must carry '{title}', got: {list_header}"
        );
    }
    assert!(
        !list_header.chars().any(|c: char| c.is_ascii_uppercase()),
        "no uppercase carriers on the list-apps header, got: {list_header}"
    );
}

/// The header row starts at the two-column gutter every eagle-eyes
/// frame line shares, and the numeric titles right-align over their
/// columns (the same `{:>}` contract the monitor's header carries).
#[test]
fn status_header_aligns_over_its_columns() {
    let line = status_header_line(&[10, 12, 10, 10, 10]);
    assert!(
        line.starts_with("  cgroup"),
        "the label title leads at the gutter, got: {line:?}"
    );
    // download right-aligned in a 12-wide column: 4 spaces of padding.
    assert!(
        line.contains("     download"),
        "numeric titles right-align over their columns, got: {line:?}"
    );
}

/// One data row: the label leads at the gutter, the cells follow in
/// order, and the row composes to the shared format (the green tier
/// wrap is the color layer's business — mono here, pinned there).
#[test]
fn status_row_composes_the_shared_shape() {
    let row = (
        "brave".to_string(),
        "100.0 KB/s".to_string(),
        "1.0 MB/s".to_string(),
        "1.4 MB".to_string(),
        "5.2 KB".to_string(),
    );
    let line = status_row_line("brave", &row, &[10, 12, 10, 10, 10]);
    assert!(line.starts_with("  brave"), "label first, got: {line:?}");
    for cell in [&row.1, &row.2, &row.3, &row.4] {
        assert!(
            line.contains(cell.as_str()),
            "cell {cell} present, got: {line:?}"
        );
    }
}

/// The watchdog prose: lowercase, grey-family wording while armed,
/// the expired verdict names the dead state plainly.
#[test]
fn watchdog_wording_is_the_engrave5_contract() {
    assert_eq!(
        watchdog_line(Some(30)),
        "  watchdog: 30s remaining",
        "armed wording, got: {}",
        watchdog_line(Some(30))
    );
    assert_eq!(
        watchdog_line(None),
        "  watchdog: expired (bpf is no-op)",
        "expired wording, got: {}",
        watchdog_line(None)
    );
}

/// The census line: lowercase, subordinate family.
#[test]
fn active_limits_wording_is_lowercase() {
    assert_eq!(
        active_limits_line(2, 1),
        "  active limits: 2 dl, 1 ul",
        "census wording, got: {}",
        active_limits_line(2, 1)
    );
}

/// The branch frames carry the flagship chrome in the owner's
/// NIGHT-private-research-3 compact order: title bar, the story
/// line(s), stamp — the engrave-5 breathing gaps retired with the
/// rest of the report-surface fillers (the more-compact-and-simple
/// directive). The clean state's single line names the verdict; the
/// stale state carries the warn finding and the suggestion-white
/// command.
#[test]
fn status_branch_frames_carry_the_flagship_chrome() {
    for (name, lines, story_rows) in [
        ("clean", status_clean_lines(60), 1usize),
        ("stale", status_stale_lines(60), 2),
    ] {
        assert_eq!(
            lines.len(),
            story_rows + 2,
            "{name}: title + {story_rows} story + stamp, zero filler, got {} lines",
            lines.len()
        );
        // NIGHT-engrave-12: the centered title — the status bar
        // composes at the raw width (no frame_width inset here),
        // (60 - 4 - 14) / 2 = 21 flank dashes a side.
        assert!(
            lines[0].starts_with(&format!("╭{} zelynic status ", "─".repeat(21))),
            "{name}: the centered eagle title bar opens the frame, got: {}",
            lines[0]
        );
        assert!(
            !lines.iter().any(|l| l.is_empty()),
            "{name}: the compact frame carries no blank filler lines"
        );
        assert!(
            lines[lines.len() - 1].contains("by oxyzenQ"),
            "{name}: the signature stamp closes the frame, got: {}",
            lines[lines.len() - 1]
        );
    }

    let clean = status_clean_lines(60);
    assert!(
        clean[1].contains("no active limits"),
        "the clean verdict, got: {}",
        clean[1]
    );

    let stale = status_stale_lines(60);
    assert!(
        stale[1].contains("stale bpf pin files detected"),
        "the stale finding, got: {}",
        stale[1]
    );
    assert!(
        stale[2].contains("'zelynic recover'"),
        "the recovery command, got: {}",
        stale[2]
    );
}

// ── charger-core-3a: the rate_ring JSON contract pins ──────────────

// ── night-during, schema v23: the window lifetime line pins ───────

/// The compact duration renderer (the "(N left)" suffix): one unit,
/// CEILED (night-improve-60, the owner's 5h find — a countdown
/// never understates what remains), sub-minute in seconds so a
/// short trial reads its own countdown; the 4h59m59s pin is the
/// owner's own transcript shape, a `--during 5h` checked seconds
/// after apply that must never read "4h".
#[test]
fn format_duration_compact_one_unit_ceiled() {
    const S: u64 = 1_000_000_000;
    const M: u64 = 60 * S;
    const H: u64 = 60 * M;
    const D: u64 = 24 * H;
    const Y: u64 = 365 * D;
    // Exact units read themselves.
    assert_eq!(format_duration_compact(45 * S), "45s");
    assert_eq!(format_duration_compact(47 * M), "47m");
    assert_eq!(format_duration_compact(3 * H), "3h");
    assert_eq!(format_duration_compact(20 * D), "20d");
    assert_eq!(format_duration_compact(5 * Y), "5y");
    // The remainder rounds UP to the unit it still holds: the
    // owner's find (5h minus a breath), the sub-second tail, and
    // the tier's own edge.
    assert_eq!(format_duration_compact(5 * H - S), "5h");
    assert_eq!(format_duration_compact(45 * S + 500_000_000), "46s");
    assert_eq!(format_duration_compact(59 * S + S / 2), "60s");
}

/// The five lifetime shapes a row with a window renders, pinned to
/// their exact wording (the owner checks this table against the CLI
/// promise — the wording IS the promise): the active span names its
/// end and its countdown, the dormant span its wake, the ended span
/// its expiry (warn yellow — the one state to notice), the daily
/// pair its hours with the active/outside verdict.
#[test]
fn window_lifetime_line_pins_all_five_shapes() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
    // The clock pair: wall 2026-10-06 12:00:00 UTC (the exact
    // epoch instant, so the day-level assertions below are
    // deterministic), mono 60s.
    let mono = 60 * 1_000_000_000u64;
    let wall = 1_791_288_000_000_000_000u64;

    let active_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono + 47 * 60 * 1_000_000_000,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&active_span, wall, mono);
    assert!(
        line.contains("window: until 2026-10-06") && line.contains("(47m left)"),
        "active span: {line}"
    );

    let dormant_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: mono + 3600 * 1_000_000_000,
        end_mono_ns: mono + 7200 * 1_000_000_000,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&dormant_span, wall, mono);
    assert!(
        line.contains("window: sleeps until 2026-10-06 13:"),
        "dormant span: {line}"
    );

    let ended_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&ended_span, wall, mono);
    assert!(
        line.contains("window: expired at") && line.contains("(awaiting sweep)"),
        "ended span: {line}"
    );

    // The anchor is 12:00 UTC inside 09:00-17:00: active.
    let active_daily = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 9 * 3600,
        end_s: 17 * 3600,
    };
    let line = window_lifetime_line(&active_daily, wall, mono);
    assert!(
        line.contains("window: daily 09:00-17:00 UTC (active)"),
        "active daily: {line}"
    );

    let outside_daily = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 22 * 3600,
        end_s: 6 * 3600,
    };
    let line = window_lifetime_line(&outside_daily, wall, mono);
    assert!(
        line.contains("window: daily 22:00-06:00 UTC (outside — not policing now)"),
        "outside daily: {line}"
    );
}

/// The window join: a row whose cgroup carries a window renders the
/// lifetime line under it; a row without one renders none (the
/// additive-field rule — the table stays exactly what it was for
/// every --during-less row).
#[test]
fn collect_display_data_joins_windows_by_cgroup() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_SPAN};
    let dl = vec![(101u32, PolicyRaw::default())];
    let windows = vec![(
        101u32,
        PolicyWindowRaw {
            kind: WINDOW_KIND_SPAN,
            reserved: 0,
            start_mono_ns: 0,
            end_mono_ns: 10,
            start_s: 0,
            end_s: 0,
        },
    )];
    let data = collect_display_data(&dl, &[], &[], &windows);
    assert!(data[0].window.is_some(), "the window joins its row");
    let data = collect_display_data(&dl, &[], &[], &[]);
    assert!(data[0].window.is_none(), "absent window = no lifetime line");
}
