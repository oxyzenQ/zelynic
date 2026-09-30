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

use super::*;

/// improve-13 style pin: the human table's ALLOWED/DROPPED cells carry
/// ONE metric (bytes) — the per-cell packing "421 (1.4 MB)" is
/// retired; packet counts stay in `--print-json`. A missing direction
/// policy renders the em dash, never a zero.
#[test]
fn status_cells_one_metric_per_cell() {
    let d = DisplayData {
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
        assert!(
            lines[0].starts_with("╭─── zelynic status"),
            "{name}: the eagle title bar opens the frame, got: {}",
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
