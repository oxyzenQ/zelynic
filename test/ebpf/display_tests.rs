// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the status display surface — kept in the repo's
//! single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C) and
//! #[path]-wired from display.rs. The NIGHT-hunt-22 pins hold the
//! `--print-json` scripting contract (field names, watchdog wording,
//! count semantics) via the extracted pure `status_json` builder —
//! no stdout capture needed. The NIGHT-engrave-5 pins hold the
//! eagle-eyes style match (lowercase headers, the line builders'
//! wording and order) the same way.

use super::*;

fn policy(rate_bps: u64) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
    }
}

fn stats(allowed: u64, dropped: u64) -> LimiterStatsRaw {
    LimiterStatsRaw {
        packets_allowed: allowed,
        packets_dropped: dropped,
        bytes_allowed: allowed * 100,
        bytes_dropped: dropped * 100,
    }
}

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

    // One-direction limit: the other side is an em dash, not a number.
    let one_sided = DisplayData {
        cgroup_id: 73390,
        dl_bps: None,
        ul_bps: Some(1_000_000),
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

/// `active_limits` counts CGROUPS, not direction entries: a cgroup
/// with both dl and ul policies is ONE limit row. Scripts compare
/// this number against strict's "(N policies...)" — which counts
/// directions — so the difference is pinned here on purpose: this is
/// the display contract, that is the apply contract.
#[test]
fn status_json_counts_cgroups_not_direction_policies() {
    let dl = vec![(73386, policy(100_000))];
    let ul = vec![(73386, policy(50_000))];
    let json = status_json(&dl, &ul, &[], &IdentityMap::new(), Some(0));

    assert_eq!(json.active_limits, 1);
    assert_eq!(json.limits.len(), 1);

    let row = &json.limits[0];
    assert_eq!(row.cgroup_id, 73386);
    assert_eq!(row.label, "cg:73386");
    assert_eq!(row.download_bps, Some(100_000));
    assert_eq!(row.upload_bps, Some(50_000));
}

/// A cgroup limited in one direction only: the other renders null,
/// never zero — "no upload policy" and "upload blocked at 0 bps"
/// must stay distinguishable for automation.
#[test]
fn status_json_single_direction_limit_renders_null_other_side() {
    let dl = vec![(73390, policy(0))];
    let json = status_json(&dl, &[], &[], &IdentityMap::new(), Some(0));

    assert_eq!(json.active_limits, 1);
    assert_eq!(json.limits[0].download_bps, Some(0));
    assert_eq!(json.limits[0].upload_bps, None);
}

/// Stats join by cgroup; a cgroup without a stats entry shows zeros
/// (fresh policy, no traffic yet) — that zero is honest because the
/// stats read itself is verified upstream (NIGHT-hunt-22: print_status
/// propagates read errors before display ever runs).
#[test]
fn status_json_joins_stats_and_zeroes_missing_entries() {
    let dl = vec![(1, policy(10)), (2, policy(20))];
    let stats_in = vec![(1, stats(7, 3))];
    let json = status_json(&dl, &[], &stats_in, &IdentityMap::new(), None);

    let with_stats = json.limits.iter().find(|l| l.cgroup_id == 1).unwrap();
    assert_eq!(with_stats.packets_allowed, 7);
    assert_eq!(with_stats.packets_dropped, 3);
    assert_eq!(with_stats.bytes_allowed, 700);
    assert_eq!(with_stats.bytes_dropped, 300);

    let without = json.limits.iter().find(|l| l.cgroup_id == 2).unwrap();
    assert_eq!(without.packets_allowed, 0);
    assert_eq!(without.bytes_dropped, 0);
}

/// Watchdog wording: the three-document states. Some(0) and None are
/// the same "enforcing" state (pin mode never arms the watchdog —
/// deadline 0 is its dormant representation); a future deadline is
/// "active"; a past one is "expired".
#[test]
fn status_json_watchdog_wording_pins_all_three_states() {
    let no_policies: Vec<(u32, PolicyRaw)> = Vec::new();
    let id = IdentityMap::new();

    // Dormant: deadline 0, and the None display-contract variant.
    assert_eq!(
        status_json(&[], &[], &[], &id, Some(0)).watchdog,
        "enforcing"
    );
    assert_eq!(
        status_json(&no_policies, &[], &[], &id, None).watchdog,
        "enforcing"
    );

    // Armed and still in the future (u64::MAX is safely above any
    // monotonic clock).
    assert_eq!(
        status_json(&[], &[], &[], &id, Some(u64::MAX)).watchdog,
        "active"
    );

    // Armed but past — monotonic_ns() is far beyond 1 by now.
    assert_eq!(status_json(&[], &[], &[], &id, Some(1)).watchdog, "expired");
}

/// Empty policy maps (pins up, nothing limited — e.g. after recover
/// swept dead-cgroup orphans) is the ONE honest "no limits" state,
/// distinct from a failed read which now exits non-zero upstream.
#[test]
fn status_json_empty_policies_is_the_zero_state() {
    let json = status_json(&[], &[], &[], &IdentityMap::new(), Some(0));
    assert_eq!(json.active_limits, 0);
    assert!(json.limits.is_empty());
    assert_eq!(json.watchdog, "enforcing");
}

/// The serialized field names are the scripting contract — renaming
/// any of them breaks every consumer at once, so they are pinned as
/// literal JSON text.
#[test]
fn status_json_field_names_are_pinned() {
    let json = status_json(
        &[(42, policy(1000))],
        &[],
        &[(42, stats(1, 2))],
        &IdentityMap::new(),
        Some(0),
    );
    let text = serde_json::to_string(&json).unwrap();
    for field in [
        "\"watchdog\"",
        "\"active_limits\"",
        "\"limits\"",
        "\"cgroup_id\"",
        "\"label\"",
        "\"download_bps\"",
        "\"upload_bps\"",
        "\"packets_allowed\"",
        "\"packets_dropped\"",
        "\"bytes_allowed\"",
        "\"bytes_dropped\"",
    ] {
        assert!(text.contains(field), "field {field} missing from: {text}");
    }
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

/// The branch frames carry the flagship chrome in the owner's line
/// order: title bar, breathing gap, the story line(s), gap, stamp.
/// The clean state's single line names the verdict; the stale state
/// carries the warn finding and the suggestion-white command.
#[test]
fn status_branch_frames_carry_the_flagship_chrome() {
    for (name, lines, story_rows) in [
        ("clean", status_clean_lines(60), 1usize),
        ("stale", status_stale_lines(60), 2),
    ] {
        assert_eq!(
            lines.len(),
            story_rows + 4,
            "{name}: title + gap + {story_rows} story + gap + stamp, got {} lines",
            lines.len()
        );
        assert!(
            lines[0].starts_with("╭─── zelynic status"),
            "{name}: the eagle title bar opens the frame, got: {}",
            lines[0]
        );
        assert!(lines[1].is_empty(), "{name}: breathing gap under the title");
        assert!(
            lines[lines.len() - 1].contains("by oxyzenQ"),
            "{name}: the signature stamp closes the frame, got: {}",
            lines[lines.len() - 1]
        );
    }

    let clean = status_clean_lines(60);
    assert!(
        clean[2].contains("no active limits"),
        "the clean verdict, got: {}",
        clean[2]
    );

    let stale = status_stale_lines(60);
    assert!(
        stale[2].contains("stale bpf pin files detected"),
        "the stale finding, got: {}",
        stale[2]
    );
    assert!(
        stale[3].contains("'zelynic recover'"),
        "the recovery command, got: {}",
        stale[3]
    );
}
