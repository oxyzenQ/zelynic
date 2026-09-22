// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes renderer pins (NIGHT-boost-1): rank ordering, column
//! degradation ladder, footer honesty, target autodetect, and the
//! focus-view switch. NIGHT-boost-5 re-pinned the ranking contract:
//! the board renders from the SESSION leaderboard (accumulated
//! totals), so quiet frames hold their rows and takeovers re-crown.
//! Lives under the single test/ tree (cosmostrix Pattern C) and is
//! #[path]-wired from src/ebpf/render/eagle.rs, so `super::` reaches
//! the eagle module exactly like inline tests did.

use super::*;
use crate::ebpf::identity::ProcessIdentity;
use std::time::Duration;

fn identity_with(comms: &[(&str, u32)]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for (comm, cg) in comms {
        identity.insert(ProcessIdentity {
            cgroup_id: *cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });
    }
    identity
}

/// Full column set at a comfortable width, label absorbing the rest.
/// NIGHT-boost-5: the reserve is rank(6) + 3 x (gap 1 + numeric 10),
/// so a full row ends flush at the frame width; the fourth column is
/// TOTAL (session-accumulated), not the old combined RATE.
#[test]
fn eagle_columns_full_width() {
    let cols = plan_eagle_columns(100);
    assert!(cols.show_total);
    assert_eq!(cols.dl_w, 10);
    assert_eq!(cols.label_w, 100 - 6 - 3 * 11);
}

/// TOTAL is the first column to go on narrow frames (full layout
/// starts at width 51: 6 rank + 12 label + 3 x (gap + numeric)).
#[test]
fn eagle_columns_drop_total_below_51() {
    let cols = plan_eagle_columns(50);
    assert!(!cols.show_total);
    assert_eq!(cols.label_w, 50 - 6 - 2 * 11);
}

/// Ultra-narrow frames pin the label to the minimum and tighten
/// the numeric columns rather than overflowing the line.
#[test]
fn eagle_columns_narrow_floor() {
    let cols = plan_eagle_columns(36);
    assert!(!cols.show_total);
    assert_eq!(cols.label_w, 12);
    assert_eq!(cols.dl_w, 9);
}

/// NIGHT-improve-2 line-building pin: the renderer fills the
/// caller's vector (title bar first, waiting-note when idle, the
/// signature footer last) — the diff engine's input contract.
#[test]
fn eagle_frame_builds_lines() {
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &CounterSummary::default(),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
    );
    assert_eq!(lines.len(), 4, "idle frame = title + note + blank + footer");
    assert!(
        lines[0].starts_with("  ─── zelynic eagle-eyes — 1s refresh"),
        "title carries the frame gutter: {}",
        lines[0]
    );
    assert_eq!(lines[1], "  waiting for traffic…");
    assert_eq!(lines[2], "");
    assert!(
        lines[3].starts_with("  zelynic v"),
        "signature footer signs the idle frame: {}",
        lines[3]
    );
}

/// The owner's leaderboard scenario (NIGHT-boost-5): rank by
/// accumulated session totals, not by the last frame's twitch.
#[test]
fn rank_is_the_session_accumulation() {
    let mut session = SessionState::new();
    let mut lines = Vec::new();
    // Frame 1: A eats a lot (10 MB), B a little.
    let summary = CounterSummary {
        total_packets: 10,
        total_bytes: 10_000,
        total_ingress_packets: 100,
        total_ingress_bytes: 1_000_000,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: 7002,
                packets: 2,
                bytes: 10_000,
                total_bytes: 900_000,
                ingress_packets: 20,
                ingress_bytes: 5_000,
                ingress_total_bytes: 800_000,
            },
            CgroupDelta {
                cgroup_id: 7001,
                packets: 8,
                bytes: 0,
                total_bytes: 10_000,
                ingress_packets: 80,
                ingress_bytes: 995_000,
                ingress_total_bytes: 5_000,
            },
        ],
    };
    render_eagle_eyes(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut session,
    );
    let joined = lines.join("\n");
    // cg:7001 moved 995 KB this frame vs cg:7002's 15 KB — rank 1
    // (a single frame: the accumulation IS the frame).
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with("   1  "))
        .unwrap_or_else(|| panic!("no rank-1 row in: {joined}"));
    assert!(
        rank1.contains("cg:7001"),
        "rank 1 = the session's heaviest: {rank1}"
    );
    let rank2 = lines
        .iter()
        .find(|l| l.starts_with("   2  "))
        .unwrap_or_else(|| panic!("no rank-2 row in: {joined}"));
    assert!(rank2.contains("cg:7002"), "rank 2 follows: {rank2}");
}

/// Quiet frames hold the board (NIGHT-boost-5, the owner's
/// "keep on monitor mode" contract): an empty poll renders the SAME
/// rows with em-dash rates and the accumulated TOTALs — the
/// "waiting for traffic…" collapse is dead once traffic was seen.
#[test]
fn quiet_frame_holds_the_board() {
    let mut session = SessionState::new();
    let summary = CounterSummary {
        total_packets: 5,
        total_bytes: 1_000,
        total_ingress_packets: 50,
        total_ingress_bytes: 500_000,
        cgroups: vec![CgroupDelta {
            cgroup_id: 7001,
            packets: 5,
            bytes: 1_000,
            total_bytes: 1_000,
            ingress_packets: 50,
            ingress_bytes: 500_000,
            ingress_total_bytes: 500_000,
        }],
    };
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut session,
    );
    assert!(lines.iter().any(|l| l.contains("cg:7001")));

    // The quiet frame: nothing moved, the row stays.
    let mut quiet = Vec::new();
    render_eagle_eyes(
        &mut quiet,
        &CounterSummary::default(),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut session,
    );
    let quiet_row = quiet
        .iter()
        .find(|l| l.starts_with("   1  "))
        .expect("the board holds its rank-1 row through the quiet frame");
    assert!(
        quiet_row.contains("cg:7001"),
        "idle row persists: {quiet_row}"
    );
    assert!(
        quiet_row.contains("—"),
        "rates render em dashes when this frame moved nothing: {quiet_row}"
    );
    assert!(
        quiet_row.contains("501.0 KB"),
        "TOTAL carries the accumulated figure: {quiet_row}"
    );
    assert!(
        !quiet.iter().any(|l| l.contains("waiting for traffic")),
        "the waiting note is dead after the first packet: {:?}",
        quiet
    );
}

/// A takeover re-crowns (the owner's A/B scenario): when B's
/// accumulated total passes A's, B takes rank 1 and A slides down.
#[test]
fn takeover_recrowns_rank1() {
    let mut session = SessionState::new();
    let frame = |cg: u32, dl: u64| CounterSummary {
        total_packets: 1,
        total_bytes: 0,
        total_ingress_packets: 1,
        total_ingress_bytes: dl,
        cgroups: vec![CgroupDelta {
            cgroup_id: cg,
            packets: 0,
            bytes: 0,
            total_bytes: 0,
            ingress_packets: 1,
            ingress_bytes: dl,
            ingress_total_bytes: dl,
        }],
    };
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &frame(7001, 10_000_000),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut session,
    );
    // B accumulates past A.
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &frame(7002, 11_000_000),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut session,
    );
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with("   1  "))
        .expect("rank-1 row after the takeover");
    assert!(
        rank1.contains("cg:7002"),
        "B takes the crown on accumulated total: {rank1}"
    );
    let rank2 = lines
        .iter()
        .find(|l| l.starts_with("   2  "))
        .expect("rank-2 row after the takeover");
    assert!(
        rank2.contains("cg:7001"),
        "A slides to rank 2 though it moved nothing this frame: {rank2}"
    );
}

/// Footer honesty + column grid (ported from the observe/top
/// pins): the TOTAL row sums EVERY candidate in the same width
/// slots the data rows use — per-frame RATES under DOWNLOAD/UPLOAD,
/// the session grand total under TOTAL.
#[test]
fn footer_total_row_aligns_and_sums_all_candidates() {
    let mut lines = Vec::new();
    let summary = CounterSummary {
        total_packets: 57,
        total_bytes: 240_000,
        total_ingress_packets: 421,
        total_ingress_bytes: 1_400_000,
        cgroups: vec![CgroupDelta {
            cgroup_id: 7001,
            packets: 57,
            bytes: 240_000,
            total_bytes: 240_000,
            ingress_packets: 421,
            ingress_bytes: 1_400_000,
            ingress_total_bytes: 1_400_000,
        }],
    };
    render_eagle_eyes(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
    );
    let joined = lines.join("\n");
    let total_row = lines
        .iter()
        .find(|l| l.split_whitespace().next() == Some("TOTAL"))
        .unwrap_or_else(|| panic!("no TOTAL row in: {joined}"));
    assert!(total_row.contains("1.4 MB/s"), "TOTAL dl rate: {total_row}");
    assert!(
        total_row.contains("240.0 KB/s"),
        "TOTAL ul rate: {total_row}"
    );
    assert!(
        total_row.contains("1.6 MB"),
        "TOTAL session sum: {total_row}"
    );
    assert!(
        joined.contains("478 packets · 1 cgroups"),
        "meta line wording: {joined}"
    );
    // The signature footer is the frame's last content line.
    assert!(
        joined.contains("zelynic v"),
        "every frame signs off: {joined}"
    );
}

/// Target autodetect (NIGHT-boost-1): a name token expands to
/// every matching cgroup; a numeric token is a cgroup ID
/// verbatim; unmatched names surface as note lines.
///
/// The id SET is compared sorted: `identity.all()` walks a HashMap,
/// so expansion order is per-process random (the renderer re-sorts
/// rows by consumption, so nothing observable depends on it) — the
/// CI catch on 5fa75d1 pinned exactly this; an order-sensitive
/// assert here is flaky by construction.
#[test]
fn name_targets_expand_and_misses_note() {
    let identity = identity_with(&[("brave", 7001), ("brave", 7002), ("firefox", 7003)]);
    let (ids, unresolved) = resolve_targets(
        &[
            Target::parse("brave"),
            Target::parse("73386"),
            Target::parse("chromium"),
        ],
        &identity,
    );
    let mut got = ids.clone();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![7001, 7002, 73386],
        "name expands + numeric verbatim"
    );
    assert_eq!(unresolved, vec!["chromium".to_string()]);

    // The note renders in the frame, and the ranked table filters.
    let summary = CounterSummary {
        total_packets: 5,
        total_bytes: 100,
        total_ingress_packets: 50,
        total_ingress_bytes: 5_000,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: 7001,
                packets: 1,
                bytes: 100,
                total_bytes: 100,
                ingress_packets: 10,
                ingress_bytes: 5_000,
                ingress_total_bytes: 5_000,
            },
            CgroupDelta {
                cgroup_id: 7004,
                packets: 4,
                bytes: 0,
                total_bytes: 0,
                ingress_packets: 40,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
        ],
    };
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &summary,
        &[Target::parse("brave"), Target::parse("chromium")],
        &identity,
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("no app named 'chromium' — see 'zelynic list-apps'"),
        "unresolved note renders: {joined}"
    );
    assert!(
        joined.contains("cg:7001"),
        "matched target renders: {joined}"
    );
    assert!(
        !joined.contains("cg:7004"),
        "unwatched cgroup is filtered out: {joined}"
    );
    assert!(
        joined.contains("1 of 2 cgroups"),
        "filtered meta names the share: {joined}"
    );
    assert!(
        !joined.contains("Top consumer"),
        "discovery hint is unfiltered-only: {joined}"
    );
}

/// Single token resolving to one cgroup takes the focus view —
/// the old `observe --cgroup` depth, autodetected (and the focus
/// frame signs off with the signature footer too).
#[test]
fn single_resolved_target_takes_focus_view() {
    let identity = identity_with(&[("brave", 7001)]);
    let summary = CounterSummary {
        total_packets: 5,
        total_bytes: 10_000_000,
        total_ingress_packets: 50,
        total_ingress_bytes: 5_000_000,
        cgroups: vec![CgroupDelta {
            cgroup_id: 7001,
            packets: 5,
            bytes: 10_000_000,
            total_bytes: 90_000_000,
            ingress_packets: 50,
            ingress_bytes: 5_000_000,
            ingress_total_bytes: 900_000_000,
        }],
    };
    let mut lines = Vec::new();
    render_eagle_eyes(
        &mut lines,
        &summary,
        &[Target::parse("brave")],
        &identity,
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("zelynic eagle-eyes — cg:7001 (brave)"),
        "focus title names the target: {joined}"
    );
    assert!(
        joined.contains("lifetime  990.0 MB"),
        "focus view carries the lifetime row: {joined}"
    );
    assert!(
        !joined.contains("DOWNLOAD"),
        "focus view is the key/value block, not the table: {joined}"
    );
    assert!(
        joined.contains("zelynic v"),
        "focus frame signs off too: {joined}"
    );
}
