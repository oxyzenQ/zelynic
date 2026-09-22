// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes renderer pins (NIGHT-boost-1): rank ordering, column
//! degradation ladder, footer honesty, target autodetect, and the
//! focus-view switch. Lives under the single test/ tree (cosmostrix
//! Pattern C) and is #[path]-wired from src/ebpf/render/eagle.rs, so
//! `super::` reaches the eagle module exactly like inline tests did.

use super::*;
use crate::ebpf::identity::ProcessIdentity;

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
#[test]
fn eagle_columns_full_width() {
    let cols = plan_eagle_columns(100);
    assert!(cols.show_rate);
    assert_eq!(cols.dl_w, 10);
    assert_eq!(cols.label_w, 100 - 6 - 3 * 10 - 3 * 2);
}

/// RATE is the first column to go on narrow frames (full layout
/// starts at width 54: 6 rank + 12 label + 30 numerics + 6 gaps).
#[test]
fn eagle_columns_drop_rate_below_54() {
    let cols = plan_eagle_columns(53);
    assert!(!cols.show_rate);
    assert_eq!(cols.label_w, 53 - 6 - 2 * 10 - 2 * 2);
}

/// Ultra-narrow frames pin the label to the minimum and tighten
/// the numeric columns rather than overflowing the line.
#[test]
fn eagle_columns_narrow_floor() {
    let cols = plan_eagle_columns(36);
    assert!(!cols.show_rate);
    assert_eq!(cols.label_w, 12);
    assert_eq!(cols.dl_w, 9);
}

/// NIGHT-improve-2 line-building pin: the renderer fills the
/// caller's vector (title bar first, waiting-note when idle) —
/// the diff engine's input contract.
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
    );
    assert_eq!(lines.len(), 2, "idle frame = title + waiting note");
    assert!(lines[0].starts_with("─── zelynic eagle-eyes — 1s refresh"));
    assert_eq!(lines[1], "  waiting for traffic…");
}

/// Rank ordering (NIGHT-boost-1): rank 1 is the heaviest
/// consumer of the interval — the realtime sort, not lifetime.
#[test]
fn rank_one_is_the_heaviest_consumer() {
    let mut lines = Vec::new();
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
    );
    let joined = lines.join("\n");
    // cg:7001 moved 995 KB this frame vs cg:7002's 15 KB — rank 1
    // despite the smaller LIFETIME figures (900 KB vs 810 KB).
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with("   1  "))
        .unwrap_or_else(|| panic!("no rank-1 row in: {joined}"));
    assert!(
        rank1.contains("cg:7001"),
        "rank 1 = this frame's heaviest: {rank1}"
    );
    let rank2 = lines
        .iter()
        .find(|l| l.starts_with("   2  "))
        .unwrap_or_else(|| panic!("no rank-2 row in: {joined}"));
    assert!(rank2.contains("cg:7002"), "rank 2 follows: {rank2}");
}

/// Footer honesty + column grid (ported from the observe/top
/// pins): the TOTAL row sums EVERY candidate in the same width
/// slots the data rows use.
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
    );
    let joined = lines.join("\n");
    let total_row = lines
        .iter()
        .find(|l| l.split_whitespace().next() == Some("TOTAL"))
        .unwrap_or_else(|| panic!("no TOTAL row in: {joined}"));
    assert!(total_row.contains("1.4 MB"), "TOTAL dl sum: {total_row}");
    assert!(total_row.contains("240.0 KB"), "TOTAL ul sum: {total_row}");
    assert!(total_row.contains("1.6 MB/s"), "TOTAL rate: {total_row}");
    assert!(
        joined.contains("478 packets · 1 cgroups"),
        "meta line wording: {joined}"
    );
}

/// Target autodetect (NIGHT-boost-1): a name token expands to
/// every matching cgroup; a numeric token is a cgroup ID
/// verbatim; unmatched names surface as note lines.
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
    assert_eq!(
        ids,
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
/// the old `observe --cgroup` depth, autodetected.
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
}
