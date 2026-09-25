// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes renderer pins (NIGHT-boost-1): rank ordering, column
//! degradation ladder, footer honesty, target autodetect, and the
//! focus-view switch. NIGHT-boost-5 re-pinned the ranking contract:
//! the board renders from the SESSION leaderboard (accumulated
//! totals), so quiet frames hold their rows and takeovers re-crown.
//! NIGHT-boost-14 re-pinned the composition: the frame is pinned to
//! the terminal height with the grip footer near the bottom, the
//! traffic-light tiers are static (no blink), subprocess detail is
//! grey and width-adaptive, and the footer compression ladder holds
//! the short-terminal degradation. Lives under the single test/ tree
//! (cosmostrix Pattern C) and is #[path]-wired from
//! src/ebpf/render/eagle.rs, so `super::` reaches the eagle module
//! exactly like inline tests did.

use super::*;
use crate::ebpf::identity::ProcessIdentity;
use crate::ebpf::loader::CgroupDelta;
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

/// One traffic frame for `cg` with the given per-frame deltas.
fn frame(cg: u32, dl: u64, ul: u64) -> CounterSummary {
    CounterSummary {
        total_packets: 1,
        total_bytes: ul,
        total_ingress_packets: 1,
        total_ingress_bytes: dl,
        cgroups: vec![CgroupDelta {
            cgroup_id: cg,
            packets: 1,
            bytes: ul,
            total_bytes: ul,
            ingress_packets: 1,
            ingress_bytes: dl,
            ingress_total_bytes: dl,
        }],
    }
}

/// The 80x24 classic terminal — the geometry every plain
/// `render_eagle_eyes` call sees (the piped-fallback probe), made
/// explicit for the size-injectable core.
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// Full column set at a comfortable width, label absorbing the rest.
/// NIGHT-boost-5: the reserve is rank(6) + 3 x (gap 1 + numeric 10);
/// NIGHT-engrave-4 adds the symmetric right gutter(2) to the reserve
/// — a full row ends two columns short of the content inset (the
/// border's fit() pads them), the mirror of the left gutter; the
/// fourth column is TOTAL (session-accumulated), not the old
/// combined RATE.
#[test]
fn eagle_columns_full_width() {
    let cols = plan_eagle_columns(100);
    assert!(cols.show_total);
    assert_eq!(cols.dl_w, 10);
    assert_eq!(cols.label_w, 100 - 6 - 3 * 11 - 2);
}

/// TOTAL is the first column to go on narrow frames (full layout
/// starts at width 53 since NIGHT-engrave-4: 6 rank + 12 label +
/// 3 x (gap + numeric) + 2 right gutter; it was 51 before the
/// gutter — the boundary moved with the air it buys).
#[test]
fn eagle_columns_drop_total_below_53() {
    // The exact boundary: 53 carries the TOTAL column.
    let cols = plan_eagle_columns(53);
    assert!(cols.show_total);
    assert_eq!(cols.label_w, 53 - 6 - 3 * 11 - 2);
    // One column short: TOTAL drops, the label re-absorbs.
    let cols = plan_eagle_columns(52);
    assert!(!cols.show_total);
    assert_eq!(cols.label_w, 52 - 6 - 2 * 11 - 2);
}

/// NIGHT-engrave-4's symmetric-rails contract, pinned on a rendered
/// frame: the header's `top process` title starts at the frame's
/// CANONICAL text column — the same two-column gutter every footer
/// and note line uses — instead of floating six columns past the
/// blank rank cell; the TOTAL column's figures end with the same
/// two columns of air before the right rail that the left gutter
/// gives the rank; and the data rows keep the classic rank shape
/// (rank digits over their cell, 2-gap, label over its column).
#[test]
fn header_and_total_column_carry_symmetric_air() {
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 1_400_000, 240_000),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    // The header: title at the canonical text column (rail + the
    // 2-column gutter), NOT floating past the blank rank cell.
    let header = lines
        .iter()
        .find(|l| l.contains("top process"))
        .unwrap_or_else(|| panic!("no header row in: {joined}"));
    assert!(
        header.starts_with(" │  top process"),
        "engrave-4: the title starts at the canonical text column          (inset + rail + gutter, NIGHT-engrave-8): {header}"
    );
    // The header's TOTAL title closes at the right gutter's edge —
    // exactly two columns of air before the rail, never flush.
    assert!(
        header.ends_with("total  │"),
        "engrave-4: two columns of air after the total title: {header}"
    );
    // The data row: same right gutter (exactly two air columns —
    // `  │` but never `   │`), and the classic rank shape unchanged.
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with(" │   1  "))
        .unwrap_or_else(|| panic!("no rank-1 row in: {joined}"));
    assert!(
        rank1.ends_with("  │") && !rank1.ends_with("   │"),
        "engrave-4: the TOTAL figures end at the gutter's edge, exactly two columns of air: {rank1}"
    );
    assert!(
        rank1.contains("1.6 MB"),
        "the session total still rides the row: {rank1}"
    );
    // The download/upload titles carry the same right-aligned
    // numeric family (span check: header and data row end at the
    // same column — one straight right edge, two columns off the
    // rail).
    assert!(
        header.contains("download") && header.contains("upload"),
        "numeric titles ride the header: {header}"
    );
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
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    // cg:7001 moved 995 KB this frame vs cg:7002's 15 KB — rank 1
    // (a single frame: the accumulation IS the frame).
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with(" │   1  "))
        .unwrap_or_else(|| panic!("no rank-1 row in: {joined}"));
    assert!(
        rank1.contains("cg:7001"),
        "rank 1 = the session's heaviest: {rank1}"
    );
    let rank2 = lines
        .iter()
        .find(|l| l.starts_with(" │   2  "))
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
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    assert!(lines.iter().any(|l| l.contains("cg:7001")));

    // The quiet frame: nothing moved, the row stays.
    let mut quiet = Vec::new();
    render_eagle_eyes_at(
        &mut quiet,
        &CounterSummary::default(),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    let quiet_row = quiet
        .iter()
        .find(|l| l.starts_with(" │   1  "))
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
/// NIGHT-boost-14: the re-crown is STATIC — no blink attribute, no
/// timing state; the rows read by color and order alone.
#[test]
fn takeover_recrowns_rank1() {
    let mut session = SessionState::new();
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 10_000_000, 0),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    // B accumulates past A.
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7002, 11_000_000, 0),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with(" │   1  "))
        .expect("rank-1 row after the takeover");
    assert!(
        rank1.contains("cg:7002"),
        "B takes the crown on accumulated total: {rank1}"
    );
    let rank2 = lines
        .iter()
        .find(|l| l.starts_with(" │   2  "))
        .expect("rank-2 row after the takeover");
    assert!(
        rank2.contains("cg:7001"),
        "A slides to rank 2 though it moved nothing this frame: {rank2}"
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
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[Target::parse("brave")],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
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
        !joined.contains("top process"),
        "focus view is the key/value block, not the ranked table: {joined}"
    );
    assert!(
        joined.contains(" by oxyzenQ"),
        "focus frame signs off with the build stamp too: {joined}"
    );
    assert_eq!(lines.len(), 24, "focus frame pinned to the height");
}

// NIGHT-engrave-6: the target-filter contract (name expansion,
// miss notes, the filtered board's own census and speed pair) took
// its own file — the speed-pair pins pushed this file past the
// owner's LOC cap, the same one-file-per-contract split the footer
// tree already uses (cosmostrix Pattern C, #[path]-wired).

/// NIGHT-lts-3 (the measured-span rate contract): the DOWNLOAD and
/// UPLOAD columns and the footer's MAX line divide each frame's
/// deltas by the MEASURED poll-to-poll span, not the configured
/// cadence — the beat scheduler fires on the first 50ms wake past
/// the cadence, so nominal division overstated every rate. Pin: one
/// frame, two spans — the same 1,400,000/240,000 byte deltas render
/// 1.4 MB/s | 240.0 KB/s at a 1s span and exactly half at a 2s
/// span, while the status line keeps the CONFIGURED cadence's
/// "1s realtime" identity on both frames.
#[test]
fn rate_columns_divide_by_the_measured_span_not_the_cadence() {
    for (span, dl_rate, ul_rate) in [
        (Duration::from_secs(1), "1.4 MB/s", "240.0 KB/s"),
        (Duration::from_secs(2), "700.0 KB/s", "120.0 KB/s"),
    ] {
        let mut lines = Vec::new();
        render_eagle_eyes_at(
            &mut lines,
            &frame(7001, 1_400_000, 240_000),
            &[],
            &IdentityMap::new(),
            None,
            Duration::from_secs(1),
            span,
            &mut SessionState::new(),
            Duration::from_secs(70),
            classic(),
        );
        let joined = lines.join("\n");
        let rank1 = lines
            .iter()
            .find(|l| l.starts_with(" │   1  "))
            .unwrap_or_else(|| panic!("no rank-1 row at span {span:?}: {joined}"));
        assert!(
            rank1.contains(dl_rate),
            "span {span:?}: download rate reads {dl_rate}: {rank1}"
        );
        assert!(
            rank1.contains(ul_rate),
            "span {span:?}: upload rate reads {ul_rate}: {rank1}"
        );
        // The footer's MAX pair converts with the same measured span.
        assert!(
            joined.contains(&format!("total max dl | ul = {dl_rate} | {ul_rate}")),
            "span {span:?}: the footer MAX pair reads the same figures: {joined}"
        );
        // The status line stays on the CONFIGURED cadence — the
        // span is the rate denominator, never the cadence identity.
        assert!(
            joined.contains("1s realtime"),
            "span {span:?}: the status line keeps the configured cadence: {joined}"
        );
    }
}
