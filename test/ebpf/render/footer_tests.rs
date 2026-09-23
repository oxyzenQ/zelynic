// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pinned grip-footer composition pins (NIGHT-boost-14): the tier
//! ladder, the owner's exact grip layout, the pin itself (frame
//! spanning the terminal height with the footer near the bottom,
//! never following the table), the discovery pair, and the adaptive
//! subprocess-detail behavior. Split from the eagle renderer pins
//! when the boost-14 composition work pushed the file past the
//! owner's LOC cap - one file per contract, the same
//! #[path] discipline as the diff engine's pins. `super::` reaches
//! the footer module; the eagle renderer core is imported across the
//! render tree (it is `pub(super)` there).

use super::{plan_footer_tier, FooterTier};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::{FrameGeometry, SessionState};
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

/// The 80x24 classic terminal (the piped-fallback probe).
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// One flanked row (mono, as tests run piped): rail + content padded
/// to the 78-column inset + rail — the exact wrap contract for footer
/// text rows (NIGHT-boost-20).
fn flanked(content: &str) -> String {
    let pad = " ".repeat(78 - content.chars().count());
    format!("│{content}{pad}│")
}

/// A one-cgroup traffic frame.
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

/// Footer compression ladder (NIGHT-boost-14; NIGHT-engrave-1 folded
/// the boost-17 uptime line into the census row and NIGHT-engrave-2
/// added the status line below the limit suggestions — one line out,
/// one line in, so the counts stand at the pre-engrave 12/8/6/5): the
/// classic 80x24 carries the full 12-line grip block; a 16-row window
/// drops to Compact; 10 rows to Minimal; the survival floor holds
/// from 10.
#[test]
fn footer_tier_ladder() {
    assert_eq!(plan_footer_tier(24, 0), FooterTier::Full);
    assert_eq!(
        plan_footer_tier(17, 0),
        FooterTier::Full,
        "17 = 4 chrome + 12 footer + 1 row"
    );
    assert_eq!(plan_footer_tier(16, 0), FooterTier::Compact);
    assert_eq!(plan_footer_tier(13, 0), FooterTier::Compact);
    assert_eq!(plan_footer_tier(12, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(11, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(10, 0), FooterTier::Tiny);
    assert_eq!(plan_footer_tier(5, 0), FooterTier::Tiny, "survival floor");
    // The rare identities-unresolved note rides the footer and is
    // accounted: it costs one line, so the Full boundary moves to 18.
    assert_eq!(plan_footer_tier(18, 1), FooterTier::Full);
    assert_eq!(plan_footer_tier(17, 1), FooterTier::Compact);
}

/// NIGHT-improve-2 line-building pin (NIGHT-boost-14 composition):
/// the renderer fills the caller's vector — title bar first, the
/// breathing gap under it, the waiting note when idle, blank padding
/// in the middle, and the pinned footer last, the whole frame
/// spanning exactly the terminal height.
#[test]
fn eagle_frame_builds_lines() {
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &CounterSummary::default(),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
    );
    assert_eq!(lines.len(), 24, "the frame is pinned to the height");
    assert!(
        lines[0].starts_with("╭─── zelynic eagle-eyes"),
        "title carries the rounded top border (NIGHT-boost-20): {}",
        lines[0]
    );
    assert_eq!(
        lines[1],
        format!("│{}│", " ".repeat(78)),
        "breathing gap under the title, flanked by the rails"
    );
    assert!(lines.contains(&flanked("  waiting for traffic…").to_string()));
    // The pinned footer: the flat total row between two grid lines,
    // the census, the status line (NIGHT-engrave-2), and the
    // copyright as the frame's LAST content row — the closing border
    // row (NIGHT-boost-20) after it.
    let total_idx = lines
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .expect("total row even when idle");
    assert_eq!(
        lines[total_idx - 1],
        format!("│  {}│", "─".repeat(76)),
        "grid above the total row, inside the rails"
    );
    assert_eq!(
        lines[total_idx + 1],
        format!("│  {}│", "─".repeat(76)),
        "grid below the total row, inside the rails"
    );
    assert!(
        lines[total_idx].contains("total usage internet in 1m:10s"),
        "the total row carries the session uptime (NIGHT-engrave-1): {}",
        lines[total_idx]
    );
    assert!(
        lines.iter().any(|l| l.contains("0 packets + 0 cgroups")),
        "census line renders the + join: {:?}",
        lines
    );
    assert_eq!(
        lines[21],
        flanked("  1s realtime - theme netrunner - q quit - t theme"),
        "status line below where the limit suggestions sit (NIGHT-engrave-2)"
    );
    assert!(
        lines[22].starts_with("│  v") && lines[22].contains(") by oxyzenQ"),
        "copyright is the frame's last content row: {}",
        lines[22]
    );
    assert_eq!(
        lines[23],
        format!("╰{}╯", "─".repeat(78)),
        "the closing border row floors the frame (NIGHT-boost-20)"
    );
}

/// Footer honesty + the grip layout (NIGHT-boost-14, the owner's
/// exact spec; the total row re-shaped by NIGHT-engrave-1): the flat
/// `total usage internet in <uptime>` row sums EVERY candidate —
/// this frame's download/upload rates plus the session grand —
/// framed by two full-width grid lines; under it the census with its
/// own-width grip, the top consumer with its grip, the limit
/// suggestion, and the copyright pinned to the bottom of the
/// terminal whatever the table does.
#[test]
fn footer_grip_layout_pins_to_the_bottom() {
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
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    let total_row = lines
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .unwrap_or_else(|| panic!("no total row in: {joined}"));
    assert!(
        lines[total_row].contains("total usage internet in 1m:10s"),
        "the uptime rides inside the total row (NIGHT-engrave-1): {}",
        lines[total_row]
    );
    assert!(
        lines[total_row].contains("1.4 MB/s"),
        "total row dl rate: {}",
        lines[total_row]
    );
    assert!(
        lines[total_row].contains("240.0 KB/s"),
        "total row ul rate: {}",
        lines[total_row]
    );
    assert!(
        lines[total_row].contains("1.6 MB"),
        "total row session sum: {}",
        lines[total_row]
    );
    // The grip layout: grid above and below the total row (inside
    // the rails), census "+"-joined with its own-width grip,
    // copyright on the last content row, closing border after it.
    assert_eq!(lines[total_row - 1], format!("│  {}│", "─".repeat(76)));
    assert_eq!(lines[total_row + 1], format!("│  {}│", "─".repeat(76)));
    let census = &lines[total_row + 3];
    assert!(
        census.contains("478 packets + 1 cgroups"),
        "census wording: {census}"
    );
    assert_eq!(
        lines[total_row + 4],
        flanked(&format!(
            "  {}",
            "─".repeat("478 packets + 1 cgroups".chars().count())
        )),
        "the census grip is exactly the census text's own width"
    );
    assert_eq!(
        lines[21],
        flanked("  1s realtime - theme netrunner - q quit - t theme"),
        "status line below the limit suggestion (NIGHT-engrave-2)"
    );
    assert!(
        lines[22].starts_with("│  v") && lines[22].contains(") by oxyzenQ"),
        "copyright is the frame's last content row: {}",
        lines[22]
    );
    assert_eq!(
        lines[23],
        format!("╰{}╯", "─".repeat(78)),
        "the closing border row floors the frame (NIGHT-boost-20)"
    );
    assert_eq!(lines.len(), 24, "frame pinned to the terminal height");
    // The footer does not follow the table: blank padding sits
    // between the last table row and the grid above the total row.
    assert!(
        lines[total_row - 2].starts_with('│')
            && lines[total_row - 2].ends_with('│')
            && lines[total_row - 2]
                .chars()
                .skip(1)
                .take(76)
                .all(|c| c == ' '),
        "blank (railed) padding above the footer grid: {:?}",
        lines[total_row - 2]
    );
}

/// The top-consumer hint (NIGHT-boost-14; the name re-colored by
/// NIGHT-engrave-1): the rank-1 cgroup's busiest socket holder names
/// itself with a brand-purple name inside the grey footer, and the
/// limit suggestion follows — the discovery pair renders only on
/// unfiltered frames with live detail.
#[test]
fn footer_top_consumer_and_limit_hint() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    let identity = identity_with(&[("alacritty", 7001)]);
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                sockets: vec![SocketInfo {
                    proto: Proto::Tcp,
                    remote: "10.90.170.143:443".to_string(),
                    state: "ESTABLISHED",
                    queued: false,
                }],
            }],
        },
    );
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 500_000, 5_000),
        &[],
        &identity,
        Some(&conns),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("Top consumer: curl"),
        "the hint names the busiest process inside the champion: {joined}"
    );
    assert!(
        joined.contains("Limit it: sudo zelynic strict-single curl 100kb"),
        "the actionable limit line rides along: {joined}"
    );
    // Mono mode (tests run piped) strips color — the wording pins
    // the layout; the color tiers are pinned in output/color.rs.
    let top_idx = lines
        .iter()
        .position(|l| l.starts_with("│  Top consumer:"))
        .expect("top consumer line");
    assert_eq!(
        lines[top_idx + 1],
        flanked(&format!(
            "  {}",
            "─".repeat("Top consumer: curl".chars().count())
        )),
        "the consumer grip matches its own line width"
    );
}

/// Adaptive compact (NIGHT-boost-14, dynamic WxH): the subprocess
/// detail hides on frames too narrow for the TOTAL column, and
/// above it every detail line is trimmed to the frame width — a
/// long process/endpoint string can never wrap the frame.
#[test]
fn detail_hides_and_cuts_on_narrow_frames() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    let identity = identity_with(&[("alacritty", 7001)]);
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                // The long-horizon IPv6 endpoint: the detail line runs
                // past 51 columns naturally, so the trim path is the
                // one under test at width 51.
                sockets: vec![SocketInfo {
                    proto: Proto::Tcp,
                    remote: "2001:0db8:85a3:0000:0000:8a2e:0370:7334:443".to_string(),
                    state: "ESTABLISHED",
                    queued: false,
                }],
            }],
        },
    );

    // Narrow frame (width 50 — border inset 48 < 51): no detail
    // lines at all.
    let mut narrow = Vec::new();
    render_eagle_eyes_at(
        &mut narrow,
        &frame(7001, 500_000, 5_000),
        &[],
        &identity,
        Some(&conns),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 50,
            height: 24,
        },
    );
    assert!(
        !narrow.iter().any(|l| l.contains("└")),
        "subprocess detail hides below the TOTAL-column width: {:?}",
        narrow
    );
    assert_eq!(narrow.len(), 24, "the pin holds on narrow frames too");

    // Comfortable width (NIGHT-boost-20: the rails claim two columns,
    // so the frame needs 53 for a 51-column inset): the detail line
    // shows, trimmed to the inset — a long process or endpoint
    // string can never wrap the frame or shift the pinned footer.
    let mut snug = Vec::new();
    render_eagle_eyes_at(
        &mut snug,
        &frame(7001, 500_000, 5_000),
        &[],
        &identity,
        Some(&conns),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 53,
            height: 24,
        },
    );
    let detail = snug
        .iter()
        .find(|l| l.contains("curl ("))
        .expect("detail line at width 53");
    assert!(
        detail.chars().count() <= 53,
        "detail trimmed to the frame width (rails included): {detail}"
    );
    assert!(detail.contains('…'), "truncation marks itself: {detail}");
}

/// NIGHT-boost-16 / safety-security-1: the accumulate-explosion
/// render pin. A frame whose deltas and session accumulator sit at
/// u64::MAX must render WITHOUT panic in a debug build (the four
/// footer sums and the ranking key used to be plain `+` and `sum` —
/// debug panicked, release wrapped to a tiny grand total) and the
/// TOTAL row must carry the honest saturation figure (18.4 EB), not
/// a wrapped number.
#[test]
fn saturated_session_renders_without_panic() {
    let identity = identity_with(&[("saturator", 9001)]);
    let summary = CounterSummary {
        total_packets: u64::MAX,
        total_bytes: u64::MAX,
        total_ingress_packets: u64::MAX,
        total_ingress_bytes: u64::MAX,
        cgroups: vec![CgroupDelta {
            cgroup_id: 9001,
            packets: u64::MAX,
            bytes: u64::MAX,
            total_bytes: u64::MAX,
            ingress_packets: u64::MAX,
            ingress_bytes: u64::MAX,
            ingress_total_bytes: u64::MAX,
        }],
    };
    let mut session = SessionState::new();
    session.absorb(&summary);
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    assert_eq!(lines.len(), 24, "the pin holds at saturation");
    let joined = lines.join("\n");
    // NIGHT-boost-22: the extended SI ladder answers in EB at the
    // ceiling — u64::MAX renders as "18.4 EB" (the old TB-terminal
    // formatter drew "18446744.1 TB", five digits, the ragged
    // column the promotion contract forbids everywhere else).
    assert!(
        joined.contains("18.4 EB"),
        "the saturated session total renders the u64 ceiling honestly: {joined}"
    );
    assert!(
        lines.iter().any(|l| l.contains("total usage internet in")),
        "the total row survives saturation"
    );
}
