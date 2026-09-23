// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pinned footer composition pins (NIGHT-boost-14; re-cut by
//! NIGHT-engrave-3): the tier ladder, the owner's engraved layout
//! (the flush roof grid, the `= grand` total row, the status line,
//! the gap above the copyright), the retirement of the census and
//! the discovery pair, the pin itself (frame spanning the terminal
//! height with the footer near the bottom, never following the
//! table), and the adaptive subprocess-detail behavior. Split from
//! the eagle renderer pins when the boost-14 composition work pushed
//! the file past the owner's LOC cap - one file per contract, the
//! same #[path] discipline as the diff engine's pins. `super::`
//! reaches the footer module; the eagle renderer core is imported
//! across the render tree (it is `pub(super)` there).

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

/// Footer compression ladder (NIGHT-boost-14; NIGHT-engrave-3 re-cut
/// it for the trimmed block — 6/5/4/3): the classic 80x24 carries the
/// full engraved block; a 10-row window drops to Compact, 9 to
/// Minimal, and the survival floor holds from 8 down. The rare
/// identities-unresolved note costs one line and moves the Full
/// boundary with it.
#[test]
fn footer_tier_ladder() {
    assert_eq!(plan_footer_tier(24, 0), FooterTier::Full);
    assert_eq!(
        plan_footer_tier(11, 0),
        FooterTier::Full,
        "11 = 4 chrome + 6 footer + 1 row"
    );
    assert_eq!(plan_footer_tier(10, 0), FooterTier::Compact);
    assert_eq!(plan_footer_tier(9, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(8, 0), FooterTier::Tiny);
    assert_eq!(plan_footer_tier(5, 0), FooterTier::Tiny, "survival floor");
    // The rare identities-unresolved note rides the footer and is
    // accounted: it costs one line, so the Full boundary moves to 12.
    assert_eq!(plan_footer_tier(12, 1), FooterTier::Full);
    assert_eq!(plan_footer_tier(11, 1), FooterTier::Compact);
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
    // The pinned footer (NIGHT-engrave-3): the total row under its
    // FLUSH roof grid, air, the status line, the owner's gap above
    // the copyright, and the build stamp as the frame's LAST content
    // row — the closing border row (NIGHT-boost-20) after it.
    let total_idx = lines
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .expect("total row even when idle");
    assert_eq!(
        lines[total_idx - 1],
        format!("│{}│", "─".repeat(78)),
        "the roof grid JOINS the left rail — the owner's |---, never | ---: {:?}",
        lines[total_idx - 1]
    );
    assert_eq!(
        lines[total_idx + 1],
        flanked("  (identities unresolved — labels show raw cgroup IDs)"),
        "the rare note rides between the total row and the status line"
    );
    assert!(
        lines[total_idx].contains("total usage internet in 1m:10s"),
        "the total row carries the session uptime (NIGHT-engrave-1): {}",
        lines[total_idx]
    );
    assert!(
        lines[total_idx].contains("= 0 B"),
        "engrave-3: the `=` grand total, the rates retired: {}",
        lines[total_idx]
    );
    assert_eq!(
        lines[20],
        flanked("  1s realtime - theme netrunner - q quit - t theme"),
        "status line (NIGHT-engrave-2), the legend's only home since the engrave-3 title trim"
    );
    assert_eq!(
        lines[21],
        format!("│{}│", " ".repeat(78)),
        "the owner's engrave-3 gap above the copyright"
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

/// Footer layout (NIGHT-boost-14, re-cut by NIGHT-engrave-3): the
/// flat `total usage internet in <uptime> = <grand>` row under its
/// flush roof grid — the per-frame rates RETIRED at the owner's
/// "only total consume bandwidth" call — then air, the status line,
/// the owner's gap above the copyright, and the build stamp pinned
/// to the bottom of the terminal whatever the table does.
#[test]
fn footer_layout_pins_to_the_bottom() {
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
        lines[total_row].contains("= 1.6 MB"),
        "engrave-3: the row reads horizon = grand, nothing else: {}",
        lines[total_row]
    );
    assert!(
        !lines[total_row].contains("/s"),
        "engrave-3: the rate tail is retired from the total row: {}",
        lines[total_row]
    );
    // The engraved trim: census, discovery pair, second grid — all
    // retired (the owner's leanest-footer call).
    assert!(!joined.contains("packets +"), "census retired: {joined}");
    assert!(
        !joined.contains("Top consumer"),
        "discovery retired: {joined}"
    );
    assert!(!joined.contains("Limit it"), "limit hint retired: {joined}");
    // The roof grid joins the left rail — the owner's |--- contract.
    assert_eq!(lines[total_row - 1], format!("│{}│", "─".repeat(78)));
    assert_eq!(
        lines[20],
        flanked("  1s realtime - theme netrunner - q quit - t theme"),
        "status line (NIGHT-engrave-2)"
    );
    assert_eq!(
        lines[21],
        format!("│{}│", " ".repeat(78)),
        "the owner's engrave-3 gap above the copyright"
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
    // between the last table row and the roof grid above the total
    // row.
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

/// The NIGHT-engrave-3 retirement pin: the discovery pair (Top
/// consumer + Limit it) and the census line no longer render on ANY
/// frame — the owner's leanest-footer call. The same live-detail
/// fixture that used to light the pair now proves its absence.
#[test]
fn footer_discovery_pair_and_census_are_retired() {
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
        !joined.contains("Top consumer"),
        "retired at engrave-3: {joined}"
    );
    assert!(
        !joined.contains("Limit it"),
        "retired with its pair: {joined}"
    );
    assert!(
        !joined.contains("packets +"),
        "the census is retired: {joined}"
    );
    assert_eq!(lines.len(), 24, "the pin is unchanged by the trim");
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
