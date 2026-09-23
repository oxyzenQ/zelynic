// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pinned footer composition pins (NIGHT-boost-14; re-cut by
//! NIGHT-engrave-3, REBUILT by NIGHT-engrave-4): the owner's
//! engraved layout (the consumer headline, the session census, the
//! `= grand` total row, the limit suggestion, the status line, the
//! gap above the copyright), the pin itself (frame spanning the
//! terminal height with the footer near the bottom, never following
//! the table), and the saturated-session render. The tier ladder
//! and the rendered tier degradation live in footer_tier_tests.rs
//! (split when the engrave-4 rebuild pushed this file past the
//! owner's LOC cap), and the adaptive subprocess-detail pins live
//! with the detail tree's own pins. One file per contract, the same
//! #[path] discipline as the diff engine's pins. `super::` reaches
//! the footer module; the eagle renderer core is imported across
//! the render tree (it is `pub(super)` there).

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
    // The pinned footer (NIGHT-engrave-4): the census line joins the
    // block under the FLUSH roof grid, the total row follows, the
    // rare note rides, then air, the status line, the owner's gap
    // above the copyright, and the build stamp as the frame's LAST
    // content row — the closing border row (NIGHT-boost-20) after
    // it. An idle frame carries no consumer headline and no limit
    // suggestion (there is no champion yet) — the block is two
    // lines shorter and the measured pin absorbs it.
    let census_idx = lines
        .iter()
        .position(|l| l.contains("packets +"))
        .expect("census line even when idle");
    assert_eq!(
        lines[census_idx],
        flanked("  0 packets + 0 cgroups"),
        "the idle census is honest zeroes: {}",
        lines[census_idx]
    );
    let total_idx = lines
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .expect("total row even when idle");
    assert_eq!(
        total_idx,
        census_idx + 1,
        "the owner's order: census above the total row"
    );
    assert_eq!(
        lines[total_idx - 2],
        format!("│{}│", "─".repeat(78)),
        "the roof grid JOINS the left rail above the whole block — the owner's |---: {:?}",
        lines[total_idx - 2]
    );
    assert_eq!(
        lines[total_idx + 1],
        flanked("  (identities unresolved — labels show raw cgroup IDs)"),
        "the rare note rides between the total row and the status line"
    );
    assert!(
        !lines.iter().any(|l| l.contains("top consumer is")),
        "no consumer headline on an idle board: {:?}",
        lines
    );
    assert!(
        !lines.iter().any(|l| l.contains("limit target")),
        "no limit suggestion without a champion: {:?}",
        lines
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

/// Footer layout (NIGHT-boost-14, rebuilt by NIGHT-engrave-4): the
/// owner's exact line order — the consumer headline, the session
/// census, the total row, the limit suggestion, then the air, the
/// status line, the owner's gap above the copyright, and the build
/// stamp pinned to the bottom of the terminal whatever the table
/// does. The unresolved identity exercises the fallback chain: the
/// champion's name is the raw label (`cg:7001`), the identity-honest
/// name — the headline never goes dark over an identity miss.
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
    // The owner's engrave-4 order, as positions: headline, census,
    // total, limit — each found and compared to the next.
    let consumer_idx = lines
        .iter()
        .position(|l| l.contains("top consumer is"))
        .unwrap_or_else(|| panic!("no consumer headline in: {joined}"));
    assert_eq!(
        lines[consumer_idx],
        flanked("  top consumer is cg:7001"),
        "the unresolved identity falls back to the raw label — the identity-honest name: {}",
        lines[consumer_idx]
    );
    let census_idx = lines
        .iter()
        .position(|l| l.contains("packets +"))
        .unwrap_or_else(|| panic!("no census line in: {joined}"));
    assert_eq!(
        lines[census_idx],
        flanked("  478 packets + 1 cgroups"),
        "SESSION packets (57 ul + 421 dl) + the board count, one horizon: {}",
        lines[census_idx]
    );
    let total_row = lines
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .unwrap_or_else(|| panic!("no total row in: {joined}"));
    let limit_idx = lines
        .iter()
        .position(|l| l.contains("limit target with"))
        .unwrap_or_else(|| panic!("no limit suggestion in: {joined}"));
    assert_eq!(
        consumer_idx + 1,
        census_idx,
        "the owner's order: headline above census"
    );
    assert_eq!(census_idx + 1, total_row, "census above the total row");
    assert_eq!(
        total_row + 1,
        limit_idx,
        "the limit suggestion below the story"
    );
    assert_eq!(
        lines[limit_idx],
        flanked("  limit target with 'sudo zelynic ss cg:7001 100kb'"),
        "the owner's exact wording: quoted command, the ss short alias, the engraved default rate: {}",
        lines[limit_idx]
    );
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
    // The roof grid roofs the WHOLE block — the headline included.
    assert_eq!(lines[consumer_idx - 1], format!("│{}│", "─".repeat(78)));
    // The rare note rides after the limit line, end of the data
    // paragraph.
    assert_eq!(
        lines[limit_idx + 1],
        flanked("  (identities unresolved — labels show raw cgroup IDs)")
    );
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
    // between the last table row and the roof grid above the
    // headline.
    assert!(
        lines[consumer_idx - 2].starts_with('│')
            && lines[consumer_idx - 2].ends_with('│')
            && lines[consumer_idx - 2]
                .chars()
                .skip(1)
                .take(76)
                .all(|c| c == ' '),
        "blank (railed) padding above the footer grid: {:?}",
        lines[consumer_idx - 2]
    );
}

/// The NIGHT-engrave-4 restoration pin (the engraved pair is BACK,
/// re-cut to the owner's exact wording): the same live-detail
/// fixture that proved the pair's absence at engrave-3 now proves
/// the AUTODETECT — the rank-1 cgroup's busiest PROCESS (curl, the
/// socket holder) headlines, not the cgroup's first-resolved comm
/// (alacritty) — and the limit suggestion names the same process
/// with the `ss` short alias and the engraved default rate.
#[test]
fn footer_discovery_pair_renders_with_the_autodetect_name() {
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
        joined.contains("top consumer is curl"),
        "the autodetect names the busiest process INSIDE the champion cgroup (NIGHT-hunt-8 lineage): {joined}"
    );
    assert!(
        joined.contains("limit target with 'sudo zelynic ss curl 100kb'"),
        "the suggestion follows the owner's engrave-4 wording — the quoted command and the ss alias: {joined}"
    );
    assert!(
        !joined.contains("alacritty 100kb"),
        "the cgroup's first-resolved comm is NOT the suggested target: {joined}"
    );
    assert!(
        joined.contains("2 packets + 1 cgroups"),
        "the census rides too — the frame helper carries one packet per direction: {joined}"
    );
    assert_eq!(lines.len(), 24, "the pin is unchanged by the rebuild");
}

/// NIGHT-boost-16 / safety-security-1: the accumulate-explosion
/// render pin. A frame whose deltas and session accumulator sit at
/// u64::MAX must render WITHOUT panic in a debug build (the footer
/// sums and the ranking key used to be plain `+` and `sum` — debug
/// panicked, release wrapped to a tiny grand total) and the TOTAL
/// row must carry the honest saturation figure (18.4 EB), not a
/// wrapped number. NIGHT-engrave-4: the census line and the consumer
/// headline ride the same saturated frame without panic — the packet
/// counter saturates at its own honest ceiling.
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
    // NIGHT-engrave-4: the census saturates at its own honest
    // ceiling — the raw u64 packet count, no panic, no wrap.
    assert!(
        joined.contains("18446744073709551615 packets + 1 cgroups"),
        "the saturated packet counter renders its full figure: {joined}"
    );
    assert!(
        joined.contains("top consumer is saturator"),
        "the consumer headline rides the saturated frame: {joined}"
    );
}
