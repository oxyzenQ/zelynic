// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-engrave-1-ee layout pins: the deep line's indent contract.
//! The eagle-eyes deep line — the row's rtt ± jitter / retransmit /
//! tcp-eps figures — indents to the detail tree's FIRST level (the
//! cgroup block's own four columns), so it reads as the child of the
//! row whose sockets it summarizes. The old column-0 shape read as
//! the next row's opening line: the owner's live find ("disangka
//! bug" — the layout said bug where the truth was structure). Wired
//! into `src/ebpf/render/eagle.rs` via #[path] (cosmostrix Pattern
//! C, the one-file-per-contract split).

use super::*;
use crate::ebpf::connections::{
    CgroupConnections, ProcessDetail, Proto, SocketInfo, TcpDeepWindow,
};
use crate::ebpf::loader::CgroupDelta;
use std::collections::HashMap;

/// One traffic frame for `cg` with the given per-frame deltas (the
/// eagle_tests fixture, carried self-contained — Pattern C's rule).
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

/// A two-socket curl holder with one readable deep window (cookie
/// 100 measured, cookie 200 fresh — the row's hungriest endpoint
/// carries the figures, the count spans both).
fn seeded_conns() -> ConnectionMap {
    let tcp = |cookie: u64| SocketInfo {
        inode: 42,
        proto: Proto::Tcp,
        remote: "149.50.211.154:4444".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie: Some(cookie),
        deep: None,
    };
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([(
        100u64,
        TcpDeepWindow {
            rtt_us: 40_200,
            rttvar_us: 14_600,
            retrans_window: 0,
            segs_out_window: 287,
        },
    )]));
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                sockets: vec![tcp(100), tcp(200)],
            }],
        },
    );
    conns
}

/// The masterclass law, pinned end to end: the deep line renders
/// under the socket tree it summarizes — indented to the detail
/// tree's first level, carrying the figures verbatim — and the
/// column-0 shape can never render again.
#[test]
fn deep_line_indents_under_the_socket_tree_it_summarizes() {
    let conns = seeded_conns();
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 1_400_000, 240_000),
        &[],
        &IdentityMap::new(),
        Some(&conns),
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        &BaselineLane::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 100,
            height: 40,
        },
        &mut ScrollState::new(),
        true,
    );
    let joined = lines.join("\n");

    // The indented shape renders — the cgroup block's own four
    // columns, under the tree.
    let deep_idx = lines
        .iter()
        .position(|l| l.starts_with(" │    rtt"))
        .unwrap_or_else(|| panic!("no indented deep line in:\n{joined}"));

    // The figures ride it verbatim (the deep family's own grammar).
    let deep = &lines[deep_idx];
    for figure in [
        "rtt 40.2ms",
        "±14.6ms",
        "retrans 0/287 segs (0.00%)",
        "2 tcp eps",
    ] {
        assert!(deep.contains(figure), "`{figure}` missing from: {deep}");
    }

    // The noob shape is dead: no deep figures at column 0.
    assert!(
        !lines.iter().any(|l| l.starts_with(" │rtt")),
        "a column-0 deep line rendered:\n{joined}"
    );

    // And it sits BELOW the socket tree it summarizes — the detail
    // tree's own lines come first, the figures under them.
    let tree_idx = lines
        .iter()
        .position(|l| l.starts_with(" │    └"))
        .unwrap_or_else(|| panic!("no detail tree in:\n{joined}"));
    assert!(
        deep_idx > tree_idx,
        "the deep line ({deep_idx}) must follow the socket tree ({tree_idx})"
    );
}

/// The detail tree's own contract is untouched (night-engrave-1-ee
/// moved ONLY the deep line): the holder lines keep their first-
/// level indent, the endpoint children their second.
#[test]
fn detail_tree_indents_stay_untouched() {
    let conns = seeded_conns();
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 1_400_000, 240_000),
        &[],
        &IdentityMap::new(),
        Some(&conns),
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        &BaselineLane::new(),
        Duration::from_secs(70),
        FrameGeometry {
            width: 100,
            height: 40,
        },
        &mut ScrollState::new(),
        true,
    );
    let joined = lines.join("\n");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(" │    └ curl (4242) 2 sockets:")),
        "the holder line keeps its first-level indent:\n{joined}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with(" │        ├ tcp")),
        "the endpoint children keep their second-level indent:\n{joined}"
    );
}
