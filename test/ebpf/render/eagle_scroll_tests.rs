// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The night-improve-58 scroll-integration pins (one file per
//! contract, the eagle_tests LOC-cap split): the arrows walking
//! the REAL render path — the window, the true ranks, the scroll
//! note, and the focus gutter marker. The pure scroll-state core
//! pins live in scroll_tests.rs one home over; this tree holds the
//! frame-level contracts only.

use super::*;
use crate::ebpf::identity::ProcessIdentity;
use crate::ebpf::loader::CgroupDelta;
use crate::ebpf::render::ScrollState;
use std::time::Duration;

/// The 80x24 classic terminal, self-contained (the Pattern C rule:
/// every #[path] tree carries its own fixtures).
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// An identity naming every cgroup `app` (the pin's labels stay
/// predictable regardless of resolution).
fn flat_identity(ids: &[u32]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for cg in ids {
        identity.insert(ProcessIdentity {
            cgroup_id: *cg,
            uid: 1000,
            comm: "app".to_string(),
        });
    }
    identity
}

/// night-improve-58: the arrows walk the table's window — the rank
/// column keeps the board's TRUE rank (never the window's
/// position), the scroll note names both directions (the rows the
/// offset skipped AND the rows the room cut), and the focus marker
/// rides the focused section's header gutter: `▸` on the table at
/// rest, gone the moment the right arrow moves the focus to the
/// panel.
#[test]
fn arrow_scroll_walks_the_table_window() {
    let identity = flat_identity(&(1..=12u32).map(|i| 70000 + i).collect::<Vec<_>>());
    // Twelve roots, the heaviest first: rank i belongs to cg:7000i
    // (the board sorts by session total, descending).
    let summary = CounterSummary {
        total_packets: 12,
        total_bytes: 78_000,
        total_ingress_packets: 120,
        total_ingress_bytes: 78_000,
        cgroups: (1..=12u32)
            .map(|i| CgroupDelta {
                cgroup_id: 70000 + i,
                packets: 1,
                bytes: ((13 - i) * 500) as u64,
                total_bytes: ((13 - i) * 1000) as u64,
                ingress_packets: 10,
                ingress_bytes: ((13 - i) * 500) as u64,
                ingress_total_bytes: ((13 - i) * 1000) as u64,
            })
            .collect(),
    };

    // The resting window: rank 1 leads, the note counts the rows
    // the 80x24 room cut (twelve roots cannot fit — the frame that
    // once said "raise the window" now says scroll).
    let mut session = SessionState::new();
    let mut scroll = ScrollState::new();
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        &BaselineLane::new(),
        Duration::from_secs(70),
        classic(),
        &mut scroll,
    );
    let joined = lines.join("\n");
    assert!(
        lines.iter().any(|l| l.starts_with(" │   1  ")),
        "rank 1 leads the resting window: {joined}"
    );
    assert!(
        joined.contains("more — ↑↓ scroll"),
        "the truncating table names the scroll instead of the resize: {joined}"
    );

    // Two downs walk the window: rank 3 leads, rank 1 sits above
    // the window (its row gone, the note naming the skip), and the
    // rank column keeps the TRUE ranks — 3, not a window-position 1.
    scroll.apply(crate::terminal::InputAction::ScrollDown);
    scroll.apply(crate::terminal::InputAction::ScrollDown);
    let mut walked = Vec::new();
    render_eagle_eyes_at(
        &mut walked,
        &summary,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        &BaselineLane::new(),
        Duration::from_secs(70),
        classic(),
        &mut scroll,
    );
    let w = walked.join("\n");
    assert!(
        !walked.iter().any(|l| l.starts_with(" │   1  ")),
        "rank 1 sits above the walked window: {w}"
    );
    assert!(
        walked.iter().any(|l| l.starts_with(" │   3  ")),
        "rank 3 leads the walked window (the TRUE rank, never the position): {w}"
    );
    assert!(
        w.contains("-2 above"),
        "the note names the rows the offset skipped: {w}"
    );

    // The right arrow moves the focus: the table's header loses
    // the marker (the panel owns it now — the panel pin holds that
    // side of the contract).
    scroll.apply(crate::terminal::InputAction::SectionNext);
    let mut refocused = Vec::new();
    render_eagle_eyes_at(
        &mut refocused,
        &summary,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        &BaselineLane::new(),
        Duration::from_secs(70),
        classic(),
        &mut scroll,
    );
    let header = refocused
        .iter()
        .find(|l| l.contains("top process"))
        .unwrap_or_else(|| panic!("no header row in: {refocused:?}"));
    assert!(
        header.starts_with(" │  top process"),
        "the unfocused table's header keeps its plain gutter: {header}"
    );
}
