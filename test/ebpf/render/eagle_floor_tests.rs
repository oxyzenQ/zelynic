// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! night-improve-72 floor pins: the table never starves the baseline
//! police. The owner's live find: scrolling the top process window
//! decided the panel's fate — scroll up to the busy head ranks and
//! the `baseline · policy aggregate` section vanished whole (the
//! table ate every line to the footer pin, the panel's leftover
//! room hit zero, and its renderer returned before drawing a
//! thing); scroll down to the quiet tail and the shorter rows let
//! it back. The floor this task carves — the panel's
//! guaranteed-visible shape withheld from the table's budget —
//! breaks that coupling: both sections hold their places at every
//! window offset, at every height that can fit them both. The
//! degradation below the floor is pinned too: a frame too short
//! for both keeps the table (the ranked view is the primary one).

use super::*;
use crate::ebpf::identity::ProcessIdentity;
use crate::ebpf::loader::CgroupDelta;
use crate::ebpf::render::ScrollState;
use std::time::Duration;

/// The 80-wide geometry at the asked height, self-contained (the
/// Pattern C rule: every #[path] tree carries its own fixtures).
fn classic(height: usize) -> FrameGeometry {
    FrameGeometry { width: 80, height }
}

/// An identity naming every cgroup `app` (predictable labels,
/// regardless of rank order).
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

/// Thirty roots, the heaviest first — a board rich enough to fill
/// the frame at BOTH pinned heights, so the table's appetite is the
/// only variable (the scroll-integration sibling's twelve-root
/// fixture starves only the short frame; this one starves them
/// both, the owner's normal-and-limited report).
fn rich_board() -> CounterSummary {
    CounterSummary {
        total_packets: 30,
        total_bytes: 465_000,
        total_ingress_packets: 300,
        total_ingress_bytes: 465_000,
        cgroups: (1..=30u32)
            .map(|i| CgroupDelta {
                cgroup_id: 70000 + i,
                packets: 1,
                bytes: ((31 - i) * 500) as u64,
                total_bytes: ((31 - i) * 1000) as u64,
                ingress_packets: 10,
                ingress_bytes: ((31 - i) * 500) as u64,
                ingress_total_bytes: ((31 - i) * 1000) as u64,
            })
            .collect(),
    }
}

/// The night-improve-72 law, pinned at a limited and a normal
/// height: a board rich enough to fill the frame STILL leaves the
/// baseline police its floor — the section title, at least one
/// verdict row, and rank 1 all visible in the SAME frame. Before
/// the floor, both heights starved the panel to zero rows and the
/// section vanished whole.
#[test]
fn a_full_board_never_starves_the_baseline_panel() {
    for height in [24usize, 40] {
        let identity = flat_identity(&(1..=30u32).map(|i| 70000 + i).collect::<Vec<_>>());
        let mut lane = BaselineLane::new();
        lane.seed_for_pins(7001, 40_000);
        let mut session = SessionState::new();
        let mut scroll = ScrollState::new();
        let mut lines = Vec::new();
        render_eagle_eyes_at(
            &mut lines,
            &rich_board(),
            &[],
            &identity,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &mut session,
            &lane,
            Duration::from_secs(70),
            classic(height),
            &mut scroll,
        );
        let joined = lines.join("\n");
        assert_eq!(lines.len(), height, "the frame stays pinned to the height");
        assert!(
            lines.iter().any(|l| l.starts_with(" │    1  ")),
            "rank 1 stays visible beside the panel (height {height}): {joined}"
        );
        assert!(
            joined.contains("baseline · policy aggregate"),
            "the panel's section title survives a full board (height {height}): {joined}"
        );
        assert!(
            joined.contains("learning 7/8"),
            "at least one verdict row rides under the title (height {height}): {joined}"
        );
    }
}

/// The owner's exact walk: the panel's visibility no longer depends
/// on WHERE the table's window sits. Before the floor, scrolling
/// toward the quiet tail was the only way to bring the panel back;
/// now the section holds its place at every offset — walked down,
/// walked back up, the title and a verdict row stay on the frame.
#[test]
fn the_panel_stays_through_the_window_walk() {
    let identity = flat_identity(&(1..=30u32).map(|i| 70000 + i).collect::<Vec<_>>());
    let mut lane = BaselineLane::new();
    lane.seed_for_pins(7001, 40_000);
    let mut session = SessionState::new();
    let mut scroll = ScrollState::new();

    let mut render = |scroll: &mut ScrollState| {
        let mut lines = Vec::new();
        render_eagle_eyes_at(
            &mut lines,
            &rich_board(),
            &[],
            &identity,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &mut session,
            &lane,
            Duration::from_secs(70),
            classic(24),
            scroll,
        );
        lines.join("\n")
    };

    // Walked down two: rank 3 leads, the note names the skip — and
    // the panel stays.
    scroll.apply(crate::terminal::InputAction::ScrollDown);
    scroll.apply(crate::terminal::InputAction::ScrollDown);
    let walked = render(&mut scroll);
    assert!(
        walked.contains(" │    3  "),
        "rank 3 leads the walked window: {walked}"
    );
    assert!(
        walked.contains("-2 above"),
        "the note names the rows the offset skipped: {walked}"
    );
    assert!(
        walked.contains("baseline · policy aggregate") && walked.contains("learning 7/8"),
        "the panel holds its place through the walk down: {walked}"
    );

    // Walked back up: rank 1 leads again — the panel never left.
    scroll.apply(crate::terminal::InputAction::ScrollUp);
    scroll.apply(crate::terminal::InputAction::ScrollUp);
    let back = render(&mut scroll);
    assert!(
        back.contains(" │    1  "),
        "rank 1 leads the returned window: {back}"
    );
    assert!(
        back.contains("baseline · policy aggregate") && back.contains("learning 7/8"),
        "the panel holds its place through the walk back: {back}"
    );
}

/// The degradation, pinned: a frame too short to hold the table's
/// minimum AND the panel's floor keeps the table — the ranked view
/// is the primary one, and the panel starving below the floor is
/// the old behavior by design, not a regression. The champion row
/// is the last thing the short frame gives up.
#[test]
fn a_frame_too_short_for_both_keeps_the_table() {
    let identity = flat_identity(&(1..=30u32).map(|i| 70000 + i).collect::<Vec<_>>());
    let mut lane = BaselineLane::new();
    lane.seed_for_pins(7001, 40_000);
    let mut session = SessionState::new();
    let mut scroll = ScrollState::new();
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &rich_board(),
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        &lane,
        Duration::from_secs(70),
        classic(14),
        &mut scroll,
    );
    let joined = lines.join("\n");
    assert_eq!(lines.len(), 14, "the frame stays pinned to the height");
    assert!(
        lines.iter().any(|l| l.starts_with(" │    1  ")),
        "the short frame keeps the ranked view (rank 1 visible): {joined}"
    );
}
