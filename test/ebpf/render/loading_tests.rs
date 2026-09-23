// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the monitor's opening frame (NIGHT-boost-25), kept
//! in the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from render/loading.rs. The contract has three
//! halves: the frame's SHAPE (it fills the terminal like every live
//! frame), its HONESTY (the note says loading, never the idle-state
//! "waiting for traffic"), and the MORPH (the first live frame at
//! t=0 differs from it in exactly ONE row — the note — because the
//! title bar and the pinned footer are byte-identical).

use super::*;

/// Both frames the morph pin compares carry the status line, whose
/// theme slot follows the process-global theme — other pins
/// legitimately flip it (`theme::set` in border_tests). Normalizing
/// the theme NAME keeps the morph pin deterministic under the
/// default parallel test runner; the RAIL colors follow the theme
/// too, so both frames are built back-to-back under a pinned theme.
fn with_theme_pinned(
    frames: impl FnOnce() -> (Vec<String>, Vec<String>),
) -> (Vec<String>, Vec<String>) {
    crate::output::theme::set(crate::output::theme::Theme::Netrunner);
    frames()
}

#[test]
fn loading_frame_fills_the_terminal_at_every_size() {
    for (w, h) in [(80usize, 24usize), (100, 40), (60, 12), (45, 9), (80, 8)] {
        let geo = FrameGeometry {
            width: w,
            height: h,
        };
        let frame = loading_frame(Duration::from_secs(1), geo);
        assert_eq!(
            frame.len(),
            geo.height,
            "the opening frame fills the terminal exactly at {w}x{h}"
        );
    }
}

#[test]
fn loading_frame_carries_the_live_title_and_floor() {
    let geo = FrameGeometry {
        width: 80,
        height: 24,
    };
    let frame = loading_frame(Duration::from_secs(1), geo);
    // Byte-identical to the live frame's title row — the morph never
    // repaints it.
    assert_eq!(
        frame[0],
        title_bar("zelynic eagle-eyes", 80),
        "the title row must match the live frame's exactly"
    );
    // The closing border row (BD-02 bright anchor floor).
    assert!(
        frame[23].starts_with('╰') && frame[23].ends_with('╯'),
        "the frame closes on its floor row, got: {}",
        frame[23]
    );
}

#[test]
fn the_note_says_loading_not_the_idle_state() {
    let geo = FrameGeometry {
        width: 80,
        height: 24,
    };
    let frame = loading_frame(Duration::from_secs(1), geo);
    assert!(
        frame[2].contains("loading observer…"),
        "row 2 carries the loading note, got: {}",
        frame[2]
    );
    // Honesty: the observer is not up yet, so the idle-state line
    // must not appear anywhere — and the morph stays visible.
    assert!(
        !frame.iter().any(|r| r.contains("waiting for traffic")),
        "loading is not idle: no waiting line during the load"
    );
}

#[test]
fn the_footer_is_the_empty_session_footer() {
    let geo = FrameGeometry {
        width: 80,
        height: 24,
    };
    let frame = loading_frame(Duration::from_secs(1), geo);
    let joined = frame.join("\n");
    // The census-of-nothing rows, pinned as text (the tier Full
    // carries at 24 rows): zero figures, no consumer headline, no
    // limit suggestion — those need a champion the board lacks. The
    // NIGHT-engrave-6 speed pair rides as honest zeroes (`0 B/s`,
    // never the limiter's BLOCKED verdict) so the morph never
    // touches these rows either.
    for fragment in [
        "0 packets + 0 cgroups",
        "total usage internet in 0s = 0 B",
        "total max dl | ul = 0 B/s | 0 B/s",
        "total avg dl | ul = 0 B/s | 0 B/s",
        "1s realtime - theme ",
        " - q quit - t theme",
        "by oxyzenQ",
    ] {
        assert!(
            joined.contains(fragment),
            "the empty-session footer carries '{fragment}'"
        );
    }
    assert!(
        !joined.contains("top consumer is"),
        "no consumer headline before a board exists"
    );
    assert!(
        !joined.contains("limit target with"),
        "no limit suggestion before a consumer exists"
    );
}

/// THE morph pin: the first live frame at t=0 (empty session, default
/// summary, identity resolved — one entry, the normal machine) vs the
/// opening frame. Every row is byte-identical except row 2, where
/// `loading observer…` becomes `waiting for traffic…` — the masterclass
/// transition: one row repaints, the chrome never does.
#[test]
fn the_first_live_frame_morphs_only_the_note_row() {
    use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
    use crate::ebpf::loader::CounterSummary;
    use crate::ebpf::render::SessionState;

    let geo = FrameGeometry {
        width: 80,
        height: 24,
    };
    let interval = Duration::from_secs(1);

    let (loading, live) = with_theme_pinned(|| {
        let mut identity = IdentityMap::new();
        identity.insert(ProcessIdentity {
            cgroup_id: 42,
            uid: 1000,
            comm: "curl".to_string(),
        });
        let mut session_state = SessionState::new();
        let summary = CounterSummary::default();
        let mut live: Vec<String> = Vec::new();
        super::super::eagle::render_eagle_eyes_at(
            &mut live,
            &summary,
            &[],
            &identity,
            None,
            interval,
            &mut session_state,
            Duration::ZERO,
            geo,
        );
        let loading = loading_frame(interval, geo);
        (loading, live)
    });

    assert_eq!(loading.len(), live.len(), "both frames fill the terminal");
    assert!(
        live[2].contains("waiting for traffic…"),
        "the live t=0 frame is idle at row 2, got: {}",
        live[2]
    );
    let mut diffs = Vec::new();
    for (i, (a, b)) in loading.iter().zip(live.iter()).enumerate() {
        if a != b {
            diffs.push(i);
        }
    }
    assert_eq!(
        diffs,
        vec![2],
        "exactly the note row differs (loading -> waiting); got diffs at {diffs:?}"
    );
}

/// Short terminals: the opening frame survives the same compression
/// ladder the live footer walks (the tier pins the footer module
/// holds) — the frame still fills the terminal, the note still rides
/// under the title.
#[test]
fn short_terminals_keep_the_note_and_the_fill() {
    let geo = FrameGeometry {
        width: 80,
        height: 10,
    };
    let frame = loading_frame(Duration::from_secs(5), geo);
    assert_eq!(frame.len(), geo.height, "the frame fills a 10-row window");
    assert!(frame[0].starts_with("╭─── zelynic eagle-eyes"));
    assert!(frame[2].contains("loading observer…"));
    let joined = frame.join("\n");
    assert!(
        joined.contains("5s realtime - theme "),
        "the status line names the real cadence, got: {joined}"
    );
    assert!(joined.contains("by oxyzenQ"), "the stamp survives");
}
