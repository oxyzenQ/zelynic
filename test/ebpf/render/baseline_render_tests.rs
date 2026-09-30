// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! EAGLE EYES V2 render pins (NIGHT-improve-1a): the phrase
//! vocabulary, the focus row, and the panel shapes — the render
//! half of test/ebpf/render/baseline_tests.rs's fold pins (the
//! sibling-split the 500-LOC owner cap demanded, the docker_tests
//! lineage). #[path]-wired from src/ebpf/render/baseline.rs beside
//! its fold sibling, so `super::` reaches the lane exactly the same.

use super::*;
use crate::ebpf::identity::ProcessIdentity;
use crate::ebpf::limiter::rate_ring::RATE_RING_WINDOW_NS;

// ── Fixtures (the fold sibling's shapes, self-contained — the
// Pattern C single-test-tree rule: every #[path] tree carries its
// own) ──────────────────────────────────────────────────────────────

/// Read time mid-window AFTER `win` (the fold sibling's twin).
fn at(win: u64) -> u64 {
    (win + 1) * RATE_RING_WINDOW_NS + 500_000_000
}

/// One read at `at(win)` with the given stamps.
fn fold_call(states: &mut HashMap<u32, BaselineState>, key: u32, win: u64, stamps: &[(u64, u64)]) {
    let mut raw = RateRingRaw::default();
    for (w, b) in stamps {
        let slot = &mut raw.slots[(*w % RATE_RING_SLOTS as u64) as usize];
        slot.window = *w;
        slot.bytes = *b;
    }
    BaselineLane::fold_direction(states, Some(&[(key, raw)]), at(win));
}

/// Steady at `level`: the full horizon at the level, then its
/// eighth window — eight contiguous live folds, EMA exactly level.
fn drive_steady(states: &mut HashMap<u32, BaselineState>, key: u32, level: u64) {
    let horizon: Vec<(u64, u64)> = (94..=100).map(|w| (w, level)).collect();
    fold_call(states, key, 100, &horizon);
    fold_call(states, key, 101, &[(101, level)]);
}

/// One read carrying SEVERAL keys' rings (the census shape).
fn fold_call_multi(
    states: &mut HashMap<u32, BaselineState>,
    rings: &[(u32, &[(u64, u64)])],
    win: u64,
) {
    let rows: Vec<(u32, RateRingRaw)> = rings
        .iter()
        .map(|(k, stamps)| {
            let mut raw = RateRingRaw::default();
            for (w, b) in *stamps {
                let slot = &mut raw.slots[(*w % RATE_RING_SLOTS as u64) as usize];
                slot.window = *w;
                slot.bytes = *b;
            }
            (*k, raw)
        })
        .collect();
    BaselineLane::fold_direction(states, Some(&rows), at(win));
}

/// The phrase vocabulary, every arm — the wording is the contract.
#[test]
fn phrase_vocabulary_every_arm() {
    assert_eq!(phrase(None), "");
    assert_eq!(
        phrase(Some(BaselineWord::Learning { samples: 3 })),
        grey("learning 3/8")
    );
    assert_eq!(
        phrase(Some(BaselineWord::Steady { bps: 98_000 })),
        "steady 98.0 KB/s"
    );
    // The learned-quiet zero: steady 0 B/s, never the limiter's
    // BLOCKED verdict wording — the two contexts disagree about
    // zero on purpose (rate_figure's doc).
    assert_eq!(
        phrase(Some(BaselineWord::Steady { bps: 0 })),
        "steady 0 B/s"
    );
    assert_eq!(
        phrase(Some(BaselineWord::Above {
            percent: Some(64),
            base: 12_400
        })),
        warn("above +64% (base 12.4 KB/s)")
    );
    assert_eq!(
        phrase(Some(BaselineWord::Below {
            percent: Some(78),
            base: 5_400_000
        })),
        warn("below -78% (base 5.4 MB/s)")
    );
    // A percent of zero has no meaning; the figure drops, the
    // verdict and its base stay.
    assert_eq!(
        phrase(Some(BaselineWord::Above {
            percent: None,
            base: 0
        })),
        warn("above (base 0 B/s)")
    );
}

/// Both directions on one line, ` · ` between; one-sided states
/// render their one side alone.
#[test]
fn pair_phrase_forms() {
    let both = pair_phrase(
        Some(BaselineWord::Steady { bps: 98_000 }),
        Some(BaselineWord::Learning { samples: 2 }),
    );
    assert_eq!(both, format!("steady 98.0 KB/s · {}", grey("learning 2/8")));
    let dl_only = pair_phrase(Some(BaselineWord::Steady { bps: 98_000 }), None);
    assert_eq!(dl_only, "steady 98.0 KB/s");
    assert_eq!(pair_phrase(None, None), "");
}

/// The focus row joins the key/value block at the baseline key
/// column; a lens with no state for the cgroup renders nothing.
#[test]
fn focus_row_shape_and_absence() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 98_000);
    let mut lines = Vec::new();
    render_focus_row(&mut lines, &lane, 7);
    assert_eq!(
        lines,
        vec!["  baseline  steady 98.0 KB/s".to_string()],
        "the key/value block's column: two spaces after the 8-char key"
    );
    let mut quiet = Vec::new();
    render_focus_row(&mut quiet, &lane, 8);
    assert!(quiet.is_empty(), "absent-lens: no state, no row");
}

/// The panel: header, per-policy rows with identity labels, the
/// watched-set filter, the honest hidden note, and the two-row
/// floor. A policy unknown to identity labels by its cgroup id —
/// the depth tree's own fallback shape.
#[test]
fn panel_shapes_filter_and_trim() {
    let mut lane = BaselineLane::new();
    // Three policies across both directions, every direction's set
    // riding the census reads (the retain drops keys a read does
    // not name — per-key drives would drop each other).
    let horizon = |l: u64| (94..=100).map(|w| (w, l)).collect::<Vec<_>>();
    fold_call_multi(
        &mut lane.dl,
        &[(7, &horizon(98_000)), (8, &horizon(3_100_000))],
        100,
    );
    fold_call_multi(
        &mut lane.dl,
        &[(7, &[(101, 98_000)]), (8, &[(101, 3_100_000)])],
        101,
    );
    fold_call_multi(&mut lane.ul, &[(9, &horizon(1_400_000))], 100);
    fold_call_multi(&mut lane.ul, &[(9, &[(101, 1_400_000)])], 101);
    let mut identity = IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 7,
        uid: 1000,
        comm: "nginx".to_string(),
    });
    let mut lines = Vec::new();
    render_panel(&mut lines, &lane, &identity, None, 10);
    let joined = lines.join("\n");
    assert!(
        joined.contains("baseline · policy aggregate (8s ring)"),
        "the header names the lens: {joined}"
    );
    assert!(
        joined.contains("cg:7 (nginx)") && joined.contains("steady 98.0 KB/s"),
        "known policy roots label with identity: {joined}"
    );
    assert!(
        joined.contains("cg:9") && joined.contains("steady 1.4 MB/s"),
        "unknown roots fall back to the id label: {joined}"
    );
    // The filter: a watched set that names key 9 drops the others.
    let mut filtered = Vec::new();
    render_panel(&mut filtered, &lane, &identity, Some(&[9]), 10);
    assert!(filtered.join("\n").contains("cg:9"));
    assert!(!filtered.join("\n").contains("nginx"));
    // The trim: room for header + 1 row of the three, plus the
    // honest hidden note for the other two.
    let mut trimmed = Vec::new();
    render_panel(&mut trimmed, &lane, &identity, None, 3);
    let t = trimmed.join("\n");
    assert!(
        t.contains("steady 3.1 MB/s") && t.contains("(+2 more hidden — raise the window)"),
        "the honest trim: {t}"
    );
    // Below two rows of room the panel is skipped entirely.
    let mut tiny = Vec::new();
    render_panel(&mut tiny, &lane, &identity, None, 1);
    assert!(tiny.is_empty(), "a header with nothing under it is noise");
}

/// The lane absent (no pins anywhere — the rootless shape every
/// monitor owns when nothing is policed): no panel, no focus row.
/// This pins the ABSENCE through the pure layer — a lane with no
/// states renders nothing at either surface.
#[test]
fn absent_lane_renders_nothing() {
    let lane = BaselineLane::new();
    assert!(lane.panel_rows().is_empty());
    assert!(lane.focus_pair(1).is_none());
    let mut lines = Vec::new();
    render_panel(&mut lines, &lane, &IdentityMap::new(), None, 40);
    render_focus_row(&mut lines, &lane, 1);
    assert!(
        lines.is_empty(),
        "the absent lens renders nothing, honestly"
    );
}
