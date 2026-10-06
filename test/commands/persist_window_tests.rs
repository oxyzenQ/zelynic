// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! night-during's persistence pins (schema v23; the owner's
//! duration-only revision): the WINDOW family the snapshot/restore
//! lane owns, rootless — the wall-form census join, the plan's
//! window round-trip (the restore lane's Span/Daily vocabulary,
//! the read-side belt), and the window-kind gate that refuses an
//! unreadable auto-expire promise instead of swallowing it into a
//! forever-limit. Split out of persist_tests.rs when the
//! window-kind gate pushed that file past the 500-LOC owner cap
//! (the during_map discipline, one test tree over); the shared
//! census factories stay with the parent file (pub(super), the
//! sibling's vocabulary).

use super::persist_tests::{entry, raw};
use super::{restore_plan, validate_persisted_windows, SnapshotDoc, SnapshotEntry, STATE_SCHEMA};

#[test]
fn an_unknown_window_kind_refuses_the_restore_naming_the_row() {
    // night-during-7's honesty catch, pinned beside the tag
    // refusal it mirrors: a `during` form whose kind is neither
    // "span" nor "daily" (hand-edited, corrupted) must REFUSE the
    // restore naming the row — the plan's and_then would otherwise
    // swallow the unreadable window into "no window" and apply the
    // row without its lifetime, the auto-expires-into-forever
    // inversion the design brief forbids.
    let windowed = |kind: &str| SnapshotEntry {
        name: "brave".to_string(),
        direction: "download".to_string(),
        rate_bps: 1_000_000,
        group_id: 0,
        per_socket: false,
        during: Some(crate::ebpf::limiter::WindowPersist {
            kind: kind.to_string(),
            start_wall_ns: 0,
            end_wall_ns: 3_600_000_000_000,
            start_s: 0,
            end_s: 0,
        }),
        floor_bps: 0,
        ceil_bps: 0,
    };
    let doc = |during| SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![windowed(during)],
    };
    // The two readable kinds pass the gate (the restore lane's
    // whole vocabulary, belt included).
    assert!(validate_persisted_windows(&doc("span")).is_ok());
    assert!(validate_persisted_windows(&doc("daily")).is_ok());
    // Anything else refuses, the row's name and the kind both in
    // the error (the refusal can name what it refused).
    let err = validate_persisted_windows(&doc("whenever"))
        .expect_err("an unknown window kind must refuse the restore");
    let msg = format!("{err}");
    assert!(
        msg.contains("brave") && msg.contains("whenever"),
        "the refusal names the row and the kind: {msg}"
    );
    // A document whose entries carry no window validates trivially
    // (the majority shape: most rows are plain forever-limits).
    assert!(validate_persisted_windows(&SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![entry("brave", "download", 1_000_000, 0, false)],
    })
    .is_ok());
}

/// from_rows joins the window census: a leg whose root carries a
/// window serializes its WALL form (the offset pair makes the
/// instants deterministic); a row without one stays absent; both
/// leg entries of one row carry the same form.
#[test]
fn from_rows_joins_the_window_wall_form() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_SPAN};
    use crate::ebpf::limiter::window_persist_form;

    let rows = vec![(101u32, raw(1_000_000, 0, 0))];
    let names = |id: u32| {
        if id == 101 {
            Some("brave".to_string())
        } else {
            None
        }
    };
    let wall = 1_791_288_000_000_000_000u64;
    let mono = 5 * 1_000_000_000u64;
    let windows = vec![(
        101u32,
        PolicyWindowRaw {
            kind: WINDOW_KIND_SPAN,
            reserved: 0,
            start_mono_ns: 0,
            end_mono_ns: 3600 * 1_000_000_000,
            start_s: 0,
            end_s: 0,
        },
    )];
    let mut skip = Vec::new();
    let doc = SnapshotDoc::from_rows(
        crate::ebpf::limiter::Direction::Download,
        &rows,
        &names,
        1,
        &windows,
        wall,
        mono,
        &mut skip,
    );
    let expected = window_persist_form(&windows[0].1, wall, mono);
    assert_eq!(doc.entries[0].during, Some(expected));

    // Without a window: absent, never a fabricated form.
    let mut skip = Vec::new();
    let doc = SnapshotDoc::from_rows(
        crate::ebpf::limiter::Direction::Download,
        &rows,
        &names,
        1,
        &[],
        wall,
        mono,
        &mut skip,
    );
    assert!(doc.entries[0].during.is_none());
}

/// restore_plan carries the window into the step (the wall form
/// back into the spec the apply family takes), solo and group
/// alike; a mixed member set keeps the FIRST form the census read.
#[test]
fn restore_plan_carries_the_window_spec() {
    // A solo row's daily window round-trips into the step's spec.
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            SnapshotEntry {
                name: "brave".to_string(),
                direction: "download".to_string(),
                rate_bps: 1_000_000,
                group_id: 0,
                per_socket: false,
                during: Some(crate::ebpf::limiter::WindowPersist {
                    kind: "daily".to_string(),
                    start_wall_ns: 0,
                    end_wall_ns: 0,
                    start_s: 22 * 3600,
                    end_s: 6 * 3600,
                }),
                floor_bps: 0,
                ceil_bps: 0,
            },
            SnapshotEntry {
                name: "brave".to_string(),
                direction: "upload".to_string(),
                rate_bps: 1_000_000,
                group_id: 0,
                per_socket: false,
                during: Some(crate::ebpf::limiter::WindowPersist {
                    kind: "daily".to_string(),
                    start_wall_ns: 0,
                    end_wall_ns: 0,
                    start_s: 22 * 3600,
                    end_s: 6 * 3600,
                }),
                floor_bps: 0,
                ceil_bps: 0,
            },
        ],
    };
    let plan = restore_plan(&doc);
    assert_eq!(
        plan[0].during,
        Some(crate::ebpf::limiter::DuringSpec::Daily {
            start_s: 22 * 3600,
            end_s: 6 * 3600
        }),
        "the daily form round-trips into the step's spec"
    );

    // A span form round-trips into the wall-span spec; a mixed
    // member set keeps the FIRST form the census read (the map
    // guarantees one row per root, so disagreement means torn).
    let span_form = crate::ebpf::limiter::WindowPersist {
        kind: "span".to_string(),
        start_wall_ns: 100,
        end_wall_ns: 200,
        start_s: 0,
        end_s: 0,
    };
    let daily_form = crate::ebpf::limiter::WindowPersist {
        kind: "daily".to_string(),
        start_wall_ns: 0,
        end_wall_ns: 0,
        start_s: 22 * 3600,
        end_s: 6 * 3600,
    };
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            SnapshotEntry {
                name: "brave".to_string(),
                direction: "download".to_string(),
                rate_bps: 1_000_000,
                group_id: 0,
                per_socket: false,
                during: Some(span_form.clone()),
                floor_bps: 0,
                ceil_bps: 0,
            },
            SnapshotEntry {
                name: "brave".to_string(),
                direction: "upload".to_string(),
                rate_bps: 1_000_000,
                group_id: 0,
                per_socket: false,
                during: Some(daily_form),
                floor_bps: 0,
                ceil_bps: 0,
            },
        ],
    };
    let plan = restore_plan(&doc);
    assert_eq!(
        plan[0].during,
        Some(crate::ebpf::limiter::DuringSpec::Span {
            start_wall_ns: 100,
            end_wall_ns: 200
        }),
        "the first form wins on a mixed (torn) member set"
    );
}
