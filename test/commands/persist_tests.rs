// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! private-research-4's persistence pins: the pure transforms the
//! snapshot/restore lane owns, rootless (the map-touching halves are
//! root-gated in the handlers; these pins hold the shaping laws):
//!
//!  * from_rows — the census join: names in, skipped cgroup ids OUT
//!    (honestly named, never serialized as bare ids a restore would
//!    misresolve);
//!  * restore_plan — the collapse laws: solo legs merge per-name
//!    into one strict-single step with both directions in one
//!    RateSpec; grouped legs merge per member-set into one
//!    strict-multi step; per-socket rides the individual lane only;
//!  * the serde round-trip — the state file's shape is the same JSON
//!    the --print-json surface emits, so write-then-read is the
//!    identity (schema tag included);
//!  * the schema refusal — a drifted tag never parses into an
//!    applied fleet.

use super::{restore_plan, SnapshotDoc, SnapshotEntry, STATE_SCHEMA};

use crate::ebpf::limiter::{Direction, PolicyRaw, RateSpec};

/// A census row factory (the pinned PolicyRaw layout's fields that
/// matter to the document: rate, group, flags).
fn raw(rate_bps: u64, group_id: u32, flags: u32) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: 0,
        floor_bps: 0,
        ceil_bps: 0,
        group_id,
        flags,
    }
}

fn entry(
    name: &str,
    direction: &str,
    rate_bps: u64,
    group_id: u32,
    per_socket: bool,
) -> SnapshotEntry {
    SnapshotEntry {
        name: name.to_string(),
        direction: direction.to_string(),
        rate_bps,
        group_id,
        per_socket,
        during: None,
        floor_bps: 0,
        ceil_bps: 0,
    }
}

#[test]
fn from_rows_joins_names_and_names_the_skips() {
    // Two resolvable rows serialize; the cgroup with no running
    // process lands in the skip list by ID — the honesty contract:
    // it cannot be restored by name, so it must be NAMED, not
    // serialized as a bare id.
    let rows = vec![(101u32, raw(1_000_000, 0, 0)), (999u32, raw(5, 0, 0))];
    let names = |id: u32| {
        if id == 101 {
            Some("brave".to_string())
        } else {
            None
        }
    };
    let mut skip = Vec::new();
    let doc = SnapshotDoc::from_rows(Direction::Download, &rows, &names, 1, &[], 0, 0, &mut skip);
    assert_eq!(doc.entries.len(), 1);
    assert_eq!(
        doc.entries[0],
        entry("brave", "download", 1_000_000, 0, false)
    );
    assert_eq!(skip, vec![999u32]);
}

#[test]
fn from_rows_carries_group_and_per_socket_flags() {
    let rows = vec![(7u32, raw(2_000_000, 42, 1))];
    let names = |id: u32| {
        if id == 7 {
            Some("nginx".to_string())
        } else {
            None
        }
    };
    let mut skip = Vec::new();
    let doc = SnapshotDoc::from_rows(Direction::Upload, &rows, &names, 1, &[], 0, 0, &mut skip);
    assert_eq!(
        doc.entries[0],
        entry("nginx", "upload", 2_000_000, 42, true)
    );
    assert!(skip.is_empty());
}

#[test]
fn restore_plan_merges_solo_legs_per_name() {
    // brave carries both directions: ONE strict-single step with both
    // legs in one RateSpec (the apply's unset-direction removal then
    // has nothing to remove — the restored policy is faithful).
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            entry("brave", "download", 1_000_000, 0, false),
            entry("brave", "upload", 500_000, 0, false),
        ],
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].names, vec!["brave".to_string()]);
    assert_eq!(
        plan[0].rates,
        RateSpec {
            download: Some(1_000_000),
            upload: Some(500_000)
        }
    );
    assert!(!plan[0].per_socket);
}

#[test]
fn restore_plan_keeps_one_direction_policies_faithful() {
    // A download-only limit restores as a download-only RateSpec —
    // the upload leg stays None, so the apply's unset-direction
    // removal reproduces the one-direction policy exactly.
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![entry("curl", "download", 100_000, 0, false)],
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 1);
    assert_eq!(
        plan[0].rates,
        RateSpec {
            download: Some(100_000),
            upload: None
        }
    );
}

#[test]
fn restore_plan_carries_the_per_socket_flag() {
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![entry("nginx", "download", 1_000, 0, true)],
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 1);
    assert!(plan[0].per_socket);
}

#[test]
fn restore_plan_collapses_group_members_into_one_step() {
    // Three members shared one bucket (the map's group_id 9): the
    // grouped legs collapse into ONE strict-multi step carrying the
    // member set and the shared rates — the ID is the grouping key
    // that re-joins members a census read apart. Per-socket never
    // rides the group lane (the CLI's own constraint — the flag is
    // individual-lane only).
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            entry("brave", "download", 1_000_000, 9, false),
            entry("curl", "download", 1_000_000, 9, true),
            entry("wget", "upload", 1_000_000, 9, false),
        ],
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 1, "one shared bucket, one step");
    assert_eq!(plan[0].names.len(), 3);
    assert!(plan[0].names.contains(&"brave".to_string()));
    assert!(plan[0].names.contains(&"curl".to_string()));
    assert!(plan[0].names.contains(&"wget".to_string()));
    assert_eq!(
        plan[0].rates,
        RateSpec {
            download: Some(1_000_000),
            upload: Some(1_000_000)
        }
    );
    assert!(!plan[0].per_socket);
}

#[test]
fn restore_plan_separates_solos_from_groups() {
    // A solo and a group in one fleet: two steps, the solo's
    // per-socket preserved, the group's member set intact.
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            entry("ssh", "upload", 50_000, 0, true),
            entry("brave", "download", 1_000_000, 7, false),
            entry("curl", "download", 1_000_000, 7, false),
        ],
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 2);
    let solo = plan.iter().find(|s| s.names.len() == 1).unwrap();
    let group = plan.iter().find(|s| s.names.len() == 2).unwrap();
    assert_eq!(solo.names, vec!["ssh".to_string()]);
    assert!(solo.per_socket);
    assert!(group.names.contains(&"brave".to_string()));
    assert!(group.names.contains(&"curl".to_string()));
    assert!(!group.per_socket);
}

#[test]
fn the_state_file_shape_round_trips() {
    // The document is the file: serialize -> parse is the identity,
    // schema tag and field names included (the --print-json surface
    // emits the same shape, one writer discipline).
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 1_780_000_000,
        entries: vec![
            entry("brave", "download", 1_000_000, 0, false),
            entry("nginx", "upload", 2_000_000, 5, true),
        ],
    };
    let body = serde_json::to_string_pretty(&doc).unwrap();
    let back: SnapshotDoc = serde_json::from_str(&body).unwrap();
    assert_eq!(doc, back);
    // The field names are the scripting contract — pinned as text.
    assert!(body.contains("\"schema\":"));
    assert!(body.contains("\"captured_at_unix\":"));
    assert!(body.contains("\"entries\":"));
    assert!(body.contains("\"rate_bps\":"));
    assert!(body.contains("\"per_socket\":"));
}

#[test]
fn a_drifted_schema_tag_is_its_own_document() {
    // The refusal's shape: a file with a newer tag parses as a
    // document but must NEVER parse as applicable state — the
    // handler refuses it, and the pin holds that the tag itself
    // survives the round-trip (the refusal can name it).
    let body = r#"{
  "schema": 99,
  "captured_at_unix": 1,
  "entries": []
}"#;
    let doc: SnapshotDoc = serde_json::from_str(body).unwrap();
    assert_ne!(doc.schema, STATE_SCHEMA);
    assert!(doc.entries.is_empty());
}

// ── night-during, schema v23: the window's persistence pins ───────

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
        Direction::Download,
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
        Direction::Download,
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

/// improve-40 (schema v24): a v23 file (the pair absent) restores as
/// the zero sentinel — serde's default keeps the old document the
/// fail-open posture, never a parse failure and never a fabricated
/// bracket.
#[test]
fn a_v23_file_restores_as_the_zero_sentinel() {
    let v23 = r#"{"schema":2,"captured_at_unix":0,"entries":[{"name":"brave","direction":"download","rate_bps":1000000,"group_id":0,"per_socket":false}]}"#;
    let doc: SnapshotDoc = serde_json::from_str(v23).expect("the v23 shape parses");
    assert_eq!(doc.entries[0].floor_bps, 0);
    assert_eq!(doc.entries[0].ceil_bps, 0);
}

/// improve-40 (schema v24): the bracket round-trips — both legs
/// carry the pair, the plan collapses it, the step hands it back.
#[test]
fn the_bracket_round_trips_the_restore_plan() {
    let doc = SnapshotDoc {
        schema: STATE_SCHEMA,
        captured_at_unix: 0,
        entries: vec![
            entry("brave", "download", 1_000_000, 0, false),
            entry("brave", "upload", 1_000_000, 0, false),
        ],
    };
    let doc = SnapshotDoc {
        entries: doc
            .entries
            .into_iter()
            .map(|mut e| {
                e.floor_bps = 100_000;
                e.ceil_bps = 300_000;
                e
            })
            .collect(),
        ..doc
    };
    let plan = restore_plan(&doc);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].floor_bps, 100_000);
    assert_eq!(plan[0].ceil_bps, 300_000);
}
