// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The window JSON pins (night-during, schema v23 — split from
//! display_json_tests.rs when the family crossed the 500-line owner
//! cap, the ecn_socket_tests precedent: one cohesive pin family,
//! its own module). The imports mirror the parent's `use super::*`
//! so the pinned names resolve identically.

use super::*;

fn policy(rate_bps: u64) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
        flags: 0,
    }
}

// ── night-during, schema v23: the window JSON pins ────────────────

/// The window field (additive, absent when the row carries none):
/// a span serializes its WALL instants (never the monotonic
/// deadlines — meaningless to a script and across reboots alike)
/// with the state vocabulary; a daily serializes its seconds-of-day
/// pair; the skip-if-absent rules keep old documents' scripts
/// unpolluted.
#[test]
fn window_json_pins_span_and_daily_shapes() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
    // wall 2026-10-06 12:00 UTC, mono 60s — the offset pair makes
    // the span's wall instants deterministic.
    let wall = 1_791_288_000_000_000_000u64;
    let mono = 60 * 1_000_000_000u64;
    let offset = wall - mono;

    let dl = vec![(101u32, policy(100_000))];
    let windows = vec![
        (
            101u32,
            PolicyWindowRaw {
                kind: WINDOW_KIND_SPAN,
                reserved: 0,
                start_mono_ns: 0,
                end_mono_ns: mono + 3600 * 1_000_000_000,
                start_s: 0,
                end_s: 0,
            },
        ),
        (
            202u32,
            PolicyWindowRaw {
                kind: WINDOW_KIND_DAILY,
                reserved: 0,
                start_mono_ns: 0,
                end_mono_ns: 0,
                start_s: 22 * 3600,
                end_s: 6 * 3600,
            },
        ),
    ];
    // The second window's row has no policy: the join drops it (a
    // window rides a policy row, never floats alone).
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &windows,
        wall,
        mono,
    );
    let row = &json.limits[0];
    let win = row.window.as_ref().expect("the span window joins its row");
    assert_eq!(win.kind, "span");
    assert_eq!(win.state, "active");
    assert_eq!(win.start_wall_ns, Some(offset));
    assert_eq!(win.end_wall_ns, Some(wall + 3600 * 1_000_000_000));
    assert!(win.start_s.is_none() && win.end_s.is_none());

    let dl_daily = vec![(202u32, policy(5_000_000))];
    let json = status_json(
        &dl_daily,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &windows,
        wall,
        mono,
    );
    let win = json.limits[0]
        .window
        .as_ref()
        .expect("the daily window joins");
    assert_eq!(win.kind, "daily");
    // The anchor is 12:00 UTC: outside 22:00-06:00.
    assert_eq!(win.state, "outside");
    assert_eq!(win.start_s, Some(22 * 3600));
    assert_eq!(win.end_s, Some(6 * 3600));
    assert!(win.start_wall_ns.is_none() && win.end_wall_ns.is_none());

    // Absent windows stay absent (the additive-field rule).
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );
    assert!(json.limits[0].window.is_none());
    let doc = serde_json::to_value(&json).unwrap();
    assert!(
        doc["limits"][0].get("window").is_none(),
        "the field serializes only when the row carries one"
    );
}
