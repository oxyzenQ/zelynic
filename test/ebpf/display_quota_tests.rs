// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The quota telemetry's display pins (night-spark-6 landed the
//! PREP family; night-spark-7, the quota saver's Layer 4 math,
//! rewrote it for the live line): the Quota Saved subordinate
//! line's total-with-split contract, split from display_tests.rs at
//! the 600-line owner cap (the display_json sibling-split lineage,
//! one family over).

use super::*;

// ── night-spark-7 (the quota saver's Layer 4 math): the quota
// telemetry's subordinate line ─────────────────────────────────────────

/// The Quota Saved line renders the three lanes' saved-byte total
/// with the layer split through format_bytes' own human shape — the
/// window family's indent — and stays SILENT while the lanes book
/// nothing (the dormant-watchdog precedent: a zero is absence,
/// never information).
#[test]
fn quota_saved_line_renders_the_lane_sum_and_stays_silent_on_zero() {
    let booked = DisplayData {
        window: None,
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
        cgroup_id: 73386,
        dl_bps: Some(100_000),
        ul_bps: Some(50_000),
        dl_per_socket: false,
        ul_per_socket: false,
        packets_allowed: 50,
        packets_dropped: 3,
        bytes_allowed: 50_000,
        bytes_dropped: 3_000,
        ce_marked_packets: 12,
        ce_marked_bytes: 17_432,
        bytes_saved_by_edt: 0,
        bytes_saved_by_recwn: 700_000,
        bytes_saved_by_ecn: 300_000,
    };
    assert_eq!(
        quota_saved_line(&booked).unwrap(),
        "    Quota Saved: 1.0 MB (EDT: 0 B, ECN: 300.0 KB, RECWN: 700.0 KB)"
    );

    // A single lane's savings still render — the total leads, the
    // split names the two lanes that booked nothing (the human line
    // carries all three; the JSON carries the same four fields).
    let one_lane = DisplayData {
        bytes_saved_by_recwn: 0,
        bytes_saved_by_edt: 0,
        bytes_saved_by_ecn: 862_000,
        ..booked
    };
    assert_eq!(
        quota_saved_line(&one_lane).unwrap(),
        "    Quota Saved: 862.0 KB (EDT: 0 B, ECN: 862.0 KB, RECWN: 0 B)"
    );

    // All three lanes live at once: the total is the saturating sum
    // of the split — the row can never disagree with itself.
    let three_lanes = DisplayData {
        bytes_saved_by_edt: 25_000,
        bytes_saved_by_ecn: 17_432,
        bytes_saved_by_recwn: 222_144,
        ..booked
    };
    assert_eq!(
        quota_saved_line(&three_lanes).unwrap(),
        "    Quota Saved: 264.6 KB (EDT: 25.0 KB, ECN: 17.4 KB, RECWN: 222.1 KB)"
    );

    let quiet = DisplayData {
        bytes_saved_by_edt: 0,
        bytes_saved_by_recwn: 0,
        bytes_saved_by_ecn: 0,
        ..booked
    };
    assert!(quota_saved_line(&quiet).is_none());
}
