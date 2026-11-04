// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The quota telemetry's display pins (night-spark-6, the quota
//! saver's Layer 4 PREP — the human surface): the Quota Saved
//! subordinate line's family, split from display_tests.rs at the
//! 600-line owner cap (the display_json sibling-split lineage, one
//! family over).

use super::*;

// ── night-spark-6 (the quota saver's Layer 4 PREP): the quota
// telemetry's subordinate line ─────────────────────────────────────────

/// The Quota Saved line renders the two lanes' saved-byte sum through
/// format_bytes' own human shape — the window family's indent — and
/// stays SILENT while the placeholders book nothing (the
/// dormant-watchdog precedent: the v28 tail has not landed, a zero is
/// absence, never information).
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
        bytes_saved_by_recwn: 700_000,
        bytes_saved_by_ecn: 300_000,
    };
    assert_eq!(
        quota_saved_line(&booked).unwrap(),
        "    Quota Saved: 1.0 MB"
    );

    // A single lane's savings still render (the sum, not the pair —
    // the human line is the total, the JSON carries the split).
    let one_lane = DisplayData {
        bytes_saved_by_recwn: 0,
        bytes_saved_by_ecn: 862_000,
        ..booked
    };
    assert_eq!(
        quota_saved_line(&one_lane).unwrap(),
        "    Quota Saved: 862.0 KB"
    );

    let quiet = DisplayData {
        bytes_saved_by_recwn: 0,
        bytes_saved_by_ecn: 0,
        ..booked
    };
    assert!(quota_saved_line(&quiet).is_none());
}
