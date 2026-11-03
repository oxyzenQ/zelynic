// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The egress pacing lane's --print-json pins (night-spark-5, schema
//! v27), split from display_json_tests.rs with the pacing field (the
//! display_json_window_tests sibling-split lineage — the LOC-cap
//! discipline: the parent rode past 600 when this lane's pins joined
//! it). No stdout capture: the pins work through the extracted pure
//! `status_json` builder.

use super::*;

fn policy(rate_bps: u64) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    }
}

fn stats_ce(allowed: u64, dropped: u64, ce_packets: u64, ce_bytes: u64) -> LimiterStatsRaw {
    LimiterStatsRaw {
        packets_allowed: allowed,
        packets_dropped: dropped,
        bytes_allowed: allowed * 100,
        bytes_dropped: dropped * 100,
        ce_marked_packets: ce_packets,
        ce_marked_bytes: ce_bytes,
    }
}

/// night-spark-5 (schema v27): the egress pacing lane's commanded
/// rate — present on a row carrying a live upload policy (the rate
/// the sock_ops program pins onto its upload sockets), absent on
/// upload-less rows and on BLOCKED rows (rate 0): the additive-
/// field rule the floors ride, never a fabricated zero.
#[test]
fn status_json_carries_the_pacing_rate() {
    let ul = vec![(73386, policy(100_000))];
    let json = status_json(
        &[],
        &ul,
        &[(73386, stats_ce(50, 3, 12, 17_432))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );
    let row = &json.limits[0];
    assert_eq!(row.pacing_rate_bytes, Some(100_000));
    let text = json.to_json();
    assert!(text.contains("\"pacing_rate_bytes\":100000"), "{text}");

    // Upload-less rows carry no pacing field — absence, never a
    // fabricated zero.
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[(73386, stats_ce(50, 3, 12, 17_432))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );
    assert!(
        !json.to_json().contains("pacing_rate_bytes"),
        "{}",
        json.to_json()
    );

    // A BLOCKED upload row (rate 0) paces nothing — a blocked lane
    // delivers nothing, so no pacing rate can help it.
    let blocked = vec![(73386, policy(0))];
    let json = status_json(
        &[],
        &blocked,
        &[(73386, stats_ce(50, 3, 12, 17_432))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );
    assert!(
        !json.to_json().contains("pacing_rate_bytes"),
        "{}",
        json.to_json()
    );
}
