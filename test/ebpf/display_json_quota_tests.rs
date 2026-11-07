// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The quota telemetry's JSON pins (night-spark-6 landed the PREP
//! family as placeholders; night-spark-7, the quota saver's Layer 4
//! math, rewrote it for the live mapping): the four-field contract
//! on every limit row and the RECWN estimate's own law, split from
//! display_json_tests.rs at the 600-line owner cap (the
//! window/recwn/pacing sibling-split lineage, one family over).
//!
//! The helpers below are LOCAL on purpose (the pacing sibling's own
//! discipline): a split family carries its own fixtures, so the
//! pins never lean on a sibling module's private scope — the
//! resolution the PREP-era file assumed and its `use super::*`
//! could never actually provide.

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

/// The Layer 4 fixture: a stats row whose saved tail books what the
/// kernel books — the ECN word one-for-one with the delivered marks,
/// the EDT word the egress accrual's own volume.
fn stats_saved(bytes_allowed: u64, edt_saved: u64, ecn_saved: u64) -> LimiterStatsRaw {
    LimiterStatsRaw {
        packets_allowed: bytes_allowed / 100,
        packets_dropped: 0,
        bytes_allowed,
        bytes_dropped: 0,
        ce_marked_packets: ecn_saved / 1500,
        ce_marked_bytes: ecn_saved,
        bytes_saved_by_edt: edt_saved,
        bytes_saved_by_ecn: ecn_saved,
    }
}

/// night-spark-7 (Layer 4): the four-field contract rides every
/// limit row — ALWAYS present, the additive contract the CE-ledger
/// pair set — with the live mapping: the two kernel-booked columns
/// copy straight off the v28 stats tail, the total sums the three
/// lanes, and the JSON names every field a script would read.
#[test]
fn status_json_carries_the_quota_telemetry_columns_live() {
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[(73386, stats_saved(50_000, 25_000, 17_432))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );
    let row = &json.limits[0];
    assert_eq!(row.bytes_saved_by_edt, 25_000);
    assert_eq!(row.bytes_saved_by_ecn, 17_432);
    // The inert lane shapes no window, so the RECWN estimate books
    // nothing — never a fabricated saving.
    assert_eq!(row.bytes_saved_by_recwn, 0);
    assert_eq!(row.bytes_saved_total, 42_432);
    let text = json.to_json();
    assert!(text.contains("\"bytes_saved_by_edt\":25000"), "{text}");
    assert!(text.contains("\"bytes_saved_by_ecn\":17432"), "{text}");
    assert!(text.contains("\"bytes_saved_by_recwn\":0"), "{text}");
    assert!(text.contains("\"bytes_saved_total\":42432"), "{text}");
}

/// night-spark-7 (Layer 4): the RECWN estimate's own law, live on a
/// planted lane — the window-law counterfactual against the
/// documented 128 KiB default-window assumption. A 100 KB/s policy
/// derives a 20_000-byte window; 40_000 delivered bytes are two
/// full window-cycles; each cycle held back 131_072 - 20_000 bytes
/// a default-window sender would have had in flight: the estimate
/// books exactly 2 x 111_072.
#[test]
fn the_recwn_estimate_rides_the_window_law_on_a_planted_lane() {
    let dl = vec![(73386, policy(100_000))];
    let lane = RecwnLane {
        planted: true,
        window_bytes: Some(20_000),
        binding_policies: 1,
    };
    let json = status_json(
        &dl,
        &[],
        &[(73386, stats_saved(40_000, 0, 0))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &lane,
        0,
        0,
    );
    let row = &json.limits[0];
    assert_eq!(row.bytes_saved_by_recwn, 222_144);
    // The estimate is the only lane that booked: the total IS it.
    assert_eq!(row.bytes_saved_total, 222_144);
    assert!(json.to_json().contains("\"bytes_saved_by_recwn\":222144"));
}

/// The estimate's self-extinguishing edge (the law's own honesty): a
/// rate whose clamped window reaches the default (700 KB/s derives
/// a 140_000-byte window against the 131_072 assumption) books ZERO
/// — the clamp is not the binding constraint there, the policer is,
/// and the column refuses to claim the policer's work as the
/// window's.
#[test]
fn the_recwn_estimate_extinguishes_where_the_clamp_is_not_binding() {
    let dl = vec![(73386, policy(700_000))];
    let lane = RecwnLane {
        planted: true,
        window_bytes: Some(140_000),
        binding_policies: 1,
    };
    let json = status_json(
        &dl,
        &[],
        &[(73386, stats_saved(1_000_000, 0, 0))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &lane,
        0,
        0,
    );
    assert_eq!(json.limits[0].bytes_saved_by_recwn, 0);
    assert_eq!(json.limits[0].bytes_saved_total, 0);
}

/// The zero row keeps the additive contract: no stats entry at all
/// and every saved field reads an honest 0 — never an absent field
/// automation would read as a pre-v28 object.
#[test]
fn a_row_without_stats_books_no_savings_and_keeps_the_fields() {
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );
    let row = &json.limits[0];
    assert_eq!(row.bytes_saved_by_edt, 0);
    assert_eq!(row.bytes_saved_by_ecn, 0);
    assert_eq!(row.bytes_saved_by_recwn, 0);
    assert_eq!(row.bytes_saved_total, 0);
    let text = json.to_json();
    assert!(text.contains("\"bytes_saved_by_edt\":0"), "{text}");
    assert!(text.contains("\"bytes_saved_by_ecn\":0"), "{text}");
    assert!(text.contains("\"bytes_saved_by_recwn\":0"), "{text}");
    assert!(text.contains("\"bytes_saved_total\":0"), "{text}");
}
