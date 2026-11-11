// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The quota telemetry's JSON pins (night-spark-6 landed the PREP
//! family as placeholders; night-spark-7, the quota saver's Layer 4
//! math, rewrote it for the live mapping): the four-field contract
//! on every limit row and the retirement pins the saved word carries
//! since night-quota-audit (EDT, schema v29) and night-recvn-audit
//! (RECWN, schema v30), split from display_json_tests.rs at the
//! 600-line owner cap (the window/recwn/pacing sibling-split
//! lineage, one family over).
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
/// the EDT word the retired kernel column (zero from the kernel
/// since v29; the display copies whatever the tail carries, so the
/// fixture's nonzero value pins the verbatim copy).
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
        measured_srtt_us: 0,
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

/// night-recvn-audit (schema v30): the saved word's retirement, live
/// on a planted lane — every ingredient the old window-law estimate
/// asked for (a planted lane shaping a 20_000-byte window from a
/// 100 KB/s policy, 40_000 delivered bytes) and the RECWN word reads
/// ZERO. The old estimate booked 2 x 111_072 here; the counterfactual
/// assumed a 128 KiB default window the autotuned 48-78 KB windows
/// of the owner's live reading never carried, and a clamp 10 of 11
/// connections' BDP could never fill.
#[test]
fn the_recwn_saved_word_is_retired_on_a_planted_lane() {
    let dl = vec![(73386, policy(100_000))];
    let lane = RecwnLane {
        planted: true,
        window_bytes: Some(20_000),
        binding_policies: 1,
        measured_srtt_us: None,
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
    assert_eq!(row.bytes_saved_by_recwn, 0);
    assert_eq!(row.bytes_saved_total, 0);
    // The key stays present at zero (the additive contract): a
    // pre-v30 reader reads the same four fields.
    assert!(json.to_json().contains("\"bytes_saved_by_recwn\":0"));
}

/// night-recvn-audit (schema v30): the total is ECN's one-for-one
/// alone — the retired EDT and RECWN words stay in the additive sum
/// at zero, so a scripted `Quota Saved: X` reads the delivered ECN
/// marks exactly. The estimate's old self-extinguishing edge (the
/// clamp-not-binding rate books zero) is subsumed: every rate books
/// zero now, the booking is the marks'.
#[test]
fn the_saved_total_is_the_ecn_one_for_one_alone() {
    let dl = vec![(73386, policy(100_000))];
    let lane = RecwnLane {
        planted: true,
        window_bytes: Some(20_000),
        binding_policies: 1,
        measured_srtt_us: None,
    };
    let json = status_json(
        &dl,
        &[],
        &[(73386, stats_saved(40_000, 0, 862_000))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &lane,
        0,
        0,
    );
    let row = &json.limits[0];
    assert_eq!(row.bytes_saved_by_ecn, 862_000);
    assert_eq!(row.bytes_saved_by_edt, 0);
    assert_eq!(row.bytes_saved_by_recwn, 0);
    assert_eq!(row.bytes_saved_total, 862_000);
    assert!(json.to_json().contains("\"bytes_saved_total\":862000"));
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
