// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-spark-2 (RECWN, schema v25): the recwn_limits JSON pins,
//! one family over (the display_json_window_tests precedent — the
//! LOC-cap split the ecn_socket_tests precedent set). The
//! owner-defined top-level object's fields, the exact enabled:true
//! shape, the enabled:false absent-window shape, and the
//! additive-absence contract on the unplanted lane.

use super::*;

/// One policy row at the rate the family's fixtures ride (the
/// display_json_tests family's own helper, restated here — each
/// family file is self-contained, the window family's precedent).
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

/// night-spark-2 (RECWN, schema v25): the owner-defined top-level
/// object's three fields are pinned as literal JSON text — the
/// scripting contract the quota-saver tooling will parse.
#[test]
fn recwn_limits_fields_are_pinned_when_the_lane_is_planted() {
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &super::RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: None,
        },
        0,
        0,
    );
    let text = json.to_json();
    for field in [
        "\"recwn_limits\"",
        "\"enabled\"",
        "\"window_bytes\"",
        "\"rtt_estimate_us\"",
    ] {
        assert!(text.contains(field), "field {field} missing from: {text}");
    }
}

/// schema the task brief pinned.
#[test]
fn recwn_limits_carries_the_derived_window_and_rtt_estimate() {
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &super::RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: None,
        },
        0,
        0,
    );
    assert!(
        json.to_json().contains(
            "\"recwn_limits\":{\"enabled\":true,\"window_bytes\":20000,\"rtt_estimate_us\":200000}"
        ),
        "the owner-defined recwn_limits shape drifted: {}",
        json.to_json()
    );
}

/// constant, present whatever it shapes).
#[test]
fn recwn_limits_enabled_false_omits_the_window() {
    let json = status_json(
        &[],
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &super::RecwnLane {
            planted: true,
            window_bytes: None,
            binding_policies: 0,
            measured_srtt_us: None,
        },
        0,
        0,
    );
    assert!(
        json.to_json()
            .contains("\"recwn_limits\":{\"enabled\":false,\"rtt_estimate_us\":200000}"),
        "the enabled:false shape drifted: {}",
        json.to_json()
    );
}

/// night-verify-final (schema v33): the measured-srtt field rides
/// the object when the binding policy's stats row carries a ratchet
/// — the measured half of the window derivation, additive AFTER
/// rtt_estimate_us — and stays honestly absent (omitted, never a
/// fabricated zero) while the lane is unmeasured: the pinned v32
/// wire shapes above ride unchanged byte for byte.
#[test]
fn recwn_limits_carries_the_measured_srtt_when_the_row_has_one() {
    let dl = vec![(73386, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        &super::RecwnLane {
            planted: true,
            // 100 kb/s at the verify workflow's leg-B srtt: the
            // measured extension the JSON now names beside its rtt.
            window_bytes: Some(30_010),
            binding_policies: 1,
            measured_srtt_us: Some(300_104),
        },
        0,
        0,
    );
    assert!(
        json.to_json().contains(
            "\"recwn_limits\":{\"enabled\":true,\"window_bytes\":30010,\"rtt_estimate_us\":200000,\"measured_srtt_us\":300104}"
        ),
        "the v33 measured shape drifted: {}",
        json.to_json()
    );
}

/// all — the exact pre-v25 document shape, automation unaffected.
#[test]
fn recwn_limits_is_omitted_when_the_lane_is_not_planted() {
    let json = status_json(
        &[],
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
    assert!(
        !json.to_json().contains("recwn_limits"),
        "an unplanted lane must not fabricate a recwn_limits object: {}",
        json.to_json()
    );
}
