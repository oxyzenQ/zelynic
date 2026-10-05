// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The status-JSON pins (the NIGHT-hunt-22 --print-json contract —
//! field names, watchdog wording, count semantics — plus the
//! charger-core-3a rate_ring JSON pins and the charger-core-3b
//! per-socket field pins), split from display_tests.rs with the
//! display_json module (one test file per module, the docker_tests
//! sibling-split lineage). No stdout capture: the pins work through
//! the extracted pure `status_json` builder.

use super::*;

fn policy(rate_bps: u64) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
        flags: 0,
    }
}

fn stats(allowed: u64, dropped: u64) -> LimiterStatsRaw {
    LimiterStatsRaw {
        packets_allowed: allowed,
        packets_dropped: dropped,
        bytes_allowed: allowed * 100,
        bytes_dropped: dropped * 100,
    }
}

/// `active_limits` counts CGROUPS, not direction entries: a cgroup
/// with both dl and ul policies is ONE limit row. Scripts compare
/// this number against strict's "(N policies...)" — which counts
/// directions — so the difference is pinned here on purpose: this is
/// the display contract, that is the apply contract.
#[test]
fn status_json_counts_cgroups_not_direction_policies() {
    let dl = vec![(73386, policy(100_000))];
    let ul = vec![(73386, policy(50_000))];
    let json = status_json(
        &dl,
        &ul,
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );

    assert_eq!(json.active_limits, 1);
    assert_eq!(json.limits.len(), 1);

    let row = &json.limits[0];
    assert_eq!(row.cgroup_id, 73386);
    assert_eq!(row.label, "cg:73386");
    assert_eq!(row.download_bps, Some(100_000));
    assert_eq!(row.upload_bps, Some(50_000));
}

/// A cgroup limited in one direction only: the other renders null,
/// never zero — "no upload policy" and "upload blocked at 0 bps"
/// must stay distinguishable for automation.
#[test]
fn status_json_single_direction_limit_renders_null_other_side() {
    let dl = vec![(73390, policy(0))];
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

    assert_eq!(json.active_limits, 1);
    assert_eq!(json.limits[0].download_bps, Some(0));
    assert_eq!(json.limits[0].upload_bps, None);
}

/// Stats join by cgroup; a cgroup without a stats entry shows zeros
/// (fresh policy, no traffic yet) — that zero is honest because the
/// stats read itself is verified upstream (NIGHT-hunt-22: print_status
/// propagates read errors before display ever runs).
#[test]
fn status_json_joins_stats_and_zeroes_missing_entries() {
    let dl = vec![(1, policy(10)), (2, policy(20))];
    let stats_in = vec![(1, stats(7, 3))];
    let json = status_json(
        &dl,
        &[],
        &stats_in,
        &IdentityMap::new(),
        None,
        &RingReads::absent(),
        &[],
        0,
        0,
    );

    let with_stats = json.limits.iter().find(|l| l.cgroup_id == 1).unwrap();
    assert_eq!(with_stats.packets_allowed, 7);
    assert_eq!(with_stats.packets_dropped, 3);
    assert_eq!(with_stats.bytes_allowed, 700);
    assert_eq!(with_stats.bytes_dropped, 300);

    let without = json.limits.iter().find(|l| l.cgroup_id == 2).unwrap();
    assert_eq!(without.packets_allowed, 0);
    assert_eq!(without.bytes_dropped, 0);
}

/// Watchdog wording: the three-document states. Some(0) and None are
/// the same "enforcing" state (pin mode never arms the watchdog —
/// deadline 0 is its dormant representation); a future deadline is
/// "active"; a past one is "expired".
#[test]
fn status_json_watchdog_wording_pins_all_three_states() {
    let no_policies: Vec<(u32, PolicyRaw)> = Vec::new();
    let id = IdentityMap::new();

    // Dormant: deadline 0, and the None display-contract variant.
    assert_eq!(
        status_json(&[], &[], &[], &id, Some(0), &RingReads::absent(), &[], 0, 0).watchdog,
        "enforcing"
    );
    assert_eq!(
        status_json(
            &no_policies,
            &[],
            &[],
            &id,
            None,
            &RingReads::absent(),
            &[],
            0,
            0
        )
        .watchdog,
        "enforcing"
    );

    // Armed and still in the future (u64::MAX is safely above any
    // monotonic clock).
    assert_eq!(
        status_json(
            &[],
            &[],
            &[],
            &id,
            Some(u64::MAX),
            &RingReads::absent(),
            &[],
            0,
            0
        )
        .watchdog,
        "active"
    );

    // Armed but past — monotonic_ns() is far beyond 1 by now.
    assert_eq!(
        status_json(&[], &[], &[], &id, Some(1), &RingReads::absent(), &[], 0, 0).watchdog,
        "expired"
    );
}

/// Empty policy maps (pins up, nothing limited — e.g. after recover
/// swept dead-cgroup orphans) is the ONE honest "no limits" state,
/// distinct from a failed read which now exits non-zero upstream.
#[test]
fn status_json_empty_policies_is_the_zero_state() {
    let json = status_json(
        &[],
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );
    assert_eq!(json.active_limits, 0);
    assert!(json.limits.is_empty());
    assert_eq!(json.watchdog, "enforcing");
}

/// The serialized field names are the scripting contract — renaming
/// any of them breaks every consumer at once, so they are pinned as
/// literal JSON text.
#[test]
fn status_json_field_names_are_pinned() {
    let json = status_json(
        &[(42, policy(1000))],
        &[],
        &[(42, stats(1, 2))],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );
    let text = serde_json::to_string(&json).unwrap();
    for field in [
        "\"watchdog\"",
        "\"active_limits\"",
        "\"limits\"",
        "\"cgroup_id\"",
        "\"label\"",
        "\"download_bps\"",
        "\"upload_bps\"",
        "\"packets_allowed\"",
        "\"packets_dropped\"",
        "\"bytes_allowed\"",
        "\"bytes_dropped\"",
    ] {
        assert!(text.contains(field), "field {field} missing from: {text}");
    }
}

/// The absent-lens contract: with no ring readable (a pre-v14 pinned
/// object, a torn-down map), the limit entries carry NO rate_ring
/// field — absent is honestly absent, never a fabricated empty
/// series. Automation sees exactly the pre-3a document shape.
#[test]
fn rate_ring_field_is_omitted_when_the_lens_is_absent() {
    let dl = vec![(73386, policy(100_000))];
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
    assert!(json.limits[0].rate_ring.is_none());
}

/// The joined contract: a readable ring for the limit's cgroup
/// renders the derived series — oldest-first bytes, the live count,
/// the completed-window peak — while a cgroup with no ring entry
/// (fresh policy, no traffic yet) stays lean.
#[test]
fn rate_ring_field_joins_series_by_cgroup() {
    use crate::ebpf::limiter::rate_ring::{RateRingRaw, RateSlotRaw, RATE_RING_SLOTS};
    let dl = vec![(1, policy(10)), (2, policy(20))];

    // Window math pinned to a fixed 'now': status_json samples its
    // own monotonic now, so the ring is stamped for windows that are
    // live under ANY now the builder samples (window 0 of a long-ago
    // boot is always stale -> the derivation reads it as zero; the
    // pin therefore asserts the join and the field's SHAPE, with the
    // series math itself pinned in rate_ring_tests.rs against fixed
    // clocks).
    let mut ring = RateRingRaw {
        slots: [RateSlotRaw {
            window: 0,
            bytes: 0,
        }; RATE_RING_SLOTS],
    };
    ring.slots[0] = RateSlotRaw {
        window: 0,
        bytes: 1234,
    };
    let rings = RingReads {
        dl: Some(vec![(1, ring)]),
        ul: None,
    };
    let json = status_json(
        &dl,
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &rings,
        &[],
        0,
        0,
    );

    // Cgroup 1: dl ring present (ul absent -> None), the dl series
    // derived; cgroup 2: no ring entry -> no field.
    let with = json.limits.iter().find(|l| l.cgroup_id == 1).unwrap();
    let rr = with.rate_ring.as_ref().expect("cgroup 1 has a dl ring");
    assert_eq!(rr.window_secs, 1);
    assert!(rr.download.is_some());
    assert!(rr.upload.is_none());
    let dl_series = rr.download.as_ref().unwrap();
    assert_eq!(dl_series.bytes.len(), RATE_RING_SLOTS);
    assert_eq!(
        dl_series.live, 0,
        "window 0 stamps are stale under any real now"
    );

    let without = json.limits.iter().find(|l| l.cgroup_id == 2).unwrap();
    assert!(without.rate_ring.is_none());
}

/// Both directions readable: the rate_ring object carries both series
/// even when one direction's cgroup has no ring entry (that side is
/// None INSIDE the object, not the object's absence).
#[test]
fn rate_ring_one_sided_entry_renders_null_direction() {
    let dl = vec![(1, policy(10))];
    let ul = vec![(1, policy(20))];
    let mut ring = RateRingRaw::default();
    ring.slots[0] = crate::ebpf::limiter::rate_ring::RateSlotRaw {
        window: 0,
        bytes: 42,
    };
    let rings = RingReads {
        dl: None,
        ul: Some(vec![(1, ring)]),
    };
    let json = status_json(
        &dl,
        &ul,
        &[],
        &IdentityMap::new(),
        Some(0),
        &rings,
        &[],
        0,
        0,
    );
    let rr = json.limits[0].rate_ring.as_ref().unwrap();
    assert!(rr.download.is_none());
    assert!(rr.upload.is_some());
}

// ── charger-core-3b: the per-socket field's JSON contract pins ────

/// A per-socket policy's limit row carries the boolean markers per
/// direction; a cgroup-lane policy's row omits them entirely (skip
/// when false — the additive-field rule: old scripts see the old
/// shape for old semantics).
#[test]
fn per_socket_fields_serialize_only_when_set() {
    let dl = vec![(
        1,
        PolicyRaw {
            rate_bps: 500_000,
            burst_bytes: 500_000,
            group_id: 0,
            flags: 1, // POLICY_FLAG_PER_SOCKET
        },
    )];
    let ul = vec![(
        1,
        PolicyRaw {
            rate_bps: 200_000,
            burst_bytes: 200_000,
            group_id: 0,
            flags: 0,
        },
    )];
    let json = status_json(
        &dl,
        &ul,
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );

    let row = &json.limits[0];
    assert!(row.download_per_socket, "the dl leg carries the bit");
    assert!(!row.upload_per_socket, "the ul leg is the cgroup lane");
    assert_eq!(row.download_bps, Some(500_000));
    assert_eq!(row.upload_bps, Some(200_000));

    // The cgroup-lane row: both markers false (and omitted by serde
    // — pinned by the serialization shape below).
    let plain = status_json(
        &[(2, policy(100_000))],
        &[],
        &[],
        &IdentityMap::new(),
        Some(0),
        &RingReads::absent(),
        &[],
        0,
        0,
    );
    let row = &plain.limits[0];
    assert!(!row.download_per_socket && !row.upload_per_socket);

    // serde: the false markers do not serialize (additive contract).
    let doc = serde_json::to_value(&plain).unwrap();
    let row_doc = &doc["limits"][0];
    assert!(row_doc.get("download_per_socket").is_none());
    assert!(row_doc.get("upload_per_socket").is_none());
    let per_socket_doc = serde_json::to_value(&json).unwrap();
    assert_eq!(per_socket_doc["limits"][0]["download_per_socket"], true);
    assert!(per_socket_doc["limits"][0]
        .get("upload_per_socket")
        .is_none());
}
