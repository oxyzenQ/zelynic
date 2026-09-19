// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the status display surface — kept in the repo's
//! single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C) and
//! #[path]-wired from display.rs. The NIGHT-hunt-22 pins hold the
//! `--print-json` scripting contract (field names, watchdog wording,
//! count semantics) via the extracted pure `status_json` builder —
//! no stdout capture needed.

use super::*;

fn policy(rate_bps: u64) -> PolicyRaw {
    PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
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
    let json = status_json(&dl, &ul, &[], &IdentityMap::new(), Some(0));

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
    let json = status_json(&dl, &[], &[], &IdentityMap::new(), Some(0));

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
    let json = status_json(&dl, &[], &stats_in, &IdentityMap::new(), None);

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
        status_json(&[], &[], &[], &id, Some(0)).watchdog,
        "enforcing"
    );
    assert_eq!(
        status_json(&no_policies, &[], &[], &id, None).watchdog,
        "enforcing"
    );

    // Armed and still in the future (u64::MAX is safely above any
    // monotonic clock).
    assert_eq!(
        status_json(&[], &[], &[], &id, Some(u64::MAX)).watchdog,
        "active"
    );

    // Armed but past — monotonic_ns() is far beyond 1 by now.
    assert_eq!(status_json(&[], &[], &[], &id, Some(1)).watchdog, "expired");
}

/// Empty policy maps (pins up, nothing limited — e.g. after recover
/// swept dead-cgroup orphans) is the ONE honest "no limits" state,
/// distinct from a failed read which now exits non-zero upstream.
#[test]
fn status_json_empty_policies_is_the_zero_state() {
    let json = status_json(&[], &[], &[], &IdentityMap::new(), Some(0));
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
