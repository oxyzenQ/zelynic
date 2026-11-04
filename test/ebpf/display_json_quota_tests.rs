// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The quota telemetry's JSON pins (night-spark-6, the quota saver's
//! Layer 4 PREP — the scripting surface): the placeholder pair's
//! additive contract, split from display_json_tests.rs at the
//! 600-line owner cap (the window/recwn/pacing sibling-split lineage,
//! one family over).

use super::*;

/// night-spark-6 (the quota saver's Layer 4 PREP): the quota
/// telemetry placeholders ride every limit row — ALWAYS present, the
/// additive contract the CE-ledger pair set — and both read 0 until
/// the Layer 4 booking lands: never a fabricated estimate (the
/// derivation law is the arc outline's open decision), never an
/// absent field automation would read as a pre-Layer-4 object.
#[test]
fn status_json_carries_the_quota_telemetry_placeholders() {
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
    let row = &json.limits[0];
    assert_eq!(row.bytes_saved_by_recwn, 0);
    assert_eq!(row.bytes_saved_by_ecn, 0);
    let text = json.to_json();
    assert!(text.contains("\"bytes_saved_by_recwn\":0"), "{text}");
    assert!(text.contains("\"bytes_saved_by_ecn\":0"), "{text}");
}
