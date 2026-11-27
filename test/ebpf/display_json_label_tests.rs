// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The status-JSON label pins (the night-dragon-fly-1 machine-fidelity
//! family): the limits[] label's uncapped-name law, split from
//! display_json_tests.rs at the 600-line owner cap (the pacing
//! sibling's own lineage, one family over). No stdout capture: the
//! pins work through the extracted pure `status_json` builder.

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

/// night-dragon-fly-1: night-cafe-1's (F1) machine-fidelity law
/// reaches the status limits[] label — the machine field carries the
/// UNCAPPED enriched name a script matches verbatim
/// ("polkit-kde-authentication-agent-1"), never the display artifact
/// "polkit-kde-authenticati…" the human table prints. The fixture
/// mirrors the owner's live find: a capped comm in the walk plus the
/// full-name side-map it enriched.
#[test]
fn status_json_label_carries_the_uncapped_name() {
    let mut identity = IdentityMap::new();
    identity.insert(crate::ebpf::identity::ProcessIdentity {
        cgroup_id: 6126,
        uid: 1000,
        comm: "polkit-kde-authenticati…".to_string(),
    });
    identity.seed_full_name_for_tests(6126, "polkit-kde-authentication-agent-1");
    let dl = vec![(6126, policy(100_000))];
    let json = status_json(
        &dl,
        &[],
        &[],
        &identity,
        Some(0),
        &RingReads::absent(),
        &[],
        &inert_recwn(),
        0,
        0,
    );

    assert_eq!(json.limits.len(), 1);
    assert_eq!(
        json.limits[0].label,
        "cg:6126 (polkit-kde-authentication-agent-1)"
    );
}
