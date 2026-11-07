// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the enforcement LANES verdict (night-netrunner-4, the
//! night-ux-2 wording): the quota saver's three lanes as the policy
//! arms them — RECWN on the download policy ("download only", the
//! full word), the ECN-first lane ARMED on the helper's fact (the
//! mark count saying whether it HAS marked: "no marks yet", "N
//! marks") or honestly "unavailable" without the helper, pacing on
//! the upload policy's commanded rate — and the honest None for an
//! unlimited target. Wired into `src/ebpf/render/report.rs` via
//! #[path] (cosmostrix Pattern C), the LOC-cap split discipline.

use super::*;

/// The LANES verdict (night-netrunner-4, pure): the quota saver's
/// three lanes as the policy arms them, one glance — and None for an
/// unlimited target (absence, not an empty promise).
#[test]
fn lanes_sentence_names_the_armed_lanes() {
    use crate::ebpf::limiter::PolicyRaw;

    let pol = |rate: u64| PolicyRaw {
        rate_bps: rate,
        burst_bytes: 0,
        ceil_bps: 0,
        floor_bps: 0,
        group_id: 0,
        flags: 0,
    };

    // Unlimited: no lanes, no line.
    assert_eq!(lanes_sentence(&Enforcement::Unlimited, true, 0), None);

    // Download only: recwn armed (the full word, not "(dl)"), ECN
    // armed with nothing booked yet, no pacing (no upload policy).
    let dl = Enforcement::Limited {
        download: Some(pol(200_000)),
        upload: None,
    };
    assert_eq!(
        lanes_sentence(&dl, true, 0).as_deref(),
        Some("recwn (download only) \u{b7} ecn armed, no marks yet")
    );

    // CE marks delivered: the ledger's own count says the lane HAS
    // marked — the count rides the SI compact ladder, the noun
    // pluralizes (1 mark / N marks).
    assert_eq!(
        lanes_sentence(&dl, true, 1_234_567).as_deref(),
        Some("recwn (download only) \u{b7} ecn armed, 1.2M marks")
    );
    assert_eq!(
        lanes_sentence(&dl, true, 1).as_deref(),
        Some("recwn (download only) \u{b7} ecn armed, 1 mark")
    );

    // Upload only: pacing at the commanded rate; no recwn.
    let ul = Enforcement::Limited {
        download: None,
        upload: Some(pol(100_000)),
    };
    assert_eq!(
        lanes_sentence(&ul, true, 0).as_deref(),
        Some("ecn armed, no marks yet \u{b7} pacing 100.0 KB/s")
    );

    // A host without the ECN helper (below 5.1 — the shape-facts
    // ladder): the lane's absence is NAMED, not silently omitted.
    assert_eq!(
        lanes_sentence(&dl, false, 0).as_deref(),
        Some("recwn (download only) \u{b7} ecn unavailable")
    );

    // Blocked upload (rate 0): no pacing rate to command — the lane
    // rides out of the sentence.
    let blocked = Enforcement::Limited {
        download: None,
        upload: Some(pol(0)),
    };
    assert_eq!(
        lanes_sentence(&blocked, true, 0).as_deref(),
        Some("ecn armed, no marks yet")
    );
}
