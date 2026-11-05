// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the enforcement LANES verdict (night-netrunner-4): the
//! quota saver's three lanes as the policy arms them — RECWN on a
//! download policy, the ECN-first lane on the helper's fact (the CE
//! ledger proving delivery when it marked), pacing on the upload
//! policy's commanded rate — and the honest None for an unlimited
//! target. Wired into `src/ebpf/render/report.rs` via #[path]
//! (cosmostrix Pattern C), the LOC-cap split discipline.

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

    // Download only: recwn armed, ECN ready (helper present), no
    // pacing (no upload policy).
    let dl = Enforcement::Limited {
        download: Some(pol(200_000)),
        upload: None,
    };
    assert_eq!(
        lanes_sentence(&dl, true, 0).as_deref(),
        Some("recwn (dl) \u{b7} ecn ready")
    );

    // CE marks delivered: the ledger's own proof replaces "ready".
    assert_eq!(
        lanes_sentence(&dl, true, 1_234_567).as_deref(),
        Some("recwn (dl) \u{b7} ecn marked 1.2 MB")
    );

    // Upload only: pacing at the commanded rate; no recwn.
    let ul = Enforcement::Limited {
        download: None,
        upload: Some(pol(100_000)),
    };
    assert_eq!(
        lanes_sentence(&ul, true, 0).as_deref(),
        Some("ecn ready \u{b7} pacing 100.0 KB/s")
    );

    // A host without the ECN helper (below 5.1 — the shape-facts
    // ladder): the lane stays honestly absent.
    assert_eq!(lanes_sentence(&dl, false, 0).as_deref(), Some("recwn (dl)"));

    // Blocked upload (rate 0): no pacing rate to command — the lane
    // rides out of the sentence.
    let blocked = Enforcement::Limited {
        download: None,
        upload: Some(pol(0)),
    };
    assert_eq!(
        lanes_sentence(&blocked, true, 0).as_deref(),
        Some("ecn ready")
    );
}
