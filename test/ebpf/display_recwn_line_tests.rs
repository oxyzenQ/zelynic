// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-spark-2 (RECWN, schema v25): the receive-window lane's
//! subordinate line's own pin family — split from display_tests.rs
//! when night-verify-final's v33 measured shapes grew the wording
//! pins past the 600-LOC owner cap (the sibling-split lineage, one
//! family over). The wording contract ("RECWN window: <window>
//! (binding across <N> download <policy/policies>; est./measured RTT
//! <rtt>)" — the line says WHAT the number is, HOW MANY policies it
//! binds, and WHICH rtt the derivation rode), the grey family, and
//! the dormant silence when the lane shapes no window (the
//! dormant-watchdog honesty).

use super::{RECWN_RTT_ESTIMATE_US, RecwnLane, recwn_line};

#[test]
fn recwn_line_pins_the_owner_wording_and_stays_silent_when_unshaping() {
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: None,
        })
        .unwrap(),
        "  RECWN window: 20.0 KB (binding across 1 download policy; est. RTT 200ms)",
        "the 100 kb/s policy's own line, wording and window"
    );
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(1_048_576),
            binding_policies: 3,
            measured_srtt_us: None,
        })
        .unwrap(),
        "  RECWN window: 1.0 MB (binding across 3 download policies; est. RTT 200ms)",
        "the ceiling's own tier, the multi-policy plural"
    );
    // night-verify-final (schema v33): a binding policy whose stats
    // row carries a high-water above the cadence floor names its
    // source honestly — the MEASURED srtt the window derivation
    // itself rode (the verify workflow's leg-B shape).
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(30_010),
            binding_policies: 1,
            measured_srtt_us: Some(300_104),
        })
        .unwrap(),
        "  RECWN window: 30.0 KB (binding across 1 download policy; measured RTT 300ms)",
        "the measured extension names its own rtt"
    );
    // The sub-floor shapes keep the est. name — the window derived
    // from the cadence floor, whatever the row's raw sample says
    // (the JSON reports the sample; this clause is the window's).
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: Some(102),
        })
        .unwrap(),
        "  RECWN window: 20.0 KB (binding across 1 download policy; est. RTT 200ms)",
        "a sub-floor sample never renames the floor's own derivation"
    );
    // The dormant shapes: not planted, or planted with no window to
    // shape — silence, never noise.
    assert!(
        recwn_line(&RecwnLane {
            planted: false,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: None,
        })
        .is_none()
    );
    assert!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: None,
            binding_policies: 0,
            measured_srtt_us: None,
        })
        .is_none()
    );
    // The estimate constant the line prints is the lane's own twin
    // of the kernel core's 200 ms cadence estimate (the E2E-evidence
    // constant, ebpf/src/recwn.rs's doc owns the record).
    assert_eq!(RECWN_RTT_ESTIMATE_US, 200_000);
}
