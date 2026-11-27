// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-spark-2 (RECWN, schema v25): the receive-window lane's
//! subordinate line's own pin family — split from display_tests.rs
//! when night-verify-final's v33 measured shapes grew the wording
//! pins past the 600-LOC owner cap (the sibling-split lineage, one
//! family over). The wording contract ("RECWN window: <window> ·
//! <N> <policy/policies> · est./measured RTT <rtt>" — the compact
//! voice night-cafe-1 F8 landed: the same three facts inside every
//! cut budget, the measured value never eaten by the frame law's
//! ellipsis), the grey family, and
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
        "  RECWN window: 20.0 KB \u{b7} 1 policy \u{b7} est. RTT 200ms",
        "the 100 kb/s policy's own line, wording and window (the compact voice, F8)"
    );
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(1_048_576),
            binding_policies: 3,
            measured_srtt_us: None,
        })
        .unwrap(),
        "  RECWN window: 1.0 MB \u{b7} 3 policies \u{b7} est. RTT 200ms",
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
        "  RECWN window: 30.0 KB \u{b7} 1 policy \u{b7} measured RTT 300ms",
        "the measured extension names its own rtt"
    );
    // night-frontier hardening (the live session's honesty pass):
    // a measured sub-floor sample no longer hides under the est.
    // name — the line names the measurement AND the floor law the
    // window rode (the JSON reports the raw sample
    // recwn_limits.measured_srtt_us; the human line now says the
    // same truth instead of an "est." beside an existing
    // measurement).
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: Some(24_000),
        })
        .unwrap(),
        "  RECWN window: 20.0 KB \u{b7} 1 policy \u{b7} measured RTT 24ms (200ms floor)",
        "the live-session shape: a real 24 ms sample the floor outshouted, named"
    );
    assert_eq!(
        recwn_line(&RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: Some(102),
        })
        .unwrap(),
        "  RECWN window: 20.0 KB \u{b7} 1 policy \u{b7} measured RTT <1ms (200ms floor)",
        "a sub-millisecond sample renders <1ms, never a fabricated 0"
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

/// night-cafe-1 (F8): the line's worst case fits the owner's
/// 80-column budget WHOLE — the old parenthetical voice ran past
/// every cut budget at a real fleet (R04/R12: "measured RTT …" was
/// exactly the payload the ellipsis ate). The compact voice carries
/// the same three facts inside the budget, so the frame law never
/// cuts the line that exists to name the measurement.
#[test]
fn recwn_line_worst_case_fits_the_80_column_budget() {
    use crate::output::display_width;
    let widest = recwn_line(&RecwnLane {
        planted: true,
        window_bytes: Some(999_950_000),
        binding_policies: 1024,
        measured_srtt_us: Some(102),
    })
    .expect("a planted lane with a window prints");
    let width = display_width(&widest);
    assert!(
        width <= 80,
        "the worst case fits the classic budget whole, got {width}: {widest}"
    );
    assert!(
        widest.contains("measured RTT <1ms (200ms floor)"),
        "the payload lands inside the budget, got: {widest}"
    );
}
