// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// night-spark-5 (Egress Socket Pacing — schema v27, Layer 3): the
// pure pacing law's rootless pins. The kernel half (pace_flow.rs)
// can only be exercised by the kernel; this tree owns the law the
// wiring rides — the simulated sock_ops call shapes and the exact
// rate the wiring would hand bpf_setsockopt — the ecn_tests
// discipline one layer up. The owner's unit-test brief, restated:
// simulate a sock_ops call, verify the rate the program would set.

#[path = "../../../ebpf/src/pace.rs"]
pub(super) mod ebpf_pace;

use ebpf_pace::pacing_decision;

/// The task brief's own example: a 100 KB/s upload policy pins
/// SO_MAX_PACING_RATE to 100000 bytes per second — the value the
/// wiring passes to the helper, byte-exact.
#[test]
fn the_100kb_policy_paces_at_its_own_rate() {
    assert_eq!(
        pacing_decision(true, true, true, Some(100_000)),
        Some(100_000)
    );
}

/// Every unowned sock_ops shape answers no opinion: an op the
/// program's match falls through (the neutral return), the passive
/// side's RWND_INIT request socket (is_fullsock 0 — the helper
/// would refuse with EINVAL anyway), and a non-TCP socket (the
/// dispatch is TCP-only by construction — the recwn twin's armor
/// note). Each shape rides untouched.
#[test]
fn every_unowned_shape_answers_no_opinion() {
    assert_eq!(
        pacing_decision(false, true, true, Some(100_000)),
        None
    );
    assert_eq!(
        pacing_decision(true, false, true, Some(100_000)),
        None
    );
    assert_eq!(
        pacing_decision(true, true, false, Some(100_000)),
        None
    );
}

/// A missing or zero hint never paces: no primed row is the
/// default-pacing shape (exactly today's behavior for an unpoliced
/// socket), and a zero rate is the BLOCK verdict's own shape — a
/// blocked lane delivers nothing, so no pacing rate can help it,
/// and a zero passed to the option would CLEAR the socket's
/// ceiling, the one direction this lane must never drift.
#[test]
fn a_missing_or_zero_hint_never_paces() {
    assert_eq!(pacing_decision(true, true, true, None), None);
    assert_eq!(pacing_decision(true, true, true, Some(0)), None);
}

/// The uapi field's u32 width is a clamp, never a wrap
/// (SO_MAX_PACING_RATE carries a u32 byte rate): a policy beyond it
/// clamps to the ceiling — the recwn sanitize guard's posture.
#[test]
fn the_uapi_field_width_is_a_clamp_never_a_wrap() {
    assert_eq!(
        pacing_decision(true, true, true, Some(u64::from(u32::MAX))),
        Some(u32::MAX)
    );
    assert_eq!(
        pacing_decision(true, true, true, Some(u32::MAX as u64 + 1)),
        Some(u32::MAX)
    );
}
