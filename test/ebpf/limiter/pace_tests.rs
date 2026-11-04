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
    assert_eq!(pacing_decision(false, true, true, Some(100_000)), None);
    assert_eq!(pacing_decision(true, false, true, Some(100_000)), None);
    assert_eq!(pacing_decision(true, true, false, Some(100_000)), None);
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

// ── night-spark-7 (Layer 4, the quota telemetry's math): the
// saved-headroom law's rootless pins — the pure core the egress
// accrual (pace_flow.rs pace_saved_book) rides ──────────────────

use ebpf_pace::pacing_saved_bytes;

/// The task brief's own formula, byte-exact: a 100 KB/s lane whose
/// uploader sent one 1500-byte packet 15 ms after the last accrues
/// the budget (100000 x 0.015 = 1500) minus the packet (1500) —
/// exactly nothing, the saturated steady state (the pacer spaces
/// the stream at the rate, so a saturated lane books no headroom —
/// and pays no RMW for the zero, the hot path's own economy).
#[test]
fn a_saturated_paced_packet_books_nothing() {
    assert_eq!(
        pacing_saved_bytes(100_000, 15_000_000, 1500),
        0,
        "15 ms of a 100 KB/s lane is exactly one 1500-byte packet"
    );
}

/// The preserved headroom books exactly: the same lane idle for a
/// full second between packets accrues the one-second budget
/// (100000 B) minus the packet — the quota the pacer held back
/// while the lane was quiet-within-the-cap.
#[test]
fn an_idle_gap_books_the_capped_budget_minus_the_packet() {
    assert_eq!(pacing_saved_bytes(100_000, 1_000_000_000, 1500), 98_500);
    // Half a second, the same law linearly.
    assert_eq!(pacing_saved_bytes(100_000, 500_000_000, 1500), 48_500);
}

/// The idle cap is the refill_credits discipline verbatim: a gap
/// past one second books at most rate x 1s (the anti-burst law's
/// own number — the counter must never reward idleness the bucket
/// itself refuses to credit), and a clock regression (now before
/// the stamp) saturates to a zero gap, the fail-safe direction.
#[test]
fn the_gap_caps_at_one_second_and_a_regression_saturates_to_zero() {
    assert_eq!(
        pacing_saved_bytes(100_000, 2_500_000_000, 1500),
        98_500,
        "a 2.5 s gap books the same one-second cap"
    );
    assert_eq!(
        pacing_saved_bytes(100_000, u64::MAX, 1500),
        98_500,
        "even a u64-extreme gap books the cap"
    );
    assert_eq!(pacing_saved_bytes(100_000, 0, 1500), 0);
}

/// A burst that outruns its own budget saturates to zero, never
/// books a negative — the column stays MONOTONIC (a drain-and-
/// refill cycle counts the refill's surplus, never the drain's
/// deficit, the clamping's stated honest cost).
#[test]
fn a_burst_never_books_a_negative() {
    // 10 ms of a 100 KB/s lane is a 1000-byte budget; a 1500-byte
    // packet rode past it — nothing preserved, nothing owed.
    assert_eq!(pacing_saved_bytes(100_000, 10_000_000, 1500), 0);
}

/// The rate sanitize guard: a rate beyond the 4 GiB/s cap rides a
/// plain (not widening) multiply — bounded factors make the product
/// overflow-impossible, and the law still reads the capped budget
/// at the u64 extremes (the recwn sanitize posture verbatim).
#[test]
fn the_rate_input_sanitizes_before_the_plain_multiply() {
    assert_eq!(
        pacing_saved_bytes(u64::MAX, 1_000_000_000, 0),
        4_294_967_296,
        "the capped rate x the full one-second window"
    );
}

/// The BLOCK verdict's shape: a zero rate preserves nothing — a
/// blocked lane delivers nothing, so no headroom can exist on it.
#[test]
fn a_zero_rate_books_nothing() {
    assert_eq!(pacing_saved_bytes(0, 1_000_000_000, 1500), 0);
}
