// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's verdict bands and outcome shape
//! (NIGHT-upgrade-charger-core-1-b): every band boundary the pure
//! verdict owns — the budget a working bucket can admit, the ceiling
//! with its in-flight slack, the flow floor that keeps a dead probe
//! from reading as a vacuous pass — plus the saturation shapes and
//! the boundary integers themselves, so a future band change is a
//! conscious edit, not drift.

use super::*;

use crate::ebpf::limiter::default_burst;

/// The canonical case: 100kb over the 3s window, burst = 1s of rate
/// (default_burst's clamp) — the budget is 4s of traffic, the ceiling
/// adds the 5% slack plus one GSO super-packet, the floor is 20% of
/// the window's refill.
#[test]
fn canonical_bands_hold() {
    let rate = 100_000_u64;
    let burst = default_burst(rate);
    assert_eq!(burst, 100_000, "1s of rate, above the GSO floor");
    // budget = 3s of refill + the burst = 400 KB.
    let budget = rate * PROBE_SECS + burst;
    assert_eq!(budget, 400_000);
    // ceiling = budget + 5% + one super-packet.
    let ceiling = budget + budget / 20 + 65_536;
    assert_eq!(ceiling, 485_536);

    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, ceiling),
        ProbeVerdict::Verified
    );
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, ceiling + 1),
        ProbeVerdict::Failed,
        "one byte past the ceiling is FAILED (strict >)"
    );
    // The floor: 20% of the window's refill.
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 60_000),
        ProbeVerdict::Verified
    );
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 59_999),
        ProbeVerdict::Unverified,
        "a flow under the floor did not measure enforcement"
    );
}

/// The motivating failure shape: an unpoliced path runs at line rate —
/// megabytes where the budget admits hundreds of kilobytes.
#[test]
fn the_escape_shape_fails_loudly() {
    let rate = 100_000_u64;
    let burst = default_burst(rate);
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 4_800_000),
        ProbeVerdict::Failed,
        "4.8 MB through a 400 KB budget is the 12x-over shape"
    );
}

/// The trickle case: at 1kb the burst is the GSO floor (64 KiB) and a
/// single admitted super-packet is a legitimate window — the burst
/// term keeps the verdict honest exactly where refill alone could
/// never feed one packet.
#[test]
fn the_trickle_case_survives_on_the_burst() {
    let rate = 1_000_u64;
    let burst = default_burst(rate);
    assert_eq!(burst, 65_536, "the GSO admit floor clamps the burst");
    // One admitted super-packet: within budget, above the floor.
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 65_536),
        ProbeVerdict::Verified
    );
    // The unpoliced trickle-rate escape: loopback would move MBs.
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 3_000_000),
        ProbeVerdict::Failed
    );
    // Nothing moved: never a vacuous pass, at ANY rate (floor >= 1).
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, 0),
        ProbeVerdict::Unverified
    );
    assert_eq!(
        probe_verdict(0, 65_536, PROBE_SECS, 0),
        ProbeVerdict::Unverified,
        "a zero-byte flow is never a measurement, even at rate 0"
    );
}

/// Saturation safety: the biggest policy the CLI accepts (1 TB/s,
/// MAX_RATE) against the biggest burst (100 MB) never overflows the
/// band math — and the unreachable u64 extreme degenerates OPEN
/// (everything fits in a saturated budget), never panics, never wraps
/// a floor or ceiling into a lie about a reachable policy.
#[test]
fn the_maximum_policy_never_overflows() {
    let rate = 1_000_000_000_000_u64;
    let burst = default_burst(rate);
    assert_eq!(burst, 100_000_000, "the 100 MB burst ceiling");
    assert_eq!(
        probe_verdict(rate, burst, PROBE_SECS, u64::MAX),
        ProbeVerdict::Failed,
        "line rate at the 1 TB policy is still FAILED"
    );
    assert_eq!(
        probe_verdict(u64::MAX, u64::MAX, u64::MAX, 0),
        ProbeVerdict::Unverified
    );
    // The unreachable extreme: a saturated budget admits everything,
    // so the verdict opens — pinned as the documented degenerate, a
    // shape no CLI rate can produce (MAX_RATE is a trillionth of it).
    assert_eq!(
        probe_verdict(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        ProbeVerdict::Verified
    );
}

/// The outcome's fields ride whole: the report (probe_report) and the
/// future JSON surface read exactly these numbers.
#[test]
fn the_outcome_carries_the_measurement() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Verified,
        direction: Direction::Download,
        rate_bps: 100_000,
        burst_bytes: 100_000,
        window_secs: PROBE_SECS,
        client_bytes: 364_000,
        ledger_bytes: 364_912,
        note: None,
        per_socket: false,
    };
    assert_eq!(outcome.verdict, ProbeVerdict::Verified);
    assert_eq!(outcome.window_secs, 3);
    assert_eq!(outcome.client_bytes, 364_000);
    // The ledger counts the target's own traffic beside the probe —
    // the cross-check row, never the verdict input.
    assert!(outcome.ledger_bytes >= outcome.client_bytes);
}
