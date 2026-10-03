// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The verdict-family pins (pure, rootless): the flow bands
//! (NIGHT-repair-1's move from probe_tests.rs) and the NIGHT-hunt-Z7
//! ledger family — the ledger-refusal proof, the leak lane and its
//! span allowance, the per-socket lane skip, the flow band's own
//! authority, and the starved-notes stack. One theme, one file: the
//! report's output-shape pins live in probe_report_tests.rs.

use super::*;

use crate::commands::probe::PROBE_SECS;
use crate::ebpf::limiter::default_burst;

// ── The verdict bands (moved from probe_tests.rs with the family,
//    NIGHT-repair-1) ─────────────────────────────────────────────

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

// ── The ledger verdict family (NIGHT-hunt-Z7) ───────────────────

/// The dual-limit starvation shape end to end: a 1kb/1kb apply, the
/// flow starved to 0 B, the ledger refusing 224.7 KB — the combined
/// verdict is VERIFIED on the ledger-refusal proof, never the old
/// false-negative UNVERIFIED.
#[test]
fn the_starved_flow_with_refusals_is_verified_by_the_ledger() {
    let legs = [(1_000_u64, default_burst(1_000))];
    let ledger = ledger_verdict(&legs, PROBE_SECS, 549, 224_700, false);
    assert_eq!(ledger, LedgerVerdict::Refused, "drops inside the envelope");
    assert_eq!(
        combined_verdict(1_000, default_burst(1_000), PROBE_SECS, 0, ledger),
        (ProbeVerdict::Verified, ProofBasis::LedgerRefusal),
        "the owner's dual-limit shape is VERIFIED on the refusal"
    );
}

/// The leak veto: a ledger that over-admits fails the apply even
/// when the flow itself measured nothing — and even when the flow
/// PASSED its own band (the target's own traffic over-delivered
/// while the probe starved).
#[test]
fn the_leak_veto_outranks_both_the_starved_and_the_passing_flow() {
    let legs = [(100_000_u64, default_burst(100_000))];
    // budget over (3+2)s = 500 KB + slack = 591,036.
    let leaked = ledger_verdict(&legs, PROBE_SECS, 900_000, 0, false);
    assert_eq!(leaked, LedgerVerdict::Leaked);
    assert_eq!(
        combined_verdict(100_000, default_burst(100_000), PROBE_SECS, 0, leaked),
        (ProbeVerdict::Failed, ProofBasis::LedgerLeak),
        "a starved flow over a leaking ledger is FAILED"
    );
    assert_eq!(
        combined_verdict(100_000, default_burst(100_000), PROBE_SECS, 120_000, leaked),
        (ProbeVerdict::Failed, ProofBasis::LedgerLeak),
        "a PASSING flow over a leaking ledger is FAILED too — the leak veto"
    );
}

/// The leak lane's span allowance: the envelope carries (window +
/// 2)s of refill, so boundary admissions (the teardown drain, the
/// connect retries) never false-fire the veto — the owner's
/// concurrent-traffic windows stay VERIFIED on the flow band.
#[test]
fn the_leak_envelope_carries_the_span_allowance() {
    let legs = [(100_000_u64, default_burst(100_000))];
    // budget = 100 KB x (3+2)s + 100 KB burst = 600 KB;
    // + 5% (30 KB) + one super-packet (64 KiB) = 695,536 — the
    // envelope's exact edge, pinned.
    let tight = ledger_verdict(&legs, PROBE_SECS, 695_536, 0, false);
    assert_eq!(
        tight,
        LedgerVerdict::Silent,
        "the allowance absorbs the span"
    );
    // One byte past the envelope is the leak.
    let over = ledger_verdict(&legs, PROBE_SECS, 695_537, 0, false);
    assert_eq!(over, LedgerVerdict::Leaked);
}

/// per-socket policies cannot be bounded by the cgroup envelope
/// (every connection spends its OWN bucket at the policy rate, and
/// the count is unknown at probe time) — the leak lane stands down,
/// the refusal lane does not (drops still prove the ceiling bit).
#[test]
fn per_socket_policies_skip_the_leak_lane_not_the_refusal_lane() {
    let legs = [(500_000_u64, default_burst(500_000))];
    assert_eq!(
        ledger_verdict(&legs, PROBE_SECS, u64::MAX, 0, true),
        LedgerVerdict::Silent,
        "no envelope bounds a per-socket cgroup total"
    );
    assert_eq!(
        ledger_verdict(&legs, PROBE_SECS, 1_000, 50_000, true),
        LedgerVerdict::Refused,
        "the refusal proof needs no envelope"
    );
}

/// The combined verdict keeps the flow band's own authority: a
/// FAILED flow stays FAILED whatever the ledger says (the measured
/// exceed is the loudest truth), and a passing flow with a silent
/// ledger stays VERIFIED on the flow basis.
#[test]
fn the_flow_band_keeps_its_own_authority() {
    let (rate, burst) = (100_000_u64, default_burst(100_000));
    assert_eq!(
        combined_verdict(rate, burst, PROBE_SECS, 4_800_000, LedgerVerdict::Refused),
        (ProbeVerdict::Failed, ProofBasis::Flow),
        "the measured exceed is the verdict, refusals or not"
    );
    assert_eq!(
        combined_verdict(rate, burst, PROBE_SECS, 200_000, LedgerVerdict::Silent),
        (ProbeVerdict::Verified, ProofBasis::Flow),
        "the passing flow needs no ledger"
    );
    assert_eq!(
        combined_verdict(rate, burst, PROBE_SECS, 0, LedgerVerdict::Silent),
        (ProbeVerdict::Unverified, ProofBasis::Flow),
        "the starved flow with a silent ledger stays unverified"
    );
}

/// The starved-notes stack: every cause its own row, the most
/// specific first — the counter-direction starvation, the
/// unsaturable ceiling, the silent window — and nothing at all for
/// a flow that made its band.
#[test]
fn starved_notes_stack_every_cause() {
    // A flow that made its band carries no starvation rows.
    assert!(starved_notes(
        200_000,
        100_000,
        PROBE_SECS,
        Some(50_000),
        crate::ebpf::limiter::Direction::Download,
        300_000,
        0,
    )
    .is_empty());
    // The dual-limit starvation: the counter-direction row.
    let dual = starved_notes(
        0,
        1_000,
        PROBE_SECS,
        Some(1_000),
        crate::ebpf::limiter::Direction::Download,
        549,
        224_700,
    );
    assert_eq!(dual.len(), 1, "one cause, one row: {dual:?}");
    assert!(dual[0].contains("policed upload (1.0 KB/s)"));
    // The silent window: nothing moved, nothing refused.
    let silent = starved_notes(
        0,
        1_000,
        PROBE_SECS,
        None,
        crate::ebpf::limiter::Direction::Download,
        0,
        0,
    );
    assert_eq!(silent.len(), 1, "the dead lane names itself: {silent:?}");
    assert!(silent[0].contains("moved nothing at all"));
}
