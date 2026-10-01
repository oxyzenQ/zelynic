// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's output surface
//! (NIGHT-upgrade-charger-core-1-b): the verify block's line shapes
//! and the FAILED error's contract — the numbers a reading owner
//! acts on, asserted without touching a socket.

use super::*;

use crate::commands::probe::PROBE_SECS;
use crate::ebpf::limiter::default_burst;

/// The VERIFIED block: the window, the direction with its limit, the
/// measured flow against the target, the budget it was measured
/// against, the kernel's own count, and the verdict — every row a
/// sysadmin needs before trusting the "applied" they just got.
#[test]
fn the_verified_block_carries_every_row() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Verified,
        direction: crate::ebpf::limiter::Direction::Download,
        rate_bps: 100_000,
        burst_bytes: 100_000,
        window_secs: 3,
        client_bytes: 364_000,
        ledger_bytes: 364_912,
        note: None,
        per_socket: false,
        teardown: false,
    };
    let lines = report_lines(&outcome);
    let text = lines.join("\n");
    assert!(lines.len() >= 6, "the block has its rows, got: {text}");
    assert!(
        text.contains("verify:") && text.contains("3s loopback window"),
        "the header names the window, got: {text}"
    );
    assert!(
        text.contains("direction:  download (limit 100.0 KB/s)"),
        "the direction row carries the limit, got: {text}"
    );
    assert!(
        text.contains("measured:") && text.contains("vs 100.0 KB/s target"),
        "the measured row names the target, got: {text}"
    );
    assert!(
        text.contains("budget:") && text.contains("burst"),
        "the budget row decomposes itself, got: {text}"
    );
    assert!(
        text.contains("kernel:") && text.contains("admitted through the ledger"),
        "the kernel row names its source, got: {text}"
    );
    assert!(text.contains("VERIFIED"), "the verdict rides, got: {text}");
    assert!(
        !text.contains("note:"),
        "no note without a reason, got: {text}"
    );
}

/// The UNVERIFIED block: the yellow verdict plus its reason — a weak
/// measurement lane is named, never hidden behind a pass.
#[test]
fn the_unverified_block_names_its_reason() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Unverified,
        direction: crate::ebpf::limiter::Direction::Download,
        rate_bps: 0,
        burst_bytes: 0,
        window_secs: 3,
        client_bytes: 0,
        ledger_bytes: 0,
        note: Some("blocked policy — the drop ledger carries the verdict".to_string()),
        per_socket: false,
        teardown: false,
    };
    let lines = report_lines(&outcome);
    let text = lines.join("\n");
    assert!(
        text.contains("UNVERIFIED"),
        "the verdict is the honest one, got: {text}"
    );
    assert!(
        text.contains("note:       blocked policy"),
        "the reason rides its own row, got: {text}"
    );
}

/// The FAILED error: exit-1 territory — the numbers attached, the
/// recovery path named, and never the word "applied" standing alone.
#[test]
fn the_failed_error_carries_the_numbers_and_the_path() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Failed,
        direction: crate::ebpf::limiter::Direction::Upload,
        rate_bps: 100_000,
        burst_bytes: 100_000,
        window_secs: 3,
        client_bytes: 4_800_000,
        ledger_bytes: 4_800_512,
        note: None,
        per_socket: false,
        teardown: false,
    };
    let err = failure_error("brave", &outcome);
    let msg = format!("{err}");
    assert!(
        msg.starts_with("enforcement NOT verified"),
        "the error leads with the verdict, got: {msg}"
    );
    assert!(
        msg.contains("target:     brave") && msg.contains("direction:  upload"),
        "the context rows ride, got: {msg}"
    );
    assert!(
        msg.contains("measured:") && msg.contains("vs 100.0 KB/s target"),
        "the measured row rides, got: {msg}"
    );
    assert!(
        msg.contains("zelynic recover") && msg.contains("re-apply"),
        "the recovery path is named, got: {msg}"
    );
    assert!(
        msg.contains("probe's numbers above are the report"),
        "the report-by-value contract is stated, got: {msg}"
    );
}

/// charger-core-3b: the report names WHICH budget it measured — a
/// per-socket probe's direction line carries " per socket" so a
/// 500kb-per-connection limit can never read as the cgroup cap.
#[test]
fn per_socket_probe_names_its_budget_kind() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Verified,
        direction: crate::ebpf::limiter::Direction::Download,
        rate_bps: 500_000,
        burst_bytes: 500_000,
        window_secs: 3,
        client_bytes: 1_500_000,
        ledger_bytes: 1_502_000,
        note: None,
        per_socket: true,
        teardown: false,
    };
    let text = report_lines(&outcome).join("\n");
    assert!(
        text.contains("(limit 500.0 KB/s per socket)"),
        "the per-socket budget is named, got: {text}"
    );
}

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

/// The outcome's fields ride whole: the report (this module) and the
/// future JSON surface read exactly these numbers.
#[test]
fn the_outcome_carries_the_measurement() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Verified,
        direction: crate::ebpf::limiter::Direction::Download,
        rate_bps: 100_000,
        burst_bytes: 100_000,
        window_secs: PROBE_SECS,
        client_bytes: 364_000,
        ledger_bytes: 364_912,
        note: None,
        per_socket: false,
        teardown: false,
    };
    assert_eq!(outcome.verdict, ProbeVerdict::Verified);
    assert_eq!(outcome.window_secs, 3);
    assert_eq!(outcome.client_bytes, 364_000);
    // The ledger counts the target's own traffic beside the probe —
    // the cross-check row, never the verdict input.
    assert!(outcome.ledger_bytes >= outcome.client_bytes);
    // The teardown belt's flag rides whole too (a Verified outcome
    // from a standing row carries false).
    assert!(!outcome.teardown);
}

/// NIGHT-repair-1 (the teardown belt): the FAILED error names its own
/// lane — the teardown shape (the policy row vanished mid-window)
/// leads with the removal headline, never the exceed wording, and the
/// outcome's note rides its own row so the finding is complete.
#[test]
fn the_teardown_error_names_its_lane() {
    let outcome = ProbeOutcome {
        verdict: ProbeVerdict::Failed,
        direction: crate::ebpf::limiter::Direction::Download,
        rate_bps: 1_000_000,
        burst_bytes: 1_000_000,
        window_secs: 3,
        client_bytes: 2_600_000,
        ledger_bytes: 2_700_000,
        note: Some(
            "the policy row vanished mid-window (a concurrent unstrict or re-apply) — the budget this window measured against no longer stands"
                .to_string(),
        ),
        per_socket: false,
        teardown: true,
    };
    let err = failure_error("fleet-a", &outcome);
    let msg = format!("{err}");
    assert!(
        msg.starts_with("enforcement NOT verified — the policy was removed mid-window"),
        "the teardown lane leads with its own headline, got: {msg}"
    );
    assert!(
        !msg.contains("exceeded the budget"),
        "the exceed wording never rides the teardown lane, got: {msg}"
    );
    assert!(
        msg.contains("note:       the policy row vanished"),
        "the note rides its own row, got: {msg}"
    );
    assert!(
        msg.contains("measured:") && msg.contains("budget:"),
        "the numbers ride either lane, got: {msg}"
    );
    assert!(
        msg.contains("zelynic recover") && msg.contains("re-apply"),
        "the recovery path is named on the teardown lane too, got: {msg}"
    );
}
