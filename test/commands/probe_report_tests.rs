// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's output surface
//! (NIGHT-upgrade-charger-core-1-b): the verify block's line shapes
//! and the FAILED error's contract — the numbers a reading owner
//! acts on, asserted without touching a socket.
//!
//! NIGHT-hunt-Z7: the ledger-verdict family pins live here too —
//! the dual-limit starvation shape, the leak veto, the unsaturable
//! ceiling, and the starved-notes stack, all pure, all rootless.

use super::*;

use crate::commands::probe::PROBE_SECS;
use crate::ebpf::limiter::default_burst;

/// The outcome constructor's Z7 field set, as one helper so every
/// pin below reads as its verdict, not its plumbing.
fn outcome(
    verdict: ProbeVerdict,
    direction: crate::ebpf::limiter::Direction,
    rate_bps: u64,
    client_bytes: u64,
    ledger_bytes: u64,
    dropped_bytes: u64,
) -> ProbeOutcome {
    ProbeOutcome {
        verdict,
        direction,
        rate_bps,
        burst_bytes: default_burst(rate_bps),
        window_secs: 3,
        client_bytes,
        ledger_bytes,
        dropped_bytes,
        counter_rate_bps: None,
        proof: ProofBasis::Flow,
        notes: Vec::new(),
        per_socket: false,
        teardown: false,
    }
}

/// The VERIFIED block: the window, the direction with its limit, the
/// measured flow against the target, the budget it was measured
/// against, the kernel's own count, and the verdict — every row a
/// sysadmin needs before trusting the "applied" they just got.
#[test]
fn the_verified_block_carries_every_row() {
    let mut o = outcome(
        ProbeVerdict::Verified,
        crate::ebpf::limiter::Direction::Download,
        100_000,
        364_000,
        364_912,
        0,
    );
    o.proof = ProofBasis::Flow;
    let lines = report_lines(&o);
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
        text.contains("kernel:") && text.contains("admitted, 0 B refused through the ledger"),
        "the kernel row names its source and its refusals, got: {text}"
    );
    assert!(text.contains("VERIFIED"), "the verdict rides, got: {text}");
    assert!(
        !text.contains("note:"),
        "no note without a reason, got: {text}"
    );
    assert!(
        !text.contains("proof:"),
        "no proof row on the flow basis (the flow numbers are the proof), got: {text}"
    );
}

/// The UNVERIFIED block: the yellow verdict plus its reason — a weak
/// measurement lane is named, never hidden behind a pass.
#[test]
fn the_unverified_block_names_its_reason() {
    let mut o = outcome(
        ProbeVerdict::Unverified,
        crate::ebpf::limiter::Direction::Download,
        0,
        0,
        0,
        0,
    );
    o.notes
        .push("blocked policy — the drop ledger carries the verdict".to_string());
    let lines = report_lines(&o);
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

/// NIGHT-hunt-Z7: a measured flow of zero renders "0 B/s", never the
/// policy surface's BLOCKED sentinel — the owner's dual-limit
/// transcript read "measured: 0 B in 3s (BLOCKED) vs 1.0 KB/s
/// target", conflating a measurement of nothing with the block
/// verdict the policy never carried (the render footer's own
/// documented discipline).
#[test]
fn a_zero_flow_renders_zero_not_blocked() {
    let o = outcome(
        ProbeVerdict::Unverified,
        crate::ebpf::limiter::Direction::Download,
        1_000,
        0,
        549,
        224_700,
    );
    let text = report_lines(&o).join("\n");
    assert!(
        text.contains("measured:   0 B in 3s (0 B/s) vs 1.0 KB/s target"),
        "the measured row renders the zero flow as a rate, got: {text}"
    );
    assert!(
        !text.contains("(BLOCKED)"),
        "the BLOCKED sentinel never rides a measured figure, got: {text}"
    );
}

/// NIGHT-hunt-Z7, the owner's dual-limit find as one pinned block:
/// the starved flow (0 B measured — its own acknowledgments ride the
/// policed upload) with the kernel's refusal beside it is VERIFIED
/// on the ledger-refusal proof, and the proof row names its basis.
#[test]
fn the_dual_limit_starvation_is_verified_by_the_ledger_refusal() {
    let mut o = outcome(
        ProbeVerdict::Verified,
        crate::ebpf::limiter::Direction::Download,
        1_000,
        0,
        549,
        224_700,
    );
    o.proof = ProofBasis::LedgerRefusal;
    o.counter_rate_bps = Some(1_000);
    o.notes = starved_notes(
        0,
        1_000,
        PROBE_SECS,
        Some(1_000),
        crate::ebpf::limiter::Direction::Download,
        549,
        224_700,
    );
    let text = report_lines(&o).join("\n");
    assert!(
        text.contains("enforced:   VERIFIED"),
        "the starved-but-refusing window is VERIFIED, got: {text}"
    );
    assert!(
        text.contains("proof:      ledger refusal — the kernel refused 224.7 KB"),
        "the proof row names the ledger-refusal basis and its number, got: {text}"
    );
    assert!(
        text.contains("(the flow check itself measured 0 B)"),
        "the proof row names the starved flow check, got: {text}"
    );
    assert!(
        text.contains("acknowledgments ride the policed upload (1.0 KB/s)"),
        "the starvation note names the counter-direction lane, got: {text}"
    );
    assert!(
        text.contains("kernel:     549 B admitted, 224.7 KB refused"),
        "the kernel row carries both counters, got: {text}"
    );
}

/// NIGHT-hunt-Z7, the unsaturable ceiling (`-d 1tb`): a flow that
/// lived under its floor with NOTHING refused and the ledger booking
/// what the client moved is UNVERIFIED with the reason that names
/// the machine's own limit — never a vacuous pass, never a missing
/// explanation.
#[test]
fn the_unsaturable_ceiling_names_its_shape() {
    let mut o = outcome(
        ProbeVerdict::Unverified,
        crate::ebpf::limiter::Direction::Download,
        1_000_000_000_000,
        807_100_000,
        848_100_000,
        0,
    );
    o.notes = starved_notes(
        807_100_000,
        1_000_000_000_000,
        PROBE_SECS,
        None,
        crate::ebpf::limiter::Direction::Download,
        848_100_000,
        0,
    );
    let text = report_lines(&o).join("\n");
    assert!(
        text.contains("UNVERIFIED"),
        "a ceiling the path cannot reach stays unverified, got: {text}"
    );
    assert!(
        text.contains("cannot be tested from this machine's loopback"),
        "the note names the untestable ceiling, got: {text}"
    );
    assert!(
        text.contains("nothing refused"),
        "the note carries the nothing-refused evidence, got: {text}"
    );
}

/// The FAILED error: exit-1 territory — the numbers attached, the
/// recovery path named, and never the word "applied" standing alone.
#[test]
fn the_failed_error_carries_the_numbers_and_the_path() {
    let o = outcome(
        ProbeVerdict::Failed,
        crate::ebpf::limiter::Direction::Upload,
        100_000,
        4_800_000,
        4_800_512,
        0,
    );
    let err = failure_error("brave", &o);
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
        msg.contains("kernel:     4.8 MB admitted, 0 B refused"),
        "the kernel row rides with both counters, got: {msg}"
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

/// NIGHT-hunt-Z7, the leak lane: a ledger that admitted beyond the
/// envelope is FAILED evidence whatever the starved flow measured —
/// the headline names the ledger, never the flow's exceed wording,
/// and the advice names the over-admission.
#[test]
fn the_ledger_leak_error_names_its_lane() {
    let mut o = outcome(
        ProbeVerdict::Failed,
        crate::ebpf::limiter::Direction::Download,
        10_000,
        0,
        900_000,
        0,
    );
    o.proof = ProofBasis::LedgerLeak;
    let err = failure_error("brave", &o);
    let msg = format!("{err}");
    assert!(
        msg.starts_with(
            "enforcement NOT verified — the kernel ledger admitted more than the budget allows"
        ),
        "the leak lane leads with its own headline, got: {msg}"
    );
    assert!(
        !msg.contains("exceeded the budget"),
        "the flow-exceed wording never rides the leak lane, got: {msg}"
    );
    assert!(
        msg.contains("over-admitting"),
        "the advice names the over-admission, got: {msg}"
    );
    assert!(
        msg.contains("kernel:     900.0 KB admitted, 0 B refused"),
        "the numbers that carry the verdict ride, got: {msg}"
    );
}

/// charger-core-3b: the report names WHICH budget it measured — a
/// per-socket probe's direction line carries " per socket" so a
/// 500kb-per-connection limit can never read as the cgroup cap.
#[test]
fn per_socket_probe_names_its_budget_kind() {
    let mut o = outcome(
        ProbeVerdict::Verified,
        crate::ebpf::limiter::Direction::Download,
        500_000,
        1_500_000,
        1_502_000,
        0,
    );
    o.per_socket = true;
    let text = report_lines(&o).join("\n");
    assert!(
        text.contains("(limit 500.0 KB/s per socket)"),
        "the per-socket budget is named, got: {text}"
    );
}

/// The outcome's fields ride whole: the report (this module) and the
/// future JSON surface read exactly these numbers.
#[test]
fn the_outcome_carries_the_measurement() {
    let o = outcome(
        ProbeVerdict::Verified,
        crate::ebpf::limiter::Direction::Download,
        100_000,
        364_000,
        364_912,
        1_400,
    );
    assert_eq!(o.verdict, ProbeVerdict::Verified);
    assert_eq!(o.window_secs, 3);
    assert_eq!(o.client_bytes, 364_000);
    // The ledger counts the target's own traffic beside the probe —
    // allowed AND refused now, both cross-check rows.
    assert!(o.ledger_bytes >= o.client_bytes);
    assert_eq!(o.dropped_bytes, 1_400);
    // The teardown belt's flag rides whole too (a Verified outcome
    // from a standing row carries false).
    assert!(!o.teardown);
}

/// NIGHT-repair-1 (the teardown belt): the FAILED error names its own
/// lane — the teardown shape (the policy row vanished mid-window)
/// leads with the removal headline, never the exceed wording, and the
/// outcome's notes ride their own rows so the finding is complete.
#[test]
fn the_teardown_error_names_its_lane() {
    let mut o = outcome(
        ProbeVerdict::Failed,
        crate::ebpf::limiter::Direction::Download,
        1_000_000,
        2_600_000,
        2_700_000,
        0,
    );
    o.teardown = true;
    o.notes.push(
        "the policy row vanished mid-window (a concurrent unstrict or re-apply) — the budget this window measured against no longer stands"
            .to_string(),
    );
    let err = failure_error("fleet-a", &o);
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
