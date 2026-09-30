// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's output surface
//! (NIGHT-upgrade-charger-core-1-b): the verify block's line shapes
//! and the FAILED error's contract — the numbers a reading owner
//! acts on, asserted without touching a socket.

use super::*;

use crate::commands::probe::{ProbeOutcome, ProbeVerdict};

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
    };
    let text = report_lines(&outcome).join("\n");
    assert!(
        text.contains("(limit 500.0 KB/s per socket)"),
        "the per-socket budget is named, got: {text}"
    );
}
