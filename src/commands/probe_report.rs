// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The enforcement probe's verdict family and output surface
//! (NIGHT-upgrade-charger-core-1-b; the verdict bands moved here
//! from probe.rs in NIGHT-repair-1 — decision and rendering are one
//! concern, and the orchestrator needed its 500-line ceiling back
//! for the teardown belt): the pure verdict bands (the budget a
//! working bucket admits, the ceiling with its in-flight slack, the
//! flow floor), the outcome they produce, the verify block
//! strict-single prints after its success epilogue, and the FAILED
//! block it errors with instead — every line shape unit-pinned
//! rootlessly.

use crate::ebpf::limiter::{format_bytes, format_rate, Direction};
use crate::output::{ok, warn};

// ── The verdict family (pure, unit-pinned) ─────────────────────

/// The verdict ceiling: the client may exceed the exact budget by
/// 5% plus one GSO super-packet (in-flight/accounting slack); above
/// is FAILED — a bucket cannot admit more than burst + rate x window.
/// The byte term is pub(crate): probe.rs's concurrent-traffic gap
/// check reuses the same one-super-packet slack.
const CEILING_SLACK_PERCENT: u64 = 5;
pub(crate) const CEILING_SLACK_BYTES: u64 = 65_536;

/// The flow floor: a client that moved under 20% of the window's
/// refill did not measure enforcement (dead server, refused entry, a
/// target too busy feeding its own traffic) — UNVERIFIED, never a
/// vacuous pass.
const FLOW_FLOOR_NUM_PERCENT: u64 = 20;

/// What the probe proved about the enforcement it just measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The measured flow stayed inside the budget the policy admits.
    Verified,
    /// The subtree moved more than the budget allows — the limit is
    /// NOT being enforced (exit 1 territory, the owner's contract).
    Failed,
    /// The probe could not measure (never a pass, never a fail).
    Unverified,
}

/// The verdict bands (pure): `budget` is what a working bucket can
/// admit over the window (burst + rate x secs — the same physics the
/// CI harness's 1.30 band family derives from); the ceiling adds the
/// in-flight slack; the floor is the flow that must have happened
/// before any verdict is meaningful.
#[must_use]
pub fn probe_verdict(
    rate_bps: u64,
    burst_bytes: u64,
    secs: u64,
    client_bytes: u64,
) -> ProbeVerdict {
    let budget = rate_bps.saturating_mul(secs).saturating_add(burst_bytes);
    let ceiling = budget
        .saturating_add(budget / (100 / CEILING_SLACK_PERCENT))
        .saturating_add(CEILING_SLACK_BYTES);
    let floor = (rate_bps
        .saturating_mul(secs)
        .saturating_mul(FLOW_FLOOR_NUM_PERCENT)
        / 100)
        .max(1);
    if client_bytes > ceiling {
        ProbeVerdict::Failed
    } else if client_bytes < floor {
        ProbeVerdict::Unverified
    } else {
        ProbeVerdict::Verified
    }
}

/// The probe's measured result, as the report renders it.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub verdict: ProbeVerdict,
    pub direction: Direction,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub window_secs: u64,
    /// The client's own transferred bytes — the measured truth.
    pub client_bytes: u64,
    /// The ledger's bytes_allowed delta over the window (the
    /// kernel's count, target traffic included — the cross-check).
    pub ledger_bytes: u64,
    /// Why an UNVERIFIED probe could not measure, or the concurrent
    /// note when the target fed itself during the window.
    pub note: Option<String>,
    /// charger-core-3b: the measured limit is per SOCKET — the
    /// report names the budget kind, never as the cgroup cap.
    pub per_socket: bool,
    /// NIGHT-repair-1 (the teardown belt): the policy row vanished or
    /// was replaced mid-window — the budget the bytes were measured
    /// against no longer stands, so the verdict is FAILED regardless
    /// of what the pipe managed to deliver (a slow line can hide a
    /// teardown inside the ceiling; the row's absence cannot).
    pub teardown: bool,
}

/// The one-direction figure pair: window bytes and the derived rate
/// against the target ("364.0 KB in 3s (121.3 KB/s)").
fn figures(bytes: u64, secs: u64) -> String {
    format!(
        "{} in {secs}s ({})",
        format_bytes(bytes),
        format_rate(bytes / secs.max(1))
    )
}

/// The verify block (pure). VERIFIED renders the green verdict line;
/// UNVERIFIED renders the yellow one with its reason; FAILED never
/// renders here — the caller errors with [`failure_error`] before
/// any success surface prints (the never-print-then-fail discipline).
#[must_use]
pub(crate) fn report_lines(outcome: &ProbeOutcome) -> Vec<String> {
    let direction = match outcome.direction {
        crate::ebpf::limiter::Direction::Download => "download",
        crate::ebpf::limiter::Direction::Upload => "upload",
    };
    let verdict_line = match outcome.verdict {
        ProbeVerdict::Verified => ok("    enforced:   VERIFIED"),
        _ => warn("    enforced:   UNVERIFIED"),
    };
    let mut lines = vec![
        format!(
            "  verify:  measured the fresh limit over a {}s loopback window",
            outcome.window_secs
        ),
        format!(
            "    direction:  {direction} (limit {}{})",
            format_rate(outcome.rate_bps),
            if outcome.per_socket {
                " per socket"
            } else {
                ""
            }
        ),
        format!(
            "    measured:   {} vs {} target",
            figures(outcome.client_bytes, outcome.window_secs),
            format_rate(outcome.rate_bps)
        ),
        format!(
            "    budget:     {} ({}s at the limit + the {} burst)",
            format_bytes(
                outcome
                    .rate_bps
                    .saturating_mul(outcome.window_secs)
                    .saturating_add(outcome.burst_bytes)
            ),
            outcome.window_secs,
            format_bytes(outcome.burst_bytes)
        ),
        format!(
            "    kernel:     {} admitted through the ledger",
            format_bytes(outcome.ledger_bytes)
        ),
        verdict_line,
    ];
    if let Some(note) = &outcome.note {
        lines.push(warn(&format!("    note:       {note}")));
    }
    lines
}

/// The FAILED error (pure): the block the command errors with — the
/// apply DID land, but the measurement says the limit is not being
/// enforced, and the owner's contract is exit 1 with the numbers
/// attached (never a silent "applied"). NIGHT-repair-1: the headline
/// names its own lane — the exceed shape (the measured flow beat the
/// budget) and the teardown shape (the policy row vanished
/// mid-window; the budget no longer stands, whatever the pipe
/// delivered) are different findings and never wear each other's
/// words — and the outcome's note rides its own row, so a FAILED
/// verdict's reason is never lost to the error path (the same gap
/// the verify block never had).
#[must_use]
pub(crate) fn failure_error(target: &str, outcome: &ProbeOutcome) -> anyhow::Error {
    let direction = match outcome.direction {
        Direction::Download => "download",
        Direction::Upload => "upload",
    };
    let headline = if outcome.teardown {
        "enforcement NOT verified — the policy was removed mid-window (the budget no longer stands)"
    } else {
        "enforcement NOT verified — the measured flow exceeded the budget"
    };
    let note_line = outcome
        .note
        .as_deref()
        .map(|n| format!("\n  note:       {n}"))
        .unwrap_or_default();
    let advice = if outcome.teardown {
        "The policy was removed while the probe measured. Re-run the command; if \
         it repeats, run 'zelynic status' and 'zelynic recover', then re-apply — \
         and file the finding (the probe's numbers above are the report)."
    } else {
        "The policy is applied but not being enforced. Re-run the command; if \
         it repeats, run 'zelynic status' and 'zelynic recover', then re-apply — \
         and file the finding (the probe's numbers above are the report)."
    };
    anyhow::anyhow!(
        "{headline}\n  \
         target:     {target}\n  \
         direction:  {direction} (limit {})\n  \
         measured:   {} vs {} target\n  \
         budget:     {} ({}s at the limit + the {} burst){note_line}\n\n\
         {advice}",
        format_rate(outcome.rate_bps),
        figures(outcome.client_bytes, outcome.window_secs),
        format_rate(outcome.rate_bps),
        format_bytes(
            outcome
                .rate_bps
                .saturating_mul(outcome.window_secs)
                .saturating_add(outcome.burst_bytes)
        ),
        outcome.window_secs,
        format_bytes(outcome.burst_bytes)
    )
}

// The probe report pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the orchestrator's.
#[cfg(test)]
#[path = "../../test/commands/probe_report_tests.rs"]
mod tests;
