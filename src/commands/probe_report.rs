// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The enforcement probe's output surface (NIGHT-upgrade-charger-core-1-b):
//! the verify block strict-single prints after its success epilogue,
//! and the FAILED block it errors with instead — pure formatting over
//! the orchestrator's measured outcome (probe.rs), so every line
//! shape is unit-pinned rootlessly.

use crate::ebpf::limiter::{format_bytes, format_rate};
use crate::output::{ok, warn};

use super::probe::{ProbeOutcome, ProbeVerdict};

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
            "    direction:  {direction} (limit {})",
            format_rate(outcome.rate_bps)
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
/// attached (never a silent "applied").
#[must_use]
pub(crate) fn failure_error(target: &str, outcome: &ProbeOutcome) -> anyhow::Error {
    let direction = match outcome.direction {
        crate::ebpf::limiter::Direction::Download => "download",
        crate::ebpf::limiter::Direction::Upload => "upload",
    };
    anyhow::anyhow!(
        "enforcement NOT verified — the measured flow exceeded the budget\n  \
         target:     {target}\n  \
         direction:  {direction} (limit {})\n  \
         measured:   {} vs {} target\n  \
         budget:     {} ({}s at the limit + the {} burst)\n\n\
         The policy is applied but not being enforced. Re-run the command; if \
         it repeats, run 'zelynic status' and 'zelynic recover', then re-apply — \
         and file the finding (the probe's numbers above are the report).",
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
