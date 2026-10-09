// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The enforcement probe's verdict family and output surface
//! (NIGHT-upgrade-charger-core-1-b; the verdict bands moved here
//! from probe.rs in NIGHT-repair-1 — decision and rendering are one
//! concern, and the orchestrator needed its 500-line ceiling back
//! for the teardown belt): the pure verdict bands (the budget a
//! working bucket admits, the ceiling with its in-flight slack, the
//! flow floor), the LEDGER verdict family (NIGHT-hunt-Z7 — the
//! kernel's own allowed/dropped counters as verdict evidence, not
//! just a display row), the outcome they produce, the verify block
//! the strict family prints after its success epilogue, and the FAILED
//! block it errors with instead — every line shape unit-pinned
//! rootlessly.
//!
//! NIGHT-hunt-Z7 (the owner's dual-limit find, the masterclass
//! hardening): the flow band alone had two live false-negative
//! shapes. A probe whose own TCP acknowledgments ride the POLICED
//! counter-direction (`-d 1kb -u 1kb` — the ACK egress spends the
//! upload bucket beside the target's own traffic) measures ~0 B
//! against a limit that is demonstrably biting, and a ceiling above
//! the path's own delivery (`-d 1tb` — the 20% flow floor is 600 GB
//! over a window loopback moved 807 MB of) can NEVER cross the
//! floor. Both read UNVERIFIED while the kernel's ledger sat right
//! there in the same maps with the truth: hundreds of KB REFUSED
//! (bytes_dropped — the refusal IS the enforcement, booked by the
//! kernel), or nothing refused while every offered byte was
//! admitted (the ceiling genuinely beyond the probe's reach). The
//! verdict family now listens to the ledger: a starved flow with
//! refusals inside the envelope is VERIFIED on the ledger-refusal
//! proof (the `proof:` row names its basis), a ledger that admits
//! beyond the envelope is FAILED on the leak lane even when the
//! flow itself measured nothing, and a silent ledger under a
//! starved flow stays UNVERIFIED with a reason that names its shape.

use crate::ebpf::limiter::{Direction, format_bytes, format_rate, format_rate_exact};
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

/// The ledger envelope's span allowance (NIGHT-hunt-Z7): the ledger
/// delta brackets the 3s window with the spawn grace, the connect
/// retries, and the teardown — up to ~2s of extra refill the
/// window's own budget does not carry. The envelope the ledger is
/// judged against therefore earns (window + 2)s of refill per
/// direction, generous on purpose: the leak lane must never
/// false-fire on boundary effects, and every byte of generosity only
/// risks missing a leak in the zone where the old verdict said
/// nothing at all.
pub(crate) const LEDGER_SPAN_ALLOWANCE_SECS: u64 = 2;

/// What the probe proved about the enforcement it just measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The measured evidence stayed inside the budget the policy
    /// admits — the flow band or the kernel's own ledger.
    Verified,
    /// The subtree moved more than the budget allows — the limit is
    /// NOT being enforced (exit 1 territory, the owner's contract).
    Failed,
    /// The probe could not measure (never a pass, never a fail).
    Unverified,
}

/// What a VERIFIED or FAILED verdict stands on (NIGHT-hunt-Z7):
/// the probe's own flow, or the kernel's ledger when the flow could
/// not measure. The basis renders as the `proof:` row — a verdict
/// and its evidence are one claim, never conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBasis {
    /// The probe's own measured flow stayed inside the budget band
    /// ([floor, ceiling]) — the original charger-core-1b proof.
    Flow,
    /// The kernel ledger REFUSED traffic from the target during the
    /// window (bytes_dropped delta > 0) while its admissions stayed
    /// inside the envelope — the refusal is the enforcement, booked
    /// by the kernel itself. The proof for the starved flow: a probe
    /// whose own acknowledgments ride a policed counter-direction,
    /// or whose bucket the target's own traffic spent, measures 0 B
    /// against a limit that is demonstrably biting.
    LedgerRefusal,
    /// The kernel ledger admitted more than the envelope allows —
    /// the leak the starved flow could never see (it measured ~0 B
    /// while the bucket over-delivered). exit-1 territory, the
    /// FAILED verdict's third lane beside exceed and teardown.
    LedgerLeak,
}

/// The ledger's own verdict over the probe's span (pure,
/// NIGHT-hunt-Z7): what the kernel's allowed/dropped counters prove
/// about ONE leaf's enforcement. `legs` carries the leaf's policed
/// directions as (rate, burst) pairs — the envelope each leg can
/// admit over (secs + LEDGER_SPAN_ALLOWANCE_SECS) with the same
/// five-percent and super-packet slack the flow ceiling carries.
/// `per_socket` policies spend per-CONNECTION buckets with an
/// unknown connection count, so the envelope cannot bound them —
/// the leak lane is structurally unavailable there (the refusal
/// lane is not: drops still prove the ceiling bit something).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerVerdict {
    /// Drops inside the span, admissions inside the envelope: the
    /// kernel refused offered traffic beyond the budget — enforced.
    Refused,
    /// Admissions beyond the envelope: the budget leaked — FAILED
    /// territory whatever the starved flow measured.
    Leaked,
    /// No refusals, no leak: the ledger observed nothing that proves
    /// either way (an idle target, a ceiling above the path's own
    /// delivery).
    Silent,
}

#[must_use]
pub fn ledger_verdict(
    legs: &[(u64, u64)],
    secs: u64,
    allowed_delta: u64,
    dropped_delta: u64,
    per_socket: bool,
) -> LedgerVerdict {
    let envelope: u64 = legs
        .iter()
        .map(|&(rate, burst)| {
            let budget = rate
                .saturating_mul(secs + LEDGER_SPAN_ALLOWANCE_SECS)
                .saturating_add(burst);
            budget
                .saturating_add(budget / (100 / CEILING_SLACK_PERCENT))
                .saturating_add(CEILING_SLACK_BYTES)
        })
        .fold(0_u64, u64::saturating_add);
    if !per_socket && !legs.is_empty() && allowed_delta > envelope {
        LedgerVerdict::Leaked
    } else if dropped_delta > 0 {
        LedgerVerdict::Refused
    } else {
        LedgerVerdict::Silent
    }
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

/// The combined verdict (pure, NIGHT-hunt-Z7): the flow band first —
/// its FAIL and PASS stand on their own measured bytes — then, in
/// the starved zone the flow band could never decide, the ledger's
/// own verdict. The leak veto rides last and outranks everything
/// except teardown (applied by the orchestrator's belt): a ledger
/// that over-admits is FAILED evidence whatever the flow measured.
#[must_use]
pub fn combined_verdict(
    rate_bps: u64,
    burst_bytes: u64,
    secs: u64,
    client_bytes: u64,
    ledger: LedgerVerdict,
) -> (ProbeVerdict, ProofBasis) {
    match probe_verdict(rate_bps, burst_bytes, secs, client_bytes) {
        ProbeVerdict::Failed => (ProbeVerdict::Failed, ProofBasis::Flow),
        ProbeVerdict::Verified => {
            if ledger == LedgerVerdict::Leaked {
                (ProbeVerdict::Failed, ProofBasis::LedgerLeak)
            } else {
                (ProbeVerdict::Verified, ProofBasis::Flow)
            }
        }
        ProbeVerdict::Unverified => match ledger {
            LedgerVerdict::Refused => (ProbeVerdict::Verified, ProofBasis::LedgerRefusal),
            LedgerVerdict::Leaked => (ProbeVerdict::Failed, ProofBasis::LedgerLeak),
            LedgerVerdict::Silent => (ProbeVerdict::Unverified, ProofBasis::Flow),
        },
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
    /// The ledger's bytes_allowed delta over the span (the kernel's
    /// count, target traffic included — the cross-check), summed
    /// across every leaf the target resolved to.
    pub ledger_bytes: u64,
    /// The ledger's bytes_dropped delta over the span, summed the
    /// same way — the kernel's own record of what it REFUSED
    /// (NIGHT-hunt-Z7: the number the verdict finally listens to).
    pub dropped_bytes: u64,
    /// The counter-direction's rate when the same apply polices it
    /// (None on single-direction applies): the probe's own
    /// acknowledgments ride that bucket, and a low counter-rate is
    /// the first suspect when the flow starves. Renders on the
    /// direction row — the verify block names the apply's whole
    /// shape, never just the leg it probed.
    pub counter_rate_bps: Option<u64>,
    /// What the verdict stands on (NIGHT-hunt-Z7): the flow band or
    /// the ledger. Renders as the `proof:` row when not the flow.
    pub proof: ProofBasis,
    /// The honest stack of reasons (NIGHT-hunt-Z7): starvation,
    /// concurrency, multi-leaf, budget history — every cause its own
    /// row, nothing dropped for sharing the old single slot.
    pub notes: Vec<String>,
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
///
/// NIGHT-hunt-Z7: a zero flow renders "0 B/s", never the policy
/// surface's BLOCKED sentinel — the render footer's own documented
/// discipline (`0 B/s`, not the limiter's verdict word): the MEASURED
/// rate is a measurement, and a measurement of nothing is zero, not
/// a block verdict the policy never carried.
fn figures(bytes: u64, secs: u64) -> String {
    let rate = if bytes == 0 {
        "0 B/s".to_string()
    } else {
        format_rate(bytes / secs.max(1))
    };
    format!("{} in {secs}s ({rate})", format_bytes(bytes))
}

/// The verify block (pure). VERIFIED renders the green verdict line;
/// UNVERIFIED renders the yellow one with its reasons; FAILED never
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
    // The counter-direction clause (NIGHT-hunt-Z7): a dual apply's
    // verify block names BOTH legs — the probe measured the one,
    // and the other is the lane its own acknowledgments rode (the
    // starvation note's subject, stated where the limits live).
    let counter = outcome
        .counter_rate_bps
        .map(|r| {
            format!(
                ", {} {}",
                outcome.direction.opposite().label(),
                format_rate_exact(r)
            )
        })
        .unwrap_or_default();
    let mut lines = vec![
        format!(
            "  verify:  measured the fresh limit over a {}s loopback window",
            outcome.window_secs
        ),
        format!(
            "    direction:  {direction} (limit {}{}{})",
            format_rate_exact(outcome.rate_bps),
            if outcome.per_socket {
                " per socket"
            } else {
                ""
            },
            counter
        ),
        format!(
            "    measured:   {} vs {} target",
            figures(outcome.client_bytes, outcome.window_secs),
            format_rate_exact(outcome.rate_bps)
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
            "    kernel:     {} admitted, {} refused through the ledger",
            format_bytes(outcome.ledger_bytes),
            format_bytes(outcome.dropped_bytes)
        ),
        verdict_line,
    ];
    if outcome.proof == ProofBasis::LedgerRefusal {
        let starved = if outcome.client_bytes == 0 {
            " (the flow check itself measured 0 B)"
        } else {
            ""
        };
        lines.push(ok(&format!(
            "    proof:      ledger refusal — the kernel refused {} from the target \
             beyond the budget during the window{starved}",
            format_bytes(outcome.dropped_bytes)
        )));
    }
    for note in &outcome.notes {
        lines.push(warn(&format!("    note:       {note}")));
    }
    lines
}

/// The FAILED error (pure): the block the command errors with — the
/// apply DID land, but the measurement says the limit is not being
/// enforced, and the owner's contract is exit 1 with the numbers
/// attached (never a silent "applied"). NIGHT-repair-1: the headline
/// names its own lane — the exceed shape (the measured flow beat the
/// budget), the teardown shape (the policy row vanished mid-window;
/// the budget no longer stands, whatever the pipe delivered), and
/// NIGHT-hunt-Z7's leak shape (the kernel ledger admitted more than
/// the envelope allows — the over-admission a starved flow could
/// never see) are different findings and never wear each other's
/// words — and every note rides its own row, so a FAILED verdict's
/// reasons are never lost to the error path.
#[must_use]
pub(crate) fn failure_error(target: &str, outcome: &ProbeOutcome) -> anyhow::Error {
    let direction = match outcome.direction {
        Direction::Download => "download",
        Direction::Upload => "upload",
    };
    let headline = if outcome.teardown {
        "enforcement NOT verified — the policy was removed mid-window (the budget no longer stands)"
    } else if outcome.proof == ProofBasis::LedgerLeak {
        "enforcement NOT verified — the kernel ledger admitted more than the budget allows"
    } else {
        "enforcement NOT verified — the measured flow exceeded the budget"
    };
    let note_lines = outcome
        .notes
        .iter()
        .map(|n| format!("\n  note:       {n}"))
        .collect::<String>();
    let advice = if outcome.teardown {
        "The policy was removed while the probe measured. Re-run the command; if \
         it repeats, run 'zelynic status' and 'zelynic recover', then re-apply — \
         and file the finding (the probe's numbers above are the report)."
    } else if outcome.proof == ProofBasis::LedgerLeak {
        "The policy is applied but the kernel is over-admitting. Re-run the \
         command; if it repeats, run 'zelynic status' and 'zelynic recover', \
         then re-apply — and file the finding (the probe's numbers above are \
         the report)."
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
         budget:     {} ({}s at the limit + the {} burst)\n  \
         kernel:     {} admitted, {} refused through the ledger{note_lines}\n\n\
         {advice}",
        format_rate_exact(outcome.rate_bps),
        figures(outcome.client_bytes, outcome.window_secs),
        format_rate_exact(outcome.rate_bps),
        format_bytes(
            outcome
                .rate_bps
                .saturating_mul(outcome.window_secs)
                .saturating_add(outcome.burst_bytes)
        ),
        outcome.window_secs,
        format_bytes(outcome.burst_bytes),
        format_bytes(outcome.ledger_bytes),
        format_bytes(outcome.dropped_bytes)
    )
}

/// The starved-flow reason stack (pure, NIGHT-hunt-Z7): the notes
/// that explain a flow under the floor, most specific first. The
/// counter-direction starvation is checked before the pipe ceiling
/// because it is the shape the operator can act on (re-run with one
/// direction, or trust the ledger's refusal proof); the unsaturable
/// ceiling is a fact of the machine, not a misconfiguration; the
/// silent window is the dead-lane fallback the old single note
/// carried. The concurrent-traffic note is folded in by the
/// orchestrator (it needs the ledger gap, not just the flow).
#[must_use]
pub(crate) fn starved_notes(
    client_bytes: u64,
    rate_bps: u64,
    secs: u64,
    counter_rate_bps: Option<u64>,
    direction: Direction,
    ledger_allowed: u64,
    ledger_dropped: u64,
) -> Vec<String> {
    let mut notes = Vec::new();
    let floor = (rate_bps
        .saturating_mul(secs)
        .saturating_mul(FLOW_FLOOR_NUM_PERCENT)
        / 100)
        .max(1);
    if client_bytes >= floor {
        return notes;
    }
    let counter = counter_rate_bps.map(|r| (r, direction.opposite()));
    if let Some((counter_rate, counter_dir)) = counter {
        notes.push(format!(
            "the probe's own acknowledgments ride the policed {} ({}) — the {} flow \
             cannot be offered through a starved counter-direction bucket",
            counter_dir.label(),
            format_rate_exact(counter_rate),
            direction.label()
        ));
    }
    if ledger_dropped == 0 && client_bytes > 0 {
        // Nothing refused, yet the flow lived under its floor: the
        // path itself could not reach the band — the ceiling sits
        // above what this machine's loopback delivers.
        notes.push(format!(
            "the window's flow floor ({}) is beyond what this path delivered \
             ({} moved, nothing refused) — a ceiling this high cannot be tested \
             from this machine's loopback",
            format_bytes(floor),
            figures(client_bytes, secs)
        ));
    }
    if client_bytes == 0 && ledger_allowed == 0 && ledger_dropped == 0 {
        notes.push(
            "the window moved nothing at all — no demand reached the bucket (a \
             dead lane, a refused entry, or a fully starved path)"
                .to_string(),
        );
    }
    notes
}

// The probe report pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the orchestrator's. The
// NIGHT-hunt-Z7 ledger family took its own file at the 500-LOC owner
// cap (the format_tests one-theme-one-file precedent).
#[cfg(test)]
#[path = "../../test/commands/probe_report_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../test/commands/probe_ledger_tests.rs"]
mod ledger_tests;
