// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The RECWN lane's derivation and its line (night-spark-2, schema
//! v25 — Receive Window Control, the quota saver's Layer 1). The
//! display.rs sibling grew past the 600-LOC owner cap when
//! night-verify-final's schema v33 made the measured srtt readable;
//! the lane's own file is the split (the display_lines discipline —
//! the parent re-exports every item, so the pins in display_tests
//! (use super::*) and the status surfaces see the same paths as
//! before the split).

use crate::ebpf::limiter::types::PolicyRaw;
use crate::ebpf::limiter::{LimiterStatsRaw, format_bytes};
use crate::output::grey;

/// The RECWN lane's status derivation (night-spark-2, schema v25 —
/// Receive Window Control, the quota saver's Layer 1): what the
/// two status surfaces (human table + --print-json) report about
/// the receive-window lane. `planted` says the sock_ops program's
/// pin stands (the lane rides the limiter object — schema v25's
/// is_pinned covers it); `window_bytes` is the BINDING window the
/// lane currently derives — the smallest window across the active
/// download policies (the single-policy case, the owner's brief's
/// own scenario, reads exactly that policy's window; a multi-
/// policy tree reports the tightest clamp the lane enforces
/// anywhere). Absent when no download policy with a live rate
/// stands (upload-only or block-only rows shape no window).
///
/// night-ux-1: `Default` is the INERT lane (not planted, no window,
/// no binding policies) — the shape every pre-RECWN surface and
/// test helper rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RecwnLane {
    pub(crate) planted: bool,
    pub(crate) window_bytes: Option<u64>,
    /// night-ux-1: the count of ACTIVE download policies (rate > 0)
    /// the binding window derives across — the human line's "binding
    /// across N download policies" names the unit the clamp polices
    /// (the multi-policy tree reports the tightest clamp and the
    /// count it wins across). Derived beside the window in
    /// [`recwn_lane`] so the pair can never drift; the human line is
    /// its only consumer (the JSON twin stays the pinned scripting
    /// shape).
    pub(crate) binding_policies: usize,
    /// night-verify-final (schema v33): the binding policy's
    /// measured-srtt high-water (microseconds) — the value
    /// `recwn_limits.measured_srtt_us` reports, the rtt half of the
    /// window_bytes derivation when it stands. None = unmeasured
    /// (no policed download socket has sampled since the stats
    /// row's birth): the honest absence, never a fabricated zero.
    /// The binding window's OWN rtt — the argmin policy's, not the
    /// fleet's global max — so the (window_bytes, measured_srtt_us)
    /// pair always derives from one policy.
    pub(crate) measured_srtt_us: Option<u64>,
}

/// The Layer 1 RTT assumption, microseconds — the userspace twin
/// of ebpf/src/recwn.rs's RECWN_DEFAULT_RTT_US (200 ms, the
/// delivery-cadence estimate the live E2E evidence set — the
/// kernel core's doc owns the full record). The twin discipline
/// default_burst carries: each tree states its own constant, and
/// test/ebpf/limiter/recwn_tests.rs pins the derived windows
/// against the kernel core so the pair can never drift.
pub(crate) const RECWN_RTT_ESTIMATE_US: u32 = 200_000;

/// The window-band clamps — the userspace twins of the kernel
/// core's RECWN_WINDOW_MIN_BYTES / RECWN_WINDOW_MAX_BYTES (2 x MSS
/// and 1 MiB; ebpf/src/recwn.rs owns the law's rationale).
pub(crate) const RECWN_WINDOW_MIN_BYTES: u64 = 2 * 1460;
pub(crate) const RECWN_WINDOW_MAX_BYTES: u64 = 1_048_576;

/// The sanitize guard on the rate input — the userspace twin of
/// ebpf/src/recwn.rs's RECWN_RATE_SANITIZE_CAP (4 GiB/s). The
/// kernel side must ride a plain 64-bit multiply (the BPF ISA has
/// no widening multiply — a saturating one lowers to `__multi3`,
/// which the kernel cannot relocate), so the twin carries the SAME
/// clamp-then-multiply shape and the parity pin holds at every
/// input, not just the sane ones.
pub(crate) const RECWN_RATE_SANITIZE_CAP: u64 = 4_294_967_296;

/// The RECWN window one download rate derives — the userspace twin
/// of the kernel core's layer1_window (rate x RTT / 1e6, clamped
/// to the [2 x MSS, 1 MiB] band). Parity-pinned against the core
/// by test/ebpf/limiter/recwn_tests.rs across the rate matrix.
pub(crate) fn recwn_window_bytes(rate_bps: u64) -> u64 {
    let rate = rate_bps.min(RECWN_RATE_SANITIZE_CAP);
    let raw = rate * u64::from(RECWN_RTT_ESTIMATE_US) / 1_000_000;
    raw.clamp(RECWN_WINDOW_MIN_BYTES, RECWN_WINDOW_MAX_BYTES)
}

/// The RECWN window one download rate derives from a MEASURED srtt
/// (microseconds) — the userspace twin of the kernel core's
/// measured_window_bytes (night-T-3's retune law): a sample above
/// the 200 ms cadence floor extends the pipe to the measured BDP,
/// every sub-floor sample — and every unmeasured socket, srtt zero
/// — answers the exact floor derivation byte for byte. Parity-
/// pinned against the core by test/ebpf/limiter/recwn_tests.rs
/// across the (rate, srtt) matrix; night-verify-final's schema v33
/// made the measured side readable (the stats row's ratchet).
pub(crate) fn recwn_measured_window_bytes(rate_bps: u64, measured_srtt_us: u32) -> u64 {
    if measured_srtt_us > RECWN_RTT_ESTIMATE_US {
        let rate = rate_bps.min(RECWN_RATE_SANITIZE_CAP);
        let raw = rate * u64::from(measured_srtt_us) / 1_000_000;
        raw.clamp(RECWN_WINDOW_MIN_BYTES, RECWN_WINDOW_MAX_BYTES)
    } else {
        recwn_window_bytes(rate_bps)
    }
}

/// Derive the RECWN lane's status row from the download policy
/// census, the per-cgroup stats rows, and the program pin's
/// existence: the BINDING window is the minimum the active download
/// rates derive (a block verdict — rate 0 — shapes no window: the
/// lane that delivers nothing has no receive window to shape), and
/// a lane that is not planted shapes nothing at all — the window
/// rides the program, not the census (an unplanted tree with stale
/// map rows reports no window, never a phantom clamp). Since
/// night-verify-final's schema v33 each policy's window derives
/// through the MEASURED twin (rate x max(ratcheted srtt, 200 ms)):
/// a policy whose stats row carries a high-water above the cadence
/// floor extends, an unmeasured one answers the exact floor
/// derivation byte for byte — and the reported measured_srtt_us is
/// the binding window's own rtt (the argmin policy's; the largest
/// high-water among ties, the deterministic rule the map's row
/// order cannot flap).
pub(crate) fn recwn_lane(
    dl_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    planted: bool,
) -> RecwnLane {
    // The ratchet each policy's stats row carries (zero when the row
    // is missing or unmeasured — the floor branch; the belt over an
    // impossible above-u32 word keeps the twin's u32 input).
    let srtt_of = |cg: u32| -> u32 {
        stats.iter().find(|(k, _)| *k == cg).map_or(0, |(_, s)| {
            s.measured_srtt_us.min(u64::from(u32::MAX)) as u32
        })
    };
    // One pass derives every active policy's (window, srtt) pair —
    // the measured twin's law, the same shape the datapath applies
    // at the socket's own callbacks.
    let derived: Vec<(u64, u32)> = dl_policies
        .iter()
        .filter(|(_, p)| p.rate_bps > 0)
        .map(|(cg, p)| {
            let s = srtt_of(*cg);
            (recwn_measured_window_bytes(p.rate_bps, s), s)
        })
        .collect();
    let window_bytes = planted
        .then(|| derived.iter().map(|(w, _)| *w).min())
        .flatten();
    // The binding window's own rtt: the largest high-water among the
    // policies tying on the minimum (ties read the same window, so
    // the highest srtt names the binding constraint), and honestly
    // absent while every tying row is unmeasured.
    let measured_srtt_us = window_bytes.and_then(|w| {
        derived
            .iter()
            .filter(|(dw, _)| *dw == w)
            .map(|(_, s)| u64::from(*s))
            .max()
            .filter(|s| *s > 0)
    });
    RecwnLane {
        planted,
        window_bytes,
        binding_policies: derived.len(),
        measured_srtt_us,
    }
}

/// The human table's RECWN subordinate line (night-spark-2, schema
/// v25 — Receive Window Control, the quota saver's Layer 1): the
/// binding receive window the lane derives and the RTT estimate it
/// derived it from, in the watchdog's grey family. night-ux-1 (the
/// owner's 200kb-on-Brave session): the line now says WHAT the
/// number IS — the receive WINDOW the lane clamps sockets to, not
/// saved bytes — and HOW MANY download policies it binds (the
/// count the derivation itself produced; singular for one, the
/// owner's own scenario). RECWN keeps its brand capitals — the
/// owner's coined vocabulary, the BLOCKED verdict-value family
/// (furniture stays lowercase, the brand is the message). None
/// when the lane shapes no window (not planted, or no download
/// policy with a live rate) — the dormant-watchdog honesty: an
/// unenforcing lane prints nothing.
pub(crate) fn recwn_line(lane: &RecwnLane) -> Option<String> {
    // The belt the derivation already owns: an unplanted lane shapes
    // nothing, whatever a stale census might claim — silence, never
    // a phantom clamp printed as state.
    if !lane.planted {
        return None;
    }
    let window = lane.window_bytes?;
    let n = lane.binding_policies;
    // night-verify-final (schema v33): the rtt clause names the rtt
    // the WINDOW derived from — a binding policy whose high-water
    // tops the cadence floor prints the MEASURED srtt (the number
    // the extension itself rode), every other shape keeps the v25
    // cadence estimate under its est. name. The JSON reports the
    // raw sample regardless — recwn_limits.measured_srtt_us is the
    // measurement's own contract, this clause is the window's.
    let (rtt_label, rtt_ms) = match lane.measured_srtt_us {
        Some(srtt) if srtt > u64::from(RECWN_RTT_ESTIMATE_US) => ("measured RTT", srtt / 1000),
        _ => ("est. RTT", u64::from(RECWN_RTT_ESTIMATE_US) / 1000),
    };
    Some(grey(&format!(
        "  RECWN window: {} (binding across {n} download {}; {rtt_label} {rtt_ms}ms)",
        format_bytes(window),
        if n == 1 { "policy" } else { "policies" },
    )))
}
