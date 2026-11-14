// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The tail-aware clamp bracket (night-frontier-Z2, Dive 2 at
//! -1000m) — the depth report's honesty step FROM THE MEAN TO THE
//! TAIL. Dive 1 (night-frontier-Z1, schema v35) gave the report the
//! cgroup's RTT distribution (the 32 log2 srtt buckets, the exact
//! min/sum/max aggregates, the tail story); the RECWN lane
//! (night-spark-2, the quota saver's Layer 1) clamps every owned
//! socket's receive window to `rate x max(measured srtt, 200 ms)`,
//! the per-socket law. The hole between them: the REPORT names one
//! window figure (the binding minimum across policies) and stays
//! silent about whether ONE clamp is even honest for the fleet
//! behind the histogram — a cgroup whose sockets ride BOTH a local
//! path (sub-millisecond RTT) and a remote path (tens of
//! milliseconds) cannot be served by one receive-window value
//! without lying to one class of them.
//!
//! The bracket is the composition of the two existing features (the
//! value-per-line reason it ships): from the srtt half's EXACT min
//! word (Z1's aggregate) and the bucket-bounded p99 (Dive 1's
//! quantile ladder) it derives, through the RECWN window law's own
//! userspace twin, the two ends of the honest single-clamp range
//! and the one metric that grades them:
//!
//! - `ceiling_bytes` = BDP(min RTT) — the TIGHTEST single clamp
//!   that still lets the fastest path fill its pipe. Any window
//!   below it under-delivers even the min-RTT socket (the exact
//!   need the instrument measured).
//! - `floor_bytes` = BDP(p99 RTT) — the clamp under which the
//!   tail's paths stop filling their pipe. The p99 read is a
//!   bucket LOWER bound (the value lives in [2^b, 2^(b+1)) of
//!   microseconds), so the floor is itself a lower bound — the
//!   render's >= prefix admits it, the same honesty the histogram
//!   line's quantiles carry.
//! - `honesty_ratio_permille` = p99 / min RTT, in permille. The
//!   ONE number that grades the fleet: near 1000 (ratio near 1)
//!   the paths agree and one clamp serves; far above it the cgroup
//!   mixes local and remote paths and NO single clamp is honest —
//!   the acceptable range [floor, ceiling] is empty because the
//!   tail's need (floor) has outrun the fastest path's need
//!   (ceiling).
//!
//! The verdict law, both clauses stated:
//!
//! - MIXED when the ratio crosses ONE LOG2 OCTAVE (permille 2000)
//!   AND the law's ends actually diverge (`floor_bytes >
//!   ceiling_bytes`). The octave is the histogram's own resolution
//!   quantum — bucket b spans [2^b, 2^(b+1)) — so a tail within
//!   one octave of the fastest path is the same path class as far
//!   as this instrument can certify; beyond it the path classes
//!   have genuinely split. The divergence clause keeps the refusal
//!   honest at the cadence floor: when BOTH ends ride the 200 ms
//!   floor derivation the law answers byte-identical windows and
//!   one clamp DOES serve (the floor absorbed the spread at this
//!   rate) — refusing there would be noise dressed as rigor.
//! - SINGLE otherwise, with the recommended clamp = the LARGER end
//!   (`max(floor_bytes, ceiling_bytes)`): the pipe no measured
//!   socket under-fills. Normally that is the floor end (BDP at
//!   p99 — delivery-first, the tail's need); when the p99 bucket
//!   bound dips under the exact min (the same-bucket case, e.g.
//!   min 3000 us inside the [2048, 4096) bucket) the exact end
//!   wins — the only exact need the instrument holds. One rule,
//!   no degenerate branches.
//!
//! On MIXED the module REFUSES to name a clamp — the answer is the
//! refusal plus the bracket's ends as the evidence, and the
//! per-socket truth already shipped elsewhere (the traffic
//! section's `[rtt X +/-Y]` pairs, the JSON `endpoints[].rtt_us`).
//! The per-socket CLAMP (sk-storage EWMA granularity) is the Dive
//! ladder's -4000m rung: deferred by the owner's verdict, not
//! forgotten — this module's refusal is the honest door it will
//! open through.
//!
//! Pure: no io, no map access — the handler's assembled
//! [`HistSection`] and [`Enforcement`] are the only inputs, the
//! same fixture-driven purity the report's pins ride. The upload
//! direction never renders: the RECWN lane shapes receive windows
//! (downloads) only, and a bracket for a lane that does not exist
//! would be furniture, not measurement.

use crate::ebpf::display_recwn::recwn_measured_window_bytes;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::limiter::hist::{HistRowRaw, quantile_permille};

use super::format_srtt_lower_bound;
use super::hist_section::HistSection;
use super::report::{Enforcement, kv};

/// The octave gate, in permille of the min RTT: 2000 = one log2
/// octave (2x), the histogram's own resolution quantum. A p99
/// within one octave of the exact min is the same path class as
/// far as the 32-bucket instrument can certify (the p99's true
/// value lives anywhere in its bucket's [2^b, 2^(b+1)) — the
/// bracket refuses to split a fleet the bucket bounds cannot
/// split); beyond one octave the local+remote mixing is real and
/// the single clamp is refused. The ratio rides the bucket-bounded
/// p99, itself a lower bound — so the computed ratio understates
/// the true one by up to the bucket factor, and a MIXED verdict is
/// final (the bound already crossed the octave) while a SINGLE
/// verdict is the octaves the bound can vouch for. Stated, not
/// hidden: the render's >= prefix carries the same caveat.
pub(crate) const BRACKET_OCTAVE_PERMILLE: u64 = 2_000;

/// The bracket's verdict: whether one receive-window clamp can
/// honestly serve the fleet the histogram sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BracketVerdict {
    /// The paths agree (sub-octave, or the cadence floor absorbed
    /// the spread): one clamp serves, named by `clamp_bytes`.
    Single,
    /// The tail outran the fastest path past one octave with the
    /// law's ends diverged: refuse the single clamp — the honest
    /// answer is per-socket (the traffic section's rtt pairs; the
    /// -4000m rung deferred by verdict).
    Mixed,
}

/// The tail-aware clamp bracket for one cgroup's download lane
/// (night-frontier-Z2): the two honest ends through the RECWN
/// window law, the honesty ratio, and the verdict. All figures are
/// what the instrument measured — an absent min word or an absent
/// p99 bucket means an absent bracket, never a zero dressed as a
/// measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClampBracket {
    /// The exact min RTT the Z1 aggregate word carries
    /// (microseconds) — the fastest path's need, `ceiling_bytes`'s
    /// input.
    pub(crate) min_rtt_us: u64,
    /// The p99 RTT's bucket LOWER bound (microseconds) — the tail's
    /// read, `floor_bytes`'s input. The true p99 lives in
    /// [2^b, 2^(b+1)) of this bound; the >= prefix admits it.
    pub(crate) p99_rtt_us: u64,
    /// BDP(min RTT) through the RECWN law — the tightest single
    /// clamp that still lets the fastest path fill its pipe (the
    /// task brief's "ceiling"). Exact input, exact law, exact end.
    pub(crate) ceiling_bytes: u64,
    /// BDP(p99 RTT) through the RECWN law — the clamp under which
    /// the tail stops filling its pipe (the brief's "floor"). A
    /// lower-bound read (the p99 bucket bound's own honesty).
    pub(crate) floor_bytes: u64,
    /// p99 / min RTT in permille, saturating — the honesty ratio.
    /// A lower-bound read (the p99 bound understates the tail by up
    /// to one bucket factor). 1000 = the paths agree exactly.
    pub(crate) honesty_ratio_permille: u64,
    /// The verdict the two clauses above derive.
    pub(crate) verdict: BracketVerdict,
    /// The single clamp when the verdict is [`BracketVerdict::Single`]:
    /// the larger end — the pipe no measured socket under-fills.
    /// None on Mixed: the refusal IS the answer.
    pub(crate) clamp_bytes: Option<u64>,
}

/// The bracket law for one download rate and one srtt half
/// (night-frontier-Z2). None on every honest absence: a zero rate
/// (a block verdict shapes no window — the recwn_lane's own
/// filter), a zero min word (the sentinel — no min yet, or the
/// cross-CPU lag the row doc names), or an empty p99 (no tail the
/// buckets can bound yet). The u32 belt on the RTT inputs keeps the
/// twin's input contract (the recwn_lane rule: an impossible
/// above-u32 word clamps into the band the ceiling already owns).
pub(crate) fn clamp_bracket(rate_bps: u64, srtt: &HistRowRaw) -> Option<ClampBracket> {
    if rate_bps == 0 || srtt.srtt_min == 0 {
        return None;
    }
    let p99_rtt_us = quantile_permille(&srtt.srtt, 990)?;
    let min_rtt_us = srtt.srtt_min;
    let belt = |us: u64| -> u32 { us.min(u64::from(u32::MAX)) as u32 };
    // The two ends ride the SAME law the runtime clamp applies at
    // every owned callback (the measured twin, night-T-3's retune):
    // sub-cadence RTTs answer the 200 ms floor derivation, longer
    // ones extend to the true pipe. The bracket and the datapath
    // can therefore never disagree about what a window IS.
    let ceiling_bytes = recwn_measured_window_bytes(rate_bps, belt(min_rtt_us));
    let floor_bytes = recwn_measured_window_bytes(rate_bps, belt(p99_rtt_us));
    let honesty_ratio_permille = p99_rtt_us.saturating_mul(1_000) / min_rtt_us.max(1);
    let spread = honesty_ratio_permille > BRACKET_OCTAVE_PERMILLE && floor_bytes > ceiling_bytes;
    let verdict = if spread {
        BracketVerdict::Mixed
    } else {
        BracketVerdict::Single
    };
    let clamp_bytes = match verdict {
        BracketVerdict::Single => Some(floor_bytes.max(ceiling_bytes)),
        BracketVerdict::Mixed => None,
    };
    Some(ClampBracket {
        min_rtt_us,
        p99_rtt_us,
        ceiling_bytes,
        floor_bytes,
        honesty_ratio_permille,
        verdict,
        clamp_bytes,
    })
}

/// The bracket from the assembled report's own fields (pure): the
/// download policy's rate against the download half's srtt row.
/// Absent when the cgroup is unlimited, the download lane carries
/// no live rate, the histogram has no download row, or the srtt
/// half has no honest bracket — every absence the text and JSON
/// surfaces render as the honest null.
pub(crate) fn clamp_bracket_for_report(
    report_hist: &Option<HistSection>,
    enforcement: &Enforcement,
) -> Option<ClampBracket> {
    let rate = match enforcement {
        Enforcement::Limited {
            download: Some(p), ..
        } if p.rate_bps > 0 => p.rate_bps,
        _ => return None,
    };
    let row = report_hist.as_ref()?.download.as_ref()?;
    clamp_bracket(rate, row)
}

/// The bracket's one-line read (night-frontier-Z2): the verdict
/// first (the answer a triage glance wants), then the evidence —
/// the honesty ratio and the two ends with their RTT inputs. The
/// lower-bound >= prefix rides every bucket-bounded figure (the
/// p99, the floor it derives, the ratio it feeds); the exact min
/// and its derived ceiling print bare. On Single the recommended
/// clamp leads; on Mixed the refusal leads and the line names the
/// per-socket door that already exists (the traffic section's rtt
/// pairs, the JSON endpoints' rtt_us) — the -4000m rung's honest
/// entrance, not a promise this layer cannot keep.
pub(crate) fn bracket_sentence(bracket: &ClampBracket) -> String {
    let ratio = bracket.honesty_ratio_permille as f64 / 1_000.0;
    let ends = format!(
        "floor >={} @ p99 >={} / ceiling {} @ min {}",
        format_bytes(bracket.floor_bytes),
        format_srtt_lower_bound(bracket.p99_rtt_us),
        format_bytes(bracket.ceiling_bytes),
        format_srtt_lower_bound(bracket.min_rtt_us),
    );
    match bracket.verdict {
        BracketVerdict::Single => format!(
            "{} single clamp (honesty ratio >={ratio:.1}x) — {ends}",
            format_bytes(bracket.clamp_bytes.unwrap_or_default()),
        ),
        BracketVerdict::Mixed => format!(
            "no single clamp (honesty ratio >={ratio:.1}x, mixed local+remote paths; per-socket: the traffic section's rtt pairs) — {ends}",
        ),
    }
}

/// Push the bracket line (night-frontier-Z2): one grey kv row under
/// the histogram section, for the DOWNLOAD lane only — the RECWN
/// lane shapes receive windows, so an upload bracket would name a
/// clamp nothing applies. Absent on every honest absence (no
/// histogram, no download row, no live download rate, no srtt
/// bracket): the line prints nothing rather than a bracket the
/// inputs cannot back.
pub(crate) fn push_bracket_lines(
    lines: &mut Vec<String>,
    histogram: &Option<HistSection>,
    enforcement: &Enforcement,
) {
    if let Some(bracket) = clamp_bracket_for_report(histogram, enforcement) {
        lines.push(kv("clamp bracket", &bracket_sentence(&bracket)));
    }
}

// The Z2 bracket pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the report pins they grew
// beside.
#[cfg(test)]
#[path = "../../../test/ebpf/render/bracket_tests.rs"]
mod tests;
