// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The tail-aware clamp bracket's JSON projection
//! (night-frontier-Z2, Dive 2 at -1000m): the target-object key the
//! law's verdict rides. Split from depth_json/mod.rs at its own
//! birth (the sibling-split lineage — one file per contract; the
//! 600-line LOC law the split serves): a pure mapping, no
//! derivation of its own — the figures ARE the bracket struct's.

use crate::ebpf::render::bracket_section::{BracketVerdict, clamp_bracket_for_report};
use crate::ebpf::render::hist_section::HistSection;
use crate::ebpf::render::report::Enforcement;

/// The tail-aware clamp bracket as JSON (night-frontier-Z2): the
/// law's own words — the exact min, the bucket-bounded p99, the two
/// window-law ends, the permille honesty ratio, the verdict word,
/// and the single-clamp recommendation (null on mixed).
#[derive(Debug, Clone)]
pub struct ClampBracketJson {
    pub min_rtt_us: u64,
    pub p99_rtt_us: u64,
    pub ceiling_bytes: u64,
    pub floor_bytes: u64,
    pub honesty_ratio_permille: u64,
    pub verdict: &'static str,
    pub clamp_bytes: Option<u64>,
}

pub(super) fn clamp_bracket_json(
    section: &Option<HistSection>,
    enforcement: &Enforcement,
) -> Option<ClampBracketJson> {
    clamp_bracket_for_report(section, enforcement).map(|b| ClampBracketJson {
        min_rtt_us: b.min_rtt_us,
        p99_rtt_us: b.p99_rtt_us,
        ceiling_bytes: b.ceiling_bytes,
        floor_bytes: b.floor_bytes,
        honesty_ratio_permille: b.honesty_ratio_permille,
        verdict: match b.verdict {
            BracketVerdict::Single => "single",
            BracketVerdict::Mixed => "mixed",
        },
        clamp_bytes: b.clamp_bytes,
    })
}
