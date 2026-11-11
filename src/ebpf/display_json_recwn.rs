// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The RECWN lane's JSON object (night-spark-2, schema v25 — the
//! object the status document carries as `recwn_limits`; see
//! display_json.rs's StatusJson doc for the wholesale-absence law).
//! night-verify-final's v33 field grew the parent past the 600-LOC
//! owner cap; the object's own file is the split (the
//! display_lines discipline — the parent re-exports the type so
//! every existing path rides unchanged).

use crate::json::write::write_number;

/// The RECWN lane's JSON object (the value of display_json.rs's
/// `StatusJson::recwn_limits` field).
#[derive(Debug, Clone)]
pub(super) struct RecwnLimitsJson {
    /// Whether a live download policy stands for the lane to shape.
    pub(super) enabled: bool,
    /// The binding receive window in bytes (the minimum across
    /// active download policies) — present only when enabled.
    pub(super) window_bytes: Option<u64>,
    /// The Layer 1 RTT assumption the window derived from (us).
    pub(super) rtt_estimate_us: u32,
    /// The binding policy's measured-srtt high-water (us;
    /// night-verify-final, schema v33) — the measured half of the
    /// window derivation when it stands. Absent while unmeasured:
    /// the honest absence, never a fabricated zero (the pinned v32
    /// wire shapes ride unchanged).
    pub(super) measured_srtt_us: Option<u64>,
}

impl RecwnLimitsJson {
    pub(super) fn write_json(&self, out: &mut String) {
        out.push_str("{\"enabled\":");
        out.push_str(if self.enabled { "true" } else { "false" });
        // The additive-field rule: a window the lane is not shaping
        // is absent, never a fabricated zero (the enabled:false
        // shape — the lane rides the object but no download policy
        // stands).
        if let Some(window) = self.window_bytes {
            out.push_str(",\"window_bytes\":");
            write_number(out, window);
        }
        out.push_str(",\"rtt_estimate_us\":");
        write_number(out, self.rtt_estimate_us);
        // night-verify-final (schema v33): the binding policy's
        // measured-srtt high-water, additive and honestly absent —
        // an unmeasured lane omits the field exactly the way an
        // unshaped window omits window_bytes (the pinned v32 wire
        // shapes ride unchanged byte for byte).
        if let Some(srtt) = self.measured_srtt_us {
            out.push_str(",\"measured_srtt_us\":");
            write_number(out, srtt);
        }
        out.push('}');
    }
}
