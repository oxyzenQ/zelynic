// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The status document's rate-ring JSON family (charger-core-3a),
//! split from display_json.rs (night-spark-4 — the v26 CE ledger
//! grew the parent past the 600-LOC owner cap, NIGHT-improve-44's
//! pure-move law; the sibling-split lineage the parent itself was
//! born from): the `rate_ring` join producer and the two series
//! records with their hand-written `write_json` wires. The parent
//! owns the document assembly; this module owns the ring shapes'
//! bytes exactly.

use crate::ebpf::limiter::rate_ring::{RATE_RING_SLOTS, RateRingRaw, ring_series};

/// One direction's derived series for one cgroup, or None when the
/// direction's ring census is absent or holds no entry for the
/// cgroup (a fresh policy with no traffic yet books nothing — the
/// sockets-that-moved-nothing rule, a lean row over a fabricated
/// zero).
pub(super) fn ring_dir_json(
    dir_rings: Option<&[(u32, RateRingRaw)]>,
    cgroup_id: u32,
    now: u64,
) -> Option<RateRingDirectionJson> {
    let rings = dir_rings?;
    let ring = rings.iter().find(|(id, _)| *id == cgroup_id)?;
    let series = ring_series(&ring.1, now);
    Some(RateRingDirectionJson {
        bytes: series.bytes,
        live_samples: series.live_samples,
        peak_bytes: series.peak_bytes,
    })
}

/// One direction's window series (see [`super::LimitEntry`]'s
/// `rate_ring` field).
#[derive(Debug, Clone)]
pub(super) struct RateRingDirectionJson {
    /// The last eight one-second byte totals, OLDEST first; the last
    /// entry is the current (still-filling) window.
    pub(super) bytes: [u64; RATE_RING_SLOTS],
    /// How many of the eight slots carry a stamp matching the
    /// window they represent (night-verdict-closure-T7 (H4), the
    /// wire name was `live` — renamed because a bare `live` reads
    /// as a rate): a stamped ZERO-byte window counts, so the figure
    /// is the honest horizon, neither a rate nor the count of
    /// non-zero slots (3 means only the last three seconds had
    /// stamped windows).
    pub(super) live_samples: u32,
    /// The largest COMPLETED window (the current window never
    /// qualifies — it can only grow).
    pub(super) peak_bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) struct RateRingJson {
    /// The number of seconds the series spans: RATE_RING_SLOTS
    /// one-second windows (NIGHT-hunt-30 — was the per-slot width,
    /// which read as the whole window). `sum(bytes) / window_secs`
    /// is the row's average rate over the horizon; the per-slot
    /// granularity is `bytes.len()`, one sample per second.
    pub(super) window_secs: u64,
    pub(super) download: Option<RateRingDirectionJson>,
    pub(super) upload: Option<RateRingDirectionJson>,
}

// The writer law is the parent document's (S1, the hand-written
// lane): field order = declaration order, absence is the None
// branch, never a fabricated shape. The wire names are the pinned
// scripting contract (docs/USAGE.md JSON reference).
impl RateRingDirectionJson {
    pub(super) fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_array, write_number};

        out.push_str("{\"bytes\":");
        write_array(out, self.bytes.len(), |out, i| {
            write_number(out, self.bytes[i]);
        });
        out.push_str(",\"live_samples\":");
        write_number(out, self.live_samples);
        out.push_str(",\"peak_bytes\":");
        write_number(out, self.peak_bytes);
        out.push('}');
    }
}

impl RateRingJson {
    pub(super) fn write_json(&self, out: &mut String) {
        use crate::json::write::write_number;

        out.push_str("{\"window_secs\":");
        write_number(out, self.window_secs);
        out.push_str(",\"download\":");
        match &self.download {
            Some(dir) => dir.write_json(out),
            None => out.push_str("null"),
        }
        out.push_str(",\"upload\":");
        match &self.upload {
            Some(dir) => dir.write_json(out),
            None => out.push_str("null"),
        }
        out.push('}');
    }
}
