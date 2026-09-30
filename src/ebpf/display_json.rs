// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The status JSON assembly (charger-core-3b split from display.rs
//! when the per-socket fields grew the file past the 500-LOC owner
//! cap — the same sibling-split lineage the file itself was born
//! from): the pure `status_json` builder (the --print-json contract
//! scripts parse), the rate_ring join, and the document structs. The
//! human table stays in display.rs; the two surfaces share
//! collect_display_data.

use anyhow::Result;

use super::display::collect_display_data;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::rate_ring::{ring_series, RateRingRaw, RingReads, RATE_RING_SLOTS};
use crate::ebpf::limiter::{monotonic_ns, LimiterStatsRaw, PolicyRaw};

/// Print JSON status (for --print-json / scripting).
///
/// NIGHT-boost-3: the write rides the unified
/// [`crate::output::print_json`] primitive — one compact line,
/// serialized field-by-field straight into the locked stdout (the old
/// path allocated the full pretty document as a String, then copied
/// it a second time through the format machinery). The document shape
/// (field names, order) is unchanged; scripts that parsed the pretty
/// layout with `jq` are unaffected, and the one-line contract is the
/// machine-first format the scripting docs promise.
pub fn print_status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
    rings: &RingReads,
) -> Result<()> {
    let status = status_json(
        dl_policies,
        ul_policies,
        stats,
        identity,
        watchdog_deadline,
        rings,
    );
    crate::output::print_json(&status);
    Ok(())
}

/// Assemble the status JSON document (pure, NIGHT-hunt-22: extracted
/// so the scripting contract — field names, watchdog wording, count
/// semantics — is unit-pinnable without capturing stdout). The shape
/// is the `--print-json` contract scripts parse; changing a field
/// name is a breaking change for automation. ADDITIVE fields ride
/// the same rule: `rate_ring` (charger-core-3a) joins only when a
/// ring was readable AND the limit's cgroup has one — absent is
/// honestly absent (skip_serializing_if), never a fabricated empty
/// series.
fn status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
    rings: &RingReads,
) -> StatusJson {
    let watchdog = match watchdog_deadline {
        Some(0) | None => "enforcing",
        Some(d) if d > monotonic_ns() => "active",
        Some(_) => "expired",
    };

    let now = monotonic_ns();
    let data = collect_display_data(dl_policies, ul_policies, stats);

    let limits: Vec<LimitEntry> = data
        .iter()
        .map(|d| {
            let dl_ring = ring_dir_json(rings.dl.as_deref(), d.cgroup_id, now);
            let ul_ring = ring_dir_json(rings.ul.as_deref(), d.cgroup_id, now);
            let rate_ring = match (dl_ring, ul_ring) {
                (None, None) => None,
                (download, upload) => Some(RateRingJson {
                    window_secs: 1,
                    download,
                    upload,
                }),
            };
            LimitEntry {
                cgroup_id: d.cgroup_id,
                label: identity.label(d.cgroup_id),
                download_bps: d.dl_bps,
                upload_bps: d.ul_bps,
                download_per_socket: d.dl_per_socket,
                upload_per_socket: d.ul_per_socket,
                packets_allowed: d.packets_allowed,
                packets_dropped: d.packets_dropped,
                bytes_allowed: d.bytes_allowed,
                bytes_dropped: d.bytes_dropped,
                rate_ring,
            }
        })
        .collect();

    StatusJson {
        watchdog,
        active_limits: limits.len(),
        limits,
    }
}

/// One direction's derived series for one cgroup, or None when the
/// direction's ring census is absent or holds no entry for the
/// cgroup (a fresh policy with no traffic yet books nothing — the
/// sockets-that-moved-nothing rule, a lean row over a fabricated
/// zero).
fn ring_dir_json(
    dir_rings: Option<&[(u32, RateRingRaw)]>,
    cgroup_id: u32,
    now: u64,
) -> Option<RateRingDirectionJson> {
    let rings = dir_rings?;
    let ring = rings.iter().find(|(id, _)| *id == cgroup_id)?;
    let series = ring_series(&ring.1, now);
    Some(RateRingDirectionJson {
        bytes: series.bytes,
        live: series.live,
        peak_bytes: series.peak_bytes,
    })
}

#[derive(serde::Serialize)]
struct LimitEntry {
    cgroup_id: u32,
    label: String,
    download_bps: Option<u64>,
    upload_bps: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    download_per_socket: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    upload_per_socket: bool,
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
    /// The in-kernel time-series ring's derived window series
    /// (charger-core-3a, EAGLE EYES V1): the last eight one-second
    /// byte totals oldest-first, per direction. Absent when the
    /// pinned object predates the ring or the cgroup booked no
    /// traffic under the policy — the absent-lens contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_ring: Option<RateRingJson>,
}

/// One direction's window series (see [`LimitEntry::rate_ring`]).
#[derive(serde::Serialize)]
struct RateRingDirectionJson {
    /// The last eight one-second byte totals, OLDEST first; the last
    /// entry is the current (still-filling) window.
    bytes: [u64; RATE_RING_SLOTS],
    /// How many of the eight windows hold live stamps (the honest
    /// horizon: 3 means only the last three seconds had data).
    live: u32,
    /// The largest COMPLETED window (the current window never
    /// qualifies — it can only grow).
    peak_bytes: u64,
}

#[derive(serde::Serialize)]
struct RateRingJson {
    window_secs: u64,
    download: Option<RateRingDirectionJson>,
    upload: Option<RateRingDirectionJson>,
}

#[derive(serde::Serialize)]
struct StatusJson {
    watchdog: &'static str,
    active_limits: usize,
    limits: Vec<LimitEntry>,
}

// The status-JSON pins (the hunt-22 field/wording/count contracts
// plus the charger-core-3a rate_ring JSON pins) — split from
// display_tests.rs with this module, one test file per module (the
// docker_tests sibling-split lineage).
#[cfg(test)]
#[path = "../../test/ebpf/display_json_tests.rs"]
mod display_json_tests;
