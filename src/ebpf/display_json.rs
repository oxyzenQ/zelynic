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
use crate::ebpf::limiter::types::PolicyWindowRaw;
use crate::ebpf::limiter::{monotonic_ns, wall_now_ns, LimiterStatsRaw, PolicyRaw};
use crate::ebpf::limiter::{wall_minus_mono, window_state};

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
    windows: &[(u32, PolicyWindowRaw)],
) -> Result<()> {
    let status = status_json(
        dl_policies,
        ul_policies,
        stats,
        identity,
        watchdog_deadline,
        rings,
        windows,
        wall_now_ns(),
        monotonic_ns(),
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
#[allow(clippy::too_many_arguments)]
fn status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
    rings: &RingReads,
    windows: &[(u32, PolicyWindowRaw)],
    wall_now_ns: u64,
    mono_now_ns: u64,
) -> StatusJson {
    let watchdog = match watchdog_deadline {
        Some(0) | None => "enforcing",
        Some(d) if d > monotonic_ns() => "active",
        Some(_) => "expired",
    };

    let now = monotonic_ns();
    let data = collect_display_data(dl_policies, ul_policies, stats, windows);

    let limits: Vec<LimitEntry> = data
        .iter()
        .map(|d| {
            let dl_ring = ring_dir_json(rings.dl.as_deref(), d.cgroup_id, now);
            let ul_ring = ring_dir_json(rings.ul.as_deref(), d.cgroup_id, now);
            let rate_ring = match (dl_ring, ul_ring) {
                (None, None) => None,
                (download, upload) => Some(RateRingJson {
                    // NIGHT-hunt-30: the field names the SPAN the
                    // series covers (8 one-second slots), not the
                    // per-slot width — the owner's "what mean window
                    // secs 1" find: `1` made `sum(bytes) /
                    // window_secs` overcount eight-fold.
                    window_secs: RATE_RING_SLOTS as u64,
                    download,
                    upload,
                }),
            };
            let window = d
                .window
                .as_ref()
                .map(|w| window_json(w, wall_now_ns, mono_now_ns));
            // improve-40 (schema v24) / improve-40-b (the
            // per-direction split): equal pairs ride the merged
            // floor_bps/ceil_bps (the one-flag shape, unchanged);
            // differing pairs ride the per-direction fields, the
            // merged pair honestly absent — never a fabricated
            // merge, never a fabricated zero.
            let equal_pair =
                (d.download == d.upload).then_some((d.download.floor_bps, d.download.ceil_bps));
            let split = (d.download != d.upload).then_some((d.download, d.upload));
            LimitEntry {
                cgroup_id: d.cgroup_id,
                label: identity.label(d.cgroup_id),
                download_bps: d.dl_bps,
                upload_bps: d.ul_bps,
                download_per_socket: d.dl_per_socket,
                upload_per_socket: d.ul_per_socket,
                floor_bps: equal_pair.map(|(floor, _)| floor).filter(|v| *v != 0),
                ceil_bps: equal_pair.map(|(_, ceil)| ceil).filter(|v| *v != 0),
                download_floor_bps: split
                    .map(|(download, _)| download.floor_bps)
                    .filter(|v| *v != 0),
                download_ceil_bps: split
                    .map(|(download, _)| download.ceil_bps)
                    .filter(|v| *v != 0),
                upload_floor_bps: split
                    .map(|(_, upload)| upload.floor_bps)
                    .filter(|v| *v != 0),
                upload_ceil_bps: split.map(|(_, upload)| upload.ceil_bps).filter(|v| *v != 0),
                packets_allowed: d.packets_allowed,
                packets_dropped: d.packets_dropped,
                bytes_allowed: d.bytes_allowed,
                bytes_dropped: d.bytes_dropped,
                rate_ring,
                window,
            }
        })
        .collect();

    StatusJson {
        watchdog,
        active_limits: limits.len(),
        limits,
    }
}

/// One row's window as JSON (night-during, schema v23 — the
/// scripting surface): the kind, the STATE vocabulary the status
/// pins own ("active" / "dormant" / "outside" / "expired"), and
/// the shape's own fields — a span's WALL instants (ns since
/// epoch, reconstructed through the same offset pair the twin
/// uses; the monotonic deadlines a map row carries would be
/// meaningless to a script and across reboots alike), a daily
/// window's seconds-of-day pair.
fn window_json(win: &PolicyWindowRaw, wall_now: u64, mono_now: u64) -> WindowJson {
    let offset = wall_minus_mono(wall_now, mono_now);
    let state = window_state(win, wall_now, mono_now);
    match win.kind {
        crate::ebpf::limiter::types::WINDOW_KIND_DAILY => WindowJson {
            kind: "daily",
            state,
            start_wall_ns: None,
            end_wall_ns: None,
            start_s: Some(win.start_s),
            end_s: Some(win.end_s),
        },
        _ => WindowJson {
            kind: "span",
            state,
            start_wall_ns: Some(win.start_mono_ns.saturating_add(offset)),
            end_wall_ns: Some(win.end_mono_ns.saturating_add(offset)),
            start_s: None,
            end_s: None,
        },
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
    /// The per-subprocess guaranteed minimum (improve-40, schema
    /// v24) — absent when the row carries none (the zero sentinel)
    /// or when the directions' pairs DIFFER (the split rides the
    /// per-direction fields below, never a fabricated merge).
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_bps: Option<u64>,
    /// The per-subprocess maximum (improve-40, schema v24) —
    /// absent when unset or when the pairs differ.
    #[serde(skip_serializing_if = "Option::is_none")]
    ceil_bps: Option<u64>,
    /// The DOWNLOAD pair's floor (improve-40-b, the per-direction
    /// split) — present only when the directions' pairs differ,
    /// the asymmetric link's own shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    download_floor_bps: Option<u64>,
    /// The DOWNLOAD pair's ceiling (improve-40-b) — split only.
    #[serde(skip_serializing_if = "Option::is_none")]
    download_ceil_bps: Option<u64>,
    /// The UPLOAD pair's floor (improve-40-b) — split only.
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_floor_bps: Option<u64>,
    /// The UPLOAD pair's ceiling (improve-40-b) — split only.
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_ceil_bps: Option<u64>,
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
    /// The row's --during window (night-during, schema v23),
    /// absent when the row carries none — the additive-field rule
    /// the rate_ring join set.
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<WindowJson>,
}

/// One row's window (see [`LimitEntry::window`]).
#[derive(serde::Serialize)]
struct WindowJson {
    /// "span" or "daily".
    kind: &'static str,
    /// "active", "dormant", "outside", or "expired" (the state
    /// vocabulary the status pins own).
    state: &'static str,
    /// SPAN: inclusive start, wall ns since epoch. DAILY: absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    start_wall_ns: Option<u64>,
    /// SPAN: exclusive end, wall ns since epoch. DAILY: absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    end_wall_ns: Option<u64>,
    /// DAILY: window start, seconds-of-day UTC. SPAN: absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    start_s: Option<u32>,
    /// DAILY: window end, seconds-of-day UTC. SPAN: absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    end_s: Option<u32>,
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
    /// The number of seconds the series spans: RATE_RING_SLOTS
    /// one-second windows (NIGHT-hunt-30 — was the per-slot width,
    /// which read as the whole window). `sum(bytes) / window_secs`
    /// is the row's average rate over the horizon; the per-slot
    /// granularity is `bytes.len()`, one sample per second.
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

// night-during (schema v23): the window field's pins, one family
// over (the LOC-cap split the ecn_socket_tests precedent set).
#[cfg(test)]
#[path = "../../test/ebpf/display_json_window_tests.rs"]
mod display_json_window_tests;
