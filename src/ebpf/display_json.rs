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
use crate::ebpf::limiter::rate_ring::{RATE_RING_SLOTS, RateRingRaw, RingReads, ring_series};
use crate::ebpf::limiter::types::PolicyWindowRaw;
use crate::ebpf::limiter::{LimiterStatsRaw, PolicyRaw, monotonic_ns, wall_now_ns};
// wall_minus_mono/window_state: the window join's own vocabulary.
use crate::ebpf::limiter::{wall_minus_mono, window_state};

/// Print JSON status (for --print-json / scripting).
///
/// NIGHT-boost-3: the write rides the unified
/// [`crate::output::print_json`] primitive — one compact line. S1:
/// the document is composed by the hand-written lane below (the
/// serde derive stack left the graph; `to_json` is reviewable code
/// whose bytes the pins hold exactly). The document shape (field
/// names, order, the skip semantics) is unchanged; scripts are
/// unaffected.
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
    crate::output::print_json(&status.to_json());
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
    // NIGHT-improve-65: one snapshot, one instant — the watchdog
    // verdict, the window states, and the ring live-stamps all judge
    // against the caller-passed mono_now_ns, never a fresh clock
    // read. The builder was documented pure (hunt-22's
    // unit-pinnable without capturing stdout) but silently read the
    // monotonic clock TWICE more inside (the watchdog comparison
    // and the ring series' now), so a deadline or ring boundary
    // straddled by those reads could emit a document whose parts
    // disagree about "now" (watchdog expired while a window from
    // the earlier snapshot still reads active). Purity restored,
    // coherence with it.
    let watchdog = match watchdog_deadline {
        Some(0) | None => "enforcing",
        Some(d) if d > mono_now_ns => "active",
        Some(_) => "expired",
    };

    let now = mono_now_ns;
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
                download_bytes_per_sec: d.dl_bps,
                upload_bytes_per_sec: d.ul_bps,
                download_per_socket: d.dl_per_socket,
                upload_per_socket: d.ul_per_socket,
                floor_bytes_per_sec: equal_pair.map(|(floor, _)| floor).filter(|v| *v != 0),
                ceil_bytes_per_sec: equal_pair.map(|(_, ceil)| ceil).filter(|v| *v != 0),
                download_floor_bytes_per_sec: split
                    .map(|(download, _)| download.floor_bps)
                    .filter(|v| *v != 0),
                download_ceil_bytes_per_sec: split
                    .map(|(download, _)| download.ceil_bps)
                    .filter(|v| *v != 0),
                upload_floor_bytes_per_sec: split
                    .map(|(_, upload)| upload.floor_bps)
                    .filter(|v| *v != 0),
                upload_ceil_bytes_per_sec: split
                    .map(|(_, upload)| upload.ceil_bps)
                    .filter(|v| *v != 0),
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
        live_samples: series.live_samples,
        peak_bytes: series.peak_bytes,
    })
}

/// The status document's writer law (S1, the hand-written lane): the
/// shapes below are plain data — the derives are gone, and each
/// `write_json` reproduces the exact wire contract the serde derive
/// emitted (field order = declaration order; `skip_serializing_if =
/// "Not::not"` becomes the false branch, `Option::is_none` the None
/// branch; plain Options ride JSON null). Field names are the pinned
/// scripting contract (docs/USAGE.md JSON reference).
impl StatusJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_array, write_number, write_string};

        out.push_str("{\"watchdog\":");
        write_string(out, self.watchdog);
        out.push_str(",\"active_limits\":");
        write_number(out, self.active_limits);
        out.push_str(",\"limits\":");
        write_array(out, self.limits.len(), |out, i| {
            self.limits[i].write_json(out);
        });
        out.push('}');
    }

    /// The status document as one compact JSON line.
    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        let mut out = String::with_capacity(128 + self.limits.len() * 256);
        self.write_json(&mut out);
        out
    }
}

impl LimitEntry {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_opt_number, write_string};

        out.push_str("{\"cgroup_id\":");
        write_number(out, self.cgroup_id);
        out.push_str(",\"label\":");
        write_string(out, &self.label);
        out.push_str(",\"download_bytes_per_sec\":");
        write_opt_number(out, self.download_bytes_per_sec);
        out.push_str(",\"upload_bytes_per_sec\":");
        write_opt_number(out, self.upload_bytes_per_sec);
        // The additive per-socket markers (improve-40): false is
        // ABSENCE — the additive rule the derive's Not::not held.
        if self.download_per_socket {
            out.push_str(",\"download_per_socket\":true");
        }
        if self.upload_per_socket {
            out.push_str(",\"upload_per_socket\":true");
        }
        for (key, value) in [
            ("floor_bytes_per_sec", self.floor_bytes_per_sec),
            ("ceil_bytes_per_sec", self.ceil_bytes_per_sec),
            (
                "download_floor_bytes_per_sec",
                self.download_floor_bytes_per_sec,
            ),
            (
                "download_ceil_bytes_per_sec",
                self.download_ceil_bytes_per_sec,
            ),
            (
                "upload_floor_bytes_per_sec",
                self.upload_floor_bytes_per_sec,
            ),
            ("upload_ceil_bytes_per_sec", self.upload_ceil_bytes_per_sec),
        ] {
            // The improve-40/v24 floors and ceilings: None (unset or
            // the split shape) is absence, never a fabricated zero.
            if let Some(v) = value {
                out.push_str(",\"");
                out.push_str(key);
                out.push_str("\":");
                write_number(out, v);
            }
        }
        out.push_str(",\"packets_allowed\":");
        write_number(out, self.packets_allowed);
        out.push_str(",\"packets_dropped\":");
        write_number(out, self.packets_dropped);
        out.push_str(",\"bytes_allowed\":");
        write_number(out, self.bytes_allowed);
        out.push_str(",\"bytes_dropped\":");
        write_number(out, self.bytes_dropped);
        if let Some(ring) = &self.rate_ring {
            out.push_str(",\"rate_ring\":");
            ring.write_json(out);
        }
        if let Some(window) = &self.window {
            out.push_str(",\"window\":");
            window.write_json(out);
        }
        out.push('}');
    }
}

impl WindowJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_string};

        out.push_str("{\"kind\":");
        write_string(out, self.kind);
        out.push_str(",\"state\":");
        write_string(out, self.state);
        // SPAN rides the wall instants, DAILY the seconds-of-day —
        // the other pair is honestly absent (the derive's
        // Option::is_none branches).
        if let Some(start) = self.start_wall_ns {
            out.push_str(",\"start_wall_ns\":");
            write_number(out, start);
        }
        if let Some(end) = self.end_wall_ns {
            out.push_str(",\"end_wall_ns\":");
            write_number(out, end);
        }
        if let Some(start) = self.start_s {
            out.push_str(",\"start_s\":");
            write_number(out, start);
        }
        if let Some(end) = self.end_s {
            out.push_str(",\"end_s\":");
            write_number(out, end);
        }
        out.push('}');
    }
}

impl RateRingDirectionJson {
    fn write_json(&self, out: &mut String) {
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
    fn write_json(&self, out: &mut String) {
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

#[derive(Debug, Clone)]
struct LimitEntry {
    cgroup_id: u32,
    label: String,
    /// The enforced rate per direction, in BYTES per second (the
    /// wire name spells the unit out — a `_bps` reading (bits)
    /// would mislead every consumer by a factor of 8). `null` when
    /// that direction is unlimited (never a fabricated zero).
    download_bytes_per_sec: Option<u64>,
    upload_bytes_per_sec: Option<u64>,
    /// The additive per-socket markers (improve-40): false is
    /// ABSENCE in the document (the writer's branch, the derive's
    /// old Not::not semantics).
    download_per_socket: bool,
    upload_per_socket: bool,
    /// The per-subprocess guaranteed minimum, in BYTES per second
    /// (improve-40, schema v24) — absent when the row carries none
    /// (the zero sentinel) or when the directions' pairs DIFFER
    /// (the split rides the per-direction fields below, never a
    /// fabricated merge). The wire name spells the unit out: a
    /// `_bps` reading (bits) would mislead by a factor of 8.
    floor_bytes_per_sec: Option<u64>,
    /// The per-subprocess maximum, in BYTES per second (improve-40,
    /// schema v24) — absent when unset or when the pairs differ.
    ceil_bytes_per_sec: Option<u64>,
    /// The DOWNLOAD pair's floor, bytes per second (improve-40-b,
    /// the per-direction split) — present only when the directions'
    /// pairs differ, the asymmetric link's own shape.
    download_floor_bytes_per_sec: Option<u64>,
    /// The DOWNLOAD pair's ceiling, bytes per second (improve-40-b)
    /// — split only.
    download_ceil_bytes_per_sec: Option<u64>,
    /// The UPLOAD pair's floor, bytes per second (improve-40-b) —
    /// split only.
    upload_floor_bytes_per_sec: Option<u64>,
    /// The UPLOAD pair's ceiling, bytes per second (improve-40-b) —
    /// split only.
    upload_ceil_bytes_per_sec: Option<u64>,
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
    /// The in-kernel time-series ring's derived window series
    /// (charger-core-3a, EAGLE EYES V1): the last eight one-second
    /// byte totals oldest-first, per direction. Absent when the
    /// pinned object predates the ring or the cgroup booked no
    /// traffic under the policy — the absent-lens contract.
    rate_ring: Option<RateRingJson>,
    /// The row's --during window (night-during, schema v23),
    /// absent when the row carries none — the additive-field rule
    /// the rate_ring join set.
    window: Option<WindowJson>,
}

/// One row's window (see [`LimitEntry::window`]).
#[derive(Debug, Clone)]
struct WindowJson {
    /// "span" or "daily".
    kind: &'static str,
    /// "active", "dormant", "outside", or "expired" (the state
    /// vocabulary the status pins own).
    state: &'static str,
    /// SPAN: inclusive start, wall ns since epoch. DAILY: absent.
    start_wall_ns: Option<u64>,
    /// SPAN: exclusive end, wall ns since epoch. DAILY: absent.
    end_wall_ns: Option<u64>,
    /// DAILY: window start, seconds-of-day UTC. SPAN: absent.
    start_s: Option<u32>,
    /// DAILY: window end, seconds-of-day UTC. SPAN: absent.
    end_s: Option<u32>,
}

/// One direction's window series (see [`LimitEntry::rate_ring`]).
#[derive(Debug, Clone)]
struct RateRingDirectionJson {
    /// The last eight one-second byte totals, OLDEST first; the last
    /// entry is the current (still-filling) window.
    bytes: [u64; RATE_RING_SLOTS],
    /// How many of the eight slots carry a stamp matching the
    /// window they represent (night-verdict-closure-T7 (H4), the
    /// wire name was `live` — renamed because a bare `live` reads
    /// as a rate): a stamped ZERO-byte window counts, so the figure
    /// is the honest horizon, neither a rate nor the count of
    /// non-zero slots (3 means only the last three seconds had
    /// stamped windows).
    live_samples: u32,
    /// The largest COMPLETED window (the current window never
    /// qualifies — it can only grow).
    peak_bytes: u64,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
