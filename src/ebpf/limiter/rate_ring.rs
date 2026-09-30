// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The time-series ring's userspace half (NIGHT-upgrade-charger-
//! core-3a, Tier B #8 — EAGLE EYES V1): the hand-mirrored layout
//! (the PolicyRaw/BucketRaw/LimiterStatsRaw discipline — the pure
//! core ebpf/src/rate_ring.rs is compiled into the BPF object and
//! the TEST tree, one inclusion per binary, so this tree mirrors it
//! instead), the pinned-map reader, and the series derivation the
//! status JSON surface carries. The WRITE protocol lives in the
//! shared core; this module only READS.

use aya::maps::{HashMap as BpfHashMap, Map};

use super::types::Direction;
use super::Limiter;
use crate::ebpf::pin::{self, PIN_MAP_RATE_RING_DL, PIN_MAP_RATE_RING_UL};

/// How many one-second windows the ring keeps (the shared core's
/// `RING_SLOTS` — mirrored, and pinned against the JSON contract in
/// the tests below: the series length is the documented surface).
pub const RATE_RING_SLOTS: usize = 8;

/// The window width in nanoseconds (the shared core's
/// `RING_WINDOW_NS` mirror).
pub const RATE_RING_WINDOW_NS: u64 = 1_000_000_000;

// ── The layout mirror (must match ebpf/src/rate_ring.rs — the size
// pins below guard drift the same way the BPF side's own pins do) ──

/// One window slot: the window index and the bytes delivered in it.
/// See the BPF twin's doc for the stamp semantics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct RateSlotRaw {
    pub window: u64,
    pub bytes: u64,
}

/// The ring: eight one-second slots, a fixed 128-byte value keyed by
/// the policy-root cgroup id.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct RateRingRaw {
    pub slots: [RateSlotRaw; RATE_RING_SLOTS],
}

unsafe impl aya::Pod for RateSlotRaw {}
unsafe impl aya::Pod for RateRingRaw {}

/// Both directions' ring censuses, the shape the status surface
/// consumes. `None` per direction is the ABSENT-LENS verdict (see
/// [`Limiter::read_rate_rings`]) — a field that is absent renders
/// as honestly absent, never as a fabricated empty series.
#[derive(Debug, Clone, Default)]
pub struct RingReads {
    pub dl: Option<Vec<(u32, RateRingRaw)>>,
    pub ul: Option<Vec<(u32, RateRingRaw)>>,
}

impl RingReads {
    /// The no-lens state: both directions unreadable/absent. The
    /// shape a pre-v14 pinned object or a torn-down pin dir yields,
    /// and the shape the display tests use to pin the
    /// field-omission contract. (Test-facing constructor, the
    /// BucketRaw precedent: production reaches the same shape through
    /// the reader, never through this spelling.)
    #[allow(dead_code)]
    pub fn absent() -> Self {
        RingReads { dl: None, ul: None }
    }
}

// ── The derivation (pure, unit-pinnable) ───────────────────────────

/// The windowed series one limit's ring contributes to the status
/// JSON: the last [`RATE_RING_SLOTS`] one-second byte totals, OLDEST
/// first (index 0 = the oldest window in the horizon, last = the
/// CURRENT window — partial by definition, a window mid-second reads
/// low), how many windows hold live stamps, and the peak completed
/// window (the honest ceiling a baseline detector compares against;
/// the live current window never qualifies — it can only grow).
///
/// A slot whose stamp does not match the window it would represent is
/// stale (the host idled past the horizon) or poison (a future stamp)
/// and contributes ZERO — never a fabricated sample. Windows before
/// boot (the horizon reaches past window 0 in the first seven
/// seconds of uptime) are absent the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingSeries {
    pub bytes: [u64; RATE_RING_SLOTS],
    pub live: u32,
    pub peak_bytes: u64,
}

/// Derive the series for one ring at `now` (the same monotonic
/// nanoseconds the watchdog comparison rides — CLOCK_MONOTONIC, the
/// clock bpf_ktime_get_ns reads).
pub fn ring_series(ring: &RateRingRaw, now: u64) -> RingSeries {
    let w = now / RATE_RING_WINDOW_NS;
    let mut out = RingSeries {
        bytes: [0; RATE_RING_SLOTS],
        live: 0,
        peak_bytes: 0,
    };
    for i in 0..RATE_RING_SLOTS {
        // The window this out-slot describes, oldest first: index 0
        // is w-7, the last is w. Windows before boot do not exist —
        // checked_sub, never a saturating clamp (a clamp would map
        // several out-slots onto window 0 and double-count its
        // bytes).
        let offset = (RATE_RING_SLOTS - 1 - i) as u64;
        let win = match w.checked_sub(offset) {
            Some(v) => v,
            None => continue,
        };
        let slot = &ring.slots[(win % RATE_RING_SLOTS as u64) as usize];
        if slot.window == win {
            out.bytes[i] = slot.bytes;
            out.live += 1;
            // The peak counts only COMPLETED windows: the current
            // window (last index) is still filling.
            if i + 1 < RATE_RING_SLOTS {
                out.peak_bytes = out.peak_bytes.max(slot.bytes);
            }
        }
    }
    out
}

// ── The reader ─────────────────────────────────────────────────────

impl Limiter {
    /// Read both directions' rings for the status surface. The
    /// ABSENT-LENS contract (deliberately not the hunt-22
    /// propagation rule): policies and stats are the enforcement
    /// TRUTH — fabricating their emptiness would lie about enforced
    /// state — but the ring is a new lens onto traffic the older
    /// object never kept. A pin dir whose rings cannot be opened
    /// (a pre-v14 pinned object, a torn-down map) renders NO ring
    /// data (`None` per direction) instead of failing status: the
    /// ledger rows beside it stay exactly as true as they ever
    /// were, and the JSON omits the `rate_ring` field (serde's
    /// skip_serializing_if) — a field that is absent is honestly
    /// absent, a fabricated empty series would not be.
    pub fn read_rate_rings(&self) -> RingReads {
        RingReads {
            dl: self.read_rate_ring_dir(Direction::Download),
            ul: self.read_rate_ring_dir(Direction::Upload),
        }
    }

    /// One direction's ring census: every (policy-root cgroup id,
    /// ring) the pinned map holds, or None under the absent-lens
    /// contract above.
    fn read_rate_ring_dir(&self, direction: Direction) -> Option<Vec<(u32, RateRingRaw)>> {
        let map_name = format!("rate_ring_{}", direction.suffix());
        let pin_path = match direction {
            Direction::Download => PIN_MAP_RATE_RING_DL,
            Direction::Upload => PIN_MAP_RATE_RING_UL,
        };
        let pinned;
        let map_ref: &Map = match self.bpf.as_ref() {
            Some(bpf) => bpf.map(&map_name)?,
            None => {
                pinned = pin::open_pinned_hash_map(pin_path).ok()?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, RateRingRaw> = BpfHashMap::try_from(map_ref).ok()?;
        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Some(results)
    }
}

// The rootless pins: the pure WRITE protocol (the shared core) plus
// this module's derivation. Wired here, not in mod.rs, so the
// 500-LOC owner cap on that file stays untouched — the docker_tests
// sibling-split lineage (test/ebpf/identity/docker_tests.rs under
// docker.rs) applied one feature over.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/rate_ring_tests.rs"]
mod rate_ring_tests;
