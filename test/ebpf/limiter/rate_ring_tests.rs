// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! charger-core-3a: rootless pins for the in-kernel time-series
//! ring — the window WRITE protocol (ebpf/src/rate_ring.rs, the same
//! file the BPF object builds, wired below with #[path]) and the
//! userspace READ derivation (src/ebpf/limiter/rate_ring.rs, the
//! module that wires THIS file). Every pin maps to a documented
//! contract in those modules:
//!
//!  * same-window accumulation — the common case is one fetch_add;
//!  * boundary crossing — the stamp CAS + byte swap pair starts a
//!    fresh window at exactly this packet's bytes;
//!  * slot cycling — eight one-second windows reuse the same slot;
//!  * the hostile future stamp — skipped, never booked, never
//!    repaired from the datapath;
//!  * the fresh-map zero stamp — the first book stamps and swaps;
//!  * the derivation's horizon — oldest-first series, stale slots
//!    read zero, the pre-boot horizon never double-counts window 0,
//!    and the peak counts only completed windows.

// The production WRITE protocol, compiled into this test module: the
// SAME file the BPF object builds. Only the test tree reaches across
// trees (the gate-tree discipline, the math_tests precedent).
#[path = "../../../ebpf/src/rate_ring.rs"]
mod ebpf_rate_ring;

use self::ebpf_rate_ring::{RING_SLOTS, RING_WINDOW_NS, RateRing, ring_book};
use crate::ebpf::limiter::rate_ring::{
    RATE_RING_SLOTS, RATE_RING_WINDOW_NS, RateRingRaw, RateSlotRaw, ring_series,
};

const SEC: u64 = RING_WINDOW_NS;

fn raw_from(ring: &RateRing) -> RateRingRaw {
    // The mirror bridge for derivation pins: same layout (the size
    // pins on both structs guard the drift), so a byte-wise copy is
    // the honest translation the aya reader performs on real reads.
    let mut out = RateRingRaw::default();
    for i in 0..RATE_RING_SLOTS {
        out.slots[i] = RateSlotRaw {
            window: ring.slots[i].window,
            bytes: ring.slots[i].bytes,
        };
    }
    out
}

#[test]
fn same_window_accumulates_one_fetch_add_shape() {
    let mut ring = RateRing::default();
    let t = 10 * SEC + 500_000_000; // mid window 10
    ring_book(&mut ring, t, 100);
    ring_book(&mut ring, t + 1_000_000, 50);
    ring_book(&mut ring, t + 2_000_000, 25);
    let slot = &ring.slots[(10 % RING_SLOTS) as usize];
    assert_eq!(slot.window, 10);
    assert_eq!(slot.bytes, 175);
}

#[test]
fn boundary_crossing_stamps_and_swaps_fresh() {
    let mut ring = RateRing::default();
    // Window 10 lands in slot (10 % 8) and holds old bytes.
    ring_book(&mut ring, 10 * SEC + 100, 400);
    // Eight seconds later the SAME slot serves window 18: the
    // boundary winner's swap REPLACES the old window's counter with
    // exactly this packet's bytes — never the old window's bytes
    // plus this one (a zero-then-add pair could straddle a race).
    ring_book(&mut ring, 18 * SEC + 100, 30);
    let slot = &ring.slots[(10 % RING_SLOTS) as usize];
    assert_eq!((slot.window, slot.bytes), (18, 30));
}

#[test]
fn slots_cycle_after_eight_windows() {
    let mut ring = RateRing::default();
    // Book one packet in each of windows 100..108: window 108 reuses
    // slot (100 % 8) — the oldest window falls off the horizon and
    // the slot's stamp/bytes belong to the newest one.
    for w in 100..108u64 {
        ring_book(&mut ring, w * SEC + 1, ((w % 7) * 10) as u32);
    }
    let recycled = &ring.slots[(100 % RING_SLOTS) as usize];
    assert_eq!(recycled.window, 100, "window 100 still held before recycle");
    assert_eq!(recycled.bytes, ((100 % 7) * 10) as u64);
    ring_book(&mut ring, 108 * SEC + 1, 999);
    let recycled = &ring.slots[(108 % RING_SLOTS) as usize];
    assert_eq!((recycled.window, recycled.bytes), (108, 999));
}

#[test]
fn hostile_future_stamp_is_skipped_never_booked() {
    let mut ring = RateRing::default();
    // Poison: a slot stamped in the future, holding a huge count.
    ring.slots[(50 % RING_SLOTS) as usize] = self::ebpf_rate_ring::RateSlot {
        window: u64::MAX,
        bytes: u64::MAX,
    };
    ring_book(&mut ring, 50 * SEC + 1, 500);
    let slot = &ring.slots[(50 % RING_SLOTS) as usize];
    assert_eq!(slot.window, u64::MAX, "poison stamp is never repaired");
    assert_eq!(slot.bytes, u64::MAX, "poison bytes are never touched");
}

#[test]
fn fresh_zero_stamp_books_window_zero_only() {
    let mut ring = RateRing::default();
    // A zeroed slot: the CAS 0 -> w wins and the swap seeds the bytes.
    ring_book(&mut ring, 77 * SEC + 1, 42);
    let slot = &ring.slots[(77 % RING_SLOTS) as usize];
    assert_eq!((slot.window, slot.bytes), (77, 42));
    // But window 0 itself (the first second of uptime) IS bookable
    // against a fresh slot: stamp 0 equals the current window.
    let mut boot = RateRing::default();
    ring_book(&mut boot, 999_999_999, 7);
    let slot = &boot.slots[0];
    assert_eq!((slot.window, slot.bytes), (0, 7));
}

// ── The READ-side derivation pins (the userspace half) ─────────────

fn slot(window: u64, bytes: u64) -> RateSlotRaw {
    RateSlotRaw { window, bytes }
}

#[test]
fn derivation_walks_oldest_first_and_counts_live() {
    let mut raw = RateRingRaw::default();
    // Windows 20..23 live (stamped), the horizon at now=window 23
    // covers 16..23: the four live windows land newest-last, the
    // stale older slots read zero, never fabricated.
    raw.slots[(20 % 8) as usize] = slot(20, 200);
    raw.slots[(21 % 8) as usize] = slot(21, 210);
    raw.slots[(22 % 8) as usize] = slot(22, 220);
    raw.slots[(23 % 8) as usize] = slot(23, 230);
    let s = ring_series(&raw, 23 * SEC + 500_000_000);
    assert_eq!(s.bytes, [0, 0, 0, 0, 200, 210, 220, 230]);
    assert_eq!(s.live, 4);
    // The peak counts only COMPLETED windows: 230 is the current
    // (still-filling) window and never qualifies.
    assert_eq!(s.peak_bytes, 220);
}

#[test]
fn derivation_pre_boot_horizon_never_double_counts_window_zero() {
    // Early boot: now is window 3, the horizon 0..7 reaches before
    // boot. Windows 0..3 exist; checked_sub (not a saturating clamp)
    // must leave the pre-boot out-slots at zero instead of mapping
    // several of them onto window 0.
    let mut raw = RateRingRaw::default();
    raw.slots[0] = slot(0, 100);
    raw.slots[1] = slot(1, 110);
    raw.slots[2] = slot(2, 120);
    raw.slots[3] = slot(3, 130);
    let s = ring_series(&raw, 3 * SEC + 100);
    assert_eq!(s.bytes, [0, 0, 0, 0, 100, 110, 120, 130]);
    assert_eq!(s.live, 4);
    assert_eq!(s.peak_bytes, 120);
}

#[test]
fn derivation_drops_stale_and_future_stamps() {
    // A stale stamp (older than its horizon window) and a future
    // stamp both render zero — the reader can never be poisoned into
    // reporting traffic, and an idle horizon reads honestly empty.
    let mut raw = RateRingRaw::default();
    raw.slots[(30 % 8) as usize] = slot(5, 500); // stale: window 5 in slot (30%8)
    raw.slots[(31 % 8) as usize] = slot(99, 999); // future poison in slot (31%8)
    raw.slots[(32 % 8) as usize] = slot(32, 320); // live
    let s = ring_series(&raw, 32 * SEC + 1);
    assert_eq!(s.live, 1);
    // The live window is the CURRENT one: out index 7 (newest),
    // which lands on slot (32 % 8) — a different index than the
    // out-slot, the exact confusion this pin exists to catch.
    assert_eq!(s.bytes[7], 320);
    assert_eq!(s.peak_bytes, 0, "the only live window is the current one");
    let stale_read = s.bytes.iter().sum::<u64>();
    assert_eq!(stale_read, 320, "stale and poison contribute zero");
}

#[test]
fn mirror_constants_match_the_shared_core() {
    // The JSON contract's frozen surface: eight windows, one second
    // each, 128-byte value. If the shared core ever changes these,
    // the userspace mirror AND the JSON docs must move together —
    // this pin is the tripwire.
    assert_eq!(RATE_RING_SLOTS as u64, RING_SLOTS);
    assert_eq!(RATE_RING_WINDOW_NS, RING_WINDOW_NS);
    assert_eq!(RATE_RING_SLOTS, 8);
    assert_eq!(RATE_RING_WINDOW_NS, 1_000_000_000);
    assert_eq!(core::mem::size_of::<RateRingRaw>(), 128);
    assert_eq!(core::mem::size_of::<RateSlotRaw>(), 16);
    assert_eq!(core::mem::size_of::<RateRing>(), 128);
}

#[test]
fn write_protocol_and_derivation_agree_end_to_end() {
    // The two halves of the feature, composed: book a few windows
    // through the WRITE protocol, derive through the READ side, and
    // assert the series a baseline detector would consume.
    let mut ring = RateRing::default();
    for w in 40..43u64 {
        for _ in 0..(w - 39) {
            ring_book(&mut ring, w * SEC + 500_000_000, 100);
        }
    }
    let s = ring_series(&raw_from(&ring), 43 * SEC + 1);
    // Window 40: 1 packet (100B), 41: 2 (200B), 42: 3 (300B), and
    // window 43 is current with no book yet: the horizon 36..43
    // puts 40/41/42 at out indices 4/5/6 and 0 at the newest slot.
    assert_eq!(s.bytes, [0, 0, 0, 0, 100, 200, 300, 0]);
    assert_eq!(s.live, 3);
    assert_eq!(s.peak_bytes, 300, "the completed peak is window 42");
}
