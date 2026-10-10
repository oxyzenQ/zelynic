// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The in-kernel time-series ring (NIGHT-upgrade-charger-core-3a,
// Tier B #8 — EAGLE EYES V1): a rolling window of delivered-rate
// samples the kernel itself keeps, one ring per policed cgroup per
// direction, so the SHAPE of a target's traffic survives between
// userspace polls. Userspace rate math today differentiates two
// cumulative counter snapshots — miss a sample and the peak between
// them is averaged away; a monitor polling at --interval 30s sees a
// 30s mean and nothing else. The ring keeps the last eight
// one-second windows in kernel state: the 8s horizon a baseline
// detector (the EAGLE EYES someday) reads directly, and the honest
// peak/shape record `status --print-json` already surfaces.
//
// Same discipline as math.rs/mmspa.rs/drr.rs (the pure-core
// lineage): `core`-only, zero aya dependencies, wired into the
// kernel object (ebpf/src/bin/limiter.rs wires it with #[path]) AND
// into the userspace test tree the same way
// (test/ebpf/limiter/rate_ring_tests.rs), so the window protocol is
// pinned by rootless unit tests. Self-contained on purpose — the
// pure cores never import from each other, because each file must
// compile standalone in BOTH trees; the three access primitives
// below are therefore the math.rs trio re-stated (that file's own
// module doc carries the ISA rationale: plain loads/stores ride
// volatile single instructions, RMW rides core's AtomicU64 which
// lowers to the BPF_ATOMIC ISA). The READ side (series derivation
// for the status surface) deliberately does NOT live here: the
// userspace tree hand-mirrors the layout instead (RateSlotRaw /
// RateRingRaw in src/ebpf/limiter/rate_ring.rs — the PolicyRaw /
// BucketRaw / LimiterStatsRaw mirror discipline, one inclusion of
// each pure core per binary), so this file carries only what the
// datapath itself runs.
//
// The honesty contract (the module's load-bearing distinction): the
// RING is a monitor, the LEDGER is the truth. cgroup_limiter_stats
// keeps the exact cumulative byte/packet counters every verdict
// books through; the ring keeps the windowed SHAPE of the allowed
// stream. A boundary crossing under SMP contention can lose one
// in-flight fetch_add per contending CPU in the nanosecond gap
// between the stamp CAS and the winner's byte swap — bounded by
// (CPUs x 1 packet) per one-second boundary, undercount-only (the
// protocol can never invent bytes), and documented here rather than
// fixed with a seqlock because the ring feeds baseline detection,
// not billing. The ledger never lies; the ring never invents.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ── The access primitives (the math.rs trio, re-stated) ───────────
// The pure cores are self-contained by discipline; these three are
// the minimal set the window protocol needs. See math.rs's block
// comment for the full single-instruction/AtomicU64 rationale —
// duplicated here, not shared, because a `use super::math` would
// break the userspace test-tree wiring (each #[path] inclusion is
// compiled standalone).

/// READ_ONCE for one slot field (see the block comment above).
#[inline(always)]
fn read_once(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // field of a map value (or a test-tree struct).
    unsafe { p.read_volatile() }
}

/// The atomic RMW view of one u64 field: fetch_add / compare_exchange
/// / swap only (see the block comment above). Loads/stores go
/// through read_once and plain struct field access.
#[inline(always)]
fn rmw_view<'a>(p: *mut u64) -> &'a AtomicU64 {
    // SAFETY: same 8-aligned-field contract as read_once.
    unsafe { AtomicU64::from_ptr(p) }
}

// ── The layout (shared contract with the userspace mirror:
// RateSlotRaw / RateRingRaw in src/ebpf/limiter/rate_ring.rs) ──────

/// One window slot: the window index (monotonic seconds since boot,
/// the same clock bpf_ktime_get_ns rides) and the bytes delivered in
/// it. A stamp of 0 is the fresh-map state — window 0 only exists
/// during the first second of uptime, so a zeroed slot reads as
/// "never written" for every real host.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RateSlot {
    pub window: u64,
    pub bytes: u64,
}

/// The ring: eight one-second slots, a fixed 128-byte value. The
/// slot for window `w` is `slots[(w % 8)]`, so the ring always holds
/// the newest window plus the seven before it — the 8s horizon.
/// Bounded by the policy census (one entry per policed cgroup, the
/// cgroup_limiter_stats posture), not by traffic.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RateRing {
    pub slots: [RateSlot; RING_SLOTS as usize],
}

const _: () = assert!(core::mem::size_of::<RateSlot>() == 16);
const _: () = assert!(core::mem::size_of::<RateRing>() == 128);

/// How many one-second windows the ring keeps. Mirrored in userspace
/// as `RATE_RING_SLOTS` (src/ebpf/limiter/rate_ring.rs — the layout
/// contract sibling; both sides pin the value in tests).
pub const RING_SLOTS: u64 = 8;

/// The window width in nanoseconds — one second, the unit the JSON
/// surface documents (`window_secs: 1`) and the smallest window a
/// baseline detector can trust under GSO bursts. Mirrored in
/// userspace as `RATE_RING_WINDOW_NS`.
pub const RING_WINDOW_NS: u64 = 1_000_000_000;

// ── The window protocol ────────────────────────────────────────────

/// Book `len` delivered bytes into the ring at time `now` (the same
/// monotonic nanoseconds the enforcement path already sampled for
/// its own refill math — no extra bpf_ktime_get_ns).
///
/// The protocol, per packet:
///  1. `w = now / 1s` — the current window index.
///  2. The slot's stamp already equals `w` — the common case: one
///     atomic fetch_add on the byte counter. Done.
///  3. The stamp is older (a boundary was crossed since the slot
///     last served, or the slot is fresh): CAS the stamp old -> w.
///     The WINNER pays one atomic swap to set bytes = len (a single
///     xchg, not a zero-then-add pair — the winner's own bytes can
///     never be half-written, and a concurrent fetch_adder either
///     lands after the swap and counts, or in the nanosecond gap
///     before it and joins the documented bound). A LOSER rides the
///     fetch_add onto the new window — the same gap, same bound,
///     undercount-only.
///  4. A stamp NEWER than `w` (a future window) is poison or drift:
///     the slot is skipped, never booked and never repaired from the
///     datapath — the v6 hostile-stamp family's answer (a monitor
///     must not be poisonable into reporting traffic that never
///     happened; the reader renders the mismatched slot as no data,
///     and the slot self-heals at its next real boundary crossing).
#[inline(always)]
pub fn ring_book(ring: &mut RateRing, now: u64, len: u32) {
    let w = now / RING_WINDOW_NS;
    // The modulo of a u64 by 8 is a mask the compiler folds; the
    // index arithmetic stays branch-free for the verifier.
    let slot = &mut ring.slots[(w % RING_SLOTS) as usize];
    let stamp_ptr = core::ptr::addr_of_mut!(slot.window);
    let bytes_ptr = core::ptr::addr_of_mut!(slot.bytes);

    let stamped = read_once(stamp_ptr);
    if stamped == w {
        rmw_view(bytes_ptr).fetch_add(u64::from(len), Ordering::AcqRel);
        return;
    }
    // A future stamp is poison or drift: skip (the honest-monitor
    // rule — see the protocol note 4 above).
    if stamped > w {
        return;
    }
    if rmw_view(stamp_ptr)
        .compare_exchange(stamped, w, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // The boundary winner: set this window's counter to exactly
        // this packet's bytes in ONE atomic exchange — no zero/store
        // pair for a concurrent fetch_adder to straddle.
        let _ = rmw_view(bytes_ptr).swap(u64::from(len), Ordering::AcqRel);
    } else {
        // The boundary loser: the winner's swap is in flight; this
        // packet's bytes ride the fetch_add onto the new window —
        // the in-flight gap's documented undercount is the only cost.
        rmw_view(bytes_ptr).fetch_add(u64::from(len), Ordering::AcqRel);
    }
}
