// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The observer's pure stats core (NIGHT-improve-29, the NIGHT-
// depthbore-1 precedent — the same file the BPF object builds,
// pinned rootlessly by test/ebpf/stats_smp_tests.rs): the
// per-cgroup stats layout and its ATOMIC booking primitives, pure
// `core`, zero aya dependencies, so the SMP invariants are
// unit-pinnable on the host build instead of root-run integration
// alone.
//
// Why atomics here at all (the owner-approved hunt into the
// observer's map stats): the observer update path used the exact
// lost-update shape NIGHT-boost-38 closed in the limiter —
// `get_ptr_mut` hands every CPU a pointer to the SAME unlocked map
// value, and the old `s.packets += 1; s.bytes += pkt_len` was a
// plain load-add-store on that shared memory. Two CPUs processing
// packets of one cgroup (any multi-flow download, any multi-queue
// NIC) each loaded the same counter, each stored their own +1, and
// one increment vanished — the eagle-eyes rates and totals read
// LOW under exactly the traffic the monitor exists to measure. The
// per-socket cookie maps carried the same race on their single u64.
// The fix rides the same ISA the v7 token bucket already requires
// (64-bit BPF_ATOMIC fetch-add, Linux 5.12+, under the verified
// 5.13 product floor — see docs/KERNEL_COMPATIBILITY.md), and the
// same access discipline as ebpf/src/math.rs: the BPF ISA has RMW
// atomics but NO atomic load/store, so RMW rides core's AtomicU64
// and the observer now performs no plain shared-field access on
// its update path at all.

use core::sync::atomic::{AtomicU64, Ordering};

/// The BPF-side stats layout; the userspace mirror is
/// `CgroupStatsRaw` in src/ebpf/loader.rs (layout contract). The
/// pre-boost-34 shape carried a third leg, `last_event_packet`, the
/// 1-in-100 event throttle's bookmark — both the throttle and its
/// leg are gone with the events ringbuf, and the value is now
/// exactly the two counters userspace reads.
///
/// The u32 cgroup-id map key (in the observer's maps, main.rs) is
/// the C twin's contract, kept deliberately: kernfs id allocation
/// starts small and a real host cannot live through the ~4 billion
/// cgroup lifetimes a 2^32 wrap-around would take, so a u64 key
/// would widen every map and the userspace mirror for a collision
/// no deployed kernel can produce.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupStats {
    pub packets: u64,
    pub bytes: u64,
}

const _: () = assert!(core::mem::size_of::<CgroupStats>() == 16);

// The atomic views' alignment contract: both fields 8-aligned at
// offsets 0 and 8 (the size pin above + repr(C)) — what makes the
// single-instruction BPF_ATOMIC RMW legal on them.
const _: () = assert!(core::mem::offset_of!(CgroupStats, packets) == 0);
const _: () = assert!(core::mem::offset_of!(CgroupStats, bytes) == 8);

/// The atomic RMW view of one u64 map-value field — the math.rs
/// idiom (NIGHT-boost-38 lineage, see ebpf/src/math.rs's
/// access-primitives block): fetch_add / compare_exchange only;
/// loads and stores of shared fields would need the volatile
/// READ_ONCE / WRITE_ONCE discipline, and the observer performs
/// none after the NIGHT-improve-29 fix (every shared-field update
/// is an RMW; the only reads happen in userspace through aya's map
/// iterators, a different address space entirely).
#[inline(always)]
pub fn rmw_view<'a>(p: *mut u64) -> &'a AtomicU64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // field of a map value (the map's own lookup) — the same
    // contract math.rs's twin helper documents.
    unsafe { AtomicU64::from_ptr(p) }
}

/// Atomically book one packet into an existing per-cgroup stats
/// entry (NIGHT-improve-29): packets +1, bytes +pkt_len, both as
/// Relaxed fetch_adds. Relaxed is the right ordering — the two
/// counters are independent (no cross-field invariant), userspace
/// reads them through map iteration (tear-free on aligned u64s by
/// the ISA, never mid-RMW), and the kernel's own per-CPU stat
/// bumps use the same relaxation. Two independent adds mean a
/// reader can observe packets incremented before bytes for the
/// same packet — the pre-existing display semantics of two
/// separate counters, not a regression.
///
/// Overflow: fetch_add wraps where the old plain `+=` saturated on
/// the socket map / wrapped on the cgroup map (release profile).
/// The wrap horizon — u64::MAX bytes through one cgroup or one
/// socket in one session-scoped map — is ~18.4 EB, years of
/// line-rate traffic through a single session; unreachable, and
/// strictly safer than the old plain `+=` (which under
/// overflow-checks would panic into the no_std `loop {}` handler —
/// a hung CPU — instead of wrapping).
#[inline(always)]
pub fn book_packet(ptr: *mut CgroupStats, pkt_len: u64) {
    // Field pointers: 8-aligned repr(C) offsets 0 and 8 (the offset
    // pins above).
    // SAFETY: ptr is a live, 8-aligned CgroupStats from the map's
    // own lookup (the caller's contract); addr_of_mut is a pure
    // place projection — no read, no write of the pointee.
    let (packets, bytes) = unsafe {
        (
            core::ptr::addr_of_mut!((*ptr).packets),
            core::ptr::addr_of_mut!((*ptr).bytes),
        )
    };
    rmw_view(packets).fetch_add(1, Ordering::Relaxed);
    rmw_view(bytes).fetch_add(pkt_len, Ordering::Relaxed);
}

/// Atomically book `pkt_len` bytes into one existing per-socket
/// cookie accumulator (NIGHT-improve-29) — the single-u64 sibling
/// of [`book_packet`], same Relaxed/fetch_add/overflow contract.
#[inline(always)]
pub fn bump_socket_bytes(ptr: *mut u64, pkt_len: u64) {
    rmw_view(ptr).fetch_add(pkt_len, Ordering::Relaxed);
}
