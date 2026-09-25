// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-improve-29: SMP invariant pins for the observer's atomic
//! stats core (ebpf/src/stats.rs — the same file the BPF object
//! builds, the NIGHT-depthbore-1 math.rs discipline). The
//! pre-improve-29 observer used the exact lost-update shape
//! NIGHT-boost-38 closed in the limiter: `get_ptr_mut` hands every
//! CPU a pointer to the SAME unlocked map value, and the old plain
//! `+=` / load-store pairs lost increments whenever two CPUs
//! carried the same cgroup's or socket's traffic — the eagle-eyes
//! rates and totals read LOW under exactly the concurrent traffic
//! the monitor exists to measure.
//!
//! These pins hold the fix's invariants under real thread
//! contention — the properties that make the lost update
//! impossible:
//!
//!  * booking conservation — N threads booking M packets each into
//!    ONE shared CgroupStats produce exactly N*M packets and
//!    exactly N*M*len bytes, to the unit; a lost increment (the
//!    bug's shape) breaks this;
//!  * socket-accumulator conservation — the single-u64 sibling,
//!    same exactness;
//!  * single-thread equivalence — on an owned struct the booking
//!    is arithmetically identical to two plain adds (the layout is
//!    unchanged, only the access became atomic);
//!  * layout pins — size 16, fields at offsets 0 and 8 (what makes
//!    the single-instruction BPF_ATOMIC RMW legal on them), the
//!    same pins stats.rs carries at compile time, asserted from
//!    the userspace tree that mirrors the layout (CgroupStatsRaw).
//!
//! The concurrency model matches production: the BPF program runs
//! on many CPUs against ONE map value, and aya hands each CPU its
//! own pointer to that same value (get_ptr_mut). The sharing
//! harness below reproduces exactly that reality through raw
//! pointers; every booking access is an atomic RMW through the
//! pointer, never a reference read/write (the math_smp_tests
//! SharedHandle discipline).

// The production stats core, compiled into this test module: the
// SAME file the BPF object builds (ebpf/src/main.rs wires it with
// its own `mod stats;`). Only the test tree reaches across trees —
// src/ wirings stay under test/ (the gate-tree discipline, the
// math_tests precedent).
#[path = "../../ebpf/src/stats.rs"]
pub(super) mod ebpf_stats;

use self::ebpf_stats::{book_packet, bump_socket_bytes, CgroupStats};
use std::thread::scope;

/// The shared-map-value reality, boxed and handed to threads as raw
/// pointers — the exact shape aya's `get_ptr_mut` creates on every
/// multi-CPU host (many CPUs, one unlocked map value).
struct Shared {
    stats: Box<CgroupStats>,
    acc: Box<u64>,
}

/// One thread's view of the shared values (math_smp_tests'
/// SharedHandle discipline).
#[derive(Clone, Copy)]
struct SharedHandle {
    stats: *mut CgroupStats,
    acc: *mut u64,
}

// SAFETY: the handle crosses threads only to reproduce the BPF
// runtime's many-CPUs-one-map-value reality; the booking primitives
// touch the shared memory solely through atomic RMWs (see the
// module docs and ebpf/src/stats.rs), never reference reads or
// writes — the pattern the production program's get_ptr_mut
// established.
unsafe impl Send for SharedHandle {}

fn handle_of(shared: &mut Shared) -> SharedHandle {
    SharedHandle {
        stats: std::ptr::addr_of_mut!(*shared.stats),
        acc: std::ptr::addr_of_mut!(*shared.acc),
    }
}

impl SharedHandle {
    /// Book one packet (the observer's per-cgroup update). Safe by
    /// stats.rs's contract: the atomics own the shared-memory
    /// discipline (the Send impl's disclosure covers the sharing
    //  itself).
    fn book(&self, pkt_len: u64) {
        book_packet(self.stats, pkt_len);
    }

    /// Book one socket accumulator bump (the observer's per-socket
    /// update). Same safety shape as [`Self::book`].
    fn bump(&self, pkt_len: u64) {
        bump_socket_bytes(self.acc, pkt_len);
    }
}

/// The layout contract from the userspace side: the mirror
/// (CgroupStatsRaw in src/ebpf/loader.rs) and the BPF-side
/// CgroupStats must agree in size — the aya map iteration reads
/// the BPF struct's bytes as the userspace struct.
#[test]
fn stats_layout_pins_size_and_offsets() {
    assert_eq!(
        core::mem::size_of::<CgroupStats>(),
        16,
        "the two-u64 stats layout is 16 bytes (loader.rs's CgroupStatsRaw mirror)"
    );
    assert_eq!(core::mem::offset_of!(CgroupStats, packets), 0);
    assert_eq!(core::mem::offset_of!(CgroupStats, bytes), 8);
}

/// Single-thread equivalence: on an owned struct the atomic booking
/// is arithmetically the two plain adds — the layout and the
/// semantics are unchanged, only the access discipline became
/// atomic (the pre-improve-29 behavior for one CPU, preserved).
#[test]
fn booking_matches_plain_adds_single_threaded() {
    let mut s = CgroupStats {
        packets: 41,
        bytes: 10_000,
    };
    book_packet(core::ptr::addr_of_mut!(s), 1500);
    assert_eq!(s.packets, 42);
    assert_eq!(s.bytes, 11_500);

    let mut acc: u64 = 700;
    bump_socket_bytes(core::ptr::addr_of_mut!(acc), 300);
    assert_eq!(acc, 1000);
}

/// Booking conservation under real thread contention: N threads x
/// M packets each into ONE shared entry — the exact production
/// sharing shape (many CPUs, one map value). A lost update (the
/// bug) fails this to the unit.
#[test]
fn concurrent_booking_loses_nothing() {
    const THREADS: usize = 8;
    const PACKETS: u64 = 20_000;
    const LEN: u64 = 1400;

    let mut shared = Shared {
        stats: Box::new(CgroupStats {
            packets: 0,
            bytes: 0,
        }),
        acc: Box::new(0),
    };
    let handle = handle_of(&mut shared);
    scope(|s| {
        for _ in 0..THREADS {
            let h = handle;
            s.spawn(move || {
                for _ in 0..PACKETS {
                    h.book(LEN);
                }
            });
        }
    });
    assert_eq!(
        shared.stats.packets,
        THREADS as u64 * PACKETS,
        "every packet's +1 must land — a lost increment is the improve-29 bug"
    );
    assert_eq!(
        shared.stats.bytes,
        THREADS as u64 * PACKETS * LEN,
        "every packet's bytes must land — the under-count the eagle-eyes display read"
    );
}

/// The single-u64 sibling: N threads x M adds into ONE shared
/// accumulator — the per-socket cookie map's production shape.
#[test]
fn concurrent_socket_bump_loses_nothing() {
    const THREADS: usize = 8;
    const ADDS: u64 = 20_000;
    const LEN: u64 = 900;

    let mut shared = Shared {
        stats: Box::new(CgroupStats {
            packets: 0,
            bytes: 0,
        }),
        acc: Box::new(0),
    };
    let handle = handle_of(&mut shared);
    scope(|s| {
        for _ in 0..THREADS {
            let h = handle;
            s.spawn(move || {
                for _ in 0..ADDS {
                    h.bump(LEN);
                }
            });
        }
    });
    assert_eq!(
        *shared.acc,
        THREADS as u64 * ADDS * LEN,
        "per-socket attribution must lose no bytes under contention"
    );
}

/// The control group at double contention: 16 threads, per-thread
/// distinct packet lengths, a closed-form expected total — any
/// future regression from the atomic booking back to a plain RMW
/// (the bug's shape) fails here to the byte, not in the field.
#[test]
fn fixed_booking_holds_the_exact_total_at_high_contention() {
    const THREADS: usize = 16;
    const PACKETS: u64 = 50_000;

    let mut shared = Shared {
        stats: Box::new(CgroupStats {
            packets: 0,
            bytes: 0,
        }),
        acc: Box::new(0),
    };
    let handle = handle_of(&mut shared);
    scope(|s| {
        for t in 0..THREADS {
            let h = handle;
            s.spawn(move || {
                // Each thread books its own packet length so the
                // expected total is the closed form sum(t)*100*PACKETS.
                for _ in 0..PACKETS {
                    h.book((t as u64 + 1) * 100);
                }
            });
        }
    });
    let expected_bytes: u64 = (1..=THREADS as u64).sum::<u64>() * 100 * PACKETS;
    assert_eq!(shared.stats.packets, THREADS as u64 * PACKETS);
    assert_eq!(shared.stats.bytes, expected_bytes);
}
