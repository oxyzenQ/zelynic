// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The allocation lens (night-frontier-Z4) — a counting global
//! allocator, test-binary-only (wired from render.rs's cfg(test);
//! one per crate). Every heap event bumps the counters; a pin
//! snapshots around a region and reads the delta. The lens measures;
//! the pins decide — the diff engine's zero-alloc claim
//! (NIGHT-blade-16) and the composition half's pool law are both
//! held by `steady_state_frame_composition_allocates_zero` in
//! bench.rs, this file's only consumer.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Heap events served since process start (alloc, alloc_zeroed, and
/// realloc growth each count one).
pub static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: each method forwards the layout to the System allocator
// unchanged and only bumps a counter — the forwarding preserves
// every GlobalAlloc contract (alignment, size, the realloc/alloc_zeroed
// semantics), so no pointer the program sees is invented here.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller upholds GlobalAlloc's own contract; the
        // call forwards verbatim.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr was allocated by this allocator (the System
        // forward) with this same layout — the mirror of alloc. The
        // counter counts ALLOCATION events only; the free itself
        // MUST still reach the system allocator (a no-op here leaves
        // every byte of the test binary unfreed — the exact leak
        // flood Miri caught on this lane).
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded verbatim to the System allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: ptr was allocated with this same layout by this
        // allocator (System), and new_size obeys the GlobalAlloc
        // realloc contract the caller signed up to.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static LENS: Counting = Counting;

/// The counter's current word — the pin's before/after pair.
pub fn count() -> usize {
    ALLOCS.load(Ordering::Relaxed)
}
