// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! repair-7: the two-lane take law — the engaged lane's catch-up
//! close, pinned at the arithmetic that convicted the fraction.
//!
//! THE FIND (best-specs, every v17 run, both libc legs): the
//! many24 quietest leaf read 78 B (gnu) / 65,614 B (musl — one
//! admit plus the headers) against a fair/4 floor of ~172 KB,
//! while the worst leaf and the aggregate stayed green — the
//! distribution alone broken, and broken exactly where the v16
//! fraction cap still binds inside the v17 ledger: a catch-up
//! drawer's take is pool/(K+2), a fraction that reaches the
//! 64 KiB GSO admit floor only when the pool holds (K+2) x 64 KiB
//! — 1.7 MB at K=24, against an unclaimed residue that
//! accumulates at refill/K per epoch (under 0.7 MB across the
//! whole 4 s window). The starved leaf banks under one admit
//! forever; its TCP never heals; the row reads one admit or none.
//!
//! THE LAW: take_size — one take, two lanes. The ENGAGED lane
//! (drawees >= 2) draws the residue law bounded by the ledger
//! room (the room owns the epoch split the fraction used to);
//! the OFF lane keeps the v16 learned-share law verbatim. The
//! pins below hold every edge of both lanes, and the arithmetic
//! of the find itself — the exact numbers the CI row measured.

use super::ebpf_drr::{
    GSO_ADMIT_FLOOR, draw_size, epoch_allowance, epoch_refill, fair_draw_size, quantum, take_size,
};

/// The find's own arithmetic (the CI row, restated as numbers):
/// at K=24 the fraction needs a 1.7 MB pool to admit ONE packet;
/// the unclaimed residue can never accumulate that inside a 4 s
/// window. The engaged law's take off the same residue clears the
/// admit floor with room to spare.
#[test]
fn the_finds_arithmetic_convicts_the_fraction_not_the_pool() {
    let rate = 4_000_000;
    let k: u16 = 24;
    let q = quantum(rate);
    let allowance = epoch_allowance(rate, k);
    // The residue at the END of a 4 s window: the refill minus the
    // room-blocked fast drawers' claims, per epoch, 40 epochs.
    let unclaimed = epoch_refill(rate) / u64::from(k) * 40;
    // The fraction's take off that residue — under one admit, the
    // row's 78 B shape (the take never banks a packet).
    let fraction_take = fair_draw_size(q, unclaimed, k);
    assert!(
        fraction_take < GSO_ADMIT_FLOOR,
        "the fraction starves the catch-up drawer: {fraction_take}"
    );
    // The engaged law's take: half the residue, bounded by the
    // room at the quantum — the leaf banks its admit and heals.
    let engaged_take = take_size(q, unclaimed, k, allowance, q);
    assert!(
        engaged_take >= GSO_ADMIT_FLOOR,
        "the engaged lane banks the catch-up admit: {engaged_take}"
    );
    assert_eq!(engaged_take, draw_size(q, unclaimed));
}

/// The hot drawer never moves: the room (its per-epoch allowance)
/// binds first, exactly the v17 edge — the monopoly bound's own
/// number. The engaged law only widens the CATCH-UP drawer's take,
/// and only up to the residue law's half-pool bound.
#[test]
fn engaged_lane_hot_drawer_stays_room_bounded() {
    let rate = 4_000_000;
    let q = quantum(rate);
    let allowance = epoch_allowance(rate, 24);
    // A rich pool, a hot drawer with one epoch's allowance banked:
    // the take is the room, not the residue.
    assert_eq!(
        take_size(q, 10_000_000, 24, allowance, allowance),
        allowance
    );
    // A scarce pool (the hot regime's puddle): the residue law
    // binds below the room — half of whatever is there.
    let puddle = 20_000;
    assert_eq!(
        take_size(q, puddle, 24, allowance, allowance),
        draw_size(q, puddle)
    );
    // The room below the residue: the room binds (the carry spent).
    assert_eq!(take_size(q, 10_000_000, 24, allowance, 4_000), 4_000);
}

/// The off lane keeps the v16 law verbatim: a lone drawer (or a
/// cold pool, or a state-map miss — the fail-open posture) draws
/// fair_draw_size, room unbounded — the whole-budget row rides it.
#[test]
fn off_lane_keeps_the_v16_law_verbatim() {
    let rate = 1_000_000;
    let q = quantum(rate);
    let pool = 300_000;
    // A lone drawer: learned 1 — pool/3, quantum-capped.
    assert_eq!(
        take_size(q, pool, 1, u64::MAX, u64::MAX),
        fair_draw_size(q, pool, 1)
    );
    // A cold pool or a miss: learned 0 — the exact v13 residue law.
    assert_eq!(
        take_size(q, pool, 0, u64::MAX, u64::MAX),
        fair_draw_size(q, pool, 0)
    );
    assert_eq!(
        take_size(q, pool, 0, u64::MAX, u64::MAX),
        draw_size(q, pool)
    );
    // The engaged lane with a spent room takes nothing (a blocked
    // leaf stops touching the pool — the v17 posture, unchanged).
    assert_eq!(take_size(q, pool, 24, 16_000, 0), 0);
}
