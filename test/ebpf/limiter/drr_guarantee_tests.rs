// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40 (schema v24): the guarantee bracket's battery — the
//! min/max laws the DRR pool's fair split is clamped between. Two
//! halves, the family's own shape:
//!
//! THE LAW PINS (pure, the drr_tests discipline): the zero
//! sentinel is the exact v23 arithmetic at every drawee count; the
//! floor raises the split to its epoch share only when it binds;
//! the ceiling lowers it only when it binds; the ceiling binds the
//! LONE drawer (a cap that folds when siblings appear is not a
//! cap); the contradiction closes with the ceiling (the cap is the
//! safety law); the bracket clamps to the row's own rate at every
//! consumer; the stockpile tracks the ceiling's own quantum.
//!
//! THE FLEET PINS (the sim, the ledger battery's own engine one
//! sibling over): the ceiling caps idle-sibling borrowing at K=2
//! and binds a lone drawer; a floor-only lone drawer keeps the
//! whole budget; over-subscribed floors (the sum above the refill,
//! the config the per-leaf validation cannot see coming) degrade
//! to the pool law without starving anyone below the unfloored
//! quietest bound — the honesty the module docs state, held by the
//! battery's own numbers.

use super::drr_sim::{run_kernel_shape, v24_cfg, verdict_for};
use super::ebpf_drr::{
    epoch_allowance, epoch_refill, guaranteed_allowance, guaranteed_stockpile, quantum,
};

// ── The law pins ──────────────────────────────────────────────────────

/// The zero sentinel is the fail-open contract: a 0/0 bracket is
/// the exact v23 arithmetic at every drawee count the lane can
/// learn, and the stockpile the legacy quantum — the composition
/// law the whole battery rides (the existing ledger/highload pins
/// ARE the bracket-off pins, unchanged).
#[test]
fn zero_bracket_is_the_v23_arithmetic() {
    for &rate in &[100_000, 1_000_000, 1_000_000_000] {
        for &drawees in &[0u16, 1, 2, 3, 6, 24, 4095] {
            assert_eq!(
                guaranteed_allowance(rate, 0, 0, drawees),
                epoch_allowance(rate, drawees),
                "rate {rate} drawees {drawees}: unset must be v23 exactly"
            );
        }
        assert_eq!(
            guaranteed_stockpile(rate, 0),
            quantum(rate),
            "rate {rate}: unset ceiling keeps the legacy stockpile"
        );
    }
}

/// The floor raises the split to its own epoch share only when the
/// fair split sits below it; a floor above the fair split is a
/// guarantee, a floor below it is arithmetic noise.
#[test]
fn floor_raises_the_split_to_its_epoch_share() {
    // rate 1mb, drawees 8: fair 12,500 < floor share 15,000.
    let raised = guaranteed_allowance(1_000_000, 150_000, 0, 8);
    assert_eq!(raised, epoch_refill(150_000), "the binding raise");
    // The same floor at drawees 2: fair 50,000 stands — the floor
    // is a minimum, not a target.
    let unbinding = guaranteed_allowance(1_000_000, 150_000, 0, 2);
    assert_eq!(
        unbinding,
        epoch_refill(1_000_000) / 2,
        "the non-binding floor"
    );
}

/// The ceiling lowers the split to its own epoch share only when
/// the fair split sits above it.
#[test]
fn ceiling_lowers_the_split_to_its_epoch_share() {
    // rate 1mb, drawees 2: fair 50,000 > ceiling share 30,000.
    let lowered = guaranteed_allowance(1_000_000, 0, 300_000, 2);
    assert_eq!(lowered, epoch_refill(300_000), "the binding lower");
    // The same ceiling at drawees 6: fair 16,666 stands.
    let unbinding = guaranteed_allowance(1_000_000, 0, 300_000, 6);
    assert_eq!(
        unbinding,
        epoch_refill(1_000_000) / 6,
        "the non-binding ceiling"
    );
}

/// THE SEMANTIC PIN: the ceiling binds the lone drawer — the OFF
/// lane's whole-budget row stands for floor-only brackets, but a
/// set ceiling engages the ledger at drawees 0 and 1 alike (the
/// single active subprocess is exactly the case the owner caps).
#[test]
fn ceiling_binds_the_lone_drawer() {
    for &drawees in &[0u16, 1] {
        assert_eq!(
            guaranteed_allowance(1_000_000, 0, 300_000, drawees),
            epoch_refill(300_000),
            "drawees {drawees}: the cap engages"
        );
    }
    // Floor-only: the whole budget stands.
    assert_eq!(
        guaranteed_allowance(1_000_000, 100_000, 0, 1),
        u64::MAX,
        "the floor-only lone drawer keeps the OFF lane"
    );
}

/// The contradiction (a floor above a ceiling — the config the
/// userspace validation rejects) closes with the ceiling: the cap
/// is the safety law, the datapath is total.
#[test]
fn contradiction_the_ceiling_wins() {
    let clamped = guaranteed_allowance(1_000_000, 500_000, 100_000, 4);
    assert_eq!(clamped, epoch_refill(100_000), "the cap wins");
}

/// The law-side clamp: a bracket side above the row's own rate can
/// never bind (the pool refills at the rate), so the consumers
/// clamp it — a drifted or hostile row reads as at-most-rate, and
/// the stockpile never grows past the legacy quantum on drifted
/// state.
#[test]
fn bracket_clamps_to_the_rows_own_rate() {
    // A floor above the rate reads as the rate's whole epoch share
    // (the maximal over-subscription, bounded).
    assert_eq!(
        guaranteed_allowance(100_000, 500_000, 0, 4),
        epoch_refill(100_000),
        "the drifted floor clamps to the rate"
    );
    // A ceiling above the rate never lowers: identical to unset.
    assert_eq!(
        guaranteed_allowance(1_000_000, 0, 2_000_000, 3),
        epoch_refill(1_000_000) / 3,
        "the drifted ceiling never binds"
    );
    // The stockpile clamps with it.
    assert_eq!(
        guaranteed_stockpile(1_000_000, 2_000_000),
        quantum(1_000_000),
        "the drifted ceiling keeps the legacy stockpile"
    );
}

/// The stockpile tracks the ceiling's own quantum: a capped leaf's
/// banking bound is its ceiling's, and the GSO admit floor (64 KiB)
/// survives every bracket.
#[test]
fn stockpile_tracks_the_ceiling_quantum() {
    assert_eq!(
        guaranteed_stockpile(1_000_000, 300_000),
        quantum(300_000),
        "the ceiling's quantum (floored at the GSO admit)"
    );
    assert_eq!(quantum(300_000), 65_536, "the admit floor holds at 300kb");
    assert_eq!(
        guaranteed_stockpile(2_000_000, 2_000_000),
        quantum(2_000_000),
        "a ceiling at the rate is the legacy bound"
    );
    // Monotonic: a ceiling can only tighten.
    assert!(guaranteed_stockpile(2_000_000, 300_000) <= quantum(2_000_000));
}

// ── The fleet pins (the shared engine, the sibling path) ─────────────

/// THE CAP OVER IDLE SIBLINGS: two dense leaves under a 300kb
/// ceiling on a 1mb pool — each bounded by the ceiling's own
/// windowed share plus the documented slop (one ceiling quantum of
/// banking plus one admit), the pool's spare standing unspent (the
/// borrowing that is NOT: past the cap, capacity sits idle by the
/// owner's own configuration).
#[test]
fn the_ceiling_caps_idle_sibling_borrowing() {
    let cfg = v24_cfg(0, 300_000);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 2, 4, 0, 0);
    let v = verdict_for(&gots);
    let cap_share = 300_000u64 * 4;
    let slop = quantum(300_000) + 65_536;
    assert!(
        v.worst <= cap_share + slop,
        "the cap: worst {} vs ceiling share {} + slop {}",
        v.worst,
        cap_share,
        slop
    );
    assert!(
        v.quietest >= cap_share * 7 / 10,
        "both capped leaves ride the cap: quietest {} vs 70% of {}",
        v.quietest,
        cap_share
    );
}

/// THE LONE-DRAWER CAP: a single leaf under a ceiling reads the
/// ceiling's share, not the whole budget — the semantic pin's
/// fleet form (a cap that folds when siblings appear is not a cap).
#[test]
fn the_ceiling_binds_a_lone_drawer() {
    let cfg = v24_cfg(0, 300_000);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 1, 4, 0, 0);
    let v = verdict_for(&gots);
    let cap_share = 300_000u64 * 4;
    let slop = quantum(300_000) + 65_536;
    assert!(
        v.total <= cap_share + slop,
        "the lone cap: {} vs ceiling share {} + slop {}",
        v.total,
        cap_share,
        slop
    );
    assert!(
        v.total >= cap_share * 7 / 10,
        "the lone capped leaf rides its cap: {} vs 70% of {}",
        v.total,
        cap_share
    );
}

/// A floor-only lone drawer keeps the whole budget — the floor is a
/// minimum, and the OFF lane's whole-budget row is the minimum's
/// own maximal case.
#[test]
fn a_floor_only_lone_drawer_keeps_the_budget() {
    let cfg = v24_cfg(100_000, 0);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 1, 2, 0, 0);
    let v = verdict_for(&gots);
    assert!(
        v.total >= 1_000_000 * 2 * 8 / 10,
        "the lo bound: the floored lone leaf delivered {} of {}",
        v.total,
        1_000_000 * 2
    );
}

/// THE OVER-SUBSCRIPTION HONESTY: eight leaves each floored at
/// 150kb on a 1mb pool (the floors' sum 1.2mb > the refill — the
/// config the per-leaf validation cannot see coming, leaves being
/// dynamic) degrade to the pool law: the pool never hands out what
/// it does not have, no leaf reads above its floor's windowed share
/// plus the slop, and the quietest keeps the unfloored battery's
/// own no-starve bound (the floor never makes a sibling worse).
#[test]
fn over_subscribed_floors_degrade_to_the_pool_law() {
    let cfg = v24_cfg(150_000, 0);
    let (gots, _) = run_kernel_shape(&cfg, 1_000_000, 8, 4, 0, 0);
    let v = verdict_for(&gots);
    let floor_share = 150_000u64 * 4;
    let slop = quantum(1_000_000) + 65_536;
    // The pool's conservation: the aggregate stays the policy.
    assert!(
        v.total <= 1_000_000 * 4 * 130 / 100,
        "the pool never creates budget: total {}",
        v.total
    );
    // No leaf reads above its own floor's windowed share + slop.
    assert!(
        v.worst <= floor_share + slop,
        "the degraded floor: worst {} vs floor share {} + slop {}",
        v.worst,
        floor_share,
        slop
    );
    // The quietest keeps the unfloored no-starve bound: fair/4.
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve under degradation: {} vs fair/4 {}",
        v.quietest,
        v.fair / 4
    );
}
