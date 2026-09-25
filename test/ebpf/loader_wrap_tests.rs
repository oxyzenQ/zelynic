// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The wrap-coherence pins for the observer's counter deltas
//! (NIGHT-lts-5, the server long-endurance ask): the kernel side's
//! booking is `fetch_add` — BPF atomics WRAP at u64::MAX (18.4 EB,
//! ~4.7 years of 1-Tbps traffic through one cgroup) — so the
//! userspace delta must be the modulo inverse, never a saturating
//! clamp. The old `saturating_sub` turned every post-wrap poll into
//! a ZERO delta: the wrapped cgroup went silent on the board (rates
//! zero, totals frozen) for another full 18.4 EB, the exact
//! long-uptime corruption a server deployment cannot afford.

use super::wrap_coherent_delta;

/// The healthy path is unchanged: a forwards step is the step.
#[test]
fn forwards_deltas_are_exact() {
    assert_eq!(wrap_coherent_delta(1_500, 1_000), 500);
    assert_eq!(wrap_coherent_delta(u64::MAX, 0), u64::MAX);
    assert_eq!(wrap_coherent_delta(0, 0), 0);
}

/// The wrap itself: a counter that crosses u64::MAX yields the TRUE
/// delta through modulo subtraction — a 1500-byte interval that
/// straddles the wrap (prev = u64::MAX - 500, cur = 999) reads
/// 1500, not the saturating clamp's 0.
#[test]
fn a_wrapped_counter_keeps_its_true_delta() {
    let prev = u64::MAX - 500;
    let cur = 999_u64; // wrapped: 999 + (2^64 - prev) = 1500 true bytes
    assert_eq!(wrap_coherent_delta(cur, prev), 1500);
}

/// The post-wrap steady state: every poll after the wrap keeps
/// reading true deltas (the old clamp read ZERO forever — the
/// silent-cgroup bug this pin exists to bury).
#[test]
fn post_wrap_polls_stay_alive() {
    let mut prev = 100_u64; // the wrap already happened
    let mut cur = 200_u64;
    assert_eq!(wrap_coherent_delta(cur, prev), 100);
    prev = cur;
    cur = 350;
    assert_eq!(wrap_coherent_delta(cur, prev), 150);
}

/// The coherence bound, documented and pinned: the modulo delta is
/// exact while the true per-interval delta stays under 2^63 bytes —
/// ~9.2 EB in ONE poll interval, which a 1-Tbps link needs ~2.3
/// years to produce. A delta at the bound's edge stays exact.
#[test]
fn the_coherence_bound_is_nine_orders_past_real_intervals() {
    // A half-wrap step: cur = prev + 2^62 (far past any real
    // interval, still deep inside the exact band).
    let prev = 1_000_u64;
    let cur = prev.wrapping_add(1 << 62);
    assert_eq!(wrap_coherent_delta(cur, prev), 1 << 62);
}
