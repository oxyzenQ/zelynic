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
//!
//! NIGHT-total-lts-5 added the eviction-restart family: the dinner-6
//! E1 rider moved the observer's counter maps to the LRU lane, and
//! an evicted-then-returning cgroup restarts its accumulator from
//! zero — a backwards step that is a RESTART, not a wrap (a genuine
//! wrap needs 18.4 EB through one cgroup inside one session-scoped
//! map; no real host produces it). The restart must read as its
//! fresh bytes, never the wrap phantom (~2^64 - prev) the bare
//! modulo subtraction answered — the phantom spiked the returning
//! row's rate, crowned a permanent +18 EB on the session
//! leaderboard, and could flip the --depth shadow audit's
//! bypass-divergence verdict on traffic that never happened.

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

/// The eviction-restart shape (NIGHT-total-lts-5, the audit-seam
/// find): the cgroup's last-seen accumulator held 50,000 bytes; LRU
/// pressure evicted the entry; the cgroup returned and its fresh
/// accumulator holds 1,500. The bare modulo read answered
/// 2^64 - 48,500 — an 18-exabyte phantom. The restart's honest
/// delta is the fresh bytes themselves.
#[test]
fn an_eviction_restart_reads_its_fresh_bytes() {
    let prev = 50_000_u64;
    let cur = 1_500_u64;
    assert_eq!(wrap_coherent_delta(cur, prev), 1_500);
}

/// The phantom's arithmetic, pinned dead: the bare modulo delta for
/// the restart shape lands past half the u64 space — the coherence
/// band's own ceiling — and the discriminator must return `cur`
/// there. This is the regression line for the exact damage surface
/// (row rate spike, session-leaderboard corruption, shadow-audit
/// divergence) the phantom carried.
#[test]
fn the_restart_phantom_is_dead() {
    let prev = 50_000_u64;
    let cur = 1_500_u64;
    let phantom = cur.wrapping_sub(prev);
    assert!(phantom > u64::MAX / 2, "the shape must land past the band");
    assert_eq!(wrap_coherent_delta(cur, prev), cur);
}

/// The discriminator's boundary is the coherence bound itself: a
/// delta exactly ON 2^63 is outside the documented exact band (the
/// pins' own bound: exact while strictly UNDER 2^63) and reads as
/// the restart; one byte under it stays the exact modulo delta.
#[test]
fn the_discriminator_boundary_is_the_coherence_bound() {
    // Just inside the band: a forwards step at 2^63 - 1 is exact.
    assert_eq!(wrap_coherent_delta(u64::MAX / 2, 0), u64::MAX / 2);
    // Exactly on the band ceiling: the restart reading (cur).
    let cur = 42_u64;
    let prev = cur.wrapping_sub(1u64 << 63);
    assert_eq!(cur.wrapping_sub(prev), 1u64 << 63);
    assert_eq!(wrap_coherent_delta(cur, prev), cur);
}

/// The documented unreachable corner, pinned for honesty: a restart
/// whose gap (prev - cur) is itself past 2^63 needs prev to hold
/// 9.2+ EB accumulated inside ONE session — ~2.3 years of 1-Tbps
/// traffic through one cgroup with the monitor watching. The corner
/// degrades to the modulo reading (never worse than the pre-audit
/// behavior); this pin documents the degradation as DELIBERATE, so
/// a future audit finds it on the record instead of hunting it.
#[test]
fn the_unreachable_deep_restart_corner_degrades_to_modulo() {
    // prev holds 2^63 + 1,000; the restart left cur at 1,000.
    let prev = (1u64 << 63) + 1_000;
    let cur = 1_000_u64;
    // gap = prev - cur = 2^63 exactly → the modulo delta lands at
    // 2^64 - 2^63 = 2^63, AT the ceiling — still the restart side.
    assert_eq!(wrap_coherent_delta(cur, prev), cur);
    // gap past 2^63: the modulo delta lands UNDER the ceiling —
    // the discriminator cannot see this restart, by design.
    let prev = (1u64 << 63) + 2_000;
    let cur = 1_000_u64;
    assert_eq!(wrap_coherent_delta(cur, prev), cur.wrapping_sub(prev));
}
