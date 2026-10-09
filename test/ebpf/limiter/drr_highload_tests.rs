// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-hunt-Z6: the high-load shapes — the fair-share law's last
//! open area (the Z4 offer's remaining candidate: DRR fairness
//! under high load), pinned on the epoch-ledger battery's shared
//! kernel-shaped runner (drr_ledger_tests) in the two shapes no
//! existing pin measures.
//!
//! SHAPE ONE, THE LTS HORIZON: 24 leaves, the 1mb trickle-hard rate
//! (the allowance at 4.3 KB per epoch banks a 64 KiB admit every
//! ~15 epochs — the deepest GSO-floor banking cadence the law owns),
//! sustained for 12 s — three times the live battery's window, the
//! steady state an LTS host actually lives in. The battery's own
//! bands must hold over the whole horizon: the aggregate at policy,
//! the worst leaf inside 1.75x fair + one quantum, the quietest
//! above fair/4. The protection does the work: the peak field holds
//! the divisor near the full count while the starved leaves ride
//! their retransmit silences, so everyone's allowance stays the
//! fair split and everyone banks toward the next admit.
//!
//! SHAPE TWO, THE MASS-DEPARTURE RELEASE WINDOW: 24 leaves run hot,
//! then 18 leave at once. The peak (the allowance's divisor, the
//! decaying high-water) cannot tell a departed leaf from a starved
//! one — a leaf that stops asking is the same signal at the pool —
//! so it releases one share every PEAK_DECAY_EPOCHS epochs and the
//! six survivors run UNDER policy for the window it takes the peak
//! to fall to the living count. That sag is the documented price of
//! the repair-4 protection (a starved leaf's silence must not
//! inflate its rivals' allowance), and it points in the safe
//! direction: an under-admit, never an over-admit — the pool never
//! hands out what it does not have. The two pins hold the tradeoff
//! from both sides: the survivors never fall below the allowance
//! floor while the window stands, and the window CLOSES on the
//! decay schedule (a stalled decay strands the subtree under-policy
//! forever; the 20 s aggregate and the final peak both refuse that
//! shape, and a decay fast enough to beat the schedule would
//! re-open the silence hole the many24 battery pins shut).
//!
//! The verdict these pins file for the Z6 audit: the law is SOUND
//! under high load — the sustained split is the allowance itself,
//! the departure sag is bounded, self-healing, and pool-safe. All
//! pins are userspace: the eBPF object is byte-identical (the
//! prebuilt lane's tree pin proves it).

use super::drr_sim::{run_kernel_shape, v17_cfg, verdict_for};
use super::ebpf_drr::{PEAK_DECAY_EPOCHS, pool_share_peak, quantum};

/// The policy both shapes run: the many24 trickle-hard rate — the
/// allowance banks a 64 KiB admit over ~15 epochs, the deepest
/// cadence the GSO floor owns.
const RATE: u64 = 1_000_000;
/// The full-contention count: every leaf the battery's many24 row
/// runs, all arriving at once (no stagger).
const K: usize = 24;

/// THE LTS HORIZON (shape one): 12 s of sustained 24-leaf
/// contention at the trickle-hard rate — the battery's bands judged
/// over three windows' span, the steady state a months-LTS host
/// lives in.
#[test]
fn sustained_contention_holds_the_band_over_the_lts_horizon() {
    let (gots, _) = run_kernel_shape(&v17_cfg(true), RATE, K, 12, 0, 0);
    let v = verdict_for(&gots);
    let q = quantum(RATE);
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "anti-monopoly over the horizon: worst {} vs bound {}",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q
    );
    assert!(
        v.quietest >= v.fair / 4,
        "no-starve over the horizon: {} vs {}",
        v.quietest,
        v.fair / 4
    );
    assert!(
        v.total <= RATE * 12 * 130 / 100,
        "the pool never creates budget: total {}",
        v.total
    );
    assert!(
        v.total >= RATE * 12 * 65 / 100,
        "the collapse guard over the horizon: total {} vs the 65% floor {}",
        v.total,
        RATE * 12 * 65 / 100
    );
}

/// The departure's shared setup: the 24-leaf round that ratchets
/// the peak to the full count — the word both departure pins
/// inherit (no mutation, no re-key: a departure is not an apply, so
/// the generation prefix never fires and the word carries as-is).
fn departed_word() -> u64 {
    let (_gots, word) = run_kernel_shape(&v17_cfg(true), RATE, K, 2, 0, 0);
    // The trickle-hard rate freezes a leaf or two by the second
    // window (the shape's own honesty — the measured round leaves
    // the high-water at 23 of 24); the departure pins derive from a
    // near-full peak, the handoff pin's own >= 20 precedent.
    assert!(
        pool_share_peak(word) >= K as u16 - 4,
        "the premise: a 2 s full round ratchets the peak near the full count, got {}",
        pool_share_peak(word)
    );
    word
}

/// THE RELEASE FLOOR (shape two, side one): 18 of 24 gone, the six
/// survivors measured over the battery's own 4 s window. The window
/// stands (the peak is still near its high-water), so the aggregate
/// reads UNDER the 65% band floor by design — the protection's
/// price — but never under the allowance floor: k/peak of policy
/// with the admit-quantization slack. The survivors split what they
/// get fairly (the allowance is uniform), and the pool never
/// over-admits.
#[test]
fn a_mass_departure_keeps_survivors_above_the_release_floor() {
    let word = departed_word();
    let survivors = 6_usize;
    let (gots, w) = run_kernel_shape(&v17_cfg(true), RATE, survivors, 4, 0, word);
    let v = verdict_for(&gots);
    let q = quantum(RATE);
    // The floor: k/peak of policy (the peak holds near its
    // high-water across a 4 s window — five decay steps at most),
    // with the 64 KiB admit one-admit-late slack folded in as the
    // 70% form. The successor run's pool also starts empty (the
    // real host's pool accumulated through the departure) — the
    // same slack carries it.
    let floor = RATE * 4 * survivors as u64 / K as u64 * 7 / 10;
    assert!(
        v.total >= floor,
        "the release floor: survivors' total {} under the allowance floor {}",
        v.total,
        floor
    );
    assert!(
        v.total <= RATE * 4 * 130 / 100,
        "the pool never creates budget on the departure: total {}",
        v.total
    );
    assert!(
        v.worst <= v.fair.saturating_mul(175) / 100 + q,
        "the survivors split fairly through the window: worst {} vs bound {}",
        v.worst,
        v.fair.saturating_mul(175) / 100 + q
    );
    assert!(
        pool_share_peak(w) > survivors as u16,
        "the window still stands over this span (peak {} vs {}) — the long-horizon pin below closes it",
        pool_share_peak(w),
        survivors
    );
}

/// THE WINDOW CLOSES (shape two, side two): the same departure,
/// measured past the end of the schedule. The peak must reach the
/// living count — (K - survivors) x PEAK_DECAY_EPOCHS epochs, 14.4 s
/// at the 24 -> 6 departure — and the 20 s aggregate must recover
/// past 40% of policy: a stalled decay strands the subtree at the
/// k/peak trickle, while a healthy window climbs linearly to well
/// past half.
#[test]
fn the_release_window_closes_on_the_decay_schedule() {
    let word = departed_word();
    let survivors = 6_usize;
    let secs = 20_u64;
    let schedule_secs = (K - survivors) as u64 * PEAK_DECAY_EPOCHS as u64 / 10;
    assert!(
        schedule_secs < secs,
        "the pin's span must cover the decay schedule ({schedule_secs} s vs {secs} s)"
    );
    let (gots, w) = run_kernel_shape(&v17_cfg(true), RATE, survivors, secs, 0, word);
    let v = verdict_for(&gots);
    let policy = RATE * secs;
    assert!(
        v.total * 100 >= policy * 40,
        "the window never closed: total {} vs 40% of {} (schedule {schedule_secs} s)",
        v.total,
        policy
    );
    assert!(
        pool_share_peak(w) <= survivors as u16,
        "the peak never reached the living count: {} vs {}",
        pool_share_peak(w),
        survivors
    );
}
