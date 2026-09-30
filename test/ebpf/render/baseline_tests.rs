// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! EAGLE EYES V2 pins (NIGHT-improve-1a): the baseline lane's fold
//! lifecycle, the deviation bands, the dedupe, the convergence
//! horizon, and the render shapes. Lives under the single test/
//! tree (cosmostrix Pattern C), #[path]-wired from
//! src/ebpf/render/baseline.rs, so `super::` reaches the private
//! fold/word cores exactly like the session pins reach theirs.
//!
//! The fold discipline every fixture rides: a read at `at(n)`
//! folds the completed horizon windows n-6..=n — stamped windows
//! live, unstamped windows ZERO (the idle-second contract), the
//! current window n+1 never folds (it can only grow). Older
//! windows dedupe by number; the stamp's slot is win % 8.

use super::*;
use crate::ebpf::limiter::rate_ring::RATE_RING_WINDOW_NS;

// ── Fixtures ────────────────────────────────────────────────────────

/// Read time mid-window AFTER `win`: at(win) the completed horizon
/// is win-6..=win and win+1 is the current, still-filling window.
fn at(win: u64) -> u64 {
    (win + 1) * RATE_RING_WINDOW_NS + 500_000_000
}

/// One read at `at(win)`: a ring whose slots stamp exactly the
/// windows the caller names. Unstamped horizon windows fold as
/// ZERO; the caller controls every sample the read produces.
fn fold_call(states: &mut HashMap<u32, BaselineState>, key: u32, win: u64, stamps: &[(u64, u64)]) {
    let mut raw = RateRingRaw::default();
    for (w, b) in stamps {
        let slot = &mut raw.slots[(*w % RATE_RING_SLOTS as u64) as usize];
        slot.window = *w;
        slot.bytes = *b;
    }
    BaselineLane::fold_direction(states, Some(&[(key, raw)]), at(win));
}

/// A schedule of single-window reads (one call per entry) — the
/// continuation shape: each call folds exactly its named window,
/// everything older dedupes.
fn drive(states: &mut HashMap<u32, BaselineState>, key: u32, schedule: &[(u64, u64)]) {
    for (win, bytes) in schedule {
        fold_call(states, key, *win, &[(*win, *bytes)]);
    }
}

/// Steady at `level`: one read stamping the whole horizon 94..=100
/// (seven live samples), then one read for window 101 — eight
/// contiguous live folds, no zeros mixed in, streak 0, EMA exactly
/// the level. The fixture every flag test departs from.
fn drive_steady(states: &mut HashMap<u32, BaselineState>, key: u32, level: u64) {
    let horizon: Vec<(u64, u64)> = (94..=100).map(|w| (w, level)).collect();
    fold_call(states, key, 100, &horizon);
    fold_call(states, key, 101, &[(101, level)]);
}

/// One read carrying SEVERAL keys' rings — the census shape the real
/// reader produces (every policy root in the map, one read, one
/// retain): the per-key fold drives above would each drop the other
/// keys' states, which is the design, so multi-key fixtures ride
/// one read for every key.
fn fold_call_multi(
    states: &mut HashMap<u32, BaselineState>,
    rings: &[(u32, &[(u64, u64)])],
    win: u64,
) {
    let rows: Vec<(u32, RateRingRaw)> = rings
        .iter()
        .map(|(k, stamps)| {
            let mut raw = RateRingRaw::default();
            for (w, b) in *stamps {
                let slot = &mut raw.slots[(*w % RATE_RING_SLOTS as u64) as usize];
                slot.window = *w;
                slot.bytes = *b;
            }
            (*k, raw)
        })
        .collect();
    BaselineLane::fold_direction(states, Some(&rows), at(win));
}

// ── The fold lifecycle ───────────────────────────────────────────────

/// Learning until the horizon fills, then steady with the EMA
/// figure. Before any fold there is no word at all — never a
/// fabricated learning figure for a lens that never opened.
#[test]
fn learning_then_steady_states_the_baseline() {
    assert_eq!(BaselineState::default().word(), None);
    // A quiet horizon read once: seven idle seconds are seven
    // honest samples — Learning carries them, never a fabricated
    // baseline from two.
    let mut quiet = BaselineLane::new();
    fold_call(&mut quiet.dl, 7, 99, &[]);
    assert_eq!(
        quiet.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Learning { samples: 7 }),
        "seven of eight is still learning"
    );
    // The full horizon at one level read once, then its eighth
    // window: the baseline states exactly the level.
    let mut steady = BaselineLane::new();
    drive_steady(&mut steady.dl, 7, 100_000);
    assert_eq!(
        steady.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Steady { bps: 100_000 }),
        "eight folds at one level state the baseline at that level"
    );
}

/// The dedupe: a window number already folded never folds again, a
/// window BELOW the last fold is stale forever, and a newer window
/// folds exactly once. Samples is the proof — a double fold would
/// inflate it.
#[test]
fn dedupe_keeps_every_window_once() {
    let mut lane = BaselineLane::new();
    fold_call(
        &mut lane.dl,
        7,
        95,
        &(89..=95).map(|w| (w, 5_000)).collect::<Vec<_>>(),
    );
    assert_eq!(lane.dl.get(&7).unwrap().samples, 7);
    // The same horizon read again: nothing new, nothing double.
    fold_call(
        &mut lane.dl,
        7,
        95,
        &(89..=95).map(|w| (w, 5_000)).collect::<Vec<_>>(),
    );
    assert_eq!(
        lane.dl.get(&7).unwrap().samples,
        7,
        "re-reading the same windows folds nothing"
    );
    // A stale (older) window arriving late is ignored entirely.
    fold_call(&mut lane.dl, 7, 95, &[(88, 999_999)]);
    assert_eq!(lane.dl.get(&7).unwrap().samples, 7);
    // One newer window folds exactly once more.
    fold_call(&mut lane.dl, 7, 96, &[(96, 5_000)]);
    assert_eq!(lane.dl.get(&7).unwrap().samples, 8);
}

/// Judge-then-update: a spike is judged against the baseline it
/// departs from — the PRE-update EMA — so a 3x burst on a steady
/// 100 KB/s flags with the honest percent, and one fold short of
/// the sustain it is still Steady (one burst window is a hiccup).
#[test]
fn spike_flags_after_two_windows_with_exact_percent() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    drive(&mut lane.dl, 7, &[(102, 300_000)]);
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Steady { bps: 125_000 }),
        "one deviant window is a hiccup, not a flag — the EMA moved \
         (100k + 200k/8) but the verdict stays steady"
    );
    drive(&mut lane.dl, 7, &[(103, 300_000)]);
    // EMA after both folds: 125_000 + 175_000/8 = 146_875.
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Above {
            percent: Some(104),
            base: 146_875
        }),
        "two deviant windows flag above, percent measured against the \
         EMA the departs are still dragging (delta 153_125 x100 / 146_875)"
    );
}

/// The mirror flag: a stall below the band flags `below` with the
/// exact percent — the direction an operator cares about most (a
/// service that stopped eating its budget).
#[test]
fn stall_flags_below_with_exact_percent() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    drive(&mut lane.dl, 7, &[(102, 10_000), (103, 10_000)]);
    // EMA after both: 100_000 - 90_000/8 = 88_750, then
    // 88_750 - 78_750/8 = 78_907. Percent: (78_907-10_000)x100/78_907.
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Below {
            percent: Some(87),
            base: 78_907
        })
    );
}

/// The 4 KiB floor: a ratio-leg-clearing delta under the floor does
/// not deviate — a near-zero baseline never flaps on noise scale.
/// Steady at 2_000, then 4_000 twice (delta 2_000, then 1_750 —
/// both under 4_096): no flag, and the EMA still followed.
#[test]
fn floor_blocks_ratio_only_deltas() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 2_000);
    drive(&mut lane.dl, 7, &[(102, 4_000), (103, 4_000)]);
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Steady { bps: 2_468 }),
        "both legs must clear and neither delta does (2_000 then \
         1_750 vs the 4_096 floor); the EMA followed: 2_000 -> 2_250 -> 2_468"
    );
}

/// A zero baseline waking up: the burst flags with a percent
/// measured against the EMA the two folds dragged up from zero.
#[test]
fn zero_base_burst_flags_with_percent() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 0);
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Steady { bps: 0 }),
        "a policy quiet since the lens opened is steady at zero"
    );
    drive(&mut lane.dl, 7, &[(102, 100_000), (103, 100_000)]);
    // EMA: 0 -> 12_500 -> 23_437; percent (100_000-23_437)x100/23_437.
    assert_eq!(
        lane.dl.get(&7).unwrap().word(),
        Some(BaselineWord::Above {
            percent: Some(326),
            base: 23_437
        }),
        "percent of zero has no meaning — the figure rides the EMA the \
         folds built, which is no longer zero"
    );
}

/// The convergence horizon (the module header's stated math): a
/// sustained doubling flags for the second through fourth window
/// after the step, then the EMA has followed and the verdict reads
/// Steady again — the baseline FOLLOWS the traffic, it does not pin
/// the past forever.
#[test]
fn flag_self_clears_when_the_ema_follows() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    // Step change to 200_000, sustained through window 106. The
    // flag must appear exactly at the second post-step window and
    // clear by the fifth (the EMA caught up: 100k -> ~141k, and
    // 58.6k delta no longer clears 50% of it).
    for n in 102..=106u64 {
        drive(&mut lane.dl, 7, &[(n, 200_000)]);
        let word = lane.dl.get(&7).unwrap().word();
        let flagged = matches!(word, Some(BaselineWord::Above { .. }));
        let expected = (103..=105).contains(&n);
        assert_eq!(
            flagged, expected,
            "window {n}: flag={flagged} expected={expected} (word {word:?})"
        );
    }
}

// ── The fold from series (idle seconds and pre-boot) ────────────────

/// An idle window (the slot never stamped) folds as ZERO — a quiet
/// second under a live policy is a real sample of "delivered
/// nothing"; the baseline must learn quiet periods, not skip them.
#[test]
fn idle_windows_fold_as_zero() {
    let mut lane = BaselineLane::new();
    // One read at at(99): horizon 93..=99 — 93,94,95 and 98,99
    // stamped, 96 and 97 idle between them.
    fold_call(
        &mut lane.dl,
        7,
        99,
        &[
            (93, 50_000),
            (94, 50_000),
            (95, 50_000),
            (98, 50_000),
            (99, 50_000),
        ],
    );
    let state = lane.dl.get(&7).unwrap();
    assert_eq!(state.samples, 7, "5 stamped + 2 idle = 7 folded windows");
    // The idle pair folded as zeros between the live ones; the
    // latest folded window (99) carried the live figure.
    assert_eq!(state.last_bytes, 50_000);
    // A horizon whose LATEST window is a live zero: last_bytes 0.
    let mut lane2 = BaselineLane::new();
    fold_call(
        &mut lane2.dl,
        7,
        99,
        &[(93, 50_000), (94, 50_000), (95, 50_000), (99, 0)],
    );
    let state2 = lane2.dl.get(&7).unwrap();
    assert_eq!(state2.samples, 7);
    assert_eq!(
        state2.last_bytes, 0,
        "the latest folded window carried zero"
    );
}

/// Pre-boot windows carry no sample: at t=3.5s only windows 0..2
/// exist; the older horizon is skipped (checked_sub), never folded
/// as fabricated zeros.
#[test]
fn pre_boot_windows_are_not_samples() {
    let mut lane = BaselineLane::new();
    BaselineLane::fold_direction(
        &mut lane.dl,
        Some(&[(7, RateRingRaw::default())]),
        3 * RATE_RING_WINDOW_NS + 500_000_000,
    );
    let state = lane.dl.get(&7).unwrap();
    assert_eq!(state.samples, 3, "only windows 0..2 exist at t=3.5s");
}

// ── The lane: lifecycle, lookups, ordering ──────────────────────────

/// The lens lifecycle: a read that fails (None) clears the whole
/// direction — enforcement gone resets the baseline, and a
/// re-applied policy would start learning fresh.
#[test]
fn failed_read_clears_the_direction() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    assert!(lane.dl.contains_key(&7));
    BaselineLane::fold_direction(&mut lane.dl, None, at(100));
    assert!(
        lane.dl.is_empty(),
        "enforcement gone means the baseline is gone"
    );
}

/// A key that vanished from a successful read drops its state the
/// same frame (its policy is gone; if it reappears it learns fresh).
#[test]
fn vanished_key_drops_its_state() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    drive_steady(&mut lane.dl, 8, 5_000);
    // A read that names ONLY key 8: key 7's state is dropped.
    fold_call(&mut lane.dl, 8, 102, &[(102, 5_000)]);
    assert!(
        !lane.dl.contains_key(&7),
        "the vanished policy's state is dropped"
    );
    assert!(lane.dl.contains_key(&8));
    assert!(lane.focus_pair(7).is_none());
}

/// focus_pair joins by EXACT id only (the aggregate law): state for
/// key 7 answers for 7 and for nothing else.
#[test]
fn focus_pair_is_exact_match() {
    let mut lane = BaselineLane::new();
    drive_steady(&mut lane.dl, 7, 100_000);
    let pair = lane.focus_pair(7).expect("key 7 holds download state");
    assert!(
        pair.0.is_some() && pair.1.is_none(),
        "dl only, ul never folded"
    );
    assert!(
        lane.focus_pair(8).is_none(),
        "no state, no pair — never a fabricated learning figure"
    );
}

/// panel_rows orders busiest first (dl+ul EMA desc) and breaks ties
/// by cgroup id — the board must not reshuffle between frames.
#[test]
fn panel_rows_busiest_first_tie_by_id() {
    let mut lane = BaselineLane::new();
    // All three keys ride the same two reads (the census shape):
    // separate per-key reads would drop each other's states, which
    // is the retain's own design.
    let horizon = |level: u64| (94..=100).map(|w| (w, level)).collect::<Vec<_>>();
    fold_call_multi(
        &mut lane.dl,
        &[
            (7, &horizon(100_000)),
            (9, &horizon(900_000)),
            (8, &horizon(100_000)),
        ],
        100,
    );
    fold_call_multi(
        &mut lane.dl,
        &[
            (7, &[(101, 100_000)]),
            (9, &[(101, 900_000)]),
            (8, &[(101, 100_000)]),
        ],
        101,
    );
    let rows = lane.panel_rows();
    let ids: Vec<u32> = rows.iter().map(|(k, _, _)| *k).collect();
    assert_eq!(
        ids,
        vec![9, 7, 8],
        "900 KB/s first, the 100 KB/s pair ties by id"
    );
}
