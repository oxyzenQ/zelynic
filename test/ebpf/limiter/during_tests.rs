// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! night-during, schema v23: rootless pins for the time-window core
//! (ebpf/src/during.rs, the same file the BPF object builds, wired
//! below with #[path]). Every pin maps to a documented law in that
//! module:
//!
//!  * the DAILY comparator (margin 0) — the plain window laws:
//!    start inclusive, end exclusive, the midnight wrap as pure
//!    arithmetic (22:00-06:00 is the bedtime shape), zero-width
//!    refused;
//!  * the MARGIN LAW — both edges erode toward LESS enforcement:
//!    the window opens FIRE_EARLY late, closes FIRE_EARLY early,
//!    a window shorter than two margins never activates, and the
//!    erosion is monotone (every margin-2s-active point is
//!    margin-0-active — the over-enforcement impossibility);
//!  * the SPAN laws — inclusive start, exclusive end, zero-length
//!    belt, offset IGNORED (the drift-free translation);
//!  * the verdict totality — a saturating (corrupt) offset yields
//!    a bounded verdict, an unknown kind enforces (the
//!    absent-entry verdict), wall_of_day_ns never leaves its
//!    domain;
//!  * the sweep predicates — span_ended (the only removal
//!    predicate), span_dormant (a future date survives every
//!    sweep), a DAILY window never ends.

// The production window core, compiled into this test module: the
// SAME file the BPF object builds. Only the test tree reaches
// across trees (the gate-tree discipline, the math_tests
// precedent).
#[path = "../../../ebpf/src/during.rs"]
pub(super) mod ebpf_during;

use self::ebpf_during::{
    FIRE_EARLY_NS, NS_PER_DAY, PolicyWindow, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN, daily_active,
    span_dormant, span_ended, wall_of_day_ns, window_active,
};

/// Seconds-of-day to ns-of-day (the comparator's input domain).
fn secs(h: u32, m: u32, s: u32) -> u64 {
    (u64::from(h) * 3600 + u64::from(m) * 60 + u64::from(s)) * 1_000_000_000
}

/// A DAILY window row over [start_s, end_s) seconds-of-day.
fn win_daily(start_s: u32, end_s: u32) -> PolicyWindow {
    PolicyWindow {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s,
        end_s,
    }
}

/// A SPAN row over [start, end) monotonic ns.
fn win_span(start: u64, end: u64) -> PolicyWindow {
    PolicyWindow {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: start,
        end_mono_ns: end,
        start_s: 0,
        end_s: 0,
    }
}

// ━━ The constants the laws quote ━━

#[test]
fn fire_early_is_two_seconds() {
    assert_eq!(FIRE_EARLY_NS, 2_000_000_000, "the margin is 2s");
}

#[test]
fn ns_per_day_is_one_utc_day() {
    assert_eq!(NS_PER_DAY, 86_400_000_000_000);
    assert_eq!(wall_of_day_ns(0), 0);
    assert_eq!(
        wall_of_day_ns(NS_PER_DAY),
        0,
        "the day wraps at exactly NS_PER_DAY"
    );
    assert_eq!(wall_of_day_ns(NS_PER_DAY - 1), NS_PER_DAY - 1);
    // Totality on hostile input: any u64 lands in the domain.
    assert!(wall_of_day_ns(u64::MAX) < NS_PER_DAY);
    assert!(wall_of_day_ns(u64::MAX / 2) < NS_PER_DAY);
}

#[test]
fn window_row_layout_contract() {
    // The 32-byte row: the userspace Pod twin (types.rs) pins the
    // same size, so a mismatch here is a two-tree drift, not a
    // local surprise.
    assert_eq!(
        core::mem::size_of::<PolicyWindow>(),
        32,
        "the window row is 32 bytes"
    );
    // Default is the all-zero row: kind SPAN, zero-length span —
    // the never-active belt, never a surprise verdict.
    assert_eq!(PolicyWindow::default(), win_span(0, 0));
    // The kinds are distinct and SPAN is 0 (a zeroed row reads as
    // a span, not a daily window).
    assert_eq!(WINDOW_KIND_SPAN, 0);
    assert_eq!(WINDOW_KIND_DAILY, 1);
}

// ━━ The DAILY comparator, margin 0: the plain window laws ━━

#[test]
fn daily_window_plain_edges() {
    // 09:00-17:00, no margin.
    let (start, end) = (9 * 3600, 17 * 3600);
    assert!(
        daily_active(secs(9, 0, 0), start, end, 0),
        "start is inclusive"
    );
    assert!(daily_active(secs(12, 30, 0), start, end, 0));
    assert!(
        !daily_active(secs(17, 0, 0), start, end, 0),
        "end is exclusive"
    );
    assert!(!daily_active(secs(8, 59, 59), start, end, 0));
    assert!(!daily_active(secs(17, 0, 1), start, end, 0));
}

#[test]
fn daily_window_midnight_wrap() {
    // 22:00-06:00 — the bedtime shape: six evening hours plus six
    // morning hours, pure arithmetic, no case split the caller
    // could get wrong.
    let (start, end) = (22 * 3600, 6 * 3600);
    assert!(daily_active(secs(22, 0, 0), start, end, 0));
    assert!(daily_active(secs(23, 59, 59), start, end, 0));
    assert!(
        daily_active(secs(0, 0, 0), start, end, 0),
        "midnight is inside the wrap"
    );
    assert!(daily_active(secs(5, 59, 59), start, end, 0));
    assert!(
        !daily_active(secs(6, 0, 0), start, end, 0),
        "wrap end is exclusive"
    );
    assert!(!daily_active(secs(12, 0, 0), start, end, 0));
    assert!(!daily_active(secs(21, 59, 59), start, end, 0));
}

#[test]
fn daily_window_zero_width_is_never_active() {
    // start == end: the parse family refuses it; the belt refuses
    // to interpret it as "all day" (an ambiguous window never
    // silently polices everything).
    let s = 9 * 3600;
    assert!(!daily_active(secs(9, 0, 0), s, s, 0));
    assert!(!daily_active(secs(0, 0, 0), s, s, 0));
    assert!(!daily_active(secs(12, 0, 0), s, s, 0));
}

// ━━ The MARGIN LAW: both edges toward less enforcement ━━

#[test]
fn daily_margin_opens_late() {
    // 09:00-17:00 with the 2s margin: the first two seconds of
    // the window are skipped — the window OPENS late, never
    // before its promised start (over-enforcement impossibility).
    let (start, end) = (9 * 3600, 17 * 3600);
    let m = FIRE_EARLY_NS;
    assert!(!daily_active(secs(9, 0, 0), start, end, m));
    assert!(
        !daily_active(secs(9, 0, 1), start, end, m),
        "1s in is still margin"
    );
    // The boundary is exact: rel == margin is the first ACTIVE ns.
    assert!(
        daily_active(secs(9, 0, 2), start, end, m),
        "rel == margin is active (the exact erosion boundary)"
    );
    assert!(
        !daily_active(secs(9, 0, 2) - 1, start, end, m),
        "one ns earlier is not"
    );
}

#[test]
fn daily_margin_closes_early() {
    // The last two seconds are skipped — the window CLOSES early,
    // so a stale offset (the datapath's computed wall lagging the
    // true wall by at most the margin) can never let enforcement
    // run PAST the promised end.
    let (start, end) = (9 * 3600, 17 * 3600);
    let m = FIRE_EARLY_NS;
    assert!(
        !daily_active(secs(16, 59, 58), start, end, m),
        "2s before end: inactive"
    );
    assert!(
        daily_active(secs(16, 59, 57), start, end, m),
        "3s before end: the last honest active second"
    );
    assert!(
        daily_active(secs(16, 59, 57) + 999_999_999, start, end, m),
        "ns math is exact at the closing edge"
    );
}

#[test]
fn daily_margin_wrap_edges() {
    // 22:00-06:00 with the margin: the wrap window erodes the same
    // 2s from BOTH its own edges (22:00 opens late, 06:00 closes
    // early) — the position-relative formulation needs no wrap
    // case split to keep the law.
    let (start, end) = (22 * 3600, 6 * 3600);
    let m = FIRE_EARLY_NS;
    assert!(!daily_active(secs(22, 0, 0), start, end, m));
    assert!(!daily_active(secs(22, 0, 1), start, end, m));
    assert!(daily_active(secs(22, 0, 2), start, end, m));
    assert!(!daily_active(secs(5, 59, 58), start, end, m));
    assert!(daily_active(secs(5, 59, 57), start, end, m));
    // Midnight stays deep inside.
    assert!(daily_active(secs(0, 0, 0), start, end, m));
}

#[test]
fn daily_margin_shorter_than_two_margins_never_activates() {
    // A 3-second window under a 2s margin is fully consumed: the
    // erosion can only shrink, so at NO point of the day does the
    // comparator flip a too-short window on.
    let (start, end) = (10 * 3600, 10 * 3600 + 3);
    let m = FIRE_EARLY_NS;
    for s in [0u32, 35_999, 36_000, 36_001, 36_002, 36_003, 43_199] {
        assert!(
            !daily_active(u64::from(s) * 1_000_000_000, start, end, m),
            "s={s}: a 3s window under a 2s margin is dead"
        );
    }
    // Without the margin it was alive — the pin that the window
    // itself parses, and only the margin kills it.
    assert!(daily_active(secs(10, 0, 1), start, end, 0));
}

#[test]
fn daily_margin_erosion_is_monotone() {
    // THE SAFETY LAW: the margin can only REMOVE active time.
    // Every point the margin-2s comparator accepts, the margin-0
    // comparator accepts too — sampled across the whole day for
    // the plain and the wrap window.
    let m = FIRE_EARLY_NS;
    for (start, end) in [(9 * 3600, 17 * 3600), (22 * 3600, 6 * 3600), (0, 86_400)] {
        let mut tick: u64 = 0;
        while tick < NS_PER_DAY {
            if daily_active(tick, start, end, m) {
                assert!(
                    daily_active(tick, start, end, 0),
                    "tick {tick}: margin-accepted point must be margin-0-active \
                     (erosion never adds enforcement)"
                );
            }
            tick += 999_999_983; // coprime stride: every test run walks different residues
        }
    }
}

// ━━ The SPAN laws: drift-free, offset-blind ━━

#[test]
fn span_edges() {
    let w = win_span(100, 200);
    assert!(!window_active(&w, 99, 0));
    assert!(window_active(&w, 100, 0), "span start is inclusive");
    assert!(window_active(&w, 199, 0));
    assert!(!window_active(&w, 200, 0), "span end is exclusive");
    assert!(!window_active(&w, 500, 0));
}

#[test]
fn span_zero_length_is_never_active() {
    // The Default row's shape: a zeroed span (start == end)
    // enforces nothing extra — today's behavior, the belt.
    let w = win_span(100, 100);
    assert!(!window_active(&w, 100, 0));
    assert!(!window_active(&w, 0, 0));
    assert!(!window_active(&w, u64::MAX, 0));
}

#[test]
fn span_ignores_the_wall_offset() {
    // The pre-translated monotonic span is drift-free: the offset
    // bridge value (stale, huge, zero) cannot move the verdict —
    // NTP slew and manual date steps are structurally invisible.
    let w = win_span(100, 200);
    let now = 150;
    assert_eq!(window_active(&w, now, 0), window_active(&w, now, 1));
    assert_eq!(
        window_active(&w, now, 0),
        window_active(&w, now, u64::MAX / 2)
    );
    assert_eq!(window_active(&w, now, 0), window_active(&w, now, u64::MAX));
}

// ━━ The verdict totality (hostile inputs stay bounded) ━━

#[test]
fn daily_through_the_offset_bridge() {
    // A DAILY row reads the wall as now + offset: an offset that
    // lands the day-position inside the window is active, one
    // that lands outside is not — the bridge is a pure shift of
    // the day position.
    let w = win_daily(9 * 3600, 17 * 3600);
    // now = 08:00 of day + a large whole-day multiple: any offset
    // that is a multiple of the day keeps the position.
    let base = secs(12, 0, 0);
    let day_mult = 1234 * NS_PER_DAY;
    assert!(window_active(&w, base, day_mult));
    // An offset shifting 5h forward: 12:00 -> 17:00, the exclusive
    // end: inactive.
    assert!(!window_active(&w, base, 5 * 3600 * 1_000_000_000));
    // Shifting 3h forward lands 15:00: inside.
    assert!(window_active(&w, base, 3 * 3600 * 1_000_000_000));
    // Shifting 12h backward (wrapping subtraction on the offset
    // input is the CALLER's arithmetic; here the offset is just
    // smaller): now dominates.
    assert!(
        window_active(&w, base + 20 * NS_PER_DAY, 0),
        "wall days beyond the first wrap fine"
    );
}

#[test]
fn daily_saturating_offset_is_total() {
    // A corrupt offset (u64::MAX territory) saturates the wall
    // computation: the verdict is SOME bounded boolean — never a
    // panic, never a hang. The pin runs the full path.
    let w = win_daily(9 * 3600, 17 * 3600);
    let _ = window_active(&w, 42, u64::MAX);
    let _ = window_active(&w, u64::MAX, u64::MAX);
    let _ = window_active(&w, 0, u64::MAX - 1);
}

#[test]
fn unknown_kind_enforces() {
    // An unreadable window kind answers ACTIVE (enforce): today's
    // behavior exactly, the absent-entry verdict — the feature
    // refines enforcement, never degrades it.
    let mut w = win_span(100, 200);
    w.kind = 7;
    assert!(window_active(&w, 150, 0));
    assert!(window_active(&w, 0, 0));
    assert!(window_active(&w, u64::MAX, 0));
    w.kind = u32::MAX;
    assert!(window_active(&w, 150, 0));
}

// ━━ The sweep predicates ━━

#[test]
fn span_ended_is_the_only_removal_predicate() {
    let w = win_span(100, 200);
    assert!(!span_ended(&w, 99), "not yet started: survives");
    assert!(!span_ended(&w, 100), "just started: survives");
    assert!(!span_ended(&w, 199), "active: survives");
    assert!(
        span_ended(&w, 200),
        "the exclusive end IS the end for the sweep"
    );
    assert!(span_ended(&w, 500));
}

#[test]
fn daily_never_ends_and_never_sleeps() {
    // A recurring window is immortal from the sweep's view: no
    // `now` ends it and none finds it dormant.
    let w = win_daily(22 * 3600, 6 * 3600);
    assert!(!span_ended(&w, 0));
    assert!(!span_ended(&w, u64::MAX));
    assert!(!span_dormant(&w, 0));
    assert!(!span_dormant(&w, u64::MAX));
}

#[test]
fn span_dormant_names_the_future_date_shape() {
    // A span that has not started is DORMANT (a future-date row):
    // the status surface names it, the sweep spares it.
    let w = win_span(10_000, 20_000);
    assert!(span_dormant(&w, 9_999));
    assert!(!span_dormant(&w, 10_000));
    assert!(!span_dormant(&w, 15_000));
    assert!(
        !span_dormant(&w, 25_000),
        "an ENDED span is not dormant — the sweep takes it"
    );
}

// ━━ THE TWIN GRID (the userspace verdict == the kernel verdict) ━━

#[test]
fn twin_matches_the_kernel_core_on_the_grid() {
    // The userspace twin (crate::ebpf::limiter::during) vs the
    // kernel core compiled above: for any (wall, mono) pair the
    // twin answers exactly what the datapath would with a freshly
    // stamped bridge — saturation domain included (the twin
    // computes the effective wall the same saturating way the
    // bridge stamp does).
    use self::ebpf_during::window_active as kernel_active;
    use crate::ebpf::limiter::during::{wall_minus_mono, window_active_user};
    use crate::ebpf::limiter::types::PolicyWindowRaw;

    let windows = [
        (WINDOW_KIND_DAILY, 9 * 3600, 17 * 3600, 0u64, 0u64),
        (WINDOW_KIND_DAILY, 22 * 3600, 6 * 3600, 0, 0),
        (WINDOW_KIND_DAILY, 0, 86_400 - 1, 0, 0),
        (WINDOW_KIND_SPAN, 0, 0, 100u64, 200u64),
        (WINDOW_KIND_SPAN, 0, 0, 0, u64::MAX / 4),
    ];
    let walls = [
        0u64,
        1_000_000_000u64,
        12 * 3600 * 1_000_000_000u64,
        23 * 3600 * 1_000_000_000u64 + 999_999_999,
        (50 * 365) as u64 * 86_400_000_000_000,
    ];
    let monos = [
        0u64,
        1_000_000_000u64,
        17 * 1_000_000_000u64,
        10_000 * 1_000_000_000u64,
    ];
    for (kind, start_s, end_s, start_mono, end_mono) in windows {
        let user_row = PolicyWindowRaw {
            kind,
            reserved: 0,
            start_mono_ns: start_mono,
            end_mono_ns: end_mono,
            start_s,
            end_s,
        };
        let kernel_row = PolicyWindow {
            kind,
            reserved: 0,
            start_mono_ns: start_mono,
            end_mono_ns: end_mono,
            start_s,
            end_s,
        };
        for wall in walls {
            for mono in monos {
                let offset = wall_minus_mono(wall, mono);
                let twin = window_active_user(&user_row, wall, mono);
                let kernel = kernel_active(&kernel_row, mono, offset);
                assert_eq!(
                    twin, kernel,
                    "twin drift at kind={kind} wall={wall} mono={mono}: \
                     twin={twin} kernel={kernel}"
                );
            }
        }
    }
}
