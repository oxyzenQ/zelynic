// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! night-during, schema v23: rootless pins for the --during
//! userspace half — the grammar family (during_parse.rs), the
//! wall-to-mono translation, the calendar renderer, and the
//! dormancy notes. THE TWIN GRID (window_active_user vs the kernel
//! core's window_active) lives in during_tests.rs beside the core
//! wiring it compares against (the one-load discipline: the core
//! file compiles into this tree exactly once).

use crate::ebpf::limiter::during_parse::{
    days_from_civil, parse_during, DuringSpec, DURING_MAX_NS, DURING_MIN_NS,
};
use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_DAY: u64 = 86_400 * NS_PER_SEC;

/// A fixed wall instant for the pure parse family: 2026-10-06
/// 12:00:00 UTC (the "today" the past-date refusals measure against).
const WALL_NOW: u64 = 1_760_000_000_000_000_000 % (50 * 365 * NS_PER_DAY) + 700_000_000_000_000_000;

/// The parse family's wall anchor, stated exactly: picked so the
/// date tests below are deterministic. 2026-10-06 12:00:00 UTC.
fn wall_anchor() -> u64 {
    // days_from_civil(2026, 10, 6) * NS_PER_DAY + 12h
    (days_from_civil(2026, 10, 6) as u64) * NS_PER_DAY + 12 * 3600 * NS_PER_SEC
}

// ━━ The grammar: the three shapes ━━

#[test]
fn daily_window_parses() {
    assert_eq!(
        parse_during("09:00-17:00", WALL_NOW).unwrap(),
        DuringSpec::Daily {
            start_s: 9 * 3600,
            end_s: 17 * 3600
        }
    );
    // The wrap shape parses to plain seconds-of-day (the comparator
    // owns the wrap law).
    assert_eq!(
        parse_during("22:00-06:00", WALL_NOW).unwrap(),
        DuringSpec::Daily {
            start_s: 22 * 3600,
            end_s: 6 * 3600
        }
    );
    // Whitespace is trimmed (a shell-quoted sloppiness is not a
    // grammar error).
    assert_eq!(
        parse_during(" 09:00-17:00 ", WALL_NOW).unwrap(),
        parse_during("09:00-17:00", WALL_NOW).unwrap()
    );
}

#[test]
fn date_day_parses_to_the_whole_utc_day() {
    let spec = parse_during("2026-10-15", WALL_NOW).unwrap();
    assert_eq!(
        spec,
        DuringSpec::Span {
            start_wall_ns: days_from_civil(2026, 10, 15) as u64 * NS_PER_DAY,
            end_wall_ns: (days_from_civil(2026, 10, 15) + 1) as u64 * NS_PER_DAY,
        }
    );
    // Today (still running at the anchor): the whole day, the
    // already-elapsed morning included.
    assert_eq!(
        parse_during("2026-10-06", wall_anchor()).unwrap(),
        DuringSpec::Span {
            start_wall_ns: days_from_civil(2026, 10, 6) as u64 * NS_PER_DAY,
            end_wall_ns: (days_from_civil(2026, 10, 6) + 1) as u64 * NS_PER_DAY,
        }
    );
    // Leap-year February parses (the calendar is real).
    assert!(parse_during("2028-02-29", WALL_NOW).is_ok());
    assert!(parse_during("2027-02-29", WALL_NOW).is_err());
}

#[test]
fn duration_parses_every_unit() {
    let base = WALL_NOW;
    for (input, ns) in [
        ("1s", NS_PER_SEC),
        ("45s", 45 * NS_PER_SEC),
        ("1m", 60 * NS_PER_SEC),
        ("30m", 1800 * NS_PER_SEC),
        ("2h", 7200 * NS_PER_SEC),
        ("20d", 20 * NS_PER_DAY),
        ("6mn", 6 * 30 * NS_PER_DAY),
        ("10y", 10 * 365 * NS_PER_DAY),
    ] {
        assert_eq!(
            parse_during(input, base).unwrap(),
            DuringSpec::Duration { ns },
            "'{input}' must parse to {ns} ns"
        );
    }
    // The owner's masterclass example: 20d is exactly 20 days.
    assert_eq!(
        parse_during("20d", base).unwrap(),
        DuringSpec::Duration {
            ns: 20 * NS_PER_DAY
        }
    );
}

// ━━ The grammar: every refusal family ━━

#[test]
fn grammar_refusals_carry_the_block() {
    for bad in [
        "",
        "   ",
        "9:00-17:00",
        "09:00-5:00",
        "24:00-06:00",
        "09:00-24:00",
        "09:60-17:00",
        "09:00-17:60",
        "09-17",
        "09:00",
        "09:00-17:00-21:00",
        "09:00-09:00",
        "2",
        "h",
        "2x",
        "1h30m",
        "0s",
        "0d",
        "500ms",
        "10y1s",
        "10000000000y",
        "2026-10",
        "2026-10-15-12",
        "26-10-15",
        "2026-13-01",
        "2026-00-10",
        "2026-10-00",
        "2026-10-32",
        "2026-9-5",
    ] {
        let err = parse_during(bad, WALL_NOW)
            .err()
            .unwrap_or_else(|| panic!("'{bad}' must be refused"));
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid --during")
                || msg.contains("is already over")
                || msg.contains("is outside"),
            "'{bad}' refusal must name the flag: {msg}"
        );
    }
}

#[test]
fn past_date_is_refused_the_future_is_not() {
    // The day fully before the anchor: a corpse, refused.
    assert!(parse_during("2026-10-05", wall_anchor()).is_err());
    // Exactly midnight of the NEXT day: the end boundary — the
    // anchor's day is over at the next 00:00, so a wall AT that
    // instant refuses the anchor day too.
    let next_midnight = (days_from_civil(2026, 10, 7) as u64) * NS_PER_DAY;
    assert!(parse_during("2026-10-06", next_midnight).is_err());
    // One nanosecond before: still alive.
    assert!(parse_during("2026-10-06", next_midnight - 1).is_ok());
    // A far-but-representable future date parses; a date past the
    // u64 horizon is refused (the u128 belt — a clamp would promise
    // the wrong century).
    assert!(parse_during("2400-01-01", wall_anchor()).is_ok());
    assert!(parse_during("9999-12-31", wall_anchor()).is_err());
}

#[test]
fn duration_bounds_are_pinned() {
    assert_eq!(DURING_MIN_NS, NS_PER_SEC, "the floor is 1s");
    assert_eq!(
        DURING_MAX_NS,
        10 * 365 * NS_PER_DAY,
        "the ceiling is 10 fixed years"
    );
    // 0.5s rounds below the floor: refused (not clamped — a clamp
    // would silently mean "not limited").
    assert!(parse_during("0s", WALL_NOW).is_err());
    // 10y parses; 11y refuses.
    assert!(parse_during("10y", WALL_NOW).is_ok());
    assert!(parse_during("11y", WALL_NOW).is_err());
    // 1s parses; 999ms is not in the grammar at all.
    assert!(parse_during("1s", WALL_NOW).is_ok());
}

// ━━ The calendar ━━

#[test]
fn civil_round_trips() {
    for (y, m, d) in [
        (1970, 1, 1),
        (2000, 2, 29),
        (2026, 10, 6),
        (2024, 12, 31),
        (1999, 12, 31),
        (2100, 3, 1),
    ] {
        let days = days_from_civil(y, m, d);
        assert_eq!(
            crate::ebpf::limiter::during_parse::civil_from_days(days),
            (y, m, d)
        );
    }
    // Known instant: the epoch.
    assert_eq!(days_from_civil(1970, 1, 1), 0);
}

#[test]
fn format_wall_utc_renders_known_instants() {
    use crate::ebpf::limiter::during::format_wall_utc;
    assert_eq!(format_wall_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(format_wall_utc(NS_PER_SEC), "1970-01-01 00:00:01 UTC");
    assert_eq!(format_wall_utc(NS_PER_DAY), "1970-01-02 00:00:00 UTC");
    let day = days_from_civil(2026, 10, 15) as u64 * NS_PER_DAY + 18 * 3600 * NS_PER_SEC;
    assert_eq!(format_wall_utc(day), "2026-10-15 18:00:00 UTC");
}

// ━━ The translation ━━

#[test]
fn duration_translates_to_a_running_span() {
    use crate::ebpf::limiter::during::{during_to_window, wall_now_ns};
    let _ = wall_now_ns(); // the impure shell compiles in this tree too
    let mono = 10 * NS_PER_SEC;
    let wall = 1_700_000_000 * NS_PER_SEC;
    let row = during_to_window(
        &DuringSpec::Duration {
            ns: 2 * 3600 * NS_PER_SEC,
        },
        wall,
        mono,
    );
    assert_eq!(row.kind, WINDOW_KIND_SPAN);
    assert_eq!(
        row.start_mono_ns, mono,
        "a duration starts at the apply instant"
    );
    assert_eq!(row.end_mono_ns, mono + 2 * 3600 * NS_PER_SEC);
}

#[test]
fn span_translates_across_the_clock_pair() {
    use crate::ebpf::limiter::during::during_to_window;
    let mono = 5 * NS_PER_SEC;
    let wall = 1_700_000_000 * NS_PER_SEC;
    let start_wall = wall - NS_PER_SEC; // started 1s before the apply
    let end_wall = wall + 100 * NS_PER_SEC;
    let row = during_to_window(
        &DuringSpec::Span {
            start_wall_ns: start_wall,
            end_wall_ns: end_wall,
        },
        wall,
        mono,
    );
    // start = mono - (wall - start_wall) = 5s - 1s = 4s.
    assert_eq!(row.start_mono_ns, 4 * NS_PER_SEC);
    assert_eq!(row.end_mono_ns, mono + 100 * NS_PER_SEC);
    // A start before the host booted clamps to "since boot".
    let ancient = during_to_window(
        &DuringSpec::Span {
            start_wall_ns: 0,
            end_wall_ns: end_wall,
        },
        wall,
        mono,
    );
    assert_eq!(ancient.start_mono_ns, 0, "a pre-boot start saturates to 0");
}

#[test]
fn future_date_span_sleeps_until_its_day() {
    use crate::ebpf::limiter::during::during_to_window;
    let mono = 5 * NS_PER_SEC;
    let wall = 1_700_000_000 * NS_PER_SEC;
    // A future date: the day starts 9 days out and ends 10 days out
    // (the --during 2026-10-15 shape applied 9 days early).
    let start_wall = wall + 9 * NS_PER_DAY;
    let end_wall = wall + 10 * NS_PER_DAY;
    let row = during_to_window(
        &DuringSpec::Span {
            start_wall_ns: start_wall,
            end_wall_ns: end_wall,
        },
        wall,
        mono,
    );
    // The dormancy law: the row sleeps until its day arrives — the
    // future start translates FORWARD into the monotonic domain,
    // it must never collapse onto the apply instant.
    assert_eq!(
        row.start_mono_ns,
        mono + 9 * NS_PER_DAY,
        "a future start sleeps until its instant: start_mono={}",
        row.start_mono_ns
    );
    assert_eq!(row.end_mono_ns, mono + 10 * NS_PER_DAY);
    assert!(
        row.start_mono_ns > mono,
        "a freshly applied future date is dormant at the apply instant"
    );
}

#[test]
fn daily_translates_verbatim() {
    use crate::ebpf::limiter::during::during_to_window;
    let row = during_to_window(
        &DuringSpec::Daily {
            start_s: 22 * 3600,
            end_s: 6 * 3600,
        },
        WALL_NOW,
        5 * NS_PER_SEC,
    );
    assert_eq!(row.kind, WINDOW_KIND_DAILY);
    assert_eq!(row.start_s, 22 * 3600);
    assert_eq!(row.end_s, 6 * 3600);
    assert_eq!(row.start_mono_ns, 0);
    assert_eq!(row.end_mono_ns, 0);
}

// ━━ The dormancy notes (the probe's stand-down wording) ━━

#[test]
fn dormancy_notes_name_the_three_shapes() {
    use crate::ebpf::limiter::during::dormancy_note;
    let wall = wall_anchor();
    let mono = 60 * NS_PER_SEC;
    // A dormant future span: sleeps until, rendered as wall UTC.
    let dormant = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: mono + 3600 * NS_PER_SEC,
        end_mono_ns: mono + 7200 * NS_PER_SEC,
        start_s: 0,
        end_s: 0,
    };
    let note = dormancy_note(&dormant, wall, mono).unwrap();
    assert!(
        note.contains("sleeps until 2026-10-06 13:0"),
        "the dormant note names the wake instant: {note}"
    );
    // An active span: no note.
    let active = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono + NS_PER_SEC,
        start_s: 0,
        end_s: 0,
    };
    assert!(dormancy_note(&active, wall, mono).is_none());
    // An ended span: expired, awaiting sweep.
    let ended = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono,
        start_s: 0,
        end_s: 0,
    };
    let note = dormancy_note(&ended, wall, mono).unwrap();
    assert!(
        note.contains("expired at") && note.contains("awaiting sweep"),
        "the ended note names expiry: {note}"
    );
    // A daily window outside its hours (the anchor is 12:00 UTC).
    let outside = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 22 * 3600,
        end_s: 6 * 3600,
    };
    let note = dormancy_note(&outside, wall, mono).unwrap();
    assert!(
        note.contains("outside the daily window 22:00-06:00 UTC"),
        "the daily note names the hours: {note}"
    );
    // An unknown kind enforces: no note (the absent-entry verdict).
    let mut corrupt = outside;
    corrupt.kind = 7;
    assert!(dormancy_note(&corrupt, wall, mono).is_none());
}

// ━━ The status vocabulary + the persistence round-trip ━━

#[test]
fn window_state_names_the_four_states() {
    use crate::ebpf::limiter::during::window_state;
    use crate::ebpf::limiter::types::{WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
    // The anchor is 12:00 UTC (inside 09:00-17:00, outside 22:00-06:00).
    let wall = 1_791_288_000_000_000_000u64;
    let mono = 60 * 1_000_000_000u64;
    let span = |s: u64, e: u64| PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: s,
        end_mono_ns: e,
        start_s: 0,
        end_s: 0,
    };
    let daily = |s: u32, e: u32| PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: s,
        end_s: e,
    };
    assert_eq!(window_state(&span(0, mono + 1), wall, mono), "active");
    assert_eq!(
        window_state(&span(mono + 1, mono + 2), wall, mono),
        "dormant"
    );
    assert_eq!(window_state(&span(0, mono), wall, mono), "expired");
    assert_eq!(
        window_state(&daily(9 * 3600, 17 * 3600), wall, mono),
        "active"
    );
    assert_eq!(
        window_state(&daily(22 * 3600, 6 * 3600), wall, mono),
        "outside"
    );
    // Unknown kinds are "active" (the absent-entry verdict).
    let mut corrupt = daily(0, 10);
    corrupt.kind = 7;
    assert_eq!(window_state(&corrupt, wall, mono), "active");
}

#[test]
fn window_persistence_round_trips_both_shapes() {
    use crate::ebpf::limiter::during::{window_persist_form, window_persist_to_spec};
    use crate::ebpf::limiter::types::WINDOW_KIND_SPAN;
    let wall = 1_791_288_000_000_000_000u64;
    let mono = 5 * 1_000_000_000u64;
    // A span: the wall instants reconstruct through the offset pair
    // (start_wall = mono_start + (wall - mono)).
    let offset = wall - mono;
    let row = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 10 * 1_000_000_000,
        end_mono_ns: 3600 * 1_000_000_000,
        start_s: 0,
        end_s: 0,
    };
    let form = window_persist_form(&row, wall, mono);
    assert_eq!(form.kind, "span");
    assert_eq!(form.start_wall_ns, 10 * 1_000_000_000 + offset);
    assert_eq!(form.end_wall_ns, 3600 * 1_000_000_000 + offset);
    assert_eq!(
        window_persist_to_spec(&form),
        Some(DuringSpec::Span {
            start_wall_ns: 10 * 1_000_000_000 + offset,
            end_wall_ns: 3600 * 1_000_000_000 + offset,
        }),
        "the span round-trips through its wall form"
    );
    // A daily: the pair verbatim.
    let daily_row = PolicyWindowRaw {
        kind: crate::ebpf::limiter::types::WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 22 * 3600,
        end_s: 6 * 3600,
    };
    let form = window_persist_form(&daily_row, wall, mono);
    assert_eq!(form.kind, "daily");
    assert_eq!(form.start_s, 22 * 3600);
    assert_eq!(form.end_s, 6 * 3600);
    assert_eq!(
        window_persist_to_spec(&form),
        Some(DuringSpec::Daily {
            start_s: 22 * 3600,
            end_s: 6 * 3600
        })
    );
    // A corrupt kind name refuses — never a best-guess parse.
    let mut bad = form;
    bad.kind = "whenever".to_string();
    assert!(window_persist_to_spec(&bad).is_none());
}
