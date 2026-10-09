// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! night-during, schema v23 (the owner's duration-only revision):
//! rootless pins for the --during userspace half — the grammar
//! family (during_parse.rs: the flag's ONE shape, and the removed
//! window/date shapes refusing by name), the wall-to-mono
//! translation (the LEGACY MAP ROW variants included — a row an
//! older build pinned in the map keeps its promise), the calendar
//! renderer, and the dormancy notes. THE TWIN GRID
//! (window_active_user vs the kernel core's window_active) lives
//! in during_tests.rs beside the core wiring it compares against
//! (the one-load discipline: the core file compiles into this
//! tree exactly once).
//!
//! NIGHT-improve-55: the persistence round-trip grid that lived
//! here went with the snapshot/restore pair when the owner retired
//! the feature whole — the wall form had no reader left.

use crate::ebpf::limiter::during_parse::{DURING_MAX_NS, DURING_MIN_NS, DuringSpec, parse_during};
use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_DAY: u64 = 86_400 * NS_PER_SEC;

/// Days from the epoch to 2026-10-06 (the anchor the dormancy
/// renders measure against), hardcoded: the parse family no
/// longer carries a calendar helper (the date form is gone), so
/// the test tree states the day count itself — the renderer's
/// own pins verify the calendar below.
const DAYS_TO_2026_10_06: i64 = 20_732;

/// The tests' wall anchor, stated exactly: 2026-10-06 12:00:00
/// UTC.
fn wall_anchor() -> u64 {
    DAYS_TO_2026_10_06 as u64 * NS_PER_DAY + 12 * 3600 * NS_PER_SEC
}

// ━━ The grammar: one shape, the duration ━━

#[test]
fn duration_parses_every_unit() {
    for (input, ns) in [
        ("1s", NS_PER_SEC),
        ("45s", 45 * NS_PER_SEC),
        ("1m", 60 * NS_PER_SEC),
        ("30m", 1800 * NS_PER_SEC),
        ("2h", 7200 * NS_PER_SEC),
        ("20d", 20 * NS_PER_DAY),
        ("6mn", 6 * 30 * NS_PER_DAY),
        ("5y", 5 * 365 * NS_PER_DAY),
    ] {
        assert_eq!(
            parse_during(input).unwrap(),
            DuringSpec::Duration { ns },
            "'{input}' must parse to {ns} ns"
        );
    }
    // The owner's masterclass example: 20d is exactly 20 days.
    assert_eq!(
        parse_during("20d").unwrap(),
        DuringSpec::Duration {
            ns: 20 * NS_PER_DAY
        }
    );
    // Whitespace is trimmed (a shell-quoted sloppiness is not a
    // grammar error).
    assert_eq!(
        parse_during(" 20d ").unwrap(),
        DuringSpec::Duration {
            ns: 20 * NS_PER_DAY
        }
    );
}

// ━━ The grammar: the shapes that are gone ━━

#[test]
fn window_forms_are_gone() {
    // The recurring-daily shape the flag no longer takes: every
    // spelling refuses, the wording naming the removed shape and
    // the duration that replaced it (the owner's revision).
    for gone in [
        "09:00-17:00",
        "22:00-06:00",
        " 09:00-17:00 ",
        "09:00",
        "09:00-09:00",
        "24:00-06:00",
    ] {
        let err = parse_during(gone)
            .err()
            .unwrap_or_else(|| panic!("'{gone}' must be refused"));
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid --during") && msg.contains("window form"),
            "'{gone}' refusal must name the removed shape: {msg}"
        );
    }
}

#[test]
fn date_forms_are_gone() {
    // The whole-UTC-day shape the flag no longer takes: refused
    // by name, whatever the calendar would have said about it.
    for gone in [
        "2026-10-15",
        "2028-02-29",
        "2027-02-29",
        "2026-10",
        "26-10-15",
        "2026-13-01",
    ] {
        let err = parse_during(gone)
            .err()
            .unwrap_or_else(|| panic!("'{gone}' must be refused"));
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid --during") && msg.contains("date form"),
            "'{gone}' refusal must name the removed shape: {msg}"
        );
    }
}

// ━━ The grammar: every refusal family ━━

#[test]
fn grammar_refusals_carry_the_block() {
    for bad in [
        "",
        "   ",
        "2",
        "h",
        "2x",
        "1h30m",
        "0s",
        "0d",
        "500ms",
        "10y1s",
        "10000000000y",
        "6y",
        "5y1s",
    ] {
        let err = parse_during(bad)
            .err()
            .unwrap_or_else(|| panic!("'{bad}' must be refused"));
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid --during"),
            "'{bad}' refusal must name the flag: {msg}"
        );
    }
}

#[test]
fn duration_bounds_are_pinned() {
    assert_eq!(DURING_MIN_NS, NS_PER_SEC, "the floor is 1s");
    assert_eq!(
        DURING_MAX_NS,
        5 * 365 * NS_PER_DAY,
        "the ceiling is 5 fixed years (night-improve-60, was 10)"
    );
    // 0.5s rounds below the floor: refused (not clamped — a clamp
    // would silently mean "not limited").
    assert!(parse_during("0s").is_err());
    // 5y parses; 6y refuses.
    assert!(parse_during("5y").is_ok());
    assert!(parse_during("6y").is_err());
    // 1s parses; 999ms is not in the grammar at all.
    assert!(parse_during("1s").is_ok());
}

// ━━ The calendar ━━

#[test]
fn format_wall_utc_renders_known_instants() {
    use crate::ebpf::limiter::during::format_wall_utc;
    assert_eq!(format_wall_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(format_wall_utc(NS_PER_SEC), "1970-01-01 00:00:01 UTC");
    assert_eq!(format_wall_utc(NS_PER_DAY), "1970-01-02 00:00:00 UTC");
    // 20741 days = 2026-10-15 (hardcoded the way the anchor above
    // is: the renderer still owns the wall-clock surface the
    // status lines print, so its calendar stays pinned on known
    // instants).
    let day = 20_741 * NS_PER_DAY + 18 * 3600 * NS_PER_SEC;
    assert_eq!(format_wall_utc(day), "2026-10-15 18:00:00 UTC");
}

// ━━ The translation ━━

#[test]
fn duration_translates_to_a_running_span() {
    use crate::ebpf::limiter::during::{during_to_window, wall_now_ns};
    let _ = wall_now_ns(); // the impure shell compiles in this tree too
    let mono = 10 * NS_PER_SEC;
    let row = during_to_window(
        &DuringSpec::Duration {
            ns: 2 * 3600 * NS_PER_SEC,
        },
        mono,
    );
    assert_eq!(row.kind, WINDOW_KIND_SPAN);
    assert_eq!(
        row.start_mono_ns, mono,
        "a duration starts at the apply instant"
    );
    assert_eq!(row.end_mono_ns, mono + 2 * 3600 * NS_PER_SEC);
}

// NIGHT-improve-55: the span/daily translation pins that lived
// here went with the restore lane — DuringSpec's Span/Daily
// variants were the snapshot file's read-side vocabulary, and
// they have no constructor left. The LEGACY MAP ROW contract
// (dormant spans sleeping until their instant, daily rows honoring
// their hours) stays pinned where it lives: window_state and the
// dormancy-note grids above, PolicyWindowRaw level, the runtime
// never forgetting a promised row.

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

// ━━ The status vocabulary ━━

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
