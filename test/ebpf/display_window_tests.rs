// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! Unit pins for the status window family — the human lane's
//! lifetime line, the apply epilogue's window echo, and the census
//! join (night-during, schema v23; night-dragon-fly-1 rev 5 split
//! the family out of display_tests.rs when the echo pin grew the
//! parent past the 600-LOC owner cap — the pacing/quota sibling
//! lineage). #[path]-wired from display.rs beside the parent, the
//! same `use super::*` scope.

use super::*;

/// The five lifetime shapes a row with a window renders, pinned to
/// their exact wording (the owner checks this table against the CLI
/// promise — the wording IS the promise): the active span names its
/// end and its countdown, the dormant span its wake, the ended span
/// its expiry (warn yellow — the one state to notice), the daily
/// pair its hours with the active/outside verdict.
#[test]
fn window_lifetime_line_pins_all_five_shapes() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
    // The clock pair: wall 2026-10-06 12:00:00 UTC (the exact
    // epoch instant, so the day-level assertions below are
    // deterministic), mono 60s.
    let mono = 60 * 1_000_000_000u64;
    let wall = 1_791_288_000_000_000_000u64;

    let active_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono + 47 * 60 * 1_000_000_000,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&active_span, wall, mono);
    assert!(
        line.contains("window: until 2026-10-06") && line.contains("(47m left)"),
        "active span: {line}"
    );

    let dormant_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: mono + 3600 * 1_000_000_000,
        end_mono_ns: mono + 7200 * 1_000_000_000,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&dormant_span, wall, mono);
    assert!(
        line.contains("window: sleeps until 2026-10-06 13:"),
        "dormant span: {line}"
    );

    let ended_span = PolicyWindowRaw {
        kind: WINDOW_KIND_SPAN,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: mono,
        start_s: 0,
        end_s: 0,
    };
    let line = window_lifetime_line(&ended_span, wall, mono);
    assert!(
        line.contains("window: expired at") && line.contains("(awaiting sweep)"),
        "ended span: {line}"
    );

    // The anchor is 12:00 UTC inside 09:00-17:00: active.
    let active_daily = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 9 * 3600,
        end_s: 17 * 3600,
    };
    let line = window_lifetime_line(&active_daily, wall, mono);
    assert!(
        line.contains("window: daily 09:00-17:00 UTC (active)"),
        "active daily: {line}"
    );

    let outside_daily = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 22 * 3600,
        end_s: 6 * 3600,
    };
    let line = window_lifetime_line(&outside_daily, wall, mono);
    assert!(
        line.contains("window: daily 22:00-06:00 UTC (outside — not policing now)"),
        "outside daily: {line}"
    );
}

/// The apply epilogue's window echo (night-dragon-fly-1 rev 5): the
/// --during promise named at the moment it is made — the wall instant
/// the span ends plus the operator's own spelling of the duration,
/// the same two facts the lifetime line keeps current at every
/// status visit. Pinned on the same clock pair the shapes above ride.
#[test]
fn window_apply_echo_pins_the_promise_line() {
    // wall 2026-10-06 12:00:00 UTC, 30 minutes out: the echo answers
    // 12:30:00 UTC and repeats the OPERATOR'S OWN spelling — the
    // flag's `mn` unit is months, and the raw echo is what makes a
    // `30mn` acceptance read as two-plus years the moment it lands
    // (the manual's H3 trap, decided at acceptance time).
    let wall = 1_791_288_000_000_000_000u64;
    let line = window_apply_echo(30 * 60 * 1_000_000_000u64, "30m", wall);
    assert_eq!(
        line, "window: lifts itself at 2026-10-06 12:30:00 UTC (30m)",
        "the echo names the instant and the typed spelling: {line}"
    );
    // Two hours: the hour grammar, the operator's words back.
    let line = window_apply_echo(2 * 3600 * 1_000_000_000u64, "2h", wall);
    assert_eq!(
        line, "window: lifts itself at 2026-10-06 14:00:00 UTC (2h)",
        "the hour shape: {line}"
    );
    // The months trap: 30mn is 900 days — the raw spelling rides
    // verbatim beside the resolved instant, no re-spelling.
    let line = window_apply_echo(900 * 86_400 * 1_000_000_000u64, "30mn", wall);
    assert_eq!(
        line, "window: lifts itself at 2029-03-24 12:00:00 UTC (30mn)",
        "the months shape carries the typed unit: {line}"
    );
}

/// The window join: a row whose cgroup carries a window renders the
/// lifetime line under it; a row without one renders none (the
/// additive-field rule — the table stays exactly what it was for
/// every --during-less row).
#[test]
fn collect_display_data_joins_windows_by_cgroup() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_SPAN};
    let dl = vec![(101u32, PolicyRaw::default())];
    let windows = vec![(
        101u32,
        PolicyWindowRaw {
            kind: WINDOW_KIND_SPAN,
            reserved: 0,
            start_mono_ns: 0,
            end_mono_ns: 10,
            start_s: 0,
            end_s: 0,
        },
    )];
    // night-recvn-audit (schema v30): the RECWN lane join the Layer 4
    // estimate once rode came out with the estimate — the census call
    // takes policies, stats, and windows only.
    let data = collect_display_data(&dl, &[], &[], &windows);
    assert!(data[0].window.is_some(), "the window joins its row");
    let data = collect_display_data(&dl, &[], &[], &[]);
    assert!(data[0].window.is_none(), "absent window = no lifetime line");
}
