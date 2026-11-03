// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// The pacing sweep-line pins (the recwn_flush_lines_tests
// discipline, one lane over): the wording is part of the verbose
// diagnostic contract — exact strings, pinned.

use super::pace_hint_failed_line;
use super::pace_hint_trace_line;

#[test]
fn the_sweep_trace_line_pins_both_states() {
    assert_eq!(
        pace_hint_trace_line(0),
        "[limiter] pace hint map: 0 rows — no egress pacing hints stood"
    );
    assert_eq!(
        pace_hint_trace_line(1),
        "[limiter] pace hint map: swept 1 row — each covered socket answers the kernel's default pacing on its next callback"
    );
    assert_eq!(
        pace_hint_trace_line(3),
        "[limiter] pace hint map: swept 3 rows — each covered socket answers the kernel's default pacing on its next callback"
    );
}

#[test]
fn the_sweep_failure_line_names_the_recovery() {
    assert_eq!(
        pace_hint_failed_line("ENOENT"),
        "pace hint sweep failed (ENOENT) — a removed policy's last pacing rate can linger on its live connections until they close; run 'zelynic recover' if this persists"
    );
}
