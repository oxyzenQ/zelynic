// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-spark-2 (RECWN): the hint-sweep line pins — the mmspa
//! flush-lines discipline one lane over. The wording is the
//! verbose-diagnostic contract; the counts are honest plurals.

use super::super::recwn::{hint_flush_failed_line, hint_flush_trace_line};

#[test]
fn sweep_trace_line_pins_both_counts() {
    assert_eq!(
        hint_flush_trace_line(0),
        "[limiter] recwn hint map: 0 rows — no receive-window hints stood"
    );
    assert_eq!(
        hint_flush_trace_line(1),
        "[limiter] recwn hint map: swept 1 row — each covered socket answers \
         the OS default window on its next callback"
    );
    assert_eq!(
        hint_flush_trace_line(4096),
        "[limiter] recwn hint map: swept 4096 rows — each covered socket answers \
         the OS default window on its next callback"
    );
}

#[test]
fn sweep_failed_line_names_the_degradation() {
    let line = hint_flush_failed_line("pin unreadable");
    assert!(
        line.starts_with("recwn hint sweep failed (pin unreadable) — a removed policy's last"),
        "the failure line must name the cause first: {line}"
    );
    assert!(
        line.contains("'zelynic recover'"),
        "the failure line must name the repair command: {line}"
    );
}
