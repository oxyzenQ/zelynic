// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Warning-specific tests for delta JSON output.

use super::*;

// ── Warnings: counter reset appended ────────────────────────────────

#[test]
fn counter_reset_warnings_appended() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_RESET);
    let output = build_delta_json_success(&start, &end);
    assert!(output.warnings.len() > 13);
    let has_reset_warning = output.warnings.iter().any(|w| {
        w.contains("counter reset detected") && w.contains("wlan0") && w.contains("rx_bytes")
    });
    assert!(has_reset_warning);
}

// ── Warnings: default 13 ───────────────────────────────────────────

#[test]
fn default_warnings_has_13_entries() {
    let warnings = delta_default_warnings();
    assert_eq!(warnings.len(), 13);
}

#[test]
fn default_warnings_include_counter_reset_warning() {
    let warnings = delta_default_warnings();
    assert!(warnings.iter().any(|w| w.contains("counters may reset")));
}

#[test]
fn default_warnings_include_delta_incomplete_warning() {
    let warnings = delta_default_warnings();
    assert!(warnings
        .iter()
        .any(|w| w.contains("delta may be incomplete")));
}

#[test]
fn default_warnings_include_not_per_app() {
    let warnings = delta_default_warnings();
    assert!(warnings.iter().any(|w| w.contains("per-app")));
}

#[test]
fn success_output_includes_all_13_default_warnings() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert!(output.warnings.len() >= 13);
}
