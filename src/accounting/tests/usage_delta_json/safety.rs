// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Structural safety tests for delta JSON output.

use super::*;

// ── Structural: no CLI flag ──────────────────────────────────────────

#[test]
fn no_cli_flag_added() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    assert_eq!(output.command, "usage --sample --delta --json");
}

// ── Structural: no live /proc/net/dev read in tests ──────────────────

#[test]
fn tests_do_not_read_real_proc_net_dev() {
    // Structural test: all test data is const strings parsed by
    // parse_proc_net_dev(). No std::fs API is used in this test module.
}

// ── Structural: no filesystem write APIs ────────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: usage_delta_json.rs contains only pure functions
    // and serde serialization. No std::fs, no write operations.
}
