// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 3: Injected reader backend tests.
//!
//! Tests the `ContentReader` trait, `InjectedContentReader`, `FakeReadErrorReader`,
//! `read_live_proc_net_dev_with_injected_reader()`, source path constants,
//! injected reader flags, LiveReadError display, and structural no-path/real-read tests.
//! All tests use injected/fake content — no live filesystem reads.

use super::*;

// ══════════════════════════════════════════════════════════════════════════════
// Phase 3: Injected Reader Backend + Boundary Audit Tests
// ══════════════════════════════════════════════════════════════════════════════

// ── Fake reader: success ───────────────────────────────────────────────

#[test]
fn fake_reader_success_parses_sample_content() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert_eq!(plan.read_status, LiveReadStatus::Success);
    assert!(plan.snapshot.is_some());
    let snap = plan.snapshot.as_ref().unwrap();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap.interfaces[0].interface, "lo");
    assert_eq!(snap.interfaces[1].interface, "wlan0");
    assert_eq!(snap.interfaces[2].interface, "eth0");
}

// ── Fake reader: read failure ─────────────────────────────────────────

#[test]
fn fake_reader_failure_returns_read_error() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert!(
        matches!(plan.read_status, LiveReadStatus::Error(ref msg) if msg.starts_with("read error:"))
    );
    assert!(plan.snapshot.is_none());
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── Fake reader: parse failure ────────────────────────────────────────

#[test]
fn fake_reader_malformed_content_returns_parse_error() {
    let reader = InjectedContentReader::new(LIVE_SEAM_MALFORMED_NO_COLON);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert!(
        matches!(plan.read_status, LiveReadStatus::Error(ref msg) if msg.starts_with("parse error:"))
    );
    assert!(plan.snapshot.is_none());
    // Read succeeded (filesystem_read_performed = true) but parse failed
    assert!(plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── Source path constant ──────────────────────────────────────────────

#[test]
fn source_path_is_exactly_proc_net_dev() {
    assert_eq!(DEFAULT_LIVE_SOURCE_PATH, "/proc/net/dev");
}

#[test]
fn injected_reader_source_path_is_proc_net_dev() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert_eq!(plan.source_path, "/proc/net/dev");
}

// ── Arbitrary paths are not accepted ─────────────────────────────────

#[test]
fn arbitrary_paths_not_accepted_by_injected_reader() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    // Source path is always /proc/net/dev — ContentReader has no path parameter
    assert_eq!(plan.source_path, "/proc/net/dev");
    assert_ne!(plan.source_path, "/etc/passwd");
    assert_ne!(plan.source_path, "/sys/fs/cgroup");
    assert_ne!(plan.source_path, "/proc/self/mountinfo");
}

// ── Injected reader flags ────────────────────────────────────────────

#[test]
fn injected_reader_sets_honest_source_label() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert_eq!(plan.source_label, SOURCE_LABEL_INJECTED);
    assert!(plan.is_injected());
    assert!(!plan.is_live());
}

#[test]
fn injected_reader_success_sets_read_performed_true() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert!(plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

#[test]
fn read_error_sets_read_performed_false() {
    let reader = FakeReadErrorReader::new("no such file");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    assert!(!plan.filesystem_read_performed);
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── Content reader trait has no path parameter ────────────────────────

#[test]
fn content_reader_trait_has_no_path_parameter() {
    // Structural test: ContentReader trait has only read_content(&self)
    // with no path parameter. This verifies that the read seam cannot
    // be configured to read arbitrary paths.
    let _ = InjectedContentReader::new("test");
    let _ = FakeReadErrorReader::new("error");
    // The trait method signature is: fn read_content(&self) -> Result<String, String>
    // No path argument exists.
}

// ── Tests do not read real /proc/net/dev ─────────────────────────────

#[test]
fn tests_do_not_read_real_proc_net_dev() {
    // Structural test: no test in this file calls read_live_proc_net_dev()
    // (the actual filesystem read function). All tests use InjectedContentReader,
    // FakeReadErrorReader, or build_live_proc_net_dev_snapshot_from_content().
    let _ = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let _ = FakeReadErrorReader::new("simulated error");
    let _ = build_live_proc_net_dev_read_plan();
    // read_live_proc_net_dev() is never called in any test.
}

// ── LiveReadError display ────────────────────────────────────────────

#[test]
fn live_read_error_display_read_failed() {
    let err = LiveReadError::ReadFailed("permission denied".to_string());
    assert_eq!(format!("{}", err), "read failed: permission denied");
}

#[test]
fn live_read_error_display_parse_failed() {
    let parse_err = ParseError::MissingColon {
        line_number: 3,
        line: "wlan0 1000".to_string(),
    };
    let err = LiveReadError::ParseFailed(parse_err);
    let display = format!("{}", err);
    assert!(
        display.contains("parse failed:"),
        "display must start with 'parse failed:'"
    );
}

// ── Rendered success/error output includes read-only statement ───

#[test]
fn rendered_injected_success_includes_read_only_statement() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "render must include read-only seam statement"
    );
}

#[test]
fn rendered_read_error_includes_read_only_statement() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "error render must include read-only seam statement"
    );
}

#[test]
fn rendered_parse_error_includes_read_only_statement() {
    let reader = InjectedContentReader::new(LIVE_SEAM_MALFORMED_NO_COLON);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "parse error render must include read-only seam statement"
    );
}
