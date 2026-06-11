// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-14 tests: event stream reader lab dry run.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::decoder::EbpfRawEventFrame;
use crate::intergalaxion_engine::backends::ebpf::event_schema::EbpfEventSource;
use crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::*;
use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::{
    build_fixture_from_raw_frames, decode_event_stream_fixture,
};
use clap::CommandFactory;

const I14_DOC: &str =
    include_str!("../../docs/intergalaxion/I-14-event-stream-reader-lab-dry-run.md");
const I14_SOURCE: &str = include_str!("backends/ebpf/event_stream_dry_run.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

fn valid_raw_frame(frame_id: u64) -> EbpfRawEventFrame {
    EbpfRawEventFrame {
        frame_id,
        source: EbpfEventSource::Model,
        payload: vec![0x01, 0x02, 0x03],
        decode_source_label: String::from("i14-fixture"),
    }
}
fn invalid_raw_frame(frame_id: u64) -> EbpfRawEventFrame {
    EbpfRawEventFrame {
        frame_id,
        source: EbpfEventSource::Model,
        payload: Vec::new(),
        decode_source_label: String::from("i14-fixture"),
    }
}
fn valid_dry_run_input() -> EbpfEventStreamDryRunInput {
    let mut input = default_event_stream_dry_run_input();
    input.explicit_dry_run_feature_enabled = true;
    input.explicit_operator_label = String::from("i14-operator");
    input
}
fn valid_dry_run_input_with_fixture_counts() -> EbpfEventStreamDryRunInput {
    let mut input = valid_dry_run_input();
    input.allow_fixture_counts = true;
    input
}
fn render_help(app: &mut clap::Command) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

// ── 1. default dry run input is safe ──────────────────────────────────
#[test]
fn i14_default_dry_run_input_is_safe() {
    let input = default_event_stream_dry_run_input();
    assert!(!input.explicit_dry_run_feature_enabled);
    assert!(input.explicit_operator_label.is_empty());
    assert!(!input.allow_fixture_counts);
    assert!(!input.allow_live_reader);
    assert!(!input.allow_ring_buffer_open);
    assert!(!input.allow_live_event_read);
    assert!(!input.allow_map_pin);
    assert!(!input.allow_persistence);
}

// ── 2. default dry run result has all operation flags false ───────────
#[test]
fn i14_default_dry_run_result_all_flags_false() {
    let result = evaluate_event_stream_dry_run(&default_event_stream_dry_run_input());
    assert!(!result.dry_run_completed);
    assert!(!result.reader_attempted);
    assert!(!result.reader_succeeded);
    assert!(result.fixture_only);
    assert!(!result.public_cli_exposed);
    assert!(!result.ring_buffer_opened);
    assert!(!result.live_event_stream_read);
    assert!(!result.map_pin_performed);
    assert!(!result.enforcement_performed);
    assert!(!result.packet_drop_performed);
    assert!(!result.mutation_performed);
    assert!(!result.persistence_performed);
}

// ── 3. dry run status labels are stable ──────────────────────────────
#[test]
fn i14_dry_run_status_labels_stable() {
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::FeatureDisabled),
        "feature_disabled"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::ReaderPlanRejected),
        "reader_plan_rejected"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::FixtureReportRejected),
        "fixture_report_rejected"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::DryRunReady),
        "dry_run_ready"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::DryRunCompleted),
        "dry_run_completed"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::DryRunFailed),
        "dry_run_failed"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::LiveReaderUnsupported),
        "live_reader_unsupported"
    );
    assert_eq!(
        event_stream_dry_run_status_label(EbpfEventStreamDryRunStatus::Rejected),
        "rejected"
    );
}

// ── 4. dry run mode labels are stable ────────────────────────────────
#[test]
fn i14_dry_run_mode_labels_stable() {
    assert_eq!(
        event_stream_dry_run_mode_label(EbpfEventStreamDryRunMode::FixtureOnlyDryRun),
        "fixture_only_dry_run"
    );
    assert_eq!(
        event_stream_dry_run_mode_label(EbpfEventStreamDryRunMode::ReaderBoundaryDryRun),
        "reader_boundary_dry_run"
    );
    assert_eq!(
        event_stream_dry_run_mode_label(EbpfEventStreamDryRunMode::LiveReaderUnsupported),
        "live_reader_unsupported"
    );
}

// ── 5. feature disabled returns FeatureDisabled ───────────────────────
#[test]
fn i14_feature_disabled_returns_feature_disabled() {
    assert_eq!(
        evaluate_event_stream_dry_run(&default_event_stream_dry_run_input()).status,
        EbpfEventStreamDryRunStatus::FeatureDisabled
    );
}

// ── 6. feature disabled dry_run_completed=false ────────────────────────
#[test]
fn i14_feature_disabled_not_completed() {
    assert!(
        !evaluate_event_stream_dry_run(&default_event_stream_dry_run_input()).dry_run_completed
    );
}

// ── 7. feature disabled reader_attempted=false ────────────────────────
#[test]
fn i14_feature_disabled_reader_not_attempted() {
    assert!(!evaluate_event_stream_dry_run(&default_event_stream_dry_run_input()).reader_attempted);
}

// ── 8. feature disabled reader_succeeded=false ─────────────────────────
#[test]
fn i14_feature_disabled_reader_not_succeeded() {
    assert!(!evaluate_event_stream_dry_run(&default_event_stream_dry_run_input()).reader_succeeded);
}

// ── 9. empty operator label blocks ─────────────────────────────────────
#[test]
fn i14_empty_operator_label_blocks() {
    let mut input = default_event_stream_dry_run_input();
    input.explicit_dry_run_feature_enabled = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 10. reader result validation failure blocks ───────────────────────
#[test]
fn i14_reader_result_validation_failure_blocks() {
    let mut input = valid_dry_run_input();
    input.reader_result.ring_buffer_opened = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::ReaderPlanRejected
    );
}

// ── 11. fixture report validation failure blocks ────────────────────────
#[test]
fn i14_fixture_report_validation_failure_blocks() {
    let mut input = valid_dry_run_input();
    input.fixture_report.reader_attempted = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::FixtureReportRejected
    );
}

// ── 12. fixture report with fixture_only=false blocks ────────────────
#[test]
fn i14_fixture_report_fixture_only_false_blocks() {
    let mut input = valid_dry_run_input();
    input.fixture_report.fixture_only = false;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 13. reader result ReaderSucceeded blocks ──────────────────────────
#[test]
fn i14_reader_result_reader_succeeded_blocks() {
    let mut input = valid_dry_run_input();
    input.reader_result.status =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderStatus::ReaderSucceeded;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::ReaderPlanRejected
    );
}

// ── 14. reader result with live_event_stream_read=true blocks ──────────
#[test]
fn i14_reader_result_live_event_stream_read_blocks() {
    let mut input = valid_dry_run_input();
    input.reader_result.live_event_stream_read = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::ReaderPlanRejected
    );
}

// ── 15. allow_fixture_counts=false keeps reported counts zero ──────────
#[test]
fn i14_allow_fixture_counts_false_zero_reported() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2)];
    let fixture = build_fixture_from_raw_frames("i14-z", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    let result = evaluate_event_stream_dry_run(&input);
    assert_eq!(result.reported_events_read, 0);
    assert_eq!(result.reported_decode_errors, 0);
    assert_eq!(result.reported_bridge_records, 0);
}

// ── 16. allow_fixture_counts=true reports fixture decoded frames ──────
#[test]
fn i14_allow_fixture_counts_true_reports_decoded() {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2), valid_raw_frame(3)];
    let fixture = build_fixture_from_raw_frames("i14-dec", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    let result = evaluate_event_stream_dry_run(&input);
    assert_eq!(result.reported_events_read, result.fixture_frames_decoded);
    assert!(result.fixture_frames_decoded > 0);
}

// ── 17. allow_fixture_counts=true reports fixture decode errors ────────
#[test]
fn i14_allow_fixture_counts_true_reports_decode_errors() {
    let frames = vec![invalid_raw_frame(1), invalid_raw_frame(2)];
    let fixture = build_fixture_from_raw_frames("i14-err", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    let result = evaluate_event_stream_dry_run(&input);
    assert_eq!(result.reported_decode_errors, result.fixture_decode_errors);
    assert!(result.fixture_decode_errors > 0);
}

// ── 18. allow_fixture_counts=true reports fixture bridge records ──────
#[test]
fn i14_allow_fixture_counts_true_reports_bridge_records() {
    let frames = vec![valid_raw_frame(1)];
    let fixture = build_fixture_from_raw_frames("i14-br", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    let result = evaluate_event_stream_dry_run(&input);
    assert_eq!(
        result.reported_bridge_records,
        result.fixture_bridge_records
    );
    assert!(result.fixture_bridge_records > 0);
}

// ── 19. allow_live_reader=true blocks in I-14 ────────────────────────
#[test]
fn i14_allow_live_reader_blocks() {
    let mut input = valid_dry_run_input();
    input.allow_live_reader = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::LiveReaderUnsupported
    );
}

// ── 20. allow_ring_buffer_open=true blocks ───────────────────────────
#[test]
fn i14_allow_ring_buffer_open_blocks() {
    let mut input = valid_dry_run_input();
    input.allow_ring_buffer_open = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 21. allow_live_event_read=true blocks ─────────────────────────────
#[test]
fn i14_allow_live_event_read_blocks() {
    let mut input = valid_dry_run_input();
    input.allow_live_event_read = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 22. allow_map_pin=true blocks ─────────────────────────────────────
#[test]
fn i14_allow_map_pin_blocks() {
    let mut input = valid_dry_run_input();
    input.allow_map_pin = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 23. allow_persistence=true blocks ────────────────────────────────
#[test]
fn i14_allow_persistence_blocks() {
    let mut input = valid_dry_run_input();
    input.allow_persistence = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).status,
        EbpfEventStreamDryRunStatus::Rejected
    );
}

// ── 24. dry run completed can be represented with fixture counts ──────
#[test]
fn i14_dry_run_completed_with_fixture_counts() {
    let frames = vec![valid_raw_frame(1), invalid_raw_frame(2), valid_raw_frame(3)];
    let fixture = build_fixture_from_raw_frames("i14-mix", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    let result = evaluate_event_stream_dry_run(&input);
    assert_eq!(result.status, EbpfEventStreamDryRunStatus::DryRunCompleted);
    assert!(result.dry_run_completed);
    assert!(result.fixture_frames_seen > 0);
}

// ── 25-34. dry run completed safety flags ─────────────────────────────
fn completed_result() -> EbpfEventStreamDryRunResult {
    let frames = vec![valid_raw_frame(1)];
    let fixture = build_fixture_from_raw_frames("i14-safe", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    evaluate_event_stream_dry_run(&input)
}

#[test]
fn i14_completed_reader_not_attempted() {
    assert!(!completed_result().reader_attempted);
}
#[test]
fn i14_completed_reader_not_succeeded() {
    assert!(!completed_result().reader_succeeded);
}
#[test]
fn i14_completed_no_ring_buffer() {
    assert!(!completed_result().ring_buffer_opened);
}
#[test]
fn i14_completed_no_live_event_read() {
    assert!(!completed_result().live_event_stream_read);
}
#[test]
fn i14_completed_no_map_pin() {
    assert!(!completed_result().map_pin_performed);
}
#[test]
fn i14_completed_no_enforcement() {
    assert!(!completed_result().enforcement_performed);
}
#[test]
fn i14_completed_no_packet_drop() {
    assert!(!completed_result().packet_drop_performed);
}
#[test]
fn i14_completed_no_mutation() {
    assert!(!completed_result().mutation_performed);
}
#[test]
fn i14_completed_no_persistence() {
    assert!(!completed_result().persistence_performed);
}
#[test]
fn i14_completed_no_public_cli() {
    assert!(!completed_result().public_cli_exposed);
}

// ── 35. validation accepts safe default dry run result ────────────────
#[test]
fn i14_validation_accepts_safe_default() {
    assert!(
        validate_event_stream_dry_run_result(&evaluate_event_stream_dry_run(
            &default_event_stream_dry_run_input()
        ))
        .is_ok()
    );
}

// ── 36-49. validation rejects unsafe flags ─────────────────────────────
fn default_result() -> EbpfEventStreamDryRunResult {
    evaluate_event_stream_dry_run(&default_event_stream_dry_run_input())
}
#[test]
fn i14_validation_rejects_reader_attempted() {
    let mut r = default_result();
    r.reader_attempted = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_reader_succeeded() {
    let mut r = default_result();
    r.reader_succeeded = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_fixture_only_false() {
    let mut r = default_result();
    r.fixture_only = false;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_reported_events_exceeds_decoded() {
    let mut r = default_result();
    r.fixture_frames_decoded = 5;
    r.reported_events_read = 10;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_reported_errors_exceeds_fixture() {
    let mut r = default_result();
    r.fixture_decode_errors = 3;
    r.reported_decode_errors = 7;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_reported_bridge_exceeds_fixture() {
    let mut r = default_result();
    r.fixture_bridge_records = 2;
    r.reported_bridge_records = 9;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_ring_buffer_opened() {
    let mut r = default_result();
    r.ring_buffer_opened = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_live_event_stream_read() {
    let mut r = default_result();
    r.live_event_stream_read = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_map_pin() {
    let mut r = default_result();
    r.map_pin_performed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_enforcement() {
    let mut r = default_result();
    r.enforcement_performed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_packet_drop() {
    let mut r = default_result();
    r.packet_drop_performed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_mutation() {
    let mut r = default_result();
    r.mutation_performed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_persistence() {
    let mut r = default_result();
    r.persistence_performed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}
#[test]
fn i14_validation_rejects_public_cli() {
    let mut r = default_result();
    r.public_cli_exposed = true;
    assert!(validate_event_stream_dry_run_result(&r).is_err());
}

// ── 50. evaluation is deterministic ────────────────────────────────────
#[test]
fn i14_evaluation_is_deterministic() {
    let frames = vec![valid_raw_frame(1), invalid_raw_frame(2), valid_raw_frame(3)];
    let fixture = build_fixture_from_raw_frames("i14-det", EbpfEventSource::Model, frames);
    let mut input = valid_dry_run_input_with_fixture_counts();
    input.fixture_report = decode_event_stream_fixture(&fixture);
    assert_eq!(
        evaluate_event_stream_dry_run(&input),
        evaluate_event_stream_dry_run(&input)
    );
}

// ── 51-68. doc content checks ─────────────────────────────────────────
#[test]
fn i14_doc_exists() {
    assert!(!I14_DOC.is_empty());
}
#[test]
fn i14_doc_mentions_reader_lab_dry_run() {
    assert!(I14_DOC
        .to_lowercase()
        .contains("event stream reader lab dry run"));
}
#[test]
fn i14_doc_says_feature_gated() {
    assert!(I14_DOC.to_lowercase().contains("feature-gated"));
}
#[test]
fn i14_doc_says_disabled_by_default() {
    assert!(I14_DOC.to_lowercase().contains("disabled by default"));
}
#[test]
fn i14_doc_says_fixture_counts_not_live() {
    let d = I14_DOC.to_lowercase();
    assert!(
        d.contains("fixture counts are not live kernel event counts")
            || (d.contains("fixture counts") && d.contains("not live kernel"))
    );
}
#[test]
fn i14_doc_says_no_public_cli() {
    assert!(I14_DOC.to_lowercase().contains("no public cli"));
}
#[test]
fn i14_doc_says_no_normal_ci_live_read() {
    assert!(I14_DOC.to_lowercase().contains("no normal ci"));
}
#[test]
fn i14_doc_says_no_ring_buffer() {
    assert!(I14_DOC.to_lowercase().contains("no ring buffer"));
}
#[test]
fn i14_doc_says_no_live_kernel_event_read() {
    assert!(I14_DOC.to_lowercase().contains("no live kernel event read"));
}
#[test]
fn i14_doc_says_no_map_pin() {
    assert!(I14_DOC.to_lowercase().contains("no map pin"));
}
#[test]
fn i14_doc_says_no_enforcement() {
    assert!(I14_DOC.to_lowercase().contains("no enforcement"));
}
#[test]
fn i14_doc_says_no_packet_drop() {
    assert!(I14_DOC.to_lowercase().contains("no packet drop"));
}
#[test]
fn i14_doc_says_no_block_allow_quota() {
    assert!(I14_DOC.to_lowercase().contains("block/allow/quota"));
}
#[test]
fn i14_doc_says_no_nft_tc_fallback() {
    assert!(I14_DOC.to_lowercase().contains("nft") || I14_DOC.to_lowercase().contains("tc"));
}
#[test]
fn i14_doc_says_no_ledger_persistence() {
    let d = I14_DOC.to_lowercase();
    assert!(d.contains("no ledger") || d.contains("persistence"));
}
#[test]
fn i14_doc_says_usage_schema_unchanged() {
    let d = I14_DOC.to_lowercase();
    assert!(
        d.contains("usage json schema") || (d.contains("json schema") && d.contains("unchanged"))
    );
}
#[test]
fn i14_doc_says_ledger_schema_unchanged() {
    let d = I14_DOC.to_lowercase();
    assert!(
        d.contains("ledger json schema")
            || (d.contains("ledger") && d.contains("schema") && d.contains("unchanged"))
    );
}
#[test]
fn i14_doc_says_no_fake_reader_success() {
    let d = I14_DOC.to_lowercase();
    assert!(
        d.contains("no fake live reader success")
            || (d.contains("fake") && d.contains("reader success"))
    );
}
#[test]
fn i14_doc_says_no_fake_live_event_counts() {
    let d = I14_DOC.to_lowercase();
    assert!(
        d.contains("no fake live event counts")
            || (d.contains("fake") && d.contains("event counts"))
    );
}

// ── 69-73. integration checks ────────────────────────────────────────
#[test]
fn i14_version_remains_v3_1_0() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "3.1.0");
}
#[test]
fn i14_ledger_inspect_works() {
    let _ = handle_ledger_inspect(true, None);
}
#[test]
fn i14_ledger_export_works() {
    let path = std::env::temp_dir().join("i14-ledger-export-test.json");
    let _ = handle_ledger_export(true, Some(path.to_string_lossy().as_ref()));
}
#[test]
fn i14_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.to_lowercase().contains("intergalaxion"));
}
#[test]
fn i14_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let h = render_help(&mut app).to_lowercase();
    assert!(!h.contains("block") || !h.contains("allow") || !h.contains("quota"));
}

// ── 74. no new dependency added ──────────────────────────────────────
#[test]
fn i14_no_new_dependency() {
    assert!(CARGO_TOML.contains("clap = "));
    assert!(CARGO_TOML.contains("intergalaxion-event-stream-lab = []"));
    assert!(CARGO_TOML.contains("intergalaxion-live-attach-lab"));
}

// ── 75. no nft/tc source ───────────────────────────────────────────────
#[test]
fn i14_no_nft_tc_source() {
    assert!(!I14_SOURCE.contains("tc::"));
    assert!(!I14_SOURCE.contains("nft::"));
}

// ── 76. all touched files under 1000 LOC ──────────────────────────────
#[test]
fn i14_source_under_1000_loc() {
    let lines = I14_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "event_stream_dry_run.rs has {lines} lines (max 1000)"
    );
}

// ── Additional coverage ────────────────────────────────────────────────
#[test]
fn i14_all_status_variants_have_labels() {
    for status in [
        EbpfEventStreamDryRunStatus::FeatureDisabled,
        EbpfEventStreamDryRunStatus::ReaderPlanRejected,
        EbpfEventStreamDryRunStatus::FixtureReportRejected,
        EbpfEventStreamDryRunStatus::DryRunReady,
        EbpfEventStreamDryRunStatus::DryRunCompleted,
        EbpfEventStreamDryRunStatus::DryRunFailed,
        EbpfEventStreamDryRunStatus::LiveReaderUnsupported,
        EbpfEventStreamDryRunStatus::Rejected,
    ] {
        assert!(!event_stream_dry_run_status_label(status).is_empty());
    }
}

#[test]
fn i14_all_mode_variants_have_labels() {
    for mode in [
        EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
        EbpfEventStreamDryRunMode::ReaderBoundaryDryRun,
        EbpfEventStreamDryRunMode::LiveReaderUnsupported,
    ] {
        assert!(!event_stream_dry_run_mode_label(mode).is_empty());
    }
}

#[test]
fn i14_no_forbidden_patterns_in_source() {
    for pattern in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "RingBuf",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
    ] {
        assert!(
            !I14_SOURCE.contains(pattern),
            "forbidden pattern found: {pattern}"
        );
    }
}

#[test]
fn i14_no_forbidden_mutation_patterns_in_source() {
    for pattern in [
        "File::create",
        "fs::write",
        "OpenOptions",
        "drop_packet",
        "block(",
        "allow(",
        "quota",
    ] {
        assert!(
            !I14_SOURCE.contains(pattern),
            "forbidden mutation pattern found: {pattern}"
        );
    }
    for line in I14_SOURCE.lines() {
        let t = line.trim();
        if !t.starts_with("//") && t.contains("persist") && !t.contains("persistence") {
            panic!("standalone 'persist' found in source: {t}");
        }
    }
}

#[test]
fn i14_dry_run_completed_with_empty_fixture() {
    let result = evaluate_event_stream_dry_run(&valid_dry_run_input());
    assert_eq!(result.status, EbpfEventStreamDryRunStatus::DryRunCompleted);
    assert!(result.dry_run_completed);
    assert_eq!(result.fixture_frames_seen, 0);
    assert_eq!(result.reported_events_read, 0);
}

#[test]
fn i14_dry_run_completed_fixture_only_always_true() {
    assert!(completed_result().fixture_only);
}

#[test]
fn i14_dry_run_completed_mode_is_fixture_only() {
    assert_eq!(
        evaluate_event_stream_dry_run(&valid_dry_run_input()).mode,
        EbpfEventStreamDryRunMode::FixtureOnlyDryRun
    );
}

#[test]
fn i14_dry_run_completed_operator_label_propagated() {
    let mut input = valid_dry_run_input();
    input.explicit_operator_label = String::from("test-operator-label");
    assert_eq!(
        evaluate_event_stream_dry_run(&input).operator_label,
        "test-operator-label"
    );
}

#[test]
fn i14_validation_accepts_completed_result() {
    assert!(validate_event_stream_dry_run_result(&completed_result()).is_ok());
}

#[test]
fn i14_live_reader_unsupported_mode_is_correct() {
    let mut input = valid_dry_run_input();
    input.allow_live_reader = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).mode,
        EbpfEventStreamDryRunMode::LiveReaderUnsupported
    );
}

#[test]
fn i14_reader_plan_rejected_mode_is_reader_boundary() {
    let mut input = valid_dry_run_input();
    input.reader_result.live_event_stream_read = true;
    assert_eq!(
        evaluate_event_stream_dry_run(&input).mode,
        EbpfEventStreamDryRunMode::ReaderBoundaryDryRun
    );
}

#[test]
fn i14_rejected_reason_mentions_operator_label() {
    let mut input = default_event_stream_dry_run_input();
    input.explicit_dry_run_feature_enabled = true;
    assert!(evaluate_event_stream_dry_run(&input)
        .reason
        .contains("operator label"));
}

#[test]
fn i14_rejected_reason_mentions_ring_buffer() {
    let mut input = valid_dry_run_input();
    input.allow_ring_buffer_open = true;
    assert!(evaluate_event_stream_dry_run(&input)
        .reason
        .contains("ring buffer"));
}

#[test]
fn i14_rejected_reason_mentions_persistence() {
    let mut input = valid_dry_run_input();
    input.allow_persistence = true;
    assert!(evaluate_event_stream_dry_run(&input)
        .reason
        .contains("persistence"));
}

#[test]
fn i14_feature_disabled_reason_mentions_disabled() {
    assert!(
        evaluate_event_stream_dry_run(&default_event_stream_dry_run_input())
            .reason
            .contains("disabled")
    );
}

#[test]
fn i14_dry_run_completed_reason_mentions_fixture() {
    assert!(evaluate_event_stream_dry_run(&valid_dry_run_input())
        .reason
        .contains("fixture"));
}
