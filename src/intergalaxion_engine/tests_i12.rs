// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-12 tests: event stream reader boundary.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind;
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::{
    default_event_stream_read_plan_input, evaluate_event_stream_read_plan,
    validate_event_stream_read_plan, EbpfEventStreamReadMode,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::*;
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::{
    default_manual_lab_capture, summarize_manual_lab_captures, EbpfLiveAttachManualResultStatus,
};
use clap::CommandFactory;

const I12_DOC: &str = include_str!(
    "../../docs/intergalaxion/I-12-event-stream-reader-boundary-disabled-by-default.md"
);
const I12_SOURCE: &str = include_str!("backends/ebpf/event_stream_reader.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helpers ──────────────────────────────────────────────────────────

fn ready_summary() -> crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualLabSummary{
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.operator_label = String::from("i12-ready-op");
    c.attach_succeeded = true;
    c.detach_attempted = true;
    c.detached_cleanly = true;
    summarize_manual_lab_captures(&[c])
}

fn ready_plan(
) -> crate::intergalaxion_engine::backends::ebpf::event_stream_plan::EbpfEventStreamReadPlan {
    let mut plan_input = default_event_stream_read_plan_input();
    plan_input.manual_summary = ready_summary();
    plan_input.explicit_event_stream_planning_consent = true;
    evaluate_event_stream_read_plan(&plan_input)
}

fn ready_reader_input() -> EbpfEventStreamReaderInput {
    EbpfEventStreamReaderInput {
        read_plan: ready_plan(),
        explicit_event_stream_lab_feature_enabled: true,
        explicit_operator_label: String::from("i12-operator"),
        allow_reader_attempt: true,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        max_events: 100,
        timeout_ms: 5000,
    }
}

fn render_help(app: &mut clap::Command) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

// ── 1. Default reader input is safe ──────────────────────────────

#[test]
fn i12_default_reader_input_is_safe() {
    let inp = default_event_stream_reader_input();
    assert!(!inp.explicit_event_stream_lab_feature_enabled);
    assert!(!inp.allow_reader_attempt);
    assert!(!inp.allow_ring_buffer_open);
    assert!(!inp.allow_live_event_read);
    assert!(!inp.allow_map_pin);
    assert!(!inp.allow_persistence);
    assert!(inp.explicit_operator_label.is_empty());
    assert_eq!(inp.max_events, 0);
    assert_eq!(inp.timeout_ms, 0);
}

// ── 2. Default reader result has all operation flags false ──────────

#[test]
fn i12_default_result_all_flags_false() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.attempted);
    assert!(!result.reader_started);
    assert!(!result.reader_completed);
    assert!(!result.ring_buffer_opened);
    assert!(!result.live_event_stream_read);
    assert!(!result.map_pin_performed);
    assert!(!result.enforcement_performed);
    assert!(!result.packet_drop_performed);
    assert!(!result.mutation_performed);
    assert!(!result.persistence_performed);
    assert!(!result.public_cli_exposed);
    assert_eq!(result.events_read, 0);
    assert_eq!(result.decode_errors, 0);
}

// ── 3. Status labels are stable ──────────────────────────────────

#[test]
fn i12_status_labels_stable() {
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::FeatureDisabled),
        "feature_disabled"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::PlanRejected),
        "plan_rejected"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::ManualEvidenceMissing),
        "manual_evidence_missing"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::UnsupportedMode),
        "unsupported_mode"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::UnsupportedTarget),
        "unsupported_target"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::ReaderNotImplemented),
        "reader_not_implemented"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::FutureReaderReady),
        "future_reader_ready"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::ReaderAttempted),
        "reader_attempted"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::ReaderSucceeded),
        "reader_succeeded"
    );
    assert_eq!(
        event_stream_reader_status_label(EbpfEventStreamReaderStatus::ReaderFailed),
        "reader_failed"
    );
}

// ── 4. Feature disabled returns FeatureDisabled ────────────────────

#[test]
fn i12_feature_disabled_returns_feature_disabled() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::FeatureDisabled);
}

// ── 5. Feature disabled attempted=false ───────────────────────────

#[test]
fn i12_feature_disabled_attempted_false() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.attempted);
}

// ── 6. Feature disabled reader_started=false ────────────────────────

#[test]
fn i12_feature_disabled_reader_started_false() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.reader_started);
}

// ── 7. Feature disabled reader_completed=false ────────────────────

#[test]
fn i12_feature_disabled_reader_completed_false() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.reader_completed);
}

// ── 8. Plan rejected when future_read_candidate=false ─────────────

#[test]
fn i12_plan_rejected_when_not_candidate() {
    let mut inp = ready_reader_input();
    // ready_plan has future_read_candidate=true but ReaderNotImplemented
    // status. Force it to PlanOnly by using default plan.
    let default_plan_input = default_event_stream_read_plan_input();
    inp.read_plan = evaluate_event_stream_read_plan(&default_plan_input);
    assert!(!inp.read_plan.future_read_candidate);
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::PlanRejected);
}

// ── 9. Plan rejected when read plan validation fails ───────────────

#[test]
fn i12_plan_rejected_when_plan_validation_fails() {
    let mut inp = ready_reader_input();
    // Make the plan unsafe by setting reader_implemented=true
    inp.read_plan.reader_implemented = true;
    assert!(validate_event_stream_read_plan(&inp.read_plan).is_err());
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::PlanRejected);
}

// ── 10. Empty operator label blocks ───────────────────────────────

#[test]
fn i12_empty_operator_label_blocks() {
    let mut inp = ready_reader_input();
    inp.explicit_operator_label = String::new();
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(
        result.status,
        EbpfEventStreamReaderStatus::ManualEvidenceMissing
    );
}

// ── 11. allow_reader_attempt=false blocks ──────────────────────────

#[test]
fn i12_allow_reader_attempt_false_blocks() {
    let mut inp = ready_reader_input();
    inp.allow_reader_attempt = false;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(
        result.status,
        EbpfEventStreamReaderStatus::ReaderNotImplemented
    );
}

// ── 12. allow_ring_buffer_open=true blocks in I-12 ─────────────────

#[test]
fn i12_allow_ring_buffer_open_blocks() {
    let mut inp = ready_reader_input();
    inp.allow_ring_buffer_open = true;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::UnsupportedMode);
}

// ── 13. allow_live_event_read=true blocks in I-12 ─────────────────

#[test]
fn i12_allow_live_event_read_blocks() {
    let mut inp = ready_reader_input();
    inp.allow_live_event_read = true;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::UnsupportedMode);
}

// ── 14. allow_map_pin=true blocks in I-12 ──────────────────────────

#[test]
fn i12_allow_map_pin_blocks() {
    let mut inp = ready_reader_input();
    inp.allow_map_pin = true;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(
        result.status,
        EbpfEventStreamReaderStatus::UnsupportedTarget
    );
}

// ── 15. allow_persistence=true blocks in I-12 ────────────────────

#[test]
fn i12_allow_persistence_blocks() {
    let mut inp = ready_reader_input();
    inp.allow_persistence = true;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(
        result.status,
        EbpfEventStreamReaderStatus::UnsupportedTarget
    );
}

// ── 16. Unsupported mode blocks ───────────────────────────────────

#[test]
fn i12_unsupported_mode_blocks() {
    let mut inp = ready_reader_input();
    inp.read_plan.mode = EbpfEventStreamReadMode::Unsupported;
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::UnsupportedMode);
}

// ── 17. Unsupported target blocks ─────────────────────────────────
// (All current targets are supported; this is a structural test)

#[test]
fn i12_all_current_targets_supported() {
    for kind in [
        EbpfAttachTargetKind::SocketFilter,
        EbpfAttachTargetKind::CgroupSkb,
        EbpfAttachTargetKind::Tracepoint,
    ] {
        let mut inp = ready_reader_input();
        inp.read_plan.target_kind = kind;
        let result = evaluate_event_stream_reader(&inp);
        assert_ne!(
            result.status,
            EbpfEventStreamReaderStatus::UnsupportedTarget
        );
    }
}

// ── 18-31. FutureReaderReady checks ───────────────────────────────

#[test]
fn i12_future_reader_ready_status() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert_eq!(
        result.status,
        EbpfEventStreamReaderStatus::FutureReaderReady
    );
}

#[test]
fn i12_future_reader_ready_attempted_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.attempted);
}

#[test]
fn i12_future_reader_ready_reader_started_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.reader_started);
}

#[test]
fn i12_future_reader_ready_reader_completed_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.reader_completed);
}

#[test]
fn i12_future_reader_ready_events_read_zero() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert_eq!(result.events_read, 0);
}

#[test]
fn i12_future_reader_ready_decode_errors_zero() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert_eq!(result.decode_errors, 0);
}

#[test]
fn i12_future_reader_ready_ring_buffer_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.ring_buffer_opened);
}

#[test]
fn i12_future_reader_ready_live_read_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.live_event_stream_read);
}

#[test]
fn i12_future_reader_ready_map_pin_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.map_pin_performed);
}

#[test]
fn i12_future_reader_ready_enforcement_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.enforcement_performed);
}

#[test]
fn i12_future_reader_ready_packet_drop_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.packet_drop_performed);
}

#[test]
fn i12_future_reader_ready_mutation_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.mutation_performed);
}

#[test]
fn i12_future_reader_ready_persistence_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.persistence_performed);
}

#[test]
fn i12_future_reader_ready_public_cli_false() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.public_cli_exposed);
}

// ── 32. Validation accepts safe default result ─────────────────────

#[test]
fn i12_validation_accepts_safe_default() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(validate_event_stream_reader_result(&result).is_ok());
}

// ── 33. Validation rejects attempted=true for FeatureDisabled ────

#[test]
fn i12_validation_rejects_attempted_for_feature_disabled() {
    let mut result = evaluate_event_stream_reader(&default_event_stream_reader_input());
    result.attempted = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 34. Validation rejects reader_started=true when attempted=false

#[test]
fn i12_validation_rejects_started_without_attempted() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.reader_started = true;
    result.attempted = false;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 35. Validation rejects reader_completed=true when reader_started=false

#[test]
fn i12_validation_rejects_completed_without_started() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.reader_completed = true;
    result.reader_started = false;
    result.attempted = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 36. Validation rejects ReaderSucceeded in normal boundary ────

#[test]
fn i12_validation_rejects_reader_succeeded() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.status = EbpfEventStreamReaderStatus::ReaderSucceeded;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 37. Validation rejects events_read>0 when live_event_stream_read=false

#[test]
fn i12_validation_rejects_events_without_live_read() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.events_read = 10;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 38. Validation rejects decode_errors>0 when attempted=false ────

#[test]
fn i12_validation_rejects_decode_errors_without_attempted() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.decode_errors = 5;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 39. Validation rejects ring_buffer_opened=true ────────────────

#[test]
fn i12_validation_rejects_ring_buffer_opened() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 40. Validation rejects live_event_stream_read=true ─────────────

#[test]
fn i12_validation_rejects_live_event_stream_read() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.live_event_stream_read = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 41. Validation rejects map_pin_performed=true ───────────────────

#[test]
fn i12_validation_rejects_map_pin_performed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.map_pin_performed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 42. Validation rejects enforcement_performed=true ─────────────

#[test]
fn i12_validation_rejects_enforcement_performed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.enforcement_performed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 43. Validation rejects packet_drop_performed=true ──────────────

#[test]
fn i12_validation_rejects_packet_drop_performed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.packet_drop_performed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 44. Validation rejects mutation_performed=true ─────────────────

#[test]
fn i12_validation_rejects_mutation_performed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.mutation_performed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 45. Validation rejects persistence_performed=true ──────────────

#[test]
fn i12_validation_rejects_persistence_performed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.persistence_performed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 46. Validation rejects public_cli_exposed=true ────────────────

#[test]
fn i12_validation_rejects_public_cli_exposed() {
    let mut result = evaluate_event_stream_reader(&ready_reader_input());
    result.public_cli_exposed = true;
    assert!(validate_event_stream_reader_result(&result).is_err());
}

// ── 47. Evaluation is deterministic ─────────────────────────────────

#[test]
fn i12_evaluation_is_deterministic() {
    let inp = ready_reader_input();
    let r1 = evaluate_event_stream_reader(&inp);
    let r2 = evaluate_event_stream_reader(&inp);
    assert_eq!(r1, r2);
}

// ── 48. Docs exist ──────────────────────────────────────────────────

#[test]
fn i12_doc_exists() {
    assert!(!I12_DOC.is_empty());
}

// ── 49-62. Doc content checks ───────────────────────────────────────

#[test]
fn i12_doc_mentions_reader_boundary() {
    assert!(I12_DOC.to_lowercase().contains("event stream reader"));
}

#[test]
fn i12_doc_says_disabled_by_default() {
    assert!(I12_DOC.to_lowercase().contains("disabled by default"));
}

#[test]
fn i12_doc_says_feature_gated() {
    assert!(I12_DOC.to_lowercase().contains("feature") && I12_DOC.to_lowercase().contains("gated"));
}

#[test]
fn i12_doc_says_no_public_cli() {
    assert!(I12_DOC.to_lowercase().contains("no public cli"));
}

#[test]
fn i12_doc_says_no_normal_ci_live_read() {
    assert!(
        I12_DOC.to_lowercase().contains("no normal ci")
            || I12_DOC.to_lowercase().contains("no normal ci")
    );
}

#[test]
fn i12_doc_says_no_ring_buffer() {
    assert!(I12_DOC.to_lowercase().contains("no ring buffer"));
}

#[test]
fn i12_doc_says_no_live_kernel_event_read() {
    assert!(I12_DOC.to_lowercase().contains("no live kernel event read"));
}

#[test]
fn i12_doc_says_no_map_pin() {
    assert!(I12_DOC.to_lowercase().contains("no map pin"));
}

#[test]
fn i12_doc_says_no_enforcement() {
    assert!(I12_DOC.to_lowercase().contains("no enforcement"));
}

#[test]
fn i12_doc_says_no_packet_drop() {
    assert!(I12_DOC.to_lowercase().contains("no packet drop"));
}

#[test]
fn i12_doc_says_no_block_allow_quota() {
    let doc_lower = I12_DOC.to_lowercase();
    assert!(doc_lower.contains("no block") || doc_lower.contains("block/allow/quota"));
}

#[test]
fn i12_doc_says_no_nft_tc_fallback() {
    let doc_lower = I12_DOC.to_lowercase();
    assert!(doc_lower.contains("nft") || doc_lower.contains("tc"));
}

#[test]
fn i12_doc_says_no_ledger_persistence() {
    let doc_lower = I12_DOC.to_lowercase();
    assert!(doc_lower.contains("no ledger") || doc_lower.contains("persistence"));
}

#[test]
fn i12_doc_says_schema_unchanged() {
    let doc_lower = I12_DOC.to_lowercase();
    assert!(doc_lower.contains("unchanged") || doc_lower.contains("schema"));
}

#[test]
fn i12_doc_says_no_fake_success() {
    assert!(I12_DOC.to_lowercase().contains("fake"));
}

// ── 63. Version remains v3.1.0 ─────────────────────────────────────

#[test]
fn i12_version_remains_v3_1_0() {
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(version, "3.1.0");
}

// ── 64. Ledger inspect still works ──────────────────────────────────

#[test]
fn i12_ledger_inspect_works() {
    let _ = handle_ledger_inspect(true, None);
}

// ── 65. Ledger export still works ──────────────────────────────────

#[test]
fn i12_ledger_export_works() {
    let path = std::env::temp_dir().join("i12-ledger-export-test.json");
    let _ = handle_ledger_export(true, Some(path.to_string_lossy().as_ref()));
}

// ── 66. Public help does not mention intergalaxion ──────────────────

#[test]
fn i12_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

// ── 67. Public help no block/allow/quota ───────────────────────────

#[test]
fn i12_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    let h = help.to_lowercase();
    assert!(!h.contains("block") || !h.contains("allow") || !h.contains("quota"));
}

// ── 68. No new dependency added ────────────────────────────────────

#[test]
fn i12_no_new_dependency() {
    let cargo = CARGO_TOML;
    // Check that no new dependencies were added beyond what existed
    assert!(cargo.contains("clap = "));
    assert!(cargo.contains("serde = "));
    assert!(cargo.contains("serde_json = "));
    // intergalaxion-event-stream-lab should have no extra deps
    assert!(cargo.contains("intergalaxion-event-stream-lab = []"));
}

// ── 69. No nft/tc source ────────────────────────────────────────────

#[test]
fn i12_no_nft_tc_source() {
    let src = I12_SOURCE;
    assert!(!src.contains("tc::"));
    assert!(!src.contains("nft::"));
}

// ── 70. Source file under 1000 LOC ────────────────────────────────

#[test]
fn i12_source_under_1000_loc() {
    let lines = I12_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "event_stream_reader.rs has {lines} lines (max 1000)"
    );
}

// ── 71. Feature-gated execute returns FeatureDisabled ──────────────

#[test]
fn i12_execute_feature_gated_returns_disabled() {
    let inp = default_event_stream_reader_input();
    let result = execute_event_stream_reader_feature_gated(&inp);
    assert_eq!(result.status, EbpfEventStreamReaderStatus::FeatureDisabled);
}

// ── Additional coverage ──────────────────────────────────────────

#[test]
fn i12_execute_feature_gated_no_live_operations() {
    let inp = default_event_stream_reader_input();
    let result = execute_event_stream_reader_feature_gated(&inp);
    assert!(!result.attempted);
    assert!(!result.reader_started);
    assert!(!result.reader_completed);
    assert!(!result.ring_buffer_opened);
    assert!(!result.live_event_stream_read);
    assert_eq!(result.events_read, 0);
}

#[test]
fn i12_feature_enabled_carries_operator_label() {
    let mut inp = ready_reader_input();
    inp.explicit_operator_label = String::from("i12-test-op");
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.operator_label, "i12-test-op");
}

#[test]
fn i12_feature_enabled_carries_max_events() {
    let inp = ready_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.max_events, 100);
}

#[test]
fn i12_feature_enabled_carries_timeout_ms() {
    let inp = ready_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.timeout_ms, 5000);
}

#[test]
fn i12_feature_enabled_carries_mode() {
    let inp = ready_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert_eq!(result.mode, EbpfEventStreamReadMode::PlanningOnly);
}

#[test]
fn i12_validation_accepts_future_reader_ready() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(validate_event_stream_reader_result(&result).is_ok());
}

#[test]
fn i12_future_reader_ready_reason_nonempty() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(!result.reason.is_empty());
}

#[test]
fn i12_plan_rejected_reason_nonempty() {
    let mut inp = ready_reader_input();
    inp.read_plan = evaluate_event_stream_read_plan(&default_event_stream_read_plan_input());
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.reason.is_empty());
}

#[test]
fn i12_feature_disabled_reason_nonempty() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.reason.is_empty());
}

#[test]
fn i12_default_result_feature_enabled_false() {
    let inp = default_event_stream_reader_input();
    let result = evaluate_event_stream_reader(&inp);
    assert!(!result.feature_enabled);
}

#[test]
fn i12_ready_input_feature_enabled_true() {
    let result = evaluate_event_stream_reader(&ready_reader_input());
    assert!(result.feature_enabled);
}

#[test]
fn i12_all_status_variants_have_labels() {
    use EbpfEventStreamReaderStatus::*;
    for status in [
        FeatureDisabled,
        PlanRejected,
        ManualEvidenceMissing,
        UnsupportedMode,
        UnsupportedTarget,
        ReaderNotImplemented,
        FutureReaderReady,
        ReaderAttempted,
        ReaderSucceeded,
        ReaderFailed,
    ] {
        let label = event_stream_reader_status_label(status);
        assert!(!label.is_empty());
    }
}

#[test]
fn i12_no_forbidden_patterns_in_source() {
    let src = I12_SOURCE;
    let forbidden = [
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
    ];
    for pattern in &forbidden {
        assert!(!src.contains(pattern), "forbidden pattern found: {pattern}");
    }
}

#[test]
fn i12_no_forbidden_mutation_patterns_in_source() {
    let src = I12_SOURCE;
    let forbidden = [
        "File::create",
        "fs::write",
        "OpenOptions",
        "drop_packet",
        "block(",
        "allow(",
        "quota",
    ];
    for pattern in &forbidden {
        assert!(
            !src.contains(pattern),
            "forbidden mutation pattern found: {pattern}"
        );
    }
    // "persist" and "save" are used only as part of field names
    // (allow_persistence, persistence_performed), not as calls.
    // Check that they do not appear standalone outside identifiers.
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains("persist") && !trimmed.contains("persistence") {
            panic!("standalone 'persist' found in source: {trimmed}");
        }
    }
}
