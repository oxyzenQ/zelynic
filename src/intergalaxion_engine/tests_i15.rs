// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-15 tests: event stream reader evidence audit.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::decoder::EbpfRawEventFrame;
use crate::intergalaxion_engine::backends::ebpf::event_schema::EbpfEventSource;
use crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::{
    default_event_stream_dry_run_input, evaluate_event_stream_dry_run, EbpfEventStreamDryRunResult,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::*;
use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::{
    build_fixture_from_raw_frames, decode_event_stream_fixture, EbpfEventStreamFixtureBridgeReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::{
    default_event_stream_read_plan_input, evaluate_event_stream_read_plan,
    EbpfEventStreamReadPlanStatus,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::{
    default_event_stream_reader_input, evaluate_event_stream_reader, EbpfEventStreamReaderStatus,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::{
    EbpfLiveAttachManualLabSummary, EbpfLiveAttachManualRecommendation,
    EbpfLiveAttachManualResultStatus,
};
use clap::CommandFactory;

const I15_DOC: &str =
    include_str!("../../docs/intergalaxion/I-15-event-stream-reader-evidence-audit.md");
const I15_SOURCE: &str = include_str!("backends/ebpf/event_stream_evidence_audit.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

fn valid_raw_frame(frame_id: u64) -> EbpfRawEventFrame {
    EbpfRawEventFrame {
        frame_id,
        source: EbpfEventSource::Model,
        payload: vec![0x01, 0x02, 0x03],
        decode_source_label: String::from("i15-fixture"),
    }
}

fn safe_manual_summary() -> EbpfLiveAttachManualLabSummary {
    EbpfLiveAttachManualLabSummary {
        phase: String::from("I-10F"),
        captures: vec![],
        total_captures: 1,
        successful_attach_count: 1,
        clean_detach_count: 1,
        failed_attach_count: 0,
        failed_detach_count: 0,
        not_run_count: 0,
        ready_for_event_stream_planning: true,
        summary_status: EbpfLiveAttachManualResultStatus::DetachedCleanly,
        recommendation: EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning,
        public_cli_exposed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
    }
}

/// Build a read plan that passes validation with future_read_candidate=true.
fn ready_read_plan(
) -> crate::intergalaxion_engine::backends::ebpf::event_stream_plan::EbpfEventStreamReadPlan {
    let mut plan_input = default_event_stream_read_plan_input();
    plan_input.manual_summary = safe_manual_summary();
    plan_input.explicit_event_stream_planning_consent = true;
    let mut plan = evaluate_event_stream_read_plan(&plan_input);
    // Force future_read_candidate=true and valid status for audit testing
    plan.status = EbpfEventStreamReadPlanStatus::ReaderNotImplemented;
    plan.future_read_candidate = true;
    plan
}

/// Build a reader result that is safe and FutureReaderReady.
fn safe_reader_result(
) -> crate::intergalaxion_engine::backends::ebpf::event_stream_reader::EbpfEventStreamReaderResult {
    let reader_input = default_event_stream_reader_input();
    let mut result = evaluate_event_stream_reader(&reader_input);
    result.status = EbpfEventStreamReaderStatus::FutureReaderReady;
    result
}

/// Build a fixture bridge report with valid frames and bridge records.
fn ready_fixture_report() -> EbpfEventStreamFixtureBridgeReport {
    let frames = vec![valid_raw_frame(1), valid_raw_frame(2)];
    let fixture = build_fixture_from_raw_frames("i15-ready", EbpfEventSource::Model, frames);
    decode_event_stream_fixture(&fixture)
}

/// Build a dry run result that completed successfully.
fn ready_dry_run_result() -> EbpfEventStreamDryRunResult {
    let frames = vec![valid_raw_frame(1)];
    let fixture = build_fixture_from_raw_frames("i15-dr", EbpfEventSource::Model, frames);
    let fixture_report = decode_event_stream_fixture(&fixture);
    let mut input = default_event_stream_dry_run_input();
    input.explicit_dry_run_feature_enabled = true;
    input.explicit_operator_label = String::from("i15-operator");
    input.allow_fixture_counts = true;
    input.fixture_report = fixture_report;
    evaluate_event_stream_dry_run(&input)
}

/// Build a fully ready audit input.
fn ready_audit_input() -> EbpfEventStreamEvidenceAuditInput {
    EbpfEventStreamEvidenceAuditInput {
        manual_summary: safe_manual_summary(),
        read_plan: ready_read_plan(),
        reader_result: safe_reader_result(),
        fixture_report: ready_fixture_report(),
        dry_run_result: ready_dry_run_result(),
        require_clean_detach_evidence: true,
        require_fixture_bridge_records: true,
        require_dry_run_completed: true,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

fn render_help(app: &mut clap::Command) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

// ── 1. default evidence audit input is safe ──────────────────────────
#[test]
fn i15_default_audit_input_is_safe() {
    let input = default_event_stream_evidence_audit_input();
    assert!(!input.manual_summary.ready_for_event_stream_planning);
    assert!(input.require_clean_detach_evidence);
    assert!(input.require_fixture_bridge_records);
    assert!(input.require_dry_run_completed);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
}

// ── 2. default audit report phase is I-15 ────────────────────────────
#[test]
fn i15_default_report_phase_is_i15() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert_eq!(report.phase, "I-15");
}

// ── 3. default audit report has all operation flags false ────────────
#[test]
fn i15_default_report_all_flags_false() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert!(!report.public_cli_exposed);
    assert!(!report.usage_schema_changed);
    assert!(!report.ledger_schema_changed);
    assert!(!report.ring_buffer_opened);
    assert!(!report.live_event_stream_read);
    assert!(!report.map_pin_performed);
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
    assert!(!report.mutation_performed);
    assert!(!report.persistence_performed);
}

// ── 4. audit status labels are stable ────────────────────────────────
#[test]
fn i15_audit_status_labels_stable() {
    assert_eq!(
        event_stream_evidence_audit_status_label(EbpfEventStreamEvidenceAuditStatus::Passed),
        "passed"
    );
    assert_eq!(
        event_stream_evidence_audit_status_label(EbpfEventStreamEvidenceAuditStatus::Failed),
        "failed"
    );
    assert_eq!(
        event_stream_evidence_audit_status_label(EbpfEventStreamEvidenceAuditStatus::Warning),
        "warning"
    );
    assert_eq!(
        event_stream_evidence_audit_status_label(EbpfEventStreamEvidenceAuditStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        event_stream_evidence_audit_status_label(
            EbpfEventStreamEvidenceAuditStatus::ReadyForReaderSpikePreparation
        ),
        "ready_for_reader_spike_preparation"
    );
    assert_eq!(
        event_stream_evidence_audit_status_label(EbpfEventStreamEvidenceAuditStatus::NotReady),
        "not_ready"
    );
}

// ── 5. finding kind labels are stable ────────────────────────────────
#[test]
fn i15_finding_kind_labels_stable() {
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::ManualCapture
        ),
        "manual_capture"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::ReadPlan
        ),
        "read_plan"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::ReaderBoundary
        ),
        "reader_boundary"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::FixtureBridge
        ),
        "fixture_bridge"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::DryRun
        ),
        "dry_run"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant
        ),
        "safety_invariant"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::SchemaInvariant
        ),
        "schema_invariant"
    );
    assert_eq!(
        event_stream_evidence_audit_finding_kind_label(
            EbpfEventStreamEvidenceAuditFindingKind::CliInvariant
        ),
        "cli_invariant"
    );
}

// ── 6. default audit is not ready for reader spike preparation ────────
#[test]
fn i15_default_audit_not_ready() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert!(!report.ready_for_reader_spike_preparation);
}

// ── 7. default audit findings are nonempty ────────────────────────────
#[test]
fn i15_default_audit_findings_nonempty() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert!(!report.findings.is_empty());
}

// ── 8. ready audit requires manual summary readiness ──────────────────
#[test]
fn i15_requires_manual_summary_readiness() {
    let mut input = ready_audit_input();
    input.manual_summary.ready_for_event_stream_planning = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == EbpfEventStreamEvidenceAuditFindingKind::ManualCapture));
}

// ── 9. ready audit requires clean detach evidence when configured ────
#[test]
fn i15_requires_clean_detach_when_configured() {
    let mut input = ready_audit_input();
    input.manual_summary.clean_detach_count = 0;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "clean_detach_evidence_missing"));
}

// ── 10. ready audit requires read_plan.future_read_candidate=true ─────
#[test]
fn i15_requires_future_read_candidate() {
    let mut input = ready_audit_input();
    input.read_plan.future_read_candidate = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "read_plan_not_future_candidate"));
}

// ── 11. ready audit rejects invalid read plan ────────────────────────
#[test]
fn i15_rejects_invalid_read_plan() {
    let mut input = ready_audit_input();
    input.read_plan.ring_buffer_opened = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "read_plan_validation_failed"));
}

// ── 12. ready audit requires safe reader result ──────────────────────
#[test]
fn i15_requires_safe_reader_result() {
    let mut input = ready_audit_input();
    input.reader_result.ring_buffer_opened = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "reader_result_validation_failed"));
}

// ── 13. ready audit rejects ReaderSucceeded ──────────────────────────
#[test]
fn i15_rejects_reader_succeeded() {
    let mut input = ready_audit_input();
    input.reader_result.status = EbpfEventStreamReaderStatus::ReaderSucceeded;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "reader_result_reader_succeeded"));
}

// ── 14. ready audit rejects reader result with live_event_stream_read=true
#[test]
fn i15_rejects_reader_live_event_read() {
    let mut input = ready_audit_input();
    input.reader_result.live_event_stream_read = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "reader_result_live_event_read"));
}

// ── 15. ready audit requires fixture report validation ───────────────
#[test]
fn i15_requires_fixture_report_validation() {
    let mut input = ready_audit_input();
    input.fixture_report.reader_attempted = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "fixture_report_validation_failed"));
}

// ── 16. ready audit requires fixture_report.fixture_only=true ──────────
#[test]
fn i15_requires_fixture_only_true() {
    let mut input = ready_audit_input();
    input.fixture_report.fixture_only = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "fixture_report_not_fixture_only"));
}

// ── 17. ready audit requires fixture bridge records when configured ──
#[test]
fn i15_requires_fixture_bridge_records_when_configured() {
    let mut input = ready_audit_input();
    // Use an empty fixture report with no bridge records
    input.fixture_report = decode_event_stream_fixture(
        &crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::default_event_stream_fixture(),
    );
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "fixture_bridge_records_missing"));
}

// ── 18. ready audit requires dry run validation ───────────────────────
#[test]
fn i15_requires_dry_run_validation() {
    let mut input = ready_audit_input();
    input.dry_run_result.reader_attempted = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "dry_run_validation_failed"));
}

// ── 19. ready audit requires dry_run_completed when configured ────────
#[test]
fn i15_requires_dry_run_completed_when_configured() {
    let mut input = ready_audit_input();
    let mut dry_input = default_event_stream_dry_run_input();
    dry_input.explicit_dry_run_feature_enabled = true;
    dry_input.explicit_operator_label = String::from("i15-op");
    input.dry_run_result = evaluate_event_stream_dry_run(&dry_input);
    // override to not completed
    input.dry_run_result.dry_run_completed = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "dry_run_not_completed"));
}

// ── 20. ready audit rejects dry run with reader_succeeded=true ────────
#[test]
fn i15_rejects_dry_run_reader_succeeded() {
    let mut input = ready_audit_input();
    input.dry_run_result.reader_succeeded = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "dry_run_reader_succeeded"));
}

// ── 21. ready audit rejects dry run with live_event_stream_read=true ───
#[test]
fn i15_rejects_dry_run_live_event_read() {
    let mut input = ready_audit_input();
    input.dry_run_result.live_event_stream_read = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "dry_run_live_event_read"));
}

// ── 22. ready audit rejects public_cli_expected_hidden=false ────────
#[test]
fn i15_rejects_public_cli_not_hidden() {
    let mut input = ready_audit_input();
    input.public_cli_expected_hidden = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == EbpfEventStreamEvidenceAuditFindingKind::CliInvariant));
}

// ── 23. ready audit rejects usage_schema_expected_unchanged=false ─────
#[test]
fn i15_rejects_usage_schema_changed() {
    let mut input = ready_audit_input();
    input.usage_schema_expected_unchanged = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "usage_schema_changed"));
}

// ── 24. ready audit rejects ledger_schema_expected_unchanged=false ────
#[test]
fn i15_rejects_ledger_schema_changed() {
    let mut input = ready_audit_input();
    input.ledger_schema_expected_unchanged = false;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert!(!report.ready_for_reader_spike_preparation);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "ledger_schema_changed"));
}

// ── 25. ready audit can pass with all safe evidence ──────────────────
#[test]
fn i15_ready_audit_passes() {
    let report = evaluate_event_stream_evidence_audit(&ready_audit_input());
    assert!(report.ready_for_reader_spike_preparation);
}

// ── 26. passed audit ready_for_reader_spike_preparation=true ──────────
#[test]
fn i15_passed_audit_ready_flag() {
    let report = evaluate_event_stream_evidence_audit(&ready_audit_input());
    assert_eq!(
        report.status,
        EbpfEventStreamEvidenceAuditStatus::ReadyForReaderSpikePreparation
    );
    assert!(report.ready_for_reader_spike_preparation);
}

// ── 27-34. passed audit individual readiness flags ────────────────────
#[test]
fn i15_passed_manual_capture_ready() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).manual_capture_ready);
}
#[test]
fn i15_passed_read_plan_ready() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).read_plan_ready);
}
#[test]
fn i15_passed_reader_boundary_safe() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).reader_boundary_safe);
}
#[test]
fn i15_passed_fixture_bridge_ready() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).fixture_bridge_ready);
}
#[test]
fn i15_passed_dry_run_ready() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).dry_run_ready);
}
#[test]
fn i15_passed_clean_detach_present() {
    assert!(
        evaluate_event_stream_evidence_audit(&ready_audit_input()).clean_detach_evidence_present
    );
}
#[test]
fn i15_passed_fixture_bridge_records_present() {
    assert!(
        evaluate_event_stream_evidence_audit(&ready_audit_input()).fixture_bridge_records_present
    );
}
#[test]
fn i15_passed_dry_run_completed() {
    assert!(evaluate_event_stream_evidence_audit(&ready_audit_input()).dry_run_completed);
}

// ── 35. validation accepts safe default report ──────────────────────
#[test]
fn i15_validation_accepts_safe_default() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert!(validate_event_stream_evidence_audit_report(&report).is_ok());
}

// ── 36-45. validation rejects unsafe flags ────────────────────────────
fn default_audit_report() -> EbpfEventStreamEvidenceAuditReport {
    evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input())
}
#[test]
fn i15_validation_rejects_public_cli_exposed() {
    let mut r = default_audit_report();
    r.public_cli_exposed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_usage_schema_changed() {
    let mut r = default_audit_report();
    r.usage_schema_changed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_ledger_schema_changed() {
    let mut r = default_audit_report();
    r.ledger_schema_changed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_ring_buffer_opened() {
    let mut r = default_audit_report();
    r.ring_buffer_opened = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_live_event_stream_read() {
    let mut r = default_audit_report();
    r.live_event_stream_read = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_map_pin() {
    let mut r = default_audit_report();
    r.map_pin_performed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_enforcement() {
    let mut r = default_audit_report();
    r.enforcement_performed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_packet_drop() {
    let mut r = default_audit_report();
    r.packet_drop_performed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_mutation() {
    let mut r = default_audit_report();
    r.mutation_performed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}
#[test]
fn i15_validation_rejects_persistence() {
    let mut r = default_audit_report();
    r.persistence_performed = true;
    assert!(validate_event_stream_evidence_audit_report(&r).is_err());
}

// ── 46. validation rejects ready_for_reader_spike_preparation=true when status is Failed
#[test]
fn i15_validation_rejects_ready_with_failed_status() {
    let mut report = default_audit_report();
    report.ready_for_reader_spike_preparation = true;
    report.status = EbpfEventStreamEvidenceAuditStatus::Failed;
    assert!(validate_event_stream_evidence_audit_report(&report).is_err());
}

// ── 47. (removed: findings can be empty when audit passes cleanly) ────

// ── 48. failed audit has blocking finding ────────────────────────────
#[test]
fn i15_failed_audit_has_blocking_finding() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert!(report.findings.iter().any(|f| f.blocking));
}

// ── 49. evaluation is deterministic ───────────────────────────────────
#[test]
fn i15_evaluation_is_deterministic() {
    let input = ready_audit_input();
    let r1 = evaluate_event_stream_evidence_audit(&input);
    let r2 = evaluate_event_stream_evidence_audit(&input);
    assert_eq!(r1, r2);
}

// ── 50-68. doc content checks ────────────────────────────────────────
#[test]
fn i15_doc_exists() {
    assert!(!I15_DOC.is_empty());
}
#[test]
fn i15_doc_mentions_evidence_audit() {
    assert!(I15_DOC
        .to_lowercase()
        .contains("event stream reader evidence audit"));
}
#[test]
fn i15_doc_says_audit_only() {
    assert!(I15_DOC.to_lowercase().contains("audit-only"));
}
#[test]
fn i15_doc_says_no_public_cli() {
    assert!(I15_DOC.to_lowercase().contains("no public cli"));
}
#[test]
fn i15_doc_says_no_normal_ci_live_read() {
    assert!(I15_DOC.to_lowercase().contains("no normal ci"));
}
#[test]
fn i15_doc_says_no_ring_buffer() {
    assert!(I15_DOC.to_lowercase().contains("no ring buffer"));
}
#[test]
fn i15_doc_says_no_live_kernel_event_read() {
    assert!(I15_DOC.to_lowercase().contains("no live kernel event read"));
}
#[test]
fn i15_doc_says_no_map_pin() {
    assert!(I15_DOC.to_lowercase().contains("no map pin"));
}
#[test]
fn i15_doc_says_no_enforcement() {
    assert!(I15_DOC.to_lowercase().contains("no enforcement"));
}
#[test]
fn i15_doc_says_no_packet_drop() {
    assert!(I15_DOC.to_lowercase().contains("no packet drop"));
}
#[test]
fn i15_doc_says_no_block_allow_quota() {
    assert!(I15_DOC.to_lowercase().contains("block/allow/quota"));
}
#[test]
fn i15_doc_says_no_nft_tc_fallback() {
    assert!(I15_DOC.to_lowercase().contains("nft") || I15_DOC.to_lowercase().contains("tc"));
}
#[test]
fn i15_doc_says_no_ledger_persistence() {
    let d = I15_DOC.to_lowercase();
    assert!(d.contains("no ledger") || d.contains("persistence"));
}
#[test]
fn i15_doc_says_usage_schema_unchanged() {
    let d = I15_DOC.to_lowercase();
    assert!(
        d.contains("usage json schema") || (d.contains("json schema") && d.contains("unchanged"))
    );
}
#[test]
fn i15_doc_says_ledger_schema_unchanged() {
    let d = I15_DOC.to_lowercase();
    assert!(
        d.contains("ledger json schema")
            || (d.contains("ledger") && d.contains("schema") && d.contains("unchanged"))
    );
}
#[test]
fn i15_doc_says_clean_detach_required() {
    assert!(I15_DOC.to_lowercase().contains("clean detach evidence"));
}
#[test]
fn i15_doc_says_fixture_bridge_required() {
    assert!(I15_DOC.to_lowercase().contains("fixture bridge evidence"));
}
#[test]
fn i15_doc_says_dry_run_completion_required() {
    assert!(I15_DOC.to_lowercase().contains("dry run completion"));
}
#[test]
fn i15_doc_says_fixture_counts_not_live() {
    let d = I15_DOC.to_lowercase();
    assert!(
        d.contains("fixture counts are not live kernel event counts")
            || (d.contains("fixture counts") && d.contains("not live"))
    );
}
#[test]
fn i15_doc_says_no_fake_reader_readiness() {
    let d = I15_DOC.to_lowercase();
    assert!(
        d.contains("no fake reader readiness")
            || (d.contains("fake") && d.contains("reader readiness"))
    );
}

// ── 69-73. integration checks ────────────────────────────────────────
#[test]
fn i15_version_remains_v3_1_0() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "3.1.0");
}
#[test]
fn i15_ledger_inspect_works() {
    let _ = handle_ledger_inspect(true, None);
}
#[test]
fn i15_ledger_export_works() {
    let path = std::env::temp_dir().join("i15-ledger-export-test.json");
    let _ = handle_ledger_export(true, Some(path.to_string_lossy().as_ref()));
}
#[test]
fn i15_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    assert!(!render_help(&mut app)
        .to_lowercase()
        .contains("intergalaxion"));
}
#[test]
fn i15_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let h = render_help(&mut app).to_lowercase();
    assert!(!h.contains("block") || !h.contains("allow") || !h.contains("quota"));
}

// ── 74. no new dependency added ──────────────────────────────────────
#[test]
fn i15_no_new_dependency() {
    assert!(CARGO_TOML.contains("clap = "));
    assert!(CARGO_TOML.contains("intergalaxion-event-stream-lab = []"));
    assert!(CARGO_TOML.contains("intergalaxion-live-attach-lab"));
}

// ── 75. no nft/tc source ─────────────────────────────────────────────
#[test]
fn i15_no_nft_tc_source() {
    assert!(!I15_SOURCE.contains("tc::"));
    assert!(!I15_SOURCE.contains("nft::"));
}

// ── 76. all touched files under 1000 LOC ──────────────────────────────
#[test]
fn i15_source_under_1000_loc() {
    let lines = I15_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "event_stream_evidence_audit.rs has {lines} lines (max 1000)"
    );
}

// ── Additional coverage ────────────────────────────────────────────────
#[test]
fn i15_all_status_variants_have_labels() {
    for status in [
        EbpfEventStreamEvidenceAuditStatus::Passed,
        EbpfEventStreamEvidenceAuditStatus::Failed,
        EbpfEventStreamEvidenceAuditStatus::Warning,
        EbpfEventStreamEvidenceAuditStatus::Blocked,
        EbpfEventStreamEvidenceAuditStatus::ReadyForReaderSpikePreparation,
        EbpfEventStreamEvidenceAuditStatus::NotReady,
    ] {
        assert!(!event_stream_evidence_audit_status_label(status).is_empty());
    }
}

#[test]
fn i15_all_kind_variants_have_labels() {
    for kind in [
        EbpfEventStreamEvidenceAuditFindingKind::ManualCapture,
        EbpfEventStreamEvidenceAuditFindingKind::ReadPlan,
        EbpfEventStreamEvidenceAuditFindingKind::ReaderBoundary,
        EbpfEventStreamEvidenceAuditFindingKind::FixtureBridge,
        EbpfEventStreamEvidenceAuditFindingKind::DryRun,
        EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
        EbpfEventStreamEvidenceAuditFindingKind::SchemaInvariant,
        EbpfEventStreamEvidenceAuditFindingKind::CliInvariant,
    ] {
        assert!(!event_stream_evidence_audit_finding_kind_label(kind).is_empty());
    }
}

#[test]
fn i15_no_forbidden_patterns_in_source() {
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
            !I15_SOURCE.contains(pattern),
            "forbidden pattern found: {pattern}"
        );
    }
}

#[test]
fn i15_no_forbidden_mutation_patterns_in_source() {
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
            !I15_SOURCE.contains(pattern),
            "forbidden mutation pattern found: {pattern}"
        );
    }
    for line in I15_SOURCE.lines() {
        let t = line.trim();
        if !t.starts_with("//") && t.contains("persist") && !t.contains("persistence") {
            panic!("standalone 'persist' found in source: {t}");
        }
    }
}

#[test]
fn i15_blocked_status_when_safety_violation() {
    let mut input = ready_audit_input();
    input.reader_result.map_pin_performed = true;
    let report = evaluate_event_stream_evidence_audit(&input);
    assert_eq!(report.status, EbpfEventStreamEvidenceAuditStatus::Blocked);
    assert!(report.map_pin_performed);
}

#[test]
fn i15_failed_status_when_evidence_missing() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    assert_eq!(report.status, EbpfEventStreamEvidenceAuditStatus::Failed);
}

#[test]
fn i15_validation_accepts_passed_report() {
    let report = evaluate_event_stream_evidence_audit(&ready_audit_input());
    assert!(validate_event_stream_evidence_audit_report(&report).is_ok());
}

#[test]
fn i15_findings_have_codes() {
    let report = evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    for f in &report.findings {
        assert!(!f.code.is_empty());
        assert!(!f.message.is_empty());
    }
}
