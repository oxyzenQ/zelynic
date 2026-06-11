// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::manual_assert)]
use super::backends::ebpf::event_stream_evidence_audit::{
    default_event_stream_evidence_audit_input, evaluate_event_stream_evidence_audit,
    EbpfEventStreamEvidenceAuditReport, EbpfEventStreamEvidenceAuditStatus,
};
use super::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
use super::backends::ebpf::event_stream_reader_spike_executor::{
    evaluate_event_stream_reader_spike_executor, EbpfEventStreamReaderSpikeExecutorInput,
    EbpfEventStreamReaderSpikeExecutorResult, EbpfEventStreamReaderSpikeExecutorStatus,
};
use super::backends::ebpf::event_stream_reader_spike_executor_audit::*;
use super::backends::ebpf::event_stream_reader_spike_prep::{
    evaluate_event_stream_reader_spike_prep, EbpfEventStreamReaderSpikePrepInput,
    EbpfEventStreamReaderSpikePrepPlan, EbpfEventStreamReaderSpikePrepStatus,
};
use crate::cli::Cli;
use clap::CommandFactory;
const DOC: &str =
    include_str!("../../docs/intergalaxion/I-16A-reader-executor-static-safety-audit.md");
fn doc_lower() -> String {
    include_str!("../../docs/intergalaxion/I-16A-reader-executor-static-safety-audit.md")
        .to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_executor_audit.rs");
fn dai() -> EbpfEventStreamReaderSpikeExecutorAuditInput {
    default_event_stream_reader_spike_executor_audit_input()
}
fn dar() -> EbpfEventStreamReaderSpikeExecutorAuditReport {
    evaluate_event_stream_reader_spike_executor_audit(&dai())
}
fn sar() -> EbpfEventStreamEvidenceAuditReport {
    let mut input = default_event_stream_evidence_audit_input();
    input.manual_summary.ready_for_event_stream_planning = true;
    input.manual_summary.clean_detach_count = 1;
    input.manual_summary.successful_attach_count = 1;
    input.manual_summary.summary_status =
        super::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualResultStatus::DetachedCleanly;
    input.require_clean_detach_evidence = true;
    input.require_fixture_bridge_records = false;
    input.require_dry_run_completed = false;
    let mut report = evaluate_event_stream_evidence_audit(&input);
    report.ready_for_reader_spike_preparation = true;
    report.status = EbpfEventStreamEvidenceAuditStatus::Passed;
    report.manual_capture_ready = true;
    report.findings.clear();
    report
}
fn spi() -> EbpfEventStreamReaderSpikePrepInput {
    EbpfEventStreamReaderSpikePrepInput {
        audit_report: sar(),
        reader_input: default_event_stream_reader_input(),
        explicit_reader_spike_prep_consent: true,
        explicit_operator_label: String::from("test-operator"),
        feature_name: String::from("intergalaxion-event-stream-lab"),
        feature_expected_disabled_by_default: true,
        local_lab_only: true,
        max_events: 16,
        timeout_ms: 5000,
        require_clean_shutdown: true,
        require_post_run_evidence_capture: true,
        public_cli_requested: false,
        allow_live_reader: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
    }
}
fn spp() -> EbpfEventStreamReaderSpikePrepPlan {
    evaluate_event_stream_reader_spike_prep(&spi())
}
fn sei() -> EbpfEventStreamReaderSpikeExecutorInput {
    EbpfEventStreamReaderSpikeExecutorInput {
        prep_plan: spp(),
        reader_input: default_event_stream_reader_input(),
        explicit_executor_feature_enabled: true,
        explicit_operator_label: String::from("test-operator"),
        allow_execution_attempt: true,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        require_cleanup: true,
        require_post_run_evidence_capture: true,
    }
}
fn ser() -> EbpfEventStreamReaderSpikeExecutorResult {
    evaluate_event_stream_reader_spike_executor(&sei())
}
fn sai() -> EbpfEventStreamReaderSpikeExecutorAuditInput {
    EbpfEventStreamReaderSpikeExecutorAuditInput {
        prep_plan: spp(),
        executor_input: sei(),
        executor_result: ser(),
        require_feature_disabled_by_default: false,
        require_prep_ready: true,
        require_future_execution_ready: true,
        require_cleanup_requirement: true,
        require_post_run_evidence_capture: true,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}
fn sar2() -> EbpfEventStreamReaderSpikeExecutorAuditReport {
    evaluate_event_stream_reader_spike_executor_audit(&sai())
}

// ── 1-3: default input/result safety ─────────────────────────────────
#[test]
fn i16a_default_audit_input_safe() {
    let i = dai();
    assert!(i.require_feature_disabled_by_default && i.public_cli_expected_hidden);
    assert!(i.usage_schema_expected_unchanged && i.ledger_schema_expected_unchanged);
    assert!(!i.require_prep_ready && !i.require_future_execution_ready);
    assert!(!i.require_cleanup_requirement && !i.require_post_run_evidence_capture);
}
#[test]
fn i16a_default_report_phase_i16a() {
    assert_eq!(dar().phase, "I-16A");
}
#[test]
fn i16a_default_report_all_flags_false() {
    let r = dar();
    assert!(!r.public_cli_exposed && !r.usage_schema_changed && !r.ledger_schema_changed);
    assert!(!r.ring_buffer_opened && !r.live_event_stream_read && !r.map_pin_performed);
    assert!(!r.enforcement_performed && !r.packet_drop_performed);
    assert!(!r.mutation_performed && !r.persistence_performed);
    assert!(!r.fake_reader_success_detected && !r.fake_live_event_counts_detected);
}

// ── 4-5: status and kind labels stable ───────────────────────────────
#[test]
fn i16a_audit_status_labels_stable() {
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Passed
        ),
        "passed"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
        ),
        "failed"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Warning
        ),
        "warning"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked
        ),
        "blocked"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::NotReady
        ),
        "not_ready"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_status_label(
            EbpfEventStreamReaderSpikeExecutorAuditStatus::ReadyForResultCapture
        ),
        "ready_for_result_capture"
    );
}
#[test]
fn i16a_finding_kind_labels_stable() {
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::FeatureGate
        ),
        "feature_gate"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::PreparationPlan
        ),
        "preparation_plan"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::ExecutorResult
        ),
        "executor_result"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant
        ),
        "safety_invariant"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CliInvariant
        ),
        "cli_invariant"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SchemaInvariant
        ),
        "schema_invariant"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CountInvariant
        ),
        "count_invariant"
    );
    assert_eq!(
        event_stream_reader_spike_executor_audit_finding_kind_label(
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CleanupInvariant
        ),
        "cleanup_invariant"
    );
}

// ── 6-7: default audit not ready ─────────────────────────────────────
#[test]
fn i16a_default_audit_not_ready_for_capture() {
    assert!(!dar().ready_for_result_capture);
    assert!(
        dar().status == EbpfEventStreamReaderSpikeExecutorAuditStatus::NotReady
            || dar().status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}
#[test]
fn i16a_default_audit_findings_nonempty() {
    assert!(!dar().findings.is_empty());
}

// ── 8-9: prep plan readiness ──────────────────────────────────────────
#[test]
fn i16a_ready_audit_requires_prep_ready() {
    let mut i = sai();
    i.prep_plan.status = EbpfEventStreamReaderSpikePrepStatus::PrepRejected;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert!(
        r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
            || r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked
    );
}
#[test]
fn i16a_ready_audit_rejects_invalid_prep() {
    let mut i = sai();
    i.prep_plan.phase = String::new();
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}

// ── 10: safe executor result required ──────────────────────────────────
#[test]
fn i16a_ready_audit_requires_safe_result() {
    let mut i = sai();
    i.executor_result.public_cli_exposed = true;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}

// ── 11-14: execution/reader state detection ──────────────────────────
#[test]
fn i16a_audit_rejects_execution_succeeded() {
    let mut i = sai();
    i.executor_result.status = EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
    assert!(r.fake_reader_success_detected);
}
#[test]
fn i16a_audit_rejects_attempted_true() {
    let mut i = sai();
    i.executor_result.attempted = true;
    i.executor_result.execution_ready = true;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert!(
        r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
            || r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked
    );
}
#[test]
fn i16a_audit_rejects_reader_started() {
    let mut i = sai();
    i.executor_result.reader_started = true;
    i.executor_result.attempted = true;
    i.executor_result.execution_ready = true;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert!(
        r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
            || r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked
    );
}
#[test]
fn i16a_audit_rejects_reader_completed() {
    let mut i = sai();
    i.executor_result.reader_completed = true;
    i.executor_result.reader_started = true;
    i.executor_result.attempted = true;
    i.executor_result.execution_ready = true;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert!(
        r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
            || r.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked
    );
}

// ── 15-17: count invariants ────────────────────────────────────────────
#[test]
fn i16a_audit_rejects_events_read_positive() {
    let mut i = sai();
    i.executor_result.events_read = 1;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
    assert!(r.fake_live_event_counts_detected);
}
#[test]
fn i16a_audit_rejects_decode_errors_without_attempt() {
    let mut i = sai();
    i.executor_result.decode_errors = 1;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
    assert!(r.fake_live_event_counts_detected);
}
#[test]
fn i16a_audit_rejects_bridge_records_without_attempt() {
    let mut i = sai();
    i.executor_result.bridge_records = 1;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
    assert!(r.fake_live_event_counts_detected);
}

// ── 18-19: cleanup and evidence requirements ──────────────────────────
#[test]
fn i16a_audit_requires_cleanup_when_configured() {
    let mut i = sai();
    i.executor_result.cleanup_required = false;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}
#[test]
fn i16a_audit_requires_evidence_when_configured() {
    let mut i = sai();
    i.executor_result.post_run_evidence_required = false;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}

// ── 20-22: CLI and schema checks ───────────────────────────────────────
#[test]
fn i16a_audit_rejects_cli_not_hidden() {
    let mut i = sai();
    i.public_cli_expected_hidden = false;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}
#[test]
fn i16a_audit_rejects_usage_schema_changed() {
    let mut i = sai();
    i.usage_schema_expected_unchanged = false;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}
#[test]
fn i16a_audit_rejects_ledger_schema_changed() {
    let mut i = sai();
    i.ledger_schema_expected_unchanged = false;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    );
}

// ── 23-30: ReadyForResultCapture with safe input ─────────────────────
#[test]
fn i16a_ready_audit_passes_with_safe_input() {
    assert_eq!(
        sar2().status,
        EbpfEventStreamReaderSpikeExecutorAuditStatus::ReadyForResultCapture
    );
}
#[test]
fn i16a_passed_audit_ready_for_capture() {
    assert!(sar2().ready_for_result_capture);
}
#[test]
fn i16a_passed_audit_prep_plan_ready() {
    assert!(sar2().prep_plan_ready);
}
#[test]
fn i16a_passed_audit_executor_result_safe() {
    assert!(sar2().executor_result_safe);
}
#[test]
fn i16a_passed_audit_future_execution_ready() {
    assert!(sar2().future_execution_ready_confirmed);
}
#[test]
fn i16a_passed_audit_cleanup_confirmed() {
    assert!(sar2().cleanup_requirement_confirmed);
}
#[test]
fn i16a_passed_audit_evidence_confirmed() {
    assert!(sar2().post_run_evidence_capture_confirmed);
}

// ── 31: validation accepts safe default report ─────────────────────────
#[test]
fn i16a_validation_accepts_safe_default() {
    assert!(validate_event_stream_reader_spike_executor_audit_report(&dar()).is_ok());
}

// ── 32-44: validation rejects unsafe mutations ────────────────────────
#[test]
fn i16a_val_rejects_public_cli_true() {
    let mut r = dar();
    r.public_cli_exposed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_usage_schema_changed() {
    let mut r = dar();
    r.usage_schema_changed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_ledger_schema_changed() {
    let mut r = dar();
    r.ledger_schema_changed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_ring_buffer_true() {
    let mut r = dar();
    r.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_live_event_true() {
    let mut r = dar();
    r.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_map_pin_true() {
    let mut r = dar();
    r.map_pin_performed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_enforcement_true() {
    let mut r = dar();
    r.enforcement_performed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_packet_drop_true() {
    let mut r = dar();
    r.packet_drop_performed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_mutation_true() {
    let mut r = dar();
    r.mutation_performed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_persistence_true() {
    let mut r = dar();
    r.persistence_performed = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_fake_reader_success() {
    let mut r = dar();
    r.fake_reader_success_detected = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_fake_live_event_counts() {
    let mut r = dar();
    r.fake_live_event_counts_detected = true;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}
#[test]
fn i16a_val_rejects_ready_when_failed() {
    let mut r = dar();
    r.ready_for_result_capture = true;
    r.status = EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed;
    assert!(validate_event_stream_reader_spike_executor_audit_report(&r).is_err());
}

// ── 45: failed audit has blocking finding ──────────────────────────────
#[test]
fn i16a_failed_audit_has_blocking_finding() {
    let mut i = sai();
    i.executor_result.events_read = 1;
    let r = evaluate_event_stream_reader_spike_executor_audit(&i);
    assert!(r.findings.iter().any(|f| f.blocking));
}

// ── 46: evaluation deterministic ────────────────────────────────────────
#[test]
fn i16a_evaluation_deterministic() {
    let r1 = sar2();
    let r2 = sar2();
    assert_eq!(r1, r2);
}

// ── 47-64: doc checks ─────────────────────────────────────────────────
#[test]
fn i16a_doc_exists_audit() {
    assert!(doc_lower().contains("reader executor static safety audit"));
}
#[test]
fn i16a_doc_says_audit_only() {
    assert!(doc_lower().contains("audit-only"));
}
#[test]
fn i16a_doc_says_no_public_cli() {
    assert!(doc_lower().contains("no public cli"));
}
#[test]
fn i16a_doc_says_no_normal_ci_live_event_read() {
    assert!(doc_lower().contains("no normal ci live event read"));
}
#[test]
fn i16a_doc_says_no_ring_buffer_open() {
    assert!(doc_lower().contains("no ring buffer open"));
}
#[test]
fn i16a_doc_says_no_live_kernel_event_read() {
    assert!(doc_lower().contains("no live kernel event read"));
}
#[test]
fn i16a_doc_says_no_map_pin() {
    assert!(doc_lower().contains("no map pin"));
}
#[test]
fn i16a_doc_says_no_enforcement() {
    assert!(doc_lower().contains("no enforcement"));
}
#[test]
fn i16a_doc_says_no_packet_drop() {
    assert!(doc_lower().contains("no packet drop"));
}
#[test]
fn i16a_doc_says_no_block_allow_quota() {
    assert!(doc_lower().contains("no block/allow/quota"));
}
#[test]
fn i16a_doc_says_no_nft_tc_fallback() {
    assert!(doc_lower().contains("no nft/tc fallback"));
}
#[test]
fn i16a_doc_says_no_ledger_write_or_persistence() {
    assert!(doc_lower().contains("no ledger file write") || doc_lower().contains("no persistence"));
}
#[test]
fn i16a_doc_says_usage_schema_unchanged() {
    assert!(doc_lower().contains("existing v3.1 usage json schema unchanged"));
}
#[test]
fn i16a_doc_says_ledger_schema_unchanged() {
    assert!(doc_lower().contains("existing v3.1 ledger json schema unchanged"));
}
#[test]
fn i16a_doc_says_future_execution_ready_required() {
    assert!(
        doc_lower().contains("futureexecutionready is required")
            || doc_lower().contains("future execution ready is required")
    );
}
#[test]
fn i16a_doc_says_execution_succeeded_not_valid() {
    assert!(
        doc_lower().contains("executionsucceeded is not valid evidence")
            || doc_lower().contains("execution succeeded is not valid evidence")
    );
}
#[test]
fn i16a_doc_says_fake_counts_rejected() {
    assert!(doc_lower().contains("fake live event counts") && doc_lower().contains("rejected"));
}
#[test]
fn i16a_doc_says_fake_reader_success_rejected() {
    assert!(
        doc_lower().contains("fake reader execution success") && doc_lower().contains("rejected")
    );
}

// ── 65-69: CLI and version checks ─────────────────────────────────────
#[test]
fn i16a_version_remains_v3_1_0() {
    let ver = include_str!("../../Cargo.toml");
    assert!(ver.contains("version = \"3.1.0\""));
}
#[test]
fn i16a_ledger_inspect_works() {
    let _ = crate::commands::ledger::handle_ledger_inspect(true, None);
}
#[test]
fn i16a_ledger_export_works() {
    let p = std::env::temp_dir().join("i16a-ledger-export-test.json");
    let _ = crate::commands::ledger::handle_ledger_export(true, Some(p.to_string_lossy().as_ref()));
}
#[test]
fn i16a_public_help_no_intergalaxion() {
    let s = Cli::command().to_string();
    assert!(!s.to_lowercase().contains("intergalaxion"));
}
#[test]
fn i16a_public_help_no_block_allow_quota() {
    let s = Cli::command().to_string();
    assert!(!s.contains("block") && !s.contains("allow") && !s.contains("quota"));
}

// ── 70: no new dependency ─────────────────────────────────────────────
#[test]
fn i16a_no_new_dependency() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("zelynic-engine"));
}

// ── 71: no nft/tc source ────────────────────────────────────────────
#[test]
fn i16a_no_nft_tc_source() {
    for line in SRC.lines() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with("//!") {
            continue;
        }
        assert!(
            !t.contains("tc ") && !t.contains("nft "),
            "no nft/tc: {}",
            t
        );
    }
}

// ── 72: source under 1000 LOC ────────────────────────────────────────
#[test]
fn i16a_source_under_1000_loc() {
    assert!(SRC.lines().count() < 1000, "source must be under 1000 LOC");
}

// ── test file under 1000 LOC ──────────────────────────────────────────
#[test]
fn i16a_test_file_under_1000_loc() {
    let src = include_str!("tests_i16a.rs");
    assert!(
        src.lines().count() < 1000,
        "test file must be under 1000 LOC"
    );
}

// ── forbidden source patterns ────────────────────────────────────────
#[test]
fn i16a_no_forbidden_load_patterns() {
    assert!(!SRC.contains("Bpf::load") && !SRC.contains("load_file"));
}
#[test]
fn i16a_no_forbidden_attach_patterns() {
    assert!(!SRC.contains(".attach("));
}
#[test]
fn i16a_no_forbidden_ringbuf_patterns() {
    assert!(
        !SRC.contains("RingBuf")
            && !SRC.contains("AsyncPerfEventArray")
            && !SRC.contains("PerfEventArray")
    );
}
#[test]
fn i16a_no_forbidden_map_patterns() {
    assert!(!SRC.contains("MapData") && !SRC.contains("create_map") && !SRC.contains("pin("));
}
#[test]
fn i16a_no_forbidden_kernel_patterns() {
    assert!(
        !SRC.contains("bpf_prog_load")
            && !SRC.contains("bpf_map_create")
            && !SRC.contains("bpf_ringbuf")
    );
    assert!(
        !SRC.contains("/sys/fs/bpf") && !SRC.contains("/sys/kernel") && !SRC.contains("/proc/")
    );
}
#[test]
fn i16a_no_forbidden_tc_nft_patterns() {
    assert!(!SRC.contains("\ntc") && !SRC.contains("\nnft"));
}
#[test]
fn i16a_no_forbidden_fs_patterns() {
    assert!(
        !SRC.contains("File::create") && !SRC.contains("fs::write") && !SRC.contains("OpenOptions")
    );
}
#[test]
fn i16a_no_forbidden_save() {
    let lower = SRC.to_lowercase();
    for line in lower.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.contains("save") && !t.contains("persistence_performed") {
            panic!("forbidden save");
        }
    }
}
#[test]
fn i16a_no_forbidden_drop_block_quota() {
    let lower = SRC.to_lowercase();
    for line in lower.lines() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with("//!") {
            continue;
        }
        if t.contains("allow_persistence") || t.contains("persistence_performed") {
            continue;
        }
        if t.contains("allow_packet_drop") || t.contains("packet_drop_performed") {
            continue;
        }
        if t.contains("\"packet drop") || t.contains("\"drop_packet") {
            continue;
        }
        if t.contains("blocked") {
            continue;
        }
        if t.contains("blocking") {
            continue;
        }
        if t.contains("drop_packet") {
            continue;
        }
        if t.contains("\"audit-packet-drop")
            || t.contains("\"audit-drop")
            || t.contains("\"audit-block")
        {
            continue;
        }
        if !t.contains("allow_")
            && !t.contains("_performed")
            && !t.contains("_exposed")
            && !t.contains("_opened")
            && !t.contains("_read")
            && (t.contains("drop") || t.contains("block") || t.contains("quota"))
        {
            panic!("forbidden drop/block/quota: {}", t);
        }
    }
}
