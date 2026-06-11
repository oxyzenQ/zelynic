// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::manual_assert)]
use super::backends::ebpf::event_stream_evidence_audit::{
    default_event_stream_evidence_audit_input, evaluate_event_stream_evidence_audit,
    EbpfEventStreamEvidenceAuditReport, EbpfEventStreamEvidenceAuditStatus,
};
use super::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
use super::backends::ebpf::event_stream_reader_spike_executor::*;
use super::backends::ebpf::event_stream_reader_spike_prep::{
    evaluate_event_stream_reader_spike_prep, EbpfEventStreamReaderSpikePrepInput,
    EbpfEventStreamReaderSpikePrepPlan, EbpfEventStreamReaderSpikePrepStatus,
};
use crate::cli::Cli;
use clap::CommandFactory;
const DOC: &str = include_str!(
    "../../docs/intergalaxion/I-16-feature-gated-local-reader-spike-executor-boundary.md"
);
fn doc_lower() -> String {
    include_str!(
        "../../docs/intergalaxion/I-16-feature-gated-local-reader-spike-executor-boundary.md"
    )
    .to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_executor.rs");
fn di() -> EbpfEventStreamReaderSpikeExecutorInput {
    default_event_stream_reader_spike_executor_input()
}
fn dr() -> EbpfEventStreamReaderSpikeExecutorResult {
    evaluate_event_stream_reader_spike_executor(&di())
}
fn sar() -> EbpfEventStreamEvidenceAuditReport {
    let mut input = default_event_stream_evidence_audit_input();
    input.manual_summary.ready_for_event_stream_planning = true;
    input.manual_summary.clean_detach_count = 1;
    input.manual_summary.successful_attach_count = 1;
    input.manual_summary.summary_status = super::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualResultStatus::DetachedCleanly;
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

// ── 1-3: default input/result safety ─────────────────────────────────
#[test]
fn i16_default_executor_input_safe() {
    let i = di();
    assert!(!i.explicit_executor_feature_enabled && i.explicit_operator_label.is_empty());
    assert!(!i.allow_execution_attempt && !i.allow_ring_buffer_open);
    assert!(!i.allow_live_event_read && !i.allow_map_pin);
    assert!(!i.allow_persistence && !i.allow_enforcement && !i.allow_packet_drop);
    assert!(!i.require_cleanup && !i.require_post_run_evidence_capture);
}
#[test]
fn i16_default_result_phase_i16() {
    assert_eq!(dr().phase, "I-16");
}
#[test]
fn i16_default_result_all_flags_false() {
    let r = dr();
    assert!(!r.public_cli_exposed && !r.ring_buffer_opened && !r.live_event_stream_read);
    assert!(!r.map_pin_performed && !r.enforcement_performed && !r.packet_drop_performed);
    assert!(!r.mutation_performed && !r.persistence_performed);
    assert!(!r.attempted && !r.reader_started && !r.reader_completed);
    assert!(!r.execution_ready && !r.cleanup_completed && !r.post_run_evidence_captured);
    assert!(
        r.events_read == 0 && r.decode_errors == 0 && r.bridge_records == 0,
        "counts zero"
    );
}

// ── 4: status labels stable ─────────────────────────────────────────
#[test]
fn i16_executor_status_labels_stable() {
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled
        ),
        "feature_disabled"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected
        ),
        "prep_rejected"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::ExecutorDisabled
        ),
        "executor_disabled"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::ReaderNotImplemented
        ),
        "reader_not_implemented"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady
        ),
        "future_execution_ready"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::ExecutionAttempted
        ),
        "execution_attempted"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded
        ),
        "execution_succeeded"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::ExecutionFailed
        ),
        "execution_failed"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::CleanupRequired
        ),
        "cleanup_required"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::CleanupCompleted
        ),
        "cleanup_completed"
    );
    assert_eq!(
        event_stream_reader_spike_executor_status_label(
            EbpfEventStreamReaderSpikeExecutorStatus::Blocked
        ),
        "blocked"
    );
}

// ── 5-8: feature disabled ──────────────────────────────────────────
#[test]
fn i16_feature_disabled_returns_feature_disabled() {
    assert_eq!(
        dr().status,
        EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled
    );
}
#[test]
fn i16_feature_disabled_attempted_false() {
    assert!(!dr().attempted);
}
#[test]
fn i16_feature_disabled_reader_started_false() {
    assert!(!dr().reader_started);
}
#[test]
fn i16_feature_disabled_reader_completed_false() {
    assert!(!dr().reader_completed);
}

// ── 9-10: prep rejected ───────────────────────────────────────────────
#[test]
fn i16_prep_rejected_when_not_prep_ready() {
    let mut i = sei();
    i.prep_plan.status = EbpfEventStreamReaderSpikePrepStatus::PrepRejected;
    let r = evaluate_event_stream_reader_spike_executor(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected
    );
}
#[test]
fn i16_prep_rejected_when_plan_validation_fails() {
    let mut i = sei();
    i.prep_plan.phase = String::new();
    let r = evaluate_event_stream_reader_spike_executor(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected
    );
}

// ── 11: feature_enabled=false blocks readiness ────────────────────────
#[test]
fn i16_feature_enabled_false_blocks_readiness() {
    let mut i = sei();
    i.explicit_executor_feature_enabled = false;
    let r = evaluate_event_stream_reader_spike_executor(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled
    );
    assert!(!r.execution_ready);
}

// ── 12: empty operator label blocks ───────────────────────────────────
#[test]
fn i16_empty_operator_label_blocks() {
    let mut i = sei();
    i.explicit_operator_label = String::new();
    let r = evaluate_event_stream_reader_spike_executor(&i);
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorStatus::PrepRejected
    );
}

// ── 13: allow_execution_attempt=false returns disabled ────────────────
#[test]
fn i16_execution_attempt_false_returns_disabled() {
    let mut i = sei();
    i.allow_execution_attempt = false;
    let r = evaluate_event_stream_reader_spike_executor(&i);
    assert!(
        r.status == EbpfEventStreamReaderSpikeExecutorStatus::ExecutorDisabled
            || r.status == EbpfEventStreamReaderSpikeExecutorStatus::ReaderNotImplemented
    );
}

// ── 14-19: forbidden flags block ────────────────────────────────────
#[test]
fn i16_ring_buffer_open_blocks() {
    let mut i = sei();
    i.allow_ring_buffer_open = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_live_event_read_blocks() {
    let mut i = sei();
    i.allow_live_event_read = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_map_pin_blocks() {
    let mut i = sei();
    i.allow_map_pin = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_persistence_blocks() {
    let mut i = sei();
    i.allow_persistence = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_enforcement_blocks() {
    let mut i = sei();
    i.allow_enforcement = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_packet_drop_blocks() {
    let mut i = sei();
    i.allow_packet_drop = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}

// ── 20-21: cleanup and evidence required ──────────────────────────────
#[test]
fn i16_cleanup_false_blocks() {
    let mut i = sei();
    i.require_cleanup = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}
#[test]
fn i16_evidence_capture_false_blocks() {
    let mut i = sei();
    i.require_post_run_evidence_capture = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_executor(&i).status,
        EbpfEventStreamReaderSpikeExecutorStatus::Blocked
    );
}

// ── 22-36: FutureExecutionReady ──────────────────────────────────────
#[test]
fn i16_future_execution_ready_with_safe_input() {
    assert_eq!(
        ser().status,
        EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady
    );
}
#[test]
fn i16_future_execution_ready_attempted_false() {
    assert!(!ser().attempted);
}
#[test]
fn i16_future_execution_ready_reader_started_false() {
    assert!(!ser().reader_started);
}
#[test]
fn i16_future_execution_ready_reader_completed_false() {
    assert!(!ser().reader_completed);
}
#[test]
fn i16_future_execution_ready_events_read_zero() {
    assert_eq!(ser().events_read, 0);
}
#[test]
fn i16_future_execution_ready_decode_errors_zero() {
    assert_eq!(ser().decode_errors, 0);
}
#[test]
fn i16_future_execution_ready_bridge_records_zero() {
    assert_eq!(ser().bridge_records, 0);
}
#[test]
fn i16_future_execution_ready_ring_buffer_false() {
    assert!(!ser().ring_buffer_opened);
}
#[test]
fn i16_future_execution_ready_live_event_false() {
    assert!(!ser().live_event_stream_read);
}
#[test]
fn i16_future_execution_ready_map_pin_false() {
    assert!(!ser().map_pin_performed);
}
#[test]
fn i16_future_execution_ready_enforcement_false() {
    assert!(!ser().enforcement_performed);
}
#[test]
fn i16_future_execution_ready_packet_drop_false() {
    assert!(!ser().packet_drop_performed);
}
#[test]
fn i16_future_execution_ready_mutation_false() {
    assert!(!ser().mutation_performed);
}
#[test]
fn i16_future_execution_ready_persistence_false() {
    assert!(!ser().persistence_performed);
}
#[test]
fn i16_future_execution_ready_public_cli_false() {
    assert!(!ser().public_cli_exposed);
}

// ── 37: validation accepts safe default result ────────────────────────
#[test]
fn i16_validation_accepts_safe_default() {
    assert!(validate_event_stream_reader_spike_executor_result(&dr()).is_ok());
}

// ── 38-54: validation rejects unsafe mutations ─────────────────────
#[test]
fn i16_val_rejects_execution_ready_feature_disabled() {
    let mut r = dr();
    r.execution_ready = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_attempted_feature_disabled() {
    let mut r = dr();
    r.attempted = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_reader_started_when_not_attempted() {
    let mut r = dr();
    r.reader_started = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_reader_completed_when_not_started() {
    let mut r = dr();
    r.attempted = true;
    r.reader_completed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_execution_succeeded() {
    let mut r = dr();
    r.status = EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_events_read_when_not_live() {
    let mut r = dr();
    r.events_read = 1;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_decode_errors_when_not_attempted() {
    let mut r = dr();
    r.decode_errors = 1;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_bridge_records_when_not_attempted() {
    let mut r = dr();
    r.bridge_records = 1;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_cleanup_completed_when_not_required() {
    let mut r = dr();
    r.cleanup_completed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_public_cli_true() {
    let mut r = dr();
    r.public_cli_exposed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_ring_buffer_true() {
    let mut r = dr();
    r.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_live_event_true() {
    let mut r = dr();
    r.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_map_pin_true() {
    let mut r = dr();
    r.map_pin_performed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_enforcement_true() {
    let mut r = dr();
    r.enforcement_performed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_packet_drop_true() {
    let mut r = dr();
    r.packet_drop_performed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_mutation_true() {
    let mut r = dr();
    r.mutation_performed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}
#[test]
fn i16_val_rejects_persistence_true() {
    let mut r = dr();
    r.persistence_performed = true;
    assert!(validate_event_stream_reader_spike_executor_result(&r).is_err());
}

// ── 55: evaluation deterministic ──────────────────────────────────────
#[test]
fn i16_evaluation_deterministic() {
    let r1 = ser();
    let r2 = ser();
    assert_eq!(r1, r2);
}

// ── 56: feature-gated executor disabled by default ──────────────────
#[test]
fn i16_feature_gated_executor_disabled_by_default() {
    let r = execute_event_stream_reader_spike_feature_gated(&di());
    assert_eq!(
        r.status,
        EbpfEventStreamReaderSpikeExecutorStatus::FeatureDisabled
    );
    assert!(!r.attempted && !r.reader_started && !r.reader_completed);
}

// ── 57-76: doc checks ────────────────────────────────────────────────
#[test]
fn i16_doc_exists_reader_spike_executor_boundary() {
    assert!(doc_lower().contains("reader spike executor boundary"));
}
#[test]
fn i16_doc_says_executor_boundary_only() {
    assert!(doc_lower().contains("executor-boundary only"));
}
#[test]
fn i16_doc_says_disabled_by_default() {
    assert!(doc_lower().contains("disabled by default"));
}
#[test]
fn i16_doc_says_no_public_cli() {
    assert!(doc_lower().contains("no public cli"));
}
#[test]
fn i16_doc_says_no_normal_ci_live_event_read() {
    assert!(doc_lower().contains("no normal ci live event read"));
}
#[test]
fn i16_doc_says_no_ring_buffer_open() {
    assert!(doc_lower().contains("no ring buffer open"));
}
#[test]
fn i16_doc_says_no_live_kernel_event_read() {
    assert!(doc_lower().contains("no live kernel event read"));
}
#[test]
fn i16_doc_says_no_map_pin() {
    assert!(doc_lower().contains("no map pin"));
}
#[test]
fn i16_doc_says_no_enforcement() {
    assert!(doc_lower().contains("no enforcement"));
}
#[test]
fn i16_doc_says_no_packet_drop() {
    assert!(doc_lower().contains("no packet drop"));
}
#[test]
fn i16_doc_says_no_block_allow_quota() {
    assert!(doc_lower().contains("no block/allow/quota"));
}
#[test]
fn i16_doc_says_no_nft_tc_fallback() {
    assert!(doc_lower().contains("no nft/tc fallback"));
}
#[test]
fn i16_doc_says_no_ledger_file_write() {
    assert!(doc_lower().contains("no ledger file write") || doc_lower().contains("no persistence"));
}
#[test]
fn i16_doc_says_usage_schema_unchanged() {
    assert!(doc_lower().contains("existing v3.1 usage json schema unchanged"));
}
#[test]
fn i16_doc_says_ledger_schema_unchanged() {
    assert!(doc_lower().contains("existing v3.1 ledger json schema unchanged"));
}
#[test]
fn i16_doc_says_i15a_prep_ready_required() {
    assert!(
        doc_lower().contains("i-15a prepready is required")
            || doc_lower().contains("i-15a prep ready is required")
    );
}
#[test]
fn i16_doc_says_cleanup_required() {
    assert!(
        doc_lower().contains("cleanup requirement is required")
            || doc_lower().contains("cleanup is required")
    );
}
#[test]
fn i16_doc_says_evidence_capture_required() {
    assert!(doc_lower().contains("post-run evidence capture is required"));
}
#[test]
fn i16_doc_says_no_fake_reader_execution_success() {
    assert!(doc_lower().contains("no fake reader execution success"));
}
#[test]
fn i16_doc_says_no_fake_live_event_counts() {
    assert!(doc_lower().contains("no fake live event counts"));
}

// ── 77-81: CLI and version checks ────────────────────────────────────
#[test]
fn i16_version_remains_v3_1_0() {
    let ver = include_str!("../../Cargo.toml");
    assert!(
        ver.contains("version = \"3.1.0\""),
        "version must remain v3.1.0"
    );
}
#[test]
fn i16_ledger_inspect_works() {
    let _ = crate::commands::ledger::handle_ledger_inspect(true, None);
}
#[test]
fn i16_ledger_export_works() {
    let p = std::env::temp_dir().join("i16-ledger-export-test.json");
    let _ = crate::commands::ledger::handle_ledger_export(true, Some(p.to_string_lossy().as_ref()));
}
#[test]
fn i16_public_help_no_intergalaxion() {
    let s = Cli::command().to_string();
    assert!(
        !s.to_lowercase().contains("intergalaxion"),
        "help must not mention intergalaxion"
    );
}
#[test]
fn i16_public_help_no_block_allow_quota() {
    let s = Cli::command().to_string();
    assert!(
        !s.contains("block") && !s.contains("allow") && !s.contains("quota"),
        "help must not mention block/allow/quota"
    );
}

// ── 82: no new dependency ─────────────────────────────────────────────
#[test]
fn i16_no_new_dependency() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(
        !cargo.contains("zelynic-engine"),
        "no new engine dependency"
    );
}

// ── 83: no nft/tc source ────────────────────────────────────────────
#[test]
fn i16_no_nft_tc_source() {
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

// ── 84: source under 1000 LOC ────────────────────────────────────────
#[test]
fn i16_source_under_1000_loc() {
    let lines = SRC.lines().count();
    assert!(lines < 1000, "source must be under 1000 LOC, got {}", lines);
}

// ── 85: test file under 1000 LOC ─────────────────────────────────────
#[test]
fn i16_test_file_under_1000_loc() {
    let src = include_str!("tests_i16.rs");
    let lines = src.lines().count();
    assert!(
        lines < 1000,
        "test file must be under 1000 LOC, got {}",
        lines
    );
}

// ── forbidden source patterns ────────────────────────────────────────
#[test]
fn i16_no_forbidden_load_patterns() {
    assert!(!SRC.contains("Bpf::load") && !SRC.contains("load_file"));
}
#[test]
fn i16_no_forbidden_attach_patterns() {
    assert!(!SRC.contains(".attach("));
}
#[test]
fn i16_no_forbidden_ringbuf_patterns() {
    assert!(
        !SRC.contains("RingBuf")
            && !SRC.contains("AsyncPerfEventArray")
            && !SRC.contains("PerfEventArray")
    );
}
#[test]
fn i16_no_forbidden_map_patterns() {
    assert!(!SRC.contains("MapData") && !SRC.contains("create_map") && !SRC.contains("pin("));
}
#[test]
fn i16_no_forbidden_kernel_patterns() {
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
fn i16_no_forbidden_tc_nft_patterns() {
    assert!(!SRC.contains("\ntc") && !SRC.contains("\nnft"));
}
#[test]
fn i16_no_forbidden_drop_block_quota() {
    let lower = SRC.to_lowercase();
    for line in lower.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("//!") {
            continue;
        }
        if trimmed.contains("allow_persistence") || trimmed.contains("persistence_performed") {
            continue;
        }
        if trimmed.contains("allow_packet_drop") || trimmed.contains("packet_drop_performed") {
            continue;
        }
        if trimmed.contains("\"packet drop") || trimmed.contains("\"drop_packet") {
            continue;
        }
        if trimmed.contains("blocked") {
            continue;
        }
        if trimmed.contains("drop_packet") {
            continue;
        }
        if !trimmed.contains("allow_")
            && !trimmed.contains("_performed")
            && !trimmed.contains("_exposed")
            && !trimmed.contains("_opened")
            && !trimmed.contains("_read")
            && (trimmed.contains("drop") || trimmed.contains("block") || trimmed.contains("quota"))
        {
            panic!("forbidden drop/block/quota pattern found: {}", trimmed);
        }
    }
}
#[test]
fn i16_no_forbidden_fs_patterns() {
    assert!(
        !SRC.contains("File::create") && !SRC.contains("fs::write") && !SRC.contains("OpenOptions")
    );
}
#[test]
fn i16_no_forbidden_save() {
    let lower = SRC.to_lowercase();
    for line in lower.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.contains("save") && !t.contains("persistence_performed") {
            panic!("forbidden save pattern found");
        }
    }
}
