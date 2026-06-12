// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader spike review pack model for the Intergalaxion Engine.
//!
//! Phase I-19 gathers evidence from previous reader-spike phases into a
//! deterministic internal review pack. This phase is review-pack only — not
//! a release, not a public feature, not a live reader, not a ring buffer
//! reader, not a kernel event consumer. It is an internal evidence bundle
//! and decision summary only.
//!
//! # Design constraints (I-19)
//!
//! * Review-pack only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake review success, no fake release readiness.
//! * release_allowed is always false in I-19.
//! * must_remain_experimental is always true in I-19.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::{
    evaluate_event_stream_dry_run, validate_event_stream_dry_run_result,
    EbpfEventStreamDryRunResult,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::{
    evaluate_event_stream_evidence_audit, validate_event_stream_evidence_audit_report,
    EbpfEventStreamEvidenceAuditReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::{
    decode_event_stream_fixture, validate_event_stream_fixture_bridge_report,
    EbpfEventStreamFixtureBridgeReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::{
    evaluate_event_stream_read_plan, validate_event_stream_read_plan, EbpfEventStreamReadPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::{
    evaluate_event_stream_reader, validate_event_stream_reader_result, EbpfEventStreamReaderResult,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::{
    evaluate_event_stream_reader_spike_executor,
    validate_event_stream_reader_spike_executor_result, EbpfEventStreamReaderSpikeExecutorResult,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::{
    evaluate_event_stream_reader_spike_executor_audit,
    validate_event_stream_reader_spike_executor_audit_report,
    EbpfEventStreamReaderSpikeExecutorAuditReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::{
    evaluate_event_stream_reader_spike_prep, validate_event_stream_reader_spike_prep_plan,
    EbpfEventStreamReaderSpikePrepPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_release_gate::{
    evaluate_reader_spike_release_gate, validate_reader_spike_release_gate_report,
    EbpfReaderSpikeReleaseGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_result::{
    summarize_event_stream_reader_spike_results, validate_event_stream_reader_spike_result_summary,
    EbpfEventStreamReaderSpikeResultSummary,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::{
    summarize_manual_lab_captures, validate_manual_lab_summary, EbpfLiveAttachManualLabSummary,
};

/// Status of the reader spike review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReviewPackStatus {
    /// Review pack is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Ready for review.
    ReviewReady,
    /// Review was rejected.
    ReviewRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderSpikeReviewPackStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::ReviewReady => "review_ready",
            Self::ReviewRejected => "review_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader spike review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReviewPackDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix evidence before proceeding.
    FixEvidence,
    /// Capture more results before proceeding.
    CaptureMoreResults,
    /// Continue local lab work only.
    ContinueLocalLab,
    /// Prepare for a manual reader spike review.
    PrepareManualReaderSpikeReview,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Release is explicitly rejected.
    RejectRelease,
}

impl EbpfReaderSpikeReviewPackDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixEvidence => "fix_evidence",
            Self::CaptureMoreResults => "capture_more_results",
            Self::ContinueLocalLab => "continue_local_lab",
            Self::PrepareManualReaderSpikeReview => "prepare_manual_reader_spike_review",
            Self::KeepExperimental => "keep_experimental",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of review pack finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReviewPackFindingKind {
    /// Manual capture finding.
    ManualCapture,
    /// Read plan finding.
    ReadPlan,
    /// Reader boundary finding.
    ReaderBoundary,
    /// Fixture bridge finding.
    FixtureBridge,
    /// Dry run finding.
    DryRun,
    /// Evidence audit finding.
    EvidenceAudit,
    /// Preparation gate finding.
    PrepGate,
    /// Executor boundary finding.
    ExecutorBoundary,
    /// Executor audit finding.
    ExecutorAudit,
    /// Result capture finding.
    ResultCapture,
    /// Release gate finding.
    ReleaseGate,
    /// Safety invariant finding.
    SafetyInvariant,
    /// Review invariant finding.
    ReviewInvariant,
}

impl EbpfReaderSpikeReviewPackFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManualCapture => "manual_capture",
            Self::ReadPlan => "read_plan",
            Self::ReaderBoundary => "reader_boundary",
            Self::FixtureBridge => "fixture_bridge",
            Self::DryRun => "dry_run",
            Self::EvidenceAudit => "evidence_audit",
            Self::PrepGate => "prep_gate",
            Self::ExecutorBoundary => "executor_boundary",
            Self::ExecutorAudit => "executor_audit",
            Self::ResultCapture => "result_capture",
            Self::ReleaseGate => "release_gate",
            Self::SafetyInvariant => "safety_invariant",
            Self::ReviewInvariant => "review_invariant",
        }
    }
}

/// A single finding produced by the review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReviewPackFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderSpikeReviewPackFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderSpikeReviewPackStatus,
}

/// Input to the reader spike review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReviewPackInput {
    /// I-10F manual lab summary.
    pub manual_summary: EbpfLiveAttachManualLabSummary,
    /// I-11 read plan.
    pub read_plan: EbpfEventStreamReadPlan,
    /// I-12 reader result.
    pub reader_result: EbpfEventStreamReaderResult,
    /// I-13 fixture bridge report.
    pub fixture_report: EbpfEventStreamFixtureBridgeReport,
    /// I-14 dry run result.
    pub dry_run_result: EbpfEventStreamDryRunResult,
    /// I-15 evidence audit report.
    pub evidence_audit_report: EbpfEventStreamEvidenceAuditReport,
    /// I-15A preparation plan.
    pub prep_plan: EbpfEventStreamReaderSpikePrepPlan,
    /// I-16 executor result.
    pub executor_result: EbpfEventStreamReaderSpikeExecutorResult,
    /// I-16A executor audit report.
    pub executor_audit_report: EbpfEventStreamReaderSpikeExecutorAuditReport,
    /// I-17 result summary.
    pub result_summary: EbpfEventStreamReaderSpikeResultSummary,
    /// I-18 release gate report.
    pub release_gate_report: EbpfReaderSpikeReleaseGateReport,
    /// Whether release gate ready is required.
    pub require_release_gate_ready_for_review: bool,
    /// Whether result summary ready is required.
    pub require_result_summary_ready: bool,
    /// Whether executor audit ready is required.
    pub require_executor_audit_ready: bool,
    /// Whether public CLI is expected hidden.
    pub public_cli_expected_hidden: bool,
    /// Whether usage schema is expected unchanged.
    pub usage_schema_expected_unchanged: bool,
    /// Whether ledger schema is expected unchanged.
    pub ledger_schema_expected_unchanged: bool,
}

/// Review pack produced by the reader spike review evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReviewPack {
    /// The phase this pack covers.
    pub phase: String,
    /// The pack status.
    pub status: EbpfReaderSpikeReviewPackStatus,
    /// The pack decision.
    pub decision: EbpfReaderSpikeReviewPackDecision,
    /// Whether the review is ready.
    pub review_ready: bool,
    /// Whether release is allowed (always false in I-19).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-19).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderSpikeReviewPackFinding>,
    /// Whether manual capture is ready.
    pub manual_capture_ready: bool,
    /// Whether read plan is ready.
    pub read_plan_ready: bool,
    /// Whether reader boundary is safe.
    pub reader_boundary_safe: bool,
    /// Whether fixture bridge is ready.
    pub fixture_bridge_ready: bool,
    /// Whether dry run is ready.
    pub dry_run_ready: bool,
    /// Whether evidence audit is ready.
    pub evidence_audit_ready: bool,
    /// Whether preparation is ready.
    pub prep_ready: bool,
    /// Whether executor boundary is ready.
    pub executor_boundary_ready: bool,
    /// Whether executor audit is ready.
    pub executor_audit_ready: bool,
    /// Whether result summary is ready.
    pub result_summary_ready: bool,
    /// Whether release gate is ready.
    pub release_gate_ready: bool,
    /// Whether public CLI was exposed.
    pub public_cli_exposed: bool,
    /// Whether usage schema was changed.
    pub usage_schema_changed: bool,
    /// Whether ledger schema was changed.
    pub ledger_schema_changed: bool,
    /// Whether a ring buffer was opened.
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read.
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed.
    pub map_pin_performed: bool,
    /// Whether enforcement was performed.
    pub enforcement_performed: bool,
    /// Whether packet drop was performed.
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed.
    pub mutation_performed: bool,
    /// Whether file write was performed.
    pub persistence_performed: bool,
    /// Whether fake reader success was detected.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected.
    pub fake_live_event_counts_detected: bool,
    /// Whether fake release readiness was detected.
    pub fake_release_readiness_detected: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

fn safe_base_pack() -> EbpfReaderSpikeReviewPack {
    EbpfReaderSpikeReviewPack {
        phase: String::from("I-19"),
        status: EbpfReaderSpikeReviewPackStatus::Draft,
        decision: EbpfReaderSpikeReviewPackDecision::Stop,
        review_ready: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        manual_capture_ready: false,
        read_plan_ready: false,
        reader_boundary_safe: false,
        fixture_bridge_ready: false,
        dry_run_ready: false,
        evidence_audit_ready: false,
        prep_ready: false,
        executor_boundary_ready: false,
        executor_audit_ready: false,
        result_summary_ready: false,
        release_gate_ready: false,
        public_cli_exposed: false,
        usage_schema_changed: false,
        ledger_schema_changed: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
        fake_reader_success_detected: false,
        fake_live_event_counts_detected: false,
        fake_release_readiness_detected: false,
    }
}

/// Create the default reader spike review pack input.
///
/// All fields are populated by calling the default/evaluate functions for
/// each prior phase. The resulting input is safe but produces an incomplete
/// review pack because most validators require specific readiness flags.
pub fn default_reader_spike_review_pack_input() -> EbpfReaderSpikeReviewPackInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::default_event_stream_dry_run_input;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_evidence_audit::default_event_stream_evidence_audit_input;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::default_event_stream_read_plan_input;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::EbpfEventStreamReaderSpikeExecutorInput;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::EbpfEventStreamReaderSpikeExecutorAuditInput;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::EbpfEventStreamReaderSpikePrepInput;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_release_gate::default_reader_spike_release_gate_input;
    use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::default_manual_lab_capture;

    // I-10F: manual lab summary
    let manual_summary = summarize_manual_lab_captures(&[default_manual_lab_capture()]);
    // I-11: read plan
    let read_plan = evaluate_event_stream_read_plan(&default_event_stream_read_plan_input());
    // I-12: reader result
    let reader_result = evaluate_event_stream_reader(&default_event_stream_reader_input());
    // I-13: fixture bridge report
    let fixture_report = decode_event_stream_fixture(&crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::default_event_stream_fixture());
    // I-14: dry run result
    let dry_run_result = evaluate_event_stream_dry_run(&default_event_stream_dry_run_input());
    // I-15: evidence audit report
    let evidence_audit_report =
        evaluate_event_stream_evidence_audit(&default_event_stream_evidence_audit_input());
    // I-15A: prep plan (needs audit report with ready_for_reader_spike_preparation)
    let spi = EbpfEventStreamReaderSpikePrepInput {
        audit_report: evidence_audit_report.clone(),
        reader_input: default_event_stream_reader_input(),
        explicit_reader_spike_prep_consent: true,
        explicit_operator_label: String::new(),
        feature_name: String::from("intergalaxion-event-stream-lab"),
        feature_expected_disabled_by_default: true,
        local_lab_only: true,
        max_events: 0,
        timeout_ms: 0,
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
    };
    let prep_plan = evaluate_event_stream_reader_spike_prep(&spi);
    // I-16: executor result
    let sei = EbpfEventStreamReaderSpikeExecutorInput {
        prep_plan: prep_plan.clone(),
        reader_input: default_event_stream_reader_input(),
        explicit_executor_feature_enabled: false,
        explicit_operator_label: String::new(),
        allow_execution_attempt: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        require_cleanup: true,
        require_post_run_evidence_capture: true,
    };
    let executor_result = evaluate_event_stream_reader_spike_executor(&sei);
    // I-16A: executor audit report
    let sai = EbpfEventStreamReaderSpikeExecutorAuditInput {
        prep_plan: prep_plan.clone(),
        executor_input: sei,
        executor_result: executor_result.clone(),
        require_feature_disabled_by_default: true,
        require_prep_ready: true,
        require_future_execution_ready: true,
        require_cleanup_requirement: true,
        require_post_run_evidence_capture: true,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    };
    let executor_audit_report = evaluate_event_stream_reader_spike_executor_audit(&sai);
    // I-17: result summary
    let result_summary = summarize_event_stream_reader_spike_results(&[]);
    // I-18: release gate report
    let gate_input = default_reader_spike_release_gate_input();
    let release_gate_report = evaluate_reader_spike_release_gate(&gate_input);

    EbpfReaderSpikeReviewPackInput {
        manual_summary,
        read_plan,
        reader_result,
        fixture_report,
        dry_run_result,
        evidence_audit_report,
        prep_plan,
        executor_result,
        executor_audit_report,
        result_summary,
        release_gate_report,
        require_release_gate_ready_for_review: false,
        require_result_summary_ready: false,
        require_executor_audit_ready: false,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

/// Build the reader spike review pack from input.
///
/// Validates each prior phase result, aggregates safety flags, and determines
/// the overall review pack status, decision, and findings.
pub fn build_reader_spike_review_pack(
    input: &EbpfReaderSpikeReviewPackInput,
) -> EbpfReaderSpikeReviewPack {
    let mut pack = safe_base_pack();
    let mut findings: Vec<EbpfReaderSpikeReviewPackFinding> = Vec::new();
    let mut blocked = false;

    // Validate each phase
    pack.manual_capture_ready = validate_manual_lab_summary(&input.manual_summary).is_ok();
    pack.read_plan_ready = validate_event_stream_read_plan(&input.read_plan).is_ok();
    pack.reader_boundary_safe = validate_event_stream_reader_result(&input.reader_result).is_ok();
    pack.fixture_bridge_ready =
        validate_event_stream_fixture_bridge_report(&input.fixture_report).is_ok();
    pack.dry_run_ready = validate_event_stream_dry_run_result(&input.dry_run_result).is_ok();
    pack.evidence_audit_ready =
        validate_event_stream_evidence_audit_report(&input.evidence_audit_report).is_ok();
    pack.prep_ready = validate_event_stream_reader_spike_prep_plan(&input.prep_plan).is_ok();
    pack.executor_boundary_ready =
        validate_event_stream_reader_spike_executor_result(&input.executor_result).is_ok();
    pack.executor_audit_ready =
        validate_event_stream_reader_spike_executor_audit_report(&input.executor_audit_report)
            .is_ok();
    pack.result_summary_ready =
        validate_event_stream_reader_spike_result_summary(&input.result_summary).is_ok();
    pack.release_gate_ready =
        validate_reader_spike_release_gate_report(&input.release_gate_report).is_ok();

    // Release gate readiness check
    if input.require_release_gate_ready_for_review
        && !input.release_gate_report.ready_for_reader_spike_review
    {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-GATE-NOT-READY"),
            kind: EbpfReaderSpikeReviewPackFindingKind::ReleaseGate,
            message: String::from("release gate not ready for review"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Incomplete,
        });
        blocked = true;
    }

    // Result summary readiness check
    if input.require_result_summary_ready && !input.result_summary.ready_for_reader_spike_review {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-SUMMARY-NOT-READY"),
            kind: EbpfReaderSpikeReviewPackFindingKind::ResultCapture,
            message: String::from("result summary not ready for review"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Incomplete,
        });
        blocked = true;
    }

    // Executor audit readiness check
    if input.require_executor_audit_ready {
        let audit_ready = matches!(
            input.executor_audit_report.status,
            crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::EbpfEventStreamReaderSpikeExecutorAuditStatus::ReadyForResultCapture
        );
        if !audit_ready {
            findings.push(EbpfReaderSpikeReviewPackFinding {
                code: String::from("PACK-EXEC-AUDIT-NOT-READY"),
                kind: EbpfReaderSpikeReviewPackFindingKind::ExecutorAudit,
                message: String::from("executor audit not ready for result capture"),
                blocking: true,
                status: EbpfReaderSpikeReviewPackStatus::Incomplete,
            });
            blocked = true;
        }
    }

    // Copy safety flags from result summary and release gate report
    pack.fake_reader_success_detected = input.result_summary.fake_reader_success_detected
        || input.release_gate_report.fake_reader_success_detected;
    pack.fake_live_event_counts_detected = input.result_summary.fake_live_event_counts_detected
        || input.release_gate_report.fake_live_event_counts_detected;
    pack.ring_buffer_opened =
        input.result_summary.ring_buffer_opened || input.release_gate_report.ring_buffer_opened;
    pack.live_event_stream_read = input.result_summary.live_event_stream_read
        || input.release_gate_report.live_event_stream_read;
    pack.map_pin_performed =
        input.result_summary.map_pin_performed || input.release_gate_report.map_pin_performed;
    pack.enforcement_performed = input.result_summary.enforcement_performed
        || input.release_gate_report.enforcement_performed;
    pack.packet_drop_performed = input.result_summary.packet_drop_performed
        || input.release_gate_report.packet_drop_performed;
    pack.mutation_performed =
        input.result_summary.mutation_performed || input.release_gate_report.mutation_performed;
    pack.persistence_performed = input.result_summary.persistence_performed
        || input.release_gate_report.persistence_performed;
    pack.public_cli_exposed = input.release_gate_report.public_cli_exposed;
    pack.usage_schema_changed = !input.usage_schema_expected_unchanged;
    pack.ledger_schema_changed = !input.ledger_schema_expected_unchanged;

    // Detect fake release readiness
    pack.fake_release_readiness_detected = input.release_gate_report.release_allowed;

    // Safety flag checks
    if pack.fake_reader_success_detected {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-FAKE-READER-SUCCESS"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.fake_live_event_counts_detected {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-FAKE-LIVE-COUNTS"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.fake_release_readiness_detected {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-FAKE-RELEASE-READINESS"),
            kind: EbpfReaderSpikeReviewPackFindingKind::ReviewInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::ReviewRejected,
        });
        blocked = true;
    }
    if pack.public_cli_exposed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-PUBLIC-CLI-EXPOSED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("public CLI exposed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.usage_schema_changed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("usage schema changed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.ledger_schema_changed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("ledger schema changed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.ring_buffer_opened {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-RING-BUFFER-OPENED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("ring buffer was opened"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.live_event_stream_read {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-LIVE-EVENT-READ"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("live event stream was read"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.map_pin_performed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-MAP-PIN-PERFORMED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("map pin was performed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.enforcement_performed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-ENFORCEMENT-PERFORMED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("enforcement was performed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.packet_drop_performed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-PACKET-DROP-PERFORMED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("packet drop was performed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.mutation_performed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-MUTATION-PERFORMED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("kernel mutation was performed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if pack.persistence_performed {
        findings.push(EbpfReaderSpikeReviewPackFinding {
            code: String::from("PACK-PERSISTENCE-PERFORMED"),
            kind: EbpfReaderSpikeReviewPackFindingKind::SafetyInvariant,
            message: String::from("file write was performed"),
            blocking: true,
            status: EbpfReaderSpikeReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // Determine status and decision
    if blocked {
        pack.status = EbpfReaderSpikeReviewPackStatus::Blocked;
        pack.decision = EbpfReaderSpikeReviewPackDecision::Stop;
    } else {
        let all_valid = pack.manual_capture_ready
            && pack.read_plan_ready
            && pack.reader_boundary_safe
            && pack.fixture_bridge_ready
            && pack.dry_run_ready
            && pack.evidence_audit_ready
            && pack.prep_ready
            && pack.executor_boundary_ready
            && pack.executor_audit_ready
            && pack.result_summary_ready
            && pack.release_gate_ready;
        if all_valid {
            pack.status = EbpfReaderSpikeReviewPackStatus::ReviewReady;
            pack.decision = EbpfReaderSpikeReviewPackDecision::PrepareManualReaderSpikeReview;
        } else {
            pack.status = EbpfReaderSpikeReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderSpikeReviewPackDecision::FixEvidence;
        }
    }

    // I-19 hard invariants
    pack.release_allowed = false;
    pack.must_remain_experimental = true;
    pack.review_ready = pack.status == EbpfReaderSpikeReviewPackStatus::ReviewReady;

    pack.findings = findings;
    pack
}

/// Validate that a reader spike review pack is safe.
pub fn validate_reader_spike_review_pack(pack: &EbpfReaderSpikeReviewPack) -> Result<(), String> {
    if pack.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if pack.release_allowed {
        return Err("release_allowed must be false in I-19".to_string());
    }
    if !pack.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-19".to_string());
    }
    if pack.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if pack.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if pack.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    if pack.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if pack.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if pack.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if pack.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if pack.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if pack.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if pack.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if pack.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if pack.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if pack.fake_release_readiness_detected {
        return Err("fake_release_readiness_detected must be false".to_string());
    }
    if pack.review_ready && pack.status == EbpfReaderSpikeReviewPackStatus::ReviewRejected {
        return Err("review_ready must be false when status is ReviewRejected".to_string());
    }
    Ok(())
}

/// Map a review pack status to a stable human-readable label.
pub fn reader_spike_review_pack_status_label(
    status: EbpfReaderSpikeReviewPackStatus,
) -> &'static str {
    status.as_str()
}

/// Map a review pack decision to a stable human-readable label.
pub fn reader_spike_review_pack_decision_label(
    decision: EbpfReaderSpikeReviewPackDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a review pack finding kind to a stable human-readable label.
pub fn reader_spike_review_pack_finding_kind_label(
    kind: EbpfReaderSpikeReviewPackFindingKind,
) -> &'static str {
    kind.as_str()
}
