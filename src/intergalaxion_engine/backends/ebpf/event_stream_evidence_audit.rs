// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Event stream reader evidence audit for the Intergalaxion Engine.
//!
//! Phase I-15 adds an audit-only layer that evaluates evidence from
//! I-10F manual lab captures, I-11 read planning, I-12 reader boundary,
//! I-13 fixture decoder bridge, and I-14 reader lab dry run. It decides
//! whether the branch has enough honest evidence to prepare a future
//! feature-gated local reader spike.
//!
//! This phase is audit-only — not a live reader, not a ring buffer reader,
//! and not a kernel event consumer.
//!
//! # Design constraints (I-15)
//!
//! * Audit-only — no ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake audit success.
//! * No fake reader readiness.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.

use crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::{
    validate_event_stream_dry_run_result, EbpfEventStreamDryRunResult,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::{
    validate_event_stream_fixture_bridge_report, EbpfEventStreamFixtureBridgeReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::{
    validate_event_stream_read_plan, EbpfEventStreamReadPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::{
    validate_event_stream_reader_result, EbpfEventStreamReaderResult, EbpfEventStreamReaderStatus,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualLabSummary;

/// Status of the event stream evidence audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamEvidenceAuditStatus {
    /// All evidence gates pass; ready for reader spike preparation.
    Passed,
    /// One or more evidence gates failed.
    Failed,
    /// Evidence is present but incomplete or questionable.
    Warning,
    /// Evidence is blocked by a hard safety gate.
    Blocked,
    /// Evidence confirms readiness for a future reader spike.
    ReadyForReaderSpikePreparation,
    /// Evidence is insufficient for readiness.
    NotReady,
}

impl EbpfEventStreamEvidenceAuditStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
            Self::ReadyForReaderSpikePreparation => "ready_for_reader_spike_preparation",
            Self::NotReady => "not_ready",
        }
    }
}

/// Kind of evidence audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamEvidenceAuditFindingKind {
    /// Manual lab capture evidence.
    ManualCapture,
    /// Event stream read plan evidence.
    ReadPlan,
    /// Reader boundary evidence.
    ReaderBoundary,
    /// Fixture decoder bridge evidence.
    FixtureBridge,
    /// Dry run evidence.
    DryRun,
    /// Safety invariant violation.
    SafetyInvariant,
    /// Schema invariant violation.
    SchemaInvariant,
    /// CLI invariant violation.
    CliInvariant,
}

impl EbpfEventStreamEvidenceAuditFindingKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManualCapture => "manual_capture",
            Self::ReadPlan => "read_plan",
            Self::ReaderBoundary => "reader_boundary",
            Self::FixtureBridge => "fixture_bridge",
            Self::DryRun => "dry_run",
            Self::SafetyInvariant => "safety_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::CliInvariant => "cli_invariant",
        }
    }
}

/// A single finding from the evidence audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamEvidenceAuditFinding {
    /// Machine-readable finding code.
    pub code: String,
    /// The kind of evidence this finding relates to.
    pub kind: EbpfEventStreamEvidenceAuditFindingKind,
    /// Human-readable finding message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// The status this finding implies.
    pub status: EbpfEventStreamEvidenceAuditStatus,
}

/// Input to the evidence audit evaluation.
///
/// Combines evidence from I-10F through I-14 with explicit requirements.
/// The evaluator is pure and deterministic — no live kernel operations
/// occur in any build configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamEvidenceAuditInput {
    /// The I-10F manual lab summary.
    pub manual_summary: EbpfLiveAttachManualLabSummary,
    /// The I-11 event stream read plan.
    pub read_plan: EbpfEventStreamReadPlan,
    /// The I-12 event stream reader result.
    pub reader_result: EbpfEventStreamReaderResult,
    /// The I-13 fixture bridge report.
    pub fixture_report: EbpfEventStreamFixtureBridgeReport,
    /// The I-14 dry run result.
    pub dry_run_result: EbpfEventStreamDryRunResult,
    /// Whether clean detach evidence is required.
    pub require_clean_detach_evidence: bool,
    /// Whether fixture bridge records are required.
    pub require_fixture_bridge_records: bool,
    /// Whether dry run completion is required.
    pub require_dry_run_completed: bool,
    /// Whether public CLI is expected to be hidden.
    pub public_cli_expected_hidden: bool,
    /// Whether usage schema is expected unchanged.
    pub usage_schema_expected_unchanged: bool,
    /// Whether ledger schema is expected unchanged.
    pub ledger_schema_expected_unchanged: bool,
}

/// Report produced by the evidence audit.
///
/// All operation flags are always false in I-15. The audit is pure and
/// deterministic. No ring buffer is opened, no live events are read,
/// no maps are pinned, no persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamEvidenceAuditReport {
    /// The phase this audit covers.
    pub phase: String,
    /// The determined audit status.
    pub status: EbpfEventStreamEvidenceAuditStatus,
    /// Whether enough evidence exists for a future reader spike.
    pub ready_for_reader_spike_preparation: bool,
    /// The audit findings.
    pub findings: Vec<EbpfEventStreamEvidenceAuditFinding>,
    /// Whether manual capture evidence is ready.
    pub manual_capture_ready: bool,
    /// Whether read plan evidence is ready.
    pub read_plan_ready: bool,
    /// Whether reader boundary evidence is safe.
    pub reader_boundary_safe: bool,
    /// Whether fixture bridge evidence is ready.
    pub fixture_bridge_ready: bool,
    /// Whether dry run evidence is ready.
    pub dry_run_ready: bool,
    /// Whether clean detach evidence is present.
    pub clean_detach_evidence_present: bool,
    /// Whether fixture bridge records are present.
    pub fixture_bridge_records_present: bool,
    /// Whether dry run completed.
    pub dry_run_completed: bool,
    /// Whether public CLI was exposed (always false).
    pub public_cli_exposed: bool,
    /// Whether usage schema was changed (always false).
    pub usage_schema_changed: bool,
    /// Whether ledger schema was changed (always false).
    pub ledger_schema_changed: bool,
    /// Whether a ring buffer was opened (always false).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false).
    pub mutation_performed: bool,
    /// Whether persistence was performed (always false).
    pub persistence_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default evidence audit input.
///
/// All fields are in their safest configuration. The default input
/// is safe but not ready for reader spike preparation.
pub fn default_event_stream_evidence_audit_input() -> EbpfEventStreamEvidenceAuditInput {
    let plan_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_plan::default_event_stream_read_plan_input();
    let read_plan = crate::intergalaxion_engine::backends::ebpf::event_stream_plan::evaluate_event_stream_read_plan(&plan_input);
    let reader_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    let reader_result =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::evaluate_event_stream_reader(&reader_input);
    let fixture_report =
        crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::decode_event_stream_fixture(
            &crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::default_event_stream_fixture(),
        );
    let dry_run_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::default_event_stream_dry_run_input();
    let dry_run_result =
        crate::intergalaxion_engine::backends::ebpf::event_stream_dry_run::evaluate_event_stream_dry_run(&dry_run_input);
    EbpfEventStreamEvidenceAuditInput {
        manual_summary: crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::summarize_manual_lab_captures(&[]),
        read_plan,
        reader_result,
        fixture_report,
        dry_run_result,
        require_clean_detach_evidence: true,
        require_fixture_bridge_records: true,
        require_dry_run_completed: true,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

/// Build a safe base audit report with all operation flags false.
fn safe_base_report() -> EbpfEventStreamEvidenceAuditReport {
    EbpfEventStreamEvidenceAuditReport {
        phase: String::from("I-15"),
        status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        ready_for_reader_spike_preparation: false,
        findings: Vec::new(),
        manual_capture_ready: false,
        read_plan_ready: false,
        reader_boundary_safe: false,
        fixture_bridge_ready: false,
        dry_run_ready: false,
        clean_detach_evidence_present: false,
        fixture_bridge_records_present: false,
        dry_run_completed: false,
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
    }
}

/// Evaluate the event stream evidence audit from input.
///
/// This function is pure and deterministic. It audits evidence from
/// I-10F through I-14 to determine whether the branch has enough
/// honest evidence for a future feature-gated reader spike.
///
/// # Evaluation logic
///
/// The audit collects findings from each evidence layer. Any blocking
/// finding causes the overall status to be Failed or Blocked. If all
/// gates pass, the status is Passed (which implies readiness for
/// reader spike preparation).
pub fn evaluate_event_stream_evidence_audit(
    input: &EbpfEventStreamEvidenceAuditInput,
) -> EbpfEventStreamEvidenceAuditReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfEventStreamEvidenceAuditFinding> = Vec::new();
    let mut has_blocking = false;

    // ── 1. Manual capture readiness ─────────────────────────────────
    let manual_ok = input.manual_summary.ready_for_event_stream_planning;
    report.manual_capture_ready = manual_ok;
    if !manual_ok {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("manual_capture_not_ready"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ManualCapture,
            message: String::from(
                "manual summary does not indicate readiness for event stream planning",
            ),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        });
        has_blocking = true;
    }

    // ── 2. Clean detach evidence ─────────────────────────────────────
    let has_clean_detach = input.manual_summary.clean_detach_count > 0;
    report.clean_detach_evidence_present = has_clean_detach;
    if input.require_clean_detach_evidence && !has_clean_detach {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("clean_detach_evidence_missing"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ManualCapture,
            message: String::from("clean detach evidence is required but not present"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        });
        has_blocking = true;
    }

    // ── 3. Read plan validation ────────────────────────────────────────
    let plan_valid = validate_event_stream_read_plan(&input.read_plan).is_ok();
    let future_candidate = input.read_plan.future_read_candidate;
    report.read_plan_ready = plan_valid && future_candidate;
    if !plan_valid {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("read_plan_validation_failed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ReadPlan,
            message: String::from("read plan failed validation"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    } else if !future_candidate {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("read_plan_not_future_candidate"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ReadPlan,
            message: String::from("read plan is not a future read candidate"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        });
        has_blocking = true;
    }

    // ── 4. Reader boundary checks ────────────────────────────────────
    let reader_not_succeeded =
        input.reader_result.status != EbpfEventStreamReaderStatus::ReaderSucceeded;
    let reader_no_live_read = !input.reader_result.live_event_stream_read;
    let reader_valid = validate_event_stream_reader_result(&input.reader_result).is_ok();
    report.reader_boundary_safe = reader_valid && reader_not_succeeded && reader_no_live_read;
    if !reader_not_succeeded {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("reader_result_reader_succeeded"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ReaderBoundary,
            message: String::from(
                "reader result status is ReaderSucceeded which is not valid readiness in I-15",
            ),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
    } else if !reader_no_live_read {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("reader_result_live_event_read"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ReaderBoundary,
            message: String::from("reader result has live_event_stream_read=true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
    } else if !reader_valid {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("reader_result_validation_failed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::ReaderBoundary,
            message: String::from("reader result failed validation"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    }

    // ── 5. Fixture bridge validation ──────────────────────────────────
    let fixture_valid = validate_event_stream_fixture_bridge_report(&input.fixture_report).is_ok();
    let fixture_only = input.fixture_report.fixture_only;
    let has_bridge_records = input.fixture_report.bridge_records > 0;
    report.fixture_bridge_ready = fixture_valid && fixture_only;
    report.fixture_bridge_records_present = has_bridge_records;
    if !fixture_valid {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("fixture_report_validation_failed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::FixtureBridge,
            message: String::from("fixture bridge report failed validation"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    } else if !fixture_only {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("fixture_report_not_fixture_only"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::FixtureBridge,
            message: String::from("fixture report fixture_only must be true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
    }
    if input.require_fixture_bridge_records && !has_bridge_records {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("fixture_bridge_records_missing"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::FixtureBridge,
            message: String::from("fixture bridge records are required but none present"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        });
        has_blocking = true;
    }

    // ── 6. Dry run checks ────────────────────────────────────────────
    let dry_run_no_reader = !input.dry_run_result.reader_succeeded;
    let dry_run_no_live_read = !input.dry_run_result.live_event_stream_read;
    let dry_run_valid = validate_event_stream_dry_run_result(&input.dry_run_result).is_ok();
    let dry_run_done = input.dry_run_result.dry_run_completed;
    report.dry_run_ready = dry_run_valid && dry_run_no_reader && dry_run_no_live_read;
    report.dry_run_completed = dry_run_done;
    if !dry_run_no_reader {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("dry_run_reader_succeeded"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::DryRun,
            message: String::from(
                "dry run claims reader_succeeded=true which is not valid in I-15",
            ),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
    } else if !dry_run_no_live_read {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("dry_run_live_event_read"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::DryRun,
            message: String::from("dry run has live_event_stream_read=true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
    } else if !dry_run_valid {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("dry_run_validation_failed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::DryRun,
            message: String::from("dry run result failed validation"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    }
    if input.require_dry_run_completed && !dry_run_done {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("dry_run_not_completed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::DryRun,
            message: String::from("dry run completion is required but not achieved"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::NotReady,
        });
        has_blocking = true;
    }

    // ── 7. CLI invariant ───────────────────────────────────────────────
    if !input.public_cli_expected_hidden {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("public_cli_not_hidden"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::CliInvariant,
            message: String::from("public_cli_expected_hidden must be true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    }

    // ── 8. Schema invariants ──────────────────────────────────────────
    if !input.usage_schema_expected_unchanged {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("usage_schema_changed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SchemaInvariant,
            message: String::from("usage_schema_expected_unchanged must be true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("ledger_schema_changed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SchemaInvariant,
            message: String::from("ledger_schema_expected_unchanged must be true"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
    }

    // ── 9. Safety invariant checks across all inputs ──────────────────
    if input.manual_summary.public_cli_exposed
        || input.read_plan.public_cli_exposed
        || input.reader_result.public_cli_exposed
        || input.fixture_report.public_cli_exposed
        || input.dry_run_result.public_cli_exposed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_public_cli_exposed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("public CLI was exposed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Failed,
        });
        has_blocking = true;
        report.public_cli_exposed = true;
    }
    if input.read_plan.ring_buffer_opened
        || input.reader_result.ring_buffer_opened
        || input.fixture_report.ring_buffer_opened
        || input.dry_run_result.ring_buffer_opened
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_ring_buffer_opened"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("ring buffer was opened in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.ring_buffer_opened = true;
    }
    if input.reader_result.live_event_stream_read
        || input.fixture_report.live_event_stream_read
        || input.dry_run_result.live_event_stream_read
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_live_event_stream_read"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("live event stream was read in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.live_event_stream_read = true;
    }
    if input.read_plan.map_pin_performed
        || input.reader_result.map_pin_performed
        || input.fixture_report.map_pin_performed
        || input.dry_run_result.map_pin_performed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_map_pin_performed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("map pin was performed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.map_pin_performed = true;
    }
    if input.read_plan.enforcement_performed
        || input.reader_result.enforcement_performed
        || input.fixture_report.enforcement_performed
        || input.dry_run_result.enforcement_performed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_enforcement_performed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("enforcement was performed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.enforcement_performed = true;
    }
    if input.read_plan.packet_drop_performed
        || input.reader_result.packet_drop_performed
        || input.fixture_report.packet_drop_performed
        || input.dry_run_result.packet_drop_performed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_packet_drop_performed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("packet drop was performed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.packet_drop_performed = true;
    }
    if input.read_plan.mutation_performed
        || input.reader_result.mutation_performed
        || input.fixture_report.mutation_performed
        || input.dry_run_result.mutation_performed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_mutation_performed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("kernel mutation was performed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.mutation_performed = true;
    }
    if input.read_plan.persistence_performed
        || input.reader_result.persistence_performed
        || input.fixture_report.persistence_performed
        || input.dry_run_result.persistence_performed
    {
        findings.push(EbpfEventStreamEvidenceAuditFinding {
            code: String::from("safety_persistence_performed"),
            kind: EbpfEventStreamEvidenceAuditFindingKind::SafetyInvariant,
            message: String::from("persistence was performed in one or more evidence layers"),
            blocking: true,
            status: EbpfEventStreamEvidenceAuditStatus::Blocked,
        });
        has_blocking = true;
        report.persistence_performed = true;
    }

    // ── Determine overall status ───────────────────────────────────────
    report.findings = findings;
    if has_blocking {
        // Check if any finding is Blocked (safety violation) vs Failed
        let any_blocked = report
            .findings
            .iter()
            .any(|f| f.status == EbpfEventStreamEvidenceAuditStatus::Blocked);
        report.status = if any_blocked {
            EbpfEventStreamEvidenceAuditStatus::Blocked
        } else {
            EbpfEventStreamEvidenceAuditStatus::Failed
        };
        report.ready_for_reader_spike_preparation = false;
    } else {
        report.status = EbpfEventStreamEvidenceAuditStatus::ReadyForReaderSpikePreparation;
        report.ready_for_reader_spike_preparation = true;
    }

    report
}

/// Validate that an evidence audit report does not have any unsafe or
/// inconsistent flags.
///
/// Returns `Ok(())` if the report is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_evidence_audit_report(
    report: &EbpfEventStreamEvidenceAuditReport,
) -> Result<(), String> {
    // Safety flag checks
    if report.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-15".to_string());
    }
    if report.usage_schema_changed {
        return Err("usage_schema_changed must be false in I-15".to_string());
    }
    if report.ledger_schema_changed {
        return Err("ledger_schema_changed must be false in I-15".to_string());
    }
    if report.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-15".to_string());
    }
    if report.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-15".to_string());
    }
    if report.map_pin_performed {
        return Err("map_pin_performed must be false in I-15".to_string());
    }
    if report.enforcement_performed {
        return Err("enforcement_performed must be false in I-15".to_string());
    }
    if report.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-15".to_string());
    }
    if report.mutation_performed {
        return Err("mutation_performed must be false in I-15".to_string());
    }
    if report.persistence_performed {
        return Err("persistence_performed must be false in I-15".to_string());
    }
    // Structural consistency
    if report.ready_for_reader_spike_preparation
        && report.status == EbpfEventStreamEvidenceAuditStatus::Failed
    {
        return Err(
            "ready_for_reader_spike_preparation=true is inconsistent with Failed status"
                .to_string(),
        );
    }
    Ok(())
}

/// Map an evidence audit status to a stable human-readable label.
pub fn event_stream_evidence_audit_status_label(
    status: EbpfEventStreamEvidenceAuditStatus,
) -> &'static str {
    status.as_str()
}

/// Map an evidence audit finding kind to a stable human-readable label.
pub fn event_stream_evidence_audit_finding_kind_label(
    kind: EbpfEventStreamEvidenceAuditFindingKind,
) -> &'static str {
    kind.as_str()
}
