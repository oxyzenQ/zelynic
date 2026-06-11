// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader spike result audit and release decision gate for the Intergalaxion Engine.
//!
//! Phase I-18 defines the audit and internal decision gate for reader spike
//! result captures. This phase is audit-only — not a real release gate, not a
//! live reader, not a ring buffer reader, not a kernel event consumer. It
//! consumes I-17 result summaries and produces a gate report with a status,
//! decision, and findings list. Release is always rejected in I-18. The
//! intergalaxion branch must remain experimental.
//!
//! # Design constraints (I-18)
//!
//! * Audit and decision gate only — not a real release.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake audit success, no fake release readiness.
//! * release_allowed is always false in I-18.
//! * must_remain_experimental is always true in I-18.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_result::{
    validate_event_stream_reader_spike_result_summary, EbpfEventStreamReaderSpikeResultSummary,
};

/// Status of the reader spike release gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReleaseGateStatus {
    /// The gate has not been evaluated or prerequisites are missing.
    NotReady,
    /// The gate is blocked by a hard safety gate.
    Blocked,
    /// The gate evaluation failed.
    Failed,
    /// The gate passed with warnings.
    Warning,
    /// The gate passed all checks.
    Passed,
    /// The branch must remain experimental.
    HoldExperimental,
    /// Continue local lab work only.
    ContinueLocalLab,
    /// Ready for reader spike review.
    ReadyForReaderSpikeReview,
    /// Release is explicitly rejected.
    ReleaseRejected,
}

impl EbpfReaderSpikeReleaseGateStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Warning => "warning",
            Self::Passed => "passed",
            Self::HoldExperimental => "hold_experimental",
            Self::ContinueLocalLab => "continue_local_lab",
            Self::ReadyForReaderSpikeReview => "ready_for_reader_spike_review",
            Self::ReleaseRejected => "release_rejected",
        }
    }
}

/// Decision produced by the reader spike release gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReleaseDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix preparation before proceeding.
    FixPreparation,
    /// Fix executor before proceeding.
    FixExecutor,
    /// Capture more evidence before proceeding.
    CaptureMoreEvidence,
    /// Continue local lab work only.
    ContinueLocalLabOnly,
    /// Prepare for a future reader spike review.
    PrepareReaderSpikeReview,
    /// Release is explicitly rejected.
    RejectRelease,
    /// Keep the branch experimental.
    KeepExperimental,
}

impl EbpfReaderSpikeReleaseDecision {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixPreparation => "fix_preparation",
            Self::FixExecutor => "fix_executor",
            Self::CaptureMoreEvidence => "capture_more_evidence",
            Self::ContinueLocalLabOnly => "continue_local_lab_only",
            Self::PrepareReaderSpikeReview => "prepare_reader_spike_review",
            Self::RejectRelease => "reject_release",
            Self::KeepExperimental => "keep_experimental",
        }
    }
}

/// Kind of release gate finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderSpikeReleaseGateFindingKind {
    /// Result capture finding.
    ResultCapture,
    /// Result summary finding.
    ResultSummary,
    /// Safety invariant finding.
    SafetyInvariant,
    /// CLI invariant finding.
    CliInvariant,
    /// Schema invariant finding.
    SchemaInvariant,
    /// Release invariant finding.
    ReleaseInvariant,
    /// Count invariant finding.
    CountInvariant,
    /// Evidence invariant finding.
    EvidenceInvariant,
}

impl EbpfReaderSpikeReleaseGateFindingKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResultCapture => "result_capture",
            Self::ResultSummary => "result_summary",
            Self::SafetyInvariant => "safety_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::ReleaseInvariant => "release_invariant",
            Self::CountInvariant => "count_invariant",
            Self::EvidenceInvariant => "evidence_invariant",
        }
    }
}

/// A single finding produced by the release gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReleaseGateFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderSpikeReleaseGateFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status of this finding.
    pub status: EbpfReaderSpikeReleaseGateStatus,
}

/// Input to the reader spike release gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReleaseGateInput {
    /// The I-17 result summary to audit.
    pub result_summary: EbpfEventStreamReaderSpikeResultSummary,
    /// Whether a FutureExecutionReady capture is required.
    pub require_future_execution_ready_capture: bool,
    /// Whether a CleanupCompleted capture is required.
    pub require_cleanup_completed_capture: bool,
    /// Whether ExecutionSucceeded captures are allowed.
    pub allow_execution_succeeded_capture: bool,
    /// Whether public CLI is expected to be hidden.
    pub public_cli_expected_hidden: bool,
    /// Whether usage schema is expected unchanged.
    pub usage_schema_expected_unchanged: bool,
    /// Whether ledger schema is expected unchanged.
    pub ledger_schema_expected_unchanged: bool,
    /// Whether a stable release was requested (must block).
    pub stable_release_requested: bool,
    /// Whether a tag was requested (must block).
    pub tag_requested: bool,
    /// Whether publish was requested (must block).
    pub publish_requested: bool,
    /// Whether a version bump was requested (must block).
    pub version_bump_requested: bool,
    /// Whether a main merge was requested (must block).
    pub main_merge_requested: bool,
}

/// Report produced by the reader spike release gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderSpikeReleaseGateReport {
    /// The phase this report covers.
    pub phase: String,
    /// The gate status.
    pub status: EbpfReaderSpikeReleaseGateStatus,
    /// The gate decision.
    pub decision: EbpfReaderSpikeReleaseDecision,
    /// Whether the result is ready for reader spike review.
    pub ready_for_reader_spike_review: bool,
    /// Whether release is allowed (always false in I-18).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-18).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderSpikeReleaseGateFinding>,
    /// Whether the result summary was valid.
    pub summary_valid: bool,
    /// Whether a FutureExecutionReady capture was present.
    pub future_execution_ready_capture_present: bool,
    /// Whether a CleanupCompleted capture was present.
    pub cleanup_completed_capture_present: bool,
    /// Whether an ExecutionSucceeded capture was present.
    pub execution_succeeded_capture_present: bool,
    /// Whether an invalid capture was detected.
    pub invalid_capture_detected: bool,
    /// Whether fake reader success was detected.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected.
    pub fake_live_event_counts_detected: bool,
    /// Whether public CLI was exposed.
    pub public_cli_exposed: bool,
    /// Whether usage schema was changed.
    pub usage_schema_changed: bool,
    /// Whether ledger schema was changed.
    pub ledger_schema_changed: bool,
    /// Whether stable release was requested.
    pub stable_release_requested: bool,
    /// Whether a tag was requested.
    pub tag_requested: bool,
    /// Whether publish was requested.
    pub publish_requested: bool,
    /// Whether a version bump was requested.
    pub version_bump_requested: bool,
    /// Whether a main merge was requested.
    pub main_merge_requested: bool,
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
}

// ── Helper functions ──────────────────────────────────────────────────

fn safe_base_report() -> EbpfReaderSpikeReleaseGateReport {
    EbpfReaderSpikeReleaseGateReport {
        phase: String::from("I-18"),
        status: EbpfReaderSpikeReleaseGateStatus::NotReady,
        decision: EbpfReaderSpikeReleaseDecision::Stop,
        ready_for_reader_spike_review: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        summary_valid: false,
        future_execution_ready_capture_present: false,
        cleanup_completed_capture_present: false,
        execution_succeeded_capture_present: false,
        invalid_capture_detected: false,
        fake_reader_success_detected: false,
        fake_live_event_counts_detected: false,
        public_cli_exposed: false,
        usage_schema_changed: false,
        ledger_schema_changed: false,
        stable_release_requested: false,
        tag_requested: false,
        publish_requested: false,
        version_bump_requested: false,
        main_merge_requested: false,
        ring_buffer_opened: false,
        live_event_stream_read: false,
        map_pin_performed: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        mutation_performed: false,
        persistence_performed: false,
    }
}

/// Create the default reader spike release gate input.
///
/// All fields default to safe values. The result summary uses the default
/// I-17 empty captures summary. No releases, tags, publishes, version bumps,
/// or main merges are requested.
pub fn default_reader_spike_release_gate_input() -> EbpfReaderSpikeReleaseGateInput {
    let empty_summary =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_result::summarize_event_stream_reader_spike_results(&[]);
    EbpfReaderSpikeReleaseGateInput {
        result_summary: empty_summary,
        require_future_execution_ready_capture: false,
        require_cleanup_completed_capture: false,
        allow_execution_succeeded_capture: false,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
        stable_release_requested: false,
        tag_requested: false,
        publish_requested: false,
        version_bump_requested: false,
        main_merge_requested: false,
    }
}

/// Evaluate the reader spike release gate.
///
/// Audits the I-17 result summary, checks for invalid captures, fake success,
/// safety violations, and produces a gate report with status, decision, and
/// findings. Release is always rejected in I-18. The branch must remain
/// experimental.
pub fn evaluate_reader_spike_release_gate(
    input: &EbpfReaderSpikeReleaseGateInput,
) -> EbpfReaderSpikeReleaseGateReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfReaderSpikeReleaseGateFinding> = Vec::new();
    let mut blocked = false;

    // 1. Validate result summary
    report.summary_valid =
        validate_event_stream_reader_spike_result_summary(&input.result_summary).is_ok();
    if !report.summary_valid {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-SUMMARY-INVALID"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ResultSummary,
            message: String::from("result summary validation failed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Failed,
        });
        blocked = true;
    }

    // 2. Copy safety flags from result summary
    report.fake_reader_success_detected = input.result_summary.fake_reader_success_detected;
    report.fake_live_event_counts_detected = input.result_summary.fake_live_event_counts_detected;
    report.public_cli_exposed = input.result_summary.public_cli_exposed;
    report.ring_buffer_opened = input.result_summary.ring_buffer_opened;
    report.live_event_stream_read = input.result_summary.live_event_stream_read;
    report.map_pin_performed = input.result_summary.map_pin_performed;
    report.enforcement_performed = input.result_summary.enforcement_performed;
    report.packet_drop_performed = input.result_summary.packet_drop_performed;
    report.mutation_performed = input.result_summary.mutation_performed;
    report.persistence_performed = input.result_summary.persistence_performed;

    // 3. Detect capture-level conditions
    report.invalid_capture_detected = input.result_summary.invalid_capture_count > 0;
    report.future_execution_ready_capture_present =
        input.result_summary.future_execution_ready_count > 0;
    report.cleanup_completed_capture_present = input.result_summary.cleanup_completed_count > 0;
    report.execution_succeeded_capture_present = input.result_summary.execution_succeeded_count > 0;

    // 4. Copy release request flags from input
    report.stable_release_requested = input.stable_release_requested;
    report.tag_requested = input.tag_requested;
    report.publish_requested = input.publish_requested;
    report.version_bump_requested = input.version_bump_requested;
    report.main_merge_requested = input.main_merge_requested;
    report.usage_schema_changed = !input.usage_schema_expected_unchanged;
    report.ledger_schema_changed = !input.ledger_schema_expected_unchanged;

    // 5. Check invalid captures
    if report.invalid_capture_detected {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-INVALID-CAPTURE"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ResultCapture,
            message: String::from("invalid capture detected in result summary"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Failed,
        });
        blocked = true;
    }

    // 6. Check fake reader success
    if report.fake_reader_success_detected {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-FAKE-READER-SUCCESS"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 7. Check fake live event counts
    if report.fake_live_event_counts_detected {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-FAKE-LIVE-COUNTS"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::CountInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 8. Check execution succeeded not allowed
    if report.execution_succeeded_capture_present && !input.allow_execution_succeeded_capture {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-EXEC-SUCCEEDED-NOT-ALLOWED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ResultCapture,
            message: String::from("ExecutionSucceeded capture present but not allowed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 9. Check FutureExecutionReady capture requirement
    if input.require_future_execution_ready_capture
        && !report.future_execution_ready_capture_present
    {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-FUTURE-EXEC-READY-MISSING"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::EvidenceInvariant,
            message: String::from("FutureExecutionReady capture required but not present"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::NotReady,
        });
        blocked = true;
    }

    // 10. Check CleanupCompleted capture requirement
    if input.require_cleanup_completed_capture && !report.cleanup_completed_capture_present {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-CLEANUP-COMPLETED-MISSING"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::EvidenceInvariant,
            message: String::from("CleanupCompleted capture required but not present"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::NotReady,
        });
        blocked = true;
    }

    // 11. Check public CLI
    if report.public_cli_exposed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-PUBLIC-CLI-EXPOSED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::CliInvariant,
            message: String::from("public CLI exposed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 12. Check stable release request
    if report.stable_release_requested {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-STABLE-RELEASE-REQUESTED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ReleaseInvariant,
            message: String::from("stable release requested — always rejected in I-18"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::ReleaseRejected,
        });
        blocked = true;
    }

    // 13. Check tag request
    if report.tag_requested {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-TAG-REQUESTED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ReleaseInvariant,
            message: String::from("tag requested — always rejected in I-18"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::ReleaseRejected,
        });
        blocked = true;
    }

    // 14. Check publish request
    if report.publish_requested {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-PUBLISH-REQUESTED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ReleaseInvariant,
            message: String::from("publish requested — always rejected in I-18"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::ReleaseRejected,
        });
        blocked = true;
    }

    // 15. Check version bump request
    if report.version_bump_requested {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-VERSION-BUMP-REQUESTED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ReleaseInvariant,
            message: String::from("version bump requested — always rejected in I-18"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::ReleaseRejected,
        });
        blocked = true;
    }

    // 16. Check main merge request
    if report.main_merge_requested {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-MAIN-MERGE-REQUESTED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::ReleaseInvariant,
            message: String::from("main merge requested — always rejected in I-18"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::ReleaseRejected,
        });
        blocked = true;
    }

    // 17. Check usage schema change
    if report.usage_schema_changed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SchemaInvariant,
            message: String::from("usage schema changed — must remain unchanged"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 18. Check ledger schema change
    if report.ledger_schema_changed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SchemaInvariant,
            message: String::from("ledger schema changed — must remain unchanged"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 19. Check safety operation flags
    if report.ring_buffer_opened {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-RING-BUFFER-OPENED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("ring buffer was opened"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.live_event_stream_read {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-LIVE-EVENT-READ"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("live event stream was read"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.map_pin_performed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-MAP-PIN-PERFORMED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("map pin was performed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.enforcement_performed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-ENFORCEMENT-PERFORMED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("enforcement was performed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.packet_drop_performed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-PACKET-DROP-PERFORMED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("packet drop was performed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.mutation_performed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-MUTATION-PERFORMED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("kernel mutation was performed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }
    if report.persistence_performed {
        findings.push(EbpfReaderSpikeReleaseGateFinding {
            code: String::from("GATE-PERSISTENCE-PERFORMED"),
            kind: EbpfReaderSpikeReleaseGateFindingKind::SafetyInvariant,
            message: String::from("file write was performed"),
            blocking: true,
            status: EbpfReaderSpikeReleaseGateStatus::Blocked,
        });
        blocked = true;
    }

    // 20. Determine gate status and decision
    if blocked {
        report.status = EbpfReaderSpikeReleaseGateStatus::Blocked;
        report.decision = EbpfReaderSpikeReleaseDecision::Stop;
    } else if report.summary_valid
        && (input.result_summary.ready_for_reader_spike_review
            && report.future_execution_ready_capture_present
            || report.cleanup_completed_capture_present)
    {
        report.status = EbpfReaderSpikeReleaseGateStatus::ReadyForReaderSpikeReview;
        report.decision = EbpfReaderSpikeReleaseDecision::PrepareReaderSpikeReview;
    } else if report.summary_valid {
        report.status = EbpfReaderSpikeReleaseGateStatus::ContinueLocalLab;
        report.decision = EbpfReaderSpikeReleaseDecision::ContinueLocalLabOnly;
    }

    // 21. I-18 hard invariants: release is always rejected, experimental is always true
    report.release_allowed = false;
    report.must_remain_experimental = true;

    // 22. Determine ready_for_reader_spike_review
    report.ready_for_reader_spike_review =
        report.status == EbpfReaderSpikeReleaseGateStatus::ReadyForReaderSpikeReview;
    report.findings = findings;
    report
}

/// Validate that a reader spike release gate report is safe.
///
/// Returns `Ok(())` if the report is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_reader_spike_release_gate_report(
    report: &EbpfReaderSpikeReleaseGateReport,
) -> Result<(), String> {
    if report.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if report.release_allowed {
        return Err("release_allowed must be false in I-18".to_string());
    }
    if !report.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-18".to_string());
    }
    if report.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if report.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if report.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    if report.stable_release_requested {
        return Err("stable_release_requested must be false".to_string());
    }
    if report.tag_requested {
        return Err("tag_requested must be false".to_string());
    }
    if report.publish_requested {
        return Err("publish_requested must be false".to_string());
    }
    if report.version_bump_requested {
        return Err("version_bump_requested must be false".to_string());
    }
    if report.main_merge_requested {
        return Err("main_merge_requested must be false".to_string());
    }
    if report.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if report.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if report.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if report.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if report.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if report.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if report.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if report.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if report.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if report.ready_for_reader_spike_review
        && report.status == EbpfReaderSpikeReleaseGateStatus::Failed
    {
        return Err(
            "ready_for_reader_spike_review must be false when status is Failed".to_string(),
        );
    }
    Ok(())
}

/// Map a reader spike release gate status to a stable human-readable label.
pub fn reader_spike_release_gate_status_label(
    status: EbpfReaderSpikeReleaseGateStatus,
) -> &'static str {
    status.as_str()
}

/// Map a reader spike release decision to a stable human-readable label.
pub fn reader_spike_release_decision_label(
    decision: EbpfReaderSpikeReleaseDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a reader spike release gate finding kind to a stable human-readable label.
pub fn reader_spike_release_gate_finding_kind_label(
    kind: EbpfReaderSpikeReleaseGateFindingKind,
) -> &'static str {
    kind.as_str()
}
