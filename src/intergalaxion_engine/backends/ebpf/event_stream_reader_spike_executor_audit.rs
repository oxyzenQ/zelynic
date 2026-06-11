// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader executor static safety audit for the Intergalaxion Engine.
//!
//! Phase I-16A adds a static safety audit layer for the I-16 reader spike
//! executor boundary. This phase is audit-only — not a live reader, not a
//! ring buffer reader, not a kernel event consumer. It verifies that the
//! executor boundary remains disabled-by-default, feature-gated, non-live,
//! hidden from public CLI, and honest about not executing a reader.
//!
//! # Design constraints (I-16A)
//!
//! * Audit-only — not a live reader, not a ring buffer reader.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake audit success.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor::{
    default_event_stream_reader_spike_executor_input, evaluate_event_stream_reader_spike_executor,
    validate_event_stream_reader_spike_executor_result, EbpfEventStreamReaderSpikeExecutorInput,
    EbpfEventStreamReaderSpikeExecutorResult, EbpfEventStreamReaderSpikeExecutorStatus,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::{
    validate_event_stream_reader_spike_prep_plan, EbpfEventStreamReaderSpikePrepPlan,
};

/// Status of the reader spike executor audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeExecutorAuditStatus {
    /// Audit passed all checks.
    Passed,
    /// Audit failed one or more checks.
    Failed,
    /// Audit produced warnings but no blocking failures.
    Warning,
    /// Audit is blocked by a hard safety gate.
    Blocked,
    /// Audit prerequisites are not met.
    NotReady,
    /// Audit passed and the system is ready for result capture.
    ReadyForResultCapture,
}

impl EbpfEventStreamReaderSpikeExecutorAuditStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
            Self::NotReady => "not_ready",
            Self::ReadyForResultCapture => "ready_for_result_capture",
        }
    }
}

/// Kind of audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamReaderSpikeExecutorAuditFindingKind {
    /// Feature gate configuration check.
    FeatureGate,
    /// Preparation plan readiness check.
    PreparationPlan,
    /// Executor result state check.
    ExecutorResult,
    /// General safety invariant check.
    SafetyInvariant,
    /// Public CLI exposure check.
    CliInvariant,
    /// JSON schema change check.
    SchemaInvariant,
    /// Event/record count check.
    CountInvariant,
    /// Cleanup requirement check.
    CleanupInvariant,
}

impl EbpfEventStreamReaderSpikeExecutorAuditFindingKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureGate => "feature_gate",
            Self::PreparationPlan => "preparation_plan",
            Self::ExecutorResult => "executor_result",
            Self::SafetyInvariant => "safety_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::CountInvariant => "count_invariant",
            Self::CleanupInvariant => "cleanup_invariant",
        }
    }
}

/// A single finding from the reader spike executor audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeExecutorAuditFinding {
    /// Machine-readable finding code.
    pub code: String,
    /// The kind of audit finding.
    pub kind: EbpfEventStreamReaderSpikeExecutorAuditFindingKind,
    /// Human-readable finding message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// The audit status for this finding.
    pub status: EbpfEventStreamReaderSpikeExecutorAuditStatus,
}

/// Input to the reader spike executor audit evaluation.
///
/// Combines the I-15A preparation plan, I-16 executor input and result,
/// and configuration flags for what the audit should require. The
/// evaluation is pure and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeExecutorAuditInput {
    /// The I-15A preparation plan.
    pub prep_plan: EbpfEventStreamReaderSpikePrepPlan,
    /// The I-16 executor input.
    pub executor_input: EbpfEventStreamReaderSpikeExecutorInput,
    /// The I-16 executor result.
    pub executor_result: EbpfEventStreamReaderSpikeExecutorResult,
    /// Whether the feature must be disabled by default.
    pub require_feature_disabled_by_default: bool,
    /// Whether the preparation plan must be PrepReady.
    pub require_prep_ready: bool,
    /// Whether the executor result must be FutureExecutionReady.
    pub require_future_execution_ready: bool,
    /// Whether cleanup must be required.
    pub require_cleanup_requirement: bool,
    /// Whether post-run evidence capture must be required.
    pub require_post_run_evidence_capture: bool,
    /// Whether public CLI must be hidden.
    pub public_cli_expected_hidden: bool,
    /// Whether usage JSON schema must be unchanged.
    pub usage_schema_expected_unchanged: bool,
    /// Whether ledger JSON schema must be unchanged.
    pub ledger_schema_expected_unchanged: bool,
}

/// Report produced by the reader spike executor audit evaluation.
///
/// All operation flags are always false in I-16A. The evaluation is
/// pure and deterministic. No live operations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamReaderSpikeExecutorAuditReport {
    /// The phase this report covers.
    pub phase: String,
    /// The overall audit status.
    pub status: EbpfEventStreamReaderSpikeExecutorAuditStatus,
    /// Whether the system is ready for result capture.
    pub ready_for_result_capture: bool,
    /// The audit findings.
    pub findings: Vec<EbpfEventStreamReaderSpikeExecutorAuditFinding>,
    /// Whether the preparation plan is ready.
    pub prep_plan_ready: bool,
    /// Whether the executor input is safe.
    pub executor_input_safe: bool,
    /// Whether the executor result is safe.
    pub executor_result_safe: bool,
    /// Whether feature disabled by default is confirmed.
    pub feature_disabled_by_default_confirmed: bool,
    /// Whether FutureExecutionReady is confirmed.
    pub future_execution_ready_confirmed: bool,
    /// Whether cleanup requirement is confirmed.
    pub cleanup_requirement_confirmed: bool,
    /// Whether post-run evidence capture is confirmed.
    pub post_run_evidence_capture_confirmed: bool,
    /// Whether public CLI was exposed (always false in I-16A).
    pub public_cli_exposed: bool,
    /// Whether usage JSON schema was changed (always false in I-16A).
    pub usage_schema_changed: bool,
    /// Whether ledger JSON schema was changed (always false in I-16A).
    pub ledger_schema_changed: bool,
    /// Whether a ring buffer was opened (always false in I-16A).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-16A).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-16A).
    pub map_pin_performed: bool,
    /// Whether enforcement was performed (always false in I-16A).
    pub enforcement_performed: bool,
    /// Whether packet drop was performed (always false in I-16A).
    pub packet_drop_performed: bool,
    /// Whether kernel mutation was performed (always false in I-16A).
    pub mutation_performed: bool,
    /// Whether file write was performed (always false in I-16A).
    pub persistence_performed: bool,
    /// Whether fake reader execution success was detected.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected.
    pub fake_live_event_counts_detected: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default reader spike executor audit input.
///
/// All fields are in their safest configuration: default I-15A prep plan
/// (not PrepReady), default I-16 executor input (feature disabled),
/// default I-16 executor result (FeatureDisabled). The default input
/// is safe but not ready for audit.
pub fn default_event_stream_reader_spike_executor_audit_input(
) -> EbpfEventStreamReaderSpikeExecutorAuditInput {
    let prep_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::default_event_stream_reader_spike_prep_input();
    let prep_plan =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_prep::evaluate_event_stream_reader_spike_prep(&prep_input);
    let executor_input = default_event_stream_reader_spike_executor_input();
    let executor_result = evaluate_event_stream_reader_spike_executor(&executor_input);
    EbpfEventStreamReaderSpikeExecutorAuditInput {
        prep_plan,
        executor_input,
        executor_result,
        require_feature_disabled_by_default: true,
        require_prep_ready: false,
        require_future_execution_ready: false,
        require_cleanup_requirement: false,
        require_post_run_evidence_capture: false,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

fn safe_base_report() -> EbpfEventStreamReaderSpikeExecutorAuditReport {
    EbpfEventStreamReaderSpikeExecutorAuditReport {
        phase: String::from("I-16A"),
        status: EbpfEventStreamReaderSpikeExecutorAuditStatus::NotReady,
        ready_for_result_capture: false,
        findings: Vec::new(),
        prep_plan_ready: false,
        executor_input_safe: false,
        executor_result_safe: false,
        feature_disabled_by_default_confirmed: false,
        future_execution_ready_confirmed: false,
        cleanup_requirement_confirmed: false,
        post_run_evidence_capture_confirmed: false,
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
    }
}

fn make_finding(
    code: &str,
    kind: EbpfEventStreamReaderSpikeExecutorAuditFindingKind,
    message: &str,
    blocking: bool,
    status: EbpfEventStreamReaderSpikeExecutorAuditStatus,
) -> EbpfEventStreamReaderSpikeExecutorAuditFinding {
    EbpfEventStreamReaderSpikeExecutorAuditFinding {
        code: String::from(code),
        kind,
        message: String::from(message),
        blocking,
        status,
    }
}

/// Evaluate the reader spike executor audit from input.
///
/// This function is pure and deterministic. It checks the I-16 executor
/// boundary state: preparation plan, executor input, executor result,
/// safety flags, feature gate, CLI exposure, schema change flags,
/// and count invariants to produce an audit report.
///
/// # Evaluation logic
///
/// 1. **Prep plan validation**: If required, validates the prep plan.
/// 2. **Prep plan readiness**: If required, checks `prep_plan.prep_ready=true`.
/// 3. **Executor result validation**: Validates via I-16 validation function.
/// 4. **ExecutionSucceeded detection**: Blocks if result claims success.
/// 5. **Attempted detection**: Blocks if `attempted=true` in I-16A.
/// 6. **Reader started detection**: Blocks if `reader_started=true`.
/// 7. **Reader completed detection**: Blocks if `reader_completed=true`.
/// 8. **Count invariants**: Detects fake live event counts.
/// 9. **Live operation flags**: Detects ring buffer, live read, etc.
/// 10. **Cleanup requirement**: Validates cleanup is required when configured.
/// 11. **Post-run evidence**: Validates evidence capture when configured.
/// 12. **CLI exposure**: Blocks if public CLI is exposed.
/// 13. **Schema changes**: Blocks if schemas were changed.
/// 14. **Feature gate**: Confirms feature is disabled by default.
pub fn evaluate_event_stream_reader_spike_executor_audit(
    input: &EbpfEventStreamReaderSpikeExecutorAuditInput,
) -> EbpfEventStreamReaderSpikeExecutorAuditReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfEventStreamReaderSpikeExecutorAuditFinding> = Vec::new();
    let mut has_blocking = false;
    let mut has_failure = false;

    // ── 1. Prep plan validation ────────────────────────────────────
    if input.require_prep_ready {
        if validate_event_stream_reader_spike_prep_plan(&input.prep_plan).is_err() {
            findings.push(make_finding(
                "audit-prep-plan-validation-failed",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::PreparationPlan,
                "preparation plan failed validation",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        } else if !input.prep_plan.prep_ready {
            findings.push(make_finding(
                "audit-prep-plan-not-ready",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::PreparationPlan,
                "preparation plan is not PrepReady",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        } else {
            report.prep_plan_ready = true;
        }
    }

    // ── 2. Executor result validation ──────────────────────────────
    if validate_event_stream_reader_spike_executor_result(&input.executor_result).is_err() {
        findings.push(make_finding(
            "audit-executor-result-validation-failed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::ExecutorResult,
            "executor result failed I-16 validation",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        has_blocking = true;
        has_failure = true;
    } else {
        report.executor_result_safe = true;
    }

    // ── 3. ExecutionSucceeded detection ────────────────────────────
    if input.executor_result.status == EbpfEventStreamReaderSpikeExecutorStatus::ExecutionSucceeded
    {
        findings.push(make_finding(
            "audit-execution-succeeded-detected",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "ExecutionSucceeded is not valid evidence in I-16A",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        report.fake_reader_success_detected = true;
        has_blocking = true;
        has_failure = true;
    }

    // ── 4. Attempted detection ─────────────────────────────────────
    if input.executor_result.attempted {
        findings.push(make_finding(
            "audit-attempted-true-detected",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "attempted=true must not occur in I-16A",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        has_blocking = true;
        has_failure = true;
    }

    // ── 5. Reader started detection ────────────────────────────────
    if input.executor_result.reader_started {
        findings.push(make_finding(
            "audit-reader-started-detected",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "reader_started=true must not occur in I-16A",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        has_blocking = true;
        has_failure = true;
    }

    // ── 6. Reader completed detection ─────────────────────────────
    if input.executor_result.reader_completed {
        findings.push(make_finding(
            "audit-reader-completed-detected",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "reader_completed=true must not occur in I-16A",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        has_blocking = true;
        has_failure = true;
    }

    // ── 7. Count invariants ────────────────────────────────────────
    if input.executor_result.events_read > 0 {
        findings.push(make_finding(
            "audit-events-read-positive",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CountInvariant,
            "events_read>0 is treated as fake live event count in I-16A",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        report.fake_live_event_counts_detected = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.decode_errors > 0 && !input.executor_result.attempted {
        findings.push(make_finding(
            "audit-decode-errors-without-attempt",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CountInvariant,
            "decode_errors>0 without attempted is fake live event count",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        report.fake_live_event_counts_detected = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.bridge_records > 0 && !input.executor_result.attempted {
        findings.push(make_finding(
            "audit-bridge-records-without-attempt",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CountInvariant,
            "bridge_records>0 without attempted is fake live event count",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        report.fake_live_event_counts_detected = true;
        has_blocking = true;
        has_failure = true;
    }

    // ── 8. Live operation flags ────────────────────────────────────
    if input.executor_result.ring_buffer_opened {
        findings.push(make_finding(
            "audit-ring-buffer-opened",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "ring buffer was opened",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.ring_buffer_opened = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.live_event_stream_read {
        findings.push(make_finding(
            "audit-live-event-stream-read",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "live event stream was read",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.live_event_stream_read = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.map_pin_performed {
        findings.push(make_finding(
            "audit-map-pin-performed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "map pin was performed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.map_pin_performed = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.enforcement_performed {
        findings.push(make_finding(
            "audit-enforcement-performed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "enforcement was performed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.enforcement_performed = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.packet_drop_performed {
        findings.push(make_finding(
            "audit-packet-drop-performed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "packet drop was performed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.packet_drop_performed = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.mutation_performed {
        findings.push(make_finding(
            "audit-mutation-performed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "kernel mutation was performed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.mutation_performed = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.persistence_performed {
        findings.push(make_finding(
            "audit-persistence-performed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SafetyInvariant,
            "file write was performed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Blocked,
        ));
        report.persistence_performed = true;
        has_blocking = true;
        has_failure = true;
    }
    if input.executor_result.public_cli_exposed {
        findings.push(make_finding(
            "audit-public-cli-exposed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CliInvariant,
            "public CLI was exposed",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        report.public_cli_exposed = true;
        has_blocking = true;
        has_failure = true;
    }

    // ── 9. Cleanup requirement ──────────────────────────────────────
    if input.require_cleanup_requirement {
        if input.executor_result.cleanup_required {
            report.cleanup_requirement_confirmed = true;
        } else {
            findings.push(make_finding(
                "audit-cleanup-not-required",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CleanupInvariant,
                "cleanup is required but not set in executor result",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        }
    }

    // ── 10. Post-run evidence capture ──────────────────────────────
    if input.require_post_run_evidence_capture {
        if input.executor_result.post_run_evidence_required {
            report.post_run_evidence_capture_confirmed = true;
        } else {
            findings.push(make_finding(
                "audit-post-run-evidence-not-required",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CleanupInvariant,
                "post-run evidence capture is required but not set in executor result",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        }
    }

    // ── 11. CLI exposure check ──────────────────────────────────────
    if !input.public_cli_expected_hidden {
        findings.push(make_finding(
            "audit-cli-expected-hidden-false",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::CliInvariant,
            "public CLI exposure check was not configured as hidden",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        has_blocking = true;
        has_failure = true;
    }

    // ── 12. Schema change checks ──────────────────────────────────
    if !input.usage_schema_expected_unchanged {
        findings.push(make_finding(
            "audit-usage-schema-expected-changed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SchemaInvariant,
            "usage schema unchanged check was not configured",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        has_blocking = true;
        has_failure = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(make_finding(
            "audit-ledger-schema-expected-changed",
            EbpfEventStreamReaderSpikeExecutorAuditFindingKind::SchemaInvariant,
            "ledger schema unchanged check was not configured",
            true,
            EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
        ));
        has_blocking = true;
        has_failure = true;
    }

    // ── 13. Feature gate check ────────────────────────────────────
    if input.require_feature_disabled_by_default {
        if !input.executor_result.feature_enabled {
            report.feature_disabled_by_default_confirmed = true;
        } else {
            findings.push(make_finding(
                "audit-feature-not-disabled-by-default",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::FeatureGate,
                "executor feature is not disabled by default",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        }
    }

    // ── 14. FutureExecutionReady check ─────────────────────────────
    if input.require_future_execution_ready {
        if input.executor_result.status
            == EbpfEventStreamReaderSpikeExecutorStatus::FutureExecutionReady
        {
            report.future_execution_ready_confirmed = true;
        } else {
            findings.push(make_finding(
                "audit-not-future-execution-ready",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::ExecutorResult,
                "executor result is not FutureExecutionReady",
                true,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed,
            ));
            has_blocking = true;
            has_failure = true;
        }
    }

    // ── Determine final status ──────────────────────────────────────
    // ReadyForResultCapture requires active configuration of key checks
    // and all configured checks to pass.
    report.findings = findings;
    let req_met = (!input.require_prep_ready || report.prep_plan_ready)
        && (!input.require_future_execution_ready || report.future_execution_ready_confirmed)
        && (!input.require_cleanup_requirement || report.cleanup_requirement_confirmed)
        && (!input.require_post_run_evidence_capture || report.post_run_evidence_capture_confirmed)
        && (!input.require_feature_disabled_by_default
            || report.feature_disabled_by_default_confirmed);
    if has_blocking || has_failure {
        if has_blocking {
            report.status = EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed;
        } else {
            report.status = EbpfEventStreamReaderSpikeExecutorAuditStatus::Warning;
        }
    } else if report.executor_result_safe && input.require_prep_ready && req_met {
        report.status = EbpfEventStreamReaderSpikeExecutorAuditStatus::ReadyForResultCapture;
        report.ready_for_result_capture = true;
    } else {
        report.status = EbpfEventStreamReaderSpikeExecutorAuditStatus::NotReady;
        if !input.require_prep_ready {
            report.findings.push(make_finding(
                "audit-prep-ready-not-configured",
                EbpfEventStreamReaderSpikeExecutorAuditFindingKind::PreparationPlan,
                "prep readiness check is not configured",
                false,
                EbpfEventStreamReaderSpikeExecutorAuditStatus::NotReady,
            ));
        }
    }

    // Executor input safe if no forbidden flags are set
    report.executor_input_safe = !input.executor_input.allow_ring_buffer_open
        && !input.executor_input.allow_live_event_read
        && !input.executor_input.allow_map_pin
        && !input.executor_input.allow_persistence
        && !input.executor_input.allow_enforcement
        && !input.executor_input.allow_packet_drop;

    report
}

/// Validate that a reader spike executor audit report does not have any
/// unsafe or inconsistent flags.
///
/// Returns `Ok(())` if the report is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_event_stream_reader_spike_executor_audit_report(
    report: &EbpfEventStreamReaderSpikeExecutorAuditReport,
) -> Result<(), String> {
    if report.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-16A".to_string());
    }
    if report.usage_schema_changed {
        return Err("usage_schema_changed must be false in I-16A".to_string());
    }
    if report.ledger_schema_changed {
        return Err("ledger_schema_changed must be false in I-16A".to_string());
    }
    if report.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-16A".to_string());
    }
    if report.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-16A".to_string());
    }
    if report.map_pin_performed {
        return Err("map_pin_performed must be false in I-16A".to_string());
    }
    if report.enforcement_performed {
        return Err("enforcement_performed must be false in I-16A".to_string());
    }
    if report.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-16A".to_string());
    }
    if report.mutation_performed {
        return Err("mutation_performed must be false in I-16A".to_string());
    }
    if report.persistence_performed {
        return Err("persistence_performed must be false in I-16A".to_string());
    }
    if report.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false in I-16A".to_string());
    }
    if report.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false in I-16A".to_string());
    }
    if report.ready_for_result_capture
        && report.status == EbpfEventStreamReaderSpikeExecutorAuditStatus::Failed
    {
        return Err("ready_for_result_capture=true requires status not Failed".to_string());
    }
    Ok(())
}

/// Map a reader spike executor audit status to a stable human-readable label.
pub fn event_stream_reader_spike_executor_audit_status_label(
    status: EbpfEventStreamReaderSpikeExecutorAuditStatus,
) -> &'static str {
    status.as_str()
}

/// Map a reader spike executor audit finding kind to a stable label.
pub fn event_stream_reader_spike_executor_audit_finding_kind_label(
    kind: EbpfEventStreamReaderSpikeExecutorAuditFindingKind,
) -> &'static str {
    kind.as_str()
}
