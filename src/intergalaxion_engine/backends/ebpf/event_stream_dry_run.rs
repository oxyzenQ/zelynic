// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Event stream reader lab dry run for the Intergalaxion Engine.
//!
//! Phase I-14 adds a feature-gated event stream reader lab dry-run model
//! that rehearses the reader path using I-12 reader boundary state and I-13
//! fixture bridge reports. This phase does NOT open ring buffers, NOT read
//! live kernel events, NOT start the event stream reader, NOT expose public
//! CLI, NOT add enforcement, NOT fake live reader success, and NOT fake
//! live event counts from fixture counts.
//!
//! # Design constraints (I-14)
//!
//! * Dry run only — not the real event stream reader.
//! * Disabled by default — requires explicit feature and configuration.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend.
//! * No public CLI exposure.
//! * No ledger file write.
//! * No persistence.
//! * No fake reader success.
//! * No fake live event counts from fixture counts.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live event stream read.

use crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::{
    validate_event_stream_fixture_bridge_report, EbpfEventStreamFixtureBridgeReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader::{
    validate_event_stream_reader_result, EbpfEventStreamReaderInput, EbpfEventStreamReaderResult,
    EbpfEventStreamReaderStatus,
};

/// Status of the event stream reader lab dry run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamDryRunStatus {
    /// The dry-run feature is not enabled.
    FeatureDisabled,
    /// The I-12 reader result failed validation.
    ReaderPlanRejected,
    /// The I-13 fixture bridge report failed validation.
    FixtureReportRejected,
    /// All gates pass; dry run is ready.
    DryRunReady,
    /// The dry run completed successfully (fixture-only).
    DryRunCompleted,
    /// The dry run failed.
    DryRunFailed,
    /// Live reader is not supported in I-14.
    LiveReaderUnsupported,
    /// Dry run was rejected due to unsafe configuration.
    Rejected,
}

impl EbpfEventStreamDryRunStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::ReaderPlanRejected => "reader_plan_rejected",
            Self::FixtureReportRejected => "fixture_report_rejected",
            Self::DryRunReady => "dry_run_ready",
            Self::DryRunCompleted => "dry_run_completed",
            Self::DryRunFailed => "dry_run_failed",
            Self::LiveReaderUnsupported => "live_reader_unsupported",
            Self::Rejected => "rejected",
        }
    }
}

/// Mode of the event stream reader lab dry run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventStreamDryRunMode {
    /// Fixture-only dry run (in-memory data).
    FixtureOnlyDryRun,
    /// Reader boundary dry run (I-12 state only).
    ReaderBoundaryDryRun,
    /// Live reader is not supported in I-14.
    LiveReaderUnsupported,
}

impl EbpfEventStreamDryRunMode {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixtureOnlyDryRun => "fixture_only_dry_run",
            Self::ReaderBoundaryDryRun => "reader_boundary_dry_run",
            Self::LiveReaderUnsupported => "live_reader_unsupported",
        }
    }
}

/// Input to the event stream reader lab dry-run evaluation.
///
/// Combines the I-12 reader input/result and I-13 fixture bridge report.
/// The dry-run evaluator is pure and deterministic — no live kernel
/// operations occur in any build configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamDryRunInput {
    /// The I-12 event stream reader input (informational).
    pub reader_input: EbpfEventStreamReaderInput,
    /// The I-12 event stream reader result (must be valid/safe).
    pub reader_result: EbpfEventStreamReaderResult,
    /// The I-13 fixture bridge report (must be valid/safe).
    pub fixture_report: EbpfEventStreamFixtureBridgeReport,
    /// Whether the dry-run feature is explicitly enabled.
    pub explicit_dry_run_feature_enabled: bool,
    /// Operator label for audit trail (must be non-empty for dry run).
    pub explicit_operator_label: String,
    /// Whether fixture counts may be reported (fixture-only counts).
    pub allow_fixture_counts: bool,
    /// Whether live reader is requested (rejected in I-14).
    pub allow_live_reader: bool,
    /// Whether ring buffer open is requested (rejected in I-14).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is requested (rejected in I-14).
    pub allow_live_event_read: bool,
    /// Whether map pin is requested (rejected in I-14).
    pub allow_map_pin: bool,
    /// Whether persistence is requested (rejected in I-14).
    pub allow_persistence: bool,
}

/// Result of evaluating the event stream reader lab dry run.
///
/// All operation flags are always false in I-14. The evaluation is
/// pure and deterministic. No ring buffer is opened, no live events
/// are read, no maps are pinned, no persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEventStreamDryRunResult {
    /// The determined dry-run status.
    pub status: EbpfEventStreamDryRunStatus,
    /// The dry-run mode.
    pub mode: EbpfEventStreamDryRunMode,
    /// Operator label for audit trail.
    pub operator_label: String,
    /// Whether the dry run completed.
    pub dry_run_completed: bool,
    /// Whether a reader was attempted (always false in I-14).
    pub reader_attempted: bool,
    /// Whether a reader succeeded (always false in I-14).
    pub reader_succeeded: bool,
    /// Whether this is fixture-only (always true in I-14).
    pub fixture_only: bool,
    /// Fixture frames seen (from I-13 report).
    pub fixture_frames_seen: usize,
    /// Fixture frames decoded (from I-13 report).
    pub fixture_frames_decoded: usize,
    /// Fixture decode errors (from I-13 report).
    pub fixture_decode_errors: usize,
    /// Fixture bridge records (from I-13 report).
    pub fixture_bridge_records: usize,
    /// Reported events read (fixture counts when enabled, else 0).
    pub reported_events_read: usize,
    /// Reported decode errors (fixture counts when enabled, else 0).
    pub reported_decode_errors: usize,
    /// Reported bridge records (fixture counts when enabled, else 0).
    pub reported_bridge_records: usize,
    /// Reason explaining the dry-run decision.
    pub reason: String,
    /// Whether public CLI was exposed (always false in I-14).
    pub public_cli_exposed: bool,
    /// Whether a ring buffer was opened (always false in I-14).
    pub ring_buffer_opened: bool,
    /// Whether a live event stream was read (always false in I-14).
    pub live_event_stream_read: bool,
    /// Whether a map pin was performed (always false in I-14).
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

/// Create the default event stream dry-run input.
///
/// All fields are in their safest configuration: feature disabled,
/// empty operator label, no unsafe flags set. The reader result and
/// fixture report are built from their respective defaults.
pub fn default_event_stream_dry_run_input() -> EbpfEventStreamDryRunInput {
    let reader_input =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::default_event_stream_reader_input();
    let reader_result =
        crate::intergalaxion_engine::backends::ebpf::event_stream_reader::evaluate_event_stream_reader(
            &reader_input,
        );
    let fixture_report =
        crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::decode_event_stream_fixture(
            &crate::intergalaxion_engine::backends::ebpf::event_stream_fixture::default_event_stream_fixture(
            ),
        );
    EbpfEventStreamDryRunInput {
        reader_input,
        reader_result,
        fixture_report,
        explicit_dry_run_feature_enabled: false,
        explicit_operator_label: String::new(),
        allow_fixture_counts: false,
        allow_live_reader: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
    }
}

/// Build a safe base dry-run result with all operation flags false.
fn safe_base_dry_run_result(
    operator_label: String,
    mode: EbpfEventStreamDryRunMode,
) -> EbpfEventStreamDryRunResult {
    EbpfEventStreamDryRunResult {
        status: EbpfEventStreamDryRunStatus::FeatureDisabled,
        mode,
        operator_label,
        dry_run_completed: false,
        reader_attempted: false,
        reader_succeeded: false,
        fixture_only: true,
        fixture_frames_seen: 0,
        fixture_frames_decoded: 0,
        fixture_decode_errors: 0,
        fixture_bridge_records: 0,
        reported_events_read: 0,
        reported_decode_errors: 0,
        reported_bridge_records: 0,
        reason: String::from("dry run is disabled by default"),
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

/// Evaluate the event stream reader lab dry run from input.
///
/// This function is pure and deterministic. It checks the feature flag,
/// operator label, reader result validity, fixture report validity, and
/// safety flags to determine whether the dry run can proceed.
///
/// # Evaluation logic
///
/// 1. **Feature disabled**: `explicit_dry_run_feature_enabled=false`
///    always returns `FeatureDisabled`.
/// 2. **Operator label**: Empty operator label returns `Rejected`.
/// 3. **Reader result validation**: If the I-12 reader result fails
///    validation, returns `ReaderPlanRejected`.
/// 4. **Reader result ReaderSucceeded**: Not reachable in I-14.
/// 5. **Reader result live event read**: Not reachable in I-14.
/// 6. **Fixture report validation**: If the I-13 fixture report fails
///    validation, returns `FixtureReportRejected`.
/// 7. **Fixture report fixture_only=false**: Returns `Rejected`.
/// 8. **allow_live_reader=true**: Returns `LiveReaderUnsupported`.
/// 9. **allow_ring_buffer_open=true**: Returns `Rejected`.
/// 10. **allow_live_event_read=true**: Returns `Rejected`.
/// 11. **allow_map_pin=true**: Returns `Rejected`.
/// 12. **allow_persistence=true**: Returns `Rejected`.
/// 13. **DryRunCompleted**: All gates pass. Fixture counts are reported
///     only when `allow_fixture_counts=true`.
pub fn evaluate_event_stream_dry_run(
    input: &EbpfEventStreamDryRunInput,
) -> EbpfEventStreamDryRunResult {
    // ── 1. Feature disabled ─────────────────────────────────────────
    if !input.explicit_dry_run_feature_enabled {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::FeatureDisabled,
            reason: String::from("dry-run feature is disabled"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 2. Operator label required ────────────────────────────────────
    if input.explicit_operator_label.is_empty() {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("operator label must not be empty"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 3. Reader result validation ────────────────────────────────────
    if validate_event_stream_reader_result(&input.reader_result).is_err() {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::ReaderPlanRejected,
            reason: String::from("reader result failed validation"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::ReaderBoundaryDryRun,
            )
        };
    }

    // ── 4. Reader result must not be ReaderSucceeded ────────────────────
    if input.reader_result.status == EbpfEventStreamReaderStatus::ReaderSucceeded {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::ReaderPlanRejected,
            reason: String::from("reader result status must not be ReaderSucceeded in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::ReaderBoundaryDryRun,
            )
        };
    }

    // ── 5. Reader result must not have live event read ────────────────
    if input.reader_result.live_event_stream_read {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::ReaderPlanRejected,
            reason: String::from("reader result must not have live_event_stream_read in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::ReaderBoundaryDryRun,
            )
        };
    }

    // ── 6. Fixture report validation ──────────────────────────────────
    if validate_event_stream_fixture_bridge_report(&input.fixture_report).is_err() {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::FixtureReportRejected,
            reason: String::from("fixture bridge report failed validation"),
            fixture_frames_seen: input.fixture_report.frames_seen,
            fixture_frames_decoded: input.fixture_report.frames_decoded,
            fixture_decode_errors: input.fixture_report.decode_errors,
            fixture_bridge_records: input.fixture_report.bridge_records,
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 7. Fixture report fixture_only must be true ───────────────────
    if !input.fixture_report.fixture_only {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("fixture report fixture_only must be true in I-14"),
            fixture_frames_seen: input.fixture_report.frames_seen,
            fixture_frames_decoded: input.fixture_report.frames_decoded,
            fixture_decode_errors: input.fixture_report.decode_errors,
            fixture_bridge_records: input.fixture_report.bridge_records,
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 8. allow_live_reader rejected in I-14 ────────────────────────
    if input.allow_live_reader {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::LiveReaderUnsupported,
            reason: String::from("live reader is not supported in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::LiveReaderUnsupported,
            )
        };
    }

    // ── 9. allow_ring_buffer_open rejected ───────────────────────────
    if input.allow_ring_buffer_open {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("ring buffer open is not supported in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 10. allow_live_event_read rejected ────────────────────────────
    if input.allow_live_event_read {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("live event read is not supported in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 11. allow_map_pin rejected ────────────────────────────────────
    if input.allow_map_pin {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("map pin is not supported in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 12. allow_persistence rejected ────────────────────────────────
    if input.allow_persistence {
        return EbpfEventStreamDryRunResult {
            status: EbpfEventStreamDryRunStatus::Rejected,
            reason: String::from("persistence is not supported in I-14"),
            ..safe_base_dry_run_result(
                input.explicit_operator_label.clone(),
                EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
            )
        };
    }

    // ── 13. DryRunCompleted ──────────────────────────────────────────
    // All gates pass. Report fixture counts when allow_fixture_counts=true.
    let reported_events_read = if input.allow_fixture_counts {
        input.fixture_report.frames_decoded
    } else {
        0
    };
    let reported_decode_errors = if input.allow_fixture_counts {
        input.fixture_report.decode_errors
    } else {
        0
    };
    let reported_bridge_records = if input.allow_fixture_counts {
        input.fixture_report.bridge_records
    } else {
        0
    };

    EbpfEventStreamDryRunResult {
        status: EbpfEventStreamDryRunStatus::DryRunCompleted,
        mode: EbpfEventStreamDryRunMode::FixtureOnlyDryRun,
        operator_label: input.explicit_operator_label.clone(),
        dry_run_completed: true,
        reader_attempted: false,
        reader_succeeded: false,
        fixture_only: true,
        fixture_frames_seen: input.fixture_report.frames_seen,
        fixture_frames_decoded: input.fixture_report.frames_decoded,
        fixture_decode_errors: input.fixture_report.decode_errors,
        fixture_bridge_records: input.fixture_report.bridge_records,
        reported_events_read,
        reported_decode_errors,
        reported_bridge_records,
        reason: String::from("dry run completed with fixture-only counts"),
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

/// Validate that an event stream dry-run result does not have any unsafe
/// or inconsistent flags.
///
/// Returns `Ok(())` if the result is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
///
/// # Validation rules (I-14)
///
/// * All safety flags must be false.
/// * `reader_attempted` must be false.
/// * `reader_succeeded` must be false.
/// * `fixture_only` must be true.
/// * `reported_events_read` must not exceed `fixture_frames_decoded`.
/// * `reported_decode_errors` must not exceed `fixture_decode_errors`.
/// * `reported_bridge_records` must not exceed `fixture_bridge_records`.
/// * `dry_run_completed` requires `fixture_only=true`.
pub fn validate_event_stream_dry_run_result(
    result: &EbpfEventStreamDryRunResult,
) -> Result<(), String> {
    // Safety flag checks
    if result.reader_attempted {
        return Err("reader_attempted must be false in I-14".to_string());
    }
    if result.reader_succeeded {
        return Err("reader_succeeded must be false in I-14".to_string());
    }
    if !result.fixture_only {
        return Err("fixture_only must be true in I-14".to_string());
    }
    if result.ring_buffer_opened {
        return Err("ring_buffer_opened must be false in I-14".to_string());
    }
    if result.live_event_stream_read {
        return Err("live_event_stream_read must be false in I-14".to_string());
    }
    if result.map_pin_performed {
        return Err("map_pin_performed must be false in I-14".to_string());
    }
    if result.enforcement_performed {
        return Err("enforcement_performed must be false in I-14".to_string());
    }
    if result.packet_drop_performed {
        return Err("packet_drop_performed must be false in I-14".to_string());
    }
    if result.mutation_performed {
        return Err("mutation_performed must be false in I-14".to_string());
    }
    if result.persistence_performed {
        return Err("persistence_performed must be false in I-14".to_string());
    }
    if result.public_cli_exposed {
        return Err("public_cli_exposed must be false in I-14".to_string());
    }
    // Structural consistency
    if result.reported_events_read > result.fixture_frames_decoded {
        return Err("reported_events_read must not exceed fixture_frames_decoded".to_string());
    }
    if result.reported_decode_errors > result.fixture_decode_errors {
        return Err("reported_decode_errors must not exceed fixture_decode_errors".to_string());
    }
    if result.reported_bridge_records > result.fixture_bridge_records {
        return Err("reported_bridge_records must not exceed fixture_bridge_records".to_string());
    }
    if result.dry_run_completed && !result.fixture_only {
        return Err("dry_run_completed requires fixture_only=true".to_string());
    }
    Ok(())
}

/// Map an event stream dry-run status to a stable human-readable label.
pub fn event_stream_dry_run_status_label(status: EbpfEventStreamDryRunStatus) -> &'static str {
    status.as_str()
}

/// Map an event stream dry-run mode to a stable human-readable label.
pub fn event_stream_dry_run_mode_label(mode: EbpfEventStreamDryRunMode) -> &'static str {
    mode.as_str()
}
