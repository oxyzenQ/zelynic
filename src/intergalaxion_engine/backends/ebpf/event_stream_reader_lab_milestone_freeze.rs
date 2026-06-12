// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab milestone freeze model for the Intergalaxion Engine.
//!
//! Phase I-20 freezes the I-10F through I-19 reader-lab evidence chain into
//! an internal milestone record. This phase is milestone-freeze only — not a
//! release, not a public feature, not a live reader, not a ring buffer
//! reader, not a kernel event consumer. It is an internal deterministic
//! milestone checkpoint only.
//!
//! # Design constraints (I-20)
//!
//! * Milestone-freeze only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake freeze success, no fake release readiness.
//! * release_allowed is always false in I-20.
//! * must_remain_experimental is always true in I-20.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_executor_audit::{
    validate_event_stream_reader_spike_executor_audit_report,
    EbpfEventStreamReaderSpikeExecutorAuditReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_release_gate::{
    validate_reader_spike_release_gate_report, EbpfReaderSpikeReleaseGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_result::{
    validate_event_stream_reader_spike_result_summary, EbpfEventStreamReaderSpikeResultSummary,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_review_pack::{
    build_reader_spike_review_pack, default_reader_spike_review_pack_input,
    validate_reader_spike_review_pack, EbpfReaderSpikeReviewPack,
};

/// Status of the reader lab milestone freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabMilestoneFreezeStatus {
    /// Freeze is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Milestone is frozen.
    Frozen,
    /// Freeze was rejected.
    FreezeRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderLabMilestoneFreezeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::Frozen => "frozen",
            Self::FreezeRejected => "freeze_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab milestone freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabMilestoneFreezeDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix evidence before proceeding.
    FixEvidence,
    /// Capture more results before proceeding.
    CaptureMoreResults,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Freeze the milestone.
    FreezeMilestone,
    /// Reject any release.
    RejectRelease,
    /// Prepare next lab arc.
    PrepareNextLabArc,
}

impl EbpfReaderLabMilestoneFreezeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixEvidence => "fix_evidence",
            Self::CaptureMoreResults => "capture_more_results",
            Self::KeepExperimental => "keep_experimental",
            Self::FreezeMilestone => "freeze_milestone",
            Self::RejectRelease => "reject_release",
            Self::PrepareNextLabArc => "prepare_next_lab_arc",
        }
    }
}

/// Kind of milestone freeze finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabMilestoneFreezeFindingKind {
    /// Review pack finding.
    ReviewPack,
    /// Release gate finding.
    ReleaseGate,
    /// Result capture finding.
    ResultCapture,
    /// Executor audit finding.
    ExecutorAudit,
    /// Executor boundary finding.
    ExecutorBoundary,
    /// Evidence audit finding.
    EvidenceAudit,
    /// Safety invariant finding.
    SafetyInvariant,
    /// Schema invariant finding.
    SchemaInvariant,
    /// CLI invariant finding.
    CliInvariant,
    /// Release invariant finding.
    ReleaseInvariant,
    /// Freeze invariant finding.
    FreezeInvariant,
}

impl EbpfReaderLabMilestoneFreezeFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewPack => "review_pack",
            Self::ReleaseGate => "release_gate",
            Self::ResultCapture => "result_capture",
            Self::ExecutorAudit => "executor_audit",
            Self::ExecutorBoundary => "executor_boundary",
            Self::EvidenceAudit => "evidence_audit",
            Self::SafetyInvariant => "safety_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::ReleaseInvariant => "release_invariant",
            Self::FreezeInvariant => "freeze_invariant",
        }
    }
}

/// A single finding produced by the milestone freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabMilestoneFreezeFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderLabMilestoneFreezeFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderLabMilestoneFreezeStatus,
}

/// Input to the reader lab milestone freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabMilestoneFreezeInput {
    /// The I-19 review pack.
    pub review_pack: EbpfReaderSpikeReviewPack,
    /// The I-18 release gate report.
    pub release_gate_report: EbpfReaderSpikeReleaseGateReport,
    /// The I-17 result summary.
    pub result_summary: EbpfEventStreamReaderSpikeResultSummary,
    /// The I-16A executor audit report.
    pub executor_audit_report: EbpfEventStreamReaderSpikeExecutorAuditReport,
    /// Whether review pack ready is required.
    pub require_review_pack_ready: bool,
    /// Whether release gate ready is required.
    pub require_release_gate_ready: bool,
    /// Whether result summary ready is required.
    pub require_result_summary_ready: bool,
    /// Whether public CLI is expected hidden.
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

/// Record produced by the reader lab milestone freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabMilestoneFreezeRecord {
    /// The phase this record covers.
    pub phase: String,
    /// The freeze status.
    pub status: EbpfReaderLabMilestoneFreezeStatus,
    /// The freeze decision.
    pub decision: EbpfReaderLabMilestoneFreezeDecision,
    /// Whether the milestone is frozen.
    pub milestone_frozen: bool,
    /// Whether release is allowed (always false in I-20).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-20).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderLabMilestoneFreezeFinding>,
    /// Whether the review pack is ready.
    pub review_pack_ready: bool,
    /// Whether the release gate is ready.
    pub release_gate_ready: bool,
    /// Whether the result summary is ready.
    pub result_summary_ready: bool,
    /// Whether the executor audit is ready.
    pub executor_audit_ready: bool,
    /// Whether a FutureExecutionReady capture is present.
    pub future_execution_ready_capture_present: bool,
    /// Whether a CleanupCompleted capture is present.
    pub cleanup_completed_capture_present: bool,
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
    /// Whether fake reader success was detected.
    pub fake_reader_success_detected: bool,
    /// Whether fake live event counts were detected.
    pub fake_live_event_counts_detected: bool,
    /// Whether fake release readiness was detected.
    pub fake_release_readiness_detected: bool,
    /// Whether fake freeze success was detected.
    pub fake_freeze_success_detected: bool,
}

// -- Helper functions --

fn safe_base_record() -> EbpfReaderLabMilestoneFreezeRecord {
    EbpfReaderLabMilestoneFreezeRecord {
        phase: String::from("I-20"),
        status: EbpfReaderLabMilestoneFreezeStatus::Draft,
        decision: EbpfReaderLabMilestoneFreezeDecision::Stop,
        milestone_frozen: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        review_pack_ready: false,
        release_gate_ready: false,
        result_summary_ready: false,
        executor_audit_ready: false,
        future_execution_ready_capture_present: false,
        cleanup_completed_capture_present: false,
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
        fake_reader_success_detected: false,
        fake_live_event_counts_detected: false,
        fake_release_readiness_detected: false,
        fake_freeze_success_detected: false,
    }
}

/// Create the default reader lab milestone freeze input.
///
/// Builds the full safe evidence chain from I-10F through I-19, then wraps
/// it with safe configuration flags. No releases, tags, publishes, version
/// bumps, or main merges are requested.
pub fn default_reader_lab_milestone_freeze_input() -> EbpfReaderLabMilestoneFreezeInput {
    let pack_input = default_reader_spike_review_pack_input();
    let review_pack = build_reader_spike_review_pack(&pack_input);
    // Extract the release gate and result summary from the pack input chain
    let release_gate_report = pack_input.release_gate_report;
    let result_summary = pack_input.result_summary;
    let executor_audit_report = pack_input.executor_audit_report;
    EbpfReaderLabMilestoneFreezeInput {
        review_pack,
        release_gate_report,
        result_summary,
        executor_audit_report,
        require_review_pack_ready: false,
        require_release_gate_ready: false,
        require_result_summary_ready: false,
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

/// Build the reader lab milestone freeze record from input.
///
/// Validates the review pack, release gate, result summary, and executor
/// audit. Aggregates safety flags, checks readiness requirements, and
/// determines the overall freeze status, decision, and findings. Release is
/// always rejected in I-20. The branch must remain experimental.
pub fn build_reader_lab_milestone_freeze_record(
    input: &EbpfReaderLabMilestoneFreezeInput,
) -> EbpfReaderLabMilestoneFreezeRecord {
    let mut rec = safe_base_record();
    let mut findings: Vec<EbpfReaderLabMilestoneFreezeFinding> = Vec::new();
    let mut blocked = false;

    // Validate each evidence type
    let rp_valid = validate_reader_spike_review_pack(&input.review_pack).is_ok();
    let rg_valid = validate_reader_spike_release_gate_report(&input.release_gate_report).is_ok();
    let rs_valid = validate_event_stream_reader_spike_result_summary(&input.result_summary).is_ok();
    let ea_valid =
        validate_event_stream_reader_spike_executor_audit_report(&input.executor_audit_report)
            .is_ok();

    rec.review_pack_ready = rp_valid;
    rec.release_gate_ready = rg_valid;
    rec.result_summary_ready = rs_valid;
    rec.executor_audit_ready = ea_valid;

    // Evidence validation checks
    if !rp_valid {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RP-INVALID"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReviewPack,
            message: String::from("review pack validation failed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }
    if !rg_valid {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RG-INVALID"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseGate,
            message: String::from("release gate validation failed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }
    if !rs_valid {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RS-INVALID"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ResultCapture,
            message: String::from("result summary validation failed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }

    // Readiness checks when required
    if input.require_review_pack_ready && !input.review_pack.review_ready {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RP-NOT-READY"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReviewPack,
            message: String::from("review pack not ready for freeze"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }
    if input.require_release_gate_ready && !input.release_gate_report.ready_for_reader_spike_review
    {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RG-NOT-READY"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseGate,
            message: String::from("release gate not ready for freeze"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }
    if input.require_result_summary_ready && !input.result_summary.ready_for_reader_spike_review {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RS-NOT-READY"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ResultCapture,
            message: String::from("result summary not ready for freeze"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Incomplete,
        });
        blocked = true;
    }

    // Aggregate safety flags from review pack and release gate
    rec.fake_reader_success_detected = input.review_pack.fake_reader_success_detected
        || input.release_gate_report.fake_reader_success_detected;
    rec.fake_live_event_counts_detected = input.review_pack.fake_live_event_counts_detected
        || input.release_gate_report.fake_live_event_counts_detected;
    rec.fake_release_readiness_detected = input.review_pack.fake_release_readiness_detected;
    rec.ring_buffer_opened =
        input.review_pack.ring_buffer_opened || input.release_gate_report.ring_buffer_opened;
    rec.live_event_stream_read = input.review_pack.live_event_stream_read
        || input.release_gate_report.live_event_stream_read;
    rec.map_pin_performed =
        input.review_pack.map_pin_performed || input.release_gate_report.map_pin_performed;
    rec.enforcement_performed =
        input.review_pack.enforcement_performed || input.release_gate_report.enforcement_performed;
    rec.packet_drop_performed =
        input.review_pack.packet_drop_performed || input.release_gate_report.packet_drop_performed;
    rec.mutation_performed =
        input.review_pack.mutation_performed || input.release_gate_report.mutation_performed;
    rec.persistence_performed =
        input.review_pack.persistence_performed || input.release_gate_report.persistence_performed;
    rec.public_cli_exposed =
        input.review_pack.public_cli_exposed || input.release_gate_report.public_cli_exposed;
    rec.usage_schema_changed = !input.usage_schema_expected_unchanged;
    rec.ledger_schema_changed = !input.ledger_schema_expected_unchanged;

    // Release-requested flags from input
    rec.stable_release_requested = input.stable_release_requested;
    rec.tag_requested = input.tag_requested;
    rec.publish_requested = input.publish_requested;
    rec.version_bump_requested = input.version_bump_requested;
    rec.main_merge_requested = input.main_merge_requested;

    // Capture-level flags from release gate
    rec.future_execution_ready_capture_present = input
        .release_gate_report
        .future_execution_ready_capture_present;
    rec.cleanup_completed_capture_present =
        input.release_gate_report.cleanup_completed_capture_present;

    // Safety flag checks — fake reader success
    if rec.fake_reader_success_detected {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-FAKE-READER"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    // Fake live event counts
    if rec.fake_live_event_counts_detected {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-FAKE-LIVE-COUNTS"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    // Fake release readiness
    if rec.fake_release_readiness_detected {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-FAKE-RELEASE"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Public CLI exposure
    if rec.public_cli_exposed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-PUBLIC-CLI"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::CliInvariant,
            message: String::from("public CLI exposed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    // Usage schema change
    if rec.usage_schema_changed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-USAGE-SCHEMA"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SchemaInvariant,
            message: String::from("usage schema changed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    // Ledger schema change
    if rec.ledger_schema_changed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-LEDGER-SCHEMA"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SchemaInvariant,
            message: String::from("ledger schema changed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    // Stable release requested
    if rec.stable_release_requested {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-STABLE-RELEASE"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("stable release requested"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Tag requested
    if rec.tag_requested {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-TAG"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("tag requested"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Publish requested
    if rec.publish_requested {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-PUBLISH"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("publish requested"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Version bump requested
    if rec.version_bump_requested {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-VERSION-BUMP"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("version bump requested"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Main merge requested
    if rec.main_merge_requested {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-MAIN-MERGE"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::ReleaseInvariant,
            message: String::from("main merge requested"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::FreezeRejected,
        });
        blocked = true;
    }
    // Operation flag checks
    if rec.ring_buffer_opened {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-RING-BUFFER"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("ring buffer was opened"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.live_event_stream_read {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-LIVE-EVENT"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("live event stream was read"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.map_pin_performed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-MAP-PIN"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("map pin was performed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.enforcement_performed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-ENFORCEMENT"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("enforcement was performed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.packet_drop_performed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-PACKET-DROP"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("packet drop was performed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.mutation_performed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-MUTATION"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("kernel mutation was performed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if rec.persistence_performed {
        findings.push(EbpfReaderLabMilestoneFreezeFinding {
            code: String::from("FREEZE-PERSISTENCE"),
            kind: EbpfReaderLabMilestoneFreezeFindingKind::SafetyInvariant,
            message: String::from("file write was performed"),
            blocking: true,
            status: EbpfReaderLabMilestoneFreezeStatus::Blocked,
        });
        blocked = true;
    }

    // Determine status and decision
    if blocked {
        rec.status = EbpfReaderLabMilestoneFreezeStatus::Blocked;
        rec.decision = EbpfReaderLabMilestoneFreezeDecision::Stop;
    } else {
        let all_valid = rp_valid && rg_valid && rs_valid && ea_valid;
        if all_valid {
            rec.status = EbpfReaderLabMilestoneFreezeStatus::Frozen;
            rec.decision = EbpfReaderLabMilestoneFreezeDecision::FreezeMilestone;
            rec.milestone_frozen = true;
        } else {
            rec.status = EbpfReaderLabMilestoneFreezeStatus::Incomplete;
            rec.decision = EbpfReaderLabMilestoneFreezeDecision::FixEvidence;
        }
    }

    // I-20 hard invariants
    rec.release_allowed = false;
    rec.must_remain_experimental = true;

    // Detect fake freeze success: if milestone_frozen but unsafe conditions exist
    rec.fake_freeze_success_detected = rec.milestone_frozen
        && (rec.fake_reader_success_detected
            || rec.fake_live_event_counts_detected
            || rec.fake_release_readiness_detected
            || rec.public_cli_exposed
            || rec.ring_buffer_opened
            || rec.live_event_stream_read
            || rec.map_pin_performed
            || rec.enforcement_performed
            || rec.packet_drop_performed
            || rec.mutation_performed
            || rec.persistence_performed
            || rec.stable_release_requested
            || rec.tag_requested
            || rec.publish_requested
            || rec.version_bump_requested
            || rec.main_merge_requested);

    rec.findings = findings;
    rec
}

/// Validate that a reader lab milestone freeze record is safe.
pub fn validate_reader_lab_milestone_freeze_record(
    record: &EbpfReaderLabMilestoneFreezeRecord,
) -> Result<(), String> {
    if record.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if record.release_allowed {
        return Err("release_allowed must be false in I-20".to_string());
    }
    if !record.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-20".to_string());
    }
    if record.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if record.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if record.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    if record.stable_release_requested {
        return Err("stable_release_requested must be false".to_string());
    }
    if record.tag_requested {
        return Err("tag_requested must be false".to_string());
    }
    if record.publish_requested {
        return Err("publish_requested must be false".to_string());
    }
    if record.version_bump_requested {
        return Err("version_bump_requested must be false".to_string());
    }
    if record.main_merge_requested {
        return Err("main_merge_requested must be false".to_string());
    }
    if record.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if record.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if record.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if record.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if record.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if record.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if record.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if record.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if record.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if record.fake_release_readiness_detected {
        return Err("fake_release_readiness_detected must be false".to_string());
    }
    if record.fake_freeze_success_detected {
        return Err("fake_freeze_success_detected must be false".to_string());
    }
    if record.milestone_frozen
        && record.status == EbpfReaderLabMilestoneFreezeStatus::FreezeRejected
    {
        return Err("milestone_frozen must be false when status is FreezeRejected".to_string());
    }
    Ok(())
}

/// Map a milestone freeze status to a stable human-readable label.
pub fn reader_lab_milestone_freeze_status_label(
    status: EbpfReaderLabMilestoneFreezeStatus,
) -> &'static str {
    status.as_str()
}

/// Map a milestone freeze decision to a stable human-readable label.
pub fn reader_lab_milestone_freeze_decision_label(
    decision: EbpfReaderLabMilestoneFreezeDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a milestone freeze finding kind to a stable human-readable label.
pub fn reader_lab_milestone_freeze_finding_kind_label(
    kind: EbpfReaderLabMilestoneFreezeFindingKind,
) -> &'static str {
    kind.as_str()
}
