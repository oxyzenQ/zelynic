// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc planning model for the Intergalaxion Engine.
//!
//! Phase I-21 plans the next Intergalaxion reader lab arc after the I-20
//! milestone freeze. This phase is planning-only — not a release, not a public
//! feature, not a live reader, not a ring buffer reader, not a kernel event
//! consumer. It is an internal deterministic next-arc planning checkpoint only.
//!
//! # Design constraints (I-21)
//!
//! * Planning-only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake planning success, no fake release readiness.
//! * release_allowed is always false in I-21.
//! * must_remain_experimental is always true in I-21.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_milestone_freeze::{
    validate_reader_lab_milestone_freeze_record, EbpfReaderLabMilestoneFreezeRecord,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_release_gate::{
    validate_reader_spike_release_gate_report, EbpfReaderSpikeReleaseGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_review_pack::{
    validate_reader_spike_review_pack, EbpfReaderSpikeReviewPack,
};

/// Status of the reader lab next arc plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcPlanStatus {
    /// Plan is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Plan is ready.
    PlanReady,
    /// Plan was rejected.
    PlanRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderLabNextArcPlanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::PlanReady => "plan_ready",
            Self::PlanRejected => "plan_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab next arc plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix milestone evidence before proceeding.
    FixMilestoneEvidence,
    /// Continue fixture-only refinement.
    ContinueFixtureOnly,
    /// Freeze static policy.
    FreezeStaticPolicy,
    /// Prepare manual reader spike checklist.
    PrepareManualReaderSpikeChecklist,
    /// Prepare reader spike review.
    PrepareReaderSpikeReview,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Reject any release.
    RejectRelease,
}

impl EbpfReaderLabNextArcDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixMilestoneEvidence => "fix_milestone_evidence",
            Self::ContinueFixtureOnly => "continue_fixture_only",
            Self::FreezeStaticPolicy => "freeze_static_policy",
            Self::PrepareManualReaderSpikeChecklist => "prepare_manual_reader_spike_checklist",
            Self::PrepareReaderSpikeReview => "prepare_reader_spike_review",
            Self::KeepExperimental => "keep_experimental",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of next arc plan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFindingKind {
    /// Milestone freeze finding.
    MilestoneFreeze,
    /// Review pack finding.
    ReviewPack,
    /// Release gate finding.
    ReleaseGate,
    /// Safety invariant finding.
    SafetyInvariant,
    /// Schema invariant finding.
    SchemaInvariant,
    /// CLI invariant finding.
    CliInvariant,
    /// Release invariant finding.
    ReleaseInvariant,
    /// Planning invariant finding.
    PlanningInvariant,
    /// Next arc risk finding.
    NextArcRisk,
}

impl EbpfReaderLabNextArcFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MilestoneFreeze => "milestone_freeze",
            Self::ReviewPack => "review_pack",
            Self::ReleaseGate => "release_gate",
            Self::SafetyInvariant => "safety_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::ReleaseInvariant => "release_invariant",
            Self::PlanningInvariant => "planning_invariant",
            Self::NextArcRisk => "next_arc_risk",
        }
    }
}

/// A single finding produced by the next arc plan evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderLabNextArcFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderLabNextArcPlanStatus,
}

/// Input to the reader lab next arc plan evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcPlanInput {
    /// The I-20 milestone freeze record.
    pub milestone_freeze_record: EbpfReaderLabMilestoneFreezeRecord,
    /// The I-19 review pack.
    pub review_pack: EbpfReaderSpikeReviewPack,
    /// The I-18 release gate report.
    pub release_gate_report: EbpfReaderSpikeReleaseGateReport,
    /// Whether to prefer fixture-only refinement for the next arc.
    pub prefer_fixture_only_next: bool,
    /// Whether to prefer static policy freeze for the next arc.
    pub prefer_static_policy_freeze: bool,
    /// Whether to prefer manual reader spike checklist for the next arc.
    pub prefer_manual_reader_spike_checklist: bool,
    /// Whether to prefer reader spike review for the next arc.
    pub prefer_reader_spike_review: bool,
    /// Whether a live reader is allowed in the next arc (must block).
    pub allow_live_reader_next: bool,
    /// Whether a public CLI is allowed in the next arc (must block).
    pub allow_public_cli_next: bool,
    /// Whether a release path is allowed in the next arc (must block).
    pub allow_release_path_next: bool,
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

/// Plan produced by the reader lab next arc evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcPlan {
    /// The phase this plan covers.
    pub phase: String,
    /// The plan status.
    pub status: EbpfReaderLabNextArcPlanStatus,
    /// The plan decision.
    pub decision: EbpfReaderLabNextArcDecision,
    /// Whether the plan is ready.
    pub plan_ready: bool,
    /// Whether release is allowed (always false in I-21).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-21).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderLabNextArcFinding>,
    /// Whether the milestone was frozen.
    pub milestone_frozen: bool,
    /// Whether the review pack is ready.
    pub review_pack_ready: bool,
    /// Whether the release gate is ready.
    pub release_gate_ready: bool,
    /// Whether fixture-only refinement is the chosen next arc.
    pub fixture_only_next: bool,
    /// Whether static policy freeze is the chosen next arc.
    pub static_policy_freeze_next: bool,
    /// Whether manual reader spike checklist is the chosen next arc.
    pub manual_reader_spike_checklist_next: bool,
    /// Whether reader spike review is the chosen next arc.
    pub reader_spike_review_next: bool,
    /// Whether a live reader is allowed in the next arc.
    pub live_reader_next_allowed: bool,
    /// Whether a public CLI is allowed in the next arc.
    pub public_cli_next_allowed: bool,
    /// Whether a release path is allowed in the next arc.
    pub release_path_next_allowed: bool,
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
    /// Whether fake planning success was detected.
    pub fake_planning_success_detected: bool,
}

// -- Helper functions --

fn safe_base_plan() -> EbpfReaderLabNextArcPlan {
    EbpfReaderLabNextArcPlan {
        phase: String::from("I-21"),
        status: EbpfReaderLabNextArcPlanStatus::Draft,
        decision: EbpfReaderLabNextArcDecision::Stop,
        plan_ready: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        milestone_frozen: false,
        review_pack_ready: false,
        release_gate_ready: false,
        fixture_only_next: false,
        static_policy_freeze_next: false,
        manual_reader_spike_checklist_next: false,
        reader_spike_review_next: false,
        live_reader_next_allowed: false,
        public_cli_next_allowed: false,
        release_path_next_allowed: false,
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
        fake_planning_success_detected: false,
    }
}

/// Create the default reader lab next arc plan input.
///
/// Builds safe evidence from I-20 milestone freeze, I-19 review pack, and
/// I-18 release gate. No safe next preference is selected by default, making
/// the default plan incomplete or experimental-only.
pub fn default_reader_lab_next_arc_plan_input() -> EbpfReaderLabNextArcPlanInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_milestone_freeze::build_reader_lab_milestone_freeze_record;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_milestone_freeze::default_reader_lab_milestone_freeze_input;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_review_pack::build_reader_spike_review_pack;
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_spike_review_pack::default_reader_spike_review_pack_input;
    let freeze_input = default_reader_lab_milestone_freeze_input();
    let milestone_freeze_record = build_reader_lab_milestone_freeze_record(&freeze_input);
    let pack_input = default_reader_spike_review_pack_input();
    let review_pack = build_reader_spike_review_pack(&pack_input);
    let release_gate_report = pack_input.release_gate_report;
    EbpfReaderLabNextArcPlanInput {
        milestone_freeze_record,
        review_pack,
        release_gate_report,
        prefer_fixture_only_next: false,
        prefer_static_policy_freeze: false,
        prefer_manual_reader_spike_checklist: false,
        prefer_reader_spike_review: false,
        allow_live_reader_next: false,
        allow_public_cli_next: false,
        allow_release_path_next: false,
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

/// Build the reader lab next arc plan from input.
///
/// Validates the milestone freeze record, review pack, and release gate.
/// Checks safety flags, verifies no unsafe requests or mutations, and
/// determines the next arc decision. Release is always rejected in I-21.
pub fn build_reader_lab_next_arc_plan(
    input: &EbpfReaderLabNextArcPlanInput,
) -> EbpfReaderLabNextArcPlan {
    let mut plan = safe_base_plan();
    let mut findings: Vec<EbpfReaderLabNextArcFinding> = Vec::new();
    let mut blocked = false;

    // Validate each evidence type
    let mf_valid =
        validate_reader_lab_milestone_freeze_record(&input.milestone_freeze_record).is_ok();
    let rp_valid = validate_reader_spike_review_pack(&input.review_pack).is_ok();
    let rg_valid = validate_reader_spike_release_gate_report(&input.release_gate_report).is_ok();

    plan.milestone_frozen = input.milestone_freeze_record.milestone_frozen;
    plan.review_pack_ready = input.review_pack.review_ready;
    plan.release_gate_ready = input.release_gate_report.ready_for_reader_spike_review;

    // Evidence validation checks
    if !mf_valid {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-MF-INVALID"),
            kind: EbpfReaderLabNextArcFindingKind::MilestoneFreeze,
            message: String::from("milestone freeze record validation failed"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }
    if !rp_valid {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-RP-INVALID"),
            kind: EbpfReaderLabNextArcFindingKind::ReviewPack,
            message: String::from("review pack validation failed"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }
    if !rg_valid {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-RG-INVALID"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseGate,
            message: String::from("release gate report validation failed"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }

    // Milestone frozen check
    if !input.milestone_freeze_record.milestone_frozen {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-MF-NOT-FROZEN"),
            kind: EbpfReaderLabNextArcFindingKind::MilestoneFreeze,
            message: String::from("milestone is not frozen"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }

    // Review pack ready check
    if !input.review_pack.review_ready {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-RP-NOT-READY"),
            kind: EbpfReaderLabNextArcFindingKind::ReviewPack,
            message: String::from("review pack is not ready"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }

    // Release gate ready check
    if !input.release_gate_report.ready_for_reader_spike_review {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-RG-NOT-READY"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseGate,
            message: String::from("release gate is not ready"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }

    // Unsafe next-arc flags
    if input.allow_live_reader_next {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-UNSAFE-LIVE-READER"),
            kind: EbpfReaderLabNextArcFindingKind::SafetyInvariant,
            message: String::from("live reader is not allowed in I-21"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_public_cli_next {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-UNSAFE-PUBLIC-CLI"),
            kind: EbpfReaderLabNextArcFindingKind::CliInvariant,
            message: String::from("public CLI is not allowed in I-21"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_release_path_next {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-UNSAFE-RELEASE-PATH"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("release path is not allowed in I-21"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }

    // Public CLI hidden check
    if !input.public_cli_expected_hidden {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-CLI-EXPECTED-HIDDEN"),
            kind: EbpfReaderLabNextArcFindingKind::CliInvariant,
            message: String::from("public CLI expected hidden but was not"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }

    // Schema checks
    if !input.usage_schema_expected_unchanged {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderLabNextArcFindingKind::SchemaInvariant,
            message: String::from("usage schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderLabNextArcFindingKind::SchemaInvariant,
            message: String::from("ledger schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }

    // Block release/tag/publish/version/main requests
    if input.stable_release_requested {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-RELEASE-REQUESTED"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("stable release requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.tag_requested {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-TAG-REQUESTED"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("tag requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.publish_requested {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-PUBLISH-REQUESTED"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("publish requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.version_bump_requested {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-VERSION-BUMP-REQUESTED"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("version bump requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.main_merge_requested {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-MAIN-MERGE-REQUESTED"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("main merge requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
        });
        blocked = true;
    }

    // Fake detection checks
    let has_fake_reader = input.milestone_freeze_record.fake_reader_success_detected;
    let has_fake_events = input
        .milestone_freeze_record
        .fake_live_event_counts_detected;
    let has_fake_release = input
        .milestone_freeze_record
        .fake_release_readiness_detected;
    if has_fake_reader {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-FAKE-READER"),
            kind: EbpfReaderLabNextArcFindingKind::SafetyInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }
    if has_fake_events {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-FAKE-EVENTS"),
            kind: EbpfReaderLabNextArcFindingKind::SafetyInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }
    if has_fake_release {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-FAKE-RELEASE"),
            kind: EbpfReaderLabNextArcFindingKind::ReleaseInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Blocked,
        });
        blocked = true;
    }

    // Safe next preference check: at least one must be selected
    let has_safe_pref = input.prefer_fixture_only_next
        || input.prefer_static_policy_freeze
        || input.prefer_manual_reader_spike_checklist
        || input.prefer_reader_spike_review;

    if !blocked && !has_safe_pref {
        findings.push(EbpfReaderLabNextArcFinding {
            code: String::from("PLAN-NO-SAFE-PREF"),
            kind: EbpfReaderLabNextArcFindingKind::NextArcRisk,
            message: String::from("no safe next arc preference selected"),
            blocking: true,
            status: EbpfReaderLabNextArcPlanStatus::Incomplete,
        });
        blocked = true;
    }

    // Determine status and decision
    if blocked {
        let has_release_block = input.stable_release_requested
            || input.tag_requested
            || input.publish_requested
            || input.version_bump_requested
            || input.main_merge_requested;
        if has_release_block {
            plan.status = EbpfReaderLabNextArcPlanStatus::ReleaseForbidden;
            plan.decision = EbpfReaderLabNextArcDecision::RejectRelease;
        } else {
            plan.status = EbpfReaderLabNextArcPlanStatus::Blocked;
            plan.decision = EbpfReaderLabNextArcDecision::FixMilestoneEvidence;
        }
    } else {
        // All evidence valid, milestone frozen, safe pref selected
        // Apply priority: FreezeStaticPolicy > ContinueFixtureOnly >
        // PrepareManualReaderSpikeChecklist > PrepareReaderSpikeReview
        if input.prefer_static_policy_freeze {
            plan.status = EbpfReaderLabNextArcPlanStatus::PlanReady;
            plan.decision = EbpfReaderLabNextArcDecision::FreezeStaticPolicy;
            plan.static_policy_freeze_next = true;
        } else if input.prefer_fixture_only_next {
            plan.status = EbpfReaderLabNextArcPlanStatus::PlanReady;
            plan.decision = EbpfReaderLabNextArcDecision::ContinueFixtureOnly;
            plan.fixture_only_next = true;
        } else if input.prefer_manual_reader_spike_checklist {
            plan.status = EbpfReaderLabNextArcPlanStatus::PlanReady;
            plan.decision = EbpfReaderLabNextArcDecision::PrepareManualReaderSpikeChecklist;
            plan.manual_reader_spike_checklist_next = true;
        } else {
            plan.status = EbpfReaderLabNextArcPlanStatus::PlanReady;
            plan.decision = EbpfReaderLabNextArcDecision::PrepareReaderSpikeReview;
            plan.reader_spike_review_next = true;
        }
        plan.plan_ready = true;
    }

    plan.findings = findings;
    plan
}

/// Validate that a reader lab next arc plan is safe.
pub fn validate_reader_lab_next_arc_plan(plan: &EbpfReaderLabNextArcPlan) -> Result<(), String> {
    if plan.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if plan.release_allowed {
        return Err("release_allowed must be false in I-21".to_string());
    }
    if !plan.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-21".to_string());
    }
    if plan.live_reader_next_allowed {
        return Err("live_reader_next_allowed must be false".to_string());
    }
    if plan.public_cli_next_allowed {
        return Err("public_cli_next_allowed must be false".to_string());
    }
    if plan.release_path_next_allowed {
        return Err("release_path_next_allowed must be false".to_string());
    }
    if plan.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if plan.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if plan.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    if plan.stable_release_requested {
        return Err("stable_release_requested must be false".to_string());
    }
    if plan.tag_requested {
        return Err("tag_requested must be false".to_string());
    }
    if plan.publish_requested {
        return Err("publish_requested must be false".to_string());
    }
    if plan.version_bump_requested {
        return Err("version_bump_requested must be false".to_string());
    }
    if plan.main_merge_requested {
        return Err("main_merge_requested must be false".to_string());
    }
    if plan.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if plan.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if plan.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if plan.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if plan.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if plan.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if plan.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if plan.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if plan.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if plan.fake_release_readiness_detected {
        return Err("fake_release_readiness_detected must be false".to_string());
    }
    if plan.fake_planning_success_detected {
        return Err("fake_planning_success_detected must be false".to_string());
    }
    if plan.plan_ready && plan.status == EbpfReaderLabNextArcPlanStatus::PlanRejected {
        return Err("plan_ready must be false when status is PlanRejected".to_string());
    }
    Ok(())
}

/// Map a next arc plan status to a stable human-readable label.
pub fn reader_lab_next_arc_plan_status_label(
    status: EbpfReaderLabNextArcPlanStatus,
) -> &'static str {
    status.as_str()
}

/// Map a next arc decision to a stable human-readable label.
pub fn reader_lab_next_arc_decision_label(decision: EbpfReaderLabNextArcDecision) -> &'static str {
    decision.as_str()
}

/// Map a next arc finding kind to a stable human-readable label.
pub fn reader_lab_next_arc_finding_kind_label(
    kind: EbpfReaderLabNextArcFindingKind,
) -> &'static str {
    kind.as_str()
}
