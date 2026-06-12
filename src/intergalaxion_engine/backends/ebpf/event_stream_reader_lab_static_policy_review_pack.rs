// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab static policy review pack model for the Intergalaxion Engine.
//!
//! Phase I-23 reviews and bundles the I-21 next arc planning record and the
//! I-22 static policy freeze record into an internal review pack. This phase
//! is static-policy-review-pack only — not a release, not a public feature,
//! not a live reader, not a ring buffer reader, not a kernel event consumer.
//! It is an internal deterministic review checkpoint only.
//!
//! # Design constraints (I-23)
//!
//! * Static-policy-review-pack only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake static policy review success, no fake release readiness.
//! * release_allowed is always false in I-23.
//! * must_remain_experimental is always true in I-23.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
    validate_reader_lab_next_arc_plan, EbpfReaderLabNextArcPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
    validate_reader_lab_static_policy_freeze_record, EbpfReaderLabStaticPolicyFreezeRecord,
};

/// Status of the reader lab static policy review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyReviewPackStatus {
    /// Review pack is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Review is ready.
    ReviewReady,
    /// Review was rejected.
    ReviewRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderLabStaticPolicyReviewPackStatus {
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

/// Decision produced by the reader lab static policy review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyReviewDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix next arc plan before proceeding.
    FixNextArcPlan,
    /// Fix static policy freeze before proceeding.
    FixStaticPolicyFreeze,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Prepare for hardening.
    PrepareHardening,
    /// Prepare next arc review.
    PrepareNextArcReview,
    /// Reject any release.
    RejectRelease,
}

impl EbpfReaderLabStaticPolicyReviewDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixNextArcPlan => "fix_next_arc_plan",
            Self::FixStaticPolicyFreeze => "fix_static_policy_freeze",
            Self::KeepExperimental => "keep_experimental",
            Self::PrepareHardening => "prepare_hardening",
            Self::PrepareNextArcReview => "prepare_next_arc_review",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of static policy review finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyReviewFindingKind {
    /// Next arc plan finding.
    NextArcPlan,
    /// Static policy freeze finding.
    StaticPolicyFreeze,
    /// Release invariant finding.
    ReleaseInvariant,
    /// CLI invariant finding.
    CliInvariant,
    /// Schema invariant finding.
    SchemaInvariant,
    /// Runtime invariant finding.
    RuntimeInvariant,
    /// Kernel invariant finding.
    KernelInvariant,
    /// Mutation invariant finding.
    MutationInvariant,
    /// Fake evidence invariant finding.
    FakeEvidenceInvariant,
    /// Review invariant finding.
    ReviewInvariant,
}

impl EbpfReaderLabStaticPolicyReviewFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::ReviewInvariant => "review_invariant",
        }
    }
}

/// A single finding produced by the static policy review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyReviewFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderLabStaticPolicyReviewFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderLabStaticPolicyReviewPackStatus,
}

/// Input to the reader lab static policy review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyReviewPackInput {
    /// The I-21 next arc plan.
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    /// The I-22 static policy freeze record.
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    /// Whether the next arc plan must be ready.
    pub require_next_arc_plan_ready: bool,
    /// Whether the static policy must be frozen.
    pub require_static_policy_frozen: bool,
    /// Whether experimental-only mode is required.
    pub require_experimental_only: bool,
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

/// Review pack produced by the reader lab static policy review evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyReviewPack {
    /// The phase this review pack covers.
    pub phase: String,
    /// The review pack status.
    pub status: EbpfReaderLabStaticPolicyReviewPackStatus,
    /// The review pack decision.
    pub decision: EbpfReaderLabStaticPolicyReviewDecision,
    /// Whether the review is ready.
    pub review_ready: bool,
    /// Whether release is allowed (always false in I-23).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-23).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderLabStaticPolicyReviewFinding>,
    /// Whether the next arc plan is ready.
    pub next_arc_plan_ready: bool,
    /// Whether the static policy is frozen.
    pub static_policy_frozen: bool,
    /// Whether experimental-only mode is confirmed.
    pub experimental_only_confirmed: bool,
    /// Whether a live reader is allowed in the future.
    pub live_reader_next_allowed: bool,
    /// Whether a public CLI is allowed in the future.
    pub public_cli_next_allowed: bool,
    /// Whether a release path is allowed in the future.
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
    /// Whether fake policy freeze success was detected.
    pub fake_policy_freeze_success_detected: bool,
    /// Whether fake review success was detected.
    pub fake_review_success_detected: bool,
}

// -- Helper functions --

fn safe_base_pack() -> EbpfReaderLabStaticPolicyReviewPack {
    EbpfReaderLabStaticPolicyReviewPack {
        phase: String::from("I-23"),
        status: EbpfReaderLabStaticPolicyReviewPackStatus::Draft,
        decision: EbpfReaderLabStaticPolicyReviewDecision::Stop,
        review_ready: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        next_arc_plan_ready: false,
        static_policy_frozen: false,
        experimental_only_confirmed: false,
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
        fake_policy_freeze_success_detected: false,
        fake_review_success_detected: false,
    }
}

/// Create the default reader lab static policy review pack input.
///
/// Builds safe evidence from I-21 next arc plan and I-22 static policy
/// freeze defaults. No unsafe requests are included. The default input is
/// safe but incomplete or experimental-only.
pub fn default_reader_lab_static_policy_review_pack_input(
) -> EbpfReaderLabStaticPolicyReviewPackInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
        build_reader_lab_static_policy_freeze_record, default_reader_lab_static_policy_freeze_input,
    };
    let next_arc_plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    let freeze_input = default_reader_lab_static_policy_freeze_input();
    let static_policy_freeze_record = build_reader_lab_static_policy_freeze_record(&freeze_input);
    EbpfReaderLabStaticPolicyReviewPackInput {
        next_arc_plan,
        static_policy_freeze_record,
        require_next_arc_plan_ready: false,
        require_static_policy_frozen: false,
        require_experimental_only: false,
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

/// Build the reader lab static policy review pack from input.
///
/// Validates the next arc plan and static policy freeze record, checks
/// safety flags, verifies no unsafe requests or mutations, and determines
/// the overall review pack status, decision, and findings. Release is
/// always rejected in I-23.
pub fn build_reader_lab_static_policy_review_pack(
    input: &EbpfReaderLabStaticPolicyReviewPackInput,
) -> EbpfReaderLabStaticPolicyReviewPack {
    let mut pack = safe_base_pack();
    let mut findings: Vec<EbpfReaderLabStaticPolicyReviewFinding> = Vec::new();
    let mut blocked = false;

    // Validate each evidence type
    let plan_valid = validate_reader_lab_next_arc_plan(&input.next_arc_plan).is_ok();
    let freeze_valid =
        validate_reader_lab_static_policy_freeze_record(&input.static_policy_freeze_record).is_ok();

    pack.next_arc_plan_ready = plan_valid;
    pack.static_policy_frozen = input.static_policy_freeze_record.policy_frozen;

    if !plan_valid {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-PLAN-INVALID"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::NextArcPlan,
            message: String::from("next arc plan validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete,
        });
        blocked = true;
    }
    if !freeze_valid {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-INVALID"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::StaticPolicyFreeze,
            message: String::from("static policy freeze record validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete,
        });
        blocked = true;
    }

    // Require plan ready when configured
    if input.require_next_arc_plan_ready && !input.next_arc_plan.plan_ready {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-PLAN-NOT-READY"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::NextArcPlan,
            message: String::from("next arc plan is not ready"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete,
        });
        blocked = true;
    }

    // Require static policy frozen when configured
    if input.require_static_policy_frozen && !input.static_policy_freeze_record.policy_frozen {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-NOT-FROZEN"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::StaticPolicyFreeze,
            message: String::from("static policy is not frozen"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete,
        });
        blocked = true;
    }

    // Experimental-only check
    if input.require_experimental_only {
        pack.experimental_only_confirmed = true;
        if !input.next_arc_plan.must_remain_experimental {
            findings.push(EbpfReaderLabStaticPolicyReviewFinding {
                code: String::from("RPP-PLAN-NOT-EXPERIMENTAL"),
                kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReviewInvariant,
                message: String::from("next arc plan must remain experimental"),
                blocking: true,
                status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
            });
            blocked = true;
        }
        if !input.static_policy_freeze_record.must_remain_experimental {
            findings.push(EbpfReaderLabStaticPolicyReviewFinding {
                code: String::from("RPP-FREEZE-NOT-EXPERIMENTAL"),
                kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReviewInvariant,
                message: String::from("static policy freeze must remain experimental"),
                blocking: true,
                status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
            });
            blocked = true;
        }
    }

    // Reject release_allowed from evidence
    if input.next_arc_plan.release_allowed {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-PLAN-RELEASE-ALLOWED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("next arc plan incorrectly allows release"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.static_policy_freeze_record.release_allowed {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-RELEASE-ALLOWED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("static policy freeze incorrectly allows release"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // Live reader / public CLI / release path disallowed
    if input.next_arc_plan.live_reader_next_allowed {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-LIVE-READER-ALLOWED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::RuntimeInvariant,
            message: String::from("live reader next is not allowed in I-23"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.public_cli_next_allowed {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-PUBLIC-CLI-ALLOWED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::CliInvariant,
            message: String::from("public CLI next is not allowed in I-23"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.release_path_next_allowed {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-RELEASE-PATH-ALLOWED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("release path next is not allowed in I-23"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // CLI and schema checks
    if !input.public_cli_expected_hidden {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-CLI-NOT-HIDDEN"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::CliInvariant,
            message: String::from("public CLI expected hidden but was not"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if !input.usage_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::SchemaInvariant,
            message: String::from("usage schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::SchemaInvariant,
            message: String::from("ledger schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // Block release/tag/publish/version/main requests
    if input.stable_release_requested {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-RELEASE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("stable release requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.tag_requested {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-TAG-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("tag requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.publish_requested {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-PUBLISH-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("publish requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.version_bump_requested {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-VERSION-BUMP-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("version bump requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.main_merge_requested {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-MAIN-MERGE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReleaseInvariant,
            message: String::from("main merge requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden,
        });
        blocked = true;
    }

    // Fake evidence detection from next arc plan
    if input.next_arc_plan.fake_reader_success_detected {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FAKE-READER"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_live_event_counts_detected {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FAKE-EVENTS"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_release_readiness_detected {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FAKE-RELEASE"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_planning_success_detected {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FAKE-PLANNING"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake planning success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // Fake evidence detection from static policy freeze record
    if input
        .static_policy_freeze_record
        .fake_reader_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-FAKE-READER"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake reader success detected in freeze record"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_live_event_counts_detected
    {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-FAKE-EVENTS"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake live event counts detected in freeze record"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_release_readiness_detected
    {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-FAKE-RELEASE"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake release readiness detected in freeze record"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_planning_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FREEZE-FAKE-PLANNING"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake planning success detected in freeze record"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_policy_freeze_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-FAKE-POLICY-FREEZE"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::FakeEvidenceInvariant,
            message: String::from("fake static policy freeze success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::Blocked,
        });
        blocked = true;
    }

    // Require experimental-only confirmation
    if !input.require_experimental_only {
        findings.push(EbpfReaderLabStaticPolicyReviewFinding {
            code: String::from("RPP-NO-EXPERIMENTAL-CONFIRM"),
            kind: EbpfReaderLabStaticPolicyReviewFindingKind::ReviewInvariant,
            message: String::from("experimental-only confirmation not provided"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyReviewPackStatus::ExperimentalOnly,
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
        let has_experimental_only_block = !input.require_experimental_only;
        let has_plan_block = !plan_valid;
        let has_freeze_block = !freeze_valid;
        if has_release_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::ReleaseForbidden;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::RejectRelease;
        } else if has_experimental_only_block && has_plan_block && has_freeze_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::FixNextArcPlan;
        } else if has_experimental_only_block && has_freeze_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::FixStaticPolicyFreeze;
        } else if has_experimental_only_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::ExperimentalOnly;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::KeepExperimental;
        } else if has_plan_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::FixNextArcPlan;
        } else if has_freeze_block {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::FixStaticPolicyFreeze;
        } else {
            pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::ReviewRejected;
            pack.decision = EbpfReaderLabStaticPolicyReviewDecision::RejectRelease;
        }
    } else {
        pack.status = EbpfReaderLabStaticPolicyReviewPackStatus::ReviewReady;
        pack.decision = EbpfReaderLabStaticPolicyReviewDecision::PrepareHardening;
        pack.review_ready = true;
    }

    pack.findings = findings;
    pack
}

/// Validate that a reader lab static policy review pack is safe.
pub fn validate_reader_lab_static_policy_review_pack(
    pack: &EbpfReaderLabStaticPolicyReviewPack,
) -> Result<(), String> {
    if pack.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if pack.release_allowed {
        return Err("release_allowed must be false in I-23".to_string());
    }
    if !pack.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-23".to_string());
    }
    if pack.live_reader_next_allowed {
        return Err("live_reader_next_allowed must be false".to_string());
    }
    if pack.public_cli_next_allowed {
        return Err("public_cli_next_allowed must be false".to_string());
    }
    if pack.release_path_next_allowed {
        return Err("release_path_next_allowed must be false".to_string());
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
    if pack.stable_release_requested {
        return Err("stable_release_requested must be false".to_string());
    }
    if pack.tag_requested {
        return Err("tag_requested must be false".to_string());
    }
    if pack.publish_requested {
        return Err("publish_requested must be false".to_string());
    }
    if pack.version_bump_requested {
        return Err("version_bump_requested must be false".to_string());
    }
    if pack.main_merge_requested {
        return Err("main_merge_requested must be false".to_string());
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
    if pack.fake_planning_success_detected {
        return Err("fake_planning_success_detected must be false".to_string());
    }
    if pack.fake_policy_freeze_success_detected {
        return Err("fake_policy_freeze_success_detected must be false".to_string());
    }
    if pack.fake_review_success_detected {
        return Err("fake_review_success_detected must be false".to_string());
    }
    if pack.review_ready && pack.status == EbpfReaderLabStaticPolicyReviewPackStatus::ReviewRejected
    {
        return Err("review_ready must be false when status is ReviewRejected".to_string());
    }
    Ok(())
}

/// Map a static policy review pack status to a stable human-readable label.
pub fn reader_lab_static_policy_review_pack_status_label(
    status: EbpfReaderLabStaticPolicyReviewPackStatus,
) -> &'static str {
    status.as_str()
}

/// Map a static policy review decision to a stable human-readable label.
pub fn reader_lab_static_policy_review_decision_label(
    decision: EbpfReaderLabStaticPolicyReviewDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a static policy review finding kind to a stable human-readable label.
pub fn reader_lab_static_policy_review_finding_kind_label(
    kind: EbpfReaderLabStaticPolicyReviewFindingKind,
) -> &'static str {
    kind.as_str()
}
