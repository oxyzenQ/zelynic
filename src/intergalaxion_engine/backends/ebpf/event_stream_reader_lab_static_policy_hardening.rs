// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab static policy hardening model for the Intergalaxion Engine.
//!
//! Phase I-24 hardens the I-21 next arc plan, I-22 static policy freeze,
//! and I-23 static policy review pack by adding deterministic invariant
//! checks and contradiction detection. This phase is
//! static-policy-hardening only — not a release, not a public feature,
//! not a live reader, not a ring buffer reader, not a kernel event consumer.
//! It is an internal deterministic hardening checkpoint only.
//!
//! # Design constraints (I-24)
//!
//! * Static-policy-hardening only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake static policy hardening success, no fake release readiness.
//! * release_allowed is always false in I-24.
//! * must_remain_experimental is always true in I-24.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
    validate_reader_lab_next_arc_plan, EbpfReaderLabNextArcPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
    validate_reader_lab_static_policy_freeze_record, EbpfReaderLabStaticPolicyFreezeRecord,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{
    validate_reader_lab_static_policy_review_pack, EbpfReaderLabStaticPolicyReviewPack,
};

/// Status of the reader lab static policy hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyHardeningStatus {
    /// Hardening is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Policy is hardened.
    Hardened,
    /// Hardening was rejected.
    HardeningRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderLabStaticPolicyHardeningStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::Hardened => "hardened",
            Self::HardeningRejected => "hardening_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab static policy hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyHardeningDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix next arc plan before proceeding.
    FixNextArcPlan,
    /// Fix static policy freeze before proceeding.
    FixStaticPolicyFreeze,
    /// Fix static policy review before proceeding.
    FixStaticPolicyReview,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Harden the policy.
    HardenPolicy,
    /// Prepare policy freeze completion.
    PreparePolicyFreeze,
    /// Reject any release.
    RejectRelease,
}

impl EbpfReaderLabStaticPolicyHardeningDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixNextArcPlan => "fix_next_arc_plan",
            Self::FixStaticPolicyFreeze => "fix_static_policy_freeze",
            Self::FixStaticPolicyReview => "fix_static_policy_review",
            Self::KeepExperimental => "keep_experimental",
            Self::HardenPolicy => "harden_policy",
            Self::PreparePolicyFreeze => "prepare_policy_freeze",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of static policy hardening finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyHardeningFindingKind {
    /// Next arc plan finding.
    NextArcPlan,
    /// Static policy freeze finding.
    StaticPolicyFreeze,
    /// Static policy review finding.
    StaticPolicyReview,
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
    /// Contradiction invariant finding.
    ContradictionInvariant,
    /// Hardening invariant finding.
    HardeningInvariant,
}

impl EbpfReaderLabStaticPolicyHardeningFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::StaticPolicyReview => "static_policy_review",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::ContradictionInvariant => "contradiction_invariant",
            Self::HardeningInvariant => "hardening_invariant",
        }
    }
}

/// A single finding produced by the static policy hardening evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyHardeningFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderLabStaticPolicyHardeningFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderLabStaticPolicyHardeningStatus,
}

/// Input to the reader lab static policy hardening evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyHardeningInput {
    /// The I-21 next arc plan.
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    /// The I-22 static policy freeze record.
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    /// The I-23 static policy review pack.
    pub static_policy_review_pack: EbpfReaderLabStaticPolicyReviewPack,
    /// Whether the next arc plan must be ready.
    pub require_next_arc_plan_ready: bool,
    /// Whether the static policy must be frozen.
    pub require_static_policy_frozen: bool,
    /// Whether the static policy review must be ready.
    pub require_static_policy_review_ready: bool,
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

/// Hardening report produced by the reader lab static policy hardening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyHardeningReport {
    /// The phase this report covers.
    pub phase: String,
    /// The hardening status.
    pub status: EbpfReaderLabStaticPolicyHardeningStatus,
    /// The hardening decision.
    pub decision: EbpfReaderLabStaticPolicyHardeningDecision,
    /// Whether hardening passed.
    pub hardening_passed: bool,
    /// Whether release is allowed (always false in I-24).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-24).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderLabStaticPolicyHardeningFinding>,
    /// Whether the next arc plan is ready.
    pub next_arc_plan_ready: bool,
    /// Whether the static policy is frozen.
    pub static_policy_frozen: bool,
    /// Whether the static policy review is ready.
    pub static_policy_review_ready: bool,
    /// Whether experimental-only mode is confirmed.
    pub experimental_only_confirmed: bool,
    /// Whether a contradiction was detected.
    pub contradiction_detected: bool,
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
    /// Whether fake policy review success was detected.
    pub fake_policy_review_success_detected: bool,
    /// Whether fake hardening success was detected.
    pub fake_hardening_success_detected: bool,
}

// -- Helper functions --

fn safe_base_report() -> EbpfReaderLabStaticPolicyHardeningReport {
    EbpfReaderLabStaticPolicyHardeningReport {
        phase: String::from("I-24"),
        status: EbpfReaderLabStaticPolicyHardeningStatus::Draft,
        decision: EbpfReaderLabStaticPolicyHardeningDecision::Stop,
        hardening_passed: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        next_arc_plan_ready: false,
        static_policy_frozen: false,
        static_policy_review_ready: false,
        experimental_only_confirmed: false,
        contradiction_detected: false,
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
        fake_policy_review_success_detected: false,
        fake_hardening_success_detected: false,
    }
}

/// Create the default reader lab static policy hardening input.
///
/// Builds safe evidence from I-21, I-22, and I-23 defaults. No unsafe
/// requests are included. The default input is safe but incomplete or
/// experimental-only.
pub fn default_reader_lab_static_policy_hardening_input() -> EbpfReaderLabStaticPolicyHardeningInput
{
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
        build_reader_lab_static_policy_freeze_record, default_reader_lab_static_policy_freeze_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{
        build_reader_lab_static_policy_review_pack,
        default_reader_lab_static_policy_review_pack_input,
    };
    let next_arc_plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    let freeze_input = default_reader_lab_static_policy_freeze_input();
    let static_policy_freeze_record = build_reader_lab_static_policy_freeze_record(&freeze_input);
    let static_policy_review_pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    EbpfReaderLabStaticPolicyHardeningInput {
        next_arc_plan,
        static_policy_freeze_record,
        static_policy_review_pack,
        require_next_arc_plan_ready: false,
        require_static_policy_frozen: false,
        require_static_policy_review_ready: false,
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

/// Build the reader lab static policy hardening report from input.
///
/// Validates all three evidence types, checks safety flags, detects
/// contradictions between evidence states, verifies no unsafe requests
/// or mutations, and determines the overall hardening status, decision,
/// and findings. Release is always rejected in I-24.
pub fn build_reader_lab_static_policy_hardening_report(
    input: &EbpfReaderLabStaticPolicyHardeningInput,
) -> EbpfReaderLabStaticPolicyHardeningReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfReaderLabStaticPolicyHardeningFinding> = Vec::new();
    let mut blocked = false;
    let mut has_contradiction = false;

    // Validate each evidence type
    let plan_valid = validate_reader_lab_next_arc_plan(&input.next_arc_plan).is_ok();
    let freeze_valid =
        validate_reader_lab_static_policy_freeze_record(&input.static_policy_freeze_record).is_ok();
    let review_valid =
        validate_reader_lab_static_policy_review_pack(&input.static_policy_review_pack).is_ok();

    report.next_arc_plan_ready = plan_valid;
    report.static_policy_frozen = input.static_policy_freeze_record.policy_frozen;
    report.static_policy_review_ready = input.static_policy_review_pack.review_ready;

    if !plan_valid {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-PLAN-INVALID"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::NextArcPlan,
            message: String::from("next arc plan validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }
    if !freeze_valid {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FREEZE-INVALID"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyFreeze,
            message: String::from("static policy freeze record validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }
    if !review_valid {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-REVIEW-INVALID"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyReview,
            message: String::from("static policy review pack validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }

    // Require ready/frozen when configured
    if input.require_next_arc_plan_ready && !input.next_arc_plan.plan_ready {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-PLAN-NOT-READY"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::NextArcPlan,
            message: String::from("next arc plan is not ready"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }
    if input.require_static_policy_frozen && !input.static_policy_freeze_record.policy_frozen {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FREEZE-NOT-FROZEN"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyFreeze,
            message: String::from("static policy is not frozen"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }
    if input.require_static_policy_review_ready && !input.static_policy_review_pack.review_ready {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-REVIEW-NOT-READY"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::StaticPolicyReview,
            message: String::from("static policy review is not ready"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Incomplete,
        });
        blocked = true;
    }

    // Experimental-only check
    if input.require_experimental_only {
        report.experimental_only_confirmed = true;
        let exp = [
            input.next_arc_plan.must_remain_experimental,
            input.static_policy_freeze_record.must_remain_experimental,
            input.static_policy_review_pack.must_remain_experimental,
        ];
        if !exp.iter().all(|&v| v) {
            findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
                code: String::from("SPH-NOT-EXPERIMENTAL"),
                kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
                message: String::from("evidence disagrees on must_remain_experimental"),
                blocking: true,
                status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
            });
            blocked = true;
            has_contradiction = true;
        }
    }

    // Contradiction: release_allowed
    let ra = [
        input.next_arc_plan.release_allowed,
        input.static_policy_freeze_record.release_allowed,
        input.static_policy_review_pack.release_allowed,
    ];
    if ra.iter().any(|&v| v) {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-CONTRADICTION-RELEASE"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
            message: String::from("evidence disagrees on release_allowed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: next allowances
    let lr = [
        input.next_arc_plan.live_reader_next_allowed,
        input.static_policy_freeze_record.live_reader_next_allowed,
        input.static_policy_review_pack.live_reader_next_allowed,
    ];
    if lr.iter().any(|&v| v) {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-CONTRADICTION-LIVE-READER"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
            message: String::from("evidence disagrees on live_reader_next_allowed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
        has_contradiction = true;
    }
    let pc = [
        input.next_arc_plan.public_cli_next_allowed,
        input.static_policy_freeze_record.public_cli_next_allowed,
        input.static_policy_review_pack.public_cli_next_allowed,
    ];
    if pc.iter().any(|&v| v) {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-CONTRADICTION-PUBLIC-CLI"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
            message: String::from("evidence disagrees on public_cli_next_allowed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
        has_contradiction = true;
    }
    let rp = [
        input.next_arc_plan.release_path_next_allowed,
        input.static_policy_freeze_record.release_path_next_allowed,
        input.static_policy_review_pack.release_path_next_allowed,
    ];
    if rp.iter().any(|&v| v) {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-CONTRADICTION-RELEASE-PATH"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ContradictionInvariant,
            message: String::from("evidence disagrees on release_path_next_allowed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
        has_contradiction = true;
    }

    report.contradiction_detected = has_contradiction;

    // CLI and schema checks
    if !input.public_cli_expected_hidden {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-CLI-NOT-HIDDEN"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::CliInvariant,
            message: String::from("public CLI expected hidden but was not"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if !input.usage_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::SchemaInvariant,
            message: String::from("usage schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::SchemaInvariant,
            message: String::from("ledger schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }

    // Block release/tag/publish/version/main requests
    if input.stable_release_requested {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-RELEASE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            message: String::from("stable release requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.tag_requested {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-TAG-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            message: String::from("tag requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.publish_requested {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-PUBLISH-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            message: String::from("publish requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.version_bump_requested {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-VERSION-BUMP-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            message: String::from("version bump requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.main_merge_requested {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-MAIN-MERGE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::ReleaseInvariant,
            message: String::from("main merge requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden,
        });
        blocked = true;
    }

    // Fake evidence detection from all evidence types
    if input.next_arc_plan.fake_reader_success_detected
        || input
            .static_policy_freeze_record
            .fake_reader_success_detected
        || input.static_policy_review_pack.fake_reader_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-READER"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_live_event_counts_detected
        || input
            .static_policy_freeze_record
            .fake_live_event_counts_detected
        || input
            .static_policy_review_pack
            .fake_live_event_counts_detected
    {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-EVENTS"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_release_readiness_detected
        || input
            .static_policy_freeze_record
            .fake_release_readiness_detected
        || input
            .static_policy_review_pack
            .fake_release_readiness_detected
    {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-RELEASE"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_planning_success_detected
        || input
            .static_policy_freeze_record
            .fake_planning_success_detected
        || input
            .static_policy_review_pack
            .fake_planning_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-PLANNING"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake planning success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_policy_freeze_success_detected
        || input
            .static_policy_review_pack
            .fake_policy_freeze_success_detected
    {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-POLICY-FREEZE"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake static policy freeze success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }
    if input.static_policy_review_pack.fake_review_success_detected {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-FAKE-REVIEW"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::FakeEvidenceInvariant,
            message: String::from("fake static policy review success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::Blocked,
        });
        blocked = true;
    }

    // Require experimental-only confirmation
    if !input.require_experimental_only {
        findings.push(EbpfReaderLabStaticPolicyHardeningFinding {
            code: String::from("SPH-NO-EXPERIMENTAL-CONFIRM"),
            kind: EbpfReaderLabStaticPolicyHardeningFindingKind::HardeningInvariant,
            message: String::from("experimental-only confirmation not provided"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyHardeningStatus::ExperimentalOnly,
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
        let has_review_block = !review_valid;
        if has_release_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::ReleaseForbidden;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::RejectRelease;
        } else if has_experimental_only_block
            && has_plan_block
            && has_freeze_block
            && has_review_block
        {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Incomplete;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixNextArcPlan;
        } else if has_experimental_only_block && has_review_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Incomplete;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyReview;
        } else if has_experimental_only_block && has_freeze_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Incomplete;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyFreeze;
        } else if has_experimental_only_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::ExperimentalOnly;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::KeepExperimental;
        } else if has_contradiction {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Blocked;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::RejectRelease;
        } else if has_plan_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Blocked;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixNextArcPlan;
        } else if has_freeze_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Blocked;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyFreeze;
        } else if has_review_block {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::Blocked;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::FixStaticPolicyReview;
        } else {
            report.status = EbpfReaderLabStaticPolicyHardeningStatus::HardeningRejected;
            report.decision = EbpfReaderLabStaticPolicyHardeningDecision::RejectRelease;
        }
    } else {
        report.status = EbpfReaderLabStaticPolicyHardeningStatus::Hardened;
        report.decision = EbpfReaderLabStaticPolicyHardeningDecision::HardenPolicy;
        report.hardening_passed = true;
    }

    report.findings = findings;
    report
}

/// Validate that a reader lab static policy hardening report is safe.
pub fn validate_reader_lab_static_policy_hardening_report(
    report: &EbpfReaderLabStaticPolicyHardeningReport,
) -> Result<(), String> {
    if report.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if report.release_allowed {
        return Err("release_allowed must be false in I-24".to_string());
    }
    if !report.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-24".to_string());
    }
    if report.live_reader_next_allowed {
        return Err("live_reader_next_allowed must be false".to_string());
    }
    if report.public_cli_next_allowed {
        return Err("public_cli_next_allowed must be false".to_string());
    }
    if report.release_path_next_allowed {
        return Err("release_path_next_allowed must be false".to_string());
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
    if report.fake_release_readiness_detected {
        return Err("fake_release_readiness_detected must be false".to_string());
    }
    if report.fake_planning_success_detected {
        return Err("fake_planning_success_detected must be false".to_string());
    }
    if report.fake_policy_freeze_success_detected {
        return Err("fake_policy_freeze_success_detected must be false".to_string());
    }
    if report.fake_policy_review_success_detected {
        return Err("fake_policy_review_success_detected must be false".to_string());
    }
    if report.fake_hardening_success_detected {
        return Err("fake_hardening_success_detected must be false".to_string());
    }
    if report.contradiction_detected {
        return Err("contradiction_detected must be false".to_string());
    }
    if report.hardening_passed
        && report.status == EbpfReaderLabStaticPolicyHardeningStatus::HardeningRejected
    {
        return Err("hardening_passed must be false when status is HardeningRejected".to_string());
    }
    Ok(())
}

/// Map a static policy hardening status to a stable human-readable label.
pub fn reader_lab_static_policy_hardening_status_label(
    status: EbpfReaderLabStaticPolicyHardeningStatus,
) -> &'static str {
    status.as_str()
}

/// Map a static policy hardening decision to a stable human-readable label.
pub fn reader_lab_static_policy_hardening_decision_label(
    decision: EbpfReaderLabStaticPolicyHardeningDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a static policy hardening finding kind to a stable human-readable label.
pub fn reader_lab_static_policy_hardening_finding_kind_label(
    kind: EbpfReaderLabStaticPolicyHardeningFindingKind,
) -> &'static str {
    kind.as_str()
}
