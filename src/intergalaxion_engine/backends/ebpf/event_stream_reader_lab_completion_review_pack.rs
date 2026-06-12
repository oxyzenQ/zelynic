// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab completion review pack model for the Intergalaxion Engine.
//!
//! Phase I-26 produces a completion review pack that summarizes whether the
//! policy arc is complete, still experimental-only, release-forbidden, and
//! safe for future next-arc planning. It consumes I-21 next arc plan,
//! I-22 static policy freeze, I-23 static policy review pack, I-24 static
//! policy hardening report, and I-25 policy freeze completion gate report.
//! This phase is completion-review-pack only — not a release, not a public
//! feature, not a live reader, not a ring buffer reader, not a kernel event
//! consumer. It is an internal deterministic review checkpoint only.
//!
//! # Design constraints (I-26)
//!
//! * Completion-review-pack only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake completion review success, no fake release readiness.
//! * release_allowed is always false in I-26.
//! * must_remain_experimental is always true in I-26.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
    validate_reader_lab_next_arc_plan, EbpfReaderLabNextArcPlan,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::{
    validate_reader_lab_policy_completion_gate_report, EbpfReaderLabPolicyCompletionGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
    validate_reader_lab_static_policy_freeze_record, EbpfReaderLabStaticPolicyFreezeRecord,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{
    validate_reader_lab_static_policy_hardening_report, EbpfReaderLabStaticPolicyHardeningReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{
    validate_reader_lab_static_policy_review_pack, EbpfReaderLabStaticPolicyReviewPack,
};

/// Status of the reader lab completion review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabCompletionReviewPackStatus {
    Draft,
    Incomplete,
    Blocked,
    ReviewReady,
    ReviewRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}

impl EbpfReaderLabCompletionReviewPackStatus {
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

/// Decision produced by the reader lab completion review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabCompletionReviewDecision {
    Stop,
    FixNextArcPlan,
    FixStaticPolicyFreeze,
    FixStaticPolicyReview,
    FixStaticPolicyHardening,
    FixCompletionGate,
    KeepExperimental,
    PrepareNextArc,
    RejectRelease,
}

impl EbpfReaderLabCompletionReviewDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixNextArcPlan => "fix_next_arc_plan",
            Self::FixStaticPolicyFreeze => "fix_static_policy_freeze",
            Self::FixStaticPolicyReview => "fix_static_policy_review",
            Self::FixStaticPolicyHardening => "fix_static_policy_hardening",
            Self::FixCompletionGate => "fix_completion_gate",
            Self::KeepExperimental => "keep_experimental",
            Self::PrepareNextArc => "prepare_next_arc",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of completion review pack finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabCompletionReviewFindingKind {
    NextArcPlan,
    StaticPolicyFreeze,
    StaticPolicyReview,
    StaticPolicyHardening,
    PolicyCompletionGate,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    ContradictionInvariant,
    CompletionReviewInvariant,
}

impl EbpfReaderLabCompletionReviewFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::StaticPolicyReview => "static_policy_review",
            Self::StaticPolicyHardening => "static_policy_hardening",
            Self::PolicyCompletionGate => "policy_completion_gate",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::ContradictionInvariant => "contradiction_invariant",
            Self::CompletionReviewInvariant => "completion_review_invariant",
        }
    }
}

/// A single finding produced by the completion review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabCompletionReviewFinding {
    pub code: String,
    pub kind: EbpfReaderLabCompletionReviewFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabCompletionReviewPackStatus,
}

/// Input to the reader lab completion review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabCompletionReviewPackInput {
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    pub static_policy_review_pack: EbpfReaderLabStaticPolicyReviewPack,
    pub static_policy_hardening_report: EbpfReaderLabStaticPolicyHardeningReport,
    pub policy_completion_gate_report: EbpfReaderLabPolicyCompletionGateReport,
    pub require_next_arc_plan_ready: bool,
    pub require_static_policy_frozen: bool,
    pub require_static_policy_review_ready: bool,
    pub require_static_policy_hardening_passed: bool,
    pub require_policy_completion_passed: bool,
    pub require_experimental_only: bool,
    pub public_cli_expected_hidden: bool,
    pub usage_schema_expected_unchanged: bool,
    pub ledger_schema_expected_unchanged: bool,
    pub stable_release_requested: bool,
    pub tag_requested: bool,
    pub publish_requested: bool,
    pub version_bump_requested: bool,
    pub main_merge_requested: bool,
}

/// Completion review pack produced by the reader lab completion review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabCompletionReviewPack {
    pub phase: String,
    pub status: EbpfReaderLabCompletionReviewPackStatus,
    pub decision: EbpfReaderLabCompletionReviewDecision,
    pub review_ready: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabCompletionReviewFinding>,
    pub next_arc_plan_ready: bool,
    pub static_policy_frozen: bool,
    pub static_policy_review_ready: bool,
    pub static_policy_hardening_passed: bool,
    pub policy_completion_passed: bool,
    pub experimental_only_confirmed: bool,
    pub contradiction_detected: bool,
    pub live_reader_next_allowed: bool,
    pub public_cli_next_allowed: bool,
    pub release_path_next_allowed: bool,
    pub public_cli_exposed: bool,
    pub usage_schema_changed: bool,
    pub ledger_schema_changed: bool,
    pub stable_release_requested: bool,
    pub tag_requested: bool,
    pub publish_requested: bool,
    pub version_bump_requested: bool,
    pub main_merge_requested: bool,
    pub ring_buffer_opened: bool,
    pub live_event_stream_read: bool,
    pub map_pin_performed: bool,
    pub enforcement_performed: bool,
    pub packet_drop_performed: bool,
    pub mutation_performed: bool,
    pub persistence_performed: bool,
    pub fake_reader_success_detected: bool,
    pub fake_live_event_counts_detected: bool,
    pub fake_release_readiness_detected: bool,
    pub fake_planning_success_detected: bool,
    pub fake_policy_freeze_success_detected: bool,
    pub fake_policy_review_success_detected: bool,
    pub fake_policy_hardening_success_detected: bool,
    pub fake_policy_completion_success_detected: bool,
    pub fake_completion_review_success_detected: bool,
}

// -- Helper: push a blocking finding --
#[inline]
fn push_finding(
    findings: &mut Vec<EbpfReaderLabCompletionReviewFinding>,
    code: &str,
    kind: EbpfReaderLabCompletionReviewFindingKind,
    message: &str,
    status: EbpfReaderLabCompletionReviewPackStatus,
) {
    findings.push(EbpfReaderLabCompletionReviewFinding {
        code: String::from(code),
        kind,
        message: String::from(message),
        blocking: true,
        status,
    });
}

fn safe_base_pack() -> EbpfReaderLabCompletionReviewPack {
    EbpfReaderLabCompletionReviewPack {
        phase: String::from("I-26"),
        status: EbpfReaderLabCompletionReviewPackStatus::Draft,
        decision: EbpfReaderLabCompletionReviewDecision::Stop,
        review_ready: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        next_arc_plan_ready: false,
        static_policy_frozen: false,
        static_policy_review_ready: false,
        static_policy_hardening_passed: false,
        policy_completion_passed: false,
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
        fake_policy_hardening_success_detected: false,
        fake_policy_completion_success_detected: false,
        fake_completion_review_success_detected: false,
    }
}

/// Create the default reader lab completion review pack input.
///
/// Builds safe evidence from I-21, I-22, I-23, I-24, and I-25 defaults.
/// No unsafe requests are included. The default input is safe but
/// incomplete or experimental-only.
pub fn default_reader_lab_completion_review_pack_input() -> EbpfReaderLabCompletionReviewPackInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::{
        build_reader_lab_policy_completion_gate_report,
        default_reader_lab_policy_completion_gate_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{
        build_reader_lab_static_policy_freeze_record, default_reader_lab_static_policy_freeze_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{
        build_reader_lab_static_policy_hardening_report,
        default_reader_lab_static_policy_hardening_input,
    };
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{
        build_reader_lab_static_policy_review_pack,
        default_reader_lab_static_policy_review_pack_input,
    };
    let next_arc_plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    let static_policy_freeze_record = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    let static_policy_review_pack = build_reader_lab_static_policy_review_pack(
        &default_reader_lab_static_policy_review_pack_input(),
    );
    let static_policy_hardening_report = build_reader_lab_static_policy_hardening_report(
        &default_reader_lab_static_policy_hardening_input(),
    );
    let policy_completion_gate_report = build_reader_lab_policy_completion_gate_report(
        &default_reader_lab_policy_completion_gate_input(),
    );
    EbpfReaderLabCompletionReviewPackInput {
        next_arc_plan,
        static_policy_freeze_record,
        static_policy_review_pack,
        static_policy_hardening_report,
        policy_completion_gate_report,
        require_next_arc_plan_ready: false,
        require_static_policy_frozen: false,
        require_static_policy_review_ready: false,
        require_static_policy_hardening_passed: false,
        require_policy_completion_passed: false,
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

/// Build the reader lab completion review pack from input.
///
/// Validates all five evidence types, checks safety flags, detects
/// contradictions between evidence states, verifies no unsafe requests
/// or mutations, and determines the overall review status, decision,
/// and findings. Release is always rejected in I-26.
pub fn build_reader_lab_completion_review_pack(
    input: &EbpfReaderLabCompletionReviewPackInput,
) -> EbpfReaderLabCompletionReviewPack {
    let mut pack = safe_base_pack();
    let mut findings: Vec<EbpfReaderLabCompletionReviewFinding> = Vec::new();
    let mut blocked = false;
    let mut has_contradiction = false;

    let plan_valid = validate_reader_lab_next_arc_plan(&input.next_arc_plan).is_ok();
    let freeze_valid =
        validate_reader_lab_static_policy_freeze_record(&input.static_policy_freeze_record).is_ok();
    let review_valid =
        validate_reader_lab_static_policy_review_pack(&input.static_policy_review_pack).is_ok();
    let hardening_valid =
        validate_reader_lab_static_policy_hardening_report(&input.static_policy_hardening_report)
            .is_ok();
    let gate_valid =
        validate_reader_lab_policy_completion_gate_report(&input.policy_completion_gate_report)
            .is_ok();

    pack.next_arc_plan_ready = plan_valid;
    pack.static_policy_frozen = input.static_policy_freeze_record.policy_frozen;
    pack.static_policy_review_ready = input.static_policy_review_pack.review_ready;
    pack.static_policy_hardening_passed = input.static_policy_hardening_report.hardening_passed;
    pack.policy_completion_passed = input.policy_completion_gate_report.completion_passed;

    let inc = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
    let pk = EbpfReaderLabCompletionReviewFindingKind::PolicyCompletionGate;
    if !plan_valid {
        push_finding(
            &mut findings,
            "CRP-PLAN-INVALID",
            EbpfReaderLabCompletionReviewFindingKind::NextArcPlan,
            "next arc plan validation failed",
            inc,
        );
        blocked = true;
    }
    if !freeze_valid {
        push_finding(
            &mut findings,
            "CRP-FREEZE-INVALID",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyFreeze,
            "static policy freeze record validation failed",
            inc,
        );
        blocked = true;
    }
    if !review_valid {
        push_finding(
            &mut findings,
            "CRP-REVIEW-INVALID",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyReview,
            "static policy review pack validation failed",
            inc,
        );
        blocked = true;
    }
    if !hardening_valid {
        push_finding(
            &mut findings,
            "CRP-HARDENING-INVALID",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyHardening,
            "static policy hardening report validation failed",
            inc,
        );
        blocked = true;
    }
    if !gate_valid {
        push_finding(
            &mut findings,
            "CRP-GATE-INVALID",
            pk,
            "policy completion gate report validation failed",
            inc,
        );
        blocked = true;
    }

    // Require ready/frozen/review_ready/hardening_passed/completion_passed when configured
    if input.require_next_arc_plan_ready && !input.next_arc_plan.plan_ready {
        push_finding(
            &mut findings,
            "CRP-PLAN-NOT-READY",
            EbpfReaderLabCompletionReviewFindingKind::NextArcPlan,
            "next arc plan is not ready",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_frozen && !input.static_policy_freeze_record.policy_frozen {
        push_finding(
            &mut findings,
            "CRP-FREEZE-NOT-FROZEN",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyFreeze,
            "static policy is not frozen",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_review_ready && !input.static_policy_review_pack.review_ready {
        push_finding(
            &mut findings,
            "CRP-REVIEW-NOT-READY",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyReview,
            "static policy review is not ready",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_hardening_passed
        && !input.static_policy_hardening_report.hardening_passed
    {
        push_finding(
            &mut findings,
            "CRP-HARDENING-NOT-PASSED",
            EbpfReaderLabCompletionReviewFindingKind::StaticPolicyHardening,
            "static policy hardening has not passed",
            inc,
        );
        blocked = true;
    }
    if input.require_policy_completion_passed
        && !input.policy_completion_gate_report.completion_passed
    {
        push_finding(
            &mut findings,
            "CRP-COMPLETION-NOT-PASSED",
            pk,
            "policy completion gate has not passed",
            inc,
        );
        blocked = true;
    }

    // Experimental-only check across all five evidence types
    if input.require_experimental_only {
        pack.experimental_only_confirmed = true;
        let exp = [
            input.next_arc_plan.must_remain_experimental,
            input.static_policy_freeze_record.must_remain_experimental,
            input.static_policy_review_pack.must_remain_experimental,
            input
                .static_policy_hardening_report
                .must_remain_experimental,
            input.policy_completion_gate_report.must_remain_experimental,
        ];
        if !exp.iter().all(|&v| v) {
            push_finding(
                &mut findings,
                "CRP-NOT-EXPERIMENTAL",
                EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
                "evidence disagrees on must_remain_experimental",
                EbpfReaderLabCompletionReviewPackStatus::Blocked,
            );
            blocked = true;
            has_contradiction = true;
        }
    }

    // Contradiction: release_allowed across all five evidence types
    let ra = [
        input.next_arc_plan.release_allowed,
        input.static_policy_freeze_record.release_allowed,
        input.static_policy_review_pack.release_allowed,
        input.static_policy_hardening_report.release_allowed,
        input.policy_completion_gate_report.release_allowed,
    ];
    if ra.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "CRP-CONTRADICTION-RELEASE",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "evidence disagrees on release_allowed",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: live_reader_next_allowed
    let lr = [
        input.next_arc_plan.live_reader_next_allowed,
        input.static_policy_freeze_record.live_reader_next_allowed,
        input.static_policy_review_pack.live_reader_next_allowed,
        input
            .static_policy_hardening_report
            .live_reader_next_allowed,
        input.policy_completion_gate_report.live_reader_next_allowed,
    ];
    if lr.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "CRP-CONTRADICTION-LIVE-READER",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "evidence disagrees on live_reader_next_allowed",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: public_cli_next_allowed
    let pc = [
        input.next_arc_plan.public_cli_next_allowed,
        input.static_policy_freeze_record.public_cli_next_allowed,
        input.static_policy_review_pack.public_cli_next_allowed,
        input.static_policy_hardening_report.public_cli_next_allowed,
        input.policy_completion_gate_report.public_cli_next_allowed,
    ];
    if pc.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "CRP-CONTRADICTION-PUBLIC-CLI",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "evidence disagrees on public_cli_next_allowed",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: release_path_next_allowed
    let rp = [
        input.next_arc_plan.release_path_next_allowed,
        input.static_policy_freeze_record.release_path_next_allowed,
        input.static_policy_review_pack.release_path_next_allowed,
        input
            .static_policy_hardening_report
            .release_path_next_allowed,
        input
            .policy_completion_gate_report
            .release_path_next_allowed,
    ];
    if rp.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "CRP-CONTRADICTION-RELEASE-PATH",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "evidence disagrees on release_path_next_allowed",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: I-25 completed but contradiction_detected=true
    if input.policy_completion_gate_report.completion_passed
        && input.policy_completion_gate_report.contradiction_detected
    {
        push_finding(
            &mut findings,
            "CRP-GATE-CONTRADICTION",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "completion gate claims passed but also reports contradiction",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: any evidence claims public_cli_exposed=true
    let cli_exp = [
        input.next_arc_plan.public_cli_exposed,
        input.static_policy_freeze_record.public_cli_exposed,
        input.static_policy_review_pack.public_cli_exposed,
        input.static_policy_hardening_report.public_cli_exposed,
        input.policy_completion_gate_report.public_cli_exposed,
    ];
    if cli_exp.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "CRP-CONTRADICTION-CLI-EXPOSED",
            EbpfReaderLabCompletionReviewFindingKind::ContradictionInvariant,
            "evidence claims public_cli_exposed=true",
            EbpfReaderLabCompletionReviewPackStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    pack.contradiction_detected = has_contradiction;

    let blk = EbpfReaderLabCompletionReviewPackStatus::Blocked;
    // CLI and schema checks
    if !input.public_cli_expected_hidden {
        push_finding(
            &mut findings,
            "CRP-CLI-NOT-HIDDEN",
            EbpfReaderLabCompletionReviewFindingKind::CliInvariant,
            "public CLI expected hidden but was not",
            blk,
        );
        blocked = true;
    }
    if !input.usage_schema_expected_unchanged {
        push_finding(
            &mut findings,
            "CRP-USAGE-SCHEMA-CHANGED",
            EbpfReaderLabCompletionReviewFindingKind::SchemaInvariant,
            "usage schema expected unchanged but was changed",
            blk,
        );
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        push_finding(
            &mut findings,
            "CRP-LEDGER-SCHEMA-CHANGED",
            EbpfReaderLabCompletionReviewFindingKind::SchemaInvariant,
            "ledger schema expected unchanged but was changed",
            blk,
        );
        blocked = true;
    }

    // Block release/tag/publish/version/main requests
    let rf = EbpfReaderLabCompletionReviewPackStatus::ReleaseForbidden;
    let release_cases: &[(&str, bool)] = &[
        (
            "stable release requested in experimental branch",
            input.stable_release_requested,
        ),
        ("tag requested in experimental branch", input.tag_requested),
        (
            "publish requested in experimental branch",
            input.publish_requested,
        ),
        (
            "version bump requested in experimental branch",
            input.version_bump_requested,
        ),
        (
            "main merge requested in experimental branch",
            input.main_merge_requested,
        ),
    ];
    let release_codes: &[&str] = &[
        "CRP-RELEASE-REQUESTED",
        "CRP-TAG-REQUESTED",
        "CRP-PUBLISH-REQUESTED",
        "CRP-VERSION-BUMP-REQUESTED",
        "CRP-MAIN-MERGE-REQUESTED",
    ];
    for ((msg, flag), code) in release_cases.iter().zip(release_codes.iter()) {
        if *flag {
            push_finding(
                &mut findings,
                code,
                EbpfReaderLabCompletionReviewFindingKind::ReleaseInvariant,
                msg,
                rf,
            );
            blocked = true;
        }
    }

    // Fake evidence detection from all evidence types (compressed with any5 helper)
    let fe = EbpfReaderLabCompletionReviewFindingKind::FakeEvidenceInvariant;
    let p = &input.next_arc_plan;
    let f = &input.static_policy_freeze_record;
    let rv = &input.static_policy_review_pack;
    let h = &input.static_policy_hardening_report;
    let g = &input.policy_completion_gate_report;
    let any5 = |a: bool, b: bool, c: bool, d: bool, e: bool| a || b || c || d || e;
    let mut fake_check = |flag: bool, code: &str, msg: &str| {
        if flag {
            push_finding(&mut findings, code, fe, msg, blk);
            blocked = true;
        }
    };
    fake_check(
        any5(
            p.fake_reader_success_detected,
            f.fake_reader_success_detected,
            rv.fake_reader_success_detected,
            h.fake_reader_success_detected,
            g.fake_reader_success_detected,
        ),
        "CRP-FAKE-READER",
        "fake reader execution success detected",
    );
    fake_check(
        any5(
            p.fake_live_event_counts_detected,
            f.fake_live_event_counts_detected,
            rv.fake_live_event_counts_detected,
            h.fake_live_event_counts_detected,
            g.fake_live_event_counts_detected,
        ),
        "CRP-FAKE-EVENTS",
        "fake live event counts detected",
    );
    fake_check(
        any5(
            p.fake_release_readiness_detected,
            f.fake_release_readiness_detected,
            rv.fake_release_readiness_detected,
            h.fake_release_readiness_detected,
            g.fake_release_readiness_detected,
        ),
        "CRP-FAKE-RELEASE",
        "fake release readiness detected",
    );
    fake_check(
        any5(
            p.fake_planning_success_detected,
            f.fake_planning_success_detected,
            rv.fake_planning_success_detected,
            h.fake_planning_success_detected,
            g.fake_planning_success_detected,
        ),
        "CRP-FAKE-PLANNING",
        "fake planning success detected",
    );
    fake_check(
        any5(
            false,
            f.fake_policy_freeze_success_detected,
            rv.fake_policy_freeze_success_detected,
            h.fake_policy_freeze_success_detected,
            g.fake_policy_freeze_success_detected,
        ),
        "CRP-FAKE-POLICY-FREEZE",
        "fake static policy freeze success detected",
    );
    fake_check(
        any5(
            false,
            false,
            rv.fake_review_success_detected,
            h.fake_policy_review_success_detected,
            g.fake_policy_review_success_detected,
        ),
        "CRP-FAKE-REVIEW",
        "fake static policy review success detected",
    );
    fake_check(
        any5(
            false,
            false,
            false,
            h.fake_hardening_success_detected,
            g.fake_policy_hardening_success_detected,
        ),
        "CRP-FAKE-HARDENING",
        "fake static policy hardening success detected",
    );
    fake_check(
        g.fake_completion_success_detected,
        "CRP-FAKE-COMPLETION",
        "fake policy freeze completion success detected",
    );

    // Require experimental-only confirmation
    if !input.require_experimental_only {
        push_finding(
            &mut findings,
            "CRP-NO-EXPERIMENTAL-CONFIRM",
            EbpfReaderLabCompletionReviewFindingKind::CompletionReviewInvariant,
            "experimental-only confirmation not provided",
            EbpfReaderLabCompletionReviewPackStatus::ExperimentalOnly,
        );
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
        let has_hardening_block = !hardening_valid;
        let has_gate_block = !gate_valid;
        if has_release_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::ReleaseForbidden;
            pack.decision = EbpfReaderLabCompletionReviewDecision::RejectRelease;
        } else if has_experimental_only_block
            && has_plan_block
            && has_freeze_block
            && has_review_block
        {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixNextArcPlan;
        } else if has_experimental_only_block && has_review_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyReview;
        } else if has_experimental_only_block && has_freeze_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyFreeze;
        } else if has_experimental_only_block && has_hardening_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyHardening;
        } else if has_experimental_only_block && has_gate_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixCompletionGate;
        } else if has_experimental_only_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::ExperimentalOnly;
            pack.decision = EbpfReaderLabCompletionReviewDecision::KeepExperimental;
        } else if has_contradiction {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::RejectRelease;
        } else if has_gate_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixCompletionGate;
        } else if has_plan_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixNextArcPlan;
        } else if has_freeze_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyFreeze;
        } else if has_review_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyReview;
        } else if has_hardening_block {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::Blocked;
            pack.decision = EbpfReaderLabCompletionReviewDecision::FixStaticPolicyHardening;
        } else {
            pack.status = EbpfReaderLabCompletionReviewPackStatus::ReviewRejected;
            pack.decision = EbpfReaderLabCompletionReviewDecision::RejectRelease;
        }
    } else {
        pack.status = EbpfReaderLabCompletionReviewPackStatus::ReviewReady;
        pack.decision = EbpfReaderLabCompletionReviewDecision::PrepareNextArc;
        pack.review_ready = true;
    }

    pack.findings = findings;
    pack
}

/// Validate that a reader lab completion review pack is safe.
pub fn validate_reader_lab_completion_review_pack(
    pack: &EbpfReaderLabCompletionReviewPack,
) -> Result<(), String> {
    if pack.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-26"))
        } else {
            Ok(())
        }
    };
    deny(pack.release_allowed, "release_allowed")?;
    deny(!pack.must_remain_experimental, "must_remain_experimental")?;
    deny(pack.live_reader_next_allowed, "live_reader_next_allowed")?;
    deny(pack.public_cli_next_allowed, "public_cli_next_allowed")?;
    deny(pack.release_path_next_allowed, "release_path_next_allowed")?;
    deny(pack.public_cli_exposed, "public_cli_exposed")?;
    deny(pack.usage_schema_changed, "usage_schema_changed")?;
    deny(pack.ledger_schema_changed, "ledger_schema_changed")?;
    deny(pack.stable_release_requested, "stable_release_requested")?;
    deny(pack.tag_requested, "tag_requested")?;
    deny(pack.publish_requested, "publish_requested")?;
    deny(pack.version_bump_requested, "version_bump_requested")?;
    deny(pack.main_merge_requested, "main_merge_requested")?;
    deny(pack.ring_buffer_opened, "ring_buffer_opened")?;
    deny(pack.live_event_stream_read, "live_event_stream_read")?;
    deny(pack.map_pin_performed, "map_pin_performed")?;
    deny(pack.enforcement_performed, "enforcement_performed")?;
    deny(pack.packet_drop_performed, "packet_drop_performed")?;
    deny(pack.mutation_performed, "mutation_performed")?;
    deny(pack.persistence_performed, "persistence_performed")?;
    deny(
        pack.fake_reader_success_detected,
        "fake_reader_success_detected",
    )?;
    deny(
        pack.fake_live_event_counts_detected,
        "fake_live_event_counts_detected",
    )?;
    deny(
        pack.fake_release_readiness_detected,
        "fake_release_readiness_detected",
    )?;
    deny(
        pack.fake_planning_success_detected,
        "fake_planning_success_detected",
    )?;
    deny(
        pack.fake_policy_freeze_success_detected,
        "fake_policy_freeze_success_detected",
    )?;
    deny(
        pack.fake_policy_review_success_detected,
        "fake_policy_review_success_detected",
    )?;
    deny(
        pack.fake_policy_hardening_success_detected,
        "fake_policy_hardening_success_detected",
    )?;
    deny(
        pack.fake_policy_completion_success_detected,
        "fake_policy_completion_success_detected",
    )?;
    deny(
        pack.fake_completion_review_success_detected,
        "fake_completion_review_success_detected",
    )?;
    deny(pack.contradiction_detected, "contradiction_detected")?;
    if pack.review_ready && pack.status == EbpfReaderLabCompletionReviewPackStatus::ReviewRejected {
        return Err("review_ready must be false when status is ReviewRejected".to_string());
    }
    Ok(())
}

/// Map a completion review pack status to a stable human-readable label.
pub fn reader_lab_completion_review_pack_status_label(
    status: EbpfReaderLabCompletionReviewPackStatus,
) -> &'static str {
    status.as_str()
}

/// Map a completion review decision to a stable human-readable label.
pub fn reader_lab_completion_review_decision_label(
    decision: EbpfReaderLabCompletionReviewDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a completion review finding kind to a stable human-readable label.
pub fn reader_lab_completion_review_finding_kind_label(
    kind: EbpfReaderLabCompletionReviewFindingKind,
) -> &'static str {
    kind.as_str()
}
