// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab policy freeze completion gate model for the Intergalaxion Engine.
//!
//! Phase I-25 decides whether the static policy arc can be marked internally
//! complete after consuming I-21 next arc plan, I-22 static policy freeze,
//! I-23 static policy review pack, and I-24 static policy hardening report.
//! This phase is policy-freeze-completion-gate only — not a release, not a
//! public feature, not a live reader, not a ring buffer reader, not a kernel
//! event consumer. It is an internal deterministic completion checkpoint only.
//!
//! # Design constraints (I-25)
//!
//! * Policy-freeze-completion-gate only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake policy freeze completion success, no fake release readiness.
//! * release_allowed is always false in I-25.
//! * must_remain_experimental is always true in I-25.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
    validate_reader_lab_next_arc_plan, EbpfReaderLabNextArcPlan,
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

/// Status of the reader lab policy freeze completion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabPolicyCompletionGateStatus {
    Draft,
    Incomplete,
    Blocked,
    Completed,
    CompletionRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}

impl EbpfReaderLabPolicyCompletionGateStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::CompletionRejected => "completion_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab policy freeze completion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabPolicyCompletionDecision {
    Stop,
    FixNextArcPlan,
    FixStaticPolicyFreeze,
    FixStaticPolicyReview,
    FixStaticPolicyHardening,
    KeepExperimental,
    CompletePolicyFreeze,
    PrepareNextArc,
    RejectRelease,
}

impl EbpfReaderLabPolicyCompletionDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixNextArcPlan => "fix_next_arc_plan",
            Self::FixStaticPolicyFreeze => "fix_static_policy_freeze",
            Self::FixStaticPolicyReview => "fix_static_policy_review",
            Self::FixStaticPolicyHardening => "fix_static_policy_hardening",
            Self::KeepExperimental => "keep_experimental",
            Self::CompletePolicyFreeze => "complete_policy_freeze",
            Self::PrepareNextArc => "prepare_next_arc",
            Self::RejectRelease => "reject_release",
        }
    }
}

/// Kind of policy freeze completion gate finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabPolicyCompletionFindingKind {
    NextArcPlan,
    StaticPolicyFreeze,
    StaticPolicyReview,
    StaticPolicyHardening,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    ContradictionInvariant,
    CompletionInvariant,
}

impl EbpfReaderLabPolicyCompletionFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::StaticPolicyReview => "static_policy_review",
            Self::StaticPolicyHardening => "static_policy_hardening",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::ContradictionInvariant => "contradiction_invariant",
            Self::CompletionInvariant => "completion_invariant",
        }
    }
}

/// A single finding produced by the policy completion gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabPolicyCompletionFinding {
    pub code: String,
    pub kind: EbpfReaderLabPolicyCompletionFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabPolicyCompletionGateStatus,
}

/// Input to the reader lab policy freeze completion gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabPolicyCompletionGateInput {
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    pub static_policy_review_pack: EbpfReaderLabStaticPolicyReviewPack,
    pub static_policy_hardening_report: EbpfReaderLabStaticPolicyHardeningReport,
    pub require_next_arc_plan_ready: bool,
    pub require_static_policy_frozen: bool,
    pub require_static_policy_review_ready: bool,
    pub require_static_policy_hardening_passed: bool,
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

/// Completion gate report produced by the reader lab policy completion gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabPolicyCompletionGateReport {
    pub phase: String,
    pub status: EbpfReaderLabPolicyCompletionGateStatus,
    pub decision: EbpfReaderLabPolicyCompletionDecision,
    pub completion_passed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabPolicyCompletionFinding>,
    pub next_arc_plan_ready: bool,
    pub static_policy_frozen: bool,
    pub static_policy_review_ready: bool,
    pub static_policy_hardening_passed: bool,
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
    pub fake_completion_success_detected: bool,
}

// -- Helper: push a blocking finding --
#[inline]
fn push_finding(
    findings: &mut Vec<EbpfReaderLabPolicyCompletionFinding>,
    code: &str,
    kind: EbpfReaderLabPolicyCompletionFindingKind,
    message: &str,
    status: EbpfReaderLabPolicyCompletionGateStatus,
) {
    findings.push(EbpfReaderLabPolicyCompletionFinding {
        code: String::from(code),
        kind,
        message: String::from(message),
        blocking: true,
        status,
    });
}

fn safe_base_report() -> EbpfReaderLabPolicyCompletionGateReport {
    EbpfReaderLabPolicyCompletionGateReport {
        phase: String::from("I-25"),
        status: EbpfReaderLabPolicyCompletionGateStatus::Draft,
        decision: EbpfReaderLabPolicyCompletionDecision::Stop,
        completion_passed: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        next_arc_plan_ready: false,
        static_policy_frozen: false,
        static_policy_review_ready: false,
        static_policy_hardening_passed: false,
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
        fake_completion_success_detected: false,
    }
}

/// Create the default reader lab policy completion gate input.
///
/// Builds safe evidence from I-21, I-22, I-23, and I-24 defaults. No unsafe
/// requests are included. The default input is safe but incomplete or
/// experimental-only.
pub fn default_reader_lab_policy_completion_gate_input() -> EbpfReaderLabPolicyCompletionGateInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input,
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
    EbpfReaderLabPolicyCompletionGateInput {
        next_arc_plan,
        static_policy_freeze_record,
        static_policy_review_pack,
        static_policy_hardening_report,
        require_next_arc_plan_ready: false,
        require_static_policy_frozen: false,
        require_static_policy_review_ready: false,
        require_static_policy_hardening_passed: false,
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

/// Build the reader lab policy freeze completion gate report from input.
///
/// Validates all four evidence types, checks safety flags, detects
/// contradictions between evidence states, verifies no unsafe requests
/// or mutations, and determines the overall completion status, decision,
/// and findings. Release is always rejected in I-25.
pub fn build_reader_lab_policy_completion_gate_report(
    input: &EbpfReaderLabPolicyCompletionGateInput,
) -> EbpfReaderLabPolicyCompletionGateReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfReaderLabPolicyCompletionFinding> = Vec::new();
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

    report.next_arc_plan_ready = plan_valid;
    report.static_policy_frozen = input.static_policy_freeze_record.policy_frozen;
    report.static_policy_review_ready = input.static_policy_review_pack.review_ready;
    report.static_policy_hardening_passed = input.static_policy_hardening_report.hardening_passed;

    let inc = EbpfReaderLabPolicyCompletionGateStatus::Incomplete;
    if !plan_valid {
        push_finding(
            &mut findings,
            "PCG-PLAN-INVALID",
            EbpfReaderLabPolicyCompletionFindingKind::NextArcPlan,
            "next arc plan validation failed",
            inc,
        );
        blocked = true;
    }
    if !freeze_valid {
        push_finding(
            &mut findings,
            "PCG-FREEZE-INVALID",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyFreeze,
            "static policy freeze record validation failed",
            inc,
        );
        blocked = true;
    }
    if !review_valid {
        push_finding(
            &mut findings,
            "PCG-REVIEW-INVALID",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyReview,
            "static policy review pack validation failed",
            inc,
        );
        blocked = true;
    }
    if !hardening_valid {
        push_finding(
            &mut findings,
            "PCG-HARDENING-INVALID",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyHardening,
            "static policy hardening report validation failed",
            inc,
        );
        blocked = true;
    }

    // Require ready/frozen/review_ready/hardening_passed when configured
    if input.require_next_arc_plan_ready && !input.next_arc_plan.plan_ready {
        push_finding(
            &mut findings,
            "PCG-PLAN-NOT-READY",
            EbpfReaderLabPolicyCompletionFindingKind::NextArcPlan,
            "next arc plan is not ready",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_frozen && !input.static_policy_freeze_record.policy_frozen {
        push_finding(
            &mut findings,
            "PCG-FREEZE-NOT-FROZEN",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyFreeze,
            "static policy is not frozen",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_review_ready && !input.static_policy_review_pack.review_ready {
        push_finding(
            &mut findings,
            "PCG-REVIEW-NOT-READY",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyReview,
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
            "PCG-HARDENING-NOT-PASSED",
            EbpfReaderLabPolicyCompletionFindingKind::StaticPolicyHardening,
            "static policy hardening has not passed",
            inc,
        );
        blocked = true;
    }

    // Experimental-only check across all four evidence types
    if input.require_experimental_only {
        report.experimental_only_confirmed = true;
        let exp = [
            input.next_arc_plan.must_remain_experimental,
            input.static_policy_freeze_record.must_remain_experimental,
            input.static_policy_review_pack.must_remain_experimental,
            input
                .static_policy_hardening_report
                .must_remain_experimental,
        ];
        if !exp.iter().all(|&v| v) {
            push_finding(
                &mut findings,
                "PCG-NOT-EXPERIMENTAL",
                EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
                "evidence disagrees on must_remain_experimental",
                EbpfReaderLabPolicyCompletionGateStatus::Blocked,
            );
            blocked = true;
            has_contradiction = true;
        }
    }

    // Contradiction: release_allowed across all four evidence types
    let ra = [
        input.next_arc_plan.release_allowed,
        input.static_policy_freeze_record.release_allowed,
        input.static_policy_review_pack.release_allowed,
        input.static_policy_hardening_report.release_allowed,
    ];
    if ra.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "PCG-CONTRADICTION-RELEASE",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "evidence disagrees on release_allowed",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
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
    ];
    if lr.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "PCG-CONTRADICTION-LIVE-READER",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "evidence disagrees on live_reader_next_allowed",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
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
    ];
    if pc.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "PCG-CONTRADICTION-PUBLIC-CLI",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "evidence disagrees on public_cli_next_allowed",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
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
    ];
    if rp.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "PCG-CONTRADICTION-RELEASE-PATH",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "evidence disagrees on release_path_next_allowed",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    // Contradiction: I-24 hardened but contradiction_detected=true
    if input.static_policy_hardening_report.hardening_passed
        && input.static_policy_hardening_report.contradiction_detected
    {
        push_finding(
            &mut findings,
            "PCG-HARDENING-CONTRADICTION",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "hardening report claims passed but also reports contradiction",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
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
    ];
    if cli_exp.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "PCG-CONTRADICTION-CLI-EXPOSED",
            EbpfReaderLabPolicyCompletionFindingKind::ContradictionInvariant,
            "evidence claims public_cli_exposed=true",
            EbpfReaderLabPolicyCompletionGateStatus::Blocked,
        );
        blocked = true;
        has_contradiction = true;
    }

    report.contradiction_detected = has_contradiction;

    let blk = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
    // CLI and schema checks
    if !input.public_cli_expected_hidden {
        push_finding(
            &mut findings,
            "PCG-CLI-NOT-HIDDEN",
            EbpfReaderLabPolicyCompletionFindingKind::CliInvariant,
            "public CLI expected hidden but was not",
            blk,
        );
        blocked = true;
    }
    if !input.usage_schema_expected_unchanged {
        push_finding(
            &mut findings,
            "PCG-USAGE-SCHEMA-CHANGED",
            EbpfReaderLabPolicyCompletionFindingKind::SchemaInvariant,
            "usage schema expected unchanged but was changed",
            blk,
        );
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        push_finding(
            &mut findings,
            "PCG-LEDGER-SCHEMA-CHANGED",
            EbpfReaderLabPolicyCompletionFindingKind::SchemaInvariant,
            "ledger schema expected unchanged but was changed",
            blk,
        );
        blocked = true;
    }

    // Block release/tag/publish/version/main requests
    let rf = EbpfReaderLabPolicyCompletionGateStatus::ReleaseForbidden;
    let release_cases: &[(&str, bool)] = &[
        (
            "stable_release requested in experimental branch",
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
        "PCG-RELEASE-REQUESTED",
        "PCG-TAG-REQUESTED",
        "PCG-PUBLISH-REQUESTED",
        "PCG-VERSION-BUMP-REQUESTED",
        "PCG-MAIN-MERGE-REQUESTED",
    ];
    for ((msg, flag), code) in release_cases.iter().zip(release_codes.iter()) {
        if *flag {
            push_finding(
                &mut findings,
                code,
                EbpfReaderLabPolicyCompletionFindingKind::ReleaseInvariant,
                msg,
                rf,
            );
            blocked = true;
        }
    }

    // Fake evidence detection from all evidence types
    let fe = EbpfReaderLabPolicyCompletionFindingKind::FakeEvidenceInvariant;
    if input.next_arc_plan.fake_reader_success_detected
        || input
            .static_policy_freeze_record
            .fake_reader_success_detected
        || input.static_policy_review_pack.fake_reader_success_detected
        || input
            .static_policy_hardening_report
            .fake_reader_success_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-READER",
            fe,
            "fake reader execution success detected",
            blk,
        );
        blocked = true;
    }
    if input.next_arc_plan.fake_live_event_counts_detected
        || input
            .static_policy_freeze_record
            .fake_live_event_counts_detected
        || input
            .static_policy_review_pack
            .fake_live_event_counts_detected
        || input
            .static_policy_hardening_report
            .fake_live_event_counts_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-EVENTS",
            fe,
            "fake live event counts detected",
            blk,
        );
        blocked = true;
    }
    if input.next_arc_plan.fake_release_readiness_detected
        || input
            .static_policy_freeze_record
            .fake_release_readiness_detected
        || input
            .static_policy_review_pack
            .fake_release_readiness_detected
        || input
            .static_policy_hardening_report
            .fake_release_readiness_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-RELEASE",
            fe,
            "fake release readiness detected",
            blk,
        );
        blocked = true;
    }
    if input.next_arc_plan.fake_planning_success_detected
        || input
            .static_policy_freeze_record
            .fake_planning_success_detected
        || input
            .static_policy_review_pack
            .fake_planning_success_detected
        || input
            .static_policy_hardening_report
            .fake_planning_success_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-PLANNING",
            fe,
            "fake planning success detected",
            blk,
        );
        blocked = true;
    }
    if input
        .static_policy_freeze_record
        .fake_policy_freeze_success_detected
        || input
            .static_policy_review_pack
            .fake_policy_freeze_success_detected
        || input
            .static_policy_hardening_report
            .fake_policy_freeze_success_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-POLICY-FREEZE",
            fe,
            "fake static policy freeze success detected",
            blk,
        );
        blocked = true;
    }
    if input.static_policy_review_pack.fake_review_success_detected
        || input
            .static_policy_hardening_report
            .fake_policy_review_success_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-REVIEW",
            fe,
            "fake static policy review success detected",
            blk,
        );
        blocked = true;
    }
    if input
        .static_policy_hardening_report
        .fake_hardening_success_detected
    {
        push_finding(
            &mut findings,
            "PCG-FAKE-HARDENING",
            fe,
            "fake static policy hardening success detected",
            blk,
        );
        blocked = true;
    }

    // Require experimental-only confirmation
    if !input.require_experimental_only {
        push_finding(
            &mut findings,
            "PCG-NO-EXPERIMENTAL-CONFIRM",
            EbpfReaderLabPolicyCompletionFindingKind::CompletionInvariant,
            "experimental-only confirmation not provided",
            EbpfReaderLabPolicyCompletionGateStatus::ExperimentalOnly,
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
        if has_release_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::ReleaseForbidden;
            report.decision = EbpfReaderLabPolicyCompletionDecision::RejectRelease;
        } else if has_experimental_only_block
            && has_plan_block
            && has_freeze_block
            && has_review_block
        {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Incomplete;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixNextArcPlan;
        } else if has_experimental_only_block && has_review_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Incomplete;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyReview;
        } else if has_experimental_only_block && has_freeze_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Incomplete;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyFreeze;
        } else if has_experimental_only_block && has_hardening_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Incomplete;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyHardening;
        } else if has_experimental_only_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::ExperimentalOnly;
            report.decision = EbpfReaderLabPolicyCompletionDecision::KeepExperimental;
        } else if has_contradiction {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
            report.decision = EbpfReaderLabPolicyCompletionDecision::RejectRelease;
        } else if has_plan_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixNextArcPlan;
        } else if has_freeze_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyFreeze;
        } else if has_review_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyReview;
        } else if has_hardening_block {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::Blocked;
            report.decision = EbpfReaderLabPolicyCompletionDecision::FixStaticPolicyHardening;
        } else {
            report.status = EbpfReaderLabPolicyCompletionGateStatus::CompletionRejected;
            report.decision = EbpfReaderLabPolicyCompletionDecision::RejectRelease;
        }
    } else {
        report.status = EbpfReaderLabPolicyCompletionGateStatus::Completed;
        report.decision = EbpfReaderLabPolicyCompletionDecision::CompletePolicyFreeze;
        report.completion_passed = true;
    }

    report.findings = findings;
    report
}

/// Validate that a reader lab policy freeze completion gate report is safe.
pub fn validate_reader_lab_policy_completion_gate_report(
    report: &EbpfReaderLabPolicyCompletionGateReport,
) -> Result<(), String> {
    if report.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if report.release_allowed {
        return Err("release_allowed must be false in I-25".to_string());
    }
    if !report.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-25".to_string());
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
    if report.fake_policy_hardening_success_detected {
        return Err("fake_policy_hardening_success_detected must be false".to_string());
    }
    if report.fake_completion_success_detected {
        return Err("fake_completion_success_detected must be false".to_string());
    }
    if report.contradiction_detected {
        return Err("contradiction_detected must be false".to_string());
    }
    if report.completion_passed
        && report.status == EbpfReaderLabPolicyCompletionGateStatus::CompletionRejected
    {
        return Err(
            "completion_passed must be false when status is CompletionRejected".to_string(),
        );
    }
    Ok(())
}

/// Map a policy completion gate status to a stable human-readable label.
pub fn reader_lab_policy_completion_gate_status_label(
    status: EbpfReaderLabPolicyCompletionGateStatus,
) -> &'static str {
    status.as_str()
}

/// Map a policy completion gate decision to a stable human-readable label.
pub fn reader_lab_policy_completion_decision_label(
    decision: EbpfReaderLabPolicyCompletionDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a policy completion gate finding kind to a stable human-readable label.
pub fn reader_lab_policy_completion_finding_kind_label(
    kind: EbpfReaderLabPolicyCompletionFindingKind,
) -> &'static str {
    kind.as_str()
}
