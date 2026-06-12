// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc entry gate model for the Intergalaxion Engine (I-27).
//! Consumes I-21 through I-26 evidence to decide whether the next reader-lab
//! arc may begin as an internal experimental-only planning arc. Next-arc-entry-gate
//! only, not a release, not a live reader, not a ring buffer reader.
//! release_allowed is always false. must_remain_experimental is always true.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::{
    validate_reader_lab_completion_review_pack, EbpfReaderLabCompletionReviewPack,
};
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

/// Status of the reader lab next arc entry gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcEntryStatus {
    Draft,
    Incomplete,
    Blocked,
    EntryReady,
    EntryRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}

impl EbpfReaderLabNextArcEntryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::EntryReady => "entry_ready",
            Self::EntryRejected => "entry_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab next arc entry gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcEntryDecision {
    Stop,
    KeepExperimental,
    StartFixtureOnlyArc,
    StartStaticPolicyArc,
    StartManualReaderSpikeChecklistArc,
    StartReaderSpikeReviewArc,
    RejectLiveReaderArc,
    RejectPublicCliArc,
    RejectReleaseArc,
    RejectEnforcementArc,
}

impl EbpfReaderLabNextArcEntryDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepExperimental => "keep_experimental",
            Self::StartFixtureOnlyArc => "start_fixture_only_arc",
            Self::StartStaticPolicyArc => "start_static_policy_arc",
            Self::StartManualReaderSpikeChecklistArc => "start_manual_reader_spike_checklist_arc",
            Self::StartReaderSpikeReviewArc => "start_reader_spike_review_arc",
            Self::RejectLiveReaderArc => "reject_live_reader_arc",
            Self::RejectPublicCliArc => "reject_public_cli_arc",
            Self::RejectReleaseArc => "reject_release_arc",
            Self::RejectEnforcementArc => "reject_enforcement_arc",
        }
    }
}

/// Kind of next arc entry gate finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcEntryFindingKind {
    NextArcPlan,
    StaticPolicyFreeze,
    StaticPolicyReview,
    StaticPolicyHardening,
    PolicyCompletionGate,
    CompletionReview,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    EntryInvariant,
}

impl EbpfReaderLabNextArcEntryFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::StaticPolicyReview => "static_policy_review",
            Self::StaticPolicyHardening => "static_policy_hardening",
            Self::PolicyCompletionGate => "policy_completion_gate",
            Self::CompletionReview => "completion_review",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::EntryInvariant => "entry_invariant",
        }
    }
}

/// A single finding produced by the next arc entry gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcEntryFinding {
    pub code: String,
    pub kind: EbpfReaderLabNextArcEntryFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabNextArcEntryStatus,
}

/// Input to the reader lab next arc entry gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcEntryGateInput {
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    pub static_policy_review_pack: EbpfReaderLabStaticPolicyReviewPack,
    pub static_policy_hardening_report: EbpfReaderLabStaticPolicyHardeningReport,
    pub policy_completion_gate_report: EbpfReaderLabPolicyCompletionGateReport,
    pub completion_review_pack: EbpfReaderLabCompletionReviewPack,
    pub require_completion_review_ready: bool,
    pub require_policy_completion_passed: bool,
    pub require_static_policy_hardening_passed: bool,
    pub require_experimental_only: bool,
    pub prefer_fixture_only_arc: bool,
    pub prefer_static_policy_arc: bool,
    pub prefer_manual_reader_spike_checklist_arc: bool,
    pub prefer_reader_spike_review_arc: bool,
    pub allow_live_reader_arc: bool,
    pub allow_public_cli_arc: bool,
    pub allow_release_arc: bool,
    pub allow_enforcement_arc: bool,
    pub public_cli_expected_hidden: bool,
    pub usage_schema_expected_unchanged: bool,
    pub ledger_schema_expected_unchanged: bool,
    pub stable_release_requested: bool,
    pub tag_requested: bool,
    pub publish_requested: bool,
    pub version_bump_requested: bool,
    pub main_merge_requested: bool,
}

/// Next arc entry gate report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcEntryGateReport {
    pub phase: String,
    pub status: EbpfReaderLabNextArcEntryStatus,
    pub decision: EbpfReaderLabNextArcEntryDecision,
    pub entry_ready: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabNextArcEntryFinding>,
    pub completion_review_ready: bool,
    pub policy_completion_passed: bool,
    pub static_policy_hardening_passed: bool,
    pub experimental_only_confirmed: bool,
    pub selected_fixture_only_arc: bool,
    pub selected_static_policy_arc: bool,
    pub selected_manual_reader_spike_checklist_arc: bool,
    pub selected_reader_spike_review_arc: bool,
    pub live_reader_arc_allowed: bool,
    pub public_cli_arc_allowed: bool,
    pub release_arc_allowed: bool,
    pub enforcement_arc_allowed: bool,
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
    pub fake_next_arc_entry_success_detected: bool,
}

// -- Helper: push a blocking finding --
#[inline]
fn push_finding(
    findings: &mut Vec<EbpfReaderLabNextArcEntryFinding>,
    code: &str,
    kind: EbpfReaderLabNextArcEntryFindingKind,
    message: &str,
    status: EbpfReaderLabNextArcEntryStatus,
) {
    findings.push(EbpfReaderLabNextArcEntryFinding {
        code: String::from(code),
        kind,
        message: String::from(message),
        blocking: true,
        status,
    });
}

fn safe_base_report() -> EbpfReaderLabNextArcEntryGateReport {
    EbpfReaderLabNextArcEntryGateReport {
        phase: String::from("I-27"),
        status: EbpfReaderLabNextArcEntryStatus::Draft,
        decision: EbpfReaderLabNextArcEntryDecision::Stop,
        entry_ready: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        completion_review_ready: false,
        policy_completion_passed: false,
        static_policy_hardening_passed: false,
        experimental_only_confirmed: false,
        selected_fixture_only_arc: false,
        selected_static_policy_arc: false,
        selected_manual_reader_spike_checklist_arc: false,
        selected_reader_spike_review_arc: false,
        live_reader_arc_allowed: false,
        public_cli_arc_allowed: false,
        release_arc_allowed: false,
        enforcement_arc_allowed: false,
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
        fake_next_arc_entry_success_detected: false,
    }
}

/// Returns a safe default input.
pub fn default_reader_lab_next_arc_entry_gate_input() -> EbpfReaderLabNextArcEntryGateInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::{build_reader_lab_completion_review_pack, default_reader_lab_completion_review_pack_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::{build_reader_lab_policy_completion_gate_report, default_reader_lab_policy_completion_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{build_reader_lab_static_policy_freeze_record, default_reader_lab_static_policy_freeze_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{build_reader_lab_static_policy_hardening_report, default_reader_lab_static_policy_hardening_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{build_reader_lab_static_policy_review_pack, default_reader_lab_static_policy_review_pack_input};
    EbpfReaderLabNextArcEntryGateInput {
        next_arc_plan: build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input()),
        static_policy_freeze_record: build_reader_lab_static_policy_freeze_record(
            &default_reader_lab_static_policy_freeze_input(),
        ),
        static_policy_review_pack: build_reader_lab_static_policy_review_pack(
            &default_reader_lab_static_policy_review_pack_input(),
        ),
        static_policy_hardening_report: build_reader_lab_static_policy_hardening_report(
            &default_reader_lab_static_policy_hardening_input(),
        ),
        policy_completion_gate_report: build_reader_lab_policy_completion_gate_report(
            &default_reader_lab_policy_completion_gate_input(),
        ),
        completion_review_pack: build_reader_lab_completion_review_pack(
            &default_reader_lab_completion_review_pack_input(),
        ),
        require_completion_review_ready: false,
        require_policy_completion_passed: false,
        require_static_policy_hardening_passed: false,
        require_experimental_only: false,
        prefer_fixture_only_arc: false,
        prefer_static_policy_arc: false,
        prefer_manual_reader_spike_checklist_arc: false,
        prefer_reader_spike_review_arc: false,
        allow_live_reader_arc: false,
        allow_public_cli_arc: false,
        allow_release_arc: false,
        allow_enforcement_arc: false,
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

/// Build the next arc entry gate report.
pub fn build_reader_lab_next_arc_entry_gate_report(
    input: &EbpfReaderLabNextArcEntryGateInput,
) -> EbpfReaderLabNextArcEntryGateReport {
    let mut report = safe_base_report();
    let mut findings: Vec<EbpfReaderLabNextArcEntryFinding> = Vec::new();
    let mut blocked = false;
    let mut has_contradiction = false;
    let inc = EbpfReaderLabNextArcEntryStatus::Incomplete;
    let blk = EbpfReaderLabNextArcEntryStatus::Blocked;

    // Validate all 6 evidence types via loop
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
    let crp_valid =
        validate_reader_lab_completion_review_pack(&input.completion_review_pack).is_ok();
    let evidence_checks: &[(&str, EbpfReaderLabNextArcEntryFindingKind, &str, bool)] = &[
        (
            "NAEG-PLAN-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::NextArcPlan,
            "next arc plan validation failed",
            plan_valid,
        ),
        (
            "NAEG-FREEZE-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::StaticPolicyFreeze,
            "static policy freeze validation failed",
            freeze_valid,
        ),
        (
            "NAEG-REVIEW-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::StaticPolicyReview,
            "static policy review validation failed",
            review_valid,
        ),
        (
            "NAEG-HARDENING-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::StaticPolicyHardening,
            "static policy hardening validation failed",
            hardening_valid,
        ),
        (
            "NAEG-GATE-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::PolicyCompletionGate,
            "policy completion gate validation failed",
            gate_valid,
        ),
        (
            "NAEG-CRP-INVALID",
            EbpfReaderLabNextArcEntryFindingKind::CompletionReview,
            "completion review pack validation failed",
            crp_valid,
        ),
    ];
    for (code, kind, msg, valid) in evidence_checks {
        if !valid {
            push_finding(&mut findings, code, *kind, msg, inc);
            blocked = true;
        }
    }
    // Require flags
    if input.require_completion_review_ready && !input.completion_review_pack.review_ready {
        push_finding(
            &mut findings,
            "NAEG-CRP-NOT-READY",
            EbpfReaderLabNextArcEntryFindingKind::CompletionReview,
            "completion review pack is not review_ready",
            inc,
        );
        blocked = true;
    }
    if input.require_policy_completion_passed
        && !input.policy_completion_gate_report.completion_passed
    {
        push_finding(
            &mut findings,
            "NAEG-COMPLETION-NOT-PASSED",
            EbpfReaderLabNextArcEntryFindingKind::PolicyCompletionGate,
            "policy completion gate has not passed",
            inc,
        );
        blocked = true;
    }
    if input.require_static_policy_hardening_passed
        && !input.static_policy_hardening_report.hardening_passed
    {
        push_finding(
            &mut findings,
            "NAEG-HARDENING-NOT-PASSED",
            EbpfReaderLabNextArcEntryFindingKind::StaticPolicyHardening,
            "static policy hardening has not passed",
            inc,
        );
        blocked = true;
    }
    // Experimental-only check
    if input.require_experimental_only {
        report.experimental_only_confirmed = true;
        let exp = [
            input.next_arc_plan.must_remain_experimental,
            input.static_policy_freeze_record.must_remain_experimental,
            input.static_policy_review_pack.must_remain_experimental,
            input
                .static_policy_hardening_report
                .must_remain_experimental,
            input.policy_completion_gate_report.must_remain_experimental,
            input.completion_review_pack.must_remain_experimental,
        ];
        if !exp.iter().all(|&v| v) {
            push_finding(
                &mut findings,
                "NAEG-NOT-EXPERIMENTAL",
                EbpfReaderLabNextArcEntryFindingKind::MutationInvariant,
                "evidence disagrees on must_remain_experimental",
                blk,
            );
            blocked = true;
            has_contradiction = true;
        }
    }
    // Contradiction checks
    let ra = [
        input.next_arc_plan.release_allowed,
        input.static_policy_freeze_record.release_allowed,
        input.static_policy_review_pack.release_allowed,
        input.static_policy_hardening_report.release_allowed,
        input.policy_completion_gate_report.release_allowed,
        input.completion_review_pack.release_allowed,
    ];
    if ra.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "NAEG-CONTRADICTION-RELEASE",
            EbpfReaderLabNextArcEntryFindingKind::ReleaseInvariant,
            "evidence disagrees on release_allowed",
            blk,
        );
        blocked = true;
        has_contradiction = true;
    }

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
            "NAEG-CONTRADICTION-LIVE-READER",
            EbpfReaderLabNextArcEntryFindingKind::MutationInvariant,
            "evidence disagrees on live_reader_next_allowed",
            blk,
        );
        blocked = true;
        has_contradiction = true;
    }

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
            "NAEG-CONTRADICTION-PUBLIC-CLI",
            EbpfReaderLabNextArcEntryFindingKind::CliInvariant,
            "evidence disagrees on public_cli_next_allowed",
            blk,
        );
        blocked = true;
        has_contradiction = true;
    }

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
            "NAEG-CONTRADICTION-RELEASE-PATH",
            EbpfReaderLabNextArcEntryFindingKind::ReleaseInvariant,
            "evidence disagrees on release_path_next_allowed",
            blk,
        );
        blocked = true;
        has_contradiction = true;
    }

    let cli_exp = [
        input.next_arc_plan.public_cli_exposed,
        input.static_policy_freeze_record.public_cli_exposed,
        input.static_policy_review_pack.public_cli_exposed,
        input.static_policy_hardening_report.public_cli_exposed,
        input.policy_completion_gate_report.public_cli_exposed,
        input.completion_review_pack.public_cli_exposed,
    ];
    if cli_exp.iter().any(|&v| v) {
        push_finding(
            &mut findings,
            "NAEG-CONTRADICTION-CLI-EXPOSED",
            EbpfReaderLabNextArcEntryFindingKind::CliInvariant,
            "evidence claims public_cli_exposed=true",
            blk,
        );
        blocked = true;
        has_contradiction = true;
    }
    // CLI/schema checks (loop)
    let schema_checks: &[(bool, &str, EbpfReaderLabNextArcEntryFindingKind, &str)] = &[
        (
            !input.public_cli_expected_hidden,
            "NAEG-CLI-NOT-HIDDEN",
            EbpfReaderLabNextArcEntryFindingKind::CliInvariant,
            "public CLI expected hidden but was not",
        ),
        (
            !input.usage_schema_expected_unchanged,
            "NAEG-USAGE-SCHEMA-CHANGED",
            EbpfReaderLabNextArcEntryFindingKind::SchemaInvariant,
            "usage schema expected unchanged but was changed",
        ),
        (
            !input.ledger_schema_expected_unchanged,
            "NAEG-LEDGER-SCHEMA-CHANGED",
            EbpfReaderLabNextArcEntryFindingKind::SchemaInvariant,
            "ledger schema expected unchanged but was changed",
        ),
    ];
    for (flag, code, kind, msg) in schema_checks {
        if *flag {
            push_finding(&mut findings, code, *kind, msg, blk);
            blocked = true;
        }
    }
    // Release block
    let rf = EbpfReaderLabNextArcEntryStatus::ReleaseForbidden;
    let ri = EbpfReaderLabNextArcEntryFindingKind::ReleaseInvariant;
    let release_cases: &[(&str, bool, &str)] = &[
        (
            "stable release requested in experimental branch",
            input.stable_release_requested,
            "NAEG-RELEASE-REQUESTED",
        ),
        (
            "tag requested in experimental branch",
            input.tag_requested,
            "NAEG-TAG-REQUESTED",
        ),
        (
            "publish requested in experimental branch",
            input.publish_requested,
            "NAEG-PUBLISH-REQUESTED",
        ),
        (
            "version bump requested in experimental branch",
            input.version_bump_requested,
            "NAEG-VERSION-BUMP-REQUESTED",
        ),
        (
            "main merge requested in experimental branch",
            input.main_merge_requested,
            "NAEG-MAIN-MERGE-REQUESTED",
        ),
    ];
    for (msg, flag, code) in release_cases {
        if *flag {
            push_finding(&mut findings, code, ri, msg, rf);
            blocked = true;
        }
    }
    // Disallowed arcs
    let disallowed_cases: &[(
        &str,
        bool,
        EbpfReaderLabNextArcEntryDecision,
        EbpfReaderLabNextArcEntryFindingKind,
        &str,
    )] = &[
        (
            "allow_live_reader_arc",
            input.allow_live_reader_arc,
            EbpfReaderLabNextArcEntryDecision::RejectLiveReaderArc,
            EbpfReaderLabNextArcEntryFindingKind::KernelInvariant,
            "NAEG-LIVE-READER-ARC",
        ),
        (
            "allow_public_cli_arc",
            input.allow_public_cli_arc,
            EbpfReaderLabNextArcEntryDecision::RejectPublicCliArc,
            EbpfReaderLabNextArcEntryFindingKind::CliInvariant,
            "NAEG-PUBLIC-CLI-ARC",
        ),
        (
            "allow_release_arc",
            input.allow_release_arc,
            EbpfReaderLabNextArcEntryDecision::RejectReleaseArc,
            EbpfReaderLabNextArcEntryFindingKind::ReleaseInvariant,
            "NAEG-RELEASE-ARC",
        ),
        (
            "allow_enforcement_arc",
            input.allow_enforcement_arc,
            EbpfReaderLabNextArcEntryDecision::RejectEnforcementArc,
            EbpfReaderLabNextArcEntryFindingKind::MutationInvariant,
            "NAEG-ENFORCEMENT-ARC",
        ),
    ];
    for (name, flag, decision, kind, code) in disallowed_cases {
        if *flag {
            push_finding(
                &mut findings,
                code,
                *kind,
                &format!("{name} is not allowed in experimental branch"),
                blk,
            );
            blocked = true;
            report.decision = *decision;
        }
    }
    // Fake evidence
    let fe = EbpfReaderLabNextArcEntryFindingKind::FakeEvidenceInvariant;
    let p = &input.next_arc_plan;
    let f = &input.static_policy_freeze_record;
    let rv = &input.static_policy_review_pack;
    let h = &input.static_policy_hardening_report;
    let g = &input.policy_completion_gate_report;
    let c = &input.completion_review_pack;
    let any6 =
        |a: bool, b: bool, c2: bool, d: bool, e: bool, fv: bool| a || b || c2 || d || e || fv;
    let mut fake_check = |flag: bool, code: &str, msg: &str| {
        if flag {
            push_finding(&mut findings, code, fe, msg, blk);
            blocked = true;
        }
    };
    fake_check(
        any6(
            p.fake_reader_success_detected,
            f.fake_reader_success_detected,
            rv.fake_reader_success_detected,
            h.fake_reader_success_detected,
            g.fake_reader_success_detected,
            c.fake_reader_success_detected,
        ),
        "NAEG-FAKE-READER",
        "fake reader execution success detected",
    );
    fake_check(
        any6(
            p.fake_live_event_counts_detected,
            f.fake_live_event_counts_detected,
            rv.fake_live_event_counts_detected,
            h.fake_live_event_counts_detected,
            g.fake_live_event_counts_detected,
            c.fake_live_event_counts_detected,
        ),
        "NAEG-FAKE-EVENTS",
        "fake live event counts detected",
    );
    fake_check(
        any6(
            p.fake_release_readiness_detected,
            f.fake_release_readiness_detected,
            rv.fake_release_readiness_detected,
            h.fake_release_readiness_detected,
            g.fake_release_readiness_detected,
            c.fake_release_readiness_detected,
        ),
        "NAEG-FAKE-RELEASE",
        "fake release readiness detected",
    );
    fake_check(
        any6(
            p.fake_planning_success_detected,
            f.fake_planning_success_detected,
            rv.fake_planning_success_detected,
            h.fake_planning_success_detected,
            g.fake_planning_success_detected,
            c.fake_planning_success_detected,
        ),
        "NAEG-FAKE-PLANNING",
        "fake planning success detected",
    );
    fake_check(
        any6(
            false,
            f.fake_policy_freeze_success_detected,
            rv.fake_policy_freeze_success_detected,
            h.fake_policy_freeze_success_detected,
            g.fake_policy_freeze_success_detected,
            c.fake_policy_freeze_success_detected,
        ),
        "NAEG-FAKE-POLICY-FREEZE",
        "fake static policy freeze success detected",
    );
    fake_check(
        any6(
            false,
            false,
            rv.fake_review_success_detected,
            h.fake_policy_review_success_detected,
            g.fake_policy_review_success_detected,
            c.fake_policy_review_success_detected,
        ),
        "NAEG-FAKE-REVIEW",
        "fake static policy review success detected",
    );
    fake_check(
        any6(
            false,
            false,
            false,
            h.fake_hardening_success_detected,
            g.fake_policy_hardening_success_detected,
            c.fake_policy_hardening_success_detected,
        ),
        "NAEG-FAKE-HARDENING",
        "fake static policy hardening success detected",
    );
    fake_check(
        any6(
            false,
            false,
            false,
            false,
            g.fake_completion_success_detected,
            c.fake_policy_completion_success_detected,
        ),
        "NAEG-FAKE-COMPLETION",
        "fake policy freeze completion success detected",
    );
    fake_check(
        c.fake_completion_review_success_detected,
        "NAEG-FAKE-COMPLETION-REVIEW",
        "fake completion review success detected",
    );
    // Preference
    let has_pref = input.prefer_fixture_only_arc
        || input.prefer_static_policy_arc
        || input.prefer_manual_reader_spike_checklist_arc
        || input.prefer_reader_spike_review_arc;
    if !has_pref {
        push_finding(
            &mut findings,
            "NAEG-NO-PREFERENCE",
            EbpfReaderLabNextArcEntryFindingKind::EntryInvariant,
            "at least one allowed next arc preference must be selected",
            inc,
        );
        blocked = true;
    }

    if !input.require_experimental_only {
        push_finding(
            &mut findings,
            "NAEG-NO-EXPERIMENTAL-CONFIRM",
            EbpfReaderLabNextArcEntryFindingKind::EntryInvariant,
            "experimental-only confirmation not provided",
            EbpfReaderLabNextArcEntryStatus::ExperimentalOnly,
        );
        blocked = true;
    }
    // Status
    if blocked {
        let has_release_block = input.stable_release_requested
            || input.tag_requested
            || input.publish_requested
            || input.version_bump_requested
            || input.main_merge_requested;
        let has_experimental_only_block = !input.require_experimental_only;
        let has_disallowed = input.allow_live_reader_arc
            || input.allow_public_cli_arc
            || input.allow_release_arc
            || input.allow_enforcement_arc;
        let all_evidence_invalid = !plan_valid
            && !freeze_valid
            && !review_valid
            && !hardening_valid
            && !gate_valid
            && !crp_valid;
        if has_release_block {
            report.status = EbpfReaderLabNextArcEntryStatus::ReleaseForbidden;
            if !has_disallowed {
                report.decision = EbpfReaderLabNextArcEntryDecision::RejectReleaseArc;
            }
        } else if has_disallowed {
            report.status = EbpfReaderLabNextArcEntryStatus::Blocked;
        } else if has_experimental_only_block && all_evidence_invalid {
            report.status = EbpfReaderLabNextArcEntryStatus::Incomplete;
            report.decision = EbpfReaderLabNextArcEntryDecision::Stop;
        } else if has_experimental_only_block {
            report.status = EbpfReaderLabNextArcEntryStatus::ExperimentalOnly;
            report.decision = EbpfReaderLabNextArcEntryDecision::KeepExperimental;
        } else if has_contradiction {
            report.status = EbpfReaderLabNextArcEntryStatus::Blocked;
            report.decision = EbpfReaderLabNextArcEntryDecision::RejectReleaseArc;
        } else if !crp_valid
            || !gate_valid
            || !plan_valid
            || !freeze_valid
            || !review_valid
            || !hardening_valid
        {
            report.status = EbpfReaderLabNextArcEntryStatus::Blocked;
            report.decision = EbpfReaderLabNextArcEntryDecision::Stop;
        } else {
            report.status = EbpfReaderLabNextArcEntryStatus::EntryRejected;
            report.decision = EbpfReaderLabNextArcEntryDecision::Stop;
        }
    } else {
        report.status = EbpfReaderLabNextArcEntryStatus::EntryReady;
        report.entry_ready = true;
        if input.prefer_static_policy_arc {
            report.decision = EbpfReaderLabNextArcEntryDecision::StartStaticPolicyArc;
            report.selected_static_policy_arc = true;
        } else if input.prefer_fixture_only_arc {
            report.decision = EbpfReaderLabNextArcEntryDecision::StartFixtureOnlyArc;
            report.selected_fixture_only_arc = true;
        } else if input.prefer_manual_reader_spike_checklist_arc {
            report.decision = EbpfReaderLabNextArcEntryDecision::StartManualReaderSpikeChecklistArc;
            report.selected_manual_reader_spike_checklist_arc = true;
        } else if input.prefer_reader_spike_review_arc {
            report.decision = EbpfReaderLabNextArcEntryDecision::StartReaderSpikeReviewArc;
            report.selected_reader_spike_review_arc = true;
        } else {
            report.status = EbpfReaderLabNextArcEntryStatus::EntryRejected;
            report.decision = EbpfReaderLabNextArcEntryDecision::Stop;
            report.entry_ready = false;
        }
    }

    report.findings = findings;
    report
}

/// Validate a next arc entry gate report.
pub fn validate_reader_lab_next_arc_entry_gate_report(
    report: &EbpfReaderLabNextArcEntryGateReport,
) -> Result<(), String> {
    if report.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-27"))
        } else {
            Ok(())
        }
    };
    deny(report.release_allowed, "release_allowed")?;
    deny(!report.must_remain_experimental, "must_remain_experimental")?;
    deny(report.live_reader_arc_allowed, "live_reader_arc_allowed")?;
    deny(report.public_cli_arc_allowed, "public_cli_arc_allowed")?;
    deny(report.release_arc_allowed, "release_arc_allowed")?;
    deny(report.enforcement_arc_allowed, "enforcement_arc_allowed")?;
    deny(report.public_cli_exposed, "public_cli_exposed")?;
    deny(report.usage_schema_changed, "usage_schema_changed")?;
    deny(report.ledger_schema_changed, "ledger_schema_changed")?;
    deny(report.stable_release_requested, "stable_release_requested")?;
    deny(report.tag_requested, "tag_requested")?;
    deny(report.publish_requested, "publish_requested")?;
    deny(report.version_bump_requested, "version_bump_requested")?;
    deny(report.main_merge_requested, "main_merge_requested")?;
    deny(report.ring_buffer_opened, "ring_buffer_opened")?;
    deny(report.live_event_stream_read, "live_event_stream_read")?;
    deny(report.map_pin_performed, "map_pin_performed")?;
    deny(report.enforcement_performed, "enforcement_performed")?;
    deny(report.packet_drop_performed, "packet_drop_performed")?;
    deny(report.mutation_performed, "mutation_performed")?;
    deny(report.persistence_performed, "persistence_performed")?;
    // Fake evidence fields (loop)
    let fake_fields: &[(bool, &str)] = &[
        (
            report.fake_reader_success_detected,
            "fake_reader_success_detected",
        ),
        (
            report.fake_live_event_counts_detected,
            "fake_live_event_counts_detected",
        ),
        (
            report.fake_release_readiness_detected,
            "fake_release_readiness_detected",
        ),
        (
            report.fake_planning_success_detected,
            "fake_planning_success_detected",
        ),
        (
            report.fake_policy_freeze_success_detected,
            "fake_policy_freeze_success_detected",
        ),
        (
            report.fake_policy_review_success_detected,
            "fake_policy_review_success_detected",
        ),
        (
            report.fake_policy_hardening_success_detected,
            "fake_policy_hardening_success_detected",
        ),
        (
            report.fake_policy_completion_success_detected,
            "fake_policy_completion_success_detected",
        ),
        (
            report.fake_completion_review_success_detected,
            "fake_completion_review_success_detected",
        ),
        (
            report.fake_next_arc_entry_success_detected,
            "fake_next_arc_entry_success_detected",
        ),
    ];
    for (flag, name) in fake_fields {
        deny(*flag, name)?;
    }
    if report.entry_ready && report.status == EbpfReaderLabNextArcEntryStatus::EntryRejected {
        return Err("entry_ready must be false when status is EntryRejected".to_string());
    }
    Ok(())
}

/// Map status to label.
pub fn reader_lab_next_arc_entry_status_label(
    status: EbpfReaderLabNextArcEntryStatus,
) -> &'static str {
    status.as_str()
}

/// Map decision to label.
pub fn reader_lab_next_arc_entry_decision_label(
    decision: EbpfReaderLabNextArcEntryDecision,
) -> &'static str {
    decision.as_str()
}

/// Map finding kind to label.
pub fn reader_lab_next_arc_entry_finding_kind_label(
    kind: EbpfReaderLabNextArcEntryFindingKind,
) -> &'static str {
    kind.as_str()
}
