// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc review pack model for the Intergalaxion Engine (I-28).
//! Consumes I-21 through I-27 evidence to produce a deterministic internal review
//! pack that summarizes whether the selected next arc entry is safe,
//! experimental-only, release-forbidden, and still no-live-reader by default.
//! Next-arc-review-pack only, not a release, not a live reader, not a ring buffer reader.
//! release_allowed is always false. must_remain_experimental is always true.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::{
    validate_reader_lab_completion_review_pack, EbpfReaderLabCompletionReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    validate_reader_lab_next_arc_entry_gate_report, EbpfReaderLabNextArcEntryGateReport,
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

/// Status of the reader lab next arc review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcReviewPackStatus {
    Draft,
    Incomplete,
    Blocked,
    ReviewReady,
    ReviewRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}
impl EbpfReaderLabNextArcReviewPackStatus {
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

/// Decision produced by the reader lab next arc review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcReviewDecision {
    Stop,
    KeepExperimental,
    ReviewFixtureOnlyArc,
    ReviewStaticPolicyArc,
    ReviewManualReaderSpikeChecklistArc,
    ReviewReaderSpikeReviewArc,
    RejectLiveReaderArc,
    RejectPublicCliArc,
    RejectReleaseArc,
    RejectEnforcementArc,
}
impl EbpfReaderLabNextArcReviewDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepExperimental => "keep_experimental",
            Self::ReviewFixtureOnlyArc => "review_fixture_only_arc",
            Self::ReviewStaticPolicyArc => "review_static_policy_arc",
            Self::ReviewManualReaderSpikeChecklistArc => "review_manual_reader_spike_checklist_arc",
            Self::ReviewReaderSpikeReviewArc => "review_reader_spike_review_arc",
            Self::RejectLiveReaderArc => "reject_live_reader_arc",
            Self::RejectPublicCliArc => "reject_public_cli_arc",
            Self::RejectReleaseArc => "reject_release_arc",
            Self::RejectEnforcementArc => "reject_enforcement_arc",
        }
    }
}

/// Kind of next arc review pack finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcReviewFindingKind {
    NextArcPlan,
    StaticPolicyFreeze,
    StaticPolicyReview,
    StaticPolicyHardening,
    PolicyCompletionGate,
    CompletionReview,
    NextArcEntryGate,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    ReviewInvariant,
}
impl EbpfReaderLabNextArcReviewFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::StaticPolicyFreeze => "static_policy_freeze",
            Self::StaticPolicyReview => "static_policy_review",
            Self::StaticPolicyHardening => "static_policy_hardening",
            Self::PolicyCompletionGate => "policy_completion_gate",
            Self::CompletionReview => "completion_review",
            Self::NextArcEntryGate => "next_arc_entry_gate",
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

/// A single finding produced by the next arc review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcReviewFinding {
    pub code: String,
    pub kind: EbpfReaderLabNextArcReviewFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabNextArcReviewPackStatus,
}

/// Input to the reader lab next arc review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcReviewPackInput {
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    pub static_policy_freeze_record: EbpfReaderLabStaticPolicyFreezeRecord,
    pub static_policy_review_pack: EbpfReaderLabStaticPolicyReviewPack,
    pub static_policy_hardening_report: EbpfReaderLabStaticPolicyHardeningReport,
    pub policy_completion_gate_report: EbpfReaderLabPolicyCompletionGateReport,
    pub completion_review_pack: EbpfReaderLabCompletionReviewPack,
    pub next_arc_entry_gate_report: EbpfReaderLabNextArcEntryGateReport,
    pub require_next_arc_entry_ready: bool,
    pub require_completion_review_ready: bool,
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

/// Next arc review pack output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcReviewPack {
    pub phase: String,
    pub status: EbpfReaderLabNextArcReviewPackStatus,
    pub decision: EbpfReaderLabNextArcReviewDecision,
    pub review_ready: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabNextArcReviewFinding>,
    pub next_arc_entry_ready: bool,
    pub completion_review_ready: bool,
    pub policy_completion_passed: bool,
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
    pub fake_next_arc_review_success_detected: bool,
}

#[inline]
fn pf(
    findings: &mut Vec<EbpfReaderLabNextArcReviewFinding>,
    code: &str,
    kind: EbpfReaderLabNextArcReviewFindingKind,
    msg: &str,
    status: EbpfReaderLabNextArcReviewPackStatus,
) {
    findings.push(EbpfReaderLabNextArcReviewFinding {
        code: code.into(),
        kind,
        message: msg.into(),
        blocking: true,
        status,
    });
}

#[rustfmt::skip]
fn safe_base_pack() -> EbpfReaderLabNextArcReviewPack {
    EbpfReaderLabNextArcReviewPack {
        phase: "I-28".into(), status: EbpfReaderLabNextArcReviewPackStatus::Draft,
        decision: EbpfReaderLabNextArcReviewDecision::Stop, review_ready: false,
        release_allowed: false, must_remain_experimental: true, findings: Vec::new(),
        next_arc_entry_ready: false, completion_review_ready: false, policy_completion_passed: false,
        experimental_only_confirmed: false, selected_fixture_only_arc: false,
        selected_static_policy_arc: false, selected_manual_reader_spike_checklist_arc: false,
        selected_reader_spike_review_arc: false, live_reader_arc_allowed: false,
        public_cli_arc_allowed: false, release_arc_allowed: false, enforcement_arc_allowed: false,
        public_cli_exposed: false, usage_schema_changed: false, ledger_schema_changed: false,
        stable_release_requested: false, tag_requested: false, publish_requested: false,
        version_bump_requested: false, main_merge_requested: false,
        ring_buffer_opened: false, live_event_stream_read: false, map_pin_performed: false,
        enforcement_performed: false, packet_drop_performed: false, mutation_performed: false,
        persistence_performed: false, fake_reader_success_detected: false,
        fake_live_event_counts_detected: false, fake_release_readiness_detected: false,
        fake_planning_success_detected: false, fake_policy_freeze_success_detected: false,
        fake_policy_review_success_detected: false, fake_policy_hardening_success_detected: false,
        fake_policy_completion_success_detected: false, fake_completion_review_success_detected: false,
        fake_next_arc_entry_success_detected: false, fake_next_arc_review_success_detected: false,
    }
}

/// Returns a safe default input for the next arc review pack.
#[rustfmt::skip]
pub fn default_reader_lab_next_arc_review_pack_input() -> EbpfReaderLabNextArcReviewPackInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_completion_review_pack::{build_reader_lab_completion_review_pack, default_reader_lab_completion_review_pack_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_policy_completion_gate::{build_reader_lab_policy_completion_gate_report, default_reader_lab_policy_completion_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_freeze::{build_reader_lab_static_policy_freeze_record, default_reader_lab_static_policy_freeze_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_hardening::{build_reader_lab_static_policy_hardening_report, default_reader_lab_static_policy_hardening_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_static_policy_review_pack::{build_reader_lab_static_policy_review_pack, default_reader_lab_static_policy_review_pack_input};
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true;
    gi.prefer_fixture_only_arc = true;
    EbpfReaderLabNextArcReviewPackInput {
        next_arc_plan: build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input()),
        static_policy_freeze_record: build_reader_lab_static_policy_freeze_record(&default_reader_lab_static_policy_freeze_input()),
        static_policy_review_pack: build_reader_lab_static_policy_review_pack(&default_reader_lab_static_policy_review_pack_input()),
        static_policy_hardening_report: build_reader_lab_static_policy_hardening_report(&default_reader_lab_static_policy_hardening_input()),
        policy_completion_gate_report: build_reader_lab_policy_completion_gate_report(&default_reader_lab_policy_completion_gate_input()),
        completion_review_pack: build_reader_lab_completion_review_pack(&default_reader_lab_completion_review_pack_input()),
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        require_next_arc_entry_ready: false, require_completion_review_ready: false,
        require_policy_completion_passed: false, require_experimental_only: false,
        public_cli_expected_hidden: true, usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true, stable_release_requested: false,
        tag_requested: false, publish_requested: false, version_bump_requested: false,
        main_merge_requested: false,
    }
}

/// Build the next arc review pack from the given input.
#[rustfmt::skip]
pub fn build_reader_lab_next_arc_review_pack(input: &EbpfReaderLabNextArcReviewPackInput) -> EbpfReaderLabNextArcReviewPack {
    let mut pack = safe_base_pack();
    let mut findings: Vec<EbpfReaderLabNextArcReviewFinding> = Vec::new();
    let mut blocked = false;
    let inc = EbpfReaderLabNextArcReviewPackStatus::Incomplete;
    let blk = EbpfReaderLabNextArcReviewPackStatus::Blocked;
    let fe = EbpfReaderLabNextArcReviewFindingKind::FakeEvidenceInvariant;
    let ri = EbpfReaderLabNextArcReviewFindingKind::ReleaseInvariant;
    let rf = EbpfReaderLabNextArcReviewPackStatus::ReleaseForbidden;
    let plan_ok = validate_reader_lab_next_arc_plan(&input.next_arc_plan).is_ok();
    let freeze_ok = validate_reader_lab_static_policy_freeze_record(&input.static_policy_freeze_record).is_ok();
    let review_ok = validate_reader_lab_static_policy_review_pack(&input.static_policy_review_pack).is_ok();
    let hard_ok = validate_reader_lab_static_policy_hardening_report(&input.static_policy_hardening_report).is_ok();
    let gate_ok = validate_reader_lab_policy_completion_gate_report(&input.policy_completion_gate_report).is_ok();
    let crp_ok = validate_reader_lab_completion_review_pack(&input.completion_review_pack).is_ok();
    let eg_ok = validate_reader_lab_next_arc_entry_gate_report(&input.next_arc_entry_gate_report).is_ok();
    let evs: &[(&str, EbpfReaderLabNextArcReviewFindingKind, &str, bool)] = &[
        ("NARP-PLAN-INVALID", EbpfReaderLabNextArcReviewFindingKind::NextArcPlan, "next arc plan validation failed", plan_ok),
        ("NARP-FREEZE-INVALID", EbpfReaderLabNextArcReviewFindingKind::StaticPolicyFreeze, "static policy freeze validation failed", freeze_ok),
        ("NARP-REVIEW-INVALID", EbpfReaderLabNextArcReviewFindingKind::StaticPolicyReview, "static policy review validation failed", review_ok),
        ("NARP-HARDENING-INVALID", EbpfReaderLabNextArcReviewFindingKind::StaticPolicyHardening, "static policy hardening validation failed", hard_ok),
        ("NARP-GATE-INVALID", EbpfReaderLabNextArcReviewFindingKind::PolicyCompletionGate, "policy completion gate validation failed", gate_ok),
        ("NARP-CRP-INVALID", EbpfReaderLabNextArcReviewFindingKind::CompletionReview, "completion review pack validation failed", crp_ok),
        ("NARP-EG-INVALID", EbpfReaderLabNextArcReviewFindingKind::NextArcEntryGate, "next arc entry gate validation failed", eg_ok),
    ];
    for (code, kind, msg, ok) in evs { if !ok { pf(&mut findings, code, *kind, msg, inc); blocked = true; } }
    let eg = &input.next_arc_entry_gate_report;
    if input.require_next_arc_entry_ready && !eg.entry_ready { pf(&mut findings, "NARP-EG-NOT-READY", EbpfReaderLabNextArcReviewFindingKind::NextArcEntryGate, "next arc entry gate is not entry_ready", inc); blocked = true; }
    if input.require_completion_review_ready && !input.completion_review_pack.review_ready { pf(&mut findings, "NARP-CRP-NOT-READY", EbpfReaderLabNextArcReviewFindingKind::CompletionReview, "completion review pack is not review_ready", inc); blocked = true; }
    if input.require_policy_completion_passed && !input.policy_completion_gate_report.completion_passed { pf(&mut findings, "NARP-COMPLETION-NOT-PASSED", EbpfReaderLabNextArcReviewFindingKind::PolicyCompletionGate, "policy completion gate has not passed", inc); blocked = true; }
    if input.require_experimental_only {
        pack.experimental_only_confirmed = true;
        let h = &input.static_policy_hardening_report;
        let g = &input.policy_completion_gate_report;
        let c = &input.completion_review_pack;
        if !(input.next_arc_plan.must_remain_experimental && input.static_policy_freeze_record.must_remain_experimental && input.static_policy_review_pack.must_remain_experimental && h.must_remain_experimental && g.must_remain_experimental && c.must_remain_experimental && eg.must_remain_experimental) {
            pf(&mut findings, "NARP-NOT-EXPERIMENTAL", EbpfReaderLabNextArcReviewFindingKind::MutationInvariant, "evidence disagrees on must_remain_experimental", blk); blocked = true;
        }
    }
    if input.next_arc_plan.release_allowed || input.static_policy_freeze_record.release_allowed || input.static_policy_review_pack.release_allowed || input.static_policy_hardening_report.release_allowed || input.policy_completion_gate_report.release_allowed || input.completion_review_pack.release_allowed || eg.release_allowed {
        pf(&mut findings, "NARP-CONTRADICTION-RELEASE", ri, "evidence disagrees on release_allowed", blk); blocked = true;
    }
    if input.next_arc_plan.live_reader_next_allowed || input.static_policy_freeze_record.live_reader_next_allowed || input.static_policy_review_pack.live_reader_next_allowed || input.static_policy_hardening_report.live_reader_next_allowed || input.policy_completion_gate_report.live_reader_next_allowed || eg.live_reader_arc_allowed {
        pf(&mut findings, "NARP-CONTRADICTION-LIVE-READER", EbpfReaderLabNextArcReviewFindingKind::KernelInvariant, "evidence disagrees on live reader allowance", blk); blocked = true;
    }
    if input.next_arc_plan.public_cli_next_allowed || input.static_policy_freeze_record.public_cli_next_allowed || input.static_policy_review_pack.public_cli_next_allowed || input.static_policy_hardening_report.public_cli_next_allowed || input.policy_completion_gate_report.public_cli_next_allowed || eg.public_cli_arc_allowed {
        pf(&mut findings, "NARP-CONTRADICTION-PUBLIC-CLI", EbpfReaderLabNextArcReviewFindingKind::CliInvariant, "evidence disagrees on public cli allowance", blk); blocked = true;
    }
    if input.next_arc_plan.public_cli_exposed || input.static_policy_freeze_record.public_cli_exposed || input.static_policy_review_pack.public_cli_exposed || input.static_policy_hardening_report.public_cli_exposed || input.policy_completion_gate_report.public_cli_exposed || input.completion_review_pack.public_cli_exposed || eg.public_cli_exposed {
        pf(&mut findings, "NARP-CONTRADICTION-CLI-EXPOSED", EbpfReaderLabNextArcReviewFindingKind::CliInvariant, "evidence claims public cli exposed", blk); blocked = true;
    }
    if !input.public_cli_expected_hidden { pf(&mut findings, "NARP-CLI-NOT-HIDDEN", EbpfReaderLabNextArcReviewFindingKind::CliInvariant, "public cli expected hidden but was not", blk); blocked = true; }
    if !input.usage_schema_expected_unchanged { pf(&mut findings, "NARP-USAGE-SCHEMA-CHANGED", EbpfReaderLabNextArcReviewFindingKind::SchemaInvariant, "usage schema expected unchanged but was changed", blk); blocked = true; }
    if !input.ledger_schema_expected_unchanged { pf(&mut findings, "NARP-LEDGER-SCHEMA-CHANGED", EbpfReaderLabNextArcReviewFindingKind::SchemaInvariant, "ledger schema expected unchanged but was changed", blk); blocked = true; }
    if input.stable_release_requested { pf(&mut findings, "NARP-RELEASE-REQUESTED", ri, "stable release requested in experimental branch", rf); blocked = true; }
    if input.tag_requested { pf(&mut findings, "NARP-TAG-REQUESTED", ri, "tag requested in experimental branch", rf); blocked = true; }
    if input.publish_requested { pf(&mut findings, "NARP-PUBLISH-REQUESTED", ri, "publish requested in experimental branch", rf); blocked = true; }
    if input.version_bump_requested { pf(&mut findings, "NARP-VERSION-BUMP-REQUESTED", ri, "version bump requested in experimental branch", rf); blocked = true; }
    if input.main_merge_requested { pf(&mut findings, "NARP-MAIN-MERGE-REQUESTED", ri, "main merge requested in experimental branch", rf); blocked = true; }
    if eg.live_reader_arc_allowed { pf(&mut findings, "NARP-LIVE-READER-ARC", EbpfReaderLabNextArcReviewFindingKind::KernelInvariant, "live_reader_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcReviewDecision::RejectLiveReaderArc; }
    if eg.public_cli_arc_allowed { pf(&mut findings, "NARP-PUBLIC-CLI-ARC", EbpfReaderLabNextArcReviewFindingKind::CliInvariant, "public_cli_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcReviewDecision::RejectPublicCliArc; }
    if eg.release_arc_allowed { pf(&mut findings, "NARP-RELEASE-ARC", EbpfReaderLabNextArcReviewFindingKind::ReleaseInvariant, "release_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcReviewDecision::RejectReleaseArc; }
    if eg.enforcement_arc_allowed { pf(&mut findings, "NARP-ENFORCEMENT-ARC", EbpfReaderLabNextArcReviewFindingKind::MutationInvariant, "enforcement_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcReviewDecision::RejectEnforcementArc; }
    pack.ring_buffer_opened = eg.ring_buffer_opened;
    pack.live_event_stream_read = eg.live_event_stream_read;
    pack.map_pin_performed = eg.map_pin_performed;
    pack.enforcement_performed = eg.enforcement_performed;
    pack.packet_drop_performed = eg.packet_drop_performed;
    pack.mutation_performed = eg.mutation_performed;
    pack.persistence_performed = eg.persistence_performed;
    if eg.ring_buffer_opened || eg.live_event_stream_read || eg.map_pin_performed || eg.enforcement_performed || eg.packet_drop_performed || eg.mutation_performed || eg.persistence_performed {
        pf(&mut findings, "NARP-OP-FLAGS-TRUE", EbpfReaderLabNextArcReviewFindingKind::RuntimeInvariant, "operation flag is true in evidence", blk); blocked = true;
    }
    // Fake evidence across all 7 types
    let p = &input.next_arc_plan;
    let f = &input.static_policy_freeze_record;
    let rv = &input.static_policy_review_pack;
    let h = &input.static_policy_hardening_report;
    let g = &input.policy_completion_gate_report;
    let c = &input.completion_review_pack;
    macro_rules! fk { ($a:expr,$b:expr,$c2:expr,$d:expr,$e:expr,$fv:expr,$gv:expr,$code:expr,$msg:expr) => { if $a||$b||$c2||$d||$e||$fv||$gv { pf(&mut findings,$code,fe,$msg,blk); blocked=true; } } }
    fk!(p.fake_reader_success_detected,f.fake_reader_success_detected,rv.fake_reader_success_detected,h.fake_reader_success_detected,g.fake_reader_success_detected,c.fake_reader_success_detected,eg.fake_reader_success_detected,"NARP-FAKE-READER","fake reader execution success detected");
    fk!(p.fake_live_event_counts_detected,f.fake_live_event_counts_detected,rv.fake_live_event_counts_detected,h.fake_live_event_counts_detected,g.fake_live_event_counts_detected,c.fake_live_event_counts_detected,eg.fake_live_event_counts_detected,"NARP-FAKE-EVENTS","fake live event counts detected");
    fk!(p.fake_release_readiness_detected,f.fake_release_readiness_detected,rv.fake_release_readiness_detected,h.fake_release_readiness_detected,g.fake_release_readiness_detected,c.fake_release_readiness_detected,eg.fake_release_readiness_detected,"NARP-FAKE-RELEASE","fake release readiness detected");
    fk!(p.fake_planning_success_detected,f.fake_planning_success_detected,rv.fake_planning_success_detected,h.fake_planning_success_detected,g.fake_planning_success_detected,c.fake_planning_success_detected,eg.fake_planning_success_detected,"NARP-FAKE-PLANNING","fake planning success detected");
    fk!(false,f.fake_policy_freeze_success_detected,rv.fake_policy_freeze_success_detected,h.fake_policy_freeze_success_detected,g.fake_policy_freeze_success_detected,c.fake_policy_freeze_success_detected,eg.fake_policy_freeze_success_detected,"NARP-FAKE-POLICY-FREEZE","fake static policy freeze success detected");
    fk!(false,false,rv.fake_review_success_detected,h.fake_policy_review_success_detected,g.fake_policy_review_success_detected,c.fake_policy_review_success_detected,eg.fake_policy_review_success_detected,"NARP-FAKE-REVIEW","fake static policy review success detected");
    fk!(false,false,false,h.fake_hardening_success_detected,g.fake_policy_hardening_success_detected,c.fake_policy_hardening_success_detected,eg.fake_policy_hardening_success_detected,"NARP-FAKE-HARDENING","fake static policy hardening success detected");
    fk!(false,false,false,false,g.fake_completion_success_detected,c.fake_policy_completion_success_detected,eg.fake_policy_completion_success_detected,"NARP-FAKE-COMPLETION","fake policy freeze completion success detected");
    fk!(false,false,false,false,false,c.fake_completion_review_success_detected,eg.fake_completion_review_success_detected,"NARP-FAKE-COMPLETION-REVIEW","fake completion review success detected");
    if eg.fake_next_arc_entry_success_detected { pf(&mut findings,"NARP-FAKE-ENTRY",fe,"fake next arc entry success detected",blk); blocked=true; }
    // At least one safe selected arc
    let has_safe_arc = eg.selected_fixture_only_arc || eg.selected_static_policy_arc || eg.selected_manual_reader_spike_checklist_arc || eg.selected_reader_spike_review_arc;
    if !has_safe_arc && !blocked { pf(&mut findings,"NARP-NO-SAFE-ARC",EbpfReaderLabNextArcReviewFindingKind::ReviewInvariant,"at least one safe selected arc must be true in entry gate",inc); blocked=true; }
    // Propagate flags
    pack.selected_fixture_only_arc = eg.selected_fixture_only_arc;
    pack.selected_static_policy_arc = eg.selected_static_policy_arc;
    pack.selected_manual_reader_spike_checklist_arc = eg.selected_manual_reader_spike_checklist_arc;
    pack.selected_reader_spike_review_arc = eg.selected_reader_spike_review_arc;
    pack.live_reader_arc_allowed = eg.live_reader_arc_allowed;
    pack.public_cli_arc_allowed = eg.public_cli_arc_allowed;
    pack.release_arc_allowed = eg.release_arc_allowed;
    pack.enforcement_arc_allowed = eg.enforcement_arc_allowed;
    pack.public_cli_exposed = eg.public_cli_exposed;
    pack.usage_schema_changed = eg.usage_schema_changed;
    pack.ledger_schema_changed = eg.ledger_schema_changed;
    pack.stable_release_requested = input.stable_release_requested;
    pack.tag_requested = input.tag_requested;
    pack.publish_requested = input.publish_requested;
    pack.version_bump_requested = input.version_bump_requested;
    pack.main_merge_requested = input.main_merge_requested;
    pack.next_arc_entry_ready = eg.entry_ready;
    pack.completion_review_ready = input.completion_review_pack.review_ready;
    pack.policy_completion_passed = input.policy_completion_gate_report.completion_passed;
    // Propagate fake flags
    pack.fake_reader_success_detected = p.fake_reader_success_detected||f.fake_reader_success_detected||rv.fake_reader_success_detected||h.fake_reader_success_detected||g.fake_reader_success_detected||c.fake_reader_success_detected||eg.fake_reader_success_detected;
    pack.fake_live_event_counts_detected = p.fake_live_event_counts_detected||f.fake_live_event_counts_detected||rv.fake_live_event_counts_detected||h.fake_live_event_counts_detected||g.fake_live_event_counts_detected||c.fake_live_event_counts_detected||eg.fake_live_event_counts_detected;
    pack.fake_release_readiness_detected = p.fake_release_readiness_detected||f.fake_release_readiness_detected||rv.fake_release_readiness_detected||h.fake_release_readiness_detected||g.fake_release_readiness_detected||c.fake_release_readiness_detected||eg.fake_release_readiness_detected;
    pack.fake_planning_success_detected = p.fake_planning_success_detected||f.fake_planning_success_detected||rv.fake_planning_success_detected||h.fake_planning_success_detected||g.fake_planning_success_detected||c.fake_planning_success_detected||eg.fake_planning_success_detected;
    pack.fake_policy_freeze_success_detected = f.fake_policy_freeze_success_detected||rv.fake_policy_freeze_success_detected||h.fake_policy_freeze_success_detected||g.fake_policy_freeze_success_detected||c.fake_policy_freeze_success_detected||eg.fake_policy_freeze_success_detected;
    pack.fake_policy_review_success_detected = rv.fake_review_success_detected||h.fake_policy_review_success_detected||g.fake_policy_review_success_detected||c.fake_policy_review_success_detected||eg.fake_policy_review_success_detected;
    pack.fake_policy_hardening_success_detected = h.fake_hardening_success_detected||g.fake_policy_hardening_success_detected||c.fake_policy_hardening_success_detected||eg.fake_policy_hardening_success_detected;
    pack.fake_policy_completion_success_detected = g.fake_completion_success_detected||c.fake_policy_completion_success_detected||eg.fake_policy_completion_success_detected;
    pack.fake_completion_review_success_detected = c.fake_completion_review_success_detected||eg.fake_completion_review_success_detected;
    pack.fake_next_arc_entry_success_detected = eg.fake_next_arc_entry_success_detected;
    if !input.require_experimental_only { pf(&mut findings,"NARP-NO-EXPERIMENTAL-CONFIRM",EbpfReaderLabNextArcReviewFindingKind::ReviewInvariant,"experimental-only confirmation not provided",EbpfReaderLabNextArcReviewPackStatus::ExperimentalOnly); blocked=true; }
    // Status determination
    if blocked {
        let has_rel = input.stable_release_requested||input.tag_requested||input.publish_requested||input.version_bump_requested||input.main_merge_requested;
        let has_exp = !input.require_experimental_only;
        let has_dis = eg.live_reader_arc_allowed||eg.public_cli_arc_allowed||eg.release_arc_allowed||eg.enforcement_arc_allowed;
        let all_inv = !plan_ok&&!freeze_ok&&!review_ok&&!hard_ok&&!gate_ok&&!crp_ok&&!eg_ok;
        if has_rel { pack.status = EbpfReaderLabNextArcReviewPackStatus::ReleaseForbidden; if !has_dis { pack.decision = EbpfReaderLabNextArcReviewDecision::RejectReleaseArc; } }
        else if has_dis { pack.status = EbpfReaderLabNextArcReviewPackStatus::Blocked; }
        else if has_exp && all_inv { pack.status = EbpfReaderLabNextArcReviewPackStatus::Incomplete; pack.decision = EbpfReaderLabNextArcReviewDecision::Stop; }
        else if has_exp { pack.status = EbpfReaderLabNextArcReviewPackStatus::ExperimentalOnly; pack.decision = EbpfReaderLabNextArcReviewDecision::KeepExperimental; }
        else { pack.status = EbpfReaderLabNextArcReviewPackStatus::ReviewRejected; pack.decision = EbpfReaderLabNextArcReviewDecision::Stop; }
    } else {
        pack.status = EbpfReaderLabNextArcReviewPackStatus::ReviewReady;
        pack.review_ready = true;
        if eg.selected_static_policy_arc { pack.decision = EbpfReaderLabNextArcReviewDecision::ReviewStaticPolicyArc; }
        else if eg.selected_fixture_only_arc { pack.decision = EbpfReaderLabNextArcReviewDecision::ReviewFixtureOnlyArc; }
        else if eg.selected_manual_reader_spike_checklist_arc { pack.decision = EbpfReaderLabNextArcReviewDecision::ReviewManualReaderSpikeChecklistArc; }
        else if eg.selected_reader_spike_review_arc { pack.decision = EbpfReaderLabNextArcReviewDecision::ReviewReaderSpikeReviewArc; }
        else { pack.status = EbpfReaderLabNextArcReviewPackStatus::ReviewRejected; pack.decision = EbpfReaderLabNextArcReviewDecision::Stop; pack.review_ready = false; }
    }
    pack.findings = findings;
    pack
}

/// Validate a next arc review pack.
pub fn validate_reader_lab_next_arc_review_pack(
    pack: &EbpfReaderLabNextArcReviewPack,
) -> Result<(), String> {
    if pack.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-28"))
        } else {
            Ok(())
        }
    };
    deny(pack.release_allowed, "release_allowed")?;
    deny(!pack.must_remain_experimental, "must_remain_experimental")?;
    deny(pack.live_reader_arc_allowed, "live_reader_arc_allowed")?;
    deny(pack.public_cli_arc_allowed, "public_cli_arc_allowed")?;
    deny(pack.release_arc_allowed, "release_arc_allowed")?;
    deny(pack.enforcement_arc_allowed, "enforcement_arc_allowed")?;
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
    let fakes: &[(bool, &str)] = &[
        (
            pack.fake_reader_success_detected,
            "fake_reader_success_detected",
        ),
        (
            pack.fake_live_event_counts_detected,
            "fake_live_event_counts_detected",
        ),
        (
            pack.fake_release_readiness_detected,
            "fake_release_readiness_detected",
        ),
        (
            pack.fake_planning_success_detected,
            "fake_planning_success_detected",
        ),
        (
            pack.fake_policy_freeze_success_detected,
            "fake_policy_freeze_success_detected",
        ),
        (
            pack.fake_policy_review_success_detected,
            "fake_policy_review_success_detected",
        ),
        (
            pack.fake_policy_hardening_success_detected,
            "fake_policy_hardening_success_detected",
        ),
        (
            pack.fake_policy_completion_success_detected,
            "fake_policy_completion_success_detected",
        ),
        (
            pack.fake_completion_review_success_detected,
            "fake_completion_review_success_detected",
        ),
        (
            pack.fake_next_arc_entry_success_detected,
            "fake_next_arc_entry_success_detected",
        ),
        (
            pack.fake_next_arc_review_success_detected,
            "fake_next_arc_review_success_detected",
        ),
    ];
    for (flag, name) in fakes {
        deny(*flag, name)?;
    }
    if pack.review_ready && pack.status == EbpfReaderLabNextArcReviewPackStatus::ReviewRejected {
        return Err("review_ready must be false when status is ReviewRejected".to_string());
    }
    Ok(())
}

/// Map review pack status to label.
pub fn reader_lab_next_arc_review_pack_status_label(
    status: EbpfReaderLabNextArcReviewPackStatus,
) -> &'static str {
    status.as_str()
}

/// Map review decision to label.
pub fn reader_lab_next_arc_review_decision_label(
    decision: EbpfReaderLabNextArcReviewDecision,
) -> &'static str {
    decision.as_str()
}

/// Map review finding kind to label.
pub fn reader_lab_next_arc_review_finding_kind_label(
    kind: EbpfReaderLabNextArcReviewFindingKind,
) -> &'static str {
    kind.as_str()
}
