// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc static freeze model for the Intergalaxion Engine (I-29).
//! Consumes I-27 entry gate report and I-28 review pack evidence to produce a
//! deterministic static freeze record. Static freeze only, not a release,
//! not a live reader, not a ring buffer reader.
//! release_allowed is always false. must_remain_experimental is always true.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    validate_reader_lab_next_arc_entry_gate_report, EbpfReaderLabNextArcEntryGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    validate_reader_lab_next_arc_review_pack, EbpfReaderLabNextArcReviewPack,
};

/// Status of the reader lab next arc static freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcStaticFreezeStatus {
    Draft,
    Incomplete,
    Blocked,
    Frozen,
    FreezeRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}
impl EbpfReaderLabNextArcStaticFreezeStatus {
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

/// Decision produced by the reader lab next arc static freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcStaticFreezeDecision {
    Stop,
    KeepExperimental,
    FreezeFixtureOnlyArc,
    FreezeStaticPolicyArc,
    FreezeManualReaderSpikeChecklistArc,
    FreezeReaderSpikeReviewArc,
    RejectLiveReaderArc,
    RejectPublicCliArc,
    RejectReleaseArc,
    RejectEnforcementArc,
}
impl EbpfReaderLabNextArcStaticFreezeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepExperimental => "keep_experimental",
            Self::FreezeFixtureOnlyArc => "freeze_fixture_only_arc",
            Self::FreezeStaticPolicyArc => "freeze_static_policy_arc",
            Self::FreezeManualReaderSpikeChecklistArc => "freeze_manual_reader_spike_checklist_arc",
            Self::FreezeReaderSpikeReviewArc => "freeze_reader_spike_review_arc",
            Self::RejectLiveReaderArc => "reject_live_reader_arc",
            Self::RejectPublicCliArc => "reject_public_cli_arc",
            Self::RejectReleaseArc => "reject_release_arc",
            Self::RejectEnforcementArc => "reject_enforcement_arc",
        }
    }
}

/// Kind of next arc static freeze finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcStaticFreezeFindingKind {
    NextArcEntryGate,
    NextArcReviewPack,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    FreezeInvariant,
}
impl EbpfReaderLabNextArcStaticFreezeFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcEntryGate => "next_arc_entry_gate",
            Self::NextArcReviewPack => "next_arc_review_pack",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::FreezeInvariant => "freeze_invariant",
        }
    }
}

/// A single finding produced by the next arc static freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcStaticFreezeFinding {
    pub code: String,
    pub kind: EbpfReaderLabNextArcStaticFreezeFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabNextArcStaticFreezeStatus,
}

/// Input to the reader lab next arc static freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcStaticFreezeInput {
    pub next_arc_entry_gate_report: EbpfReaderLabNextArcEntryGateReport,
    pub next_arc_review_pack: EbpfReaderLabNextArcReviewPack,
    pub require_next_arc_entry_ready: bool,
    pub require_next_arc_review_ready: bool,
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

/// Next arc static freeze output record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcStaticFreezeRecord {
    pub phase: String,
    pub status: EbpfReaderLabNextArcStaticFreezeStatus,
    pub decision: EbpfReaderLabNextArcStaticFreezeDecision,
    pub freeze_passed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabNextArcStaticFreezeFinding>,
    pub next_arc_entry_ready: bool,
    pub next_arc_review_ready: bool,
    pub experimental_only_confirmed: bool,
    pub frozen_fixture_only_arc: bool,
    pub frozen_static_policy_arc: bool,
    pub frozen_manual_reader_spike_checklist_arc: bool,
    pub frozen_reader_spike_review_arc: bool,
    pub arc_allowed_live_reader: bool,
    pub arc_allowed_public_cli: bool,
    pub arc_allowed_release: bool,
    pub arc_allowed_enforcement: bool,
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
    pub fake_next_arc_static_freeze_success_detected: bool,
}

// -- Helper: push a blocking finding --
#[inline]
fn pf(
    findings: &mut Vec<EbpfReaderLabNextArcStaticFreezeFinding>,
    code: &str,
    kind: EbpfReaderLabNextArcStaticFreezeFindingKind,
    msg: &str,
    status: EbpfReaderLabNextArcStaticFreezeStatus,
) {
    findings.push(EbpfReaderLabNextArcStaticFreezeFinding {
        code: code.into(),
        kind,
        message: msg.into(),
        blocking: true,
        status,
    });
}

#[rustfmt::skip]
fn safe_base_record() -> EbpfReaderLabNextArcStaticFreezeRecord {
    EbpfReaderLabNextArcStaticFreezeRecord {
        phase: "I-29".into(), status: EbpfReaderLabNextArcStaticFreezeStatus::Draft,
        decision: EbpfReaderLabNextArcStaticFreezeDecision::Stop, freeze_passed: false,
        release_allowed: false, must_remain_experimental: true, findings: Vec::new(),
        next_arc_entry_ready: false, next_arc_review_ready: false,
        experimental_only_confirmed: false, frozen_fixture_only_arc: false,
        frozen_static_policy_arc: false, frozen_manual_reader_spike_checklist_arc: false,
        frozen_reader_spike_review_arc: false, arc_allowed_live_reader: false,
        arc_allowed_public_cli: false, arc_allowed_release: false,
        arc_allowed_enforcement: false, public_cli_exposed: false,
        usage_schema_changed: false, ledger_schema_changed: false,
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
        fake_next_arc_static_freeze_success_detected: false,
    }
}

/// Returns a safe default input for the next arc static freeze.
#[rustfmt::skip]
pub fn default_reader_lab_next_arc_static_freeze_input() -> EbpfReaderLabNextArcStaticFreezeInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input};
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true;
    gi.prefer_fixture_only_arc = true;
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    EbpfReaderLabNextArcStaticFreezeInput {
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        next_arc_review_pack: build_reader_lab_next_arc_review_pack(&ri),
        require_next_arc_entry_ready: false,
        require_next_arc_review_ready: false,
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

/// Build the next arc static freeze record from the given input.
#[rustfmt::skip]
pub fn build_reader_lab_next_arc_static_freeze_record(
    input: &EbpfReaderLabNextArcStaticFreezeInput,
) -> EbpfReaderLabNextArcStaticFreezeRecord {
    let mut rec = safe_base_record();
    let mut findings: Vec<EbpfReaderLabNextArcStaticFreezeFinding> = Vec::new();
    let mut blocked = false;
    let inc = EbpfReaderLabNextArcStaticFreezeStatus::Incomplete;
    let blk = EbpfReaderLabNextArcStaticFreezeStatus::Blocked;
    let fe = EbpfReaderLabNextArcStaticFreezeFindingKind::FakeEvidenceInvariant;
    let ri = EbpfReaderLabNextArcStaticFreezeFindingKind::ReleaseInvariant;
    let rf = EbpfReaderLabNextArcStaticFreezeStatus::ReleaseForbidden;
    let eg = &input.next_arc_entry_gate_report;
    let rp = &input.next_arc_review_pack;
    // Validate both evidence
    let eg_ok = validate_reader_lab_next_arc_entry_gate_report(eg).is_ok();
    let rp_ok = validate_reader_lab_next_arc_review_pack(rp).is_ok();
    if !eg_ok { pf(&mut findings, "NASF-EG-INVALID", EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcEntryGate, "entry gate report validation failed", inc); blocked = true; }
    if !rp_ok { pf(&mut findings, "NASF-RP-INVALID", EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcReviewPack, "review pack validation failed", inc); blocked = true; }
    // Require flags
    if input.require_next_arc_entry_ready && !eg.entry_ready { pf(&mut findings, "NASF-EG-NOT-READY", EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcEntryGate, "entry gate report is not entry_ready", inc); blocked = true; }
    if input.require_next_arc_review_ready && !rp.review_ready { pf(&mut findings, "NASF-RP-NOT-READY", EbpfReaderLabNextArcStaticFreezeFindingKind::NextArcReviewPack, "review pack is not review_ready", inc); blocked = true; }
    // Experimental only cross-evidence check
    if input.require_experimental_only {
        rec.experimental_only_confirmed = true;
        if !(eg.must_remain_experimental && rp.must_remain_experimental) {
            pf(&mut findings, "NASF-NOT-EXPERIMENTAL", EbpfReaderLabNextArcStaticFreezeFindingKind::MutationInvariant, "evidence disagrees on must_remain_experimental", blk); blocked = true;
        }
    }
    // Release invariant cross-evidence
    if eg.release_allowed || rp.release_allowed {
        pf(&mut findings, "NASF-CONTRADICTION-RELEASE", ri, "evidence disagrees on release_allowed", blk); blocked = true;
    }
    // Live reader cross-evidence
    if eg.live_reader_arc_allowed || rp.live_reader_arc_allowed {
        pf(&mut findings, "NASF-CONTRADICTION-LIVE-READER", EbpfReaderLabNextArcStaticFreezeFindingKind::KernelInvariant, "evidence disagrees on live reader allowance", blk); blocked = true;
    }
    // Public CLI cross-evidence
    if eg.public_cli_arc_allowed || rp.public_cli_arc_allowed {
        pf(&mut findings, "NASF-CONTRADICTION-PUBLIC-CLI", EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant, "evidence disagrees on public cli allowance", blk); blocked = true;
    }
    // CLI exposed cross-evidence
    if eg.public_cli_exposed || rp.public_cli_exposed {
        pf(&mut findings, "NASF-CONTRADICTION-CLI-EXPOSED", EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant, "evidence claims public cli exposed", blk); blocked = true;
    }
    // Schema expectations
    if !input.public_cli_expected_hidden { pf(&mut findings, "NASF-CLI-NOT-HIDDEN", EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant, "public cli expected hidden but was not", blk); blocked = true; }
    if !input.usage_schema_expected_unchanged { pf(&mut findings, "NASF-USAGE-SCHEMA-CHANGED", EbpfReaderLabNextArcStaticFreezeFindingKind::SchemaInvariant, "usage schema expected unchanged but was changed", blk); blocked = true; }
    if !input.ledger_schema_expected_unchanged { pf(&mut findings, "NASF-LEDGER-SCHEMA-CHANGED", EbpfReaderLabNextArcStaticFreezeFindingKind::SchemaInvariant, "ledger schema expected unchanged but was changed", blk); blocked = true; }
    // Release invariants from input
    if input.stable_release_requested { pf(&mut findings, "NASF-RELEASE-REQUESTED", ri, "stable release requested in experimental branch", rf); blocked = true; }
    if input.tag_requested { pf(&mut findings, "NASF-TAG-REQUESTED", ri, "tag requested in experimental branch", rf); blocked = true; }
    if input.publish_requested { pf(&mut findings, "NASF-PUBLISH-REQUESTED", ri, "publish requested in experimental branch", rf); blocked = true; }
    if input.version_bump_requested { pf(&mut findings, "NASF-VERSION-BUMP-REQUESTED", ri, "version bump requested in experimental branch", rf); blocked = true; }
    if input.main_merge_requested { pf(&mut findings, "NASF-MAIN-MERGE-REQUESTED", ri, "main merge requested in experimental branch", rf); blocked = true; }
    // Forbidden arc allowances from evidence
    if eg.live_reader_arc_allowed { pf(&mut findings, "NASF-LIVE-READER-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::KernelInvariant, "live_reader_arc_allowed is not allowed", blk); blocked = true; rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::RejectLiveReaderArc; }
    if eg.public_cli_arc_allowed { pf(&mut findings, "NASF-PUBLIC-CLI-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant, "public_cli_arc_allowed is not allowed", blk); blocked = true; rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::RejectPublicCliArc; }
    if eg.release_arc_allowed { pf(&mut findings, "NASF-RELEASE-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::ReleaseInvariant, "release_arc_allowed is not allowed", blk); blocked = true; rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::RejectReleaseArc; }
    if eg.enforcement_arc_allowed { pf(&mut findings, "NASF-ENFORCEMENT-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::MutationInvariant, "enforcement_arc_allowed is not allowed", blk); blocked = true; rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::RejectEnforcementArc; }
    if rp.live_reader_arc_allowed { pf(&mut findings, "NASF-RP-LIVE-READER-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::KernelInvariant, "review pack live_reader_arc_allowed is not allowed", blk); blocked = true; }
    if rp.public_cli_arc_allowed { pf(&mut findings, "NASF-RP-PUBLIC-CLI-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::CliInvariant, "review pack public_cli_arc_allowed is not allowed", blk); blocked = true; }
    if rp.release_arc_allowed { pf(&mut findings, "NASF-RP-RELEASE-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::ReleaseInvariant, "review pack release_arc_allowed is not allowed", blk); blocked = true; }
    if rp.enforcement_arc_allowed { pf(&mut findings, "NASF-RP-ENFORCEMENT-ARC", EbpfReaderLabNextArcStaticFreezeFindingKind::MutationInvariant, "review pack enforcement_arc_allowed is not allowed", blk); blocked = true; }
    // Operation flags from evidence
    rec.ring_buffer_opened = eg.ring_buffer_opened || rp.ring_buffer_opened;
    rec.live_event_stream_read = eg.live_event_stream_read || rp.live_event_stream_read;
    rec.map_pin_performed = eg.map_pin_performed || rp.map_pin_performed;
    rec.enforcement_performed = eg.enforcement_performed || rp.enforcement_performed;
    rec.packet_drop_performed = eg.packet_drop_performed || rp.packet_drop_performed;
    rec.mutation_performed = eg.mutation_performed || rp.mutation_performed;
    rec.persistence_performed = eg.persistence_performed || rp.persistence_performed;
    if rec.ring_buffer_opened || rec.live_event_stream_read || rec.map_pin_performed || rec.enforcement_performed || rec.packet_drop_performed || rec.mutation_performed || rec.persistence_performed {
        pf(&mut findings, "NASF-OP-FLAGS-TRUE", EbpfReaderLabNextArcStaticFreezeFindingKind::RuntimeInvariant, "operation flag is true in evidence", blk); blocked = true;
    }
    // Fake evidence across both evidence types
    macro_rules! fk2 { ($a:expr,$b:expr,$code:expr,$msg:expr) => { if $a||$b { pf(&mut findings,$code,fe,$msg,blk); blocked=true; } } }
    fk2!(eg.fake_reader_success_detected,rp.fake_reader_success_detected,"NASF-FAKE-READER","fake reader execution success detected");
    fk2!(eg.fake_live_event_counts_detected,rp.fake_live_event_counts_detected,"NASF-FAKE-EVENTS","fake live event counts detected");
    fk2!(eg.fake_release_readiness_detected,rp.fake_release_readiness_detected,"NASF-FAKE-RELEASE","fake release readiness detected");
    fk2!(eg.fake_planning_success_detected,rp.fake_planning_success_detected,"NASF-FAKE-PLANNING","fake planning success detected");
    fk2!(eg.fake_policy_freeze_success_detected,rp.fake_policy_freeze_success_detected,"NASF-FAKE-POLICY-FREEZE","fake static policy freeze success detected");
    fk2!(eg.fake_policy_review_success_detected,rp.fake_policy_review_success_detected,"NASF-FAKE-REVIEW","fake static policy review success detected");
    fk2!(eg.fake_policy_hardening_success_detected,rp.fake_policy_hardening_success_detected,"NASF-FAKE-HARDENING","fake static policy hardening success detected");
    fk2!(eg.fake_policy_completion_success_detected,rp.fake_policy_completion_success_detected,"NASF-FAKE-COMPLETION","fake policy completion success detected");
    fk2!(eg.fake_completion_review_success_detected,rp.fake_completion_review_success_detected,"NASF-FAKE-COMPLETION-REVIEW","fake completion review success detected");
    fk2!(eg.fake_next_arc_entry_success_detected,rp.fake_next_arc_entry_success_detected,"NASF-FAKE-ENTRY","fake next arc entry success detected");
    if rp.fake_next_arc_review_success_detected { pf(&mut findings,"NASF-FAKE-REVIEW-PACK",fe,"fake next arc review success detected",blk); blocked=true; }
    // Propagate arc allowances
    rec.arc_allowed_live_reader = eg.live_reader_arc_allowed || rp.live_reader_arc_allowed;
    rec.arc_allowed_public_cli = eg.public_cli_arc_allowed || rp.public_cli_arc_allowed;
    rec.arc_allowed_release = eg.release_arc_allowed || rp.release_arc_allowed;
    rec.arc_allowed_enforcement = eg.enforcement_arc_allowed || rp.enforcement_arc_allowed;
    rec.public_cli_exposed = eg.public_cli_exposed || rp.public_cli_exposed;
    rec.usage_schema_changed = eg.usage_schema_changed || rp.usage_schema_changed;
    rec.ledger_schema_changed = eg.ledger_schema_changed || rp.ledger_schema_changed;
    rec.stable_release_requested = input.stable_release_requested;
    rec.tag_requested = input.tag_requested;
    rec.publish_requested = input.publish_requested;
    rec.version_bump_requested = input.version_bump_requested;
    rec.main_merge_requested = input.main_merge_requested;
    rec.next_arc_entry_ready = eg.entry_ready;
    rec.next_arc_review_ready = rp.review_ready;
    // Propagate fake flags
    rec.fake_reader_success_detected = eg.fake_reader_success_detected || rp.fake_reader_success_detected;
    rec.fake_live_event_counts_detected = eg.fake_live_event_counts_detected || rp.fake_live_event_counts_detected;
    rec.fake_release_readiness_detected = eg.fake_release_readiness_detected || rp.fake_release_readiness_detected;
    rec.fake_planning_success_detected = eg.fake_planning_success_detected || rp.fake_planning_success_detected;
    rec.fake_policy_freeze_success_detected = eg.fake_policy_freeze_success_detected || rp.fake_policy_freeze_success_detected;
    rec.fake_policy_review_success_detected = eg.fake_policy_review_success_detected || rp.fake_policy_review_success_detected;
    rec.fake_policy_hardening_success_detected = eg.fake_policy_hardening_success_detected || rp.fake_policy_hardening_success_detected;
    rec.fake_policy_completion_success_detected = eg.fake_policy_completion_success_detected || rp.fake_policy_completion_success_detected;
    rec.fake_completion_review_success_detected = eg.fake_completion_review_success_detected || rp.fake_completion_review_success_detected;
    rec.fake_next_arc_entry_success_detected = eg.fake_next_arc_entry_success_detected || rp.fake_next_arc_entry_success_detected;
    rec.fake_next_arc_review_success_detected = rp.fake_next_arc_review_success_detected;
    // Require experimental only check
    if !input.require_experimental_only { pf(&mut findings,"NASF-NO-EXPERIMENTAL-CONFIRM",EbpfReaderLabNextArcStaticFreezeFindingKind::FreezeInvariant,"experimental-only confirmation not provided",EbpfReaderLabNextArcStaticFreezeStatus::ExperimentalOnly); blocked=true; }
    // Frozen arc selection based on I-28 review pack selected arcs (priority order)
    let has_safe_arc = rp.selected_fixture_only_arc || rp.selected_static_policy_arc
        || rp.selected_manual_reader_spike_checklist_arc || rp.selected_reader_spike_review_arc;
    if !has_safe_arc && !blocked {
        pf(&mut findings,"NASF-NO-SAFE-ARC",EbpfReaderLabNextArcStaticFreezeFindingKind::FreezeInvariant,"at least one safe selected arc must be true in review pack",inc);
        blocked = true;
    }
    rec.frozen_static_policy_arc = rp.selected_static_policy_arc;
    rec.frozen_fixture_only_arc = rp.selected_fixture_only_arc;
    rec.frozen_manual_reader_spike_checklist_arc = rp.selected_manual_reader_spike_checklist_arc;
    rec.frozen_reader_spike_review_arc = rp.selected_reader_spike_review_arc;
    // Status determination
    if blocked {
        let has_rel = input.stable_release_requested || input.tag_requested || input.publish_requested
            || input.version_bump_requested || input.main_merge_requested;
        let has_exp = !input.require_experimental_only;
        let has_dis = eg.live_reader_arc_allowed || eg.public_cli_arc_allowed || eg.release_arc_allowed
            || eg.enforcement_arc_allowed || rp.live_reader_arc_allowed || rp.public_cli_arc_allowed
            || rp.release_arc_allowed || rp.enforcement_arc_allowed;
        let all_inv = !eg_ok && !rp_ok;
        if has_rel {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::ReleaseForbidden;
            if !has_dis { rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::RejectReleaseArc; }
        } else if has_dis {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Blocked;
        } else if has_exp && all_inv {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Incomplete;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::Stop;
        } else if has_exp {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::ExperimentalOnly;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::KeepExperimental;
        } else {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::Stop;
        }
    } else {
        // All checks passed - determine frozen arc by priority
        if rp.selected_static_policy_arc {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Frozen;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::FreezeStaticPolicyArc;
        } else if rp.selected_fixture_only_arc {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Frozen;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::FreezeFixtureOnlyArc;
        } else if rp.selected_manual_reader_spike_checklist_arc {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Frozen;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::FreezeManualReaderSpikeChecklistArc;
        } else if rp.selected_reader_spike_review_arc {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::Frozen;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::FreezeReaderSpikeReviewArc;
        } else {
            rec.status = EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected;
            rec.decision = EbpfReaderLabNextArcStaticFreezeDecision::Stop;
        }
        if rec.status == EbpfReaderLabNextArcStaticFreezeStatus::Frozen {
            rec.freeze_passed = true;
        }
    }
    rec.findings = findings;
    rec
}

/// Validate a next arc static freeze record.
pub fn validate_reader_lab_next_arc_static_freeze_record(
    rec: &EbpfReaderLabNextArcStaticFreezeRecord,
) -> Result<(), String> {
    if rec.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-29"))
        } else {
            Ok(())
        }
    };
    deny(rec.release_allowed, "release_allowed")?;
    deny(!rec.must_remain_experimental, "must_remain_experimental")?;
    deny(rec.arc_allowed_live_reader, "arc_allowed_live_reader")?;
    deny(rec.arc_allowed_public_cli, "arc_allowed_public_cli")?;
    deny(rec.arc_allowed_release, "arc_allowed_release")?;
    deny(rec.arc_allowed_enforcement, "arc_allowed_enforcement")?;
    deny(rec.public_cli_exposed, "public_cli_exposed")?;
    deny(rec.usage_schema_changed, "usage_schema_changed")?;
    deny(rec.ledger_schema_changed, "ledger_schema_changed")?;
    deny(rec.stable_release_requested, "stable_release_requested")?;
    deny(rec.tag_requested, "tag_requested")?;
    deny(rec.publish_requested, "publish_requested")?;
    deny(rec.version_bump_requested, "version_bump_requested")?;
    deny(rec.main_merge_requested, "main_merge_requested")?;
    deny(rec.ring_buffer_opened, "ring_buffer_opened")?;
    deny(rec.live_event_stream_read, "live_event_stream_read")?;
    deny(rec.map_pin_performed, "map_pin_performed")?;
    deny(rec.enforcement_performed, "enforcement_performed")?;
    deny(rec.packet_drop_performed, "packet_drop_performed")?;
    deny(rec.mutation_performed, "mutation_performed")?;
    deny(rec.persistence_performed, "persistence_performed")?;
    let fakes: &[(bool, &str)] = &[
        (
            rec.fake_reader_success_detected,
            "fake_reader_success_detected",
        ),
        (
            rec.fake_live_event_counts_detected,
            "fake_live_event_counts_detected",
        ),
        (
            rec.fake_release_readiness_detected,
            "fake_release_readiness_detected",
        ),
        (
            rec.fake_planning_success_detected,
            "fake_planning_success_detected",
        ),
        (
            rec.fake_policy_freeze_success_detected,
            "fake_policy_freeze_success_detected",
        ),
        (
            rec.fake_policy_review_success_detected,
            "fake_policy_review_success_detected",
        ),
        (
            rec.fake_policy_hardening_success_detected,
            "fake_policy_hardening_success_detected",
        ),
        (
            rec.fake_policy_completion_success_detected,
            "fake_policy_completion_success_detected",
        ),
        (
            rec.fake_completion_review_success_detected,
            "fake_completion_review_success_detected",
        ),
        (
            rec.fake_next_arc_entry_success_detected,
            "fake_next_arc_entry_success_detected",
        ),
        (
            rec.fake_next_arc_review_success_detected,
            "fake_next_arc_review_success_detected",
        ),
        (
            rec.fake_next_arc_static_freeze_success_detected,
            "fake_next_arc_static_freeze_success_detected",
        ),
    ];
    for (flag, name) in fakes {
        deny(*flag, name)?;
    }
    if rec.freeze_passed && rec.status == EbpfReaderLabNextArcStaticFreezeStatus::FreezeRejected {
        return Err("freeze_passed must be false when status is FreezeRejected".to_string());
    }
    Ok(())
}

/// Map static freeze status to label.
pub fn reader_lab_next_arc_static_freeze_status_label(
    status: EbpfReaderLabNextArcStaticFreezeStatus,
) -> &'static str {
    status.as_str()
}

/// Map static freeze decision to label.
pub fn reader_lab_next_arc_static_freeze_decision_label(
    decision: EbpfReaderLabNextArcStaticFreezeDecision,
) -> &'static str {
    decision.as_str()
}

/// Map static freeze finding kind to label.
pub fn reader_lab_next_arc_static_freeze_finding_kind_label(
    kind: EbpfReaderLabNextArcStaticFreezeFindingKind,
) -> &'static str {
    kind.as_str()
}
