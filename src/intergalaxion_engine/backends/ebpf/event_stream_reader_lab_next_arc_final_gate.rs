// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc final gate model for the Intergalaxion Engine (I-31).
//! Consumes I-27 entry gate report, I-28 review pack, I-29 static freeze
//! record, and I-30 freeze review pack evidence to produce a deterministic
//! final gate report. Final gate only, not a release, not a live reader,
//! not a ring buffer reader.
//! release_allowed is always false. must_remain_experimental is always true.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    validate_reader_lab_next_arc_entry_gate_report, EbpfReaderLabNextArcEntryGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_freeze_review_pack::{
    validate_reader_lab_next_arc_freeze_review_pack, EbpfReaderLabNextArcFreezeReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    validate_reader_lab_next_arc_review_pack, EbpfReaderLabNextArcReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{
    validate_reader_lab_next_arc_static_freeze_record, EbpfReaderLabNextArcStaticFreezeRecord,
};

/// Status of the reader lab next arc final gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFinalGateStatus {
    Draft,
    Incomplete,
    Blocked,
    Finalized,
    FinalRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}
impl EbpfReaderLabNextArcFinalGateStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Incomplete => "incomplete",
            Self::Blocked => "blocked",
            Self::Finalized => "finalized",
            Self::FinalRejected => "final_rejected",
            Self::ExperimentalOnly => "experimental_only",
            Self::ReleaseForbidden => "release_forbidden",
        }
    }
}

/// Decision produced by the reader lab next arc final gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFinalDecision {
    Stop,
    KeepExperimental,
    FinalizeFixtureOnlyArc,
    FinalizeStaticPolicyArc,
    FinalizeManualReaderSpikeChecklistArc,
    FinalizeReaderSpikeReviewArc,
    RejectLiveReaderArc,
    RejectPublicCliArc,
    RejectReleaseArc,
    RejectEnforcementArc,
}
impl EbpfReaderLabNextArcFinalDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepExperimental => "keep_experimental",
            Self::FinalizeFixtureOnlyArc => "finalize_fixture_only_arc",
            Self::FinalizeStaticPolicyArc => "finalize_static_policy_arc",
            Self::FinalizeManualReaderSpikeChecklistArc => {
                "finalize_manual_reader_spike_checklist_arc"
            }
            Self::FinalizeReaderSpikeReviewArc => "finalize_reader_spike_review_arc",
            Self::RejectLiveReaderArc => "reject_live_reader_arc",
            Self::RejectPublicCliArc => "reject_public_cli_arc",
            Self::RejectReleaseArc => "reject_release_arc",
            Self::RejectEnforcementArc => "reject_enforcement_arc",
        }
    }
}

/// Kind of next arc final gate finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFinalFindingKind {
    NextArcEntryGate,
    NextArcReviewPack,
    NextArcStaticFreeze,
    NextArcFreezeReview,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    FinalGateInvariant,
}
impl EbpfReaderLabNextArcFinalFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcEntryGate => "next_arc_entry_gate",
            Self::NextArcReviewPack => "next_arc_review_pack",
            Self::NextArcStaticFreeze => "next_arc_static_freeze",
            Self::NextArcFreezeReview => "next_arc_freeze_review",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::FinalGateInvariant => "final_gate_invariant",
        }
    }
}

/// A single finding produced by the next arc final gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFinalFinding {
    pub code: String,
    pub kind: EbpfReaderLabNextArcFinalFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabNextArcFinalGateStatus,
}

/// Input to the reader lab next arc final gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFinalGateInput {
    pub next_arc_entry_gate_report: EbpfReaderLabNextArcEntryGateReport,
    pub next_arc_review_pack: EbpfReaderLabNextArcReviewPack,
    pub next_arc_static_freeze_record: EbpfReaderLabNextArcStaticFreezeRecord,
    pub next_arc_freeze_review_pack: EbpfReaderLabNextArcFreezeReviewPack,
    pub require_next_arc_entry_ready: bool,
    pub require_next_arc_review_ready: bool,
    pub require_next_arc_static_freeze_passed: bool,
    pub require_next_arc_freeze_review_ready: bool,
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

/// Next arc final gate output report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFinalGateReport {
    pub phase: String,
    pub status: EbpfReaderLabNextArcFinalGateStatus,
    pub decision: EbpfReaderLabNextArcFinalDecision,
    pub final_gate_passed: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabNextArcFinalFinding>,
    pub next_arc_entry_ready: bool,
    pub next_arc_review_ready: bool,
    pub next_arc_static_freeze_passed: bool,
    pub next_arc_freeze_review_ready: bool,
    pub experimental_only_confirmed: bool,
    pub finalized_fixture_only_arc: bool,
    pub finalized_static_policy_arc: bool,
    pub finalized_manual_reader_spike_checklist_arc: bool,
    pub finalized_reader_spike_review_arc: bool,
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
    pub fake_next_arc_static_freeze_success_detected: bool,
    pub fake_next_arc_freeze_review_success_detected: bool,
    pub fake_next_arc_final_gate_success_detected: bool,
}

#[inline]
fn pf(
    findings: &mut Vec<EbpfReaderLabNextArcFinalFinding>,
    code: &str,
    kind: EbpfReaderLabNextArcFinalFindingKind,
    msg: &str,
    status: EbpfReaderLabNextArcFinalGateStatus,
) {
    findings.push(EbpfReaderLabNextArcFinalFinding {
        code: code.into(),
        kind,
        message: msg.into(),
        blocking: true,
        status,
    });
}

#[rustfmt::skip]
fn safe_base_report() -> EbpfReaderLabNextArcFinalGateReport {
    EbpfReaderLabNextArcFinalGateReport {
        phase: "I-31".into(), status: EbpfReaderLabNextArcFinalGateStatus::Draft,
        decision: EbpfReaderLabNextArcFinalDecision::Stop, final_gate_passed: false,
        release_allowed: false, must_remain_experimental: true, findings: Vec::new(),
        next_arc_entry_ready: false, next_arc_review_ready: false,
        next_arc_static_freeze_passed: false, next_arc_freeze_review_ready: false,
        experimental_only_confirmed: false, finalized_fixture_only_arc: false,
        finalized_static_policy_arc: false,
        finalized_manual_reader_spike_checklist_arc: false,
        finalized_reader_spike_review_arc: false, live_reader_arc_allowed: false,
        public_cli_arc_allowed: false, release_arc_allowed: false,
        enforcement_arc_allowed: false, public_cli_exposed: false,
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
        fake_next_arc_freeze_review_success_detected: false,
        fake_next_arc_final_gate_success_detected: false,
    }
}

/// Returns a safe default input for the next arc final gate.
#[rustfmt::skip]
pub fn default_reader_lab_next_arc_final_gate_input() -> EbpfReaderLabNextArcFinalGateInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_freeze_review_pack::{build_reader_lab_next_arc_freeze_review_pack, default_reader_lab_next_arc_freeze_review_pack_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{build_reader_lab_next_arc_static_freeze_record, default_reader_lab_next_arc_static_freeze_input};
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true; gi.prefer_fixture_only_arc = true;
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    let mut fi = default_reader_lab_next_arc_static_freeze_input();
    fi.require_experimental_only = true;
    let mut fri = default_reader_lab_next_arc_freeze_review_pack_input();
    fri.require_experimental_only = true;
    EbpfReaderLabNextArcFinalGateInput {
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        next_arc_review_pack: build_reader_lab_next_arc_review_pack(&ri),
        next_arc_static_freeze_record: build_reader_lab_next_arc_static_freeze_record(&fi),
        next_arc_freeze_review_pack: build_reader_lab_next_arc_freeze_review_pack(&fri),
        require_next_arc_entry_ready: false, require_next_arc_review_ready: false,
        require_next_arc_static_freeze_passed: false, require_next_arc_freeze_review_ready: false,
        require_experimental_only: false, public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true, ledger_schema_expected_unchanged: true,
        stable_release_requested: false, tag_requested: false, publish_requested: false,
        version_bump_requested: false, main_merge_requested: false,
    }
}

/// Build the next arc final gate report from the given input.
#[rustfmt::skip]
pub fn build_reader_lab_next_arc_final_gate_report(
    input: &EbpfReaderLabNextArcFinalGateInput,
) -> EbpfReaderLabNextArcFinalGateReport {
    let mut rpt = safe_base_report();
    let mut findings: Vec<EbpfReaderLabNextArcFinalFinding> = Vec::new();
    let mut blocked = false;
    let inc = EbpfReaderLabNextArcFinalGateStatus::Incomplete;
    let blk = EbpfReaderLabNextArcFinalGateStatus::Blocked;
    let fe = EbpfReaderLabNextArcFinalFindingKind::FakeEvidenceInvariant;
    let ri = EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant;
    let rf = EbpfReaderLabNextArcFinalGateStatus::ReleaseForbidden;
    let eg = &input.next_arc_entry_gate_report;
    let rp = &input.next_arc_review_pack;
    let sf = &input.next_arc_static_freeze_record;
    let fr = &input.next_arc_freeze_review_pack;
    // Validate all 4 evidence
    let eg_ok = validate_reader_lab_next_arc_entry_gate_report(eg).is_ok();
    let rp_ok = validate_reader_lab_next_arc_review_pack(rp).is_ok();
    let sf_ok = validate_reader_lab_next_arc_static_freeze_record(sf).is_ok();
    let fr_ok = validate_reader_lab_next_arc_freeze_review_pack(fr).is_ok();
    if !eg_ok { pf(&mut findings, "NAFG-EG-INVALID", EbpfReaderLabNextArcFinalFindingKind::NextArcEntryGate, "entry gate report validation failed", inc); blocked = true; }
    if !rp_ok { pf(&mut findings, "NAFG-RP-INVALID", EbpfReaderLabNextArcFinalFindingKind::NextArcReviewPack, "review pack validation failed", inc); blocked = true; }
    if !sf_ok { pf(&mut findings, "NAFG-SF-INVALID", EbpfReaderLabNextArcFinalFindingKind::NextArcStaticFreeze, "static freeze record validation failed", inc); blocked = true; }
    if !fr_ok { pf(&mut findings, "NAFG-FR-INVALID", EbpfReaderLabNextArcFinalFindingKind::NextArcFreezeReview, "freeze review pack validation failed", inc); blocked = true; }
    // Require flags
    if input.require_next_arc_entry_ready && !eg.entry_ready { pf(&mut findings, "NAFG-EG-NOT-READY", EbpfReaderLabNextArcFinalFindingKind::NextArcEntryGate, "entry gate report is not entry_ready", inc); blocked = true; }
    if input.require_next_arc_review_ready && !rp.review_ready { pf(&mut findings, "NAFG-RP-NOT-READY", EbpfReaderLabNextArcFinalFindingKind::NextArcReviewPack, "review pack is not review_ready", inc); blocked = true; }
    if input.require_next_arc_static_freeze_passed && !sf.freeze_passed { pf(&mut findings, "NAFG-SF-NOT-PASSED", EbpfReaderLabNextArcFinalFindingKind::NextArcStaticFreeze, "static freeze record is not freeze_passed", inc); blocked = true; }
    if input.require_next_arc_freeze_review_ready && !fr.review_ready { pf(&mut findings, "NAFG-FR-NOT-READY", EbpfReaderLabNextArcFinalFindingKind::NextArcFreezeReview, "freeze review pack is not review_ready", inc); blocked = true; }
    // Experimental only cross-evidence
    if input.require_experimental_only {
        rpt.experimental_only_confirmed = true;
        if !(eg.must_remain_experimental && rp.must_remain_experimental && sf.must_remain_experimental && fr.must_remain_experimental) {
            pf(&mut findings, "NAFG-NOT-EXPERIMENTAL", EbpfReaderLabNextArcFinalFindingKind::MutationInvariant, "evidence disagrees on must_remain_experimental", blk); blocked = true;
        }
    }
    // Release invariant cross-evidence
    if eg.release_allowed || rp.release_allowed || sf.release_allowed || fr.release_allowed {
        pf(&mut findings, "NAFG-CONTRADICTION-RELEASE", ri, "evidence disagrees on release_allowed", blk); blocked = true;
    }
    // Live reader cross-evidence
    if eg.live_reader_arc_allowed || rp.live_reader_arc_allowed || sf.arc_allowed_live_reader || fr.live_reader_arc_allowed {
        pf(&mut findings, "NAFG-CONTRADICTION-LIVE-READER", EbpfReaderLabNextArcFinalFindingKind::KernelInvariant, "evidence disagrees on live reader allowance", blk); blocked = true;
    }
    // Public CLI cross-evidence
    if eg.public_cli_arc_allowed || rp.public_cli_arc_allowed || sf.arc_allowed_public_cli || fr.public_cli_arc_allowed {
        pf(&mut findings, "NAFG-CONTRADICTION-PUBLIC-CLI", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "evidence disagrees on public cli allowance", blk); blocked = true;
    }
    // CLI exposed cross-evidence
    if eg.public_cli_exposed || rp.public_cli_exposed || sf.public_cli_exposed || fr.public_cli_exposed {
        pf(&mut findings, "NAFG-CONTRADICTION-CLI-EXPOSED", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "evidence claims public cli exposed", blk); blocked = true;
    }
    // Schema expectations
    if !input.public_cli_expected_hidden { pf(&mut findings, "NAFG-CLI-NOT-HIDDEN", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "public cli expected hidden but was not", blk); blocked = true; }
    if !input.usage_schema_expected_unchanged { pf(&mut findings, "NAFG-USAGE-SCHEMA-CHANGED", EbpfReaderLabNextArcFinalFindingKind::SchemaInvariant, "usage schema expected unchanged but was changed", blk); blocked = true; }
    if !input.ledger_schema_expected_unchanged { pf(&mut findings, "NAFG-LEDGER-SCHEMA-CHANGED", EbpfReaderLabNextArcFinalFindingKind::SchemaInvariant, "ledger schema expected unchanged but was changed", blk); blocked = true; }
    // Release invariants from input
    if input.stable_release_requested { pf(&mut findings, "NAFG-RELEASE-REQUESTED", ri, "stable release requested in experimental branch", rf); blocked = true; }
    if input.tag_requested { pf(&mut findings, "NAFG-TAG-REQUESTED", ri, "tag requested in experimental branch", rf); blocked = true; }
    if input.publish_requested { pf(&mut findings, "NAFG-PUBLISH-REQUESTED", ri, "publish requested in experimental branch", rf); blocked = true; }
    if input.version_bump_requested { pf(&mut findings, "NAFG-VERSION-BUMP-REQUESTED", ri, "version bump requested in experimental branch", rf); blocked = true; }
    if input.main_merge_requested { pf(&mut findings, "NAFG-MAIN-MERGE-REQUESTED", ri, "main merge requested in experimental branch", rf); blocked = true; }
    // Forbidden arc allowances from evidence
    if eg.live_reader_arc_allowed { pf(&mut findings, "NAFG-LIVE-READER-ARC", EbpfReaderLabNextArcFinalFindingKind::KernelInvariant, "entry gate live_reader_arc_allowed is not allowed", blk); blocked = true; rpt.decision = EbpfReaderLabNextArcFinalDecision::RejectLiveReaderArc; }
    if eg.public_cli_arc_allowed { pf(&mut findings, "NAFG-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "entry gate public_cli_arc_allowed is not allowed", blk); blocked = true; rpt.decision = EbpfReaderLabNextArcFinalDecision::RejectPublicCliArc; }
    if eg.release_arc_allowed { pf(&mut findings, "NAFG-RELEASE-ARC", EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant, "entry gate release_arc_allowed is not allowed", blk); blocked = true; rpt.decision = EbpfReaderLabNextArcFinalDecision::RejectReleaseArc; }
    if eg.enforcement_arc_allowed { pf(&mut findings, "NAFG-ENFORCEMENT-ARC", EbpfReaderLabNextArcFinalFindingKind::MutationInvariant, "entry gate enforcement_arc_allowed is not allowed", blk); blocked = true; rpt.decision = EbpfReaderLabNextArcFinalDecision::RejectEnforcementArc; }
    if rp.live_reader_arc_allowed { pf(&mut findings, "NAFG-RP-LIVE-READER-ARC", EbpfReaderLabNextArcFinalFindingKind::KernelInvariant, "review pack live_reader_arc_allowed is not allowed", blk); blocked = true; }
    if rp.public_cli_arc_allowed { pf(&mut findings, "NAFG-RP-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "review pack public_cli_arc_allowed is not allowed", blk); blocked = true; }
    if rp.release_arc_allowed { pf(&mut findings, "NAFG-RP-RELEASE-ARC", EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant, "review pack release_arc_allowed is not allowed", blk); blocked = true; }
    if rp.enforcement_arc_allowed { pf(&mut findings, "NAFG-RP-ENFORCEMENT-ARC", EbpfReaderLabNextArcFinalFindingKind::MutationInvariant, "review pack enforcement_arc_allowed is not allowed", blk); blocked = true; }
    if sf.arc_allowed_live_reader { pf(&mut findings, "NAFG-SF-LIVE-READER-ARC", EbpfReaderLabNextArcFinalFindingKind::KernelInvariant, "freeze record arc_allowed_live_reader is not allowed", blk); blocked = true; }
    if sf.arc_allowed_public_cli { pf(&mut findings, "NAFG-SF-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "freeze record arc_allowed_public_cli is not allowed", blk); blocked = true; }
    if sf.arc_allowed_release { pf(&mut findings, "NAFG-SF-RELEASE-ARC", EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant, "freeze record arc_allowed_release is not allowed", blk); blocked = true; }
    if sf.arc_allowed_enforcement { pf(&mut findings, "NAFG-SF-ENFORCEMENT-ARC", EbpfReaderLabNextArcFinalFindingKind::MutationInvariant, "freeze record arc_allowed_enforcement is not allowed", blk); blocked = true; }
    if fr.live_reader_arc_allowed { pf(&mut findings, "NAFG-FR-LIVE-READER-ARC", EbpfReaderLabNextArcFinalFindingKind::KernelInvariant, "freeze review pack live_reader_arc_allowed is not allowed", blk); blocked = true; }
    if fr.public_cli_arc_allowed { pf(&mut findings, "NAFG-FR-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFinalFindingKind::CliInvariant, "freeze review pack public_cli_arc_allowed is not allowed", blk); blocked = true; }
    if fr.release_arc_allowed { pf(&mut findings, "NAFG-FR-RELEASE-ARC", EbpfReaderLabNextArcFinalFindingKind::ReleaseInvariant, "freeze review pack release_arc_allowed is not allowed", blk); blocked = true; }
    if fr.enforcement_arc_allowed { pf(&mut findings, "NAFG-FR-ENFORCEMENT-ARC", EbpfReaderLabNextArcFinalFindingKind::MutationInvariant, "freeze review pack enforcement_arc_allowed is not allowed", blk); blocked = true; }
    // Operation flags from evidence (max across all 4)
    rpt.ring_buffer_opened = eg.ring_buffer_opened || rp.ring_buffer_opened || sf.ring_buffer_opened || fr.ring_buffer_opened;
    rpt.live_event_stream_read = eg.live_event_stream_read || rp.live_event_stream_read || sf.live_event_stream_read || fr.live_event_stream_read;
    rpt.map_pin_performed = eg.map_pin_performed || rp.map_pin_performed || sf.map_pin_performed || fr.map_pin_performed;
    rpt.enforcement_performed = eg.enforcement_performed || rp.enforcement_performed || sf.enforcement_performed || fr.enforcement_performed;
    rpt.packet_drop_performed = eg.packet_drop_performed || rp.packet_drop_performed || sf.packet_drop_performed || fr.packet_drop_performed;
    rpt.mutation_performed = eg.mutation_performed || rp.mutation_performed || sf.mutation_performed || fr.mutation_performed;
    rpt.persistence_performed = eg.persistence_performed || rp.persistence_performed || sf.persistence_performed || fr.persistence_performed;
    if rpt.ring_buffer_opened || rpt.live_event_stream_read || rpt.map_pin_performed || rpt.enforcement_performed || rpt.packet_drop_performed || rpt.mutation_performed || rpt.persistence_performed {
        pf(&mut findings, "NAFG-OP-FLAGS-TRUE", EbpfReaderLabNextArcFinalFindingKind::RuntimeInvariant, "operation flag is true in evidence", blk); blocked = true;
    }
    // Fake evidence across all 4 evidence types
    macro_rules! fk4 { ($a:expr,$b:expr,$c:expr,$d:expr,$code:expr,$msg:expr) => { if $a||$b||$c||$d { pf(&mut findings,$code,fe,$msg,blk); blocked=true; } } }
    fk4!(eg.fake_reader_success_detected,rp.fake_reader_success_detected,sf.fake_reader_success_detected,fr.fake_reader_success_detected,"NAFG-FAKE-READER","fake reader execution success detected");
    fk4!(eg.fake_live_event_counts_detected,rp.fake_live_event_counts_detected,sf.fake_live_event_counts_detected,fr.fake_live_event_counts_detected,"NAFG-FAKE-EVENTS","fake live event counts detected");
    fk4!(eg.fake_release_readiness_detected,rp.fake_release_readiness_detected,sf.fake_release_readiness_detected,fr.fake_release_readiness_detected,"NAFG-FAKE-RELEASE","fake release readiness detected");
    fk4!(eg.fake_planning_success_detected,rp.fake_planning_success_detected,sf.fake_planning_success_detected,fr.fake_planning_success_detected,"NAFG-FAKE-PLANNING","fake planning success detected");
    fk4!(eg.fake_policy_freeze_success_detected,rp.fake_policy_freeze_success_detected,sf.fake_policy_freeze_success_detected,fr.fake_policy_freeze_success_detected,"NAFG-FAKE-POLICY-FREEZE","fake static policy freeze success detected");
    fk4!(eg.fake_policy_review_success_detected,rp.fake_policy_review_success_detected,sf.fake_policy_review_success_detected,fr.fake_policy_review_success_detected,"NAFG-FAKE-REVIEW","fake static policy review success detected");
    fk4!(eg.fake_policy_hardening_success_detected,rp.fake_policy_hardening_success_detected,sf.fake_policy_hardening_success_detected,fr.fake_policy_hardening_success_detected,"NAFG-FAKE-HARDENING","fake static policy hardening success detected");
    fk4!(eg.fake_policy_completion_success_detected,rp.fake_policy_completion_success_detected,sf.fake_policy_completion_success_detected,fr.fake_policy_completion_success_detected,"NAFG-FAKE-COMPLETION","fake policy completion success detected");
    fk4!(eg.fake_completion_review_success_detected,rp.fake_completion_review_success_detected,sf.fake_completion_review_success_detected,fr.fake_completion_review_success_detected,"NAFG-FAKE-COMPLETION-REVIEW","fake completion review success detected");
    fk4!(eg.fake_next_arc_entry_success_detected,rp.fake_next_arc_entry_success_detected,sf.fake_next_arc_entry_success_detected,fr.fake_next_arc_entry_success_detected,"NAFG-FAKE-ENTRY","fake next arc entry success detected");
    if rp.fake_next_arc_review_success_detected || sf.fake_next_arc_review_success_detected || fr.fake_next_arc_review_success_detected { pf(&mut findings,"NAFG-FAKE-REVIEW-PACK",fe,"fake next arc review success detected",blk); blocked=true; }
    if sf.fake_next_arc_static_freeze_success_detected || fr.fake_next_arc_static_freeze_success_detected { pf(&mut findings,"NAFG-FAKE-STATIC-FREEZE",fe,"fake next arc static freeze success detected",blk); blocked=true; }
    if fr.fake_next_arc_freeze_review_success_detected { pf(&mut findings,"NAFG-FAKE-FREEZE-REVIEW",fe,"fake next arc freeze review success detected",blk); blocked=true; }
    // Propagate arc allowances (max across evidence)
    rpt.live_reader_arc_allowed = eg.live_reader_arc_allowed || rp.live_reader_arc_allowed || sf.arc_allowed_live_reader || fr.live_reader_arc_allowed;
    rpt.public_cli_arc_allowed = eg.public_cli_arc_allowed || rp.public_cli_arc_allowed || sf.arc_allowed_public_cli || fr.public_cli_arc_allowed;
    rpt.release_arc_allowed = eg.release_arc_allowed || rp.release_arc_allowed || sf.arc_allowed_release || fr.release_arc_allowed;
    rpt.enforcement_arc_allowed = eg.enforcement_arc_allowed || rp.enforcement_arc_allowed || sf.arc_allowed_enforcement || fr.enforcement_arc_allowed;
    rpt.public_cli_exposed = eg.public_cli_exposed || rp.public_cli_exposed || sf.public_cli_exposed || fr.public_cli_exposed;
    rpt.usage_schema_changed = eg.usage_schema_changed || rp.usage_schema_changed || sf.usage_schema_changed || fr.usage_schema_changed;
    rpt.ledger_schema_changed = eg.ledger_schema_changed || rp.ledger_schema_changed || sf.ledger_schema_changed || fr.ledger_schema_changed;
    rpt.stable_release_requested = input.stable_release_requested;
    rpt.tag_requested = input.tag_requested;
    rpt.publish_requested = input.publish_requested;
    rpt.version_bump_requested = input.version_bump_requested;
    rpt.main_merge_requested = input.main_merge_requested;
    rpt.next_arc_entry_ready = eg.entry_ready;
    rpt.next_arc_review_ready = rp.review_ready;
    rpt.next_arc_static_freeze_passed = sf.freeze_passed;
    rpt.next_arc_freeze_review_ready = fr.review_ready;
    // Propagate fake flags
    rpt.fake_reader_success_detected = eg.fake_reader_success_detected || rp.fake_reader_success_detected || sf.fake_reader_success_detected || fr.fake_reader_success_detected;
    rpt.fake_live_event_counts_detected = eg.fake_live_event_counts_detected || rp.fake_live_event_counts_detected || sf.fake_live_event_counts_detected || fr.fake_live_event_counts_detected;
    rpt.fake_release_readiness_detected = eg.fake_release_readiness_detected || rp.fake_release_readiness_detected || sf.fake_release_readiness_detected || fr.fake_release_readiness_detected;
    rpt.fake_planning_success_detected = eg.fake_planning_success_detected || rp.fake_planning_success_detected || sf.fake_planning_success_detected || fr.fake_planning_success_detected;
    rpt.fake_policy_freeze_success_detected = eg.fake_policy_freeze_success_detected || rp.fake_policy_freeze_success_detected || sf.fake_policy_freeze_success_detected || fr.fake_policy_freeze_success_detected;
    rpt.fake_policy_review_success_detected = eg.fake_policy_review_success_detected || rp.fake_policy_review_success_detected || sf.fake_policy_review_success_detected || fr.fake_policy_review_success_detected;
    rpt.fake_policy_hardening_success_detected = eg.fake_policy_hardening_success_detected || rp.fake_policy_hardening_success_detected || sf.fake_policy_hardening_success_detected || fr.fake_policy_hardening_success_detected;
    rpt.fake_policy_completion_success_detected = eg.fake_policy_completion_success_detected || rp.fake_policy_completion_success_detected || sf.fake_policy_completion_success_detected || fr.fake_policy_completion_success_detected;
    rpt.fake_completion_review_success_detected = eg.fake_completion_review_success_detected || rp.fake_completion_review_success_detected || sf.fake_completion_review_success_detected || fr.fake_completion_review_success_detected;
    rpt.fake_next_arc_entry_success_detected = eg.fake_next_arc_entry_success_detected || rp.fake_next_arc_entry_success_detected || sf.fake_next_arc_entry_success_detected || fr.fake_next_arc_entry_success_detected;
    rpt.fake_next_arc_review_success_detected = rp.fake_next_arc_review_success_detected || sf.fake_next_arc_review_success_detected || fr.fake_next_arc_review_success_detected;
    rpt.fake_next_arc_static_freeze_success_detected = sf.fake_next_arc_static_freeze_success_detected || fr.fake_next_arc_static_freeze_success_detected;
    rpt.fake_next_arc_freeze_review_success_detected = fr.fake_next_arc_freeze_review_success_detected;
    // fake_next_arc_final_gate_success_detected is always false - never set by build
    // Require experimental only
    if !input.require_experimental_only { pf(&mut findings,"NAFG-NO-EXPERIMENTAL-CONFIRM",EbpfReaderLabNextArcFinalFindingKind::FinalGateInvariant,"experimental-only confirmation not provided",EbpfReaderLabNextArcFinalGateStatus::ExperimentalOnly); blocked=true; }
    // Finalized arc from I-29 freeze record (frozen arcs)
    rpt.finalized_static_policy_arc = sf.frozen_static_policy_arc;
    rpt.finalized_fixture_only_arc = sf.frozen_fixture_only_arc;
    rpt.finalized_manual_reader_spike_checklist_arc = sf.frozen_manual_reader_spike_checklist_arc;
    rpt.finalized_reader_spike_review_arc = sf.frozen_reader_spike_review_arc;
    let has_safe_arc = sf.frozen_fixture_only_arc || sf.frozen_static_policy_arc
        || sf.frozen_manual_reader_spike_checklist_arc || sf.frozen_reader_spike_review_arc;
    if !has_safe_arc && !blocked {
        pf(&mut findings,"NAFG-NO-SAFE-ARC",EbpfReaderLabNextArcFinalFindingKind::FinalGateInvariant,"at least one finalized safe arc must be true in freeze record",inc);
        blocked = true;
    }
    // Status determination
    if blocked {
        let has_rel = input.stable_release_requested || input.tag_requested || input.publish_requested
            || input.version_bump_requested || input.main_merge_requested;
        let has_exp = !input.require_experimental_only;
        let has_dis = eg.live_reader_arc_allowed || eg.public_cli_arc_allowed || eg.release_arc_allowed
            || eg.enforcement_arc_allowed || rp.live_reader_arc_allowed || rp.public_cli_arc_allowed
            || rp.release_arc_allowed || rp.enforcement_arc_allowed || sf.arc_allowed_live_reader
            || sf.arc_allowed_public_cli || sf.arc_allowed_release || sf.arc_allowed_enforcement
            || fr.live_reader_arc_allowed || fr.public_cli_arc_allowed || fr.release_arc_allowed
            || fr.enforcement_arc_allowed;
        let all_inv = !eg_ok && !rp_ok && !sf_ok && !fr_ok;
        if has_rel {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::ReleaseForbidden;
            if !has_dis { rpt.decision = EbpfReaderLabNextArcFinalDecision::RejectReleaseArc; }
        } else if has_dis {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Blocked;
        } else if has_exp && all_inv {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Incomplete;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::Stop;
        } else if has_exp {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::ExperimentalOnly;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::KeepExperimental;
        } else {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::FinalRejected;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::Stop;
        }
    } else {
        // Priority: StaticPolicy > FixtureOnly > ManualReaderSpikeChecklist > ReaderSpikeReview
        if sf.frozen_static_policy_arc {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Finalized;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::FinalizeStaticPolicyArc;
        } else if sf.frozen_fixture_only_arc {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Finalized;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::FinalizeFixtureOnlyArc;
        } else if sf.frozen_manual_reader_spike_checklist_arc {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Finalized;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::FinalizeManualReaderSpikeChecklistArc;
        } else if sf.frozen_reader_spike_review_arc {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::Finalized;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::FinalizeReaderSpikeReviewArc;
        } else {
            rpt.status = EbpfReaderLabNextArcFinalGateStatus::FinalRejected;
            rpt.decision = EbpfReaderLabNextArcFinalDecision::Stop;
        }
        if rpt.status == EbpfReaderLabNextArcFinalGateStatus::Finalized {
            rpt.final_gate_passed = true;
        }
    }
    rpt.findings = findings;
    rpt
}

/// Validate a next arc final gate report.
pub fn validate_reader_lab_next_arc_final_gate_report(
    rpt: &EbpfReaderLabNextArcFinalGateReport,
) -> Result<(), String> {
    if rpt.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-31"))
        } else {
            Ok(())
        }
    };
    deny(rpt.release_allowed, "release_allowed")?;
    deny(!rpt.must_remain_experimental, "must_remain_experimental")?;
    deny(rpt.live_reader_arc_allowed, "live_reader_arc_allowed")?;
    deny(rpt.public_cli_arc_allowed, "public_cli_arc_allowed")?;
    deny(rpt.release_arc_allowed, "release_arc_allowed")?;
    deny(rpt.enforcement_arc_allowed, "enforcement_arc_allowed")?;
    deny(rpt.public_cli_exposed, "public_cli_exposed")?;
    deny(rpt.usage_schema_changed, "usage_schema_changed")?;
    deny(rpt.ledger_schema_changed, "ledger_schema_changed")?;
    deny(rpt.stable_release_requested, "stable_release_requested")?;
    deny(rpt.tag_requested, "tag_requested")?;
    deny(rpt.publish_requested, "publish_requested")?;
    deny(rpt.version_bump_requested, "version_bump_requested")?;
    deny(rpt.main_merge_requested, "main_merge_requested")?;
    deny(rpt.ring_buffer_opened, "ring_buffer_opened")?;
    deny(rpt.live_event_stream_read, "live_event_stream_read")?;
    deny(rpt.map_pin_performed, "map_pin_performed")?;
    deny(rpt.enforcement_performed, "enforcement_performed")?;
    deny(rpt.packet_drop_performed, "packet_drop_performed")?;
    deny(rpt.mutation_performed, "mutation_performed")?;
    deny(rpt.persistence_performed, "persistence_performed")?;
    let fakes: &[(bool, &str)] = &[
        (
            rpt.fake_reader_success_detected,
            "fake_reader_success_detected",
        ),
        (
            rpt.fake_live_event_counts_detected,
            "fake_live_event_counts_detected",
        ),
        (
            rpt.fake_release_readiness_detected,
            "fake_release_readiness_detected",
        ),
        (
            rpt.fake_planning_success_detected,
            "fake_planning_success_detected",
        ),
        (
            rpt.fake_policy_freeze_success_detected,
            "fake_policy_freeze_success_detected",
        ),
        (
            rpt.fake_policy_review_success_detected,
            "fake_policy_review_success_detected",
        ),
        (
            rpt.fake_policy_hardening_success_detected,
            "fake_policy_hardening_success_detected",
        ),
        (
            rpt.fake_policy_completion_success_detected,
            "fake_policy_completion_success_detected",
        ),
        (
            rpt.fake_completion_review_success_detected,
            "fake_completion_review_success_detected",
        ),
        (
            rpt.fake_next_arc_entry_success_detected,
            "fake_next_arc_entry_success_detected",
        ),
        (
            rpt.fake_next_arc_review_success_detected,
            "fake_next_arc_review_success_detected",
        ),
        (
            rpt.fake_next_arc_static_freeze_success_detected,
            "fake_next_arc_static_freeze_success_detected",
        ),
        (
            rpt.fake_next_arc_freeze_review_success_detected,
            "fake_next_arc_freeze_review_success_detected",
        ),
        (
            rpt.fake_next_arc_final_gate_success_detected,
            "fake_next_arc_final_gate_success_detected",
        ),
    ];
    for (flag, name) in fakes {
        deny(*flag, name)?;
    }
    if rpt.final_gate_passed && rpt.status == EbpfReaderLabNextArcFinalGateStatus::FinalRejected {
        return Err("final_gate_passed must be false when status is FinalRejected".to_string());
    }
    Ok(())
}

/// Map final gate status to label.
pub fn reader_lab_next_arc_final_gate_status_label(
    status: EbpfReaderLabNextArcFinalGateStatus,
) -> &'static str {
    status.as_str()
}

/// Map final decision to label.
pub fn reader_lab_next_arc_final_decision_label(
    decision: EbpfReaderLabNextArcFinalDecision,
) -> &'static str {
    decision.as_str()
}

/// Map final finding kind to label.
pub fn reader_lab_next_arc_final_finding_kind_label(
    kind: EbpfReaderLabNextArcFinalFindingKind,
) -> &'static str {
    kind.as_str()
}
