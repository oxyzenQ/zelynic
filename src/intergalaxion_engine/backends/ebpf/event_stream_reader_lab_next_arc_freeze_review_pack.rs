// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab next arc freeze review pack model for the Intergalaxion Engine (I-30).
//! Consumes I-27 entry gate report, I-28 review pack, and I-29 static freeze
//! record evidence to produce a deterministic freeze review pack. Freeze review
//! only, not a release, not a live reader, not a ring buffer reader.
//! release_allowed is always false. must_remain_experimental is always true.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{
    validate_reader_lab_next_arc_entry_gate_report, EbpfReaderLabNextArcEntryGateReport,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{
    validate_reader_lab_next_arc_review_pack, EbpfReaderLabNextArcReviewPack,
};
use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{
    validate_reader_lab_next_arc_static_freeze_record, EbpfReaderLabNextArcStaticFreezeRecord,
};

/// Status of the reader lab next arc freeze review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFreezeReviewPackStatus {
    Draft,
    Incomplete,
    Blocked,
    ReviewReady,
    ReviewRejected,
    ExperimentalOnly,
    ReleaseForbidden,
}
impl EbpfReaderLabNextArcFreezeReviewPackStatus {
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

/// Decision produced by the reader lab next arc freeze review pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFreezeReviewDecision {
    Stop,
    KeepExperimental,
    ReviewFrozenFixtureOnlyArc,
    ReviewFrozenStaticPolicyArc,
    ReviewFrozenManualReaderSpikeChecklistArc,
    ReviewFrozenReaderSpikeReviewArc,
    RejectLiveReaderArc,
    RejectPublicCliArc,
    RejectReleaseArc,
    RejectEnforcementArc,
}
impl EbpfReaderLabNextArcFreezeReviewDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::KeepExperimental => "keep_experimental",
            Self::ReviewFrozenFixtureOnlyArc => "review_frozen_fixture_only_arc",
            Self::ReviewFrozenStaticPolicyArc => "review_frozen_static_policy_arc",
            Self::ReviewFrozenManualReaderSpikeChecklistArc => {
                "review_frozen_manual_reader_spike_checklist_arc"
            }
            Self::ReviewFrozenReaderSpikeReviewArc => "review_frozen_reader_spike_review_arc",
            Self::RejectLiveReaderArc => "reject_live_reader_arc",
            Self::RejectPublicCliArc => "reject_public_cli_arc",
            Self::RejectReleaseArc => "reject_release_arc",
            Self::RejectEnforcementArc => "reject_enforcement_arc",
        }
    }
}

/// Kind of next arc freeze review finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabNextArcFreezeReviewFindingKind {
    NextArcEntryGate,
    NextArcReviewPack,
    NextArcStaticFreeze,
    ReleaseInvariant,
    CliInvariant,
    SchemaInvariant,
    RuntimeInvariant,
    KernelInvariant,
    MutationInvariant,
    FakeEvidenceInvariant,
    ReviewInvariant,
}
impl EbpfReaderLabNextArcFreezeReviewFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcEntryGate => "next_arc_entry_gate",
            Self::NextArcReviewPack => "next_arc_review_pack",
            Self::NextArcStaticFreeze => "next_arc_static_freeze",
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

/// A single finding produced by the next arc freeze review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFreezeReviewFinding {
    pub code: String,
    pub kind: EbpfReaderLabNextArcFreezeReviewFindingKind,
    pub message: String,
    pub blocking: bool,
    pub status: EbpfReaderLabNextArcFreezeReviewPackStatus,
}

/// Input to the reader lab next arc freeze review pack evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFreezeReviewPackInput {
    pub next_arc_entry_gate_report: EbpfReaderLabNextArcEntryGateReport,
    pub next_arc_review_pack: EbpfReaderLabNextArcReviewPack,
    pub next_arc_static_freeze_record: EbpfReaderLabNextArcStaticFreezeRecord,
    pub require_next_arc_entry_ready: bool,
    pub require_next_arc_review_ready: bool,
    pub require_next_arc_static_freeze_passed: bool,
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

/// Next arc freeze review pack output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabNextArcFreezeReviewPack {
    pub phase: String,
    pub status: EbpfReaderLabNextArcFreezeReviewPackStatus,
    pub decision: EbpfReaderLabNextArcFreezeReviewDecision,
    pub review_ready: bool,
    pub release_allowed: bool,
    pub must_remain_experimental: bool,
    pub findings: Vec<EbpfReaderLabNextArcFreezeReviewFinding>,
    pub next_arc_entry_ready: bool,
    pub next_arc_review_ready: bool,
    pub next_arc_static_freeze_passed: bool,
    pub experimental_only_confirmed: bool,
    pub frozen_fixture_only_arc: bool,
    pub frozen_static_policy_arc: bool,
    pub frozen_manual_reader_spike_checklist_arc: bool,
    pub frozen_reader_spike_review_arc: bool,
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
}

#[inline]
fn pf(
    findings: &mut Vec<EbpfReaderLabNextArcFreezeReviewFinding>,
    code: &str,
    kind: EbpfReaderLabNextArcFreezeReviewFindingKind,
    msg: &str,
    status: EbpfReaderLabNextArcFreezeReviewPackStatus,
) {
    findings.push(EbpfReaderLabNextArcFreezeReviewFinding {
        code: code.into(),
        kind,
        message: msg.into(),
        blocking: true,
        status,
    });
}

#[rustfmt::skip]
fn safe_base_pack() -> EbpfReaderLabNextArcFreezeReviewPack {
    EbpfReaderLabNextArcFreezeReviewPack {
        phase: "I-30".into(), status: EbpfReaderLabNextArcFreezeReviewPackStatus::Draft,
        decision: EbpfReaderLabNextArcFreezeReviewDecision::Stop, review_ready: false,
        release_allowed: false, must_remain_experimental: true, findings: Vec::new(),
        next_arc_entry_ready: false, next_arc_review_ready: false,
        next_arc_static_freeze_passed: false, experimental_only_confirmed: false,
        frozen_fixture_only_arc: false, frozen_static_policy_arc: false,
        frozen_manual_reader_spike_checklist_arc: false, frozen_reader_spike_review_arc: false,
        live_reader_arc_allowed: false, public_cli_arc_allowed: false,
        release_arc_allowed: false, enforcement_arc_allowed: false,
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
        fake_next_arc_static_freeze_success_detected: false, fake_next_arc_freeze_review_success_detected: false,
    }
}

/// Returns a safe default input for the next arc freeze review pack.
#[rustfmt::skip]
pub fn default_reader_lab_next_arc_freeze_review_pack_input() -> EbpfReaderLabNextArcFreezeReviewPackInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_entry_gate::{build_reader_lab_next_arc_entry_gate_report, default_reader_lab_next_arc_entry_gate_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_review_pack::{build_reader_lab_next_arc_review_pack, default_reader_lab_next_arc_review_pack_input};
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_static_freeze::{build_reader_lab_next_arc_static_freeze_record, default_reader_lab_next_arc_static_freeze_input};
    let mut gi = default_reader_lab_next_arc_entry_gate_input();
    gi.require_experimental_only = true; gi.prefer_fixture_only_arc = true;
    let mut ri = default_reader_lab_next_arc_review_pack_input();
    ri.require_experimental_only = true;
    let mut fi = default_reader_lab_next_arc_static_freeze_input();
    fi.require_experimental_only = true;
    EbpfReaderLabNextArcFreezeReviewPackInput {
        next_arc_entry_gate_report: build_reader_lab_next_arc_entry_gate_report(&gi),
        next_arc_review_pack: build_reader_lab_next_arc_review_pack(&ri),
        next_arc_static_freeze_record: build_reader_lab_next_arc_static_freeze_record(&fi),
        require_next_arc_entry_ready: false, require_next_arc_review_ready: false,
        require_next_arc_static_freeze_passed: false, require_experimental_only: false,
        public_cli_expected_hidden: true, usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true, stable_release_requested: false,
        tag_requested: false, publish_requested: false, version_bump_requested: false,
        main_merge_requested: false,
    }
}

/// Build the next arc freeze review pack from the given input.
#[rustfmt::skip]
pub fn build_reader_lab_next_arc_freeze_review_pack(
    input: &EbpfReaderLabNextArcFreezeReviewPackInput,
) -> EbpfReaderLabNextArcFreezeReviewPack {
    let mut pack = safe_base_pack();
    let mut findings: Vec<EbpfReaderLabNextArcFreezeReviewFinding> = Vec::new();
    let mut blocked = false;
    let inc = EbpfReaderLabNextArcFreezeReviewPackStatus::Incomplete;
    let blk = EbpfReaderLabNextArcFreezeReviewPackStatus::Blocked;
    let fe = EbpfReaderLabNextArcFreezeReviewFindingKind::FakeEvidenceInvariant;
    let ri = EbpfReaderLabNextArcFreezeReviewFindingKind::ReleaseInvariant;
    let rf = EbpfReaderLabNextArcFreezeReviewPackStatus::ReleaseForbidden;
    let eg = &input.next_arc_entry_gate_report;
    let rp = &input.next_arc_review_pack;
    let sf = &input.next_arc_static_freeze_record;
    // Validate all 3 evidence
    let eg_ok = validate_reader_lab_next_arc_entry_gate_report(eg).is_ok();
    let rp_ok = validate_reader_lab_next_arc_review_pack(rp).is_ok();
    let sf_ok = validate_reader_lab_next_arc_static_freeze_record(sf).is_ok();
    if !eg_ok { pf(&mut findings, "NAFRP-EG-INVALID", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcEntryGate, "entry gate report validation failed", inc); blocked = true; }
    if !rp_ok { pf(&mut findings, "NAFRP-RP-INVALID", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcReviewPack, "review pack validation failed", inc); blocked = true; }
    if !sf_ok { pf(&mut findings, "NAFRP-SF-INVALID", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcStaticFreeze, "static freeze record validation failed", inc); blocked = true; }
    // Require flags
    if input.require_next_arc_entry_ready && !eg.entry_ready { pf(&mut findings, "NAFRP-EG-NOT-READY", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcEntryGate, "entry gate report is not entry_ready", inc); blocked = true; }
    if input.require_next_arc_review_ready && !rp.review_ready { pf(&mut findings, "NAFRP-RP-NOT-READY", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcReviewPack, "review pack is not review_ready", inc); blocked = true; }
    if input.require_next_arc_static_freeze_passed && !sf.freeze_passed { pf(&mut findings, "NAFRP-SF-NOT-PASSED", EbpfReaderLabNextArcFreezeReviewFindingKind::NextArcStaticFreeze, "static freeze record is not freeze_passed", inc); blocked = true; }
    // Experimental only cross-evidence
    if input.require_experimental_only {
        pack.experimental_only_confirmed = true;
        if !(eg.must_remain_experimental && rp.must_remain_experimental && sf.must_remain_experimental) {
            pf(&mut findings, "NAFRP-NOT-EXPERIMENTAL", EbpfReaderLabNextArcFreezeReviewFindingKind::MutationInvariant, "evidence disagrees on must_remain_experimental", blk); blocked = true;
        }
    }
    // Release invariant cross-evidence
    if eg.release_allowed || rp.release_allowed || sf.release_allowed {
        pf(&mut findings, "NAFRP-CONTRADICTION-RELEASE", ri, "evidence disagrees on release_allowed", blk); blocked = true;
    }
    // Live reader cross-evidence
    if eg.live_reader_arc_allowed || rp.live_reader_arc_allowed || sf.arc_allowed_live_reader {
        pf(&mut findings, "NAFRP-CONTRADICTION-LIVE-READER", EbpfReaderLabNextArcFreezeReviewFindingKind::KernelInvariant, "evidence disagrees on live reader allowance", blk); blocked = true;
    }
    // Public CLI cross-evidence
    if eg.public_cli_arc_allowed || rp.public_cli_arc_allowed || sf.arc_allowed_public_cli {
        pf(&mut findings, "NAFRP-CONTRADICTION-PUBLIC-CLI", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "evidence disagrees on public cli allowance", blk); blocked = true;
    }
    // CLI exposed cross-evidence
    if eg.public_cli_exposed || rp.public_cli_exposed || sf.public_cli_exposed {
        pf(&mut findings, "NAFRP-CONTRADICTION-CLI-EXPOSED", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "evidence claims public cli exposed", blk); blocked = true;
    }
    // Schema expectations
    if !input.public_cli_expected_hidden { pf(&mut findings, "NAFRP-CLI-NOT-HIDDEN", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "public cli expected hidden but was not", blk); blocked = true; }
    if !input.usage_schema_expected_unchanged { pf(&mut findings, "NAFRP-USAGE-SCHEMA-CHANGED", EbpfReaderLabNextArcFreezeReviewFindingKind::SchemaInvariant, "usage schema expected unchanged but was changed", blk); blocked = true; }
    if !input.ledger_schema_expected_unchanged { pf(&mut findings, "NAFRP-LEDGER-SCHEMA-CHANGED", EbpfReaderLabNextArcFreezeReviewFindingKind::SchemaInvariant, "ledger schema expected unchanged but was changed", blk); blocked = true; }
    // Release invariants from input
    if input.stable_release_requested { pf(&mut findings, "NAFRP-RELEASE-REQUESTED", ri, "stable release requested in experimental branch", rf); blocked = true; }
    if input.tag_requested { pf(&mut findings, "NAFRP-TAG-REQUESTED", ri, "tag requested in experimental branch", rf); blocked = true; }
    if input.publish_requested { pf(&mut findings, "NAFRP-PUBLISH-REQUESTED", ri, "publish requested in experimental branch", rf); blocked = true; }
    if input.version_bump_requested { pf(&mut findings, "NAFRP-VERSION-BUMP-REQUESTED", ri, "version bump requested in experimental branch", rf); blocked = true; }
    if input.main_merge_requested { pf(&mut findings, "NAFRP-MAIN-MERGE-REQUESTED", ri, "main merge requested in experimental branch", rf); blocked = true; }
    // Forbidden arc allowances from evidence
    if eg.live_reader_arc_allowed { pf(&mut findings, "NAFRP-LIVE-READER-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::KernelInvariant, "entry gate live_reader_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::RejectLiveReaderArc; }
    if eg.public_cli_arc_allowed { pf(&mut findings, "NAFRP-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "entry gate public_cli_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::RejectPublicCliArc; }
    if eg.release_arc_allowed { pf(&mut findings, "NAFRP-RELEASE-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::ReleaseInvariant, "entry gate release_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::RejectReleaseArc; }
    if eg.enforcement_arc_allowed { pf(&mut findings, "NAFRP-ENFORCEMENT-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::MutationInvariant, "entry gate enforcement_arc_allowed is not allowed", blk); blocked = true; pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::RejectEnforcementArc; }
    if rp.live_reader_arc_allowed { pf(&mut findings, "NAFRP-RP-LIVE-READER-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::KernelInvariant, "review pack live_reader_arc_allowed is not allowed", blk); blocked = true; }
    if rp.public_cli_arc_allowed { pf(&mut findings, "NAFRP-RP-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "review pack public_cli_arc_allowed is not allowed", blk); blocked = true; }
    if rp.release_arc_allowed { pf(&mut findings, "NAFRP-RP-RELEASE-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::ReleaseInvariant, "review pack release_arc_allowed is not allowed", blk); blocked = true; }
    if rp.enforcement_arc_allowed { pf(&mut findings, "NAFRP-RP-ENFORCEMENT-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::MutationInvariant, "review pack enforcement_arc_allowed is not allowed", blk); blocked = true; }
    if sf.arc_allowed_live_reader { pf(&mut findings, "NAFRP-SF-LIVE-READER-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::KernelInvariant, "freeze record arc_allowed_live_reader is not allowed", blk); blocked = true; }
    if sf.arc_allowed_public_cli { pf(&mut findings, "NAFRP-SF-PUBLIC-CLI-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::CliInvariant, "freeze record arc_allowed_public_cli is not allowed", blk); blocked = true; }
    if sf.arc_allowed_release { pf(&mut findings, "NAFRP-SF-RELEASE-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::ReleaseInvariant, "freeze record arc_allowed_release is not allowed", blk); blocked = true; }
    if sf.arc_allowed_enforcement { pf(&mut findings, "NAFRP-SF-ENFORCEMENT-ARC", EbpfReaderLabNextArcFreezeReviewFindingKind::MutationInvariant, "freeze record arc_allowed_enforcement is not allowed", blk); blocked = true; }
    // Operation flags from evidence
    pack.ring_buffer_opened = eg.ring_buffer_opened || rp.ring_buffer_opened || sf.ring_buffer_opened;
    pack.live_event_stream_read = eg.live_event_stream_read || rp.live_event_stream_read || sf.live_event_stream_read;
    pack.map_pin_performed = eg.map_pin_performed || rp.map_pin_performed || sf.map_pin_performed;
    pack.enforcement_performed = eg.enforcement_performed || rp.enforcement_performed || sf.enforcement_performed;
    pack.packet_drop_performed = eg.packet_drop_performed || rp.packet_drop_performed || sf.packet_drop_performed;
    pack.mutation_performed = eg.mutation_performed || rp.mutation_performed || sf.mutation_performed;
    pack.persistence_performed = eg.persistence_performed || rp.persistence_performed || sf.persistence_performed;
    if pack.ring_buffer_opened || pack.live_event_stream_read || pack.map_pin_performed || pack.enforcement_performed || pack.packet_drop_performed || pack.mutation_performed || pack.persistence_performed {
        pf(&mut findings, "NAFRP-OP-FLAGS-TRUE", EbpfReaderLabNextArcFreezeReviewFindingKind::RuntimeInvariant, "operation flag is true in evidence", blk); blocked = true;
    }
    // Fake evidence across all 3 evidence types
    macro_rules! fk3 { ($a:expr,$b:expr,$c:expr,$code:expr,$msg:expr) => { if $a||$b||$c { pf(&mut findings,$code,fe,$msg,blk); blocked=true; } } }
    fk3!(eg.fake_reader_success_detected,rp.fake_reader_success_detected,sf.fake_reader_success_detected,"NAFRP-FAKE-READER","fake reader execution success detected");
    fk3!(eg.fake_live_event_counts_detected,rp.fake_live_event_counts_detected,sf.fake_live_event_counts_detected,"NAFRP-FAKE-EVENTS","fake live event counts detected");
    fk3!(eg.fake_release_readiness_detected,rp.fake_release_readiness_detected,sf.fake_release_readiness_detected,"NAFRP-FAKE-RELEASE","fake release readiness detected");
    fk3!(eg.fake_planning_success_detected,rp.fake_planning_success_detected,sf.fake_planning_success_detected,"NAFRP-FAKE-PLANNING","fake planning success detected");
    fk3!(eg.fake_policy_freeze_success_detected,rp.fake_policy_freeze_success_detected,sf.fake_policy_freeze_success_detected,"NAFRP-FAKE-POLICY-FREEZE","fake static policy freeze success detected");
    fk3!(eg.fake_policy_review_success_detected,rp.fake_policy_review_success_detected,sf.fake_policy_review_success_detected,"NAFRP-FAKE-REVIEW","fake static policy review success detected");
    fk3!(eg.fake_policy_hardening_success_detected,rp.fake_policy_hardening_success_detected,sf.fake_policy_hardening_success_detected,"NAFRP-FAKE-HARDENING","fake static policy hardening success detected");
    fk3!(eg.fake_policy_completion_success_detected,rp.fake_policy_completion_success_detected,sf.fake_policy_completion_success_detected,"NAFRP-FAKE-COMPLETION","fake policy completion success detected");
    fk3!(eg.fake_completion_review_success_detected,rp.fake_completion_review_success_detected,sf.fake_completion_review_success_detected,"NAFRP-FAKE-COMPLETION-REVIEW","fake completion review success detected");
    fk3!(eg.fake_next_arc_entry_success_detected,rp.fake_next_arc_entry_success_detected,sf.fake_next_arc_entry_success_detected,"NAFRP-FAKE-ENTRY","fake next arc entry success detected");
    if rp.fake_next_arc_review_success_detected || sf.fake_next_arc_review_success_detected { pf(&mut findings,"NAFRP-FAKE-REVIEW-PACK",fe,"fake next arc review success detected",blk); blocked=true; }
    if sf.fake_next_arc_static_freeze_success_detected { pf(&mut findings,"NAFRP-FAKE-STATIC-FREEZE",fe,"fake next arc static freeze success detected",blk); blocked=true; }
    // Propagate arc allowances (max across evidence)
    pack.live_reader_arc_allowed = eg.live_reader_arc_allowed || rp.live_reader_arc_allowed || sf.arc_allowed_live_reader;
    pack.public_cli_arc_allowed = eg.public_cli_arc_allowed || rp.public_cli_arc_allowed || sf.arc_allowed_public_cli;
    pack.release_arc_allowed = eg.release_arc_allowed || rp.release_arc_allowed || sf.arc_allowed_release;
    pack.enforcement_arc_allowed = eg.enforcement_arc_allowed || rp.enforcement_arc_allowed || sf.arc_allowed_enforcement;
    pack.public_cli_exposed = eg.public_cli_exposed || rp.public_cli_exposed || sf.public_cli_exposed;
    pack.usage_schema_changed = eg.usage_schema_changed || rp.usage_schema_changed || sf.usage_schema_changed;
    pack.ledger_schema_changed = eg.ledger_schema_changed || rp.ledger_schema_changed || sf.ledger_schema_changed;
    pack.stable_release_requested = input.stable_release_requested;
    pack.tag_requested = input.tag_requested;
    pack.publish_requested = input.publish_requested;
    pack.version_bump_requested = input.version_bump_requested;
    pack.main_merge_requested = input.main_merge_requested;
    pack.next_arc_entry_ready = eg.entry_ready;
    pack.next_arc_review_ready = rp.review_ready;
    pack.next_arc_static_freeze_passed = sf.freeze_passed;
    // Propagate fake flags
    pack.fake_reader_success_detected = eg.fake_reader_success_detected || rp.fake_reader_success_detected || sf.fake_reader_success_detected;
    pack.fake_live_event_counts_detected = eg.fake_live_event_counts_detected || rp.fake_live_event_counts_detected || sf.fake_live_event_counts_detected;
    pack.fake_release_readiness_detected = eg.fake_release_readiness_detected || rp.fake_release_readiness_detected || sf.fake_release_readiness_detected;
    pack.fake_planning_success_detected = eg.fake_planning_success_detected || rp.fake_planning_success_detected || sf.fake_planning_success_detected;
    pack.fake_policy_freeze_success_detected = eg.fake_policy_freeze_success_detected || rp.fake_policy_freeze_success_detected || sf.fake_policy_freeze_success_detected;
    pack.fake_policy_review_success_detected = eg.fake_policy_review_success_detected || rp.fake_policy_review_success_detected || sf.fake_policy_review_success_detected;
    pack.fake_policy_hardening_success_detected = eg.fake_policy_hardening_success_detected || rp.fake_policy_hardening_success_detected || sf.fake_policy_hardening_success_detected;
    pack.fake_policy_completion_success_detected = eg.fake_policy_completion_success_detected || rp.fake_policy_completion_success_detected || sf.fake_policy_completion_success_detected;
    pack.fake_completion_review_success_detected = eg.fake_completion_review_success_detected || rp.fake_completion_review_success_detected || sf.fake_completion_review_success_detected;
    pack.fake_next_arc_entry_success_detected = eg.fake_next_arc_entry_success_detected || rp.fake_next_arc_entry_success_detected || sf.fake_next_arc_entry_success_detected;
    pack.fake_next_arc_review_success_detected = rp.fake_next_arc_review_success_detected || sf.fake_next_arc_review_success_detected;
    pack.fake_next_arc_static_freeze_success_detected = sf.fake_next_arc_static_freeze_success_detected;
    // fake_next_arc_freeze_review_success_detected is always false - never set by build
    // Require experimental only
    if !input.require_experimental_only { pf(&mut findings,"NAFRP-NO-EXPERIMENTAL-CONFIRM",EbpfReaderLabNextArcFreezeReviewFindingKind::ReviewInvariant,"experimental-only confirmation not provided",EbpfReaderLabNextArcFreezeReviewPackStatus::ExperimentalOnly); blocked=true; }
    // Frozen arc from I-29 record
    pack.frozen_fixture_only_arc = sf.frozen_fixture_only_arc;
    pack.frozen_static_policy_arc = sf.frozen_static_policy_arc;
    pack.frozen_manual_reader_spike_checklist_arc = sf.frozen_manual_reader_spike_checklist_arc;
    pack.frozen_reader_spike_review_arc = sf.frozen_reader_spike_review_arc;
    let has_safe_arc = sf.frozen_fixture_only_arc || sf.frozen_static_policy_arc
        || sf.frozen_manual_reader_spike_checklist_arc || sf.frozen_reader_spike_review_arc;
    if !has_safe_arc && !blocked {
        pf(&mut findings,"NAFRP-NO-SAFE-ARC",EbpfReaderLabNextArcFreezeReviewFindingKind::ReviewInvariant,"at least one frozen safe arc must be true in freeze record",inc);
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
            || sf.arc_allowed_public_cli || sf.arc_allowed_release || sf.arc_allowed_enforcement;
        let all_inv = !eg_ok && !rp_ok && !sf_ok;
        if has_rel {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReleaseForbidden;
            if !has_dis { pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::RejectReleaseArc; }
        } else if has_dis {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::Blocked;
        } else if has_exp && all_inv {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::Incomplete;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::Stop;
        } else if has_exp {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ExperimentalOnly;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::KeepExperimental;
        } else {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewRejected;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::Stop;
        }
    } else {
        if sf.frozen_static_policy_arc {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenStaticPolicyArc;
        } else if sf.frozen_fixture_only_arc {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenFixtureOnlyArc;
        } else if sf.frozen_manual_reader_spike_checklist_arc {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenManualReaderSpikeChecklistArc;
        } else if sf.frozen_reader_spike_review_arc {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::ReviewFrozenReaderSpikeReviewArc;
        } else {
            pack.status = EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewRejected;
            pack.decision = EbpfReaderLabNextArcFreezeReviewDecision::Stop;
        }
        if pack.status == EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewReady {
            pack.review_ready = true;
        }
    }
    pack.findings = findings;
    pack
}

/// Validate a next arc freeze review pack.
pub fn validate_reader_lab_next_arc_freeze_review_pack(
    pack: &EbpfReaderLabNextArcFreezeReviewPack,
) -> Result<(), String> {
    if pack.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    let deny = |flag: bool, name: &str| -> Result<(), String> {
        if flag {
            Err(format!("{name} must be false in I-30"))
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
        (
            pack.fake_next_arc_static_freeze_success_detected,
            "fake_next_arc_static_freeze_success_detected",
        ),
        (
            pack.fake_next_arc_freeze_review_success_detected,
            "fake_next_arc_freeze_review_success_detected",
        ),
    ];
    for (flag, name) in fakes {
        deny(*flag, name)?;
    }
    if pack.review_ready
        && pack.status == EbpfReaderLabNextArcFreezeReviewPackStatus::ReviewRejected
    {
        return Err("review_ready must be false when status is ReviewRejected".to_string());
    }
    Ok(())
}

/// Map freeze review pack status to label.
pub fn reader_lab_next_arc_freeze_review_pack_status_label(
    status: EbpfReaderLabNextArcFreezeReviewPackStatus,
) -> &'static str {
    status.as_str()
}

/// Map freeze review decision to label.
pub fn reader_lab_next_arc_freeze_review_decision_label(
    decision: EbpfReaderLabNextArcFreezeReviewDecision,
) -> &'static str {
    decision.as_str()
}

/// Map freeze review finding kind to label.
pub fn reader_lab_next_arc_freeze_review_finding_kind_label(
    kind: EbpfReaderLabNextArcFreezeReviewFindingKind,
) -> &'static str {
    kind.as_str()
}
