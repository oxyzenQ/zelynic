// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Reader lab static policy freeze model for the Intergalaxion Engine.
//!
//! Phase I-22 freezes the static policy for the next Intergalaxion reader
//! lab arc after the I-21 next-arc planning. This phase is
//! static-policy-freeze only — not a release, not a public feature, not a
//! live reader, not a ring buffer reader, not a kernel event consumer. It
//! is an internal deterministic static policy checkpoint only.
//!
//! # Design constraints (I-22)
//!
//! * Static-policy-freeze only — not a release, not a live reader.
//! * No tag, no release, no publish, no version bump, no main merge.
//! * No ring buffer open, no live kernel event read, no map pin.
//! * No enforcement, no packet drop, no traffic shaping commands.
//! * No nft/tc backend, no nft/tc fallback.
//! * No public CLI exposure.
//! * No ledger file write, no persistence.
//! * No fake static policy freeze success, no fake release readiness.
//! * release_allowed is always false in I-22.
//! * must_remain_experimental is always true in I-22.
//! * Normal tests remain rootless.

use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
    validate_reader_lab_next_arc_plan, EbpfReaderLabNextArcPlan,
};

/// Status of the reader lab static policy freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyFreezeStatus {
    /// Policy freeze is in draft form.
    Draft,
    /// Evidence is incomplete.
    Incomplete,
    /// Blocked by a hard safety gate.
    Blocked,
    /// Policy is frozen.
    Frozen,
    /// Policy freeze was rejected.
    FreezeRejected,
    /// Branch must remain experimental.
    ExperimentalOnly,
    /// Release is forbidden.
    ReleaseForbidden,
}

impl EbpfReaderLabStaticPolicyFreezeStatus {
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

/// Decision produced by the reader lab static policy freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyFreezeDecision {
    /// Stop and do not proceed.
    Stop,
    /// Fix next arc plan before proceeding.
    FixNextArcPlan,
    /// Freeze the static policy.
    FreezeStaticPolicy,
    /// Keep the branch experimental.
    KeepExperimental,
    /// Reject any release.
    RejectRelease,
    /// Prepare review pack.
    PrepareReviewPack,
}

impl EbpfReaderLabStaticPolicyFreezeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::FixNextArcPlan => "fix_next_arc_plan",
            Self::FreezeStaticPolicy => "freeze_static_policy",
            Self::KeepExperimental => "keep_experimental",
            Self::RejectRelease => "reject_release",
            Self::PrepareReviewPack => "prepare_review_pack",
        }
    }
}

/// Kind of static policy freeze finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfReaderLabStaticPolicyFindingKind {
    /// Next arc plan finding.
    NextArcPlan,
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
    /// Policy invariant finding.
    PolicyInvariant,
}

impl EbpfReaderLabStaticPolicyFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextArcPlan => "next_arc_plan",
            Self::ReleaseInvariant => "release_invariant",
            Self::CliInvariant => "cli_invariant",
            Self::SchemaInvariant => "schema_invariant",
            Self::RuntimeInvariant => "runtime_invariant",
            Self::KernelInvariant => "kernel_invariant",
            Self::MutationInvariant => "mutation_invariant",
            Self::FakeEvidenceInvariant => "fake_evidence_invariant",
            Self::PolicyInvariant => "policy_invariant",
        }
    }
}

/// A single finding produced by the static policy freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyFinding {
    /// Unique finding code.
    pub code: String,
    /// Kind of finding.
    pub kind: EbpfReaderLabStaticPolicyFindingKind,
    /// Human-readable message.
    pub message: String,
    /// Whether this finding is blocking.
    pub blocking: bool,
    /// Status associated with this finding.
    pub status: EbpfReaderLabStaticPolicyFreezeStatus,
}

/// Input to the reader lab static policy freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyFreezeInput {
    /// The I-21 next arc plan.
    pub next_arc_plan: EbpfReaderLabNextArcPlan,
    /// Whether the next arc plan must be ready.
    pub require_next_arc_plan_ready: bool,
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
    /// Whether a live reader is allowed in the future (must block).
    pub allow_live_reader_next: bool,
    /// Whether a public CLI is allowed in the future (must block).
    pub allow_public_cli_next: bool,
    /// Whether a release path is allowed in the future (must block).
    pub allow_release_path_next: bool,
    /// Whether ring buffer open is allowed (must block).
    pub allow_ring_buffer_open: bool,
    /// Whether live event read is allowed (must block).
    pub allow_live_event_read: bool,
    /// Whether map pin is allowed (must block).
    pub allow_map_pin: bool,
    /// Whether enforcement is allowed (must block).
    pub allow_enforcement: bool,
    /// Whether packet drop is allowed (must block).
    pub allow_packet_drop: bool,
    /// Whether persistence is allowed (must block).
    pub allow_persistence: bool,
}

/// Record produced by the reader lab static policy freeze evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfReaderLabStaticPolicyFreezeRecord {
    /// The phase this record covers.
    pub phase: String,
    /// The freeze status.
    pub status: EbpfReaderLabStaticPolicyFreezeStatus,
    /// The freeze decision.
    pub decision: EbpfReaderLabStaticPolicyFreezeDecision,
    /// Whether the static policy is frozen.
    pub policy_frozen: bool,
    /// Whether release is allowed (always false in I-22).
    pub release_allowed: bool,
    /// Whether the branch must remain experimental (always true in I-22).
    pub must_remain_experimental: bool,
    /// Findings produced during evaluation.
    pub findings: Vec<EbpfReaderLabStaticPolicyFinding>,
    /// Whether the next arc plan is ready.
    pub next_arc_plan_ready: bool,
    /// Whether experimental-only mode is confirmed.
    pub experimental_only_confirmed: bool,
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
    /// Whether a live reader is allowed in the future.
    pub live_reader_next_allowed: bool,
    /// Whether a public CLI is allowed in the future.
    pub public_cli_next_allowed: bool,
    /// Whether a release path is allowed in the future.
    pub release_path_next_allowed: bool,
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
}

// -- Helper functions --

fn safe_base_record() -> EbpfReaderLabStaticPolicyFreezeRecord {
    EbpfReaderLabStaticPolicyFreezeRecord {
        phase: String::from("I-22"),
        status: EbpfReaderLabStaticPolicyFreezeStatus::Draft,
        decision: EbpfReaderLabStaticPolicyFreezeDecision::Stop,
        policy_frozen: false,
        release_allowed: false,
        must_remain_experimental: true,
        findings: Vec::new(),
        next_arc_plan_ready: false,
        experimental_only_confirmed: false,
        public_cli_exposed: false,
        usage_schema_changed: false,
        ledger_schema_changed: false,
        stable_release_requested: false,
        tag_requested: false,
        publish_requested: false,
        version_bump_requested: false,
        main_merge_requested: false,
        live_reader_next_allowed: false,
        public_cli_next_allowed: false,
        release_path_next_allowed: false,
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
    }
}

/// Create the default reader lab static policy freeze input.
///
/// Builds a safe next arc plan from I-21 defaults, then wraps it with safe
/// configuration flags. No unsafe allowances or requests are included.
pub fn default_reader_lab_static_policy_freeze_input() -> EbpfReaderLabStaticPolicyFreezeInput {
    use crate::intergalaxion_engine::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        build_reader_lab_next_arc_plan, default_reader_lab_next_arc_plan_input,
    };
    let next_arc_plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    EbpfReaderLabStaticPolicyFreezeInput {
        next_arc_plan,
        require_next_arc_plan_ready: false,
        require_experimental_only: false,
        public_cli_expected_hidden: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
        stable_release_requested: false,
        tag_requested: false,
        publish_requested: false,
        version_bump_requested: false,
        main_merge_requested: false,
        allow_live_reader_next: false,
        allow_public_cli_next: false,
        allow_release_path_next: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

/// Build the reader lab static policy freeze record from input.
///
/// Validates the next arc plan, checks safety flags, verifies no unsafe
/// requests or allowances, and determines the overall freeze status,
/// decision, and findings. Release is always rejected in I-22.
pub fn build_reader_lab_static_policy_freeze_record(
    input: &EbpfReaderLabStaticPolicyFreezeInput,
) -> EbpfReaderLabStaticPolicyFreezeRecord {
    let mut rec = safe_base_record();
    let mut findings: Vec<EbpfReaderLabStaticPolicyFinding> = Vec::new();
    let mut blocked = false;

    // Validate next arc plan
    let plan_valid = validate_reader_lab_next_arc_plan(&input.next_arc_plan).is_ok();
    rec.next_arc_plan_ready = plan_valid;

    if !plan_valid {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-PLAN-INVALID"),
            kind: EbpfReaderLabStaticPolicyFindingKind::NextArcPlan,
            message: String::from("next arc plan validation failed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Incomplete,
        });
        blocked = true;
    }

    // Require plan ready when configured
    if input.require_next_arc_plan_ready && !input.next_arc_plan.plan_ready {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-PLAN-NOT-READY"),
            kind: EbpfReaderLabStaticPolicyFindingKind::NextArcPlan,
            message: String::from("next arc plan is not ready"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Incomplete,
        });
        blocked = true;
    }

    // Experimental-only check
    if input.require_experimental_only {
        rec.experimental_only_confirmed = true;
        if !input.next_arc_plan.must_remain_experimental {
            findings.push(EbpfReaderLabStaticPolicyFinding {
                code: String::from("SPF-NOT-EXPERIMENTAL"),
                kind: EbpfReaderLabStaticPolicyFindingKind::PolicyInvariant,
                message: String::from("next arc plan must remain experimental"),
                blocking: true,
                status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
            });
            blocked = true;
        }
        if input.next_arc_plan.release_allowed {
            findings.push(EbpfReaderLabStaticPolicyFinding {
                code: String::from("SPF-RELEASE-ALLOWED"),
                kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
                message: String::from("next arc plan incorrectly allows release"),
                blocking: true,
                status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
            });
            blocked = true;
        }
    }

    // Release/tag/publish/version/main requests
    if input.stable_release_requested {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-RELEASE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("stable release requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.tag_requested {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-TAG-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("tag requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.publish_requested {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-PUBLISH-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("publish requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.version_bump_requested {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-VERSION-BUMP-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("version bump requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
        });
        blocked = true;
    }
    if input.main_merge_requested {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-MAIN-MERGE-REQUESTED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("main merge requested in experimental branch"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
        });
        blocked = true;
    }

    // Unsafe future allowances
    if input.allow_live_reader_next {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-LIVE-READER"),
            kind: EbpfReaderLabStaticPolicyFindingKind::RuntimeInvariant,
            message: String::from("live reader not allowed in static policy freeze"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_public_cli_next {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-PUBLIC-CLI"),
            kind: EbpfReaderLabStaticPolicyFindingKind::CliInvariant,
            message: String::from("public CLI not allowed in static policy freeze"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_release_path_next {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-RELEASE-PATH"),
            kind: EbpfReaderLabStaticPolicyFindingKind::ReleaseInvariant,
            message: String::from("release path not allowed in static policy freeze"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }

    // CLI and schema checks
    if !input.public_cli_expected_hidden {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-CLI-NOT-HIDDEN"),
            kind: EbpfReaderLabStaticPolicyFindingKind::CliInvariant,
            message: String::from("public CLI expected hidden but was not"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if !input.usage_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-USAGE-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::SchemaInvariant,
            message: String::from("usage schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if !input.ledger_schema_expected_unchanged {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-LEDGER-SCHEMA-CHANGED"),
            kind: EbpfReaderLabStaticPolicyFindingKind::SchemaInvariant,
            message: String::from("ledger schema expected unchanged but was changed"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }

    // Runtime/Kernel operation flags
    if input.allow_ring_buffer_open {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-RINGBUF"),
            kind: EbpfReaderLabStaticPolicyFindingKind::KernelInvariant,
            message: String::from("ring buffer open not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_live_event_read {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-LIVE-EVENT"),
            kind: EbpfReaderLabStaticPolicyFindingKind::KernelInvariant,
            message: String::from("live event read not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_map_pin {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-MAP-PIN"),
            kind: EbpfReaderLabStaticPolicyFindingKind::KernelInvariant,
            message: String::from("map pin not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_enforcement {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-ENFORCEMENT"),
            kind: EbpfReaderLabStaticPolicyFindingKind::MutationInvariant,
            message: String::from("enforcement not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_packet_drop {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-PACKET-DROP"),
            kind: EbpfReaderLabStaticPolicyFindingKind::MutationInvariant,
            message: String::from("packet drop not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.allow_persistence {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-ALLOW-PERSISTENCE"),
            kind: EbpfReaderLabStaticPolicyFindingKind::MutationInvariant,
            message: String::from("persistence not allowed in static policy"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }

    // Fake evidence detection
    if input.next_arc_plan.fake_reader_success_detected {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-FAKE-READER"),
            kind: EbpfReaderLabStaticPolicyFindingKind::FakeEvidenceInvariant,
            message: String::from("fake reader execution success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_live_event_counts_detected {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-FAKE-EVENTS"),
            kind: EbpfReaderLabStaticPolicyFindingKind::FakeEvidenceInvariant,
            message: String::from("fake live event counts detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_release_readiness_detected {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-FAKE-RELEASE"),
            kind: EbpfReaderLabStaticPolicyFindingKind::FakeEvidenceInvariant,
            message: String::from("fake release readiness detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }
    if input.next_arc_plan.fake_planning_success_detected {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-FAKE-PLANNING"),
            kind: EbpfReaderLabStaticPolicyFindingKind::FakeEvidenceInvariant,
            message: String::from("fake planning success detected"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::Blocked,
        });
        blocked = true;
    }

    // Require experimental-only confirmation for freeze
    if !input.require_experimental_only {
        findings.push(EbpfReaderLabStaticPolicyFinding {
            code: String::from("SPF-NO-EXPERIMENTAL-CONFIRM"),
            kind: EbpfReaderLabStaticPolicyFindingKind::PolicyInvariant,
            message: String::from("experimental-only confirmation not provided"),
            blocking: true,
            status: EbpfReaderLabStaticPolicyFreezeStatus::ExperimentalOnly,
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
        if has_release_block {
            rec.status = EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden;
            rec.decision = EbpfReaderLabStaticPolicyFreezeDecision::RejectRelease;
        } else if has_experimental_only_block && !plan_valid {
            rec.status = EbpfReaderLabStaticPolicyFreezeStatus::Incomplete;
            rec.decision = EbpfReaderLabStaticPolicyFreezeDecision::FixNextArcPlan;
        } else if has_experimental_only_block {
            rec.status = EbpfReaderLabStaticPolicyFreezeStatus::ExperimentalOnly;
            rec.decision = EbpfReaderLabStaticPolicyFreezeDecision::KeepExperimental;
        } else {
            rec.status = EbpfReaderLabStaticPolicyFreezeStatus::Blocked;
            rec.decision = EbpfReaderLabStaticPolicyFreezeDecision::FixNextArcPlan;
        }
    } else {
        rec.status = EbpfReaderLabStaticPolicyFreezeStatus::Frozen;
        rec.decision = EbpfReaderLabStaticPolicyFreezeDecision::FreezeStaticPolicy;
        rec.policy_frozen = true;
    }

    rec.findings = findings;
    rec
}

/// Validate that a reader lab static policy freeze record is safe.
pub fn validate_reader_lab_static_policy_freeze_record(
    record: &EbpfReaderLabStaticPolicyFreezeRecord,
) -> Result<(), String> {
    if record.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if record.release_allowed {
        return Err("release_allowed must be false in I-22".to_string());
    }
    if !record.must_remain_experimental {
        return Err("must_remain_experimental must be true in I-22".to_string());
    }
    if record.public_cli_exposed {
        return Err("public_cli_exposed must be false".to_string());
    }
    if record.usage_schema_changed {
        return Err("usage_schema_changed must be false".to_string());
    }
    if record.ledger_schema_changed {
        return Err("ledger_schema_changed must be false".to_string());
    }
    if record.stable_release_requested {
        return Err("stable_release_requested must be false".to_string());
    }
    if record.tag_requested {
        return Err("tag_requested must be false".to_string());
    }
    if record.publish_requested {
        return Err("publish_requested must be false".to_string());
    }
    if record.version_bump_requested {
        return Err("version_bump_requested must be false".to_string());
    }
    if record.main_merge_requested {
        return Err("main_merge_requested must be false".to_string());
    }
    if record.live_reader_next_allowed {
        return Err("live_reader_next_allowed must be false".to_string());
    }
    if record.public_cli_next_allowed {
        return Err("public_cli_next_allowed must be false".to_string());
    }
    if record.release_path_next_allowed {
        return Err("release_path_next_allowed must be false".to_string());
    }
    if record.ring_buffer_opened {
        return Err("ring_buffer_opened must be false".to_string());
    }
    if record.live_event_stream_read {
        return Err("live_event_stream_read must be false".to_string());
    }
    if record.map_pin_performed {
        return Err("map_pin_performed must be false".to_string());
    }
    if record.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if record.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if record.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if record.persistence_performed {
        return Err("persistence_performed must be false".to_string());
    }
    if record.fake_reader_success_detected {
        return Err("fake_reader_success_detected must be false".to_string());
    }
    if record.fake_live_event_counts_detected {
        return Err("fake_live_event_counts_detected must be false".to_string());
    }
    if record.fake_release_readiness_detected {
        return Err("fake_release_readiness_detected must be false".to_string());
    }
    if record.fake_planning_success_detected {
        return Err("fake_planning_success_detected must be false".to_string());
    }
    if record.fake_policy_freeze_success_detected {
        return Err("fake_policy_freeze_success_detected must be false".to_string());
    }
    if record.policy_frozen
        && record.status == EbpfReaderLabStaticPolicyFreezeStatus::FreezeRejected
    {
        return Err("policy_frozen must be false when status is FreezeRejected".to_string());
    }
    Ok(())
}

/// Map a static policy freeze status to a stable human-readable label.
pub fn reader_lab_static_policy_freeze_status_label(
    status: EbpfReaderLabStaticPolicyFreezeStatus,
) -> &'static str {
    status.as_str()
}

/// Map a static policy freeze decision to a stable human-readable label.
pub fn reader_lab_static_policy_freeze_decision_label(
    decision: EbpfReaderLabStaticPolicyFreezeDecision,
) -> &'static str {
    decision.as_str()
}

/// Map a static policy freeze finding kind to a stable human-readable label.
pub fn reader_lab_static_policy_finding_kind_label(
    kind: EbpfReaderLabStaticPolicyFindingKind,
) -> &'static str {
    kind.as_str()
}
