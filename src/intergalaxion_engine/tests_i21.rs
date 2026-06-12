// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::backends::ebpf::event_stream_reader_lab_next_arc_plan::*;

fn default_safe_input() -> EbpfReaderLabNextArcPlanInput {
    use super::backends::ebpf::event_stream_reader_lab_milestone_freeze::{
        build_reader_lab_milestone_freeze_record, default_reader_lab_milestone_freeze_input,
    };
    use super::backends::ebpf::event_stream_reader_spike_review_pack::{
        build_reader_spike_review_pack, default_reader_spike_review_pack_input,
    };
    let freeze_input = default_reader_lab_milestone_freeze_input();
    let mut milestone_freeze_record = build_reader_lab_milestone_freeze_record(&freeze_input);
    milestone_freeze_record.milestone_frozen = true;
    let pack_input = default_reader_spike_review_pack_input();
    let mut review_pack = build_reader_spike_review_pack(&pack_input);
    review_pack.review_ready = true;
    let mut release_gate_report = pack_input.release_gate_report;
    release_gate_report.ready_for_reader_spike_review = true;
    EbpfReaderLabNextArcPlanInput {
        milestone_freeze_record,
        review_pack,
        release_gate_report,
        prefer_fixture_only_next: false,
        prefer_static_policy_freeze: false,
        prefer_manual_reader_spike_checklist: false,
        prefer_reader_spike_review: false,
        allow_live_reader_next: false,
        allow_public_cli_next: false,
        allow_release_path_next: false,
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

// Coverage 1: default next arc input is safe
#[test]
fn i21_default_input_is_safe() {
    let input = default_reader_lab_next_arc_plan_input();
    assert!(!input.allow_live_reader_next);
    assert!(!input.allow_public_cli_next);
    assert!(!input.allow_release_path_next);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
    assert!(!input.stable_release_requested);
    assert!(!input.tag_requested);
    assert!(!input.publish_requested);
    assert!(!input.version_bump_requested);
    assert!(!input.main_merge_requested);
}

// Coverage 2: default next arc plan phase is I-21
#[test]
fn i21_default_plan_phase_is_i21() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert_eq!(plan.phase, "I-21");
}

// Coverage 3: default plan has all operation flags false
#[test]
fn i21_default_plan_all_ops_false() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(!plan.ring_buffer_opened);
    assert!(!plan.live_event_stream_read);
    assert!(!plan.map_pin_performed);
    assert!(!plan.enforcement_performed);
    assert!(!plan.packet_drop_performed);
    assert!(!plan.mutation_performed);
    assert!(!plan.persistence_performed);
    assert!(!plan.public_cli_exposed);
    assert!(!plan.usage_schema_changed);
    assert!(!plan.ledger_schema_changed);
    assert!(!plan.stable_release_requested);
    assert!(!plan.tag_requested);
    assert!(!plan.publish_requested);
    assert!(!plan.version_bump_requested);
    assert!(!plan.main_merge_requested);
    assert!(!plan.fake_reader_success_detected);
    assert!(!plan.fake_live_event_counts_detected);
    assert!(!plan.fake_release_readiness_detected);
    assert!(!plan.fake_planning_success_detected);
}

// Coverage 4: status labels are stable
#[test]
fn i21_status_labels_stable() {
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::Draft),
        "draft"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::PlanReady),
        "plan_ready"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::PlanRejected),
        "plan_rejected"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::ExperimentalOnly),
        "experimental_only"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::ReleaseForbidden),
        "release_forbidden"
    );
    assert_eq!(
        reader_lab_next_arc_plan_status_label(EbpfReaderLabNextArcPlanStatus::Incomplete),
        "incomplete"
    );
}

// Coverage 5: decision labels are stable
#[test]
fn i21_decision_labels_stable() {
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::Stop),
        "stop"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::FreezeStaticPolicy),
        "freeze_static_policy"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::ContinueFixtureOnly),
        "continue_fixture_only"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(
            EbpfReaderLabNextArcDecision::PrepareManualReaderSpikeChecklist
        ),
        "prepare_manual_reader_spike_checklist"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::PrepareReaderSpikeReview),
        "prepare_reader_spike_review"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::KeepExperimental),
        "keep_experimental"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::RejectRelease),
        "reject_release"
    );
    assert_eq!(
        reader_lab_next_arc_decision_label(EbpfReaderLabNextArcDecision::FixMilestoneEvidence),
        "fix_milestone_evidence"
    );
}

// Coverage 6: finding kind labels are stable
#[test]
fn i21_finding_kind_labels_stable() {
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::MilestoneFreeze),
        "milestone_freeze"
    );
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::ReviewPack),
        "review_pack"
    );
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::ReleaseGate),
        "release_gate"
    );
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::SafetyInvariant),
        "safety_invariant"
    );
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::PlanningInvariant),
        "planning_invariant"
    );
    assert_eq!(
        reader_lab_next_arc_finding_kind_label(EbpfReaderLabNextArcFindingKind::NextArcRisk),
        "next_arc_risk"
    );
}

// Coverage 7: default plan release_allowed=false
#[test]
fn i21_default_release_allowed_false() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(!plan.release_allowed);
}

// Coverage 8: default plan must_remain_experimental=true
#[test]
fn i21_default_must_remain_experimental_true() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(plan.must_remain_experimental);
}

// Coverage 9: default plan is not live-reader enabled
#[test]
fn i21_default_not_live_reader_enabled() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(!plan.live_reader_next_allowed);
    assert!(!plan.public_cli_next_allowed);
    assert!(!plan.release_path_next_allowed);
}

// Coverage 10: default plan findings nonempty or ExperimentalOnly
#[test]
fn i21_default_findings_nonempty_or_experimental() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(
        !plan.findings.is_empty()
            || plan.status == EbpfReaderLabNextArcPlanStatus::ExperimentalOnly
    );
}

// Coverage 11: plan requires milestone freeze valid
#[test]
fn i21_requires_milestone_freeze_valid() {
    let input = default_safe_input();
    let mut bad_freeze = input.milestone_freeze_record.clone();
    bad_freeze.phase = String::new();
    let mut bad_input = input;
    bad_input.milestone_freeze_record = bad_freeze;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-MF-INVALID"));
}

// Coverage 12: plan requires review pack valid
#[test]
fn i21_requires_review_pack_valid() {
    let input = default_safe_input();
    let mut bad_rp = input.review_pack.clone();
    bad_rp.phase = String::new();
    let mut bad_input = input;
    bad_input.review_pack = bad_rp;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-RP-INVALID"));
}

// Coverage 13: plan requires release gate valid
#[test]
fn i21_requires_release_gate_valid() {
    let input = default_safe_input();
    let mut bad_rg = input.release_gate_report.clone();
    bad_rg.phase = String::new();
    let mut bad_input = input;
    bad_input.release_gate_report = bad_rg;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-RG-INVALID"));
}

// Coverage 14: plan requires milestone frozen
#[test]
fn i21_requires_milestone_frozen() {
    let input = default_safe_input();
    let mut bad_input = input;
    bad_input.milestone_freeze_record.milestone_frozen = false;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-MF-NOT-FROZEN"));
}

// Coverage 15: plan requires review pack ready
#[test]
fn i21_requires_review_pack_ready() {
    let input = default_safe_input();
    let mut bad_input = input;
    bad_input.review_pack.review_ready = false;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-RP-NOT-READY"));
}

// Coverage 16: plan requires release gate ready
#[test]
fn i21_requires_release_gate_ready() {
    let input = default_safe_input();
    let mut bad_input = input;
    bad_input.release_gate_report.ready_for_reader_spike_review = false;
    let plan = build_reader_lab_next_arc_plan(&bad_input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-RG-NOT-READY"));
}

// Coverage 17: plan requires at least one safe next preference
#[test]
fn i21_requires_safe_pref() {
    let mut input = default_safe_input();
    input.prefer_fixture_only_next = false;
    input.prefer_static_policy_freeze = false;
    input.prefer_manual_reader_spike_checklist = false;
    input.prefer_reader_spike_review = false;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-NO-SAFE-PREF"));
}

// Coverage 18: priority chooses FreezeStaticPolicy
#[test]
fn i21_priority_freeze_static_policy() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_static_policy_freeze = true;
    input.prefer_fixture_only_next = true;
    input.prefer_manual_reader_spike_checklist = true;
    input.prefer_reader_spike_review = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert_eq!(
        plan.decision,
        EbpfReaderLabNextArcDecision::FreezeStaticPolicy
    );
    assert!(plan.static_policy_freeze_next);
}

// Coverage 19: priority ContinueFixtureOnly over manual/review
#[test]
fn i21_priority_continue_fixture_only() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_fixture_only_next = true;
    input.prefer_manual_reader_spike_checklist = true;
    input.prefer_reader_spike_review = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert_eq!(
        plan.decision,
        EbpfReaderLabNextArcDecision::ContinueFixtureOnly
    );
    assert!(plan.fixture_only_next);
}

// Coverage 20: priority PrepareManualReaderSpikeChecklist over review
#[test]
fn i21_priority_manual_checklist() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_manual_reader_spike_checklist = true;
    input.prefer_reader_spike_review = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert_eq!(
        plan.decision,
        EbpfReaderLabNextArcDecision::PrepareManualReaderSpikeChecklist
    );
    assert!(plan.manual_reader_spike_checklist_next);
}

// Coverage 21: priority PrepareReaderSpikeReview when only review
#[test]
fn i21_priority_reader_spike_review() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_reader_spike_review = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert_eq!(
        plan.decision,
        EbpfReaderLabNextArcDecision::PrepareReaderSpikeReview
    );
    assert!(plan.reader_spike_review_next);
}

// Coverage 22-24: unsafe flags blocked (loop)
#[test]
fn i21_unsafe_flags_blocked() {
    let unsafe_checks: &[(&str, bool)] = &[
        ("allow_live_reader_next", true),
        ("allow_public_cli_next", true),
        ("allow_release_path_next", true),
    ];
    for (field, _val) in unsafe_checks {
        let mut input = default_safe_input();
        make_input_plan_ready(&mut input);
        match *field {
            "allow_live_reader_next" => input.allow_live_reader_next = true,
            "allow_public_cli_next" => input.allow_public_cli_next = true,
            "allow_release_path_next" => input.allow_release_path_next = true,
            _ => unreachable!(),
        }
        let plan = build_reader_lab_next_arc_plan(&input);
        assert_eq!(
            plan.status,
            EbpfReaderLabNextArcPlanStatus::Blocked,
            "{} should be blocked",
            field
        );
    }
}

// Coverage 25: rejects public_cli_expected_hidden=false
#[test]
fn i21_rejects_cli_not_hidden() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.public_cli_expected_hidden = false;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan
        .findings
        .iter()
        .any(|f| f.code == "PLAN-CLI-EXPECTED-HIDDEN"));
}

// Coverage 26: rejects usage_schema_expected_unchanged=false
#[test]
fn i21_rejects_usage_schema_changed() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.usage_schema_expected_unchanged = false;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan
        .findings
        .iter()
        .any(|f| f.code == "PLAN-USAGE-SCHEMA-CHANGED"));
}

// Coverage 27: rejects ledger_schema_expected_unchanged=false
#[test]
fn i21_rejects_ledger_schema_changed() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.ledger_schema_expected_unchanged = false;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan
        .findings
        .iter()
        .any(|f| f.code == "PLAN-LEDGER-SCHEMA-CHANGED"));
}

// Coverage 28-32: release/tag/publish/version/main requests block (loop)
#[test]
fn i21_release_requests_blocked() {
    let release_checks: &[(&str, &str)] = &[
        ("stable_release_requested", "PLAN-RELEASE-REQUESTED"),
        ("tag_requested", "PLAN-TAG-REQUESTED"),
        ("publish_requested", "PLAN-PUBLISH-REQUESTED"),
        ("version_bump_requested", "PLAN-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "PLAN-MAIN-MERGE-REQUESTED"),
    ];
    for (field, code) in release_checks {
        let mut input = default_safe_input();
        make_input_plan_ready(&mut input);
        match *field {
            "stable_release_requested" => {
                input.stable_release_requested = true;
            }
            "tag_requested" => {
                input.tag_requested = true;
            }
            "publish_requested" => {
                input.publish_requested = true;
            }
            "version_bump_requested" => {
                input.version_bump_requested = true;
            }
            "main_merge_requested" => {
                input.main_merge_requested = true;
            }
            _ => unreachable!(),
        }
        let plan = build_reader_lab_next_arc_plan(&input);
        assert_eq!(
            plan.status,
            EbpfReaderLabNextArcPlanStatus::ReleaseForbidden,
            "{} should be ReleaseForbidden",
            field
        );
        assert!(
            plan.findings.iter().any(|f| f.code == *code),
            "{} should have finding {}",
            field,
            code
        );
    }
}

// Coverage 33-35: fake detections rejected
#[test]
fn i21_fake_detections_rejected() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.milestone_freeze_record.fake_reader_success_detected = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-FAKE-READER"));

    input.milestone_freeze_record.fake_reader_success_detected = false;
    input
        .milestone_freeze_record
        .fake_live_event_counts_detected = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-FAKE-EVENTS"));

    input
        .milestone_freeze_record
        .fake_live_event_counts_detected = false;
    input
        .milestone_freeze_record
        .fake_release_readiness_detected = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan.findings.iter().any(|f| f.code == "PLAN-FAKE-RELEASE"));
}

// Coverage 36: plan can become PlanReady with fixture-only next
#[test]
fn i21_plan_ready_fixture_only() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_fixture_only_next = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert_eq!(plan.status, EbpfReaderLabNextArcPlanStatus::PlanReady);
    assert!(plan.plan_ready);
}

// Coverage 37: PlanReady release_allowed=false
#[test]
fn i21_plan_ready_release_allowed_false() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_fixture_only_next = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(!plan.release_allowed);
}

// Coverage 38: PlanReady must_remain_experimental=true
#[test]
fn i21_plan_ready_must_remain_experimental() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_fixture_only_next = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(plan.must_remain_experimental);
}

// Coverage 39-41: PlanReady next flags are false
#[test]
fn i21_plan_ready_next_flags_false() {
    let mut input = default_safe_input();
    make_input_plan_ready(&mut input);
    input.prefer_fixture_only_next = true;
    let plan = build_reader_lab_next_arc_plan(&input);
    assert!(!plan.live_reader_next_allowed);
    assert!(!plan.public_cli_next_allowed);
    assert!(!plan.release_path_next_allowed);
}

// Coverage 42: validation accepts safe default plan
#[test]
fn i21_validation_accepts_safe_default() {
    let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
    assert!(validate_reader_lab_next_arc_plan(&plan).is_ok());
}

// Coverage 43-67: validation rejects unsafe fields (loop)
#[test]
fn i21_validation_rejects_unsafe_fields() {
    // (field_name, bad_value_code_for_assertion)
    let unsafe_validation_checks: &[&str] = &[
        "plan_ready_plan_rejected",
        "release_allowed",
        "must_remain_experimental_false",
        "live_reader_next_allowed",
        "public_cli_next_allowed",
        "release_path_next_allowed",
        "public_cli_exposed",
        "usage_schema_changed",
        "ledger_schema_changed",
        "stable_release_requested",
        "tag_requested",
        "publish_requested",
        "version_bump_requested",
        "main_merge_requested",
        "ring_buffer_opened",
        "live_event_stream_read",
        "map_pin_performed",
        "enforcement_performed",
        "packet_drop_performed",
        "mutation_performed",
        "persistence_performed",
        "fake_reader_success_detected",
        "fake_live_event_counts_detected",
        "fake_release_readiness_detected",
        "fake_planning_success_detected",
    ];
    for check in unsafe_validation_checks {
        let plan = build_reader_lab_next_arc_plan(&default_reader_lab_next_arc_plan_input());
        let mut bad = plan;
        match *check {
            "plan_ready_plan_rejected" => {
                bad.plan_ready = true;
                bad.status = EbpfReaderLabNextArcPlanStatus::PlanRejected;
            }
            "release_allowed" => {
                bad.release_allowed = true;
            }
            "must_remain_experimental_false" => {
                bad.must_remain_experimental = false;
            }
            "live_reader_next_allowed" => {
                bad.live_reader_next_allowed = true;
            }
            "public_cli_next_allowed" => {
                bad.public_cli_next_allowed = true;
            }
            "release_path_next_allowed" => {
                bad.release_path_next_allowed = true;
            }
            "public_cli_exposed" => {
                bad.public_cli_exposed = true;
            }
            "usage_schema_changed" => {
                bad.usage_schema_changed = true;
            }
            "ledger_schema_changed" => {
                bad.ledger_schema_changed = true;
            }
            "stable_release_requested" => {
                bad.stable_release_requested = true;
            }
            "tag_requested" => {
                bad.tag_requested = true;
            }
            "publish_requested" => {
                bad.publish_requested = true;
            }
            "version_bump_requested" => {
                bad.version_bump_requested = true;
            }
            "main_merge_requested" => {
                bad.main_merge_requested = true;
            }
            "ring_buffer_opened" => {
                bad.ring_buffer_opened = true;
            }
            "live_event_stream_read" => {
                bad.live_event_stream_read = true;
            }
            "map_pin_performed" => {
                bad.map_pin_performed = true;
            }
            "enforcement_performed" => {
                bad.enforcement_performed = true;
            }
            "packet_drop_performed" => {
                bad.packet_drop_performed = true;
            }
            "mutation_performed" => {
                bad.mutation_performed = true;
            }
            "persistence_performed" => {
                bad.persistence_performed = true;
            }
            "fake_reader_success_detected" => {
                bad.fake_reader_success_detected = true;
            }
            "fake_live_event_counts_detected" => {
                bad.fake_live_event_counts_detected = true;
            }
            "fake_release_readiness_detected" => {
                bad.fake_release_readiness_detected = true;
            }
            "fake_planning_success_detected" => {
                bad.fake_planning_success_detected = true;
            }
            _ => unreachable!(),
        }
        assert!(
            validate_reader_lab_next_arc_plan(&bad).is_err(),
            "validation should reject {}",
            check
        );
    }
}

// Coverage 68: blocked/rejected plan has blocking finding
#[test]
fn i21_blocked_plan_has_blocking_finding() {
    let input = default_safe_input();
    let plan = build_reader_lab_next_arc_plan(&input);
    if plan.status == EbpfReaderLabNextArcPlanStatus::Blocked
        || plan.status == EbpfReaderLabNextArcPlanStatus::ReleaseForbidden
    {
        assert!(
            plan.findings.iter().any(|f| f.blocking),
            "blocked plan must have at least one blocking finding"
        );
    }
}

// Coverage 69: evaluation is deterministic
#[test]
fn i21_evaluation_deterministic() {
    let input = default_reader_lab_next_arc_plan_input();
    let p1 = build_reader_lab_next_arc_plan(&input);
    let p2 = build_reader_lab_next_arc_plan(&input);
    assert_eq!(p1, p2);
}

// Coverage 70-94: doc checks (file existence + content keywords)
#[test]
fn i21_docs_exist_and_cover_planning() {
    let content =
        std::fs::read_to_string("docs/intergalaxion/I-21-reader-lab-next-arc-planning.md")
            .expect("I-21 doc must exist");
    assert!(content.contains("next arc planning"));
    assert!(content.contains("planning-only"));
    assert!(content.contains("not a release"));
    let keywords = [
        "no tag",
        "no release",
        "no publish",
        "no version bump",
        "no main merge",
        "no public CLI",
        "no ring buffer",
        "no live kernel event read",
        "no map pin",
        "no enforcement",
        "no packet drop",
        "no block",
        "no nft",
        "no ledger file write",
        "no persistence",
        "usage JSON schema unchanged",
        "ledger JSON schema unchanged",
        "release_allowed is always false",
        "must_remain_experimental is always true",
        "live reader next is not allowed",
        "public CLI next is not allowed",
        "release path next is not allowed",
        "fake reader execution success",
        "fake live event counts",
        "fake release readiness",
        "fake planning success",
    ];
    for kw in &keywords {
        assert!(
            content.to_lowercase().contains(&kw.to_lowercase()),
            "doc must mention: {}",
            kw
        );
    }
}

// Coverage 95: version remains v3.1.0
#[test]
fn i21_version_remains_v310() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let ver = std::process::Command::new("./target/release/zelynic")
        .args(["--version"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("version check");
    let ver_str = String::from_utf8_lossy(&ver.stdout);
    assert!(
        ver_str.contains("3.1.0"),
        "version should be 3.1.0, got: {}",
        ver_str
    );
}

// Coverage 96: ledger inspect --json works
#[test]
fn i21_ledger_inspect_works() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let inspect = std::process::Command::new("./target/release/zelynic")
        .args(["ledger", "inspect", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("ledger inspect");
    assert!(inspect.status.success());
}

// Coverage 97: ledger export --json --file works
#[test]
fn i21_ledger_export_works() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let tmp = std::env::temp_dir().join("i21-ledger-export-test.json");
    std::fs::write(
        &tmp,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i21-test","entries":[]}"#,
    )
    .expect("write tmp ledger");
    let export = std::process::Command::new("./target/release/zelynic")
        .args([
            "ledger",
            "export",
            "--json",
            "--file",
            tmp.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("ledger export");
    assert!(export.status.success());
    let _ = std::fs::remove_file(tmp);
}

// Coverage 98: public help does not mention intergalaxion
#[test]
fn i21_help_no_intergalaxion() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let help = std::process::Command::new("./target/release/zelynic")
        .args(["--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("help");
    let help_str = String::from_utf8_lossy(&help.stdout);
    assert!(
        !help_str.to_lowercase().contains("intergalaxion"),
        "public help should not mention intergalaxion"
    );
}

// Coverage 99: public help does not mention block/allow/quota
#[test]
fn i21_help_no_block_allow_quota() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let help = std::process::Command::new("./target/release/zelynic")
        .args(["--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("help");
    let help_str = String::from_utf8_lossy(&help.stdout);
    let lower = help_str.to_lowercase();
    assert!(
        !lower.contains("block") && !lower.contains("allow") && !lower.contains("quota"),
        "public help should not mention block/allow/quota"
    );
}

// Coverage 100: no new dependency added
#[test]
fn i21_no_new_dependency() {
    let toml = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml must exist");
    let toml_lower = toml.to_lowercase();
    assert!(
        !toml_lower.contains("aya = ") && !toml_lower.contains("aya="),
        "no new aya runtime dependency"
    );
}

// Coverage 101: no nft/tc source under intergalaxion backend
#[test]
fn i21_no_nft_tc_source() {
    let backend_dir = "src/intergalaxion_engine/backends/ebpf";
    for entry in std::fs::read_dir(backend_dir).expect("backend dir must exist") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // I-32+ introduced brave-specific tc/ifb dry-run files (allowed)
        let is_brave_tc = name_str.contains("brave_limit_lab_plan")
            || name_str.contains("brave_tc_ifb_dry_run_wiring");
        assert!(
            (!name_str.contains("nft") && !name_str.contains("tc")) || is_brave_tc,
            "no nft/tc source: {}",
            name_str
        );
    }
}

// Coverage 102: all touched files under 1000 LOC
#[test]
fn i21_all_files_under_1000_loc() {
    let files = [
        "src/intergalaxion_engine/backends/ebpf/event_stream_reader_lab_next_arc_plan.rs",
        "src/intergalaxion_engine/tests_i21.rs",
    ];
    for f in &files {
        let content = std::fs::read_to_string(f).unwrap_or_else(|_| String::new());
        let count = content.lines().count();
        assert!(count < 1000, "{} is {} lines (must be < 1000)", f, count);
    }
}

// Helper: make input plan-ready by setting all evidence to valid+frozen+ready
fn make_input_plan_ready(input: &mut EbpfReaderLabNextArcPlanInput) {
    input.milestone_freeze_record.milestone_frozen = true;
    input.review_pack.review_ready = true;
    input.release_gate_report.ready_for_reader_spike_review = true;
}
