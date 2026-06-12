// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::backends::ebpf::event_stream_reader_lab_static_policy_freeze::*;

fn frozen_input() -> EbpfReaderLabStaticPolicyFreezeInput {
    use super::backends::ebpf::event_stream_reader_lab_next_arc_plan::{
        safe_base_plan, validate_reader_lab_next_arc_plan,
    };
    // Build a valid plan-ready next arc plan by constructing manually
    let mut plan = safe_base_plan();
    plan.plan_ready = true;
    plan.release_allowed = false;
    plan.must_remain_experimental = true;
    plan.milestone_frozen = true;
    plan.review_pack_ready = true;
    plan.release_gate_ready = true;
    plan.fixture_only_next = true;
    assert!(validate_reader_lab_next_arc_plan(&plan).is_ok());
    EbpfReaderLabStaticPolicyFreezeInput {
        next_arc_plan: plan,
        require_next_arc_plan_ready: true,
        require_experimental_only: true,
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

// Coverage 1: default static policy freeze input is safe
#[test]
fn i22_default_input_is_safe() {
    let input = default_reader_lab_static_policy_freeze_input();
    assert!(!input.allow_live_reader_next);
    assert!(!input.allow_public_cli_next);
    assert!(!input.allow_release_path_next);
    assert!(!input.allow_ring_buffer_open);
    assert!(!input.allow_live_event_read);
    assert!(!input.allow_map_pin);
    assert!(!input.allow_enforcement);
    assert!(!input.allow_packet_drop);
    assert!(!input.allow_persistence);
    assert!(input.public_cli_expected_hidden);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
    assert!(!input.stable_release_requested);
    assert!(!input.tag_requested);
    assert!(!input.publish_requested);
    assert!(!input.version_bump_requested);
    assert!(!input.main_merge_requested);
}

// Coverage 2: default static policy record phase is I-22
#[test]
fn i22_default_record_phase_is_i22() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert_eq!(rec.phase, "I-22");
}

// Coverage 3: default record has all operation flags false
#[test]
fn i22_default_all_ops_false() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(!rec.ring_buffer_opened);
    assert!(!rec.live_event_stream_read);
    assert!(!rec.map_pin_performed);
    assert!(!rec.enforcement_performed);
    assert!(!rec.packet_drop_performed);
    assert!(!rec.mutation_performed);
    assert!(!rec.persistence_performed);
    assert!(!rec.public_cli_exposed);
    assert!(!rec.usage_schema_changed);
    assert!(!rec.ledger_schema_changed);
    assert!(!rec.stable_release_requested);
    assert!(!rec.tag_requested);
    assert!(!rec.publish_requested);
    assert!(!rec.version_bump_requested);
    assert!(!rec.main_merge_requested);
    assert!(!rec.live_reader_next_allowed);
    assert!(!rec.public_cli_next_allowed);
    assert!(!rec.release_path_next_allowed);
    assert!(!rec.fake_reader_success_detected);
    assert!(!rec.fake_live_event_counts_detected);
    assert!(!rec.fake_release_readiness_detected);
    assert!(!rec.fake_planning_success_detected);
    assert!(!rec.fake_policy_freeze_success_detected);
}

// Coverage 4: status labels are stable
#[test]
fn i22_status_labels_stable() {
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(EbpfReaderLabStaticPolicyFreezeStatus::Draft),
        "draft"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(EbpfReaderLabStaticPolicyFreezeStatus::Frozen),
        "frozen"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(
            EbpfReaderLabStaticPolicyFreezeStatus::Blocked
        ),
        "blocked"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(
            EbpfReaderLabStaticPolicyFreezeStatus::FreezeRejected
        ),
        "freeze_rejected"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(
            EbpfReaderLabStaticPolicyFreezeStatus::ExperimentalOnly
        ),
        "experimental_only"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(
            EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden
        ),
        "release_forbidden"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_status_label(
            EbpfReaderLabStaticPolicyFreezeStatus::Incomplete
        ),
        "incomplete"
    );
}

// Coverage 5: decision labels are stable
#[test]
fn i22_decision_labels_stable() {
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::Stop
        ),
        "stop"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::FreezeStaticPolicy
        ),
        "freeze_static_policy"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::KeepExperimental
        ),
        "keep_experimental"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::RejectRelease
        ),
        "reject_release"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::FixNextArcPlan
        ),
        "fix_next_arc_plan"
    );
    assert_eq!(
        reader_lab_static_policy_freeze_decision_label(
            EbpfReaderLabStaticPolicyFreezeDecision::PrepareReviewPack
        ),
        "prepare_review_pack"
    );
}

// Coverage 6: finding kind labels are stable
#[test]
fn i22_finding_kind_labels_stable() {
    assert_eq!(
        reader_lab_static_policy_finding_kind_label(
            EbpfReaderLabStaticPolicyFindingKind::NextArcPlan
        ),
        "next_arc_plan"
    );
    assert_eq!(
        reader_lab_static_policy_finding_kind_label(
            EbpfReaderLabStaticPolicyFindingKind::PolicyInvariant
        ),
        "policy_invariant"
    );
    assert_eq!(
        reader_lab_static_policy_finding_kind_label(
            EbpfReaderLabStaticPolicyFindingKind::FakeEvidenceInvariant
        ),
        "fake_evidence_invariant"
    );
}

// Coverage 7: default record release_allowed=false
#[test]
fn i22_default_release_allowed_false() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(!rec.release_allowed);
}

// Coverage 8: default record must_remain_experimental=true
#[test]
fn i22_default_must_remain_experimental_true() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(rec.must_remain_experimental);
}

// Coverage 9: default record is not policy_frozen
#[test]
fn i22_default_not_policy_frozen() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(!rec.policy_frozen);
}

// Coverage 10: default record findings nonempty or ExperimentalOnly
#[test]
fn i22_default_findings_nonempty_or_experimental() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(
        !rec.findings.is_empty()
            || rec.status == EbpfReaderLabStaticPolicyFreezeStatus::ExperimentalOnly
    );
}

// Coverage 11: requires next arc plan valid
#[test]
fn i22_requires_plan_valid() {
    use super::backends::ebpf::event_stream_reader_lab_next_arc_plan::safe_base_plan;
    let mut input = default_reader_lab_static_policy_freeze_input();
    let mut bad_plan = safe_base_plan();
    bad_plan.phase = String::new();
    input.next_arc_plan = bad_plan;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-PLAN-INVALID"));
}

// Coverage 12: requires next arc plan ready when configured
#[test]
fn i22_requires_plan_ready_when_configured() {
    let mut input = frozen_input();
    input.next_arc_plan.plan_ready = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-PLAN-NOT-READY"));
}

// Coverage 13: requires experimental only when configured
#[test]
fn i22_requires_experimental_only_when_configured() {
    let mut input = frozen_input();
    input.next_arc_plan.must_remain_experimental = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec
        .findings
        .iter()
        .any(|f| f.code == "SPF-NOT-EXPERIMENTAL"));
}

// Coverage 14: rejects next_arc_plan.release_allowed=true
#[test]
fn i22_rejects_plan_release_allowed() {
    let mut input = frozen_input();
    input.next_arc_plan.release_allowed = true;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-RELEASE-ALLOWED"));
}

// Coverage 15: rejects next_arc_plan.must_remain_experimental=false
#[test]
fn i22_rejects_plan_not_experimental() {
    let mut input = frozen_input();
    input.next_arc_plan.must_remain_experimental = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec
        .findings
        .iter()
        .any(|f| f.code == "SPF-NOT-EXPERIMENTAL"));
}

// Coverage 16-20: release/tag/publish/version/main requests (loop)
#[test]
fn i22_release_requests_blocked() {
    let checks: &[(&str, &str)] = &[
        ("stable_release_requested", "SPF-RELEASE-REQUESTED"),
        ("tag_requested", "SPF-TAG-REQUESTED"),
        ("publish_requested", "SPF-PUBLISH-REQUESTED"),
        ("version_bump_requested", "SPF-VERSION-BUMP-REQUESTED"),
        ("main_merge_requested", "SPF-MAIN-MERGE-REQUESTED"),
    ];
    for (field, code) in checks {
        let mut input = frozen_input();
        match *field {
            "stable_release_requested" => input.stable_release_requested = true,
            "tag_requested" => input.tag_requested = true,
            "publish_requested" => input.publish_requested = true,
            "version_bump_requested" => input.version_bump_requested = true,
            "main_merge_requested" => input.main_merge_requested = true,
            _ => unreachable!(),
        }
        let rec = build_reader_lab_static_policy_freeze_record(&input);
        assert_eq!(
            rec.status,
            EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden,
            "{} should be ReleaseForbidden",
            field
        );
        assert!(rec.findings.iter().any(|f| f.code == *code));
    }
}

// Coverage 21-23: unsafe future allowances (loop)
#[test]
fn i22_unsafe_future_allowances_blocked() {
    let checks: &[(&str, &str)] = &[
        ("allow_live_reader_next", "SPF-ALLOW-LIVE-READER"),
        ("allow_public_cli_next", "SPF-ALLOW-PUBLIC-CLI"),
        ("allow_release_path_next", "SPF-ALLOW-RELEASE-PATH"),
    ];
    for (field, code) in checks {
        let mut input = frozen_input();
        match *field {
            "allow_live_reader_next" => input.allow_live_reader_next = true,
            "allow_public_cli_next" => input.allow_public_cli_next = true,
            "allow_release_path_next" => input.allow_release_path_next = true,
            _ => unreachable!(),
        }
        let rec = build_reader_lab_static_policy_freeze_record(&input);
        assert_eq!(rec.status, EbpfReaderLabStaticPolicyFreezeStatus::Blocked);
        assert!(rec.findings.iter().any(|f| f.code == *code));
    }
}

// Coverage 24: rejects public_cli_expected_hidden=false
#[test]
fn i22_rejects_cli_not_hidden() {
    let mut input = frozen_input();
    input.public_cli_expected_hidden = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-CLI-NOT-HIDDEN"));
}

// Coverage 25: rejects usage_schema_expected_unchanged=false
#[test]
fn i22_rejects_usage_schema_changed() {
    let mut input = frozen_input();
    input.usage_schema_expected_unchanged = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec
        .findings
        .iter()
        .any(|f| f.code == "SPF-USAGE-SCHEMA-CHANGED"));
}

// Coverage 26: rejects ledger_schema_expected_unchanged=false
#[test]
fn i22_rejects_ledger_schema_changed() {
    let mut input = frozen_input();
    input.ledger_schema_expected_unchanged = false;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec
        .findings
        .iter()
        .any(|f| f.code == "SPF-LEDGER-SCHEMA-CHANGED"));
}

// Coverage 27-32: runtime/kernel operation flags (loop)
#[test]
fn i22_runtime_flags_blocked() {
    let checks: &[(&str, &str)] = &[
        ("allow_ring_buffer_open", "SPF-ALLOW-RINGBUF"),
        ("allow_live_event_read", "SPF-ALLOW-LIVE-EVENT"),
        ("allow_map_pin", "SPF-ALLOW-MAP-PIN"),
        ("allow_enforcement", "SPF-ALLOW-ENFORCEMENT"),
        ("allow_packet_drop", "SPF-ALLOW-PACKET-DROP"),
        ("allow_persistence", "SPF-ALLOW-PERSISTENCE"),
    ];
    for (field, code) in checks {
        let mut input = frozen_input();
        match *field {
            "allow_ring_buffer_open" => input.allow_ring_buffer_open = true,
            "allow_live_event_read" => input.allow_live_event_read = true,
            "allow_map_pin" => input.allow_map_pin = true,
            "allow_enforcement" => input.allow_enforcement = true,
            "allow_packet_drop" => input.allow_packet_drop = true,
            "allow_persistence" => input.allow_persistence = true,
            _ => unreachable!(),
        }
        let rec = build_reader_lab_static_policy_freeze_record(&input);
        assert_eq!(rec.status, EbpfReaderLabStaticPolicyFreezeStatus::Blocked);
        assert!(rec.findings.iter().any(|f| f.code == *code));
    }
}

// Coverage 33-36: fake evidence detections
#[test]
fn i22_fake_evidence_rejected() {
    let mut input = frozen_input();
    input.next_arc_plan.fake_reader_success_detected = true;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-FAKE-READER"));

    input.next_arc_plan.fake_reader_success_detected = false;
    input.next_arc_plan.fake_live_event_counts_detected = true;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-FAKE-EVENTS"));

    input.next_arc_plan.fake_live_event_counts_detected = false;
    input.next_arc_plan.fake_release_readiness_detected = true;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-FAKE-RELEASE"));

    input.next_arc_plan.fake_release_readiness_detected = false;
    input.next_arc_plan.fake_planning_success_detected = true;
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert!(rec.findings.iter().any(|f| f.code == "SPF-FAKE-PLANNING"));
}

// Coverage 37: can become Frozen with safe ready next arc plan
#[test]
fn i22_can_become_frozen() {
    let input = frozen_input();
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    assert_eq!(rec.status, EbpfReaderLabStaticPolicyFreezeStatus::Frozen);
    assert!(rec.policy_frozen);
}

// Coverage 38: Frozen still has release_allowed=false
#[test]
fn i22_frozen_release_allowed_false() {
    let rec = build_reader_lab_static_policy_freeze_record(&frozen_input());
    assert!(!rec.release_allowed);
}

// Coverage 39: Frozen still has must_remain_experimental=true
#[test]
fn i22_frozen_must_remain_experimental() {
    let rec = build_reader_lab_static_policy_freeze_record(&frozen_input());
    assert!(rec.must_remain_experimental);
}

// Coverage 40-42: Frozen next flags false
#[test]
fn i22_frozen_next_flags_false() {
    let rec = build_reader_lab_static_policy_freeze_record(&frozen_input());
    assert!(!rec.live_reader_next_allowed);
    assert!(!rec.public_cli_next_allowed);
    assert!(!rec.release_path_next_allowed);
}

// Coverage 43: validation accepts safe default record
#[test]
fn i22_validation_accepts_safe_default() {
    let rec = build_reader_lab_static_policy_freeze_record(
        &default_reader_lab_static_policy_freeze_input(),
    );
    assert!(validate_reader_lab_static_policy_freeze_record(&rec).is_ok());
}

// Coverage 44-69: validation rejects unsafe fields (loop)
#[test]
fn i22_validation_rejects_unsafe_fields() {
    let checks: &[&str] = &[
        "policy_frozen_freeze_rejected",
        "release_allowed",
        "must_remain_experimental_false",
        "public_cli_exposed",
        "usage_schema_changed",
        "ledger_schema_changed",
        "stable_release_requested",
        "tag_requested",
        "publish_requested",
        "version_bump_requested",
        "main_merge_requested",
        "live_reader_next_allowed",
        "public_cli_next_allowed",
        "release_path_next_allowed",
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
        "fake_policy_freeze_success_detected",
    ];
    for check in checks {
        let rec = build_reader_lab_static_policy_freeze_record(
            &default_reader_lab_static_policy_freeze_input(),
        );
        let mut bad = rec;
        match *check {
            "policy_frozen_freeze_rejected" => {
                bad.policy_frozen = true;
                bad.status = EbpfReaderLabStaticPolicyFreezeStatus::FreezeRejected;
            }
            "release_allowed" => bad.release_allowed = true,
            "must_remain_experimental_false" => {
                bad.must_remain_experimental = false;
            }
            "public_cli_exposed" => bad.public_cli_exposed = true,
            "usage_schema_changed" => bad.usage_schema_changed = true,
            "ledger_schema_changed" => bad.ledger_schema_changed = true,
            "stable_release_requested" => bad.stable_release_requested = true,
            "tag_requested" => bad.tag_requested = true,
            "publish_requested" => bad.publish_requested = true,
            "version_bump_requested" => bad.version_bump_requested = true,
            "main_merge_requested" => bad.main_merge_requested = true,
            "live_reader_next_allowed" => {
                bad.live_reader_next_allowed = true;
            }
            "public_cli_next_allowed" => {
                bad.public_cli_next_allowed = true;
            }
            "release_path_next_allowed" => {
                bad.release_path_next_allowed = true;
            }
            "ring_buffer_opened" => bad.ring_buffer_opened = true,
            "live_event_stream_read" => bad.live_event_stream_read = true,
            "map_pin_performed" => bad.map_pin_performed = true,
            "enforcement_performed" => bad.enforcement_performed = true,
            "packet_drop_performed" => bad.packet_drop_performed = true,
            "mutation_performed" => bad.mutation_performed = true,
            "persistence_performed" => bad.persistence_performed = true,
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
            "fake_policy_freeze_success_detected" => {
                bad.fake_policy_freeze_success_detected = true;
            }
            _ => unreachable!(),
        }
        assert!(
            validate_reader_lab_static_policy_freeze_record(&bad).is_err(),
            "validation should reject {}",
            check
        );
    }
}

// Coverage 70: blocked/rejected record has blocking finding
#[test]
fn i22_blocked_record_has_blocking_finding() {
    let input = default_reader_lab_static_policy_freeze_input();
    let rec = build_reader_lab_static_policy_freeze_record(&input);
    if rec.status == EbpfReaderLabStaticPolicyFreezeStatus::Blocked
        || rec.status == EbpfReaderLabStaticPolicyFreezeStatus::ReleaseForbidden
    {
        assert!(rec.findings.iter().any(|f| f.blocking));
    }
}

// Coverage 71: evaluation is deterministic
#[test]
fn i22_evaluation_deterministic() {
    let input = default_reader_lab_static_policy_freeze_input();
    let r1 = build_reader_lab_static_policy_freeze_record(&input);
    let r2 = build_reader_lab_static_policy_freeze_record(&input);
    assert_eq!(r1, r2);
}

// Coverage 72-97: doc checks (file existence + content keywords)
#[test]
fn i22_docs_exist_and_cover_static_policy() {
    let content =
        std::fs::read_to_string("docs/intergalaxion/I-22-reader-lab-static-policy-freeze.md")
            .expect("I-22 doc must exist");
    assert!(content.contains("static policy freeze"));
    assert!(content.contains("static-policy-freeze only"));
    assert!(content.contains("not a release"));
    let keywords = [
        "no tag",
        "no release",
        "no publish",
        "no version bump",
        "no main merge",
        "no public cli",
        "no ring buffer",
        "no live kernel event read",
        "no map pin",
        "no enforcement",
        "no packet drop",
        "no block",
        "no nft",
        "no ledger file write",
        "no persistence",
        "usage json schema unchanged",
        "ledger json schema unchanged",
        "release_allowed is always false",
        "must_remain_experimental is always true",
        "live reader next is not allowed",
        "public cli next is not allowed",
        "release path next is not allowed",
        "fake reader execution success",
        "fake live event counts",
        "fake release readiness",
        "fake planning success",
        "fake static policy freeze success",
    ];
    for kw in &keywords {
        assert!(
            content.to_lowercase().contains(&kw.to_lowercase()),
            "doc must mention: {}",
            kw
        );
    }
}

// Coverage 98: version remains v3.1.0
#[test]
fn i22_version_remains_v310() {
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

// Coverage 99: ledger inspect --json works
#[test]
fn i22_ledger_inspect_works() {
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

// Coverage 100: ledger export --json --file works
#[test]
fn i22_ledger_export_works() {
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build");
    assert!(output.status.success());
    let tmp = std::env::temp_dir().join("i22-ledger-export-test.json");
    std::fs::write(
        &tmp,
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"i22-test","entries":[]}"#,
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

// Coverage 101: public help no intergalaxion
#[test]
fn i22_help_no_intergalaxion() {
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

// Coverage 102: public help no block/allow/quota
#[test]
fn i22_help_no_block_allow_quota() {
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

// Coverage 103: no new dependency added
#[test]
fn i22_no_new_dependency() {
    let toml = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml must exist");
    let toml_lower = toml.to_lowercase();
    assert!(
        !toml_lower.contains("aya = ") && !toml_lower.contains("aya="),
        "no new aya runtime dependency"
    );
}

// Coverage 104: no nft/tc source under intergalaxion backend
#[test]
fn i22_no_nft_tc_source() {
    let backend_dir = "src/intergalaxion_engine/backends/ebpf";
    for entry in std::fs::read_dir(backend_dir).expect("backend dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        assert!(
            !name_str.contains("nft") && !name_str.contains("tc"),
            "no nft/tc source: {}",
            name_str
        );
    }
}

// Coverage 105: all touched files under 1000 LOC
#[test]
fn i22_all_files_under_1000_loc() {
    let files = [
        "src/intergalaxion_engine/backends/ebpf/event_stream_reader_lab_static_policy_freeze.rs",
        "src/intergalaxion_engine/tests_i22.rs",
    ];
    for f in &files {
        let content = std::fs::read_to_string(f).unwrap_or_default();
        let count = content.lines().count();
        assert!(count < 1000, "{} is {} lines (must be < 1000)", f, count);
    }
}
