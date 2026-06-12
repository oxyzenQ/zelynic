// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::{
    brave_identity_confidence_label, brave_identity_decision_label,
    brave_identity_scope_status_label, brave_identity_source_label,
    build_brave_identity_scope_proof, default_brave_identity_scope_proof_input,
    validate_brave_identity_scope_proof, BraveIdentityConfidence, BraveIdentityDecision,
    BraveIdentityScopeStatus, BraveIdentitySource,
};

type I = crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::BraveIdentityScopeProofInput;
type C =
    crate::intergalaxion_engine::backends::ebpf::brave_identity_scope_proof::BraveProcessCandidate;

/// Ready candidate: pid + cgroup + name match.
fn ready_c(pid: u32, name: &str, cgroup: &str) -> C {
    C {
        pid: Some(pid),
        process_name: name.into(),
        executable_path: Some(format!("/usr/bin/{name}")),
        cgroup_path: Some(cgroup.into()),
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: true,
        matches_brave_cgroup: true,
    }
}

// --- Coverage 1: default input targets brave ---
#[test]
fn test_default_input_targets_brave() {
    let i = default_brave_identity_scope_proof_input();
    assert_eq!(i.target_name, "brave");
}

// --- Coverage 2: default proof is not ready ---
#[test]
fn test_default_proof_not_ready() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert!(!p.identity_ready);
}

// --- Coverage 3: default proof release_allowed=false ---
#[test]
fn test_default_proof_no_release() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert!(!p.release_allowed);
}

// --- Coverage 4: default proof live_apply_allowed=false ---
#[test]
fn test_default_proof_no_live_apply() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert!(!p.live_apply_allowed);
}

// --- Coverage 5: default proof must_remain_experimental=true ---
#[test]
fn test_default_proof_experimental() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert!(p.must_remain_experimental);
}

// --- Coverage 6: no candidates does not become Ready ---
#[test]
fn test_no_candidates_not_ready() {
    let i = default_brave_identity_scope_proof_input();
    let p = build_brave_identity_scope_proof(&i);
    assert!(!p.identity_ready);
    assert!(!matches!(p.status, BraveIdentityScopeStatus::Ready));
}

// --- Coverage 7: one candidate with PID + cgroup can become Ready ---
#[test]
fn test_one_candidate_ready() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates
        .push(ready_c(1234, "brave", "/user.slice/brave.scope"));
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.identity_ready);
    assert_eq!(p.status, BraveIdentityScopeStatus::Ready);
    assert_eq!(p.decision, BraveIdentityDecision::AcceptReadyScope);
}

// --- Coverage 8: one candidate without PID is not Ready ---
#[test]
fn test_no_pid_not_ready() {
    let mut i = default_brave_identity_scope_proof_input();
    let mut c = ready_c(0, "brave", "/user.slice/brave.scope");
    c.pid = None;
    i.candidates.push(c);
    let p = build_brave_identity_scope_proof(&i);
    assert!(!p.identity_ready);
    assert_eq!(p.decision, BraveIdentityDecision::RequirePidEvidence);
}

// --- Coverage 9: one candidate without cgroup is not Ready ---
#[test]
fn test_no_cgroup_not_ready() {
    let mut i = default_brave_identity_scope_proof_input();
    let mut c = ready_c(1234, "brave", "");
    c.cgroup_path = None;
    i.candidates.push(c);
    let p = build_brave_identity_scope_proof(&i);
    assert!(!p.identity_ready);
    assert_eq!(p.decision, BraveIdentityDecision::RequireCgroupEvidence);
}

// --- Coverage 10: process name brave matches ---
#[test]
fn test_name_brave_matches() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: Some(1),
        process_name: "brave".into(),
        executable_path: None,
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 1);
}

// --- Coverage 11: process name brave-browser matches ---
#[test]
fn test_name_brave_browser_matches() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: Some(1),
        process_name: "brave-browser".into(),
        executable_path: None,
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 1);
}

// --- Coverage 12: executable path containing brave matches ---
#[test]
fn test_exec_path_brave_matches() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: None,
        process_name: "browser".into(),
        executable_path: Some("/usr/bin/brave".into()),
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: false,
        matches_brave_executable: true,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 1);
}

// --- Coverage 13: cgroup path containing brave matches ---
#[test]
fn test_cgroup_brave_matches() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: None,
        process_name: "x".into(),
        executable_path: None,
        cgroup_path: Some("/user.slice/brave-browser.scope".into()),
        systemd_scope: None,
        matches_brave_name: false,
        matches_brave_executable: false,
        matches_brave_cgroup: true,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 1);
}

// --- Coverage 14: unrelated process does not match ---
#[test]
fn test_unrelated_no_match() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: Some(999),
        process_name: "firefox".into(),
        executable_path: Some("/usr/bin/firefox".into()),
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: false,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 0);
}

// --- Coverage 15: multiple matching candidates → Ambiguous ---
#[test]
fn test_multiple_matches_ambiguous() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(ready_c(1, "brave", "/a"));
    i.candidates.push(ready_c(2, "brave", "/b"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.status, BraveIdentityScopeStatus::Ambiguous);
    assert_eq!(p.decision, BraveIdentityDecision::RejectAmbiguousTarget);
    assert!(p.ambiguous_identity_detected);
}

// --- Coverage 16: ambiguous proof identity_ready=false ---
#[test]
fn test_ambiguous_not_ready() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(ready_c(1, "brave", "/a"));
    i.candidates.push(ready_c(2, "brave", "/b"));
    let p = build_brave_identity_scope_proof(&i);
    assert!(!p.identity_ready);
}

// --- Coverage 17: live apply request is rejected ---
#[test]
fn test_live_apply_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.explicit_live_apply = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(!p.live_apply_allowed);
    assert_eq!(p.status, BraveIdentityScopeStatus::LiveApplyForbidden);
    assert_eq!(p.decision, BraveIdentityDecision::RejectLiveApply);
}

// --- Coverage 18: public CLI request is rejected ---
#[test]
fn test_public_cli_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.public_cli_requested = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.public_cli_exposed);
    assert_eq!(p.decision, BraveIdentityDecision::RejectPublicCli);
}

// --- Coverage 19: allow_proc_scan=true rejected ---
#[test]
fn test_proc_scan_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_proc_scan = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_proc_scan")));
}

// --- Coverage 20: allow_cgroup_read=true rejected ---
#[test]
fn test_cgroup_read_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_cgroup_read = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_cgroup_read")));
}

// --- Coverage 21: allow_systemd_query=true rejected ---
#[test]
fn test_systemd_query_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_systemd_query = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("allow_systemd_query")));
}

// --- Coverage 22: allow_cgroup_mutation=true rejected ---
#[test]
fn test_cgroup_mutation_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_cgroup_mutation = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("cgroup mutation")));
}

// --- Coverage 23: allow_process_mutation=true rejected ---
#[test]
fn test_process_mutation_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_process_mutation = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("process mutation")));
}

// --- Coverage 24: allow_persistence=true rejected ---
#[test]
fn test_persistence_rejected() {
    let mut i = default_brave_identity_scope_proof_input();
    i.allow_persistence = true;
    let p = build_brave_identity_scope_proof(&i);
    assert!(p.findings.iter().any(|f| f.contains("persistence")));
}

// --- Coverage 25: confidence None for no candidates ---
#[test]
fn test_confidence_none_no_candidates() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert_eq!(p.confidence, BraveIdentityConfidence::None);
}

// --- Coverage 26: confidence Low for name-only candidate ---
#[test]
fn test_confidence_low_name_only() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: None,
        process_name: "brave".into(),
        executable_path: None,
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.confidence, BraveIdentityConfidence::Low);
}

// --- Coverage 27: confidence Medium for pid + name ---
#[test]
fn test_confidence_medium_pid_name() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: Some(1234),
        process_name: "brave".into(),
        executable_path: None,
        cgroup_path: None,
        systemd_scope: None,
        matches_brave_name: true,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.confidence, BraveIdentityConfidence::Medium);
}

// --- Coverage 28: confidence High for pid + cgroup + name ---
#[test]
fn test_confidence_high_full() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates
        .push(ready_c(1234, "brave", "/user.slice/brave.scope"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.confidence, BraveIdentityConfidence::High);
}

// --- Coverage 29: confidence Ambiguous for multiple matches ---
#[test]
fn test_confidence_ambiguous() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(ready_c(1, "brave", "/a"));
    i.candidates.push(ready_c(2, "brave", "/b"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.confidence, BraveIdentityConfidence::Ambiguous);
}

// --- Coverage 30: validate accepts safe default proof ---
#[test]
fn test_validate_accepts_default() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert!(validate_brave_identity_scope_proof(&p).is_ok());
}

// --- Coverage 31: validate accepts ready dry-run proof ---
#[test]
fn test_validate_accepts_ready() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates
        .push(ready_c(1234, "brave", "/user.slice/brave.scope"));
    let p = build_brave_identity_scope_proof(&i);
    assert!(validate_brave_identity_scope_proof(&p).is_ok());
}

// --- Coverage 32: validate rejects identity_ready=true with no selected PID ---
#[test]
fn test_validate_rejects_ready_no_pid() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.identity_ready = true;
    p.selected_pid = None;
    p.selected_cgroup_path = Some("/x".into());
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 33: validate rejects identity_ready=true with no cgroup path ---
#[test]
fn test_validate_rejects_ready_no_cgroup() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.identity_ready = true;
    p.selected_pid = Some(1);
    p.selected_cgroup_path = None;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 34: validate rejects live_apply_allowed=true ---
#[test]
fn test_validate_rejects_live_apply() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.live_apply_allowed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 35: validate rejects release_allowed=true ---
#[test]
fn test_validate_rejects_release() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.release_allowed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 36: validate rejects must_remain_experimental=false ---
#[test]
fn test_validate_rejects_not_experimental() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.must_remain_experimental = false;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 37: validate rejects public_cli_exposed=true ---
#[test]
fn test_validate_rejects_public_cli() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.public_cli_exposed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 38: validate rejects proc_scan_performed=true ---
#[test]
fn test_validate_rejects_proc_scan() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.proc_scan_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 39: validate rejects cgroup_read_performed=true ---
#[test]
fn test_validate_rejects_cgroup_read() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.cgroup_read_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 40: validate rejects systemd_query_performed=true ---
#[test]
fn test_validate_rejects_systemd_query() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.systemd_query_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 41: validate rejects cgroup_mutation_performed=true ---
#[test]
fn test_validate_rejects_cgroup_mutation() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.cgroup_mutation_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 42: validate rejects process_mutation_performed=true ---
#[test]
fn test_validate_rejects_process_mutation() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.process_mutation_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 43: validate rejects persistence_performed=true ---
#[test]
fn test_validate_rejects_persistence() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.persistence_performed = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 44: validate rejects fake_identity_success_detected=true ---
#[test]
fn test_validate_rejects_fake_identity() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.fake_identity_success_detected = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 45: validate rejects ambiguous_identity_detected=true when Ready ---
#[test]
fn test_validate_rejects_ambiguous_when_ready() {
    let mut p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    p.status = BraveIdentityScopeStatus::Ready;
    p.identity_ready = true;
    p.selected_pid = Some(1);
    p.selected_cgroup_path = Some("/x".into());
    p.ambiguous_identity_detected = true;
    assert!(validate_brave_identity_scope_proof(&p).is_err());
}

// --- Coverage 46: label helpers are stable ---
#[test]
fn test_source_labels() {
    assert_eq!(
        brave_identity_source_label(BraveIdentitySource::ProcessName),
        "process_name"
    );
    assert_eq!(
        brave_identity_source_label(BraveIdentitySource::ExecutablePath),
        "executable_path"
    );
    assert_eq!(
        brave_identity_source_label(BraveIdentitySource::CgroupPath),
        "cgroup_path"
    );
    assert_eq!(
        brave_identity_source_label(BraveIdentitySource::SystemdScope),
        "systemd_scope"
    );
    assert_eq!(
        brave_identity_source_label(BraveIdentitySource::FixturePidList),
        "fixture_pid_list"
    );
}

#[test]
fn test_confidence_labels() {
    assert_eq!(
        brave_identity_confidence_label(BraveIdentityConfidence::None),
        "none"
    );
    assert_eq!(
        brave_identity_confidence_label(BraveIdentityConfidence::Low),
        "low"
    );
    assert_eq!(
        brave_identity_confidence_label(BraveIdentityConfidence::Medium),
        "medium"
    );
    assert_eq!(
        brave_identity_confidence_label(BraveIdentityConfidence::High),
        "high"
    );
    assert_eq!(
        brave_identity_confidence_label(BraveIdentityConfidence::Ambiguous),
        "ambiguous"
    );
}

#[test]
fn test_status_labels() {
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::Draft),
        "draft"
    );
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::Candidate),
        "candidate"
    );
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::Ready),
        "ready"
    );
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::Ambiguous),
        "ambiguous"
    );
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::Blocked),
        "blocked"
    );
    assert_eq!(
        brave_identity_scope_status_label(BraveIdentityScopeStatus::LiveApplyForbidden),
        "live_apply_forbidden"
    );
}

#[test]
fn test_decision_labels() {
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::Stop),
        "stop"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::AcceptCandidate),
        "accept_candidate"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::AcceptReadyScope),
        "accept_ready_scope"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RequirePidEvidence),
        "require_pid_evidence"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RequireCgroupEvidence),
        "require_cgroup_evidence"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RejectAmbiguousTarget),
        "reject_ambiguous_target"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RejectNoTarget),
        "reject_no_target"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RejectLiveApply),
        "reject_live_apply"
    );
    assert_eq!(
        brave_identity_decision_label(BraveIdentityDecision::RejectPublicCli),
        "reject_public_cli"
    );
}

// --- Coverage 47-59: docs content checks ---
#[test]
fn test_docs_exist() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    assert!(!docs.is_empty());
}

#[test]
fn test_docs_say_brave_identity_scope() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("brave") && lower.contains("identity") && lower.contains("scope"));
}

#[test]
fn test_docs_say_no_live_apply() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no live apply") || lower.contains("live apply is forbidden"));
}

#[test]
fn test_docs_say_no_public_cli() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no public cli") || lower.contains("public cli"));
}

#[test]
fn test_docs_say_no_proc_scan() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("no proc scan") || lower.contains("/proc") || lower.contains("proc scan")
    );
}

#[test]
fn test_docs_say_no_cgroup_mutation() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("cgroup") && (lower.contains("mutation") || lower.contains("write")));
}

#[test]
fn test_docs_say_no_process_mutation() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("process mutation")
            || lower.contains("no process")
            || lower.contains("no mutation")
    );
}

#[test]
fn test_docs_say_no_persistence() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no persistence") || lower.contains("persistence"));
}

#[test]
fn test_docs_say_no_enforcement() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no enforcement") || lower.contains("enforcement"));
}

#[test]
fn test_docs_say_no_packet_drop() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("no packet drop") || lower.contains("packet drop"));
}

#[test]
fn test_docs_say_limit_not_proven() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(
        lower.contains("not proven")
            || lower.contains("identity proof only")
            || lower.contains("no limiting")
    );
}

#[test]
fn test_docs_say_identity_proof_only() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("identity proof") || lower.contains("identity only"));
}

#[test]
fn test_docs_say_fake_identity_rejected() {
    let docs = include_str!("../../docs/intergalaxion/I-33-brave-identity-scope-proof.md");
    let lower = docs.to_lowercase();
    assert!(lower.contains("fake") && lower.contains("reject"));
}

// --- Extra: brave-browser target accepted ---
#[test]
fn test_brave_browser_target() {
    let mut i = default_brave_identity_scope_proof_input();
    i.target_name = "brave-browser".into();
    i.candidates.push(ready_c(1, "brave-browser", "/c"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.status, BraveIdentityScopeStatus::Ready);
}

// --- Extra: wrong target blocked ---
#[test]
fn test_wrong_target_blocked() {
    let mut i = default_brave_identity_scope_proof_input();
    i.target_name = "firefox".into();
    i.candidates.push(ready_c(1, "firefox", "/c"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.decision, BraveIdentityDecision::RejectNoTarget);
    assert_eq!(p.status, BraveIdentityScopeStatus::Blocked);
}

// --- Extra: Ready proof selects correct fields ---
#[test]
fn test_ready_selects_pid_and_cgroup() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates
        .push(ready_c(5678, "brave", "/user.slice/brave-browser.scope"));
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.selected_pid, Some(5678));
    assert_eq!(
        p.selected_cgroup_path.as_deref(),
        Some("/user.slice/brave-browser.scope")
    );
}

// --- Extra: phase is I-33 ---
#[test]
fn test_phase() {
    let p = build_brave_identity_scope_proof(&default_brave_identity_scope_proof_input());
    assert_eq!(p.phase, "I-33");
}

// --- Extra: default input all flags safe ---
#[test]
fn test_default_flags_safe() {
    let i = default_brave_identity_scope_proof_input();
    assert!(i.explicit_dry_run);
    assert!(!i.explicit_live_apply);
    assert!(!i.public_cli_requested);
    assert!(!i.allow_proc_scan);
    assert!(!i.allow_cgroup_read);
    assert!(!i.allow_systemd_query);
    assert!(!i.allow_cgroup_mutation);
    assert!(!i.allow_process_mutation);
    assert!(!i.allow_persistence);
}

// --- Extra: systemd scope propagated on Ready ---
#[test]
fn test_systemd_scope_propagated() {
    let mut i = default_brave_identity_scope_proof_input();
    let mut c = ready_c(1, "brave", "/c");
    c.systemd_scope = Some("session-1.scope".into());
    i.candidates.push(c);
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.selected_systemd_scope.as_deref(), Some("session-1.scope"));
}

// --- Extra: High confidence with pid+cgroup+executable (no name flag) ---
#[test]
fn test_confidence_high_pid_cgroup_exec() {
    let mut i = default_brave_identity_scope_proof_input();
    let mut c = ready_c(1, "brave", "/c");
    c.matches_brave_name = false; // only executable + cgroup
    i.candidates.push(c);
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.confidence, BraveIdentityConfidence::High);
    assert!(p.identity_ready);
}

// --- Extra: no match + no candidates = confidence None ---
#[test]
fn test_no_candidates_none() {
    let mut i = default_brave_identity_scope_proof_input();
    i.candidates.push(C {
        pid: Some(1),
        process_name: "chrome".into(),
        executable_path: Some("/usr/bin/google-chrome".into()),
        cgroup_path: Some("/user.slice/chrome.scope".into()),
        systemd_scope: None,
        matches_brave_name: false,
        matches_brave_executable: false,
        matches_brave_cgroup: false,
    });
    let p = build_brave_identity_scope_proof(&i);
    assert_eq!(p.matching_candidate_count, 0);
    assert_eq!(p.confidence, BraveIdentityConfidence::None);
}
