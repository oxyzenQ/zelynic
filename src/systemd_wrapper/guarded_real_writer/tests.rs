// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for the guarded real writer seam.

use super::*;

/// Builds a valid input for testing — all gates pass.
fn valid_input() -> GuardedRealWriterInput {
    GuardedRealWriterInput {
        pid: 12345,
        original_cgroup_path: Some("/sys/fs/cgroup/user.slice/session-2.scope".to_string()),
        target_cgroup_path: "/sys/fs/cgroup/zelynic/target_sleep".to_string(),
        is_root: true,
        is_system_scope: true,
        rollback_consent_present: true,
    }
}

/// Returns true if a gate with the given name has Ok status.
fn gate_ok(result: &GuardedRealWriterResult, name: &str) -> bool {
    result
        .gates
        .iter()
        .find(|g| g.name == name)
        .is_some_and(|g| g.status == GuardedWriterGateStatus::Ok)
}

/// Renders a plan result to text.
fn rendered(input: &GuardedRealWriterInput) -> String {
    let result = build_guarded_real_writer_plan(input);
    render_guarded_real_writer_plan(&result)
}

// ---- seam always blocked ----

#[test]
fn seam_always_returns_blocked_even_when_all_gates_are_valid() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert!(result.is_blocked());
    assert_eq!(result.status, "blocked");
    // All individual gates pass
    assert!(result
        .gates
        .iter()
        .all(|g| g.status == GuardedWriterGateStatus::Ok));
    // But seam is still hard-blocked
    assert!(result.reason.contains("hard-blocked"));
    assert!(result.reason.contains("not implemented"));
}

// ---- gate blocking tests ----

#[test]
fn non_root_blocks() {
    let mut input = valid_input();
    input.is_root = false;
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "root"));
    assert!(result.reason.contains("non-root"));
}

#[test]
fn user_scope_blocks() {
    let mut input = valid_input();
    input.is_system_scope = false;
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "system scope"));
    assert!(result.reason.contains("user scope"));
}

#[test]
fn zero_pid_blocks() {
    let mut input = valid_input();
    input.pid = 0;
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "PID"));
    assert!(result.reason.contains("zero PID"));
}

#[test]
fn multi_pid_blocks_if_represented() {
    // The guarded real writer input model uses a single PID field.
    // A future multi-PID representation would be blocked by design.
    // For now, verify that a valid single PID doesn't bypass the hard block.
    let mut input = valid_input();
    input.pid = 1; // valid single PID is fine for gates
    let result = build_guarded_real_writer_plan(&input);
    // Still blocked because the seam is hard-blocked
    assert!(result.is_blocked());
}

#[test]
fn missing_original_cgroup_blocks() {
    let mut input = valid_input();
    input.original_cgroup_path = None;
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "original cgroup"));
    assert!(result.reason.contains("missing original cgroup"));
}

#[test]
fn zelynic_managed_original_cgroup_blocks() {
    let mut input = valid_input();
    input.original_cgroup_path = Some("/sys/fs/cgroup/zelynic/target_previous".to_string());
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "original cgroup safety"));
    assert!(result.reason.contains("zelynic-managed"));
}

#[test]
fn target_outside_zelynic_blocks() {
    let mut input = valid_input();
    input.target_cgroup_path = "/sys/fs/cgroup/system.slice/example.scope".to_string();
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "target cgroup"));
    assert!(result.reason.contains("invalid target"));
}

#[test]
fn missing_rollback_consent_blocks() {
    let mut input = valid_input();
    input.rollback_consent_present = false;
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "rollback consent"));
    assert!(result.reason.contains("rollback consent"));
}

// ---- result model field correctness ----

#[test]
fn result_fields_are_always_non_mutating() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert_eq!(result.pid_location, GuardedPidLocation::NotMoved);
    assert!(!result.rollback_attempted);
    assert!(!result.cleanup_attempted);
    assert!(!result.cgroup_procs_writes_performed);
    assert!(!result.limiter_attach_performed);
    assert!(!result.nft_tc_state_mutation_performed);
}

#[test]
fn result_fields_are_always_non_mutating_even_with_invalid_gates() {
    let mut input = valid_input();
    input.is_root = false;
    input.pid = 0;
    let result = build_guarded_real_writer_plan(&input);
    assert_eq!(result.pid_location, GuardedPidLocation::NotMoved);
    assert!(!result.rollback_attempted);
    assert!(!result.cleanup_attempted);
    assert!(!result.cgroup_procs_writes_performed);
    assert!(!result.limiter_attach_performed);
    assert!(!result.nft_tc_state_mutation_performed);
}

// ---- deny line presence tests ----

#[test]
fn rendered_output_includes_all_deny_lines() {
    let output = rendered(&valid_input());
    for deny in CANONICAL_DENY_LINES {
        assert!(output.contains(deny), "missing deny line: {}", deny);
    }
}

#[test]
fn result_includes_all_deny_lines() {
    let result = build_guarded_real_writer_plan(&valid_input());
    for deny in CANONICAL_DENY_LINES {
        assert!(
            result.deny_lines.iter().any(|d| d == deny),
            "missing deny line in result: {}",
            deny
        );
    }
}

#[test]
fn rendered_output_includes_all_deny_lines_for_non_root() {
    let mut input = valid_input();
    input.is_root = false;
    let output = rendered(&input);
    for deny in CANONICAL_DENY_LINES {
        assert!(
            output.contains(deny),
            "non-root missing deny line: {}",
            deny
        );
    }
}

#[test]
fn rendered_output_includes_all_deny_lines_for_user_scope() {
    let mut input = valid_input();
    input.is_system_scope = false;
    let output = rendered(&input);
    for deny in CANONICAL_DENY_LINES {
        assert!(
            output.contains(deny),
            "user scope missing deny line: {}",
            deny
        );
    }
}

// ---- forbidden claim tests ----

#[test]
fn rendered_output_never_claims_pid_moved() {
    let output = rendered(&valid_input());
    assert!(!output.contains("PID was moved"));
    assert!(!output.contains("PID moved"));
    assert!(!output.contains("pid moved"));
    assert!(!output.contains("pid was moved"));
}

#[test]
fn rendered_output_never_claims_cgroup_procs_write() {
    let output = rendered(&valid_input());
    assert!(!output.contains("cgroup.procs written"));
    assert!(!output.contains("cgroup.procs was written"));
    assert!(!output.contains("cgroup.procs write performed"));
}

#[test]
fn rendered_output_never_claims_rollback_performed() {
    let output = rendered(&valid_input());
    assert!(!output.contains("rollback performed"));
    assert!(!output.contains("rollback was performed"));
    assert!(!output.contains("PID was restored"));
}

#[test]
fn rendered_output_never_claims_limiter_attach() {
    let output = rendered(&valid_input());
    assert!(!output.contains("limiter attached"));
    assert!(!output.contains("Limiter attached"));
    assert!(!output.contains("limiter was attached"));
}

#[test]
fn rendered_output_never_claims_bandwidth_limiting_active() {
    let output = rendered(&valid_input());
    assert!(!output.contains("bandwidth limiting active"));
    assert!(!output.contains("Bandwidth limiting active"));
    assert!(!output.contains("bandwidth limiting is active"));
}

#[test]
fn rendered_output_never_claims_nft_tc_state_mutation() {
    let output = rendered(&valid_input());
    assert!(!output.contains("nftables rules were"));
    assert!(!output.contains("tc qdisc"));
    assert!(!output.contains("state was mutated"));
    assert!(!output.contains("state changes performed"));
}

#[test]
fn rendered_output_says_hard_blocked_or_not_implemented() {
    let output = rendered(&valid_input());
    assert!(output.contains("hard-blocked") || output.contains("not implemented"));
    assert!(output.contains("blocked"));
}

// ---- negative-path comprehensive mutation sweep ----

#[test]
#[allow(clippy::type_complexity)]
fn negative_path_outputs_never_claim_mutation() {
    let scenarios: Vec<(&str, fn(&mut GuardedRealWriterInput))> = vec![
        ("non-root", |i| i.is_root = false),
        ("user scope", |i| i.is_system_scope = false),
        ("zero PID", |i| i.pid = 0),
        ("missing original cgroup", |i| i.original_cgroup_path = None),
        ("zelynic-managed original", |i| {
            i.original_cgroup_path = Some("/sys/fs/cgroup/zelynic/target_old".to_string())
        }),
        ("invalid target", |i| {
            i.target_cgroup_path = "/sys/fs/cgroup/system.slice/x.scope".to_string()
        }),
        ("missing rollback consent", |i| {
            i.rollback_consent_present = false
        }),
    ];
    for (label, modify) in scenarios {
        let mut input = valid_input();
        modify(&mut input);
        let output = rendered(&input);
        assert!(
            !output.contains("PID was moved"),
            "{}: must not claim PID moved",
            label
        );
        assert!(
            !output.contains("cgroup.procs written"),
            "{}: must not claim cgroup.procs written",
            label
        );
        assert!(
            !output.contains("limiter attached"),
            "{}: must not claim limiter attached",
            label
        );
        assert!(
            !output.contains("bandwidth limiting active"),
            "{}: must not claim bandwidth limiting active",
            label
        );
        assert!(
            !output.contains("rollback performed"),
            "{}: must not claim rollback performed",
            label
        );
        assert!(
            !output.contains("state was mutated"),
            "{}: must not claim state mutation",
            label
        );
    }
}

// ---- phase label tests ----

#[test]
fn result_says_phase_5d() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert!(result.phase.contains("5d"));
    assert!(result.plan_type.contains("guarded real writer"));
}

#[test]
fn rendered_output_contains_phase_5d_label() {
    let output = rendered(&valid_input());
    assert!(output.contains("phase 5d"));
    assert!(output.contains("Guarded real writer seam"));
}

// ---- render structure tests ----

#[test]
fn rendered_output_contains_all_sections() {
    let output = rendered(&valid_input());
    assert!(output.contains("Guarded real writer seam"));
    assert!(output.contains("plan type:"));
    assert!(output.contains("status:"));
    assert!(output.contains("reason:"));
    assert!(output.contains("pid location:"));
    assert!(output.contains("rollback attempted:"));
    assert!(output.contains("cleanup attempted:"));
    assert!(output.contains("cgroup.procs writes performed:"));
    assert!(output.contains("limiter attach performed:"));
    assert!(output.contains("nft/tc/state mutation performed:"));
    assert!(output.contains("gates:"));
    assert!(output.contains("deny lines:"));
}

#[test]
fn rendered_output_shows_false_for_all_mutation_flags() {
    let output = rendered(&valid_input());
    assert!(output.contains("rollback attempted: false"));
    assert!(output.contains("cleanup attempted: false"));
    assert!(output.contains("cgroup.procs writes performed: false"));
    assert!(output.contains("limiter attach performed: false"));
    assert!(output.contains("nft/tc/state mutation performed: false"));
}

// ---- gate ordering tests ----

#[test]
fn gates_are_in_correct_order() {
    let result = build_guarded_real_writer_plan(&valid_input());
    let names: Vec<&str> = result.gates.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "root",
            "system scope",
            "PID",
            "original cgroup",
            "original cgroup safety",
            "target cgroup",
            "rollback consent",
        ]
    );
}

// ---- is_safe_writer_target helper tests ----

#[test]
fn safe_writer_target_rejects_empty() {
    assert!(!is_safe_writer_target(""));
}

#[test]
fn safe_writer_target_rejects_outside_namespace() {
    assert!(!is_safe_writer_target("/sys/fs/cgroup/system.slice/foo"));
}

#[test]
fn safe_writer_target_rejects_parent_traversal() {
    assert!(!is_safe_writer_target(
        "/sys/fs/cgroup/zelynic/target_test/../etc/passwd"
    ));
}

#[test]
fn safe_writer_target_rejects_bare_root() {
    assert!(!is_safe_writer_target(ZELYNIC_CGROUP_ROOT));
}

#[test]
fn safe_writer_target_accepts_valid_target() {
    assert!(is_safe_writer_target("/sys/fs/cgroup/zelynic/target_sleep"));
}

#[test]
fn safe_writer_target_accepts_subdirectory() {
    assert!(is_safe_writer_target(
        "/sys/fs/cgroup/zelynic/experiment/target_curl"
    ));
}

// ---- whitespace-only original cgroup edge case ----

#[test]
fn whitespace_only_original_cgroup_blocks() {
    let mut input = valid_input();
    input.original_cgroup_path = Some("   ".to_string());
    let result = build_guarded_real_writer_plan(&input);
    assert!(!gate_ok(&result, "original cgroup"));
    assert!(result.reason.contains("missing original cgroup"));
}

// ---- determinism tests ----

#[test]
fn same_input_produces_same_result() {
    let input = valid_input();
    let r1 = build_guarded_real_writer_plan(&input);
    let r2 = build_guarded_real_writer_plan(&input);
    assert_eq!(r1, r2);
}

#[test]
fn same_input_produces_same_rendered_output() {
    let input = valid_input();
    let o1 = rendered(&input);
    let o2 = rendered(&input);
    assert_eq!(o1, o2);
}

// ---- PID location label tests ----

#[test]
fn pid_location_not_moved_label() {
    assert_eq!(GuardedPidLocation::NotMoved.label(), "not moved");
}

#[test]
fn pid_location_verified_target_label() {
    assert_eq!(
        GuardedPidLocation::VerifiedTarget.label(),
        "verified target"
    );
}

#[test]
fn pid_location_restored_label() {
    assert_eq!(GuardedPidLocation::Restored.label(), "restored");
}

#[test]
fn pid_location_unknown_label() {
    assert_eq!(GuardedPidLocation::Unknown.label(), "unknown");
}

// ---- deny line count test ----

#[test]
fn deny_lines_has_correct_count() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert_eq!(result.deny_lines.len(), CANONICAL_DENY_LINES.len());
    assert_eq!(result.deny_lines.len(), 7);
}

// ---- explicit hard-block denial test ----

#[test]
fn deny_lines_include_hard_blocked_statement() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert!(result
        .deny_lines
        .iter()
        .any(|d| d.contains("Guarded real writer seam is hard-blocked")));
}

#[test]
fn deny_lines_include_no_cli_path_statement() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert!(result
        .deny_lines
        .iter()
        .any(|d| d.contains("No CLI path for live PID move was enabled")));
}

#[test]
fn deny_lines_include_no_persistent_state_statement() {
    let result = build_guarded_real_writer_plan(&valid_input());
    assert!(result
        .deny_lines
        .iter()
        .any(|d| d.contains("No persistent state write was performed")));
}
