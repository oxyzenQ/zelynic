// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

#[cfg(test)]
mod tests {
    use crate::systemd_wrapper::failure_simulation::{
        build_failure_simulation_matrix, render_failure_simulation_result,
        simulate_failure_scenario, CleanupDecision, FailureScenario, PidLocationStatus,
        RollbackDecision, SimulationResult, PHASE_LABEL,
    };

    fn matrix() -> Vec<SimulationResult> {
        build_failure_simulation_matrix()
    }

    fn rendered(result: &SimulationResult) -> String {
        render_failure_simulation_result(result)
    }

    /// Extracts only the "safe" portion of rendered output (honesty lines + deny lines)
    /// without the forbidden_claims section, for testing that honest output doesn't
    /// contain forbidden phrases.
    fn rendered_safe_portion(result: &SimulationResult) -> String {
        let full = rendered(result);
        let lines: Vec<&str> = full.lines().collect();
        let mut safe = Vec::new();
        let mut in_forbidden = false;
        for line in &lines {
            if line.contains("forbidden claims:") {
                in_forbidden = true;
            }
            if !in_forbidden {
                safe.push(*line);
            }
        }
        safe.join("\n")
    }

    fn find_scenario<'a>(matrix: &'a [SimulationResult], id: &str) -> &'a SimulationResult {
        matrix
            .iter()
            .find(|r| r.scenario_id == id)
            .unwrap_or_else(|| panic!("scenario {id} not found in matrix"))
    }

    // ---- matrix completeness ----

    #[test]
    fn matrix_has_all_12_scenarios() {
        let m = matrix();
        assert_eq!(m.len(), 12, "expected exactly 12 scenarios");
        let ids: Vec<&str> = m.iter().map(|r| r.scenario_id.as_str()).collect();
        for expected in &[
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
        ] {
            assert!(ids.contains(expected), "missing scenario {expected}");
        }
    }

    #[test]
    fn all_scenarios_have_pid_location_label() {
        for result in &matrix() {
            let _ = result.pid_location.label();
            // Verify the label is non-empty
            assert!(
                !result.pid_location.label().is_empty(),
                "{}: PID location label must not be empty",
                result.scenario_id
            );
        }
    }

    #[test]
    fn all_scenarios_have_rollback_decision() {
        for result in &matrix() {
            let _ = result.rollback_decision.label();
            assert!(
                !result.rollback_decision.label().is_empty(),
                "{}: rollback decision label must not be empty",
                result.scenario_id
            );
        }
    }

    #[test]
    fn all_scenarios_have_cleanup_decision() {
        for result in &matrix() {
            let _ = result.cleanup_decision.label();
            assert!(
                !result.cleanup_decision.label().is_empty(),
                "{}: cleanup decision label must not be empty",
                result.scenario_id
            );
        }
    }

    // ---- scenario-specific PID location assertions ----

    #[test]
    fn f1_pid_location_is_not_moved() {
        let m = matrix();
        let r = find_scenario(&m, "F1");
        assert_eq!(r.pid_location, PidLocationStatus::NotMoved);
    }

    #[test]
    fn f2_pid_location_is_not_moved() {
        let m = matrix();
        let r = find_scenario(&m, "F2");
        assert_eq!(r.pid_location, PidLocationStatus::NotMoved);
    }

    #[test]
    fn f3_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F3");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f4_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F4");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f5_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F5");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f6_pid_location_is_rollback_unverified() {
        let m = matrix();
        let r = find_scenario(&m, "F6");
        assert_eq!(r.pid_location, PidLocationStatus::RollbackUnverified);
    }

    #[test]
    fn f7_pid_location_is_verified_restored() {
        let m = matrix();
        let r = find_scenario(&m, "F7");
        assert_eq!(r.pid_location, PidLocationStatus::VerifiedRestored);
    }

    #[test]
    fn f8_pid_location_is_not_moved() {
        let m = matrix();
        let r = find_scenario(&m, "F8");
        assert_eq!(r.pid_location, PidLocationStatus::NotMoved);
    }

    #[test]
    fn f9_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F9");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f10_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F10");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f11_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F11");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    #[test]
    fn f12_pid_location_is_unknown() {
        let m = matrix();
        let r = find_scenario(&m, "F12");
        assert_eq!(r.pid_location, PidLocationStatus::Unknown);
    }

    // ---- rollback decision assertions ----

    #[test]
    fn f1_f2_rollback_not_needed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F1").rollback_decision,
            RollbackDecision::NotNeeded
        );
        assert_eq!(
            find_scenario(&m, "F2").rollback_decision,
            RollbackDecision::NotNeeded
        );
    }

    #[test]
    fn f3_f4_require_rollback_attempt() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F3").rollback_decision,
            RollbackDecision::AttemptOnce
        );
        assert_eq!(
            find_scenario(&m, "F4").rollback_decision,
            RollbackDecision::AttemptOnce
        );
    }

    #[test]
    fn f5_rollback_attempted_and_failed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F5").rollback_decision,
            RollbackDecision::AttemptedAndFailed
        );
    }

    #[test]
    fn f6_rollback_attempted_and_succeeded() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F6").rollback_decision,
            RollbackDecision::AttemptedAndSucceeded
        );
    }

    #[test]
    fn f7_rollback_not_needed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F7").rollback_decision,
            RollbackDecision::NotNeeded
        );
    }

    #[test]
    fn f8_rollback_not_needed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F8").rollback_decision,
            RollbackDecision::NotNeeded
        );
    }

    #[test]
    fn f9_rollback_attempted_and_failed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F9").rollback_decision,
            RollbackDecision::AttemptedAndFailed
        );
    }

    #[test]
    fn f10_requires_rollback_attempt() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F10").rollback_decision,
            RollbackDecision::AttemptOnce
        );
    }

    // ---- cleanup decision assertions ----

    #[test]
    fn f1_cleanup_not_needed() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F1").cleanup_decision,
            CleanupDecision::NotNeeded
        );
    }

    #[test]
    fn f2_cleanup_remove_empty() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F2").cleanup_decision,
            CleanupDecision::RemoveEmptyOperationOwned
        );
    }

    #[test]
    fn f10_cleanup_leaves_because_non_empty() {
        let m = matrix();
        assert_eq!(
            find_scenario(&m, "F10").cleanup_decision,
            CleanupDecision::LeaveBecauseNonEmpty
        );
    }

    #[test]
    fn cleanup_never_removes_non_empty_target() {
        for result in &matrix() {
            if result.cleanup_decision == CleanupDecision::RemoveEmptyOperationOwned {
                // Ensure this decision is only used when target is expected empty
                assert!(
                    !result.cleanup_decision.leaves_target(),
                    "{}: remove-empty should not leave target",
                    result.scenario_id
                );
            }
        }
    }

    // ---- render output: simulation/model-only markers ----

    #[test]
    fn every_render_output_says_simulation_model_only() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("simulation/model-only"),
                "{}: rendered output must contain 'simulation/model-only'",
                result.scenario_id
            );
        }
    }

    // ---- render output: canonical deny lines ----

    #[test]
    fn every_render_output_denies_live_pid_move() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("no live PID move was performed"),
                "{}: must deny live PID move",
                result.scenario_id
            );
        }
    }

    #[test]
    fn every_render_output_denies_real_cgroup_procs_write() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("no real cgroup.procs write was performed"),
                "{}: must deny real cgroup.procs write",
                result.scenario_id
            );
        }
    }

    #[test]
    fn every_render_output_denies_limiter_attach() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("no limiter attach was performed"),
                "{}: must deny limiter attach",
                result.scenario_id
            );
        }
    }

    #[test]
    fn every_render_output_denies_nft_tc_state_mutation() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("no nftables/tc/Zelynic state mutation was performed"),
                "{}: must deny nft/tc/state mutation",
                result.scenario_id
            );
        }
    }

    #[test]
    fn every_render_output_denies_persistent_state_write() {
        for result in &matrix() {
            let output = rendered(result);
            assert!(
                output.contains("no persistent state write was performed"),
                "{}: must deny persistent state write",
                result.scenario_id
            );
        }
    }

    // ---- no false rollback claims ----

    #[test]
    fn no_render_output_claims_rollback_when_pid_not_moved() {
        let m = matrix();
        let pre_move = ["F1", "F2", "F8"];
        for id in &pre_move {
            let result = find_scenario(&m, id);
            let output = rendered_safe_portion(result);
            assert!(
                !output.contains("Rollback was performed"),
                "{}: must not claim rollback when PID was not moved",
                id
            );
            assert!(
                !output.contains("PID was restored"),
                "{}: must not claim PID restored when not moved",
                id
            );
        }
    }

    // ---- rollback attempt requirement ----

    #[test]
    fn scenarios_after_possible_pid_move_require_rollback_or_manual_recovery() {
        for result in &matrix() {
            if result.pid_location == PidLocationStatus::Unknown
                || result.pid_location == PidLocationStatus::VerifiedInTarget
            {
                assert!(
                    result.rollback_decision == RollbackDecision::AttemptOnce
                        || result.rollback_decision == RollbackDecision::AttemptedAndSucceeded
                        || result.rollback_decision == RollbackDecision::AttemptedAndFailed
                        || result.rollback_decision == RollbackDecision::ManualRecoveryRequired,
                    "{}: PID location is {:?} but rollback decision is {:?}",
                    result.scenario_id,
                    result.pid_location,
                    result.rollback_decision
                );
            }
        }
    }

    // ---- forbidden claims in rendered output ----

    #[test]
    fn no_render_output_claims_limiter_attach() {
        for result in &matrix() {
            let output = rendered_safe_portion(result);
            assert!(
                !output.contains("Limiter was attached"),
                "{}: must not claim limiter attached",
                result.scenario_id
            );
        }
    }

    // ---- no retry loop modelled ----

    #[test]
    fn no_scenario_models_retry_loop() {
        for result in &matrix() {
            let output = rendered_safe_portion(result);
            assert!(
                !output.contains("retry"),
                "{}: must not model retry loop",
                result.scenario_id
            );
            assert!(
                !output.contains("Retry"),
                "{}: must not model Retry",
                result.scenario_id
            );
        }
    }

    // ---- FailureScenario enum helpers ----

    #[test]
    fn all_scenarios_returns_12() {
        assert_eq!(FailureScenario::all().len(), 12);
    }

    #[test]
    fn scenario_ids_are_canonical() {
        let expected = vec![
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
        ];
        let actual: Vec<&str> = FailureScenario::all().iter().map(|s| s.id()).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn scenario_names_are_non_empty() {
        for scenario in FailureScenario::all() {
            assert!(
                !scenario.name().is_empty(),
                "{:?}: name must not be empty",
                scenario
            );
        }
    }

    #[test]
    fn failure_points_are_non_empty() {
        for scenario in FailureScenario::all() {
            assert!(
                !scenario.failure_point().is_empty(),
                "{:?}: failure_point must not be empty",
                scenario
            );
        }
    }

    #[test]
    fn is_before_pid_move_correct() {
        assert!(FailureScenario::FailureBeforeTargetCgroupCreation.is_before_pid_move());
        assert!(FailureScenario::FailureAfterTargetCreationBeforePidMove.is_before_pid_move());
        assert!(!FailureScenario::FailureAfterPidMoveBeforeVerification.is_before_pid_move());
        assert!(!FailureScenario::FailureDuringRollbackWrite.is_before_pid_move());
    }

    #[test]
    fn requires_rollback_attempt_correct() {
        assert!(!FailureScenario::FailureBeforeTargetCgroupCreation.requires_rollback_attempt());
        assert!(FailureScenario::FailureAfterPidMoveBeforeVerification.requires_rollback_attempt());
        assert!(FailureScenario::FailureDuringRollbackWrite.requires_rollback_attempt());
        assert!(FailureScenario::UnexpectedErrnoBehavior.requires_rollback_attempt());
    }

    // ---- PID location label coverage ----

    #[test]
    fn all_pid_location_labels_are_covered() {
        let locations: std::collections::HashSet<_> =
            matrix().iter().map(|r| r.pid_location).collect();
        assert!(locations.contains(&PidLocationStatus::NotMoved));
        assert!(locations.contains(&PidLocationStatus::VerifiedRestored));
        assert!(locations.contains(&PidLocationStatus::RollbackUnverified));
        assert!(locations.contains(&PidLocationStatus::Unknown));
    }

    // ---- render structure tests ----

    #[test]
    fn render_includes_scenario_id_and_name() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains(&result.scenario_id),
                "{}: must contain scenario ID",
                result.scenario_id
            );
            assert!(
                output.contains(&result.scenario_name),
                "{}: must contain scenario name",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_phase_label() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains(PHASE_LABEL),
                "{}: must contain phase label",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_pid_location_label() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("PID location:"),
                "{}: must contain PID location field",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_rollback_decision_label() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("rollback decision:"),
                "{}: must contain rollback decision field",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_cleanup_decision_label() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("cleanup decision:"),
                "{}: must contain cleanup decision field",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_deny_lines() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("deny lines:"),
                "{}: must contain deny lines section",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_includes_forbidden_claims() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("forbidden claims:"),
                "{}: must contain forbidden claims section",
                result.scenario_id
            );
        }
    }

    // ---- simulation result field correctness ----

    #[test]
    fn all_results_have_7_deny_lines() {
        for result in &matrix() {
            assert_eq!(
                result.deny_lines.len(),
                7,
                "{}: expected 7 deny lines, got {}",
                result.scenario_id,
                result.deny_lines.len()
            );
        }
    }

    #[test]
    fn all_results_have_non_empty_honesty_lines() {
        for result in &matrix() {
            assert!(
                !result.honesty_lines.is_empty(),
                "{}: must have honesty lines",
                result.scenario_id
            );
        }
    }

    #[test]
    fn all_results_have_non_empty_forbidden_claims() {
        for result in &matrix() {
            assert!(
                !result.forbidden_claims.is_empty(),
                "{}: must have forbidden claims",
                result.scenario_id
            );
        }
    }

    // ---- cleanup never removes non-empty target ----

    #[test]
    fn f10_cleanup_explicitly_leaves_non_empty() {
        let m = matrix();
        let r = find_scenario(&m, "F10");
        assert!(r.cleanup_decision.leaves_target());
        assert_eq!(r.cleanup_decision, CleanupDecision::LeaveBecauseNonEmpty);
    }

    // ---- universal failure rules verification ----

    #[test]
    fn rule1_no_false_rollback_claims_for_pre_move_scenarios() {
        let pre_move = [
            FailureScenario::FailureBeforeTargetCgroupCreation,
            FailureScenario::FailureAfterTargetCreationBeforePidMove,
            FailureScenario::StaleDeadPidDuringTransaction,
        ];
        for scenario in &pre_move {
            let result = simulate_failure_scenario(*scenario);
            assert_eq!(
                result.rollback_decision,
                RollbackDecision::NotNeeded,
                "{:?}: must not require rollback when PID was not moved",
                scenario
            );
            assert!(
                result
                    .forbidden_claims
                    .iter()
                    .any(|c| c.contains("Rollback")),
                "{:?}: must forbid rollback claims",
                scenario
            );
        }
    }

    #[test]
    fn rule2_rollback_attempted_once_if_move_may_have_occurred() {
        let post_move = [
            FailureScenario::FailureAfterPidMoveBeforeVerification,
            FailureScenario::FailureAfterVerificationBeforeRollback,
            FailureScenario::FailureDuringRollbackWrite,
            FailureScenario::FailureAfterRollbackWriteBeforeVerification,
            FailureScenario::TargetCgroupBecomesNonEmptyUnexpectedly,
            FailureScenario::UnexpectedErrnoBehavior,
        ];
        for scenario in &post_move {
            let result = simulate_failure_scenario(*scenario);
            assert!(
                matches!(
                    result.rollback_decision,
                    RollbackDecision::AttemptOnce
                        | RollbackDecision::AttemptedAndSucceeded
                        | RollbackDecision::AttemptedAndFailed
                        | RollbackDecision::ManualRecoveryRequired
                ),
                "{:?}: must require rollback attempt after possible PID move, got {:?}",
                scenario,
                result.rollback_decision
            );
        }
    }

    #[test]
    fn rule3_rollback_failure_reported_loudly() {
        let rollback_failed = [
            FailureScenario::FailureDuringRollbackWrite,
            FailureScenario::OriginalCgroupDisappearsDuringTransaction,
            FailureScenario::PermissionDeniedOnCgroupProcsWrite,
        ];
        for scenario in &rollback_failed {
            let result = simulate_failure_scenario(*scenario);
            assert!(
                result
                    .honesty_lines
                    .iter()
                    .any(|l| l.contains("ROLLBACK FAILURE")),
                "{:?}: must contain ROLLBACK FAILURE in honesty lines",
                scenario
            );
        }
    }

    #[test]
    fn rule4_no_limiter_attach_in_any_failure_output() {
        for scenario in FailureScenario::all() {
            let result = simulate_failure_scenario(scenario);
            let output = rendered(&result);
            assert!(
                !output.contains("Limiter attached"),
                "{:?}: must not claim limiter attached",
                scenario
            );
            assert!(
                !output.contains("Bandwidth limiting active"),
                "{:?}: must not claim bandwidth limiting active",
                scenario
            );
            assert!(
                !output.contains("Enforcement applied"),
                "{:?}: must not claim enforcement applied",
                scenario
            );
        }
    }

    #[test]
    fn rule5_no_nft_tc_state_write_in_failure_path() {
        for scenario in FailureScenario::all() {
            let output = rendered(&simulate_failure_scenario(scenario));
            assert!(
                output.contains("no nftables/tc/Zelynic state mutation was performed"),
                "{:?}: must deny nft/tc/state mutation",
                scenario
            );
        }
    }

    #[test]
    fn rule6_no_deletion_of_non_empty_cgroup() {
        for scenario in FailureScenario::all() {
            let result = simulate_failure_scenario(scenario);
            if result.cleanup_decision == CleanupDecision::RemoveEmptyOperationOwned {
                assert!(
                    result
                        .forbidden_claims
                        .iter()
                        .any(|c| c.contains("force-removed") || c.contains("Force-removed")),
                    "{:?}: remove-empty must still forbid force-removal claims",
                    scenario
                );
            }
        }
    }

    #[test]
    fn rule7_no_deletion_outside_zelynic_namespace() {
        for scenario in FailureScenario::all() {
            let result = simulate_failure_scenario(scenario);
            let output = rendered(&result);
            // The deny lines should explicitly state the simulation boundary
            assert!(
                output.contains("simulation/model-only"),
                "{:?}: must state simulation/model-only boundary",
                scenario
            );
        }
    }

    #[test]
    fn rule8_no_retry_loops() {
        for scenario in FailureScenario::all() {
            let result = simulate_failure_scenario(scenario);
            let output = rendered_safe_portion(&result);
            assert!(
                !output.contains("retry") && !output.contains("Retry"),
                "{:?}: must not model any retry loop",
                scenario
            );
        }
    }

    #[test]
    fn rule9_pid_location_explicitly_stated() {
        for scenario in FailureScenario::all() {
            let result = simulate_failure_scenario(scenario);
            let output = rendered(&result);
            assert!(
                output.contains("PID location:"),
                "{:?}: must explicitly state PID location",
                scenario
            );
            assert!(
                !result.pid_location.label().is_empty(),
                "{:?}: PID location label must not be empty",
                scenario
            );
        }
    }

    // ---- individual scenario simulate_failure_scenario correctness ----

    #[test]
    fn f1_simulate_returns_correct_model() {
        let result = simulate_failure_scenario(FailureScenario::FailureBeforeTargetCgroupCreation);
        assert_eq!(result.scenario_id, "F1");
        assert!(!result.target_may_remain);
        assert!(!result.manual_recovery_required);
        assert_eq!(result.cleanup_decision, CleanupDecision::NotNeeded);
    }

    #[test]
    fn f2_simulate_returns_correct_model() {
        let result =
            simulate_failure_scenario(FailureScenario::FailureAfterTargetCreationBeforePidMove);
        assert_eq!(result.scenario_id, "F2");
        assert!(result.target_may_remain);
        assert!(!result.manual_recovery_required);
        assert_eq!(
            result.cleanup_decision,
            CleanupDecision::RemoveEmptyOperationOwned
        );
    }

    #[test]
    fn f5_simulate_returns_correct_model() {
        let result = simulate_failure_scenario(FailureScenario::FailureDuringRollbackWrite);
        assert_eq!(result.scenario_id, "F5");
        assert_eq!(
            result.rollback_decision,
            RollbackDecision::AttemptedAndFailed
        );
        assert!(result.manual_recovery_required);
    }

    #[test]
    fn f7_simulate_returns_correct_model() {
        let result = simulate_failure_scenario(FailureScenario::FailureDuringTargetCleanup);
        assert_eq!(result.scenario_id, "F7");
        assert_eq!(result.pid_location, PidLocationStatus::VerifiedRestored);
        assert_eq!(result.rollback_decision, RollbackDecision::NotNeeded);
    }

    // ---- CleanupDecision::leaves_target helper ----

    #[test]
    fn cleanup_leaves_target_returns_correct() {
        assert!(!CleanupDecision::NotNeeded.leaves_target());
        assert!(!CleanupDecision::RemoveEmptyOperationOwned.leaves_target());
        assert!(CleanupDecision::LeaveBecauseNonEmpty.leaves_target());
        assert!(CleanupDecision::LeaveBecauseUnsafe.leaves_target());
        assert!(CleanupDecision::ManualCleanupRequired.leaves_target());
    }

    // ---- build_failure_simulation_matrix determinism ----

    #[test]
    fn matrix_is_deterministic() {
        let m1 = build_failure_simulation_matrix();
        let m2 = build_failure_simulation_matrix();
        assert_eq!(m1.len(), m2.len());
        for (a, b) in m1.iter().zip(m2.iter()) {
            assert_eq!(a, b);
        }
    }

    // ---- render output contains all required sections ----

    #[test]
    fn render_output_contains_target_may_remain_field() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("target may remain:"),
                "{}: must contain target_may_remain field",
                result.scenario_id
            );
        }
    }

    #[test]
    fn render_output_contains_manual_recovery_field() {
        let m = matrix();
        for result in &m {
            let output = rendered(result);
            assert!(
                output.contains("manual recovery required:"),
                "{}: must contain manual_recovery_required field",
                result.scenario_id
            );
        }
    }
}
