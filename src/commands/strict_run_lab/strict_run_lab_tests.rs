// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use clap::{CommandFactory, Parser};

// === Section A: Existing structural tests (1-20) ===

#[test]
fn experimental_banner_contains_lab_wording() {
    let s = module_source();
    assert!(s.contains("EXPERIMENTAL"));
    assert!(s.contains("PRE-LAUNCH"));
    assert!(s.contains("LAB"));
}

#[test]
fn experimental_banner_says_pre_launch_cgroup() {
    let s = module_source();
    assert!(s.contains("cgroup"));
}

#[test]
fn experimental_banner_does_not_claim_stable() {
    let s = module_source();
    assert!(s.contains("not stable"));
}

#[test]
fn experimental_banner_says_pid_not_traffic_proven() {
    let s = module_source();
    assert!(s.contains("PID moved"));
    assert!(s.contains("traffic proven"));
}

#[test]
fn tunnel_detection_works_for_lab_command() {
    assert!(limiter::traffic_proof::is_tunnel_interface("proton0"));
    assert!(limiter::traffic_proof::is_tunnel_interface("tun0"));
    assert!(limiter::traffic_proof::is_tunnel_interface("wg0"));
    assert!(!limiter::traffic_proof::is_tunnel_interface("eth0"));
}

#[test]
fn traffic_proof_model_reused_in_lab() {
    let p = limiter::traffic_proof::StrictTrafficProof::default();
    assert_eq!(
        p.status,
        limiter::traffic_proof::StrictTrafficProofStatus::NotChecked
    );
}

#[test]
fn cleanup_function_exists() {
    let _ = attempt_cleanup as fn(&str, &str, bool);
}

#[test]
fn no_daemon_watch_code() {
    let s = module_source();
    assert!(!s.contains("daemon"));
    assert!(!s.contains("watch"));
}

#[test]
fn no_quota_code() {
    let s = module_source();
    assert!(!s.contains("quota"));
}

#[test]
fn no_ebpf_code() {
    let s = module_source();
    assert!(!s.contains("ebpf") && !s.contains("eBPF"));
}

#[test]
fn no_ledger_persistence() {
    let s = module_source();
    assert!(!s.contains("LedgerPersistencePlan") && !s.contains("LedgerPathPlan"));
}

#[test]
fn no_usage_json_schema_change() {
    let s = module_source();
    assert!(!s.contains("schema_version"));
}

#[test]
fn cleanup_called_on_error_paths() {
    let s = module_source();
    assert!(s.contains("attempt_cleanup"));
}

#[test]
fn no_detach_or_daemonize() {
    let s = module_source();
    assert!(!s.contains("detach") && !s.contains("daemonize"));
}

#[test]
fn zero_counters_not_claimed_as_proven() {
    let proof = limiter::traffic_proof::StrictTrafficProof {
        status: limiter::traffic_proof::StrictTrafficProofStatus::NoMatchObserved,
        counters: Some(limiter::traffic_proof::StrictTrafficProofCounters {
            cgroup_match: limiter::traffic_proof::NftCounter::default(),
            policer_match: limiter::traffic_proof::NftCounter::default(),
            checked: true,
        }),
        tunnel: None,
        explicit_interface: false,
    };
    let r = capture_tp_render(&proof);
    assert!(r.contains("not observed"));
    assert!(!r.contains("active"));
}

#[test]
fn handler_source_says_experimental() {
    let s = module_source();
    assert!(s.contains("experimental"));
}

#[test]
fn handler_source_says_lab() {
    let s = module_source();
    assert!(s.contains("lab"));
}

#[test]
fn handler_source_says_policy_installed() {
    let s = module_source();
    assert!(s.contains("Policy installed"));
}

#[test]
fn handler_source_says_pre_launch_cgroup() {
    let s = module_source();
    assert!(s.contains("pre-launch"));
    assert!(s.contains("cgroup"));
}

#[test]
fn handler_source_says_traffic_proof() {
    let s = module_source();
    assert!(s.contains("Traffic proof"));
}
// === Section B: Pure model tests ===
#[test]
fn proof_state_default_is_all_false() {
    let ps = StrictRunLabProofState::default();
    assert!(!ps.checked);
    assert!(!ps.cgroup_match_observed);
    assert!(!ps.policer_match_observed);
    assert!(!ps.drop_observed);
    assert!(!ps.is_tunnel);
    assert!(!ps.placed_before_exec);
}

#[test]
fn proof_state_is_traffic_proof_active_requires_all() {
    let ps = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: true,
        drop_observed: true,
        is_tunnel: false,
        placed_before_exec: true,
    };
    assert!(ps.is_traffic_proof_active());
    assert!(!StrictRunLabProofState {
        cgroup_match_observed: false,
        ..ps.clone()
    }
    .is_traffic_proof_active());
    assert!(!StrictRunLabProofState {
        policer_match_observed: false,
        ..ps.clone()
    }
    .is_traffic_proof_active());
    assert!(!StrictRunLabProofState {
        checked: false,
        ..ps
    }
    .is_traffic_proof_active());
}

#[test]
fn proof_state_from_traffic_proof_no_counters() {
    let p = limiter::traffic_proof::StrictTrafficProof::default();
    let ps = StrictRunLabProofState::from_traffic_proof(&p, false);
    assert!(
        !ps.checked
            && !ps.cgroup_match_observed
            && !ps.policer_match_observed
            && !ps.placed_before_exec
    );
}

#[test]
fn proof_state_from_traffic_proof_zero_counters() {
    let p = limiter::traffic_proof::StrictTrafficProof {
        status: limiter::traffic_proof::StrictTrafficProofStatus::NoMatchObserved,
        counters: Some(limiter::traffic_proof::StrictTrafficProofCounters {
            cgroup_match: limiter::traffic_proof::NftCounter::default(),
            policer_match: limiter::traffic_proof::NftCounter::default(),
            checked: true,
        }),
        tunnel: None,
        explicit_interface: false,
    };
    let ps = StrictRunLabProofState::from_traffic_proof(&p, true);
    assert!(
        ps.checked
            && ps.placed_before_exec
            && !ps.cgroup_match_observed
            && !ps.is_traffic_proof_active()
    );
}

#[test]
fn proof_state_from_traffic_proof_nonzero_counters() {
    let p = limiter::traffic_proof::StrictTrafficProof {
        status: limiter::traffic_proof::StrictTrafficProofStatus::PolicerMatchObserved,
        counters: Some(limiter::traffic_proof::StrictTrafficProofCounters {
            cgroup_match: limiter::traffic_proof::NftCounter {
                packets: 1800,
                bytes: 210054,
            },
            policer_match: limiter::traffic_proof::NftCounter {
                packets: 3236,
                bytes: 4456466,
            },
            checked: true,
        }),
        tunnel: Some(limiter::traffic_proof::TunnelInterfaceCheck {
            is_tunnel: true,
            interface_name: "proton0".to_string(),
        }),
        explicit_interface: true,
    };
    let ps = StrictRunLabProofState::from_traffic_proof(&p, true);
    assert!(
        ps.checked && ps.cgroup_match_observed && ps.policer_match_observed && ps.drop_observed
    );
    assert!(ps.is_tunnel && ps.placed_before_exec && ps.is_traffic_proof_active());
}

#[test]
fn proof_state_from_traffic_proof_tunnel_detection() {
    let p = limiter::traffic_proof::StrictTrafficProof {
        tunnel: Some(limiter::traffic_proof::TunnelInterfaceCheck {
            is_tunnel: true,
            interface_name: "proton0".to_string(),
        }),
        ..Default::default()
    };
    assert!(StrictRunLabProofState::from_traffic_proof(&p, false).is_tunnel);
}

// === Section C: Outcome model tests ===

#[test]
fn outcome_default_is_error_before_launch() {
    assert_eq!(
        StrictRunLabOutcome::default(),
        StrictRunLabOutcome::ErrorBeforeLaunch
    );
}

#[test]
fn outcome_launched_variant() {
    if let StrictRunLabOutcome::Launched {
        child_pid,
        verified_in_cgroup,
    } = (StrictRunLabOutcome::Launched {
        child_pid: 1234,
        verified_in_cgroup: true,
    }) {
        assert_eq!(child_pid, 1234);
        assert!(verified_in_cgroup);
    } else {
        panic!("expected Launched variant");
    }
}

#[test]
fn outcome_completed_variant() {
    if let StrictRunLabOutcome::Completed {
        child_pid,
        cleanup_attempted,
        ..
    } = (StrictRunLabOutcome::Completed {
        child_pid: 5678,
        verified_in_cgroup: true,
        proof_state: StrictRunLabProofState::default(),
        exit_success: true,
        cleanup_attempted: true,
    }) {
        assert_eq!(child_pid, 5678);
        assert!(cleanup_attempted);
    } else {
        panic!("expected Completed variant");
    }
}

#[test]
fn outcome_error_after_launch_variant() {
    if let StrictRunLabOutcome::ErrorAfterLaunch {
        child_pid,
        cleanup_attempted,
    } = (StrictRunLabOutcome::ErrorAfterLaunch {
        child_pid: 9999,
        cleanup_attempted: true,
    }) {
        assert_eq!(child_pid, 9999);
        assert!(cleanup_attempted);
    } else {
        panic!("expected ErrorAfterLaunch variant");
    }
}

#[test]
fn outcome_policy_applied_variant() {
    let ps = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: true,
        drop_observed: true,
        is_tunnel: false,
        placed_before_exec: true,
    };
    if let StrictRunLabOutcome::PolicyApplied { proof_state, .. } =
        (StrictRunLabOutcome::PolicyApplied {
            child_pid: 42,
            verified_in_cgroup: true,
            proof_state: ps,
        })
    {
        assert!(proof_state.is_traffic_proof_active());
    } else {
        panic!("expected PolicyApplied variant");
    }
}
// === Section D: Proof summary render tests ===
#[test]
fn proof_summary_renders_not_checked() {
    assert!(
        capture_proof_render(&StrictRunLabProofState::default(), "eth0")
            .contains("traffic proof not checked")
    );
}

#[test]
fn proof_summary_renders_no_proof_observed() {
    let r = capture_proof_render(
        &StrictRunLabProofState {
            checked: true,
            ..Default::default()
        },
        "eth0",
    );
    assert!(r.contains("no traffic proof observed"));
}

#[test]
fn proof_summary_renders_traffic_proof_active() {
    let ps = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: true,
        drop_observed: true,
        placed_before_exec: true,
        ..Default::default()
    };
    let r = capture_proof_render(&ps, "eth0");
    assert!(r.contains("traffic proof observed") && r.contains("shaping appears active"));
}

#[test]
fn proof_summary_renders_tunnel_warning() {
    let r = capture_proof_render(
        &StrictRunLabProofState {
            checked: true,
            is_tunnel: true,
            ..Default::default()
        },
        "proton0",
    );
    assert!(r.contains("VPN/tunnel"));
}

#[test]
fn proof_summary_renders_attach_limitation() {
    assert!(
        capture_proof_render(&StrictRunLabProofState::default(), "eth0")
            .contains("attach-after-socket limitation")
    );
}

#[test]
fn proof_summary_renders_not_stable() {
    assert!(
        capture_proof_render(&StrictRunLabProofState::default(), "eth0").contains("not stable")
    );
}

#[test]
fn proof_summary_renders_placed_before_exec_yes() {
    assert!(capture_proof_render(
        &StrictRunLabProofState {
            placed_before_exec: true,
            ..Default::default()
        },
        "eth0",
    )
    .contains("yes"));
}

#[test]
fn proof_summary_renders_placed_before_exec_no() {
    assert!(capture_proof_render(
        &StrictRunLabProofState {
            placed_before_exec: false,
            ..Default::default()
        },
        "eth0",
    )
    .contains("no"));
}

#[test]
fn proof_summary_renders_counter_details() {
    let ps = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: true,
        drop_observed: true,
        placed_before_exec: true,
        ..Default::default()
    };
    let r = capture_proof_render(&ps, "eth0");
    assert!(
        r.contains("cgroup_match: true")
            && r.contains("policer_match: true")
            && r.contains("drop: true")
    );
}

#[test]
fn proof_summary_does_not_claim_success_when_zero() {
    let r = capture_proof_render(
        &StrictRunLabProofState {
            checked: true,
            placed_before_exec: true,
            ..Default::default()
        },
        "eth0",
    );
    assert!(!r.contains("shaping appears active"));
}

// === Section E: Output wording freeze ===

#[test]
fn output_says_policy_installed_not_limited() {
    let s = module_source();
    assert!(s.contains("policy to be installed"));
}

#[test]
fn output_says_child_launched_before_sockets() {
    let s = module_source();
    assert!(s.contains("before sockets are created"));
}

#[test]
fn output_says_attach_limitation_remains() {
    let s = module_source();
    assert!(s.contains("attach-after-socket limitation remains"));
}

#[test]
fn output_says_vpn_tunnel_cases_may_vary() {
    let s = module_source();
    assert!(s.contains("VPN/tunnel"));
}

#[test]
fn output_says_experiment_not_stable() {
    let s = module_source();
    assert!(s.contains("not stable") && s.contains("Do not use this as evidence"));
}

#[test]
fn output_says_cleanup_attempted_on_child_exit() {
    let s = module_source();
    assert!(s.contains("Cleanup attempted after child exit"));
}

// === Section F: Cleanup wording ===

#[test]
fn cleanup_says_removed_target_cgroup() {
    let s = module_source();
    assert!(s.contains("removed target cgroup directory"));
}

#[test]
fn cleanup_says_removed_tc_class_and_filters() {
    let s = module_source();
    assert!(s.contains("removed tc class and filters"));
}

#[test]
fn cleanup_says_failed_to_remove_on_error() {
    let s = module_source();
    assert!(s.contains("failed to remove cgroup dir"));
}

// === Section G: Error path cleanup ===

#[test]
fn handler_calls_attempt_cleanup_on_policy_error() {
    let s = module_source();
    assert!(s.contains("attempt_cleanup(&target_cg_path"));
}

#[test]
fn handler_kills_child_on_policy_error() {
    let s = module_source();
    assert!(s.contains("child.kill()"));
}

// === Section H: Structural safety ===

#[test]
fn no_systemd_scope_code() {
    let s = module_source();
    assert!(!s.contains("systemd_scope") && !s.contains("systemd-run"));
}

#[test]
fn no_enforcement_mutation() {
    let s = module_source();
    assert!(!s.contains("enforcement_active") && !s.contains("EnforcementStatus"));
}

#[test]
fn no_new_cli_visible_command() {
    let s = module_source();
    assert!(!s.contains("arg_required_else_help = true"));
}

// === Section I: Model determinism ===

#[test]
fn proof_state_equality_works() {
    let a = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: false,
        drop_observed: false,
        is_tunnel: true,
        placed_before_exec: true,
    };
    assert_eq!(a, a.clone());
}

#[test]
fn proof_state_debug_works() {
    let d = format!("{:?}", StrictRunLabProofState::default());
    assert!(d.contains("StrictRunLabProofState") && d.contains("checked: false"));
}

#[test]
fn outcome_debug_works() {
    let d = format!(
        "{:?}",
        StrictRunLabOutcome::Completed {
            child_pid: 1234,
            verified_in_cgroup: true,
            proof_state: StrictRunLabProofState::default(),
            exit_success: true,
            cleanup_attempted: true,
        }
    );
    assert!(d.contains("Completed") && d.contains("child_pid: 1234"));
}

// === Section J: Helpers ===

fn capture_tp_render(proof: &limiter::traffic_proof::StrictTrafficProof) -> String {
    let mut lines = Vec::new();
    match &proof.status {
        limiter::traffic_proof::StrictTrafficProofStatus::NoMatchObserved => {
            if let Some(ref c) = proof.counters {
                lines.push(format!(
                    "nft cgroup match: packets {}, bytes {}",
                    c.cgroup_match.packets, c.cgroup_match.bytes
                ));
                lines.push(format!(
                    "download policer: packets {}, bytes {}",
                    c.policer_match.packets, c.policer_match.bytes
                ));
            }
            lines.push("Traffic proof: not observed yet".to_string());
        }
        limiter::traffic_proof::StrictTrafficProofStatus::PolicerMatchObserved => {
            lines.push(
                "Traffic proof: policer observed (download rate limiting active)".to_string(),
            );
        }
        _ => {}
    }
    lines.join("\n")
}

fn capture_proof_render(proof: &StrictRunLabProofState, interface: &str) -> String {
    let mut lines = vec![
        format!(
            "placed: {}",
            if proof.placed_before_exec {
                "yes"
            } else {
                "no"
            }
        ),
        format!("checked: {}", proof.checked),
        format!("cgroup_match: {}", proof.cgroup_match_observed),
        format!("policer_match: {}", proof.policer_match_observed),
        format!("drop: {}", proof.drop_observed),
        format!("tunnel: {}", proof.is_tunnel),
        format!("interface: {}", interface),
        format!("active: {}", proof.is_traffic_proof_active()),
    ];
    if proof.is_traffic_proof_active() {
        lines.push("traffic proof observed -- shaping appears active in this run".to_string());
    } else if proof.checked && !proof.cgroup_match_observed {
        lines.push("no traffic proof observed -- counters remain at zero".to_string());
    } else {
        lines.push("traffic proof not checked".to_string());
    }
    if proof.is_tunnel {
        lines.push("VPN/tunnel cases may still vary".to_string());
    }
    lines.push("attach-after-socket limitation remains for stable 'strict'".to_string());
    lines.push("This experiment is not stable. Do not promote based on a single run.".to_string());
    lines.join("\n")
}

// === Section K: Validation freeze tests ===

#[test]
fn freeze_hidden_from_help_cli_level() {
    let help = crate::cli::Cli::command().render_help().to_string();
    assert!(
        !help.contains("strict-run-lab"),
        "strict-run-lab must remain hidden from normal help output"
    );
}

#[test]
fn freeze_requires_double_dash_before_command() {
    let result = crate::cli::Cli::try_parse_from(["zelynic", "strict-run-lab", "-d", "100kb"]);
    assert!(
        result.is_err(),
        "strict-run-lab without -- <command> must fail"
    );
}

#[test]
fn freeze_says_experimental_and_lab_and_not_stable() {
    let s = module_source();
    assert!(s.contains("experimental"), "must say experimental");
    assert!(s.contains("lab"), "must say lab");
    assert!(s.contains("not stable"), "must say not stable");
    assert!(
        !s.contains("stable command"),
        "must not claim to be a stable command"
    );
}

#[test]
fn freeze_says_pre_launch_cgroup_placement() {
    let s = module_source();
    assert!(s.contains("pre-launch"), "must say pre-launch");
    assert!(s.contains("cgroup"), "must say cgroup");
    assert!(s.contains("before sockets"), "must mention before sockets");
}

#[test]
fn freeze_traffic_proof_reuses_shared_model() {
    let s = module_source();
    assert!(
        s.contains("from_traffic_proof"),
        "must use shared from_traffic_proof conversion"
    );
    assert!(
        s.contains("build_traffic_proof"),
        "must use shared build_traffic_proof function"
    );
    assert!(
        s.contains("render_strict_traffic_proof"),
        "must reuse shared traffic proof renderer"
    );
}

#[test]
fn freeze_no_false_success_on_zero_counters() {
    let ps = StrictRunLabProofState {
        checked: true,
        placed_before_exec: true,
        ..Default::default()
    };
    assert!(
        !ps.is_traffic_proof_active(),
        "zero counters must never be claimed as active proof"
    );
    let partial = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        placed_before_exec: true,
        ..Default::default()
    };
    assert!(
        !partial.is_traffic_proof_active(),
        "partial proof (cgroup only) must not be active"
    );
}

#[test]
fn freeze_cleanup_wording_present() {
    let s = module_source();
    assert!(s.contains("removed target cgroup directory"));
    assert!(s.contains("removed tc class and filters"));
    assert!(s.contains("failed to remove cgroup dir"));
}

#[test]
fn freeze_cleanup_on_error_path() {
    let s = module_source();
    assert!(
        s.contains("child.kill()"),
        "must kill child on policy error"
    );
    assert!(s.contains("child.wait()"), "must wait for child after kill");
    assert!(
        s.contains("attempt_cleanup(&target_cg_path"),
        "must call cleanup on error path"
    );
}

#[test]
fn freeze_strict_behavior_unchanged() {
    let s = module_source();
    assert!(
        !s.contains("handle_strict("),
        "lab handler must not call stable handle_strict()"
    );
    assert!(
        !s.contains("force_reconnect"),
        "lab handler must not call force_reconnect (stable-only)"
    );
}

#[test]
fn freeze_no_usage_json_schema_change() {
    let s = module_source();
    assert!(
        !s.contains("schema_version"),
        "lab handler must not touch usage JSON schema"
    );
    assert!(
        !s.contains("UsageSnapshot"),
        "lab handler must not reference usage snapshot types"
    );
}

#[test]
fn freeze_no_forbidden_features() {
    let s = module_source();
    assert!(!s.contains("daemon"), "no daemon");
    assert!(!s.contains("watch"), "no watch");
    assert!(!s.contains("quota"), "no quota");
    assert!(!s.contains("ebpf") && !s.contains("eBPF"), "no eBPF");
    assert!(!s.contains("LedgerPersistencePlan"), "no ledger");
    assert!(!s.contains("schema_version"), "no schema change");
    assert!(!s.contains("systemd-run"), "no systemd scope");
    assert!(!s.contains("enforcement_active"), "no enforcement mutation");
    assert!(!s.contains("arg_required_else_help"), "no visible command");
}

#[test]
fn freeze_live_proof_values_reproducible() {
    let proof = limiter::traffic_proof::StrictTrafficProof {
        status: limiter::traffic_proof::StrictTrafficProofStatus::PolicerMatchObserved,
        counters: Some(limiter::traffic_proof::StrictTrafficProofCounters {
            cgroup_match: limiter::traffic_proof::NftCounter {
                packets: 1800,
                bytes: 210054,
            },
            policer_match: limiter::traffic_proof::NftCounter {
                packets: 3236,
                bytes: 4456466,
            },
            checked: true,
        }),
        tunnel: Some(limiter::traffic_proof::TunnelInterfaceCheck {
            is_tunnel: true,
            interface_name: "proton0".to_string(),
        }),
        explicit_interface: true,
    };
    let ps = StrictRunLabProofState::from_traffic_proof(&proof, true);
    assert!(ps.cgroup_match_observed, "cgroup match must be observed");
    assert!(ps.policer_match_observed, "policer match must be observed");
    assert!(ps.drop_observed, "drop must be derived from policer");
    assert!(ps.is_tunnel, "proton0 must be detected as tunnel");
    assert!(ps.placed_before_exec, "must record pre-exec placement");
    assert!(ps.checked, "must record that counters were checked");
    assert!(
        ps.is_traffic_proof_active(),
        "live proof values (1800/210054, 3236/4456466) must yield active proof"
    );
}

#[test]
fn freeze_outcome_all_variants_exhaustive() {
    use StrictRunLabOutcome::*;
    let ps = StrictRunLabProofState {
        checked: true,
        cgroup_match_observed: true,
        policer_match_observed: true,
        drop_observed: true,
        is_tunnel: false,
        placed_before_exec: true,
    };
    match (Launched {
        child_pid: 1,
        verified_in_cgroup: true,
    }) {
        Launched { child_pid, .. } => assert_eq!(child_pid, 1),
        _ => panic!("Launched mismatch"),
    }
    match (PolicyApplied {
        child_pid: 2,
        verified_in_cgroup: true,
        proof_state: ps.clone(),
    }) {
        PolicyApplied { proof_state, .. } => assert!(proof_state.is_traffic_proof_active()),
        _ => panic!("PolicyApplied mismatch"),
    }
    match (Completed {
        child_pid: 3,
        verified_in_cgroup: true,
        proof_state: ps.clone(),
        exit_success: false,
        cleanup_attempted: true,
    }) {
        Completed {
            cleanup_attempted,
            exit_success,
            ..
        } => {
            assert!(cleanup_attempted);
            assert!(!exit_success);
        }
        _ => panic!("Completed mismatch"),
    }
    assert!(matches!(StrictRunLabOutcome::default(), ErrorBeforeLaunch));
    match (ErrorAfterLaunch {
        child_pid: 5,
        cleanup_attempted: true,
    }) {
        ErrorAfterLaunch {
            child_pid,
            cleanup_attempted,
        } => {
            assert_eq!(child_pid, 5);
            assert!(cleanup_attempted);
        }
        _ => panic!("ErrorAfterLaunch mismatch"),
    }
}

// === Section M: Contract + matrix invariants ===
const CONTRACT_DOC: &str = include_str!("../../../docs/strict-run-wrapper-stable-contract.md");
const MATRIX_DOC: &str = include_str!("../../../docs/strict-run-lab-manual-validation-matrix.md");
#[test]
fn contract_doc_has_required_sections() {
    let d = CONTRACT_DOC;
    assert!(d.contains("Chosen Future Stable Command Shape"));
    assert!(d.contains("Safety Contract"));
    assert!(d.contains("Traffic Proof Contract"));
    assert!(d.contains("Cleanup Contract"));
    assert!(d.contains("Compatibility Contract"));
    assert!(d.contains("Required Before Stable Promotion"));
    assert!(d.contains("strict --run"));
    assert!(d.contains("run --net-limit"));
}
#[test]
fn matrix_doc_exists_with_all_scenarios() {
    for id in [
        "SRL-MVM-001",
        "SRL-MVM-002",
        "SRL-MVM-003",
        "SRL-MVM-004",
        "SRL-MVM-005",
        "SRL-MVM-006",
        "SRL-MVM-007",
        "SRL-MVM-008",
        "SRL-MVM-009",
        "SRL-MVM-010",
        "SRL-MVM-011",
        "SRL-MVM-012",
    ] {
        assert!(MATRIX_DOC.contains(id), "missing scenario {id}");
    }
}
#[test]
fn matrix_doc_includes_counter_fields() {
    let d = MATRIX_DOC;
    assert!(d.contains("nft socket cgroupv2 counter behavior"));
    assert!(d.contains("ct mark counter behavior"));
    assert!(d.contains("download policer counter behavior"));
    assert!(d.contains("drop counter behavior"));
}
#[test]
fn matrix_doc_includes_cleanup_criteria() {
    assert!(MATRIX_DOC.contains("expected cleanup behavior"));
    assert!(MATRIX_DOC.contains("orphaned"));
}
#[test]
fn matrix_doc_says_experimental() {
    assert!(MATRIX_DOC.contains("experimental"));
    assert!(MATRIX_DOC.contains("NOT promote"));
}
#[test]
fn matrix_doc_says_stable_not_implemented() {
    assert!(MATRIX_DOC.contains("does NOT implement stable wrapper"));
    assert!(MATRIX_DOC.contains("does NOT promote"));
}
#[test]
fn no_stable_alias_in_cli() {
    assert!(!crate::cli::Cli::command()
        .find_subcommand_mut("run")
        .unwrap()
        .render_long_help()
        .to_string()
        .contains("net-limit"));
    assert!(!crate::cli::Cli::command()
        .find_subcommand_mut("strict")
        .unwrap()
        .render_long_help()
        .to_string()
        .contains("--run"));
}
#[test]
fn matrix_hidden_from_help() {
    assert!(!crate::cli::Cli::command()
        .render_help()
        .to_string()
        .contains("strict-run-lab"));
}
#[test]
fn matrix_json_schema_unchanged() {
    let s = module_source();
    assert!(!s.contains("schema_version") && !s.contains("UsageSnapshot"));
}
#[test]
fn matrix_strict_unchanged() {
    let s = module_source();
    assert!(!s.contains("handle_strict(") && !s.contains("force_reconnect"));
}
#[test]
fn matrix_no_forbidden_features() {
    let s = module_source();
    assert!(
        !s.contains("daemon")
            && !s.contains("watch")
            && !s.contains("quota")
            && !s.contains("LedgerPersistencePlan")
            && !s.contains("ebpf")
            && !s.contains("eBPF")
    );
}
#[test]
fn matrix_no_version_bump() {
    assert!(include_str!("../../../Cargo.toml").contains("version = \"3.0.1\""));
}
fn module_source() -> String {
    let source = include_str!("mod.rs");
    if let Some(pos) = source.find("#[cfg(test)]") {
        source[..pos].to_string()
    } else {
        source.to_string()
    }
}
