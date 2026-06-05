// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};

mod attach_preview;
mod attach_safety;
mod attach_transaction;
mod cgroup_environment;
mod contract;
mod discovery;
mod experimental_attach_gate;
mod failure_simulation;
mod guarded_real_writer;
mod manual_probe;
mod mkdir_executor;
mod mkdir_transaction;
mod move_executor;
mod move_transaction;
mod operation_journal;
mod original_cgroup_preview;
mod pid_safety;
mod plan;
mod preflight;
mod render;
mod render_contract;
mod sanitize;
mod scope_probe;
mod scope_runner;
mod target_cgroup_preflight;

use experimental_attach_gate::{
    build_gate_input_from_preview, evaluate_experimental_attach_gate, ExperimentalAttachConsent,
    EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED,
};
pub(crate) const MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED: &str =
    "Mkdir-only experiment completed; experimental PID move is not implemented yet.";
use mkdir_executor::{render_mkdir_experiment_section, run_mkdir_only_experiment};
pub(crate) use plan::ScopeMode;
use plan::{build_dry_run_plan_with_scope_mode, build_live_run_plan_with_scope_mode, LiveRunPlan};
use preflight::current_execution_preflight;
use render::{print_dry_run_plan, print_live_run_plan};

#[allow(clippy::too_many_arguments)]
pub fn run_systemd_wrapper(
    dry_run: bool,
    execute: bool,
    probe_live: bool,
    attach_live: bool,
    experimental_single_pid_attach: bool,
    i_understand_this_moves_pids: bool,
    rollback_required: bool,
    mkdir_live: bool,
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    scope_mode: ScopeMode,
    command: &[String],
) -> Result<()> {
    match (dry_run, execute) {
        (true, false) => {
            let plan =
                build_dry_run_plan_with_scope_mode(target, download, upload, command, scope_mode)?;
            print_dry_run_plan(&plan);
            Ok(())
        }
        (false, true) => {
            // Check if probe-live path is requested
            if probe_live {
                let consent = ExperimentalAttachConsent {
                    experimental_single_pid_attach,
                    i_understand_this_moves_pids,
                    rollback_required,
                };
                return run_probe_live(
                    scope_mode,
                    attach_live,
                    consent,
                    mkdir_live,
                    target,
                    download,
                    upload,
                    command,
                );
            }
            let preflight = current_execution_preflight(scope_mode);
            let plan = build_live_run_plan_with_scope_mode(
                target, download, upload, command, scope_mode, preflight,
            )?;
            print_live_run_plan(&plan);
            execute_live_run(&plan)
        }
        (false, false) => {
            bail!("Live run mode is experimental. Use --dry-run to preview or --execute to opt in.")
        }
        (true, true) => bail!("--dry-run and --execute cannot be used together."),
    }
}

/// Scope Runner live probe: root-only, system-scope only.
#[allow(clippy::too_many_arguments)]
fn run_probe_live(
    scope_mode: ScopeMode,
    attach_live: bool,
    attach_consent: ExperimentalAttachConsent,
    mkdir_live: bool,
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    command: &[String],
) -> Result<()> {
    // Gate check: probe_live + system + root
    scope_runner::probe_gate(true, scope_mode)?;

    // Preserve the legacy hard block unless the v2.7 experimental consent
    // bundle is complete. Missing consent does not run the live probe.
    if attach_live && !attach_consent.all_present() {
        return scope_runner::attach_gate();
    }

    let systemd_run = scope_runner::build_probe_systemd_run_plan(target, command)?;

    let result = scope_runner::run_scope_probe(&systemd_run)?;

    // Read live cgroups before attach preview
    let live_previews = original_cgroup_preview::capture_original_cgroups_live(&result.pids);

    // Build non-mutating attach preview
    let mut preview = scope_runner::build_attach_preview(
        &systemd_run.target,
        &result.pids,
        download,
        upload,
        Some(live_previews),
    )?;

    if attach_live {
        let input = build_gate_input_from_preview(
            &preview,
            true,
            scope_mode,
            true,
            true,
            true,
            attach_consent,
        );
        let checklist = evaluate_experimental_attach_gate(input);
        preview = scope_runner::with_experimental_attach_gate(preview, checklist);
    }

    scope_runner::print_scope_probe_output_with_preview(&result, &preview, mkdir_live);

    // ---- mkdir-only experiment (v2.8 phase 2b) ----
    if mkdir_live {
        let target_name = target.map(str::to_string).unwrap_or_else(|| {
            command
                .first()
                .map(|c| c.rsplit('/').next().unwrap_or(c).to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
        let target_cgroup_path = format!(
            "{}/target_{}",
            mkdir_executor::ZELYNIC_CGROUP_ROOT,
            sanitize::sanitize_scope_component(&target_name)
        );
        let experiment =
            run_mkdir_only_experiment(mkdir_executor::ZELYNIC_CGROUP_ROOT, &target_cgroup_path);
        print_mkdir_experiment_result(&experiment);
    }

    if attach_live {
        if mkdir_live {
            anyhow::bail!(MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED);
        } else {
            anyhow::bail!(EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED);
        }
    }

    Ok(())
}

fn execute_live_run(_plan: &LiveRunPlan) -> Result<()> {
    bail!("Live systemd wrapper execution is not implemented yet.")
}

fn print_mkdir_experiment_result(experiment: &mkdir_executor::MkdirExperimentResult) {
    let mut output = String::new();
    render_mkdir_experiment_section(&mut output, experiment);
    for line in output.lines() {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_without_mode_errors_clearly() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let err = run_systemd_wrapper(
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
            Some("500kbit"),
            None,
            ScopeMode::User,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            err,
            "Live run mode is experimental. Use --dry-run to preview or --execute to opt in."
        );
    }

    #[test]
    fn execute_path_returns_not_implemented_without_running() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = plan::build_live_run_plan(None, Some("500kbit"), None, &command).unwrap();
        let err = execute_live_run(&plan).unwrap_err().to_string();

        assert_eq!(
            err,
            "Live systemd wrapper execution is not implemented yet."
        );
    }

    #[test]
    fn execute_without_probe_live_returns_not_implemented() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            err,
            "Live systemd wrapper execution is not implemented yet."
        );
    }

    #[test]
    fn probe_live_user_scope_returns_not_implemented_via_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::User,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("User-scope live runner is not implemented"));
    }

    #[test]
    fn probe_live_system_non_root_returns_root_required_via_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("requires root"));
    }

    #[test]
    fn attach_live_without_probe_live_returns_not_implemented() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            err,
            "Live systemd wrapper execution is not implemented yet."
        );
    }

    #[test]
    fn attach_live_user_scope_returns_not_implemented_via_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::User,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("User-scope live runner is not implemented"));
    }

    #[test]
    fn attach_live_system_non_root_returns_root_required_via_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        // Non-root: probe gate blocks before attach gate is reached
        assert!(err.contains("requires root"));
    }

    #[test]
    fn experimental_attach_all_flags_system_non_root_returns_root_required_via_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("requires root"));
        assert!(!err.contains("Experimental PID move is not implemented yet"));
    }

    #[test]
    fn mkdir_live_system_non_root_blocks_at_root_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        // Non-root: probe gate blocks before mkdir is reached
        assert!(err.contains("requires root"));
        assert!(!err.contains("Experimental PID move is not implemented yet"));
    }

    #[test]
    fn attach_live_root_would_hard_block_if_gate_reached() {
        let err = scope_runner::attach_gate().unwrap_err().to_string();
        assert!(err.contains("live attach is not implemented yet"));
        assert!(err.contains("live probe and attach preview"));
        // Must not claim mutation
        assert!(!err.contains("attached"));
        assert!(!err.contains("limited"));
    }

    #[test]
    fn attach_live_error_does_not_claim_mutation() {
        let err = scope_runner::attach_gate().unwrap_err().to_string();
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("limiter attach was performed"));
        assert!(!err.contains("nftables"));
        assert!(!err.contains("active limiter"));
    }

    // ---- mkdir-live error message tests ----

    #[test]
    fn mkdir_live_error_message_is_honest_about_completion() {
        // Verify the constant exists and has the right wording
        assert!(MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED.contains("Mkdir-only experiment completed"));
        assert!(MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED
            .contains("experimental PID move is not implemented yet"));
        // Must not claim full attach success
        assert!(!MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED.contains("attach"));
    }

    #[test]
    fn mkdir_live_error_differs_from_non_mkdir_error() {
        // The mkdir-live error message must be distinct from the non-mkdir one
        assert_ne!(
            MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED,
            EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED
        );
    }

    #[test]
    fn mkdir_live_non_root_still_blocks_at_root_gate() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            None,
            Some("500kbit"),
            Some("500kbit"),
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();

        // Non-root: blocks at root gate, never reaches mkdir-live error
        assert!(err.contains("requires root"));
        assert!(!err.contains(MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED));
        assert!(!err.contains("Experimental PID move is not implemented yet"));
    }

    // ---- phase 3d: output audit + negative-path error honesty ----

    #[test]
    fn non_root_full_consent_error_comprehensive_honesty() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();
        // Non-root: blocked at root gate, no mutation happened
        assert!(err.contains("requires root"));
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("cgroup.procs written"));
        assert!(!err.contains("limiter attach"));
        assert!(!err.contains("nftables"));
        assert!(!err.contains("bandwidth limiting active"));
        assert!(!err.contains("persistent state written"));
        assert!(!err.contains("rollback performed"));
    }

    #[test]
    fn user_scope_attach_error_never_claims_mutation() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::User,
            &command,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("User-scope live runner is not implemented"));
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("cgroup.procs written"));
        assert!(!err.contains("limiter attached"));
        assert!(!err.contains("nftables"));
        assert!(!err.contains("state changed"));
    }

    #[test]
    fn attach_gate_error_comprehensive_honesty_audit() {
        let err = scope_runner::attach_gate().unwrap_err().to_string();
        assert!(err.contains("live attach is not implemented yet"));
        assert!(err.contains("live probe and attach preview"));
        // Must not claim any mutation
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("cgroup.procs written"));
        assert!(!err.contains("limiter attached"));
        assert!(!err.contains("limiter attach was performed"));
        assert!(!err.contains("nftables"));
        assert!(!err.contains("bandwidth limiting active"));
        assert!(!err.contains("state written"));
        assert!(!err.contains("rollback performed"));
        assert!(!err.contains("enforced"));
        assert!(!err.contains("limited"));
    }

    #[test]
    fn probe_gate_user_scope_error_honesty() {
        let err = scope_runner::probe_gate(true, ScopeMode::User)
            .unwrap_err()
            .to_string();
        assert!(err.contains("User-scope live runner is not implemented"));
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("limiter attached"));
        assert!(!err.contains("nftables"));
        assert!(!err.contains("bandwidth limiting active"));
    }

    #[test]
    fn all_error_constants_never_claim_mutation() {
        // EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED
        assert!(!EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED.contains("PID was moved"));
        assert!(!EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED.contains("cgroup.procs written"));
        assert!(!EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED.contains("limiter attached"));
        assert!(!EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED.contains("nftables"));
        assert!(!EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED.contains("state changed"));
        assert!(EXPERIMENTAL_PID_MOVE_NOT_IMPLEMENTED
            .contains("Experimental PID move is not implemented yet"));
        // MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED
        assert!(!MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED.contains("PID was moved"));
        assert!(!MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED.contains("limiter attached"));
        assert!(!MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED.contains("nftables"));
        assert!(MKDIR_LIVE_PID_MOVE_NOT_IMPLEMENTED
            .contains("experimental PID move is not implemented yet"));
    }

    #[test]
    fn missing_probe_live_blocks_without_reaching_attach() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();
        // Falls through to "not implemented yet" since probe_live is false
        assert!(err.contains("not implemented yet"));
        assert!(!err.contains("PID was moved"));
        assert!(!err.contains("limiter attached"));
    }

    #[test]
    fn missing_attach_live_without_probe_falls_through() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let err = run_systemd_wrapper(
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            ScopeMode::System,
            &command,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not implemented yet"));
        assert!(!err.contains("PID was moved"));
    }
}
