// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};

mod contract;
mod discovery;
mod manual_probe;
mod plan;
mod preflight;
mod render;
mod render_contract;
mod sanitize;
mod scope_runner;

pub(crate) use plan::ScopeMode;
use plan::{build_dry_run_plan_with_scope_mode, build_live_run_plan_with_scope_mode, LiveRunPlan};
use preflight::current_execution_preflight;
use render::{print_dry_run_plan, print_live_run_plan};

#[allow(clippy::too_many_arguments)]
pub fn run_systemd_wrapper(
    dry_run: bool,
    execute: bool,
    probe_live: bool,
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
                return run_probe_live(scope_mode, target, download, upload, command);
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
fn run_probe_live(
    scope_mode: ScopeMode,
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    command: &[String],
) -> Result<()> {
    // Gate check: probe_live + system + root
    scope_runner::probe_gate(true, scope_mode)?;

    let systemd_run = scope_runner::build_probe_systemd_run_plan(target, command)?;

    let result = scope_runner::run_scope_probe(&systemd_run)?;

    // Build non-mutating attach preview
    let preview =
        scope_runner::build_attach_preview(&systemd_run.target, &result.pids, download, upload)?;

    scope_runner::print_scope_probe_output_with_preview(&result, &preview);

    Ok(())
}

fn execute_live_run(_plan: &LiveRunPlan) -> Result<()> {
    bail!("Live systemd wrapper execution is not implemented yet.")
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
        // Non-root execute without probe-live should fall through to
        // the old execute_live_run which returns not-implemented.
        let err = run_systemd_wrapper(
            false,
            true,
            false, // probe_live = false
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
            true, // probe_live = true
            None,
            None,
            None,
            ScopeMode::User, // user scope → blocked
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
            true, // probe_live = true
            None,
            None,
            None,
            ScopeMode::System, // system scope
            &command,
        )
        .unwrap_err()
        .to_string();

        // In CI we're non-root, so this should say requires root
        assert!(err.contains("requires root"));
    }
}
