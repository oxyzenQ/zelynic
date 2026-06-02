// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};

mod discovery;
mod plan;
mod preflight;
mod render;
mod sanitize;

pub(crate) use plan::ScopeMode;
use plan::{build_dry_run_plan_with_scope_mode, build_live_run_plan_with_scope_mode, LiveRunPlan};
use preflight::current_execution_preflight;
use render::{print_dry_run_plan, print_live_run_plan};

pub fn run_systemd_wrapper(
    dry_run: bool,
    execute: bool,
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
}
