// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use crate::cli::RunScopeModeArg;
use crate::systemd_wrapper;

/// Experimental systemd scope wrapper planning.
///
/// Converts the CLI scope-mode argument to the internal enum and delegates
/// to the systemd wrapper module.
pub(crate) fn handle_run(
    dry_run: bool,
    execute: bool,
    target: Option<String>,
    scope_mode: RunScopeModeArg,
    download: Option<String>,
    upload: Option<String>,
    command: &[String],
) -> Result<()> {
    let scope_mode = match scope_mode {
        RunScopeModeArg::User => systemd_wrapper::ScopeMode::User,
        RunScopeModeArg::System => systemd_wrapper::ScopeMode::System,
    };
    systemd_wrapper::run_systemd_wrapper(
        dry_run,
        execute,
        target.as_deref(),
        download.as_deref(),
        upload.as_deref(),
        scope_mode,
        command,
    )
}
