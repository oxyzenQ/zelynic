// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};

mod discovery;
mod plan;
mod render;
mod sanitize;

use plan::build_dry_run_plan;
use render::print_dry_run_plan;

pub fn run_systemd_wrapper_dry_run(
    dry_run: bool,
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    command: &[String],
) -> Result<()> {
    if !dry_run {
        bail!("zelynic run is dry-run only in this release. Re-run with --dry-run.");
    }

    let plan = build_dry_run_plan(target, download, upload, command)?;
    print_dry_run_plan(&plan);
    Ok(())
}
