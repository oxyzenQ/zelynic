// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Strict limiting handlers — strict-single, strict-multi, limit-all.

use anyhow::Result;

use crate::commands::rates::resolve_rates;
use crate::commands::safety::{check_dangerous_target, is_dangerous_target};

#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_strict_single(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    check_dangerous_target(target_str, force)?;

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-single brave 100kb"
        ));
    }

    let target = Target::parse(target_str);

    // Attach BPF programs (pins to /sys/fs/bpf/zelynic/ — survives exit).
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    // Open pinned maps and write policy.
    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln!("No cgroup found for '{target_str}'. Nothing to limit.");
        return Ok(());
    }

    print_pin_summary(target_str, &rates, applied);
    Ok(())
}

#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_strict_multi(
    targets_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    // Check each target for dangerous names.
    for t in targets_str.split(':') {
        let t = t.trim();
        if !t.is_empty() {
            check_dangerous_target(t, force)?;
        }
    }

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-multi brave:curl 1mb"
        ));
    }

    let targets: Vec<Target> = targets_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(Target::parse)
        .collect();

    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "No targets specified. Use colon-separated list.\n\
             Example: zelynic strict-multi brave:curl:pacman 1mb"
        ));
    }

    // If no serve child running, spawn one.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        crate::ebpf::limiter::Limiter::attach(verbose)?;
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln!("No cgroups found for any target in '{targets_str}'. Nothing to limit.");
        return Ok(());
    }

    print_pin_summary(targets_str, &rates, applied);

    // Verify serve child is still alive after apply.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        let log = std::fs::read_to_string("/tmp/zelynic-serve.log").unwrap_or_default();
        eprintln!("WARNING: Serve child died after applying policies!");
        eprintln!("Log: {log}");
    }
    Ok(())
}

/// Handle `zelynic limit-all` — limit ALL user apps.
/// System/dangerous apps are excluded unless --force.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_limit_all(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic limit-all 500kb"
        ));
    }

    // Get all apps from identity map.
    let mut identity = IdentityMap::new();
    identity.refresh();

    let mut user_apps: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for app in identity.all() {
        if app.comm.is_empty() {
            continue;
        }
        if is_dangerous_target(&app.comm) {
            if force {
                user_apps.push(app.comm.clone());
            } else {
                skipped.push(app.comm.clone());
            }
        } else {
            user_apps.push(app.comm.clone());
        }
    }

    if user_apps.is_empty() {
        eprintln!("No apps found to limit.");
        return Ok(());
    }

    // Deduplicate (multiple cgroups may have same comm).
    user_apps.sort();
    user_apps.dedup();

    eprintln!(
        "Limiting {} app(s) to {}",
        user_apps.len(),
        rates
            .download
            .map(crate::ebpf::limiter::format_rate)
            .unwrap_or_default()
    );

    if !skipped.is_empty() {
        eprintln!(
            "Skipped {} system app(s) (use --force to include):",
            skipped.len()
        );
        for s in &skipped {
            eprintln!("  - {s}");
        }
    }

    // Build targets list.
    let targets: Vec<Target> = user_apps
        .iter()
        .map(|n| Target::ProcessName(n.clone()))
        .collect();

    // If no serve child running, spawn one.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        crate::ebpf::limiter::Limiter::attach(verbose)?;
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;

    print_pin_summary(&format!("{} apps", user_apps.len()), &rates, applied);

    if !crate::ebpf::limiter::Limiter::is_pinned() {
        let log = std::fs::read_to_string("/tmp/zelynic-serve.log").unwrap_or_default();
        eprintln!("WARNING: Serve child died after applying policies!");
        eprintln!("Log: {log}");
    }
    Ok(())
}

/// Print summary for pin mode (fire-and-forget).
#[cfg(feature = "ebpf")]
fn print_pin_summary(target_str: &str, rates: &crate::ebpf::limiter::RateSpec, applied: usize) {
    let dl_str = rates
        .download
        .map(crate::ebpf::limiter::format_rate)
        .unwrap_or_default();
    let ul_str = rates
        .upload
        .map(crate::ebpf::limiter::format_rate)
        .unwrap_or_default();
    let parts: Vec<&str> = [
        if !dl_str.is_empty() {
            dl_str.as_str()
        } else {
            ""
        },
        if !ul_str.is_empty() {
            ul_str.as_str()
        } else {
            ""
        },
    ]
    .iter()
    .filter(|s| !s.is_empty())
    .copied()
    .collect();

    eprintln!(
        "Limiting '{target_str}' to {} ({applied} policies, active in background)",
        parts.join(" + ")
    );
    eprintln!("Run 'zelynic unstrict {target_str}' to remove, 'zelynic status' to check.");
}
