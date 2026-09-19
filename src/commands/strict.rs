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

    // Input validation first (fail-fast, no privileges needed): rate
    // strings and the dangerous-target blocklist are pure parsing, so
    // a typo surfaces its did-you-mean tip before the root requirement
    // — the same parse-before-execute contract clap applies to its own
    // arguments (live root-machine smoke-run find).
    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-single brave 100kb"
        ));
    }

    check_dangerous_target(target_str, force)?;

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    let target = Target::parse(target_str);

    // Attach BPF programs (pins to /sys/fs/bpf/zelynic/ — survives exit).
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    // Open pinned maps and write policy.
    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln_safe!("No cgroup found for '{target_str}'. Nothing to limit.");
        // NIGHT-hunt-10: a colon list in the single-target slot is the
        // natural mistake now that 'strict' exists as a shorthand —
        // route it to the multi form instead of a bare no-match.
        if target_str.contains(':') {
            eprintln_safe!("tip: colon-separated lists belong to strict-multi");
        }
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

    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as handle_strict_single.
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

    // Check each target for dangerous names.
    for t in targets_str.split(':') {
        let t = t.trim();
        if !t.is_empty() {
            check_dangerous_target(t, force)?;
        }
    }

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    // Attach + pin BPF programs (fire-and-forget: pins survive process
    // exit, no daemon). NIGHT-hunt-21: unconditional — attach() IS the
    // lifecycle ladder (operational-reuse check, schema-version
    // migration, stale-pin cleanup). The old `if !is_pinned()` pre-check
    // skipped the schema step, so an upgraded binary facing
    // stale-schema pins would write policies into old-layout maps while
    // strict-single and the block family already ran the full ladder.
    // With healthy, current pins attach() is a few stats + one read.
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln_safe!("No cgroups found for any target in '{targets_str}'. Nothing to limit.");
        return Ok(());
    }

    print_pin_summary(targets_str, &rates, applied);

    // Validate final state: pins must still be present after apply. A
    // concurrent operation (unstrict-all in another terminal) can tear
    // them down mid-flight; the old code misattributed this to a
    // "serve child" that no longer exists and read a stale log file.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
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

    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as the other strict handlers.
    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic limit-all 500kb"
        ));
    }

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

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
        eprintln_safe!("No apps found to limit.");
        return Ok(());
    }

    // Deduplicate (multiple cgroups may have same comm).
    user_apps.sort();
    user_apps.dedup();

    eprintln_safe!(
        "Limiting {} app(s) to {}",
        user_apps.len(),
        rates
            .download
            .map(crate::ebpf::limiter::format_rate)
            .unwrap_or_default()
    );

    if !skipped.is_empty() {
        eprintln_safe!(
            "Skipped {} system app(s) (use --force to include):",
            skipped.len()
        );
        for s in &skipped {
            eprintln_safe!("  - {s}");
        }
    }

    // Build targets list.
    let targets: Vec<Target> = user_apps
        .iter()
        .map(|n| Target::ProcessName(n.clone()))
        .collect();

    // Attach + pin BPF programs (fire-and-forget: pins survive process
    // exit, no daemon). Unconditional for the same schema-ladder parity
    // as handle_strict_multi (NIGHT-hunt-21).
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;

    print_pin_summary(&format!("{} apps", user_apps.len()), &rates, applied);

    // Validate final state: pins must still be present after apply (see
    // handle_strict_multi for the rationale).
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
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

    eprintln_safe!(
        "Limiting '{target_str}' to {} ({applied} policies, active in background)",
        parts.join(" + ")
    );
    eprintln_safe!("Run 'zelynic unstrict {target_str}' to remove, 'zelynic status' to check.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse-before-execute contract (live smoke-run find): a typo'd
    /// rate must surface its did-you-mean tip BEFORE the privilege
    /// guard, exactly like clap validates its own arguments before any
    /// handler runs. Previously ensure_root() ran first, so a non-root
    /// user was told to sudo before learning their rate string was
    /// wrong — a wasted privileged round-trip.
    ///
    /// Safe on any uid: the rate error returns before ensure_root(), so
    /// the test never reaches BPF attach even when run as root.
    #[cfg(feature = "ebpf")]
    #[test]
    fn rate_typo_surfaces_before_root_guard() {
        let err = handle_strict_single("bash", Some("1MB"), None, None, false, false, false)
            .expect_err("typo'd rate must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid rate '1MB'"),
            "rate error must lead, got: {msg}"
        );
        assert!(
            msg.contains("tip: a similar value exists: '1mb'"),
            "typo tip must ride along, got: {msg}"
        );
        assert!(
            !msg.contains("root required"),
            "rate error must precede the root guard, got: {msg}"
        );
    }

    /// Same contract for the dangerous-target blocklist: a policy
    /// refusal must surface before the privilege guard.
    #[cfg(feature = "ebpf")]
    #[test]
    fn dangerous_target_refusal_surfaces_before_root_guard() {
        let err = handle_strict_single("sshd", Some("1mb"), None, None, false, false, false)
            .expect_err("dangerous target must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("'sshd' is a system process"),
            "dangerous-target refusal must lead, got: {msg}"
        );
        assert!(
            !msg.contains("root required"),
            "policy refusal must precede the root guard, got: {msg}"
        );
    }
}
