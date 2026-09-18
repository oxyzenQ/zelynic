// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Block command handlers — block apps from internet entirely.

use anyhow::Result;

use crate::ebpf::limiter::{Limiter, RateSpec, Target};

/// Block a single app from the internet.
pub fn handle_block_single(target_str: &str, force: bool, verbose: bool) -> Result<()> {
    // Input validation first (fail-fast, no privileges needed): the
    // dangerous-target blocklist is pure string matching — a policy
    // refusal surfaces before the root requirement, the same
    // parse-before-execute ladder as the strict handlers (smoke-run
    // find).
    super::safety::check_dangerous_target(target_str, force)?;

    super::ensure_root()?;

    let _lock = crate::ebpf::lock::acquire()?;

    Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let target = Target::parse(target_str);

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln_safe!("No cgroup found for '{target_str}'. Nothing to block.");
        // Same routing tip as strict-single (NIGHT-hunt-10): colon
        // lists belong to the multi form.
        if target_str.contains(':') {
            eprintln_safe!("tip: colon-separated lists belong to block-multi");
        }
        return Ok(());
    }

    eprintln_safe!(
        "Blocked '{target_str}' from internet ({applied} policies, active in background)"
    );
    eprintln_safe!(
        "Run 'zelynic unstrict {target_str}' to restore access, 'zelynic status' to check."
    );
    Ok(())
}

/// Block multiple apps from the internet.
pub fn handle_block_multi(targets_str: &str, force: bool, verbose: bool) -> Result<()> {
    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as the strict-multi handler.
    //
    // Same parsing contract as strict-multi: trim each part, drop
    // empties, and fail with an example instead of silently limiting
    // an empty-name cgroup.
    let targets: Vec<Target> = targets_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(Target::parse)
        .collect();
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "No targets specified. Use colon-separated list.\n\
             Example: zelynic block-multi brave:curl:pacman"
        ));
    }
    for t in &targets {
        if let Target::ProcessName(name) = t {
            super::safety::check_dangerous_target(name, force)?;
        }
    }

    super::ensure_root()?;

    let _lock = crate::ebpf::lock::acquire()?;

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln_safe!("No cgroups found for '{targets_str}'. Nothing to block.");
        return Ok(());
    }

    eprintln_safe!(
        "Blocked '{targets_str}' from internet ({applied} policies, active in background)"
    );
    eprintln_safe!("Run 'zelynic unstrict <target>' to restore access.");
    Ok(())
}

/// Block ALL user apps from the internet.
pub fn handle_block_all(force: bool, verbose: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;

    super::ensure_root()?;

    let _lock = crate::ebpf::lock::acquire()?;

    let mut identity = IdentityMap::new();
    identity.refresh();

    // Same "system app" definition as limit-all: uid 0 OR on the
    // dangerous-target blocklist. The old filter (uid == 0 only) would
    // have blocked user-session processes like gnome-shell, pipewire,
    // and the display manager — a desktop-killer inconsistency with
    // limit-all's guard.
    let user_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| !e.comm.is_empty() && e.uid > 0 && !super::safety::is_dangerous_target(&e.comm))
        .collect();

    let system_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| {
            !e.comm.is_empty() && (e.uid == 0 || super::safety::is_dangerous_target(&e.comm))
        })
        .collect();

    if !force && !system_apps.is_empty() {
        eprintln_safe!("Blocking {} user app(s)", user_apps.len());
        eprintln_safe!(
            "Skipped {} system app(s) (use --force to include):",
            system_apps.len()
        );
        for app in system_apps.iter().take(20) {
            eprintln_safe!("  - {}", app.comm);
        }
    }

    let targets: Vec<Target> = if force {
        identity
            .all()
            .into_iter()
            .filter(|e| !e.comm.is_empty())
            .map(|e| Target::CgroupId(e.cgroup_id))
            .collect()
    } else {
        user_apps
            .iter()
            .map(|e| Target::CgroupId(e.cgroup_id))
            .collect()
    };

    if targets.is_empty() {
        eprintln_safe!("No apps to block.");
        return Ok(());
    }

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_group(&targets, &rates)?;
    eprintln_safe!(
        "Blocked {} app(s) from internet ({applied} policies, active in background)",
        targets.len()
    );
    eprintln_safe!("Run 'zelynic unstrict-all' to restore all access.");
    Ok(())
}
