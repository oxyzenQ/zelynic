// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Block command handlers — block apps from internet entirely.

use anyhow::Result;

use crate::ebpf::limiter::{Limiter, RateSpec, Target};

/// Block a single app from the internet.
pub fn handle_block_single(target_str: &str, force_this: bool, verbose: bool) -> Result<()> {
    // Input validation first (fail-fast, no privileges needed): the
    // dangerous-target blocklist is pure string matching — a policy
    // refusal surfaces before the root requirement, the same
    // parse-before-execute ladder as the strict handlers (smoke-run
    // find).
    super::safety::check_dangerous_target(target_str, force_this)?;

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

    // NIGHT-improve-28: the de-noised success surface — green OK. +
    // the round-tripping unstrict form (block reverses as unstrict,
    // the rates were zero either way).
    super::apply_success_epilogue(&format!("zelynic unstrict {target_str}"), "restore access");
    Ok(())
}

/// Block multiple apps from the internet.
pub fn handle_block_multi(targets_str: &str, force_this: bool, verbose: bool) -> Result<()> {
    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as the strict-multi handler.
    //
    // NIGHT-blade-18: the colon grammar (validate_multi_targets —
    // same refusals as strict-multi), and the danger loop runs on the
    // STRING tokens, not the parsed Targets: the old typed loop only
    // checked `Target::ProcessName` arms, so a numeric segment parsed
    // into `Target::CgroupId` and skipped the guard entirely — `bm
    // x:1` walked the same numeric blocklist bypass `ss 1` did. The
    // string loop closes it; check_dangerous_target's numeric path
    // resolves the id to its live members and runs the blocklist.
    let segments = super::safety::validate_multi_targets(
        targets_str,
        "zelynic block-multi brave:curl:pacman",
    )?;

    for t in &segments {
        super::safety::check_dangerous_target(t, force_this)?;
    }

    let targets: Vec<Target> = segments
        .iter()
        .map(|s| s.as_str())
        .map(Target::parse)
        .collect();

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

    // NIGHT-improve-28: the multi form suggests the multi unstrict —
    // the old '<target>' placeholder was advice the user had to
    // re-assemble by hand, and unstrict-single does not split colon
    // lists anyway.
    super::apply_success_epilogue(
        &format!("zelynic unstrict-multi {targets_str}"),
        "restore access",
    );
    Ok(())
}

/// Block ALL user apps from the internet.
pub fn handle_block_all(force_this: bool, verbose: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;

    super::ensure_root()?;

    let _lock = crate::ebpf::lock::acquire()?;

    let mut identity = IdentityMap::new();
    identity.refresh();

    // Same "system app" definition as strict-all: uid 0 OR on the
    // dangerous-target blocklist. The old filter (uid == 0 only) would
    // have blocked user-session processes like gnome-shell, pipewire,
    // and the display manager — a desktop-killer inconsistency with
    // strict-all's guard (NIGHT-blade-2: the limit-all name is gone
    // with the strict-family rename).
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

    if !force_this && !system_apps.is_empty() {
        // The pre-apply "Blocking N user app(s)" echo is gone with
        // NIGHT-improve-28 (the request lives in the shell history).
        // NIGHT-improve-30 collapses the skipped surface to ONE warn
        // line — the count and the flag that includes them; the old
        // bulleted roster (capped at 20) re-printed the safety
        // blocklist on every whole-system block, while the names are
        // one 'zelynic list-apps' away.
        crate::output::eprintln_warn_labeled(&format!(
            "Skipped {} system app(s) — re-run with --force-this to include.",
            system_apps.len()
        ));
    }

    let targets: Vec<Target> = if force_this {
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
    limiter.apply_group(&targets, &rates)?;
    // NIGHT-improve-28: the whole-system block reverses with the
    // sledgehammer — 'unstrict-all' (the epilogue carries the green
    // OK. verdict and the follow-up commands).
    super::apply_success_epilogue("zelynic unstrict-all", "restore access");
    Ok(())
}
