// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Block command handlers — block apps from internet entirely.

use anyhow::Result;

use crate::ebpf::limiter::{parse_during, BracketSpec, Limiter, RateSpec, Target};
// NIGHT-hunt-27: the block sweep's saturation wording names the
// policy family's capacity — the userspace mirror of the eBPF-side
// map size (types.rs keeps it textually in sync with the pinned
// maps).
use crate::ebpf::limiter::types::POLICY_MAP_CAPACITY as POLICY_CAP;

/// Block a single app from the internet.
/// `during` (night-during, schema v23; the owner's duration-only
/// revision): the block's own lifetime — a duration from the apply
/// instant; the block lifts itself, no daemon.
pub fn handle_block_single(
    target_str: &str,
    force_this: bool,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    // Input validation first (fail-fast, no privileges needed): the
    // dangerous-target blocklist is pure string matching — a policy
    // refusal surfaces before the root requirement, the same
    // parse-before-execute ladder as the strict handlers (smoke-run
    // find). NIGHT-dinner-16 adds the empty-target boundary at the
    // same rung: `bs ""` dies HERE, not after the root ask.
    super::safety::validate_single_target(target_str, "zelynic block-single brave")?;
    super::safety::check_dangerous_target(target_str, force_this)?;

    // night-during (schema v23): the window parses on the same
    // fail-fast rung (a typo'd grammar never burns the root ask).
    let during_spec = during.map(parse_during).transpose()?;

    super::ensure_root()?;

    // NIGHT-hunt-Z3: the resolved-position check — a block whose
    // target resolves to the cgroupfs root is machine-wide network
    // death (rate 0 caught by every socket's ancestor walk).
    super::safety::check_root_catch_all_resolved(
        std::slice::from_ref(&Target::parse(target_str)),
        force_this,
    )?;

    let _lock = crate::ebpf::lock::acquire()?;

    Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let target = Target::parse(target_str);

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    // per-socket is deliberately not offered on block-*: a rate-0
    // policy drops everything at the verdict layer, before any
    // bucket lane is consulted — a per-socket bit would be dead
    // weight on a total block (charger-core-3b's scope call).
    let applied = limiter.apply_single(
        &target,
        &rates,
        false,
        // improve-40 (schema v24): a rate-0 row never carries a
        // bracket — the block family's permanent unset (the
        // per-socket scope call's own reasoning, one lane over);
        // improve-40-b: the unset is the per-direction default.
        &BracketSpec::UNSET,
        during_spec.as_ref(),
    )?;
    if applied == 0 {
        // NIGHT-dinner-11: the no-match hard error (strict-single's
        // contract, the block family's wording). The hunt-10 colon
        // tip excludes the canonical cg: prefix — a miss on cg:<id>
        // is a dead id, not a list mistake.
        let mut tips = Vec::new();
        if target_str.contains(':') && !target_str.starts_with("cg:") {
            tips.push("colon-separated lists belong to block-multi".to_string());
        }
        tips.push(super::TIP_LIST_APPS.to_string());
        return Err(super::target_no_match_error(
            format!("No cgroup found for '{target_str}' — nothing was blocked"),
            &tips,
        ));
    }

    // NIGHT-dinner-16 (race-window parity with the strict family): a
    // concurrent unstrict-all can tear the pins down between apply
    // and the success verdict — the verdict is verified BEFORE it
    // prints, so a torn-down block never reads as enforced.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }

    // NIGHT-improve-28: the de-noised success surface — green OK. +
    // the round-tripping unstrict form (block reverses as unstrict,
    // the rates were zero either way).
    super::apply_success_epilogue(&format!("zelynic unstrict {target_str}"), "restore access");
    Ok(())
}

/// Block multiple apps from the internet.
pub fn handle_block_multi(
    targets_str: &str,
    force_this: bool,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
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
    // NIGHT-improve-50: the batched multi guard — one /proc walk for
    // every numeric segment in the list (the per-segment loop was
    // O(segments x processes)); wording and refusal order are
    // byte-identical to the loop it replaces.
    let segments = super::safety::validate_multi_targets(
        targets_str,
        "zelynic block-multi brave:curl:pacman",
    )?;

    super::safety::check_dangerous_targets_multi(&segments, force_this)?;

    let targets: Vec<Target> = segments
        .iter()
        .map(|s| s.as_str())
        .map(Target::parse)
        .collect();

    // night-during (schema v23): the window parses on the same
    // fail-fast rung — one input boundary, every refusal cheap.
    let during_spec = during.map(parse_during).transpose()?;

    super::ensure_root()?;

    // NIGHT-hunt-Z3: the resolved-position check (rate-0 catch-all).
    super::safety::check_root_catch_all_resolved(&targets, force_this)?;

    let _lock = crate::ebpf::lock::acquire()?;

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_group(
        &targets,
        &rates,
        // improve-40 (schema v24): the block family's permanent
        // unset — a bracket on a rate-0 row is dead weight;
        // improve-40-b: the unset is the per-direction default.
        &BracketSpec::UNSET,
        during_spec.as_ref(),
    )?;
    if applied == 0 {
        // NIGHT-dinner-11: the no-match hard error (block-single's
        // contract, the multi's plural wording).
        return Err(super::target_no_match_error(
            format!("No cgroups found for any target in '{targets_str}' — nothing was blocked"),
            &[super::TIP_LIST_APPS.to_string()],
        ));
    }

    // NIGHT-dinner-16 (race-window parity): verdict verified before
    // it prints — the strict family's own ordering.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
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
pub fn handle_block_all(force_this: bool, during: Option<&str>, verbose: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;

    // night-during (schema v23): the fleet-wide window refuses
    // before the identity walk (the strict-all handler's rung).
    let during_spec = during.map(crate::ebpf::limiter::parse_during).transpose()?;

    super::ensure_root()?;

    let _lock = crate::ebpf::lock::acquire()?;

    let mut identity = IdentityMap::new();
    identity.refresh();

    // Same "system app" definition as strict-all: uid 0 OR on the
    // dangerous-target blocklist. The old filter (uid == 0 only) would
    // have blocked user-session processes like gnome-shell, pipewire,
    // and the display manager — a desktop-killer inconsistency with
    // strict-all's guard (NIGHT-blade-2: the limit-all name is gone
    // with the strict-family rename). NIGHT-hunt-Z3 adds the root
    // POSITION to the system-app definition: the force branch below
    // once mapped EVERY identity row to its cgroup id, the root row
    // included — a rate-0 policy on the root is machine-wide network
    // death (every socket's ancestor walk resolves through it), so
    // the root row now rides the system roster however it is named.
    let root_id = super::safety::cgroupfs_root_id();
    let is_root_row = |e: &crate::ebpf::identity::ProcessIdentity| Some(e.cgroup_id) == root_id;
    let user_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| {
            !e.comm.is_empty()
                && e.uid > 0
                && !super::safety::is_dangerous_target(&e.comm)
                && !is_root_row(e)
        })
        .collect();

    let system_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| {
            !e.comm.is_empty()
                && (e.uid == 0 || super::safety::is_dangerous_target(&e.comm) || is_root_row(e))
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
    if force_this && system_apps.iter().any(|e| is_root_row(e)) {
        crate::output::eprintln_warn_labeled(
            "Including the root cgroup — its block kills every socket on the machine.",
        );
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
        // NIGHT-dinner-11: the no-match hard error — a vacuous sweep
        // blocked nothing, and the skip warning above already named
        // the flag when system apps were the reason.
        return Err(super::target_no_match_error(
            "No apps to block".to_string(),
            &[
                super::TIP_LIST_APPS.to_string(),
                "system apps need --force-this".to_string(),
            ],
        ));
    }

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    // NIGHT-hunt-27: the sweep rides apply_group_sweep — the
    // capacity-admitting twin (strict_all.rs's comment carries the
    // full rationale): the old shape aborted the WHOLE block-all at
    // the policy family's 1024-row ceiling, so a dense host could
    // never block anything at all. The twin admits what fits and
    // reports the rest; the applied==0 ladder below keeps the
    // no-silent-no-op contract exact (the old handler ignored the
    // apply count entirely — a fully-stale snapshot printed OK with
    // nothing blocked, the silent no-op the no-match contract
    // forbids).
    let (applied, saturated) = limiter.apply_group_sweep(
        &targets,
        &rates,
        // improve-40 (schema v24): the block family's permanent
        // unset — a bracket on a rate-0 row is dead weight;
        // improve-40-b: the unset is the per-direction default.
        &BracketSpec::UNSET,
        during_spec.as_ref(),
    )?;
    if applied == 0 {
        if saturated > 0 {
            return Err(super::target_no_match_error(
                format!(
                    "Policy family at capacity ({POLICY_CAP} rows) — 0 of {} app(s) \
                     blocked, {saturated} left with access",
                    targets.len()
                ),
                &["run 'zelynic unstrict-all' to make room".to_string()],
            ));
        }
        return Err(super::target_no_match_error(
            "No cgroups found for any target — nothing was blocked".to_string(),
            &[super::TIP_LIST_APPS.to_string()],
        ));
    }
    if saturated > 0 {
        crate::output::eprintln_warn_labeled(&format!(
            "Policy ceiling saturated: {applied} app(s) blocked, {saturated} left with \
             access — the policy family's {POLICY_CAP}-row capacity is full; \
             'zelynic unstrict-all' makes room."
        ));
    }

    // NIGHT-dinner-16 (race-window parity): verdict verified before
    // it prints.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }

    // NIGHT-improve-28: the whole-system block reverses with the
    // sledgehammer — 'unstrict-all' (the epilogue carries the green
    // OK. verdict and the follow-up commands).
    super::apply_success_epilogue("zelynic unstrict-all", "restore access");
    Ok(())
}
