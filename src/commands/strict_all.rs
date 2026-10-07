// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The strict-all handler (night-during's LOC-cap split of strict.rs:
//! the --during threading pushed the parent past the 500-line owner
//! cap, and the house split precedent moves HANDLERS out — this one
//! whole, its tests staying with the strict family's own).

use anyhow::Result;

#[cfg(feature = "ebpf")]
use crate::commands::rates::resolve_rates;
#[cfg(feature = "ebpf")]
use crate::commands::safety::is_dangerous_target;
// NIGHT-hunt-27: the sweep's saturation wording names the policy
// family's capacity — the userspace mirror of the eBPF-side map
// size (types.rs keeps it textually in sync with the pinned maps).
#[cfg(feature = "ebpf")]
use crate::ebpf::limiter::types::POLICY_MAP_CAPACITY as POLICY_CAP;

/// Handle `zelynic strict-all` — limit ALL user apps.
/// System/dangerous apps are excluded unless --force-this.
/// NIGHT-blade-2: renamed from limit-all (the strict family symmetry).
#[cfg(feature = "ebpf")]
// improve-40 (schema v24): the bracket pair joins the sweep's
// payload — the same too-many-arguments posture the strict
// handlers carry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_strict_all(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    bracket_flags: crate::commands::guarantee::BracketFlags<'_>,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::{parse_during, Limiter, Target};

    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as the other strict handlers.
    // NIGHT-improve-30: the unified --force-this override (rate bounds
    // + blocklist inclusion in one flag).
    let rates = resolve_rates(rate, download, upload, force_this)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-all 500kb"
        ));
    }

    // improve-40 (schema v24) / improve-40-b: the bracket joins
    // the sweep's parse-first ladder — one flag, every fleet row
    // carries it; the per-direction spellings ride the same struct.
    let bracket =
        crate::commands::guarantee::resolve_guarantee(bracket_flags, &rates, force_this, false)?;

    // night-during (schema v23): the sweep's own parse rung — the
    // fleet-wide window refuses before the identity walk.
    let during_spec = during.map(parse_during).transpose()?;

    super::ensure_root()?;

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    // Get all apps from identity map.
    let mut identity = IdentityMap::new();
    identity.refresh();

    let mut user_apps: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    // NIGHT-hunt-Z3: the root row is position-refused like a
    // blocklisted app — its policy is the machine-wide catch-all,
    // and the comm blocklist only catches it when kthreadd happens
    // to win root's majority vote (a daemon in the root on a
    // no-systemd guest names the row and sails the sweep in).
    let root_id = crate::commands::safety::cgroupfs_root_id();
    let mut includes_root = false;

    for app in identity.all() {
        if app.comm.is_empty() {
            continue;
        }
        if is_dangerous_target(&app.comm) || Some(app.cgroup_id) == root_id {
            includes_root |= Some(app.cgroup_id) == root_id;
            if force_this {
                user_apps.push(app.comm.clone());
            } else {
                skipped.push(app.comm.clone());
            }
        } else {
            user_apps.push(app.comm.clone());
        }
    }
    if force_this && includes_root {
        crate::output::eprintln_warn_labeled(
            "Including the root cgroup — its policy catches every socket on the machine.",
        );
    }

    // Deduplicate (multiple cgroups may have same comm).
    user_apps.sort();
    user_apps.dedup();
    // The pre-apply "Limiting N app(s) to X" echo is gone with
    // NIGHT-improve-28 (the request lives in the shell history; the
    // enforced facts live in 'zelynic status'). NIGHT-improve-30
    // collapses the skipped surface to ONE warn line — the count and
    // the flag that includes them: the old bulleted roster re-printed
    // the safety blocklist on every sweep (a server lists dozens of
    // system apps), while the names are one 'zelynic list-apps' away
    // for the rare case the count itself is the surprise.
    if !skipped.is_empty() {
        crate::output::eprintln_warn_labeled(&format!(
            "Skipped {} system app(s) — re-run with --force-this to include.",
            skipped.len()
        ));
    }

    if user_apps.is_empty() {
        // NIGHT-dinner-11: the no-match hard error, placed AFTER the
        // skip warning so an all-system box explains itself first —
        // the warn names the flag, the error names the verdict, and
        // a vacuous sweep (nothing enforced) is never a success.
        return Err(super::target_no_match_error(
            "No apps found to limit".to_string(),
            &[
                super::TIP_LIST_APPS.to_string(),
                "system apps need --force-this".to_string(),
            ],
        ));
    }

    // Build targets list.
    let targets: Vec<Target> = user_apps
        .iter()
        .map(|n| Target::ProcessName(n.clone()))
        .collect();

    // Attach + pin BPF programs (fire-and-forget: pins survive process
    // exit, no daemon). Unconditional for the same schema-ladder parity
    // as handle_strict_multi (NIGHT-hunt-21). The sweep keeps the
    // best-effort lane (NOT apply_group_atomic) on purpose:
    // the target list is a snapshot of list-apps, and an app that
    // exits between snapshot and write must not abort the fleet's
    // limits — the atomic contract belongs to the explicit colon
    // list, where every segment is the operator's own claim
    // (charger-core-2).
    // NIGHT-hunt-27: the sweep rides apply_group_sweep now — the
    // capacity-admitting twin. The old shape aborted the WHOLE
    // sweep at the policy family's 1024-row ceiling (leg 1025's
    // insert failure rolled back legs 1-1024): on a dense host —
    // the "host server padat" shape — strict-all refused
    // everything, every run, zero enforcement, contradicting the
    // best-effort contract two comments above. The twin admits
    // what fits (already-limited ids cost no new slot; fresh ids
    // up to the emptier map's free rows) and returns the skipped
    // count; the warn below names it, and the applied==0 error
    // paths keep the no-silent-no-op contract exact.
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let (applied, saturated) =
        limiter.apply_group_sweep(&targets, &rates, &bracket, during_spec.as_ref())?;

    if applied == 0 {
        // NIGHT-hunt-27: the vacuous-sweep ladder. Saturated>0 with
        // applied==0 means the policy family is FULL and the sweep
        // enforced nothing — never a success, never the generic
        // no-match wording either (the apps ARE there; the ROOM is
        // not). Saturated==0 means every snapshot member resolved
        // to nothing between the walk and the write (the stale
        // snapshot race) — the no-match contract strict-multi
        // owns, dinner-11.
        if saturated > 0 {
            return Err(super::target_no_match_error(
                format!(
                    "Policy family at capacity ({POLICY_CAP} rows) — 0 of {} app(s) \
                     limited, {saturated} left unlimited",
                    targets.len()
                ),
                &["run 'zelynic unstrict-all' to make room".to_string()],
            ));
        }
        return Err(super::target_no_match_error(
            "No cgroups found for any target — nothing was limited".to_string(),
            &[super::TIP_LIST_APPS.to_string()],
        ));
    }
    if saturated > 0 {
        // The partial-saturation warn (improve-30's one-line
        // concise contract): what landed, what did not, and the
        // one command that makes room.
        crate::output::eprintln_warn_labeled(&format!(
            "Policy ceiling saturated: {applied} app(s) limited, {saturated} left \
             unlimited — the policy family's {POLICY_CAP}-row capacity is full; \
             'zelynic unstrict-all' makes room."
        ));
    }

    // NIGHT-improve-28: strict-all reverses with the sledgehammer, not
    // a per-target unstrict — the old suggestion built
    // 'zelynic unstrict 3 apps', which is not a target at all.
    // NIGHT-dinner-16: the race-window check moved BEFORE the
    // success verdict (the multi form's own ordering fix).
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }
    super::apply_success_epilogue("zelynic unstrict-all", "remove");
    Ok(())
}
