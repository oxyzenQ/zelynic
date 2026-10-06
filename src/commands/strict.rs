// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Strict limiting handlers — strict-single, strict-multi, strict-all.

use anyhow::Result;

#[cfg(feature = "ebpf")]
use super::{probe, probe_report};
use crate::commands::rates::resolve_rates;
use crate::commands::safety::{
    check_dangerous_target, check_root_catch_all_resolved, validate_multi_targets,
    validate_single_target,
};

#[cfg(feature = "ebpf")]
// charger-core-3b: the strict-single surface grew one flag
// (--per-socket); the arg list names the CLI contract one-to-one
// (the render family's own precedent for the same growth).
// night-during (schema v23): --during joins the list — the row's
// own lifetime, parsed before the privilege guard.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_strict_single(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    no_probe: bool,
    per_socket: bool,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{parse_during, wall_now_ns, Limiter, Target};

    // Input validation first (fail-fast, no privileges needed): rate
    // strings and the dangerous-target blocklist are pure parsing, so
    // a typo surfaces its did-you-mean tip before the root requirement
    // — the same parse-before-execute contract clap applies to its own
    // arguments (live root-machine smoke-run find).
    //
    // NIGHT-improve-30: ONE flag carries both overrides — the former
    // `--allow-dangerous` (rate bounds) and `--force` (blocklist) are
    // the same "I know, force this" decision, so they parse as one.
    let rates = resolve_rates(rate, download, upload, force_this)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-single brave 100kb"
        ));
    }

    // night-during (schema v23): the window parses on the same
    // fail-fast rung the rate family owns — a typo'd grammar
    // surfaces its did-you-mean block BEFORE the root ask, the
    // parse-before-execute ladder (a bad --during never burns a
    // privileged round-trip).
    let during_spec = during
        .map(|spec| parse_during(spec, wall_now_ns()))
        .transpose()?;

    // NIGHT-dinner-16: the single-target input boundary — an empty
    // target dies HERE, before the blocklist and the root ask, the
    // same ladder rung the rate check owns.
    validate_single_target(target_str, "zelynic strict-single brave 100kb")?;

    check_dangerous_target(target_str, force_this)?;

    super::ensure_root()?;

    // NIGHT-hunt-Z3: the resolved-position check (post-privilege,
    // after the parse: a target that resolves to the cgroupfs root
    // is a machine-wide catch-all, whatever spelling reached it).
    check_root_catch_all_resolved(std::slice::from_ref(&Target::parse(target_str)), force_this)?;

    // Prevent concurrent operations (race condition elimination).
    //
    // dinner-28: the lock's scope is the APPLY, not the probe. The
    // lock serializes every policy mutation and pin teardown, and
    // holding it through the probe made the whole verification window
    // atomic against the world — a concurrent unstrict could never
    // land mid-window (the lock is non-blocking, so the concurrent
    // command ERRORED with lock-held instead), which put the
    // checklist's own scenario ("someone unstricts the target while
    // the verification runs") structurally out of reach. The probe
    // mutates no policy state — it reads the maps it was handed and
    // spawns its own transient cgroups — so the lock drops before
    // the window opens and the mid-window teardown becomes
    // observable: the MEASUREMENT is the defense (a policy that
    // vanishes mid-window reads FAILED by its own numbers), and the
    // is_pinned re-check after the probe (the dinner-16 parity, moved
    // to the new boundary) keeps the success verdict honest against
    // a torn-down pin state.
    let target = Target::parse(target_str);
    let mut limiter;
    {
        let _lock = crate::ebpf::lock::acquire()?;

        // Attach BPF programs (pins to /sys/fs/bpf/zelynic/ — survives exit).
        crate::ebpf::limiter::Limiter::attach(verbose)?;

        // Open pinned maps and write policy.
        limiter = Limiter::open_pinned(verbose)?;
        let applied = limiter.apply_single(
            &target,
            &rates,
            per_socket,
            // improve-40 (schema v24): the bracket lands with the
            // CLI lane — the plumbing pass threads zeroes so this
            // commit stays behavior-neutral.
            0,
            0,
            during_spec.as_ref(),
        )?;
        if applied == 0 {
            // NIGHT-dinner-11: the no-match hard error — branded red
            // block + exit 1 (see commands::target_no_match_error), so
            // a typo'd target can never read as calm success. The
            // hunt-10 colon tip rides as a white tip line — now EXCLUDING
            // the canonical cg: prefix: a miss on cg:<id> is a dead id,
            // not a list mistake, and the routing tip would be noise
            // there (the owner's honesty pass).
            let mut tips = Vec::new();
            // charger-core-2: a '://'-shaped target that fell through to
            // the no-match path is a malformed container URI (a
            // well-formed one surfaces resolve's specific error instead)
            // — the grammar tip beats the colon-list tip there.
            if target_str.contains("://") {
                tips.push(
                    "container target grammar: docker://<name> or k8s://<namespace>/<pod>"
                        .to_string(),
                );
            } else if target_str.contains(':') && !target_str.starts_with("cg:") {
                tips.push("colon-separated lists belong to strict-multi".to_string());
            }
            tips.push(super::TIP_LIST_APPS.to_string());
            return Err(super::target_no_match_error(
                format!("No cgroup found for '{target_str}' — nothing was limited"),
                &tips,
            ));
        }

        // NIGHT-dinner-16 (race-window parity with strict-multi/all): a
        // concurrent unstrict-all can tear the pins down between apply
        // and the success verdict — the verdict is verified BEFORE it
        // prints, so a torn-down limit never reads as enforced.
        if !crate::ebpf::limiter::Limiter::is_pinned() {
            return Err(anyhow::anyhow!(
                "BPF pins missing after apply — a concurrent operation may have interfered\n  \
                 tip: run 'zelynic recover' to repair state"
            ));
        }
    } // the lock drops here: the probe below runs unserialized

    // NIGHT-upgrade-charger-core-1-b (the self-proving enforcement):
    // "applied" is a claim, "VERIFIED" is a measurement. The probe
    // generates a real flow through the subtree the policy just
    // covered and measures what the kernel let through — BEFORE the
    // success verdict prints (a FAILED probe must never read as OK;
    // the never-print-then-fail discipline the race-window check
    // above already owns). --no-probe keeps the scripted apply-only
    // shape; UNVERIFIED prints with the epilogue and never fails the
    // apply — the measurement lane, not the enforcement, was weak.
    let probe_outcome = if no_probe {
        None
    } else {
        Some(probe::run_enforcement_probe(
            &limiter, &target, &rates, per_socket,
        ))
    };
    // The measurement's own failure verdict reports FIRST
    // (NIGHT-repair-1 ordering): a FAILED probe is the louder, more
    // specific truth — its block names the enforcement failure with
    // the measured numbers attached, while the pin guard below names
    // only a class (a concurrent teardown — exactly the event the
    // FAILED measurement just caught). The old order swallowed the
    // probe's failure report behind the pin guard on the mid-window
    // unstrict lane: exit stayed 1 but the failure block's needles
    // never printed, and the supermassive FAILED row could only
    // name the missing shape.
    if let Some(outcome) = &probe_outcome {
        if outcome.verdict == probe_report::ProbeVerdict::Failed {
            return Err(probe_report::failure_error(target_str, outcome));
        }
    }
    // The dinner-16 parity at the NEW boundary: pins torn down DURING
    // the window are caught here, before any success surface prints —
    // the verdict never reads over a state that no longer exists
    // (VERIFIED and UNVERIFIED alike; the FAILED shape above already
    // returned its own, more specific error).
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after the probe — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }

    // NIGHT-improve-28: the de-noised success surface — green OK. +
    // the round-tripping unstrict form (the owner's pro contract; the
    // old two-line request-echo restatement lives in the history).
    super::apply_success_epilogue(&format!("zelynic unstrict {target_str}"), "remove");
    if let Some(outcome) = &probe_outcome {
        for line in probe_report::report_lines(outcome) {
            eprintln_safe!("{line}");
        }
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
pub(crate) fn handle_strict_multi(
    targets_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{parse_during, wall_now_ns, Limiter, Target};

    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as handle_strict_single. NIGHT-improve-30:
    // the unified --force-this override (rate bounds + blocklist).
    let rates = resolve_rates(rate, download, upload, force_this)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-multi brave:curl 1mb"
        ));
    }

    // night-during (schema v23): the same parse-first ladder, the
    // multi's own rung placement (after the rate family, before the
    // target grammar — one input boundary, every refusal cheap).
    let during_spec = during
        .map(|spec| parse_during(spec, wall_now_ns()))
        .transpose()?;

    // NIGHT-blade-18: the colon list is a grammar now, not a best-effort
    // scan — validate_multi_targets refuses the shapes that can only be
    // mistakes (empty segments hid a dropped app; '/' or punctuation-only
    // segments can never be a comm), and the danger loop runs on the
    // validated segments, so a numeric or cg:<id> segment reaches the
    // cgroup-id guard through check_dangerous_target's numeric path
    // (the numeric blocklist bypass, closed the same task).
    let segments =
        validate_multi_targets(targets_str, "zelynic strict-multi brave:curl:pacman 1mb")?;

    // Check each target for dangerous names.
    for t in &segments {
        check_dangerous_target(t, force_this)?;
    }

    let targets: Vec<Target> = segments
        .iter()
        .map(|s| s.as_str())
        .map(Target::parse)
        .collect();

    super::ensure_root()?;

    // NIGHT-hunt-Z3: the resolved-position check (post-privilege:
    // any segment resolving to the cgroupfs root is the catch-all).
    check_root_catch_all_resolved(&targets, force_this)?;

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
    // NIGHT-upgrade-charger-core-2 (TIER A #6): the atomic apply —
    // every segment resolves BEFORE the first map write (one miss
    // aborts the whole invocation with nothing limited), and a
    // mid-flight failure restores each mutated policy to its
    // pre-apply state. The old best-effort shape skipped unresolved
    // names silently and reported OK on a half-limited list — the
    // exact trap for scripted fleet automation, which now sees the
    // transaction fail whole or land whole. night-during (schema
    // v23): the window rides the same atomic contract.
    let applied = limiter.apply_group_atomic(
        &targets,
        &rates,
        // improve-40 (schema v24): the CLI lane's zeroes, the
        // plumbing pass's behavior-neutral shape.
        0,
        0,
        during_spec.as_ref(),
    )?;
    if applied == 0 {
        // NIGHT-dinner-11: the no-match hard error (strict-single's
        // contract, the multi's plural wording).
        return Err(super::target_no_match_error(
            format!("No cgroups found for any target in '{targets_str}' — nothing was limited"),
            &[super::TIP_LIST_APPS.to_string()],
        ));
    }

    // NIGHT-improve-28: the multi form suggests the multi unstrict —
    // 'zelynic unstrict brave:curl' does not split colon lists (the
    // old suggestion was advice that could not round-trip).
    // NIGHT-dinner-16: the race-window check moved BEFORE the
    // success verdict — printing "OK." and then erroring on the
    // torn-down state said both things at once.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after apply — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }
    super::apply_success_epilogue(&format!("zelynic unstrict-multi {targets_str}"), "remove");
    Ok(())
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
        let err = handle_strict_single(
            "bash",
            Some("1MB"),
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        )
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
        let err = handle_strict_single(
            "sshd",
            Some("1mb"),
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        )
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

    /// NIGHT-dinner-16: an empty target dies at the input boundary —
    /// before the blocklist and the privilege guard — instead of
    /// flowing to the root ask as `Target::parse("")`'s invisible
    /// `ProcessName("")` (the parse-before-execute ladder's missing
    /// rung, closed by the verifier-lineage mandate).
    #[cfg(feature = "ebpf")]
    #[test]
    fn empty_target_surfaces_before_root_guard() {
        let err = handle_strict_single(
            "",
            Some("1mb"),
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        )
        .expect_err("an empty target must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("target is empty"),
            "the empty-target verdict must lead, got: {msg}"
        );
        assert!(
            msg.contains("zelynic strict-single brave 100kb"),
            "the refusal must carry the example command, got: {msg}"
        );
        assert!(
            !msg.contains("root required"),
            "the input error must precede the root guard, got: {msg}"
        );
    }
}
