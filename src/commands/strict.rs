// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Strict limiting handlers — the one `strict` verb's two lanes
//! (NIGHT-improve-53, the masterclass unification: the former
//! strict-single and strict-multi handlers are the single and group
//! lanes now, reached through the [`handle_strict`] router).
//! the --all sweep lane lives in strict_all.rs (night-during's LOC-cap split).

use anyhow::Result;

#[cfg(feature = "ebpf")]
use super::{probe, probe_report};
use crate::commands::rates::resolve_rates;
use crate::commands::safety::{
    check_dangerous_target, check_dangerous_targets_multi, check_root_catch_all_resolved,
    validate_single_target,
};
// NIGHT-improve-53: the list law rides its own module now (the
// masterclass split from safety.rs — target_grammar.rs carries the
// lineage).
use crate::commands::target_grammar::{target_is_list, validate_multi_targets};

/// NIGHT-improve-53 (the masterclass unification): the one `strict`
/// verb's router. The target grammar picks the lane — a '::'
/// anywhere means the group lane (one shared bucket for every
/// member), everything else is the single lane (the per-connection
/// --per-socket shape included). The lanes are the former
/// strict-single / strict-multi handlers, so every contract they
/// carry (the parse-before-execute ladder, the atomic group apply,
/// the probe window, the race guards) rides the merge unchanged.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_strict(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    no_test: bool,
    per_socket: bool,
    // improve-40-b: the six bracket flags ride one struct (the
    // per-direction spellings included — the resolver's own shape).
    bracket_flags: super::guarantee::BracketFlags<'_>,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    if target_is_list(target_str) {
        // The scope call rides FIRST, before any parsing — the
        // resolve_guarantee precedent one lane over: the combination
        // is refused whatever the values would have been, so a
        // typo'd rate never shadows the routing error. The group
        // lane's apply has one bucket per member-set, not the
        // per-connection multiplication --per-socket builds — the
        // shapes cannot stack.
        if per_socket {
            return Err(anyhow::anyhow!(
                "--per-socket is the single-target lane — a '::' list shares one group bucket across its members\n  \
                 tip: apply the member alone: zelynic s <member> <rate> --per-socket"
            ));
        }
        handle_strict_multi(
            target_str,
            rate,
            download,
            upload,
            force_this,
            no_test,
            bracket_flags,
            during,
            verbose,
        )
    } else {
        handle_strict_single(
            target_str,
            rate,
            download,
            upload,
            force_this,
            no_test,
            per_socket,
            bracket_flags,
            during,
            verbose,
        )
    }
}

#[cfg(feature = "ebpf")]
// charger-core-3b: the strict-single surface grew one flag
// (--per-socket); the arg list names the CLI contract one-to-one
// (the render family's own precedent for the same growth).
// night-during (schema v23): --during joins the list — the row's
// own lifetime, parsed before the privilege guard.
// NIGHT-improve-53: the single LANE of the one strict verb (the
// router above is the CLI contract; this fn is the machinery).
#[allow(clippy::too_many_arguments)]
fn handle_strict_single(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    no_test: bool,
    per_socket: bool,
    // improve-40-b: the six bracket flags ride one struct (the
    // per-direction spellings included — the resolver's own shape).
    bracket_flags: super::guarantee::BracketFlags<'_>,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{parse_during, Limiter, Target};

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
             Example: zelynic strict brave 100kb"
        ));
    }

    // improve-40 (schema v24) / improve-40-b (the per-direction
    // spellings): the guarantee bracket parses and validates on
    // the same fail-fast rung the rate family owns — the ladder's
    // own law (a contradictory bracket surfaces its wording before
    // the root ask, the parse-before-execute contract; the scope
    // call rides FIRST, before any parsing, because the
    // --per-socket combination is rejected whatever the values
    // would have been).
    let bracket =
        super::guarantee::resolve_guarantee(bracket_flags, &rates, force_this, per_socket)?;

    // night-during (schema v23): the window parses on the same
    // fail-fast rung the rate family owns — a typo'd grammar
    // surfaces its did-you-mean block BEFORE the root ask, the
    // parse-before-execute ladder (a bad --during never burns a
    // privileged round-trip).
    let during_spec = during.map(parse_during).transpose()?;

    // NIGHT-dinner-16: the single-target input boundary — an empty
    // target dies HERE, before the blocklist and the root ask, the
    // same ladder rung the rate check owns.
    validate_single_target(target_str, "zelynic strict brave 100kb")?;

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
            // improve-40-b: the per-direction bracket, written on
            // each direction's own rows.
            &bracket,
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
            // — the grammar tip beats the list tip there.
            if target_str.contains("://") {
                tips.push(
                    "container target grammar: docker://<name> or k8s://<namespace>/<pod>"
                        .to_string(),
                );
            } else if target_str.contains(':') && !target_str.starts_with("cg:") {
                // NIGHT-improve-53: the single ':' is the prefix
                // grammar's byte — the tip teaches the list law the
                // '::' separator carries now.
                tips.push(
                    "list members separate with '::' (single ':' is the cg: prefix and container grammar)"
                        .to_string(),
                );
            }
            tips.push(super::TIP_LIST_APPS.to_string());
            return Err(super::target_no_match_error(
                format!("No cgroup found for '{target_str}' — nothing was limited"),
                &tips,
            ));
        }

        // NIGHT-dinner-16 (race-window parity with strict-multi/all): a
        // concurrent u --all can tear the pins down between apply
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
    // above already owns). --no-test keeps the scripted apply-only
    // shape; UNVERIFIED prints with the epilogue and never fails the
    // apply — the measurement lane, not the enforcement, was weak.
    let probe_outcome = if no_test {
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
// improve-40 (schema v24): the bracket pair joins the multi's
// payload — the same too-many-arguments posture the single's own
// handler carries one lane over. NIGHT-hunt-30: no_test joins it
// too — the multi now carries the single's verification lane.
// NIGHT-improve-53: the group LANE of the one strict verb.
#[allow(clippy::too_many_arguments)]
fn handle_strict_multi(
    targets_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
    no_test: bool,
    bracket_flags: super::guarantee::BracketFlags<'_>,
    during: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{parse_during, Limiter, Target};

    // Input validation first (fail-fast, no privileges needed) — same
    // parse-before-execute ladder as handle_strict_single. NIGHT-improve-30:
    // the unified --force-this override (rate bounds + blocklist).
    let rates = resolve_rates(rate, download, upload, force_this)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict brave::curl 1mb"
        ));
    }

    // improve-40 (schema v24) / improve-40-b: the bracket joins
    // the multi's parse-first ladder — one flag, every member row
    // carries it (the group's own contract, the --during shape);
    // the per-direction spellings ride the same struct.
    let bracket = super::guarantee::resolve_guarantee(bracket_flags, &rates, force_this, false)?;

    // night-during (schema v23): the same parse-first ladder, the
    // multi's own rung placement (after the rate family, before the
    // target grammar — one input boundary, every refusal cheap).
    let during_spec = during.map(parse_during).transpose()?;

    // NIGHT-blade-18: the list is a grammar now, not a best-effort
    // scan — validate_multi_targets refuses the shapes that can only be
    // mistakes (empty members hid a dropped app; '/' or punctuation-only
    // members can never be a comm), and the danger loop runs on the
    // validated members, so a numeric or cg:<id> member reaches the
    // cgroup-id guard through check_dangerous_target's numeric path
    // (the numeric blocklist bypass, closed the same task).
    // NIGHT-hunt-30: the grammar's list rung refuses the
    // one-target list — "single is single, multi is multi" (read
    // through improve-53: one target needs no separator).
    // NIGHT-improve-53: the '::' grammar — the separator doubled
    // when the verbs merged.
    let segments = validate_multi_targets(targets_str, "zelynic strict brave::curl::pacman 1mb")?;

    // Check each target for dangerous names. NIGHT-improve-50: the
    // batched multi guard — one /proc walk for every numeric segment
    // in the list (the per-segment loop was O(segments x processes);
    // a fleet-scale apply walked /proc thousands of times before the
    // policy write ever ran). Wording and refusal order are
    // byte-identical to the loop it replaces.
    check_dangerous_targets_multi(&segments, force_this)?;

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
    //
    // NIGHT-hunt-30: the lock's scope is the APPLY, not the probe —
    // the single lane's own dinner-28 contract, one lane over. The
    // probe mutates no policy state (it reads the maps it was handed
    // and spawns its own transient cgroups), so the lock drops
    // before the window opens and a concurrent unstrict stays
    // observable as the measurement's own FAILED verdict.
    let mut limiter;
    {
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

        limiter = Limiter::open_pinned(verbose)?;
        // NIGHT-upgrade-charger-core-2 (TIER A #6): the atomic apply —
        // every segment resolves BEFORE the first map write (one miss
        // aborts the whole invocation with nothing limited), and a
        // mid-flight failure restores each mutated policy to its
        // pre-apply state. The old best-effort shape skipped unresolved
        // names silently and reported OK on a half-limited list — the
        // exact trap for scripted fleet automation, which now sees the
        // transaction fail whole or land whole. night-during (schema
        // v23): the window rides the same atomic contract.
        let applied =
            limiter.apply_group_atomic(&targets, &rates, &bracket, during_spec.as_ref())?;
        if applied == 0 {
            // NIGHT-dinner-11: the no-match hard error (the single lane's
            // contract, the multi's plural wording).
            return Err(super::target_no_match_error(
                format!("No cgroups found for any target in '{targets_str}' — nothing was limited"),
                &[super::TIP_LIST_APPS.to_string()],
            ));
        }

        // NIGHT-dinner-16: the race-window check — the verdict is
        // verified BEFORE it prints, so a torn-down limit never reads
        // as enforced.
        if !crate::ebpf::limiter::Limiter::is_pinned() {
            return Err(anyhow::anyhow!(
                "BPF pins missing after apply — a concurrent operation may have interfered\n  \
                 tip: run 'zelynic recover' to repair state"
            ));
        }
    } // the lock drops here: the probe below runs unserialized

    // NIGHT-hunt-30 (the owner's parity find — "need verify for
    // multi and all strict mode"): the multi carries the single's
    // self-proving enforcement now. "applied" is a claim, "VERIFIED"
    // is a measurement: the probe generates a real flow through the
    // FIRST member's subtree and measures what the kernel let
    // through — the atomic contract guarantees that member landed
    // (one miss aborts the whole list), so the measurement reads the
    // group's fresh bucket, and the report's own multi-leaf note
    // names the ledger the group spans. --no-test keeps the
    // scripted apply-only shape; a blocked (rate-0) member stands
    // down on the drop-ledger note, exactly like the single's.
    let probe_outcome = if no_test {
        None
    } else {
        Some(probe::run_enforcement_probe(
            &limiter,
            &targets[0],
            &rates,
            false,
        ))
    };
    // NIGHT-repair-1 ordering (the single's own law): a FAILED probe
    // is the louder, more specific truth — its block names the
    // enforcement failure with the measured numbers attached, while
    // the pin guard below names only a class.
    if let Some(outcome) = &probe_outcome {
        if outcome.verdict == probe_report::ProbeVerdict::Failed {
            return Err(probe_report::failure_error(&segments[0], outcome));
        }
    }
    // The dinner-16 parity at the probe boundary: pins torn down
    // DURING the window are caught here, before any success surface
    // prints (VERIFIED and UNVERIFIED alike).
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        return Err(anyhow::anyhow!(
            "BPF pins missing after the probe — a concurrent operation may have interfered\n  \
             tip: run 'zelynic recover' to repair state"
        ));
    }

    // NIGHT-improve-28: the list form suggests the list unstrict —
    // 'zelynic unstrict brave::curl' does not split lists without
    // the '::' separator (the old suggestion was advice that could
    // not round-trip).
    super::apply_success_epilogue(&format!("zelynic unstrict {targets_str}"), "remove");
    if let Some(outcome) = &probe_outcome {
        for line in probe_report::report_lines(outcome) {
            eprintln_safe!("{line}");
        }
    }
    Ok(())
}

// The strict pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired across trees exactly like the safety
// battery — moved out of the inline module at the improve-53
// masterclass split (the router pushed the file against the
// 600-line cap, the same pressure that moved types_tests out of
// types.rs at charger-core-3b).
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/commands/strict_tests.rs"]
mod tests;
