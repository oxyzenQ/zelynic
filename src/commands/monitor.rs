// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Monitor command handlers — status, list-apps, eagle-eyes.

use crate::output::print_json;
use anyhow::Result;

/// Handle `zelynic status` — show active limits + watchdog.
#[cfg(feature = "ebpf")]
pub fn handle_status(verbose: bool, json: bool) -> Result<()> {
    use crate::ebpf::limiter::{pin_dir_has_files, Limiter};

    super::ensure_root()?;

    if !pin_dir_has_files() {
        if json {
            print_json(&serde_json::json!({
                "watchdog": "clean", "active_limits": 0, "limits": []
            }));
        } else {
            println_safe!("No active limits.");
        }
        return Ok(());
    }

    if !Limiter::is_pinned() {
        if json {
            print_json(&serde_json::json!({
                "error": "stale pins detected", "hint": "run 'zelynic recover'"
            }));
        } else {
            println_safe!("Stale BPF pin files detected (partial enforcement state).");
            println_safe!("Run 'zelynic recover' to clean up, then re-apply limits.");
        }
        return Ok(());
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    limiter.refresh_identity();
    if json {
        limiter.print_status_json()?;
    } else {
        // NIGHT-hunt-22: a failed map read surfaces as a non-zero
        // exit — never rendered as "Active limits: none".
        limiter.print_status()?;
    }
    Ok(())
}

/// Handle `zelynic list-apps` — list apps with cgroup IDs.
///
/// NIGHT-hunt-8: the listing carries the cgroup's process and socket
/// counts, because a row named "alacritty" that actually hosts curl,
/// wget and ssh is exactly the discovery-stage lie the owner hit.
#[cfg(feature = "ebpf")]
pub fn handle_list_apps(json: bool) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::identity::IdentityMap;
    use crate::output::brand_bold;

    let mut identity = IdentityMap::new();
    let count = identity.refresh();

    // One /proc walk feeds both maps: identities + socket detail.
    let mut conns = ConnectionMap::new();
    let socket_cgroups = conns.refresh();

    let mut entries: Vec<_> = identity.all().into_iter().collect();
    entries.sort_by(|a, b| a.comm.cmp(&b.comm));
    entries.retain(|e| !e.comm.is_empty());

    if json {
        // NIGHT-boost-3: typed structs serialize field-by-field straight
        // through the unified print_json writer — no serde_json::Value
        // tree (one allocation per node) for the biggest document the
        // CLI emits. Field names and order are the pinned scripting
        // contract (docs/USAGE.md JSON reference).
        let apps: Vec<AppEntryJson> = entries
            .iter()
            .map(|e| AppEntryJson {
                process: e.comm.clone(),
                cgroup_id: e.cgroup_id,
                uid: e.uid,
                processes: conns.proc_count(e.cgroup_id),
                sockets: conns.socket_count(e.cgroup_id),
            })
            .collect();
        print_json(&ListAppsJson { total: count, apps });
        return Ok(());
    }

    println_safe!("{}", brand_bold("━━━ Apps with cgroup IDs ━━━"));
    println_safe!(
        "  {} cgroups resolved, {} with live sockets\n",
        count,
        socket_cgroups
    );
    // Column widths shared by header, rows, and separator — one
    // table, one width source (improve-13: the separator was a
    // hardcoded 70 while the columns sum to 69 — the rule line
    // overhung the table by one).
    let widths = [30usize, 7, 8, 10, 8];
    let table_w: usize = 2 + widths.iter().sum::<usize>() + (widths.len() - 1);
    println_safe!(
        "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        "PROCESS",
        "PROCS",
        "SOCKETS",
        "CGROUP ID",
        "UID",
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4]
    );
    println_safe!("  {}", "─".repeat(table_w - 2));

    for id in entries {
        println_safe!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
            id.comm,
            conns.proc_count(id.cgroup_id),
            conns.socket_count(id.cgroup_id),
            format!("cg:{}", id.cgroup_id),
            id.uid,
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4]
        );
    }

    Ok(())
}

/// Handle `zelynic eagle-eyes` — the unified live monitor
/// (NIGHT-boost-1: observe + top merged into one surface).
///
/// Always live (NIGHT-hunt-12): the box refreshes until the user
/// quits (q is the only quit key, NIGHT-hunt-16). `interval`
/// (NIGHT-hunt-7) is the refresh cadence, 1s..60s via
/// `--interval` (default 1s — realtime precision); it drives both
/// the render loop AND the BPF poll, so per-frame deltas divide by
/// exactly the interval for the RATE column.
///
/// The positional TARGETS spec is autodetected per Target::parse
/// (digits = cgroup ID, else process name) and re-resolved against
/// the live identity map every frame, so apps started mid-session
/// appear on the next refresh. One token resolving to one cgroup
/// takes the deep focus view; more take the filtered ranked table;
/// none take the full consumption-ranked ranking with a row budget
/// equal to the terminal height (no --limit, no cap).
#[cfg(feature = "ebpf")]
pub fn handle_eagle_eyes(
    targets: Option<&str>,
    interval: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::limiter::Target;
    use crate::ebpf::loader::Observer;
    use crate::ebpf::render::render_eagle_eyes;
    use crate::terminal;
    use std::time::Duration;

    // Input validation first (fail-fast, no privileges needed): the
    // refresh-interval string and the target spec are pure parsing —
    // a typo surfaces its did-you-mean tip before the root
    // requirement, the same parse-before-execute ladder as the
    // strict handlers (smoke-run find).
    let interval_secs = match interval {
        Some(s) => crate::ebpf::limiter::parse_monitor_interval(s)?,
        None => 1,
    };
    let tokens: Vec<Target> = match targets {
        Some(spec) => {
            let tokens: Vec<Target> = spec
                .split('/')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(Target::parse)
                .collect();
            if tokens.is_empty() {
                anyhow::bail!(
                    "No targets in '{spec}' — pass process names or cgroup IDs \
                     separated by '/' (e.g., 'zelynic eagle-eyes brave/firefox')"
                );
            }
            tokens
        }
        None => Vec::new(),
    };

    super::ensure_root()?;

    // quiet only when NOT verbose (NIGHT-hunt-9): -v surfaces the
    // observer loader trace (object path, attach) on stderr before
    // the alt screen takes over — the same diagnostic depth the
    // limiter lifecycle gives strict/block handlers.
    let mut observer = Observer::attach_quiet(!verbose)?;
    observer.refresh_identity();
    if verbose {
        eprintln_safe!("[ebpf] {} cgroups resolved", observer.identity().len());
    }

    let _ = observer.poll_and_summarize()?;

    // Eagle-eyes detail (NIGHT-hunt-8): per-cgroup process/socket
    // detail, TTL-cached inside the map so 1s frames reuse the scan.
    // NIGHT-improve-2: the closure builds the frame's logical lines;
    // run_alt's diff engine emits only what changed.
    let mut conns = ConnectionMap::new();
    let interval = Duration::from_secs(interval_secs);
    terminal::run_alt(interval, |lines| {
        // One-frame tolerance, not a swallow bug (NIGHT-optimized-2
        // audit): the opening poll below hard-failed on any broken
        // map, so an Err here is a transient read. unwrap_or_default
        // renders one blank frame; prev_stats inside the observer is
        // only rewritten on success, so the next good frame's delta
        // spans the skipped interval — no data loss, no double count.
        // Propagating here instead would kill the live TUI on a
        // single hiccup.
        let summary = observer.poll_and_summarize().unwrap_or_default();
        conns.maybe_refresh();
        render_eagle_eyes(
            lines,
            &summary,
            &tokens,
            observer.identity(),
            Some(&conns),
            interval,
        );
    });

    observer.detach();
    Ok(())
}

// ── list-apps JSON document (NIGHT-boost-3) ─────────────────────────────────
//
// Typed serializers for the `list-apps --print-json` contract — the
// same pattern display.rs uses for StatusJson/LimitEntry. Field names
// and declaration order are the pinned scripting API (docs/USAGE.md
// JSON reference); serialization rides the unified
// [`crate::output::print_json`] writer.

/// One `apps[]` row of the `list-apps --print-json` document.
#[cfg(feature = "ebpf")]
#[derive(serde::Serialize)]
struct AppEntryJson {
    process: String,
    cgroup_id: u32,
    uid: u32,
    processes: usize,
    sockets: usize,
}

/// The `list-apps --print-json` document: `{"total": N, "apps": []}`.
#[cfg(feature = "ebpf")]
#[derive(serde::Serialize)]
struct ListAppsJson {
    total: usize,
    apps: Vec<AppEntryJson>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse-before-execute contract (live smoke-run find): a typo'd
    /// refresh-interval string must surface its did-you-mean tip BEFORE
    /// the privilege guard, matching the strict handlers' ladder and
    /// clap's own argument validation order.
    ///
    /// Safe on any uid: the interval error returns before ensure_root(),
    /// so the test never reaches observer attach even as root.
    #[cfg(feature = "ebpf")]
    #[test]
    fn duration_typo_surfaces_before_root_guard() {
        let err =
            handle_eagle_eyes(None, Some("3min"), false).expect_err("typo'd interval must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid duration '3min'"),
            "duration error must lead, got: {msg}"
        );
        assert!(
            msg.contains("tip: a similar value exists: '3m'"),
            "typo tip must ride along, got: {msg}"
        );
        assert!(
            !msg.contains("root required"),
            "duration error must precede the root guard, got: {msg}"
        );
    }

    /// Interval bounds (NIGHT-hunt-7): the 1s..60s window is enforced
    /// BEFORE the privilege guard, same fail-fast ladder as interval
    /// typo parsing. Safe on any uid: both bounds return before
    /// ensure_root(), so the test never attaches an observer.
    #[cfg(feature = "ebpf")]
    #[test]
    fn interval_bounds_surface_before_root_guard() {
        for bad in ["0", "61", "90s", "2m"] {
            let err = handle_eagle_eyes(None, Some(bad), false)
                .expect_err("out-of-range interval must fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("must be between 1s and 60s"),
                "interval '{bad}' must name the bounds, got: {msg}"
            );
            assert!(
                !msg.contains("root required"),
                "interval error must precede the root guard, got: {msg}"
            );
        }
    }

    /// Target-spec validation (NIGHT-boost-1): a spec that reduces to
    /// nothing ('/' or ' // ') is a usage error BEFORE the root guard
    /// — same fail-fast ladder as the interval parsing above. Safe on
    /// any uid: the bail returns before ensure_root().
    #[cfg(feature = "ebpf")]
    #[test]
    fn empty_target_spec_surfaces_before_root_guard() {
        for bad in ["/", " // "] {
            let err =
                handle_eagle_eyes(Some(bad), None, false).expect_err("empty target spec must fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("No targets in"),
                "spec '{bad}' must name the problem, got: {msg}"
            );
            assert!(
                !msg.contains("root required"),
                "spec error must precede the root guard, got: {msg}"
            );
        }
    }
}
