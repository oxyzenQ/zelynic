// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Monitor command handlers — status, list-apps, observe, top.

use anyhow::Result;

/// Handle `zelynic status` — show active limits + watchdog.
#[cfg(feature = "ebpf")]
pub fn handle_status(verbose: bool, json: bool) -> Result<()> {
    use crate::ebpf::limiter::{pin_dir_has_files, Limiter};

    super::ensure_root()?;

    if !pin_dir_has_files() {
        if json {
            println_safe!(
                "{}",
                serde_json::json!({"watchdog": "clean", "active_limits": 0, "limits": []})
            );
        } else {
            println_safe!("No active limits.");
        }
        return Ok(());
    }

    if !Limiter::is_pinned() {
        if json {
            println_safe!(
                "{}",
                serde_json::json!({"error": "stale pins detected", "hint": "run 'zelynic recover'"})
            );
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
        limiter.print_status();
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
        let apps: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "process": e.comm,
                    "cgroup_id": e.cgroup_id,
                    "uid": e.uid,
                    "processes": conns.proc_count(e.cgroup_id),
                    "sockets": conns.socket_count(e.cgroup_id),
                })
            })
            .collect();
        println_safe!("{}", serde_json::json!({"total": count, "apps": apps}));
        return Ok(());
    }

    println_safe!("{}", brand_bold("━━━ Apps with cgroup IDs ━━━"));
    println_safe!(
        "  {} cgroups resolved, {} with live sockets\n",
        count,
        socket_cgroups
    );
    println_safe!(
        "  {:<30} {:>7} {:>8} {:>10} {:>8}",
        "PROCESS",
        "PROCS",
        "SOCKETS",
        "CGROUP ID",
        "UID"
    );
    println_safe!("  {}", "─".repeat(70));

    for id in entries {
        println_safe!(
            "  {:<30} {:>7} {:>8} {:>10} {:>8}",
            id.comm,
            conns.proc_count(id.cgroup_id),
            conns.socket_count(id.cgroup_id),
            format!("cg:{}", id.cgroup_id),
            id.uid
        );
    }

    Ok(())
}

/// Handle `zelynic observe` — real-time traffic monitor (alt screen).
///
/// Always live (NIGHT-hunt-12): the former `--live <dur>` timer is
/// gone — the box refreshes until the user quits (q is the only quit
/// key, NIGHT-hunt-16).
/// `interval` (NIGHT-hunt-7) is the refresh cadence, 1s..60s via
/// `--interval`; it drives both the render loop AND the BPF poll, so
/// per-frame deltas divide by exactly the interval for the RATE
/// column.
#[cfg(feature = "ebpf")]
pub fn handle_observe(cgroup: Option<u32>, interval: Option<&str>, verbose: bool) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::loader::Observer;
    use crate::ebpf::render::render_observe_filtered;
    use crate::ebpf::render::render_observe_frame;
    use crate::terminal;
    use std::time::Duration;

    // Input validation first (fail-fast, no privileges needed): the
    // refresh-interval string is pure parsing — a typo surfaces its
    // did-you-mean tip before the root requirement, the same
    // parse-before-execute ladder as the strict handlers (smoke-run
    // find).
    let interval_secs = match interval {
        Some(s) => crate::ebpf::limiter::parse_monitor_interval(s)?,
        None => 1,
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
        let summary = observer.poll_and_summarize().unwrap_or_default();
        conns.maybe_refresh();
        if let Some(cg) = cgroup {
            render_observe_filtered(
                lines,
                &summary,
                observer.identity(),
                Some(&conns),
                cg,
                interval,
            );
        } else {
            render_observe_frame(lines, &summary, observer.identity(), Some(&conns), interval);
        }
    });

    observer.detach();
    Ok(())
}

/// Handle `zelynic top` — live top talkers (box mode).
///
/// Always live (NIGHT-hunt-12): the former snapshot mode (`--duration`)
/// and `--live` timer are gone — the table refreshes until the user
/// quits (q is the only quit key, NIGHT-hunt-16). `interval` (NIGHT-hunt-7) is the refresh
/// cadence, 1s..60s via `--interval` (default 5s).
#[cfg(feature = "ebpf")]
pub fn handle_top(limit: usize, interval: Option<&str>, verbose: bool) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::loader::Observer;
    use crate::ebpf::render::render_top_table;
    use crate::terminal;
    use std::collections::HashMap;
    use std::time::Duration;

    // Input validation first (fail-fast, no privileges needed): the
    // refresh-interval string is pure parsing — a typo surfaces its
    // did-you-mean tip before the root requirement (smoke-run find).
    let interval_secs = match interval {
        Some(s) => crate::ebpf::limiter::parse_monitor_interval(s)?,
        None => 5,
    };

    super::ensure_root()?;

    // Same verbose contract as observe (NIGHT-hunt-9): the loader trace
    // prints before the live box takes over, so -v explains where the
    // observer object came from and what it attached to.
    let mut observer = Observer::attach_quiet(!verbose)?;
    observer.refresh_identity();
    if verbose {
        eprintln_safe!("[ebpf] {} cgroups resolved", observer.identity().len());
    }

    let mut cumulative: HashMap<u32, (u64, u64, u64)> = HashMap::new();
    let mut conns = ConnectionMap::new();
    let _ = observer.poll_and_summarize()?;

    // NIGHT-improve-2: same line-building contract as observe — the
    // diff engine emits only the changed rows.
    let interval = Duration::from_secs(interval_secs);
    terminal::run_alt(interval, |lines| {
        let summary = observer.poll_and_summarize().unwrap_or_default();
        for c in &summary.cgroups {
            let entry = cumulative.entry(c.cgroup_id).or_insert((0, 0, 0));
            entry.0 += c.ingress_bytes;
            entry.1 += c.bytes;
            entry.2 += c.packets + c.ingress_packets;
        }
        conns.maybe_refresh();
        render_top_table(
            lines,
            &cumulative,
            limit,
            observer.identity(),
            Some(&conns),
            interval,
        );
    });

    observer.detach();
    Ok(())
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
        let err = handle_observe(None, Some("3min"), false).expect_err("typo'd interval must fail");
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
            let err = handle_observe(None, Some(bad), false)
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
}
