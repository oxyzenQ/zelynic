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
            println_safe!("Stale BPF pin files detected (partial state from old version).");
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
#[cfg(feature = "ebpf")]
pub fn handle_list_apps(json: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::output::brand_bold;

    let mut identity = IdentityMap::new();
    let count = identity.refresh();

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
                })
            })
            .collect();
        println_safe!("{}", serde_json::json!({"total": count, "apps": apps}));
        return Ok(());
    }

    println_safe!("{}", brand_bold("━━━ Apps with cgroup IDs ━━━"));
    println_safe!("  {} cgroups resolved\n", count);
    println_safe!("  {:<30} {:>10} {:>8}", "PROCESS", "CGROUP ID", "UID");
    println_safe!("  {}", "─".repeat(50));

    for id in entries {
        println_safe!(
            "  {:<30} {:>10} {:>8}",
            id.comm,
            format!("cg:{}", id.cgroup_id),
            id.uid
        );
    }

    Ok(())
}

/// Handle `zelynic observe` — real-time traffic monitor (alt screen).
#[cfg(feature = "ebpf")]
pub fn handle_observe(live: Option<&str>, cgroup: Option<u32>, verbose: bool) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use crate::terminal;
    use std::time::Duration;

    // Input validation first (fail-fast, no privileges needed): the
    // live-duration string is pure parsing — a typo surfaces its
    // did-you-mean tip before the root requirement, the same
    // parse-before-execute ladder as the strict handlers (smoke-run
    // find).
    let duration_secs = match live {
        Some(s) => crate::ebpf::limiter::parse_time_duration(s)?,
        None => 0,
    };

    super::ensure_root()?;

    let mut observer = Observer::attach_quiet(true)?;
    observer.refresh_identity();
    if verbose {
        eprintln_safe!("[ebpf] {} cgroups resolved", observer.identity().len());
    }

    let _ = observer.poll_and_summarize()?;

    let duration = if duration_secs > 0 {
        Duration::from_secs(duration_secs)
    } else {
        Duration::ZERO
    };

    terminal::run_alt(Duration::from_secs(1), duration, || {
        let summary = observer.poll_and_summarize().unwrap_or_default();
        println_safe!(
            "{}",
            crate::output::brand_bold("━━━ zelynic Observe (press q/ESC to quit) ━━━")
        );
        println_safe!();
        if let Some(cg) = cgroup {
            summary.print_filtered(observer.identity(), cg);
        } else {
            summary.print(observer.identity());
        }
    });

    observer.detach();
    Ok(())
}

/// Handle `zelynic top` — snapshot or live top talkers.
#[cfg(feature = "ebpf")]
pub fn handle_top(
    duration: Option<&str>,
    limit: usize,
    live: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use crate::terminal;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // Input validation first (fail-fast, no privileges needed): both
    // duration strings are pure parsing — a typo surfaces its
    // did-you-mean tip before the root requirement (smoke-run find).
    let live_secs = match live {
        Some(s) => Some(crate::ebpf::limiter::parse_time_duration(s)?),
        None => None,
    };
    let snapshot_secs = match duration {
        Some(s) => crate::ebpf::limiter::parse_time_duration(s)?,
        None => 10,
    };

    super::ensure_root()?;

    let mut observer = Observer::attach_quiet(true)?;
    observer.refresh_identity();
    if verbose {
        eprintln_safe!("[ebpf] {} cgroups resolved", observer.identity().len());
    }

    let mut cumulative: HashMap<u32, (u64, u64, u64)> = HashMap::new();
    let _ = observer.poll_and_summarize()?;

    if let Some(duration_secs) = live_secs {
        let dur = if duration_secs > 0 {
            Duration::from_secs(duration_secs)
        } else {
            Duration::ZERO
        };

        terminal::run_alt(Duration::from_secs(5), dur, || {
            let summary = observer.poll_and_summarize().unwrap_or_default();
            for c in &summary.cgroups {
                let entry = cumulative.entry(c.cgroup_id).or_insert((0, 0, 0));
                entry.0 += c.ingress_bytes;
                entry.1 += c.bytes;
                entry.2 += c.packets + c.ingress_packets;
            }
            println_safe!(
                "{}",
                crate::output::brand_bold("━━━ zelynic Top — LIVE (press q/ESC to quit) ━━━")
            );
            println_safe!();
            print_top_table(&cumulative, limit, observer.identity(), "accumulated");
        });
    } else {
        let dur_secs = snapshot_secs;

        eprintln_safe!(
            "{}",
            crate::output::brand_bold(&format!("━━━ zelynic Top — sampling for {dur_secs}s ━━━"))
        );
        eprintln_safe!("  (collecting traffic data...)\n");

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(dur_secs) {
            std::thread::sleep(Duration::from_millis(500));
            let summary = observer.poll_and_summarize()?;
            for c in &summary.cgroups {
                let entry = cumulative.entry(c.cgroup_id).or_insert((0, 0, 0));
                entry.0 += c.ingress_bytes;
                entry.1 += c.bytes;
                entry.2 += c.packets + c.ingress_packets;
            }
        }

        print_top_table(
            &cumulative,
            limit,
            observer.identity(),
            &format!("{dur_secs}s sample"),
        );
    }

    observer.detach();
    Ok(())
}

/// Print sorted top talkers table from cumulative data.
#[cfg(feature = "ebpf")]
fn print_top_table(
    cumulative: &std::collections::HashMap<u32, (u64, u64, u64)>,
    limit: usize,
    identity: &crate::ebpf::identity::IdentityMap,
    mode: &str,
) {
    use crate::output::warn_bold;

    let mut talkers: Vec<(u32, u64, u64, u64, u64)> = cumulative
        .iter()
        .map(|(cg, (dl, ul, pkt))| (*cg, *dl, *ul, dl + ul, *pkt))
        .filter(|(_, _, _, total, _)| *total > 0)
        .collect();

    talkers.sort_by_key(|t| std::cmp::Reverse(t.3));

    if talkers.is_empty() {
        println_safe!("  (no traffic yet — waiting...)\n");
        return;
    }

    let shown = talkers.len().min(limit);
    println_safe!(
        "{}",
        crate::output::brand_bold(&format!("━━━ Top {shown} Bandwidth Consumers ({mode}) ━━━"))
    );
    println_safe!();
    println_safe!(
        "  {:>3}  {:<28} {:>12} {:>12} {:>12}",
        "#",
        "CGROUP",
        "DOWNLOAD",
        "UPLOAD",
        "TOTAL"
    );
    println_safe!("  {}", "─".repeat(73));

    let mut top_proc_name: Option<String> = None;
    let mut grand_total_pkt: u64 = 0;

    for (i, (cgroup_id, dl_bytes, ul_bytes, total, total_pkt)) in
        talkers.iter().take(limit).enumerate()
    {
        let label = identity.label(*cgroup_id);
        grand_total_pkt += total_pkt;

        println_safe!(
            "  {:>3}  {:<28} {:>12} {:>12} {:>12}",
            i + 1,
            label,
            crate::ebpf::limiter::format_bytes(*dl_bytes),
            crate::ebpf::limiter::format_bytes(*ul_bytes),
            crate::ebpf::limiter::format_bytes(*total),
        );

        if i == 0 {
            top_proc_name = label
                .split('(')
                .nth(1)
                .and_then(|s| s.strip_suffix(')'))
                .filter(|s| !s.is_empty() && *s != "unknown")
                .map(|s| s.to_string());
        }
    }

    println_safe!();
    println_safe!("  {grand_total_pkt} packets total\n");

    if let Some(proc_name) = top_proc_name {
        println_safe!("  {} Top consumer: {proc_name}", warn_bold("→"));
        println_safe!("  Limit it: sudo zelynic strict-single {proc_name} 100kb\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse-before-execute contract (live smoke-run find): a typo'd
    /// live-duration string must surface its did-you-mean tip BEFORE
    /// the privilege guard, matching the strict handlers' ladder and
    /// clap's own argument validation order.
    ///
    /// Safe on any uid: the duration error returns before ensure_root(),
    /// so the test never reaches observer attach even as root.
    #[cfg(feature = "ebpf")]
    #[test]
    fn duration_typo_surfaces_before_root_guard() {
        let err = handle_observe(Some("3min"), None, false).expect_err("typo'd duration must fail");
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
}
