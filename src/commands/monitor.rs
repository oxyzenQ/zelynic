// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Monitor command handlers — status, list-apps, eagle-eyes.

use crate::output::{grey, ok, print_json};
use anyhow::Result;

/// Handle `zelynic status` — show active limits + watchdog.
#[cfg(feature = "ebpf")]
pub fn handle_status(verbose: bool, json: bool) -> Result<()> {
    use crate::ebpf::display::{status_clean_lines, status_stale_lines};
    use crate::ebpf::limiter::{pin_dir_has_files, terminal_width, Limiter};

    super::ensure_root()?;

    if !pin_dir_has_files() {
        if json {
            print_json(&serde_json::json!({
                "watchdog": "clean", "active_limits": 0, "limits": []
            }));
        } else {
            // NIGHT-engrave-5: the clean verdict carries the flagship
            // chrome (title bar, breathing gap, stamp) — one grey
            // line inside the frame, not a bare sentence under the
            // prompt.
            for line in status_clean_lines(terminal_width()) {
                println_safe!("{line}");
            }
        }
        return Ok(());
    }

    if !Limiter::is_pinned() {
        if json {
            print_json(&serde_json::json!({
                "error": "stale pins detected", "hint": "run 'zelynic recover'"
            }));
        } else {
            // NIGHT-engrave-5: the warning state carries the same
            // chrome — warn yellow for the finding, suggestion white
            // for the recovery command.
            for line in status_stale_lines(terminal_width()) {
                println_safe!("{line}");
            }
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
///
/// NIGHT-engrave-5 (the hunt find riding the owner's status audit):
/// the table answers to the eagle-eyes contract like status does —
/// the flagship title bar (the old "━━━" banner was the pre-eagle
/// idiom), lowercase purple column headers, the monitor's purple
/// grid, grey census line, green data rows. Discovery is a REPORT
/// surface; the report family shares one table style.
#[cfg(feature = "ebpf")]
pub fn handle_list_apps(json: bool) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::display::list_apps_header_line;
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::format_count;
    use crate::ebpf::render::{grid_line, title_bar};

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

    // Column widths shared by header, rows, and separator — one
    // table, one width source (improve-13: the separator was a
    // hardcoded 70 while the columns sum to 69 — the rule line
    // overhung the table by one).
    //
    // The process/socket counts ride the SI compact ladder
    // (NIGHT-engrave-7): a busy system's cgroup hosting 4-digit
    // process counts reads "1.2K" inside the same 7-column cell —
    // no raw counter ever pushes the row past its width.
    let widths = [30usize, 7, 8, 10, 8];
    let table_w: usize = 2 + widths.iter().sum::<usize>() + (widths.len() - 1);
    println_safe!("{}", title_bar("zelynic list-apps", table_w));
    println_safe!();
    println_safe!(
        "{}",
        grey(&format!(
            "  {} cgroups resolved, {} with live sockets",
            format_count(count as u64),
            format_count(socket_cgroups as u64)
        ))
    );
    println_safe!();
    println_safe!("{}", list_apps_header_line(&widths));
    println_safe!("{}", grid_line(table_w));

    for id in entries {
        println_safe!(
            "{}",
            ok(&format!(
                // NIGHT-lts-1: the comm cell pads by RENDERED width —
                // a CJK app name padded by chars shifts the row's
                // numeric columns out of line with the ASCII rows.
                "  {} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
                crate::output::pad_to_width(&id.comm, widths[0]),
                format_count(conns.proc_count(id.cgroup_id) as u64),
                format_count(conns.socket_count(id.cgroup_id) as u64),
                format!("cg:{}", id.cgroup_id),
                id.uid,
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
                w4 = widths[4]
            ))
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
/// `--interval` (default 1s — realtime precision); it drives the
/// render loop's beat scheduler AND the BPF poll, while the rate
/// math divides each frame's deltas by the MEASURED poll-to-poll
/// span (NIGHT-lts-3) — the honest denominator, not the nominal
/// cadence the scheduler only approximates.
///
/// The smooth open (NIGHT-boost-25): the terminal session opens
/// before the BPF load — the alt screen and a quiet loading frame
/// arrive with the Enter key, the load runs under the frame, and
/// the first live frame rewrites it in place (the one-row morph,
/// see render/loading.rs). `-v` keeps the trace-first sequence (the
/// attach diagnostics print on the main screen, where they survive
/// the TUI).
///
/// The positional TARGETS spec is autodetected per Target::parse
/// (digits = cgroup ID, the display prefix cg:73386 round-trips
/// (NIGHT-boost-37), else process name) and re-resolved against
/// the live identity map every frame, so apps started mid-session
/// appear on the next refresh. One token resolving to one cgroup
/// takes the deep focus view; more take the filtered ranked table;
/// none take the full session leaderboard (NIGHT-boost-5): ranking
/// and the total column ride the per-cgroup bytes accumulated since
/// the monitor started, rows persist across quiet frames, and rank 1
/// wears the static champion red (NIGHT-boost-14 retired the
/// takeover blink) — the row budget equals the terminal height
/// (no --limit, no cap).
/// Smooth open (NIGHT-boost-25) + the interactive-stdio gate
/// (NIGHT-boost-28): the session opens only on a fully interactive
/// stdio pair — piped/redirected stdout refuses before any terminal
/// state or BPF work, the branded error teaching the scripted-output
/// alternative (`status --print-json`).
#[cfg(feature = "ebpf")]
pub fn handle_eagle_eyes(
    targets: Option<&str>,
    interval: Option<&str>,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::connections::ConnectionMap;
    use crate::ebpf::limiter::Target;
    use crate::ebpf::loader::Observer;
    use crate::ebpf::render::{loading_frame, render_eagle_eyes, FrameGeometry, SessionState};
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
    // Target parsing is owned by the depth handler's shared spec
    // parser (NIGHT-master-1 extracted it there) — both eagle-eyes
    // modes speak the same '/'-separated grammar.
    let tokens: Vec<Target> = match targets {
        Some(spec) => super::eagle::parse_target_spec(spec)?,
        None => Vec::new(),
    };

    super::ensure_root()?;

    // NIGHT-boost-28: the interactive-stdio gate, before any terminal
    // state or BPF work — `sudo zelynic ee | grep` is the owner's
    // fatal (stdin TTY + stdout pipe raw-moded the real terminal and
    // spun forever as root; see terminal::require_interactive).
    // Placed after the root guard so the unprivileged piped probe
    // still teaches sudo first (the surface pin's contract).
    terminal::require_interactive()?;

    // The cadence as a Duration, before the smooth open composes the
    // loading frame's status line with it.
    let interval = Duration::from_secs(interval_secs);

    // ── The smooth open (NIGHT-boost-25) ──────────────────────────────
    //
    // The old sequence ran the whole BPF load on the MAIN screen:
    // blank dead air for the verifier's duration, then the alt screen
    // switched and the full bright frame painted in one burst — the
    // flashy, eye-straining transition the owner audited. The default
    // path now opens the terminal session FIRST (the alt screen and
    // the loading frame arrive with the Enter key) and runs the load,
    // the identity walk, and the opening poll UNDER that frame; the
    // first live frame then rewrites the loading frame in place — no
    // clear, no blank flash — with the note row (`loading observer…`
    // -> `waiting for traffic…`) as the one visible change (see
    // render/loading.rs, the morph pin). A load failure drops the
    // session: ALT_EXIT restores the main screen and the branded
    // error prints on it.
    //
    // -v keeps the trace-first sequence (the NIGHT-boost-6 contract):
    // stderr writes during the alt screen would garble the live
    // frame, so the attach trace prints on the main screen where it
    // survives the TUI — the trace IS the loading feedback there, and
    // the session opens with no prelude.
    //
    // The opening poll seeds the delta baseline on both paths; its
    // summary is discarded on purpose (the pre-existing horizon
    // contract: bytes between attach and the first frame stay out of
    // the session ledger).
    let mut observer;
    let monitor = if verbose {
        observer = Observer::attach(verbose)?;
        observer.refresh_identity();
        eprintln_safe!("[ebpf] {} cgroups resolved", observer.identity().len());
        let first = observer.poll_and_summarize()?;
        eprintln_safe!(
            "[ebpf] first poll: {} cgroups with traffic since attach",
            first.cgroups.len()
        );
        terminal::Monitor::open(|_, _| Vec::new())?
    } else {
        let monitor = terminal::Monitor::open(|w, h| {
            loading_frame(
                interval,
                FrameGeometry {
                    width: w,
                    height: h,
                },
            )
        })?;
        observer = Observer::attach(verbose)?;
        observer.refresh_identity();
        let _ = observer.poll_and_summarize()?;
        monitor
    };

    // Eagle-eyes detail (NIGHT-hunt-8): per-cgroup process/socket
    // detail, TTL-cached inside the map so 1s frames reuse the scan.
    // NIGHT-improve-2: the closure builds the frame's logical lines;
    // the session loop's diff engine emits only what changed.
    //
    // The session leaderboard (NIGHT-boost-5) lives OUTSIDE the
    // closure: each frame folds its deltas in, so the ranked table
    // renders from what apps accumulated since the monitor started —
    // rows persist across quiet frames (a one-second hush no longer
    // wipes the board to "waiting for traffic…"), and a transient
    // map-read error renders one em-dash frame, not a collapse.
    let mut conns = ConnectionMap::new();
    let mut session = SessionState::new();
    // The session clock (NIGHT-boost-17, improve-27): starts at
    // monitor launch, reads out as the grey `uptime 1m:10s` line
    // below the footer on every frame — the horizon the leaderboard's
    // accumulated totals span.
    let started = std::time::Instant::now();
    // The rate-math clock (NIGHT-lts-3): the measured poll-to-poll
    // span — seeded after the opening poll, re-armed only on a
    // SUCCESSFUL poll. A transient map-read error folds an empty
    // frame (the one-frame tolerance below) and leaves the baseline
    // untouched, so the recovery frame's double-wide delta divides
    // by a double-wide span — the nominal-interval era doubled the
    // very spike it was recovering from.
    let mut last_poll = std::time::Instant::now();
    monitor.run(interval, |lines| {
        // One-frame tolerance, not a swallow bug (NIGHT-optimized-2
        // audit): the opening poll below hard-failed on any broken
        // map, so an Err here is a transient read. unwrap_or_default
        // folds an EMPTY frame — the leaderboard keeps every row it
        // ranked with em-dash rates; prev_stats inside the observer
        // is only rewritten on success, so the next good frame's
        // delta spans the skipped interval — no data loss, no double
        // count. Propagating here instead would kill the live TUI on
        // a single hiccup.
        let span = last_poll.elapsed();
        let summary = match observer.poll_and_summarize() {
            Ok(s) => {
                last_poll = std::time::Instant::now();
                s
            }
            Err(_) => Default::default(),
        };
        conns.maybe_refresh();
        // NIGHT-boost-26 (per-endpoint byte attribution, the 2.4
        // frontier): the join. The ConnectionMap's /proc walk resolved
        // each held socket's kernel cookie (pidfd_getfd + SO_COOKIE);
        // the loader point-looks-up the BPF cookie maps for exactly
        // that set (tens of syscalls, not a map iteration) and the
        // result parks on the map the renderers already read. An Err
        // keeps the previous join — lifetime totals stale by one
        // frame, never fabricated-absent, the leaderboard's own
        // one-frame tolerance.
        let cookies = conns.socket_cookies();
        if !cookies.is_empty() {
            if let Ok(bytes) = observer.socket_bytes(&cookies) {
                conns.apply_socket_bytes(bytes);
            }
        }
        render_eagle_eyes(
            lines,
            &summary,
            &tokens,
            observer.identity(),
            Some(&conns),
            interval,
            span,
            &mut session,
            started.elapsed(),
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
