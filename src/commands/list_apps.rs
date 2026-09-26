// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The list-apps handler (discovery surface) — split from
//! commands/monitor.rs at NIGHT-master-4 when the census-note
//! hardening pushed that file past the 500-line LOC cap; the same
//! cohesion cut the repo already made for eagle.rs (the depth
//! one-shot). This module owns the any-uid discovery table, its
//! JSON document, and the partial-census disclosure.

use anyhow::Result;

use crate::output::{grey, ok, print_json};

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

    // NIGHT-master-4 (the partial-census honesty note): list-apps
    // runs on any uid by design (the privilege matrix), but the
    // socket census is privilege-gated per pid — another user's
    // /proc/<pid>/fd answers EACCES, so their cgroups count
    // processes correctly and sockets as ZERO, silently. The note
    // rides stderr in BOTH output modes (the --print-json
    // ignored-note pattern): stdout stays byte-clean for scripts,
    // the exit code stays 0, and the human learns why the socket
    // column under-reads before concluding "nobody is connected".
    if !nix::unistd::geteuid().is_root() {
        eprintln_safe!("{}", crate::output::warn_bold(&unprivileged_census_note()));
    }

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

/// The partial-census note's wording (pure, NIGHT-master-4) — the
/// exact sentence a doc reader greps for, pinned so the contract
/// is a decision, not an accident.
#[cfg(feature = "ebpf")]
#[must_use]
pub(crate) fn unprivileged_census_note() -> String {
    "unprivileged: other users' socket counts read as zero — run with sudo for the full census"
        .to_string()
}

// NIGHT-master-4: the census-note pins live under the single test/
// tree (cosmostrix Pattern C), #[path]-wired exactly like the eagle
// depth pins.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/list_apps_census_tests.rs"]
mod census_tests;
