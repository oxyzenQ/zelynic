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
        // S1: the document is composed by the hand-written writer
        // below (list_apps_json) straight into one compact String —
        // no serde_json::Value tree (one allocation per node) for the
        // biggest document the CLI emits, and no derive stack behind
        // it. Field names and order are the pinned scripting contract
        // (docs/USAGE.md JSON reference).
        //
        // night-improve-64: the census's TWO numbers and its honesty
        // flag join the document (additive, the improve-63 rule) — the
        // human census line always spoke "N cgroups resolved, M with
        // live sockets" while the JSON carried only `total`, and the
        // partial-census disclosure stayed human-only on stderr: a
        // frontend polling the JSON on a non-root host saw `sockets:
        // 0` rows with no machine-readable hint that the census is
        // degraded. `socket_cgroups` carries the second number;
        // `census_complete` is the machine form of the stderr note
        // (false = unprivileged, other users' socket counts may read
        // zero).
        let json_doc = list_apps_json(
            &entries,
            count,
            socket_cgroups,
            nix::unistd::geteuid().is_root(),
            &conns,
        );
        print_json(&json_doc);
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
    // NIGHT-private-research-3 (the compact-and-simple pass): the
    // census line lands directly above the header row it counts —
    // one table cluster under the title, zero filler lines between
    // them (the engrave-5 breathing gaps retired on every report
    // surface by the owner's directive).
    println_safe!(
        "{}",
        grey(&format!(
            "  {} cgroups resolved, {} with live sockets",
            format_count(count as u64),
            format_count(socket_cgroups as u64)
        ))
    );
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

/// Assemble the list-apps JSON document (pure, night-improve-64:
/// extracted so the scripting contract — field names, census
/// semantics, the honesty flag — is unit-pinnable without capturing
/// stdout, the hunt-22 pattern status_json set). S1: the writer is
/// the hand-written lane's own composition — field order is the
/// pinned contract, `total` leads and the census pair trails (the
/// improve-63 additive rule: older consumers parse the prefix
/// untouched). Returns the compact document line, ready for
/// [`crate::output::print_json`].
#[cfg(feature = "ebpf")]
fn list_apps_json(
    entries: &[&crate::ebpf::identity::ProcessIdentity],
    total: usize,
    socket_cgroups: usize,
    census_complete: bool,
    conns: &crate::ebpf::connections::ConnectionMap,
) -> String {
    use crate::json::write::{write_array, write_bool, write_number, write_string};

    let mut out = String::with_capacity(64 + entries.len() * 96);
    out.push_str("{\"total\":");
    write_number(&mut out, total);
    out.push_str(",\"apps\":");
    write_array(&mut out, entries.len(), |out, i| {
        let entry = entries[i];
        out.push_str("{\"process\":");
        write_string(out, &entry.comm);
        out.push_str(",\"cgroup_id\":");
        write_number(out, entry.cgroup_id);
        out.push_str(",\"uid\":");
        write_number(out, entry.uid);
        out.push_str(",\"processes\":");
        write_number(out, conns.proc_count(entry.cgroup_id));
        out.push_str(",\"sockets\":");
        write_number(out, conns.socket_count(entry.cgroup_id));
        out.push('}');
    });
    out.push_str(",\"socket_cgroups\":");
    write_number(&mut out, socket_cgroups);
    out.push_str(",\"census_complete\":");
    write_bool(&mut out, census_complete);
    out.push('}');
    out
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
