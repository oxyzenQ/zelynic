// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the list-apps partial-census note (NIGHT-master-4)
//! — kept in the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from commands/monitor.rs. The note is the honesty
//! contract's completion of the any-uid privilege matrix: the socket
//! census is per-pid privilege-gated (another user's /proc/<pid>/fd
//! answers EACCES), so the unprivileged table under-reports sockets
//! without saying so. The wording pin holds the sentence a doc reader
//! greps for; the delivery contract (stderr only, both output modes,
//! stdout and exit codes untouched) is the --print-json ignored-note
//! pattern the note deliberately reuses.

use super::*;

/// The wording contract: the note names WHAT under-reads (other
/// users' sockets), the HONEST value (zero, not "unknown"), and the
/// repair (sudo) — the three parts any degraded-data disclosure owes
/// its reader. Changing the sentence without updating the docs that
/// quote it fails here.
#[cfg(feature = "ebpf")]
#[test]
fn census_note_names_the_gap_the_value_and_the_repair() {
    let note = unprivileged_census_note();
    assert!(
        note.contains("socket counts read as zero"),
        "the note must name the under-read metric and its honest value: {note}"
    );
    assert!(
        note.contains("sudo"),
        "the note must name the repair: {note}"
    );
    assert!(
        !note.contains("error"),
        "the note is a disclosure, not a failure verdict: {note}"
    );
}

/// The note must stay ONE line — stderr riders that wrap across
/// terminal lines read as error dumps, and the ignored-note
/// precedent it follows is a one-liner.
#[cfg(feature = "ebpf")]
#[test]
fn census_note_is_one_line() {
    let note = unprivileged_census_note();
    assert!(!note.contains('\n'), "one line, no wraps: {note:?}");
}

// ── night-improve-64: the JSON census contract ──────────────────────────────

/// The JSON document carries the census's BOTH numbers plus the
/// honesty flag (night-improve-64, additive): `total` (every cgroup
/// resolved), `socket_cgroups` (the "M with live sockets" figure the
/// human census line has always carried beside it), and
/// `census_complete` (the machine form of the partial-census note).
/// The build is pure, so the pin needs no stdout capture.
#[cfg(feature = "ebpf")]
#[test]
fn list_apps_json_carries_the_full_census() {
    let identity = crate::ebpf::identity::IdentityMap::new();
    let entries = identity.all();
    let conns = crate::ebpf::connections::ConnectionMap::new();
    let doc = list_apps_json(&entries, 142, 57, false, &conns);
    let json = serde_json::to_string(&doc).unwrap();
    assert!(json.contains(r#""total":142"#), "{json}");
    assert!(json.contains(r#""socket_cgroups":57"#), "{json}");
    assert!(json.contains(r#""census_complete":false"#), "{json}");
    // The additive rule: the pinned prefix (total, apps) rides
    // FIRST — an older consumer parsing those two fields is
    // untouched by the trailing pair.
    let total_pos = json.find(r#""total":"#).unwrap();
    let apps_pos = json.find(r#""apps":"#).unwrap();
    let sockets_pos = json.find(r#""socket_cgroups":"#).unwrap();
    let complete_pos = json.find(r#""census_complete":"#).unwrap();
    assert!(total_pos < apps_pos && apps_pos < sockets_pos && sockets_pos < complete_pos);
}

/// `census_complete` is the stderr note's machine form: true only
/// when the run can see every pid's sockets (root). The pair
/// (note on stderr, flag in the document) is the disclosure
/// contract — the JSON consumer reads the flag, the human reads
/// the note, neither fabricates.
#[cfg(feature = "ebpf")]
#[test]
fn list_apps_json_census_complete_reflects_privilege() {
    let identity = crate::ebpf::identity::IdentityMap::new();
    let entries = identity.all();
    let conns = crate::ebpf::connections::ConnectionMap::new();
    let privileged = list_apps_json(&entries, 1, 1, true, &conns);
    let json = serde_json::to_string(&privileged).unwrap();
    assert!(json.contains(r#""census_complete":true"#), "{json}");
    // The unprivileged document keeps the same shape — the flag is
    // the only honesty surface the field owns.
    let unprivileged = list_apps_json(&entries, 1, 0, false, &conns);
    let json = serde_json::to_string(&unprivileged).unwrap();
    assert!(json.contains(r#""census_complete":false"#), "{json}");
}
