// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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
//!
//! Message law (night-dragon-maintenance-T1 (S4)): assert failures
//! name the violated contract piece and never embed the composed
//! document. The list-apps document is built over the socket-census
//! joins, CodeQL models the cookie-named join fields as sensitive
//! sources and a panic format string as a logging sink, so the old
//! bare `{json}` failure dump stood as a High cleartext-logging
//! alert per assert (five here). The fixture data is synthetic — no
//! secret ever moved — but standing noise buries real findings, so
//! the dump retired.

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
    let doc = list_apps_json(&entries, 142, 57, false, &conns, &identity);
    let json = doc;
    assert!(
        json.contains(r#""total":142"#),
        "the census carries the total"
    );
    assert!(
        json.contains(r#""socket_cgroups":57"#),
        "the census carries the socket_cgroups count"
    );
    assert!(
        json.contains(r#""census_complete":false"#),
        "the census_complete flag is honest at false"
    );
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
    let privileged = list_apps_json(&entries, 1, 1, true, &conns, &identity);
    let json = privileged;
    assert!(
        json.contains(r#""census_complete":true"#),
        "the privileged document reports census_complete true"
    );
    // The unprivileged document keeps the same shape — the flag is
    // the only honesty surface the field owns.
    let unprivileged = list_apps_json(&entries, 1, 0, false, &conns, &identity);
    let json = unprivileged;
    assert!(
        json.contains(r#""census_complete":false"#),
        "the unprivileged document reports census_complete false"
    );
}

/// night-cafe-1 (F1): the machine lane's name is the UNCAPPED
/// enriched name when the display cap cut one. A cgroup whose
/// representative is a >24-column argv[0] basename (the
/// polkit-kde-authenticati… class) books its full name in the
/// identity map's other half, and the document carries it verbatim —
/// a script matching the full process name reads it from the JSON
/// and the resolution walk accepts it back. A cgroup with no
/// enriched-full name keeps the display comm's bytes unchanged.
#[cfg(feature = "ebpf")]
#[test]
fn list_apps_json_carries_the_uncapped_name() {
    use crate::ebpf::identity::ProcessIdentity;
    let mut identity = crate::ebpf::identity::IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 42,
        uid: 1000,
        comm: "polkit-kde-authenticati\u{2026}".to_string(),
    });
    identity.insert(ProcessIdentity {
        cgroup_id: 43,
        uid: 1000,
        comm: "brave".to_string(),
    });
    identity.seed_full_name_for_tests(42, "polkit-kde-authentication-agent");
    let short = identity
        .all()
        .into_iter()
        .filter(|e| e.cgroup_id == 43)
        .collect::<Vec<_>>();
    let capped = identity
        .all()
        .into_iter()
        .filter(|e| e.cgroup_id == 42)
        .collect::<Vec<_>>();
    let conns = crate::ebpf::connections::ConnectionMap::new();
    let doc = list_apps_json(&capped, 1, 0, true, &conns, &identity);
    assert!(
        doc.contains("\"process\":\"polkit-kde-authentication-agent\""),
        "the capped display artifact never rides the machine lane"
    );
    assert!(
        !doc.contains('\u{2026}'),
        "no ellipsis artifact survives into the document"
    );
    let doc = list_apps_json(&short, 1, 0, true, &conns, &identity);
    assert!(
        doc.contains("\"process\":\"brave\""),
        "a name the cap never cut is unchanged"
    );
}
