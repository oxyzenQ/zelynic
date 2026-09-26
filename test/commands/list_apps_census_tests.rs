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
