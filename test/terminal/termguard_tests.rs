// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The violent-death terminal guard's pure pins (NIGHT-boost-33):
//! the restore bytes' lockstep with the alt-screen contract and
//! the guard child's name shape. The fork/pipe/EOF mechanics are
//! the live proof's lane — the CI kill-tui battery SIGKILLs a real
//! monitor on a real pty, and a unit harness owns no tty to fork
//! against (the guard_tests discipline: pure pins here, root-run
//! proofs in the batteries). Named termguard_tests to sit beside
//! the selection-guard's guard_tests.rs without colliding — one
//! file per contract.

use super::{CLEAN_EXIT, GUARD_NAME, RESTORE};

/// The restore bytes ARE the alt-screen exit contract: a violent
/// death must leave the terminal exactly where a `q` exit leaves
/// it. One constant, one truth — if either side ever re-points,
/// this pin fails the build before a user's terminal does.
#[test]
fn guard_restores_the_exact_alt_exit_bytes() {
    assert_eq!(RESTORE, crate::terminal::screen::ALT_EXIT);
    // And the exit contract itself is non-empty (a violent death
    // with nothing to restore would be a silent no-op).
    assert!(!RESTORE.is_empty());
}

/// The guard child's name: NUL-terminated (the prctl contract),
/// within the kernel's 15-char comm cap, and — the whole point —
/// free of the "zelynic" substring so `pkill zelynic` can never
/// reach the one process that exists to clean the terminal up.
#[test]
fn guard_name_is_pkill_proof() {
    assert_eq!(*GUARD_NAME.last().expect("NUL"), 0);
    let text = std::str::from_utf8(&GUARD_NAME[..GUARD_NAME.len() - 1]).expect("ascii");
    assert!(text.len() <= 15, "comm cap is 15 chars");
    assert!(
        !text.contains("zelynic"),
        "pkill zelynic must miss the guard"
    );
}

/// The clean-exit byte is the stand-down signal: one non-zero,
/// printable byte — the protocol's two verdicts (the byte, and
/// EOF's zero bytes) can never collide.
#[test]
fn clean_exit_byte_is_the_distinct_stand_down_signal() {
    assert_eq!(CLEAN_EXIT, b'c');
}
