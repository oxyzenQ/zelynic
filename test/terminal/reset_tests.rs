// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the emergency terminal reset (NIGHT-hunt-31, the
//! cosmostrix --reset-terminal skill transfer): the restore and reset
//! byte sequences and their mode-direction contract. Kept in the
//! repo's single test/ tree (cosmostrix Pattern C) and #[path]-wired
//! from src/term_reset.rs.
//!
//! What is pinned, and why each pin earns its place:
//! 1. The restore sequence restores every optional mode the monitor
//!    (or a foreign TUI) may have left on — one missing `l` byte is
//!    a rescue that leaves exactly one breakage behind.
//! 2. The reset sequence is the restore sequence plus the destructive
//!    clear tail (screen + scrollback + home) — the prefix identity
//!    keeps the two tiers from drifting apart.
//! 3. Every DEC private mode is restored toward its DEFAULT
//!    direction: OFF-default modes only ever `l`, ON-default modes
//!    only ever `h`. The rescue may never ENABLE an optional mode —
//!    that is the takeover the mouse contract forbids, worn as a
//!    rescue costume.
//! 4. The clear tail order: home, clear screen, clear scrollback,
//!    home — clearing scrollback while the cursor is mid-screen
//!    leaves the viewport anchored wrong on some terminals.

use super::{TERMINAL_RESET_SEQUENCE, TERMINAL_RESTORE_SEQUENCE};

/// Extract every DEC private mode and its direction from an escape
/// byte sequence: the digits following each `ESC[?` prefix plus the
/// `h`/`l` suffix that follows them.
fn dec_private_modes_with_direction(seq: &[u8]) -> Vec<(u32, u8)> {
    let mut modes = Vec::new();
    let mut i = 0;
    while i + 2 < seq.len() {
        if seq[i] == 0x1b && seq[i + 1] == b'[' && seq[i + 2] == b'?' {
            let start = i + 3;
            let mut end = start;
            while end < seq.len() && seq[end].is_ascii_digit() {
                end += 1;
            }
            if end > start && end < seq.len() && matches!(seq[end], b'h' | b'l') {
                let digits = std::str::from_utf8(&seq[start..end]).unwrap_or("");
                if let Ok(n) = digits.parse::<u32>() {
                    modes.push((n, seq[end]));
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    modes
}

/// The restore sequence carries every recovery byte: SGR reset
/// (bookended — the pen state a mid-frame death leaves behind
/// survives the alt-screen switch), sync output off (the frozen-
/// screen breakage), bracketed paste off, focus off, the FULL mouse
/// family off (the monitor's trio plus the 1003/1015 legacy
/// encodings), alt screen off (the frozen frame leaves with it),
/// the kitty pop, scroll region, charset, autowrap on, cursor
/// visible.
#[test]
fn restore_sequence_carries_every_recovery_byte() {
    for needle in [
        "\x1b[0m",
        "\x1b[?2026l",
        "\x1b[?2004l",
        "\x1b[?1004l",
        "\x1b[?1006l",
        "\x1b[?1002l",
        "\x1b[?1003l",
        "\x1b[?1000l",
        "\x1b[?1015l",
        "\x1b[?1049l",
        "\x1b[<1u",
        "\x1b[r",
        "\x1b(B",
        "\x1b[?7h",
        "\x1b[?25h",
    ] {
        assert!(
            TERMINAL_RESTORE_SEQUENCE.contains(needle),
            "the restore sequence must carry {needle:?} — one missing byte is a \
             rescue that leaves exactly one breakage behind"
        );
    }
    // The bookend: SGR reset opens AND closes the sequence, so the
    // last byte the terminal receives never re-enables a style.
    assert!(TERMINAL_RESTORE_SEQUENCE.starts_with("\x1b[0m"));
    assert!(TERMINAL_RESTORE_SEQUENCE.ends_with("\x1b[0m"));
}

/// The reset sequence is the restore sequence plus the destructive
/// clear tail — prefix identity, so the two tiers can never drift
/// apart (a reset that forgets a restore byte is a rescue with a
/// hole in it).
#[test]
fn reset_sequence_is_restore_plus_clear_tail() {
    assert!(
        TERMINAL_RESET_SEQUENCE.starts_with(TERMINAL_RESTORE_SEQUENCE),
        "the reset tier must begin with the ENTIRE restore tier"
    );
    // The clear tail, in order: home, clear screen, clear scrollback,
    // home, SGR reset.
    assert!(
        TERMINAL_RESET_SEQUENCE.ends_with("\x1b[H\x1b[2J\x1b[3J\x1b[H\x1b[0m"),
        "the destructive tail is home + clear + scrollback-purge + home + SGR reset"
    );
}

/// The mode-direction contract: every DEC private mode in BOTH
/// sequences moves toward its default. OFF-default modes (sync 2026,
/// paste 2004, focus 1004, the mouse family 1000/1002/1003/1006/
/// 1015, alt screen 1049) are only ever `l`; ON-default modes
/// (cursor 25, autowrap 7) are only ever `h`. The rescue never
/// enables an optional mode — that is the takeover the mouse
/// contract forbids, and a rescue costume would not excuse it.
#[test]
fn every_mode_moves_toward_its_default() {
    const OFF_DEFAULT: &[u32] = &[2026, 2004, 1004, 1000, 1002, 1003, 1006, 1015, 1049];
    const ON_DEFAULT: &[u32] = &[25, 7];

    for seq in [TERMINAL_RESTORE_SEQUENCE, TERMINAL_RESET_SEQUENCE] {
        for (mode, direction) in dec_private_modes_with_direction(seq.as_bytes()) {
            if OFF_DEFAULT.contains(&mode) {
                assert_eq!(
                    direction, b'l',
                    "mode {mode} defaults to OFF — the rescue may only send it 'l'"
                );
            } else if ON_DEFAULT.contains(&mode) {
                assert_eq!(
                    direction, b'h',
                    "mode {mode} defaults to ON — the rescue may only send it 'h'"
                );
            } else {
                panic!("mode {mode} is outside the reset contract's inventory");
            }
        }
    }
}
