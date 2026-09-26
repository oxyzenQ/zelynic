// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the emergency terminal reset (NIGHT-hunt-31, the
//! cosmostrix --reset-terminal skill transfer): the restore and reset
//! byte sequences and their mode-direction contract. Kept in the
//! repo's single test/ tree (cosmostrix Pattern C) and #[path]-wired
//! from src/term_reset/mod.rs.
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
//! 5. The layer-1 termios transformation (NIGHT-improve-30): a raw
//!    termios — the crossterm cfmakeraw breakage plus the monitor's
//!    VMIN=0/VTIME=0 poll pair — comes back fully cooked (canonical,
//!    echo, signals, output post-processing, blocking reads), and
//!    the transformation never clears anything on an already-sane
//!    terminal.

use super::{sane_cooked, TERMINAL_RESET_SEQUENCE, TERMINAL_RESTORE_SEQUENCE};

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

// ── Layer 1 pins: the sane_cooked termios transformation ───────────
//
// The raw state under test is built the honest way: libc's own
// cfmakeraw (what a crossterm-style TUI leaves behind — the monitor's
// lighter ICANON/ECHO/ISIG-only raw is a strict subset) plus the
// monitor's VMIN=0/VTIME=0 poll pair.

/// The exact broken shape a violent TUI death leaves: cfmakeraw's
/// full raw state with the monitor's VMIN=0/VTIME=0 poll pair.
fn broken_raw_termios() -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::cfmakeraw(&mut t) };
    t.c_cc[libc::VMIN] = 0;
    t.c_cc[libc::VTIME] = 0;
    t
}

/// Layer 1 restores every flag the raw-mode class of breakage strips:
/// the cooked line discipline (canonical, echo + its erase/kill
/// refinements, signals, extended input processing), output
/// post-processing (no staircase), the CR/NL input lane, and
/// blocking reads (VMIN=1/VTIME=0 — the monitor's 0/0 pair is a
/// busy-loop hazard in any reader expecting data).
#[test]
fn sane_cooked_restores_the_raw_mode_breakage() {
    let mut t = broken_raw_termios();
    sane_cooked(&mut t);

    let lflag = t.c_lflag;
    for flag in [
        libc::ICANON,
        libc::ECHO,
        libc::ECHOE,
        libc::ECHOK,
        libc::ECHOCTL,
        libc::ECHOKE,
        libc::ISIG,
        libc::IEXTEN,
    ] {
        assert_ne!(lflag & flag, 0, "layer 1 must restore lflag bit {flag}");
    }
    assert_ne!(t.c_oflag & libc::OPOST, 0, "layer 1 must restore OPOST");
    assert_ne!(t.c_oflag & libc::ONLCR, 0, "layer 1 must restore ONLCR");
    assert_ne!(t.c_iflag & libc::BRKINT, 0, "layer 1 must restore BRKINT");
    assert_ne!(t.c_iflag & libc::ICRNL, 0, "layer 1 must restore ICRNL");
    assert_eq!(
        t.c_cc[libc::VMIN],
        1,
        "layer 1 must restore blocking reads (VMIN=1)"
    );
    assert_eq!(t.c_cc[libc::VTIME], 0, "VTIME stays 0");
}

/// The raw-mode sets go back off: IGNBRK/ISTRIP/INLCR/IGNCR/IXOFF are
/// what cfmakeraw (or a hand-rolled raw) leaves on; a rescue that
/// merely OR-ed flags in would leave the input lane half-raw.
#[test]
fn sane_cooked_clears_the_raw_mode_sets() {
    let mut t = broken_raw_termios();
    // Force every raw-mode SET bit on so the clearing side is under
    // test, not cfmakeraw's accident.
    t.c_iflag |= libc::IGNBRK | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::IXOFF;
    sane_cooked(&mut t);

    assert_eq!(t.c_iflag & libc::IGNBRK, 0, "IGNBRK is a raw-mode set");
    assert_eq!(t.c_iflag & libc::ISTRIP, 0, "ISTRIP is a raw-mode set");
    assert_eq!(t.c_iflag & libc::INLCR, 0, "INLCR is a raw-mode set");
    assert_eq!(t.c_iflag & libc::IGNCR, 0, "IGNCR is a raw-mode set");
    assert_eq!(t.c_iflag & libc::IXOFF, 0, "IXOFF is a raw-mode set");
}

/// Idempotence on a healthy terminal: applying layer 1 to an
/// already-cooked state changes nothing it touches — a rescue that
/// ran twice (or ran on a terminal only the guard had already
/// restored) must never break a working shell. The transformation
/// only ever sets cooked bits and clears raw bits, both of which an
/// already-sane termios carries.
#[test]
fn sane_cooked_is_idempotent_on_a_sane_terminal() {
    let mut sane = broken_raw_termios();
    sane_cooked(&mut sane);
    let once = sane;

    sane_cooked(&mut sane);
    assert_eq!(
        sane.c_iflag & (libc::IGNBRK | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::IXOFF),
        once.c_iflag & (libc::IGNBRK | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::IXOFF),
        "the second pass must not move the raw-mode bits"
    );
    assert_eq!(
        sane.c_iflag & (libc::BRKINT | libc::ICRNL),
        once.c_iflag & (libc::BRKINT | libc::ICRNL),
        "the second pass must not move the cooked input bits"
    );
    assert_eq!(
        sane.c_oflag, once.c_oflag,
        "the second pass must not move oflag"
    );
    assert_eq!(
        sane.c_lflag, once.c_lflag,
        "the second pass must not move lflag"
    );
    assert_eq!(
        (sane.c_cc[libc::VMIN], sane.c_cc[libc::VTIME]),
        (once.c_cc[libc::VMIN], once.c_cc[libc::VTIME]),
        "the second pass must not move VMIN/VTIME"
    );
}
