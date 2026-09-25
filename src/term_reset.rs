// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The emergency terminal reset (NIGHT-hunt-31, the cosmostrix
//! `--reset-terminal` skill transfer): the after-the-fact recovery
//! for a terminal left broken by a violent TUI death — the eagle-eyes
//! monitor killed with `kill -9` (or any terminal app that died
//! between enabling a mode and restoring it).
//!
//! The breakage anatomy: the monitor holds the terminal in raw mode,
//! the alt screen, and mouse tracking — all restored by
//! `AltScreen::drop` on every clean exit, and by the violent-death
//! guard (guard.rs, NIGHT-boost-33) when the process dies without
//! running a Drop. The guard is insurance, not a precondition
//! (fail-open by design), and the SGR pen state a mid-frame death
//! leaves behind outlives the alt-screen switch — so the residual
//! holes (guard arm failed, guard child killed, pen linger, a
//! foreign app's modes) need ONE explicit recovery path that works
//! from inside the broken terminal: blind-type
//! `zelynic --reset-terminal`, no re-opening the terminal, no new
//! window.
//!
//! The recovery is defense-in-depth, five layers (the cosmostrix
//! contract, ported to this crate's crossterm-free stack — raw ANSI
//! bytes + termios via the classic external utilities):
//!
//! 1. ANSI restore sequence — every optional mode off that a TUI may
//!    have left on (synchronized output 2026, bracketed paste 2004,
//!    focus 1004, the full mouse family, alt screen 1049, kitty
//!    keyboard pop) plus the sane-defaults resets (SGR, scroll
//!    region, charset, autowrap, cursor visible).
//! 2. ANSI reset sequence — the restore plus cursor home, clear
//!    screen, clear scrollback (the destructive layer; wipes the
//!    frozen frame AND the scrollback so the shell starts clean).
//! 3. `stty sane` — the kernel-side termios restore. This is the
//!    layer ANSI bytes can never reach: raw mode (echo off, ICANON
//!    off, ISIG off) lives in the kernel's terminal driver state,
//!    and only a termios write fixes it.
//! 4. `reset` — the external full terminal reset utility (modes,
//!    tab stops, terminal init string).
//! 5. `tput reset` — the terminfo-driven alternative for systems
//!    with tput but not reset.
//!
//! Every layer is best-effort — the terminal may be in a state where
//! some operations do not work; the goal is maximum recovery
//! probability, not perfection. The external utilities run only
//! when a stdio stream is a terminal (piping them at a file or pipe
//! is noise); the ANSI layers ride stdout unconditionally (bytes
//! into a pipe are inert).
//!
//! Module placement: a crate-root module (src/term_reset.rs), not
//! a child of the ebpf-gated terminal tree (whose session machinery
//! is the eagle-eyes graph). The rescue owns no BPF machinery —
//! ANSI bytes + stty — and must exist in EVERY build: a featureless
//! binary can still rescue a terminal some other app broke. A plain
//! module (no #[path] wiring) is also what the test-tree discipline
//! gate expects: every #[path] wiring under src/ resolves into
//! test/, and this file's own pins hang off it the ordinary way
//! (test/terminal/reset_tests.rs).
//!
//! Mode-direction contract (pinned in test/terminal/reset_tests.rs
//! and enforced by the mouse-contract source scan): every DEC
//! private mode this file touches is restored toward its DEFAULT
//! direction — modes whose default is OFF are only ever sent `l`
//! (2026 sync, 2004 paste, 1004 focus, the mouse family, 1049 alt
//! screen), and modes whose default is ON are only ever sent `h`
//! (25 cursor visible, 7 autowrap). The reset never ENABLES an
//! optional mode; it is pure restoration.

use std::io::{IsTerminal, Write};

/// The best-effort ANSI restore sequence: every optional mode off a
/// TUI may have left on, plus the sane-defaults resets. Non-destructive
/// — does NOT clear the screen or scrollback (that is
/// [`TERMINAL_RESET_SEQUENCE`], the nuclear tier).
///
/// Mode inventory and why each earns its byte:
/// - `\x1b[0m` — SGR reset (twice, bookending): a mid-frame death
///   leaves the pen mid-color/bold; the pen state is terminal-global
///   and survives the alt-screen switch, so without this the user's
///   shell prompt renders in the dead monitor's last color.
/// - `\x1b[?2026l` — synchronized output off. A stuck sync mode makes
///   the terminal buffer ALL output and render nothing: the exact
///   "frozen screen" breakage. The most valuable single byte pair a
///   modern rescue can send.
/// - `\x1b[?2004l` — bracketed paste off (vim/less kill leaves it on;
///   the shell then eats paste markers into commands).
/// - `\x1b[?1004l` — focus reporting off.
/// - `\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l` — the
///   full mouse family off: the monitor's trio (1000/1002/1006) plus
///   the two legacy encodings a foreign app may have taken (1003
///   any-motion, 1015 urxvt). A terminal stuck in 1003 floods stdin
///   with mouse-move reports on every pointer twitch.
/// - `\x1b[?1049l` — leave the alternate screen: the frozen frame
///   goes away, the user's real screen (and their shell prompt)
///   returns.
/// - `\x1b[<1u` — kitty keyboard protocol pop (one level). A no-op on
///   terminals that never pushed; inert bytes on non-compliant ones.
///   A dead kitty-protocol app otherwise turns every arrow key into
///   CSI-u garbage at the shell.
/// - `\x1b[r` — scroll region back to full screen (DECSTBM reset).
/// - `\x1b(B` — charset back to US ASCII.
/// - `\x1b[?7h` — autowrap ON (a TUI that disabled wrap leaves every
///   long line stamping over itself).
/// - `\x1b[?25h` — cursor visible again.
pub(crate) const TERMINAL_RESTORE_SEQUENCE: &str = concat!(
    "\x1b[0m",
    "\x1b[?2026l",
    "\x1b[?2004l",
    "\x1b[?1004l",
    "\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l",
    "\x1b[?1049l",
    "\x1b[<1u",
    "\x1b[r",
    "\x1b(B",
    "\x1b[?7h",
    "\x1b[?25h",
    "\x1b[0m",
);

/// The destructive terminal reset sequence (the nuclear tier):
/// [`TERMINAL_RESTORE_SEQUENCE`] plus cursor home, clear screen,
/// clear scrollback, cursor home again, SGR reset — wiping the
/// visible screen AND the scrollback buffer so the shell starts
/// clean. Used only by [`reset_terminal_emergency`] for a terminal
/// already known broken; the byte-repeat of the restore sequence is
/// deliberate (prefix-pinned in test/terminal/reset_tests.rs), the
/// cosmostrix shape.
pub(crate) const TERMINAL_RESET_SEQUENCE: &str = concat!(
    "\x1b[0m",
    "\x1b[?2026l",
    "\x1b[?2004l",
    "\x1b[?1004l",
    "\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l",
    "\x1b[?1049l",
    "\x1b[<1u",
    "\x1b[r",
    "\x1b(B",
    "\x1b[?7h",
    "\x1b[?25h",
    "\x1b[0m",
    "\x1b[H\x1b[2J\x1b[3J\x1b[H",
    "\x1b[0m",
);

/// Emergency terminal reset — the five-layer recovery behind
/// `zelynic --reset-terminal` (NIGHT-hunt-31). Silent by contract:
/// the fixed terminal IS the feedback (the shell prompt returning on
/// a clean screen says more than any status line could — and a line
/// printed after `tput reset` would land on the fresh screen as
/// residue the user did not ask for).
///
/// No privileges required and none asked for: the reset touches only
/// the caller's own terminal (ANSI bytes out, termios via stty) —
/// it is a rescue, and a rescue that demanded root would fail in the
/// one moment it is needed (the broken-terminal user can barely
/// type, let alone authenticate).
pub(crate) fn reset_terminal_emergency() {
    let mut out = std::io::stdout();

    // Layer 1: the ANSI restore sequence (every optional mode off,
    // sane defaults back). Written BEFORE the clears so the clears
    // render in a known pen/charset state.
    let _ = out.write_all(TERMINAL_RESTORE_SEQUENCE.as_bytes());
    let _ = out.flush();

    // Layer 2: the ANSI reset sequence (clear screen + scrollback).
    let _ = out.write_all(TERMINAL_RESET_SEQUENCE.as_bytes());
    let _ = out.flush();

    // Layers 3-5: the external utilities, only where a terminal can
    // receive them. `stty sane` is the critical one — raw mode lives
    // in the kernel's termios state and no ANSI byte reaches it.
    if std::io::stdin().is_terminal() || out.is_terminal() {
        let _ = std::process::Command::new("stty").arg("sane").status();
        let _ = std::process::Command::new("reset").status();
        let _ = std::process::Command::new("tput").arg("reset").status();
    }
}

// NIGHT-hunt-31: the reset pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like
// the terminal tree's own pins.
#[cfg(test)]
#[path = "../test/terminal/reset_tests.rs"]
mod reset_tests;
