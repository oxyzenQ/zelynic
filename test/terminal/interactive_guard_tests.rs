// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Interactive-stdio guard pins (NIGHT-boost-28) — the monitor
//! refuses to start unless BOTH stdio streams are terminals.
//!
//! The hazard these pins hold closed: `sudo zelynic ee | grep` —
//! stdin stays the real terminal while stdout is the pipe, so the
//! old enter path (tcgetattr on stdin alone) SUCCEEDED, raw-moded
//! the real terminal (echo off, ISIG off — Ctrl+C dead), pushed
//! every alt-screen byte into the pipe, and spun the monitor
//! forever holding root. The refusal sits on stdout; the stdin twin
//! keeps redirected input (`ee < /dev/null`) from painting frames
//! on the MAIN screen with keys that can never arrive.
//!
//! These pins run piped (cargo's harness), so the refusal branch is
//! the exercised one — the TTY branch is the owner-host battery's
//! lane (the same discipline the kill-tui rows carry).

use super::{require_interactive, AltScreen};

/// The gate refuses a piped stdout with the teaching message: the
/// refusal must name the monitor, the stream, and the scripted
/// alternative (`status --print-json`) — an operator who pipes by
/// habit gets the fix in the same breath as the refusal.
#[test]
fn require_interactive_refuses_piped_stdout() {
    let err = require_interactive()
        .expect_err("piped stdout must refuse")
        .to_string();
    assert!(
        err.contains("stdout is not a terminal"),
        "the refusal must name stdout, got: {err}"
    );
    assert!(
        err.contains("status --print-json"),
        "the refusal must teach the scripted alternative, got: {err}"
    );
}

/// `AltScreen::enter` is the structural backstop: it refuses on a
/// piped stdout BEFORE any termios call or chrome byte — the error
/// propagates (the NIGHT-boost-28 contract: enter failures are
/// honest errors, never silently swallowed into a degraded session).
#[test]
fn alt_screen_enter_refuses_piped_stdout_before_termios() {
    let err = match AltScreen::enter() {
        Err(e) => e.to_string(),
        Ok(_guard) => panic!(
            "enter must refuse a piped stdout; a screen was entered \
             and will restore on drop"
        ),
    };
    assert!(
        err.contains("stdout is not a terminal"),
        "the enter backstop must carry the stdout refusal, got: {err}"
    );
}
