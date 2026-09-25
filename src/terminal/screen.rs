// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The alt-screen contract (NIGHT-boost-28 split, the raw.rs
//! precedent — mod.rs sat at the owner's 500-LOC cap): the enter and
//! exit byte sequences, the termios guard, and the interactive-stdio
//! gate that decides whether a session may take the terminal at
//! all. One file per contract, the same discipline that split
//! diff.rs's raw-IO helpers into raw.rs.

use anyhow::Result;
use std::io::{self, Write};

/// Alt-screen enter sequence — the exact bytes `AltScreen::enter()`
/// writes (NIGHT-strict-1 pinned the plumbing; NIGHT-improve-7 added
/// the mouse modes). A named constant so the byte-level pin in
/// `test/terminal/mouse_contract_tests.rs` can hold the contract:
/// alternate screen on, cursor hidden, mouse tracking on (press/release
/// 1000 + button-drag 1002 + SGR encoding 1006) — and NOTHING ELSE
/// (no any-motion 1003 flood, no focus 1004, no bracketed paste
/// 2004).
pub(super) const ALT_ENTER: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1002h\x1b[?1006h";

/// Alt-screen exit sequence — the exact bytes `Drop for AltScreen`
/// writes: SGR reset, mouse tracking off (reverse order of the
/// enter), back to the main screen, cursor visible again. A full
/// restore of every mode `ALT_ENTER` touched, and nothing more.
/// The NIGHT-hunt-31 leading `ESC[0m` resets the SGR pen state:
/// the pen is terminal-global and survives the alt-screen switch,
/// so a death mid-frame (or a clean exit right after a styled row)
/// would otherwise leave the user's shell prompt rendering in the
/// monitor's last color until something else reset it.
pub(super) const ALT_EXIT: &[u8] = b"\x1b[0m\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?1049l\x1b[?25h";

/// The interactive-stdio gate (NIGHT-boost-28): the monitor is a
/// TTY application — raw mode, alt screen, mouse tracking, 50ms key
/// drains — and it refuses to start when either stdio stream is not
/// a terminal. Called from the eagle-eyes handler BEFORE root/BPF
/// work (cheap pure check, the teaching message surfaces through the
/// branded error renderer) and from [`AltScreen::enter`] as the
/// structural backstop, so the two can never drift apart.
///
/// The hazard the owner hit live: `sudo zelynic ee | grep` — stdin
/// stays the real terminal while stdout is the pipe, so the old
/// tcgetattr-only path SUCCEEDED, raw-moded the real terminal (echo
/// off, ISIG off — Ctrl+C dead) while every alt-screen byte and
/// frame painted into the pipe, and the loop spun forever holding
/// root, eBPF, and a /proc cadence: a garbled terminal plus a hidden
/// root process. The refusal must sit on STDOUT; the stdin twin
/// covers redirected input (`ee < /dev/null`) — keys can never
/// arrive, and without the twin the frames would paint on the MAIN
/// screen because no alt screen could be entered.
pub(crate) fn require_interactive() -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "eagle-eyes is an interactive monitor and stdout is not a terminal \
             (piped or redirected) — run it directly in a terminal; \
             for scripts use 'zelynic status --print-json'"
        );
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "eagle-eyes is an interactive monitor and stdin is not a terminal \
             (redirected) — the q/t keys would never arrive; \
             run it with the keyboard attached"
        );
    }
    Ok(())
}

/// Terminal guard — enters alt screen + raw mode, restores on drop.
pub struct AltScreen {
    original: nix::sys::termios::Termios,
}

impl AltScreen {
    pub fn enter() -> Result<Self> {
        use nix::sys::termios::*;
        // NIGHT-boost-28: the interactive-stdio gate, the structural
        // backstop — the CLI's eagle-eyes handler refuses earlier
        // (before root/BPF work); this copy protects any future
        // monitor surface wired straight to the session type.
        crate::terminal::require_interactive()?;
        let stdin = io::stdin();
        let original = tcgetattr(&stdin)?;

        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG);
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        tcsetattr(&stdin, SetArg::TCSANOW, &raw)?;

        // Enter alternate screen + hide cursor + take the pointer,
        // exactly the pinned ALT_ENTER bytes: ESC[?1049h (save cursor
        // + switch to alt screen + clear it), ESC[?25l (hide cursor),
        // then mouse tracking 1000/1002/1006 so click-drag selects
        // nothing and no paste lands in stdin (NIGHT-improve-7; the
        // drained SGR mouse events are inert input — see the module
        // contract above).
        io::stdout().write_all(ALT_ENTER)?;
        io::stdout().flush()?;

        Ok(AltScreen { original })
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        use nix::sys::termios::*;
        let stdin = io::stdin();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &self.original);

        // Leave the monitor state, exactly the pinned ALT_EXIT bytes:
        // mouse tracking off first (1006/1002/1000, reverse of the
        // enter), then ESC[?1049l (back to main screen + restore
        // cursor) and ESC[?25h (show cursor) — selection and paste
        // are the terminal's again the moment the box is gone.
        let _ = io::stdout().write_all(ALT_EXIT);
        let _ = io::stdout().flush();
    }
}

#[cfg(test)]
// NIGHT-boost-28: the interactive-stdio guard pins — the monitor
// refuses piped/redirected stdio before any terminal state is
// taken (the `sudo zelynic ee | grep` fatal: raw mode on the real
// terminal + chrome bytes into the pipe + a forever root loop).
#[path = "../../test/terminal/interactive_guard_tests.rs"]
mod interactive_guard_tests;
