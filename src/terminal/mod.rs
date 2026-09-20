// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Terminal alternate screen mode — like htop/vim/less.
//!
//! Uses the terminal's alternate screen buffer (xterm ESC[?1049h).
//! Content is rendered on the alt screen; when zelynic exits, the
//! original screen is restored — no trace left in scrollback.
//!
//! NIGHT-improve-7 terminal contract (supersedes the NIGHT-strict-1
//! mouse clause): the monitor TAKES the pointer. Box mode is a
//! live dashboard of private data — cgroup names, process IDs,
//! remote endpoints — and the owner rule is that none of it is
//! copyable while the box runs. Enabling mouse tracking
//! (1000 press/release + 1002 button-drag + 1006 SGR encoding)
//! moves the pointer into the application: click-drag no longer
//! selects terminal text, middle-click no longer pastes into the
//! monitor's stdin, and Ctrl+Shift+C has no selection to copy.
//! Every mode the enter touches is restored on exit (mouse modes
//! off first, then alt screen off, cursor shown). Two honest
//! caveats, documented not hidden: (a) every mainstream terminal
//! still offers a Shift+click bypass around application mouse
//! tracking — that is a terminal-side feature no escape sequence
//! can switch off; (b) pasted bytes that do reach stdin are drained
//! like any other non-q input (NIGHT-hunt-16 q-only quit contract
//! unchanged). The contract is pinned two ways in
//! test/terminal/mouse_contract_tests.rs: a byte-level pin over the
//! sequences below, and a source-tree scan that fails if any
//! `\x1b[?` mode outside {1049, 25, 1000, 1002, 1006} ever appears
//! in src/.
//!
//! NIGHT-improve-2: the monitor loop renders through the diff-based
//! engine ([`DiffScreen`], see `diff.rs`) — only rows that changed
//! since the previous frame are emitted, in ONE write syscall. The
//! former per-refresh full redraw (screen wipe + every line + one
//! flush per line) is gone.

mod diff;

pub use diff::{DiffScreen, RawStdout};

use anyhow::Result;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Alt-screen enter sequence — the exact bytes `AltScreen::enter()`
/// writes (NIGHT-strict-1 pinned the plumbing; NIGHT-improve-7 added
/// the mouse modes). A named constant so the byte-level pin in
/// `test/terminal/mouse_contract_tests.rs` can hold the contract:
/// alternate screen on, cursor hidden, mouse tracking on (press/release
/// 1000 + button-drag 1002 + SGR encoding 1006) — and NOTHING ELSE
/// (no any-motion 1003 flood, no focus 1004, no bracketed paste
/// 2004).
const ALT_ENTER: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1002h\x1b[?1006h";

/// Alt-screen exit sequence — the exact bytes `Drop for AltScreen`
/// writes: mouse tracking off (reverse order of the enter), back to
/// the main screen, cursor visible again. A full restore of every
/// mode `ALT_ENTER` touched, and nothing more.
const ALT_EXIT: &[u8] = b"\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?1049l\x1b[?25h";

/// Terminal guard — enters alt screen + raw mode, restores on drop.
pub struct AltScreen {
    original: nix::sys::termios::Termios,
}

impl AltScreen {
    pub fn enter() -> Result<Self> {
        use nix::sys::termios::*;
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

/// Check if q was pressed (non-blocking).
///
/// Exit contract (NIGHT-hunt-16): 'q' is THE quit key — the ONLY one.
/// The former ESC quit is gone because a standalone ESC byte is
/// indistinguishable from the head of every escape sequence (arrows,
/// mouse, scroll) and quit on ESC made any stray sequence a coin flip.
/// Ctrl+C (0x03) no longer quits either (NIGHT-hunt-16 supersedes the
/// hunt-12 interrupt clause): mainstream TUI tools (htop, vim, less)
/// treat Ctrl+C as an interrupt, not an exit, and the single-key
/// contract keeps the documented behavior unambiguous — the title bar
/// says "q quit" and nothing else quits. Ctrl+C, ESC, and every
/// multi-byte escape sequence are drained, never treated as quit. If
/// a wedged terminal ever swallows the 'q' byte, recovery from
/// another shell is `pkill zelynic` followed by `stty sane`.
pub fn should_quit() -> bool {
    let mut buf = [0u8; 16];
    if let Ok(n) = io::stdin().read(&mut buf) {
        if n > 0 {
            // Check first byte
            let first = buf[0];

            // 'q' — the only quit byte (NIGHT-hunt-16).
            if first == b'q' {
                return true;
            }

            // Everything else: drain (Ctrl+C, standalone ESC, and
            // multi-byte escape sequences alike — none of them quit).
        }
    }
    false
}

/// Run an alternate-screen loop with the diff-based render engine
/// (NIGHT-improve-2).
///
/// `render` fills a reusable line vector with the frame's logical
/// content (title bar, header, rows, footer — exactly what the
/// renderer used to println). The engine diffs that against the
/// previous frame's shadow and writes the minimal ANSI stream: idle
/// frames emit nothing, sparse changes reposition only dirty rows,
/// dense diffs rewrite sequentially, and a resize resets fully.
/// One write syscall per frame, zero screen wipes (no ESC[2J — the
/// VTE scrollback hazard the cosmic dragon engine documented).
///
/// Exits on q — the ONLY quit key (NIGHT-hunt-16: always live, no
/// duration timer, no ESC quit, no Ctrl+C quit).
/// On exit, the original terminal screen is restored — no trace in scrollback.
pub fn run_alt<F>(refresh_interval: Duration, mut render: F)
where
    F: FnMut(&mut Vec<String>),
{
    let mut run = |screen: &mut DiffScreen, lines: &mut Vec<String>| {
        let mut last_render = Instant::now() - refresh_interval; // render immediately on first iteration
        loop {
            if should_quit() {
                break;
            }

            if last_render.elapsed() >= refresh_interval {
                lines.clear();
                render(lines);
                let mut stdout = RawStdout;
                screen.emit(lines, &mut stdout);
                last_render = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    };

    let _screen = match AltScreen::enter() {
        Ok(g) => g,
        Err(_) => {
            // Fallback: simple loop (no alt screen). Same diff
            // engine, same key contract (NIGHT-hunt-16): 'q' must
            // quit here too — the contract is q-only on BOTH paths.
            // When stdout is not a TTY the ANSI stream is inert
            // bytes in the pipe — the same class of output the
            // pre-diff fallback produced with its screen clears.
            let mut screen = DiffScreen::new();
            let mut lines: Vec<String> = Vec::with_capacity(48);
            run(&mut screen, &mut lines);
            return;
        }
    };

    let mut screen = DiffScreen::new();
    let mut lines: Vec<String> = Vec::with_capacity(48);
    run(&mut screen, &mut lines);
}

// NIGHT-strict-1: the monitor terminal-contract pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired across
// trees exactly like the diff-engine pins in diff.rs.
#[cfg(test)]
#[path = "../../test/terminal/mouse_contract_tests.rs"]
mod mouse_contract_tests;
