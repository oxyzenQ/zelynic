// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The terminal layer's raw-fd IO helpers (NIGHT-ultimate-2 split:
//! diff.rs sat at the owner's 500-line cap, and the raw wrappers
//! are their own contract — one file per contract, the guard_tests
//! precedent). Three residents, unchanged from their diff.rs era:
//!
//! - [`winsize`] — the ONE canonical TIOCGWINSZ probe (NIGHT-hunt-15
//!   consolidated three copies into one); the limiter's
//!   terminal_width/terminal_height and the render engine's
//!   FrameGeometry both route through it, so the unsafe ioctl
//!   surface exists exactly once.
//! - [`probe_size`] — winsize plus the classic 80x24 fallback for
//!   non-TTY sinks (the diff engine's own sizing probe).
//! - [`RawStdout`] — stdout as a raw fd writer, ONE `write(2)` per
//!   frame, bypassing the std LineWriter that would split the
//!   emission batch at every embedded newline (the per-line syscall
//!   churn the diff engine exists to remove).

use std::io::Write;

/// The canonical terminal size probe: returns (cols, rows) when the
/// ioctl succeeds and reports a non-degenerate size; None otherwise
/// (not a TTY — piped output, tests, benchmark harnesses).
pub(crate) fn winsize() -> Option<(u16, u16)> {
    use libc::{ioctl, winsize, STDOUT_FILENO, TIOCGWINSZ};
    let mut ws: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ioctl with TIOCGWINSZ writes to a valid winsize struct.
    let ret = unsafe { ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

/// winsize with the 80x24 fallback for non-TTY sinks (the benchmark
/// harness and the diff tests pin deterministic sizes through the
/// size-injectable cores instead).
pub(crate) fn probe_size() -> (usize, usize) {
    match winsize() {
        Some((cols, rows)) => (cols as usize, rows as usize),
        None => (80, 24),
    }
}

/// Stdout as a raw fd writer: ONE `write(2)` per frame, bypassing
/// the std LineWriter (which would split the batch at every
/// embedded newline — the exact per-line syscall churn this engine
/// exists to remove).
pub struct RawStdout;

impl Write for RawStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: write(2) on fd 1 with a valid buffer + length; the
        // return value is the transferred count. EPIPE surfaces as
        // an io error, which the diff engine records as the sink
        // death verdict (NIGHT-ultimate-2) — matching the
        // println_safe broken-pipe contract, never a panic.
        let n = unsafe { libc::write(1, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // raw fd: nothing is buffered
    }
}
