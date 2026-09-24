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

// ── The terminal background query (NIGHT-boost-26) ────────────────────────
//
// The monitor's background follows the TERMINAL, not a builtin
// palette: a grey-themed terminal renders a grey eagle-eyes frame.
// The mechanism is the standard OSC 11 request (`ESC ] 11 ; ? BEL`)
// answered with `ESC ] 11 ; rgb:RRRR/GGGG/BBBB BEL` (or ST-terminated,
// `rgba:` with an alpha leg). The query runs ONCE per session, after
// raw mode is live (the answer is not newline-terminated, so it can
// only be read with canonical mode off) and after the alt screen is
// entered (the answer reflects the terminal the frame will paint
// on). A 100 ms poll timeout bounds the wait — a terminal that
// does not answer (dumb, muxer without passthrough) gets `None`
// and the frame renders exactly as before: no background escape
// at all, the terminal's own default showing through.

/// The OSC 11 answer's poll budget: mainstream local terminals
/// answer in single-digit milliseconds; the ceiling only bounds
/// the wait for terminals that never answer.
const OSC_REPLY_BUDGET_MS: i32 = 100;

/// Query the terminal's background color over fd 0/1. Requires raw
/// mode (the caller enters it first); returns the RGB triple on a
/// parseable answer, `None` on silence, garbage, or IO failure.
/// Residual reply bytes are drained so the monitor loop never sees
/// them as input.
pub(crate) fn query_terminal_bg() -> Option<(u8, u8, u8)> {
    // SAFETY: write(2) of the 8-byte OSC query on fd 1.
    let query = b"\x1b]11;?\x07";
    if unsafe { libc::write(1, query.as_ptr().cast(), query.len()) } < 0 {
        return None;
    }
    // SAFETY: poll(2) on fd 0 for readability, one entry, bounded.
    let mut pfd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut pfd, 1, OSC_REPLY_BUDGET_MS) };
    if ready <= 0 {
        return None;
    }
    let mut buf = [0u8; 96];
    // SAFETY: read(2) on fd 0 into a valid buffer; raw mode's
    // VMIN=0/VTIME=0 makes this the immediate answer the poll saw.
    let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    let parsed = parse_osc_11_rgb(&buf[..n as usize]);
    // Drain any residual reply bytes (a split answer, a trailing
    // DSR): a zero-budget poll then a read, both best-effort — the
    // ESC-led leftovers are inert input anyway (the q-only drain
    // contract), this is tidiness, not correctness.
    let mut drain = [0u8; 64];
    let mut pfd2 = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pfd2, 1, 10) } > 0 {
        // SAFETY: read(2) on fd 0 into a valid buffer, discarded.
        let _ = unsafe { libc::read(0, drain.as_mut_ptr().cast(), drain.len()) };
    }
    parsed
}

/// Parse the OSC 11 color answer: find `rgb:` (or `rgba:`, alpha
/// ignored), read the slash-separated hex channels (1-4 digits
/// each, the xterm convention), scale each to u8 by its own digit
/// width. Pure — pinned in test/terminal/raw_tests.rs.
fn parse_osc_11_rgb(bytes: &[u8]) -> Option<(u8, u8, u8)> {
    // `rgba:` is 5 bytes, `rgb:` is 4 — the payload starts past the
    // colon of whichever token answered (kitty's alpha leg rides at
    // the tail and is dropped by taking three channels).
    let (start, skip) = match find_subslice(bytes, b"rgba:") {
        Some(i) => (i, 5),
        None => (find_subslice(bytes, b"rgb:")?, 4),
    };
    let rest = &bytes[start + skip..];
    let end = rest
        .iter()
        .position(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'/'))
        .unwrap_or(rest.len());
    let body = std::str::from_utf8(&rest[..end]).ok()?;
    let mut parts = body.split('/');
    let mut channels = [0u8; 3];
    for slot in &mut channels {
        let hex = parts.next()?;
        *slot = scale_hex_to_u8(hex)?;
    }
    Some((channels[0], channels[1], channels[2]))
}

/// Find `needle` in `hay`, returning its start index.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Scale one OSC channel (1-4 hex digits, full-scale by digit
/// width) to u8, rounding half-away: `ffff` -> 255, `80` -> 128,
/// `f` -> 255, `c` -> 204.
fn scale_hex_to_u8(hex: &str) -> Option<u8> {
    if hex.is_empty() || hex.len() > 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    let max = (1u32 << (4 * hex.len() as u32)) - 1;
    Some(((value as f64 / max as f64) * 255.0).round() as u8)
}

#[cfg(test)]
// NIGHT-boost-26: the OSC 11 parser pins — pure-function contract
// over the answer shapes real terminals send.
#[path = "../../test/terminal/raw_tests.rs"]
mod raw_tests;
