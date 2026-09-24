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
// `rgba:` with an alpha leg). The open path asks once, after raw
// mode is live (the answer is not newline-terminated, so it can
// only be read with canonical mode off) and after the alt screen is
// entered (the answer reflects the terminal the frame will paint
// on). A 100 ms poll timeout bounds the wait — a terminal that
// does not answer (dumb, muxer without passthrough) gets `None`
// and the frame renders exactly as before: no background escape
// at all, the terminal's own default showing through.
//
// NIGHT-boost-32: one ask is not a follow — a terminal whose
// background changes mid-session (alacritty's live config reload
// is the owner's repro) would leave the frame painting the stale
// open-time color forever, exactly the "still fixed black" the
// owner filed. The live layer below re-asks on a fixed cadence
// and absorbs the answer from the input stream the monitor loop
// already drains — zero blocking (an SSH-slow answer costs no
// stall at all), zero extra wakes, and the reply can never land
// as a keystroke.

/// The OSC 11 answer's poll budget: mainstream local terminals
/// answer in single-digit milliseconds; the ceiling only bounds
/// the wait for terminals that never answer.
const OSC_REPLY_BUDGET_MS: i32 = 100;

/// The OSC 11 request bytes (the open-path ask and the live ask
/// write the same query).
const OSC_QUERY: &[u8] = b"\x1b]11;?\x07";

/// The OSC 11 answer's head: `ESC ] 1 1 ;`. Distinct from every
/// sequence a terminal sends unsolicited (mouse SGR is `ESC [`,
/// CSI replies are `ESC [`), so a chunk starting with this shape
/// is an answer to our own ask — never a key.
const OSC_REPLY_HEAD: &[u8] = b"\x1b]11;";

/// How long the live tracker stays patient for a split answer:
/// one ask's reply may land across several 50 ms wakes (and an
/// SSH-slow answer may take hundreds of milliseconds). Past the
/// patience the partial is dropped — the next ask re-arms. The
/// bound also caps how long garbled input can delay key
/// classification (the first-byte contract resumes fresh).
const BG_ASK_PATIENCE: std::time::Duration = std::time::Duration::from_millis(500);

/// The live ask's cadence (NIGHT-boost-32, fast since 34): one
/// 8-byte query per interval, independent of the refresh interval
/// — a config reload follows within one ask whatever `--interval`
/// runs. 250 ms, the NIGHT-boost-34 answer to "the background color
/// is changed but slow": the follow latency budget is one cadence
/// plus one 50 ms wake, so a terminal-side live reload (itself
/// 100-500 ms of editor + terminal work) lands inside the same
/// eyeblink the repaint composes in. The cost is 4 asks/second
/// tail-ward — 32 B/s of queries out, a reply only when the color
/// actually sits in flight — and a silent terminal (dumb, muxer
/// without passthrough) pays only the writes, never a stall: the
/// answer rides the input drain the 50 ms wake already owns. A
/// slower cadence would buy nothing measurable and cost the exact
/// sluggishness the owner filed.
pub(crate) const BG_ASK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The partial-answer cap: a real OSC 11 reply is at most ~32
/// bytes; anything longer without a terminator is garbage, not a
/// reply — drop it and classify the chunk's own bytes.
const BG_PARTIAL_CAP: usize = 64;

/// Query the terminal's background color over fd 0/1. Requires raw
/// mode (the caller enters it first); returns the RGB triple on a
/// parseable answer, `None` on silence, garbage, or IO failure.
/// Residual reply bytes are drained so the monitor loop never sees
/// them as input.
pub(crate) fn query_terminal_bg() -> Option<(u8, u8, u8)> {
    // SAFETY: write(2) of the 8-byte OSC query on fd 1.
    if unsafe { libc::write(1, OSC_QUERY.as_ptr().cast(), OSC_QUERY.len()) } < 0 {
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

// ── The live background follow (NIGHT-boost-32) ───────────────────────────
//
// [`BgAsk`] is the monitor loop's tracker: `send()` writes the
// 8-byte query and arms the patience; `absorb()` takes every
// drained input chunk, consumes an OSC 11 answer when one rides
// the stream (across chunks), and hands the leftover bytes back
// for key classification. The answer color is returned to the
// caller — the theme layer owns storage; the tracker owns only
// the byte plumbing.

/// The live background ask's input tracker.
pub(crate) struct BgAsk {
    /// A partial answer, accumulated across 50 ms wakes while the
    /// patience holds.
    partial: Vec<u8>,
    /// When the in-flight ask's patience expires.
    deadline: Option<std::time::Instant>,
}

impl BgAsk {
    /// A tracker with nothing in flight.
    pub(crate) fn new() -> Self {
        Self {
            partial: Vec::new(),
            deadline: None,
        }
    }

    /// Send one ask: the same 8-byte OSC 11 query the open path
    /// writes, best-effort on fd 1 (a dead sink surfaces through
    /// the frame emission's own check, never here). Re-arms the
    /// patience and restarts the partial — a late answer to a
    /// previous ask still parses on arrival.
    pub(crate) fn send(&mut self) {
        self.partial.clear();
        self.deadline = Some(std::time::Instant::now() + BG_ASK_PATIENCE);
        // SAFETY: write(2) of the 8-byte OSC query on fd 1,
        // best-effort — the return value is deliberately ignored.
        unsafe {
            libc::write(1, OSC_QUERY.as_ptr().cast(), OSC_QUERY.len());
        }
    }

    /// Feed one drained input chunk. Returns the key action for
    /// the bytes that are NOT the answer (the first-byte contract,
    /// applied to the leftover — a `q` riding behind a reply tail
    /// still quits, the exact swallow the old fixed-16-byte drain
    /// could take) and the answer's color when a reply completed
    /// on this chunk. A reply whose payload parses to nothing
    /// returns no color — the caller keeps the last known good.
    pub(crate) fn absorb(
        &mut self,
        chunk: &[u8],
        now: std::time::Instant,
    ) -> (super::InputAction, Option<(u8, u8, u8)>) {
        // Expired patience: the partial is garbage by now — drop
        // it and classify this chunk fresh.
        if let Some(deadline) = self.deadline {
            if now > deadline {
                self.partial.clear();
                self.deadline = None;
            }
        }
        // A chunk continues a pending answer; a fresh chunk starts
        // one only when it leads with the reply head. Anything
        // else is plain input — the pre-boost-32 classification.
        let continues = !self.partial.is_empty();
        let starts = chunk.starts_with(OSC_REPLY_HEAD);
        if !continues && !starts {
            return (super::input_action_from_chunk(chunk), None);
        }
        let mut work = std::mem::take(&mut self.partial);
        work.extend_from_slice(chunk);
        if let Some((len, color)) = reply_front(&work) {
            self.deadline = None;
            let leftover = &work[len..];
            let action = super::input_action_from_chunk(leftover);
            return (action, color);
        }
        // No terminator yet: keep accumulating while the cap holds.
        // Past the cap this is not a reply — drop it and classify
        // the chunk's own leading byte (the keys case).
        if work.len() <= BG_PARTIAL_CAP {
            self.partial = work;
            (super::InputAction::None, None)
        } else {
            self.deadline = None;
            (super::input_action_from_chunk(chunk), None)
        }
    }
}

/// One complete OSC 11 reply: its total length (through its
/// terminator) and its parsed color (None when the payload is not
/// a color — the shape completed, the content did not).
type ReplyFront = (usize, Option<(u8, u8, u8)>);

/// Find one complete OSC 11 answer at the FRONT of `bytes`. Pure —
/// pinned in test/terminal/raw_tests.rs together with the tracker.
fn reply_front(bytes: &[u8]) -> Option<ReplyFront> {
    if !bytes.starts_with(OSC_REPLY_HEAD) {
        return None;
    }
    // The terminator: BEL (0x07) or ST (ESC \). Scan past the head.
    let body = &bytes[OSC_REPLY_HEAD.len()..];
    let end = body
        .iter()
        .position(|b| *b == 0x07 || *b == b'\x1b')
        .map(|i| i + OSC_REPLY_HEAD.len() + if body[i] == 0x07 { 1 } else { 2 })?;
    let color = parse_osc_11_rgb(&bytes[..end]);
    Some((end, color))
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
