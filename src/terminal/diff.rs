// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Diff-based render engine for the alt-screen monitors
//! (NIGHT-improve-2) — zelynic's line-granularity adaptation of the
//! cosmic dragon engine (cosmostrix,
//! github.com/oxyzenQ/cosmostrix —
//! src/engine/cosmic_dragon_engine/terminal/{mod,draw,last_frame}.rs).
//!
//! Owner problem: the monitor loop cleared the WHOLE alt screen
//! (ESC[2J + ESC[H) and reprinted every line on every refresh — a
//! full redraw per frame, one write+flush syscall PER LINE, and a
//! terminal-side full-screen wipe, even when nothing changed. For a
//! focus monitor that runs for minutes that is wasted energy, wasted
//! I/O, and visible flicker.
//!
//! Dragon-engine principles ported here:
//! - **Shadow** (their `LastFrame`): the previous frame's lines are
//!   kept; only rows that differ are emitted.
//! - **Idle fast path**: zero dirty rows → zero bytes, zero syscalls
//!   (their zero-emit idle resync).
//! - **One write syscall per frame**: the whole emission batch goes
//!   out through a single `write(2)` (their 64 KiB buffered single
//!   `write_all`; here a direct fd write — no std LineWriter to
//!   split the buffer at embedded newlines).
//! - **Crossover between sparse and sequential emission**: they used
//!   a fixed 12.5% dirty-cell ratio because a cell is 1 char, so the
//!   MoveTo-vs-rewrite math collapses to a ratio. zelynic rows are
//!   ~50-80 chars, so the crossover is computed BYTE-EXACTLY from
//!   the actual line lengths every frame — no magic number.
//! - **Never ESC[2J**: a 2J inside the alternate screen can set an
//!   internal flag on VTE-based terminals that wipes the MAIN
//!   screen's scrollback on exit (the hazard cosmostrix documented
//!   in their draw path). Resets use ESC[H + ESC[J — a
//!   cursor-anchored erase with the same visual result and no
//!   scrollback side effect. The previous renderer emitted 2J every
//!   frame inside the alt screen; this engine never emits it at all.
//! - **Resize = width change → full reset**: the probe is one
//!   TIOCGWINSZ ioctl per frame (the render layer already probes
//!   twice per frame for layout); no SIGWINCH plumbing, no stale
//!   geometry.
//! - **Tall regime (rows >= terminal height) is top-aligned and
//!   scroll-free (NIGHT-improve-6)**: the emission paints the first
//!   min(rows, height) lines and never ends with a linefeed. The
//!   pre-improve-6 engine ended every tall frame with a bottom-row
//!   LF — one screen scroll per refresh, the title bar drifting off
//!   on every terminal at or under the render cap (the classic
//!   80x24 included) — and the idle path was disabled, forcing a
//!   full repaint per frame even when nothing changed.
//!
//! - **Selection guard (NIGHT-improve-8)**: `force_repaint`
//!   re-emits the last frame in full — the engine half of the
//!   monitor's copy guard. Terminals clear a selection the moment
//!   its cells are rewritten, so the loop's guard beat rides the
//!   reset emission (HOME + erase-below + every row) to kill
//!   terminal-side selections — Shift+click hands those clicks to
//!   the terminal, not to the application. A partial rewrite
//!   would leave the untouched rows selectable, so the beat is
//!   always whole-frame; implemented as the shadow flipped back
//!   out plus `ever_drawn = false`, the beat travels the exact
//!   same tested emission path a resize takes.
//!
//! Line granularity (vs their cell grid) is the honest adaptation:
//! zelynic's monitors are styled text tables, not per-cell scenes. A
//! row diff is unicode-width-safe by construction — whole lines are
//! written and the cursor is only ever positioned at row starts, so
//! double-width glyphs never desync the column math. Embedded ANSI
//! style bytes are part of the line string, so a style change is a
//! row change, exactly like a content change.

use std::io::Write;
use std::mem;

/// Escape prefixes/bodies used by the emission paths.
const HOME: &[u8] = b"\x1b[H"; // cursor to row 1, col 1 (3 bytes)
const ERASE_BELOW: &[u8] = b"\x1b[J"; // erase cursor..end of screen (3 bytes)
const ERASE_EOL: &[u8] = b"\x1b[K"; // erase cursor..end of line (3 bytes)

/// The one canonical TIOCGWINSZ probe (NIGHT-hunt-15: this used to
/// exist three times — twice in the ebpf-gated limiter formatters,
/// once here — so the unsafe ioctl surface and the fallback
/// semantics could drift apart; now it lives once in the ungated
/// terminal layer where every feature graph can reach it). Returns
/// (cols, rows) when the ioctl succeeds and reports a non-degenerate
/// size; None otherwise (not a TTY — piped output, tests, benchmark
/// harnesses).
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

/// The engine's own probe: the canonical winsize with the classic
/// 80x24 fallback for non-TTY sinks (the benchmark harness and the
/// diff tests pin deterministic sizes through emit_at instead).
fn probe_size() -> (usize, usize) {
    match winsize() {
        Some((cols, rows)) => (cols as usize, rows as usize),
        None => (80, 24),
    }
}

/// Decimal digit count of `n` (>= 1 for n == 0).
fn dec_len(n: usize) -> usize {
    let mut digits = 1;
    let mut v = n / 10;
    while v > 0 {
        digits += 1;
        v /= 10;
    }
    digits
}

/// Append `ESC[{row};1H` (MoveTo row, column 1; rows are 1-based).
fn push_move_to(buf: &mut Vec<u8>, row: usize) {
    buf.extend_from_slice(b"\x1b[");
    push_decimal(buf, row);
    buf.extend_from_slice(b";1H");
}

/// Allocation-free decimal append.
fn push_decimal(buf: &mut Vec<u8>, n: usize) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut v = n;
    while v > 0 {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf.extend_from_slice(&digits[i..]);
}

/// The diff-based screen: shadow + emission buffer, reused frame to
/// frame (the dragon engine's allocation-reuse discipline — the
/// Vec capacities survive the whole session, only lengths churn).
pub struct DiffScreen {
    /// Previous frame's lines (the shadow). Swapped with the
    /// caller's line vector on every emit, so both buffers stay warm
    /// and no per-frame String cloning happens.
    prev: Vec<String>,
    /// Terminal width the shadow was rendered for. A mismatch (the
    /// resize case) forces a full reset emit.
    width: usize,
    /// False until the first emit — the physical screen state is
    /// unknown, so the first frame must paint everything (the
    /// dragon engine's force_full_emit invariant).
    ever_drawn: bool,
    /// Number of leading frame rows physically on screen. Equals the
    /// visible row count of the last emission — in the tall regime
    /// that is clipped to the viewport (NIGHT-improve-6), so rows at
    /// or beyond this index have never been painted and are dirty by
    /// definition. Inert in the normal regime, where it always
    /// equals the previous frame's full row count.
    painted: usize,
    /// Emission buffer, one `write(2)` per frame.
    buf: Vec<u8>,
}

impl Default for DiffScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffScreen {
    pub fn new() -> Self {
        DiffScreen {
            prev: Vec::new(),
            width: 0,
            ever_drawn: false,
            painted: 0,
            buf: Vec::with_capacity(8 * 1024),
        }
    }

    /// Emit one frame: diff `lines` against the shadow and write the
    /// minimal ANSI stream to `sink` in a single `write_all`. Probes
    /// the terminal size (one ioctl) for the resize check. Returns
    /// the number of bytes the emission consists of (0 = idle frame,
    /// nothing written).
    ///
    /// `lines` is swapped with the internal shadow: after the call
    /// the caller's vector holds the PREVIOUS frame's strings —
    /// clear it and refill for the next frame (both `run_alt` and
    /// the benchmark harness do exactly that). This keeps the two
    /// vectors' allocations warm with zero per-frame cloning.
    pub fn emit(&mut self, lines: &mut Vec<String>, sink: &mut dyn Write) -> usize {
        let (w, h) = probe_size();
        self.emit_at(w, h, lines, sink)
    }

    /// Size-injectable core (the benchmark harness pins a
    /// deterministic 80x40 so the strategy choice is a property of
    /// the engine, not of the piped-fallback probe).
    pub fn emit_at(
        &mut self,
        width: usize,
        height: usize,
        lines: &mut Vec<String>,
        sink: &mut dyn Write,
    ) -> usize {
        let reset = !self.ever_drawn || width != self.width;
        self.width = width;
        self.ever_drawn = true;

        let n = lines.len();
        let shrunk = n < self.prev.len();

        // Tall regime: the frame meets/exceeds the terminal height, so
        // absolute row positioning would clamp to the bottom row and a
        // per-row LF at the viewport bottom would scroll the screen on
        // every frame. The emission is therefore sequential and
        // TOP-ALIGNED: only the first `visible` rows are painted and
        // the final one carries no trailing LF (NIGHT-improve-6 — the
        // former trailing LF scrolled the title bar off one line per
        // refresh on every terminal at or under the render cap, the
        // classic 80x24 included; the render layer caps the frame at
        // exactly the terminal height there, so `visible` covers the
        // whole frame, and only sub-8-row terminals actually clip).
        let seq_forced = n >= height;
        let visible = n.min(height);

        // A row is dirty when it differs from the shadow, when it is
        // new, or when it was never physically painted (clipped away
        // by a shorter viewport earlier — the `painted` term). That
        // term is inert in the normal regime (painted always equals
        // the previous frame's full row count there) but forces a
        // repaint of exactly the rows a taller terminal just revealed.
        let dirty: Vec<bool> = (0..visible)
            .map(|i| reset || i >= self.prev.len() || i >= self.painted || lines[i] != self.prev[i])
            .collect();
        let dirty_count = dirty.iter().filter(|d| **d).count();

        // Idle fast path: nothing changed, no reset, no shrink. Zero
        // bytes, zero syscalls — the "waiting for traffic" monitor
        // holds its frame for free at EVERY height (NIGHT-improve-6
        // opened the tall regime: the frame is on screen and stable,
        // so holding it costs nothing; the old engine repainted the
        // full frame on every refresh there).
        if dirty_count == 0 && !reset && !shrunk {
            mem::swap(&mut self.prev, lines);
            return 0;
        }

        // Tail clear: the frame shrank — rows below it still hold
        // the previous frame's content. Erase from the first row
        // below the frame to the end of screen. Guarded to a valid
        // row (n < height also implies seq_forced is false, so the
        // two branches below agree on when this is safe).
        let tail_clear = shrunk && n < height;

        // Maximal runs of consecutive dirty rows (row-major, so a
        // run is emitted with ONE MoveTo and LF-separated rows —
        // the dragon engine's contiguous-run batching).
        let mut runs: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        while i < visible {
            if dirty[i] {
                let start = i;
                while i < visible && dirty[i] {
                    i += 1;
                }
                runs.push((start, i));
            } else {
                i += 1;
            }
        }

        // Byte-exact crossover. Sequential: home + every row
        // (content + erase-EOL + LF) + tail. Sparse: per run a MoveTo
        // (5 + row digits) + every DIRTY row (content + erase-EOL +
        // LF) + tail. The dragon engine's 12.5% ratio assumed 1-char
        // cells; with ~50-80-char rows the exact costs are one
        // integer add each, so no ratio is needed.
        let rows_cost = |range: (usize, usize)| -> usize {
            (range.0..range.1)
                .map(|r| lines[r].len() + ERASE_EOL.len() + 1)
                .sum()
        };
        let tail_cost = if tail_clear {
            5 + dec_len(n + 1) + ERASE_BELOW.len()
        } else {
            0
        };
        let seq_cost = HOME.len()
            + if reset { ERASE_BELOW.len() } else { 0 }
            + rows_cost((0, visible))
            + tail_cost;
        let sparse_cost = runs
            .iter()
            .map(|&r| 5 + dec_len(r.0 + 1) + rows_cost(r))
            .sum::<usize>()
            + tail_cost;

        self.buf.clear();
        if !reset && !seq_forced && sparse_cost < seq_cost {
            // Sparse path: skip every clean row; position once per
            // dirty run.
            for &(start, end) in &runs {
                push_move_to(&mut self.buf, start + 1);
                for line in lines.iter().take(end).skip(start) {
                    self.buf.extend_from_slice(line.as_bytes());
                    self.buf.extend_from_slice(ERASE_EOL);
                    self.buf.push(b'\n');
                }
            }
        } else {
            // Sequential path (dense diff, first frame, resize, or
            // the tall regime): home, then every VISIBLE row in
            // order. In the tall regime the emission stops at the
            // viewport bottom without a trailing LF — the
            // pre-improve-6 engine ended every frame with a
            // bottom-row LF, scrolling the screen one line per
            // refresh. In the normal regime the trailing LF after
            // the final row is preserved byte-exactly (it lands on a
            // spare row below the frame and never scrolls).
            self.buf.extend_from_slice(HOME);
            if reset {
                self.buf.extend_from_slice(ERASE_BELOW);
            }
            for (i, line) in lines.iter().take(visible).enumerate() {
                self.buf.extend_from_slice(line.as_bytes());
                self.buf.extend_from_slice(ERASE_EOL);
                if !seq_forced || i + 1 < visible {
                    self.buf.push(b'\n');
                }
            }
        }
        if tail_clear {
            push_move_to(&mut self.buf, n + 1);
            self.buf.extend_from_slice(ERASE_BELOW);
        }

        let emitted = self.buf.len();
        if emitted > 0 {
            // Broken-pipe contract (println_safe parity): emission
            // errors are discarded — a short-reader kills the
            // monitor quietly, never a panic.
            let _ = sink.write_all(&self.buf);
        }
        self.painted = visible;
        mem::swap(&mut self.prev, lines);
        emitted
    }

    /// Copy-guard repaint (NIGHT-improve-8): re-emit the last
    /// painted frame IN FULL, bypassing the diff. Terminals clear a
    /// selection the moment its cells are rewritten (the physics
    /// that makes `watch` output unselectable) — the monitor loop
    /// calls this on a fixed cadence so a terminal-side selection
    /// (the Shift+click bypass hands those clicks to the terminal,
    /// not the application) cannot outlive one beat, and every
    /// copy path that needs a live selection finds nothing to copy.
    /// The repaint is always whole-frame: a partial rewrite would
    /// leave the unrewritten rows selectable — the owner's exact
    /// complaint.
    ///
    /// Mechanism: flip the shadow back into the caller's buffer,
    /// clear `ever_drawn`, and let [`DiffScreen::emit_at`] take its
    /// reset path (HOME + erase-below + every row — which also
    /// erases below a short frame, killing selections there too).
    /// The double swap is an involution: the caller's vector and
    /// the shadow end where they started, so run_alt's
    /// clear-and-refill cycle is untouched. Returns the emitted
    /// byte count, 0 when no frame has been painted yet (nothing
    /// to protect).
    pub fn force_repaint(&mut self, lines: &mut Vec<String>, sink: &mut dyn Write) -> usize {
        let (w, h) = probe_size();
        // A resize is in flight when the probed width moved since
        // the last render: repainting old-width lines at the new
        // width could wrap the final visible row and scroll — the
        // exact hazard the tall-regime rules exist to prevent. The
        // next render tick owns the resize (its emit resets fully),
        // so the guard stands down instead of guessing.
        if w != self.width {
            return 0;
        }
        self.force_repaint_at(w, h, lines, sink)
    }

    /// Size-injectable core of the guard repaint (the emit/emit_at
    /// discipline: contract pins and harnesses drive deterministic
    /// sizes instead of the piped-fallback probe).
    pub fn force_repaint_at(
        &mut self,
        width: usize,
        height: usize,
        lines: &mut Vec<String>,
        sink: &mut dyn Write,
    ) -> usize {
        if !self.ever_drawn {
            return 0; // nothing painted, nothing to protect
        }
        mem::swap(&mut self.prev, lines);
        self.ever_drawn = false; // the reset path IS the whole-frame repaint
        self.emit_at(width, height, lines, sink)
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
        // an io error and is discarded by the caller, matching the
        // println_safe broken-pipe contract.
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

#[cfg(test)]
// NIGHT-hunt-17: test files live under the repo's single test/ tree
// (cosmostrix Pattern C), so the pins are #[path]-wired across trees
// instead of sitting as a sibling file next to the engine.
#[path = "../../test/terminal/diff_tests.rs"]
mod diff_tests;

#[cfg(test)]
// NIGHT-improve-8: the selection-guard engine pins — split into
// their own file when they pushed diff_tests past the 500-LOC cap
// (one file per contract, the same #[path] discipline as identity/).
#[path = "../../test/terminal/guard_tests.rs"]
mod guard_tests;
