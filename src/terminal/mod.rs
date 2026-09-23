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
//! off first, then alt screen off, cursor shown).
//!
//! NIGHT-improve-8 selection guard: mouse tracking leaves exactly
//! one hole — the terminal's own Shift+click bypass, a terminal-side
//! feature no escape sequence can switch off. The counter-physics:
//! every mainstream terminal clears a selection the moment its
//! cells are rewritten (why `watch` output can never be selected).
//! So while the box runs, the loop re-emits the whole frame on a
//! fixed beat ([`SELECTION_GUARD_BEAT`]): a shift-selection cannot
//! outlive one beat, and every copy path that needs a live
//! selection — Ctrl+Shift+C, right-click Copy — finds nothing to
//! copy. The beat is always whole-frame
//! (`DiffScreen::force_repaint`, the reset emission path): a
//! partial rewrite would leave the unrewritten rows selectable,
//! exactly the "still can copy some text" the owner reported.
//! Honest physics boundaries, documented not hidden: (a) an
//! X11-style terminal that mirrors a COMPLETED selection into the
//! PRIMARY clipboard at button release can still catch what
//! re-accumulates after the last beat — terminal-side, beyond any
//! Linux application's reach; (b) a Select All + Copy fired inside
//! a single beat lands before the next rewrite; (c) pasted bytes
//! that do reach stdin are drained like any other inert input
//! (NIGHT-hunt-16 q-only quit contract unchanged; NIGHT-boost-18
//! added the t theme key — an action key, never a quit key; its
//! uppercase twin T was retired by NIGHT-engrave-2 at the owner's
//! "better only simple 't'" call: one key, one direction, modulo
//! wraparound). The
//! contract is
//! pinned three ways in test/terminal/mouse_contract_tests.rs
//! (byte-level pins over the sequences below, the beat value and
//! the loop scheduler, and a source-tree scan that fails if any
//! `\x1b[?` mode outside {1049, 25, 1000, 1002, 1006} ever appears
//! in src/), plus the whole-frame repaint pins in
//! test/terminal/diff_tests.rs.
//!
//! NIGHT-improve-2: the monitor loop renders through the diff-based
//! engine ([`DiffScreen`], see `diff.rs`) — only rows that changed
//! since the previous frame are emitted, in ONE write syscall. The
//! former per-refresh full redraw (screen wipe + every line + one
//! flush per line) is gone.

mod diff;

pub use diff::{DiffScreen, RawStdout};
// NIGHT-hunt-15: the canonical TIOCGWINSZ probe lives in the diff
// module (the terminal layer's raw-IO home); the limiter's
// terminal_width/terminal_height and the render engine both route
// through it, so the unsafe ioctl surface exists exactly once.
pub(crate) use diff::winsize;

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

/// Selection-guard beat (NIGHT-improve-8): the cadence on which the
/// monitor loop re-emits the whole frame while the box runs, so no
/// terminal-side selection can outlive one beat. Mouse tracking
/// cannot reach the terminal's Shift+click bypass (terminal-side,
/// no escape sequence switches it off) — but a selection dies the
/// moment its cells are rewritten, and 100 ms sits under the
/// fastest deliberate human select-then-copy round trip
/// (double-click plus an immediate Ctrl+Shift+C lands around
/// 200 ms). Cost: one whole-frame rewrite per beat (~1.4 KB on
/// the classic 80x24 frame), pinned by the diff tests. The loop
/// wakes at 50 ms granularity, so a beat lands within 100..150 ms
/// wall time.
const SELECTION_GUARD_BEAT: Duration = Duration::from_millis(100);

/// What the monitor loop owes the terminal this iteration
/// (NIGHT-improve-8). A due `Render` outranks a due `Guard` —
/// fresh content is also the strongest selection killer — but a
/// render never resets the guard clock: a diff-only frame leaves
/// the unchanged rows untouched, and those rows must still die on
/// the next beat (the exact hole the guard exists to close).
/// NIGHT-boost-14 added the `resized` term: a geometry change is
/// due immediately — the layout must not wait out the refresh
/// interval (up to 60s at `--interval 60`) while the frame sits at
/// a stale size.
enum Beat {
    /// A fresh frame: poll + render closure + diff emit.
    Render,
    /// A selection-guard repaint: re-emit the last frame in full.
    Guard,
    /// Nothing owed — sleep.
    Sleep,
}

/// The monitor loop's scheduler, pure so the contract pins can
/// hold it. `guard` is false on the non-TTY fallback path: a pipe
/// has no selection machinery, and flooding it with whole-frame
/// beats would only multiply the output volume (the benchmark
/// harness and CI run exactly there). `resized` forces a Render
/// beat regardless of the refresh clock (NIGHT-boost-14).
fn next_beat(
    last_render: Instant,
    last_guard: Instant,
    refresh: Duration,
    guard: bool,
    resized: bool,
) -> Beat {
    if last_render.elapsed() >= refresh || resized {
        Beat::Render
    } else if guard && last_guard.elapsed() >= SELECTION_GUARD_BEAT {
        Beat::Guard
    } else {
        Beat::Sleep
    }
}

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

/// The q-only quit decision for one drained input chunk
/// (NIGHT-hunt-16, pinned by NIGHT-boost-14): 'q' as the FIRST byte
/// quits; everything else — Ctrl+C (0x03), standalone ESC, the head
/// of every multi-byte escape sequence (arrows, mouse SGR, scroll)
/// — never quits. 'q' deeper inside a chunk does not count either:
/// an escape sequence may legally carry any printable byte in its
/// body, so only the leading byte speaks.
pub(crate) fn quit_from_chunk(buf: &[u8]) -> bool {
    matches!(buf.first(), Some(b'q'))
}

/// What one drained input chunk asks the monitor to do
/// (NIGHT-boost-18; the uppercase twin retired by NIGHT-engrave-2):
/// 'q' quits, 't' cycles the theme forward — one key, one
/// direction, modulo wraparound. Everything else is inert, on the
/// same first-byte-only contract as the quit decision: a 't' riding
/// inside a mouse SGR payload never cycles anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputAction {
    /// Nothing asked — drain and carry on.
    None,
    /// 'q' as the first byte: leave the monitor.
    Quit,
    /// 't': cycle the theme one step forward.
    ThemeNext,
}

/// Classify one drained input chunk by its leading byte. The quit
/// decision delegates to the pinned [`quit_from_chunk`] primitive —
/// one contract, one place, both pinned.
pub(crate) fn input_action_from_chunk(buf: &[u8]) -> InputAction {
    if quit_from_chunk(buf) {
        return InputAction::Quit;
    }
    match buf.first() {
        Some(b't') => InputAction::ThemeNext,
        _ => InputAction::None,
    }
}

/// Drain pending input (non-blocking) and classify the leading
/// byte. The generalization of the old `should_quit`: same read,
/// same first-byte rule, three recognized keys instead of one.
///
/// Exit contract (NIGHT-hunt-16): 'q' is THE quit key — the ONLY one.
/// The former ESC quit is gone because a standalone ESC byte is
/// indistinguishable from the head of every escape sequence (arrows,
/// mouse, scroll) and quit on ESC made any stray sequence a coin flip.
/// Ctrl+C (0x03) no longer quits either (NIGHT-hunt-16 supersedes the
/// hunt-12 interrupt clause): mainstream TUI tools (htop, vim, less)
/// treat Ctrl+C as an interrupt, not an exit, and the single-key
/// contract keeps the documented behavior unambiguous — the title bar
/// says "q quit" and nothing else quits. NIGHT-boost-18 adds the t
/// theme cycle (an action key, never a quit key; its uppercase twin
/// T was retired by NIGHT-engrave-2 — the owner wanted one simple
/// key). Ctrl+C, ESC, and every
/// multi-byte escape sequence are drained, never treated as actions.
/// If a wedged terminal ever swallows the 'q' byte, recovery from
/// another shell is `pkill zelynic` followed by `stty sane`.
pub(crate) fn read_input() -> InputAction {
    let mut buf = [0u8; 16];
    if let Ok(n) = io::stdin().read(&mut buf) {
        if n > 0 {
            return input_action_from_chunk(&buf[..n]);
        }
    }
    InputAction::None
}

/// The monitor loop shared by every session shape (NIGHT-boost-25
/// lifted it out of `run_alt` when the [`Monitor`] session type
/// arrived): q-only quit, t theme cycle, 50ms wakes with the
/// resize-reactive force render, the selection-guard beats where a
/// selection can exist, and the diff-based emission — one render
/// closure, one screen, one reusable line vector.
fn run_loop<F: FnMut(&mut Vec<String>)>(
    screen: &mut DiffScreen,
    lines: &mut Vec<String>,
    guard: bool,
    refresh_interval: Duration,
    mut render: F,
) {
    // NIGHT-improve-8: the guard runs only where a selection can
    // exist — the TTY path. The pipe fallback passes guard=false
    // (see next_beat).
    let mut last_render = Instant::now() - refresh_interval; // render immediately on first iteration
    let mut last_guard = Instant::now();
    // NIGHT-boost-14 resize reactivity: the geometry the last
    // render targeted. Every 50ms wake probes the terminal size
    // (one ioctl — the canonical winsize) and a change forces a
    // Render beat within one wake, so resizing is felt at once
    // even at `--interval 60` instead of at the next refresh
    // tick. The render closure and the diff engine re-probe on
    // their own; this loop-level probe only decides WHEN.
    let mut last_geo = winsize();
    loop {
        // NIGHT-boost-18: one drain, two recognized keys — q
        // quits, t cycles the theme (the uppercase twin retired
        // by NIGHT-engrave-2). The cycle result feeds the beat
        // scheduler's force flag below: same-wake repaint.
        let theme_switched = match read_input() {
            InputAction::Quit => break,
            InputAction::ThemeNext => {
                crate::output::theme::cycle(1);
                true
            }
            InputAction::None => false,
        };

        let geo = winsize();
        let force = geo != last_geo || theme_switched;
        match next_beat(last_render, last_guard, refresh_interval, guard, force) {
            Beat::Render => {
                lines.clear();
                render(lines);
                let mut stdout = RawStdout;
                screen.emit(lines, &mut stdout);
                last_render = Instant::now();
                last_geo = geo;
            }
            // The copy guard: re-emit the last frame in full,
            // so any terminal-side selection (Shift+click hands
            // those clicks to the terminal, not to us) dies
            // within one beat. Always whole-frame — a partial
            // rewrite would leave the untouched rows
            // selectable, the owner's exact complaint.
            Beat::Guard => {
                let mut stdout = RawStdout;
                screen.force_repaint(lines, &mut stdout);
                last_guard = Instant::now();
            }
            Beat::Sleep => {}
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A live-monitor terminal session opened with the smooth-loading
/// prelude (NIGHT-boost-25, the owner's masterclass loading audit).
///
/// The problem the type exists to fix: `sudo zelynic ee` used to run
/// the whole BPF load on the MAIN screen — the terminal sat frozen
/// blank for the verifier's duration, then the alt screen switched
/// and the full bright frame painted in one burst. Dead air, then a
/// flash: the eye reads that transition as flashy and straining.
///
/// The fix inverts the order. [`Monitor::open`] enters the alt screen
/// and paints the caller's prelude frame (the loading composition)
/// the moment the command starts, and the BPF load then runs UNDER
/// that frame — the load reads as the product loading, not the
/// terminal freezing. The prelude rides the SAME DiffScreen the live
/// loop uses, so it becomes the shadow's frame 0 and the first live
/// frame diffs against it: because the monitor frame fills the
/// terminal exactly, the emission rides the diff engine's sequential
/// path — every row rewrites IN PLACE with no clear and no blank
/// flash, the unchanged rows land their identical bytes (the same
/// glyphs, invisible to the eye), and the one row that changed is
/// the note (`loading observer…` becomes `waiting for traffic…`).
/// A load failure simply drops the session — ALT_EXIT restores the
/// main screen and the branded error prints on it.
///
/// On a pipe (`AltScreen::enter` fails) the session opens silent:
/// the prelude is never composed (no chrome bytes into the pipe) and
/// the loop runs the fallback contract (no selection guard) exactly
/// as the pre-Monitor era did — the benchmark harness and CI live
/// there.
///
/// The alt screen (and every mode ALT_ENTER touched) restores when
/// the session drops: mouse modes off, main screen back, cursor
/// visible — unchanged from the `run_alt` era.
pub struct Monitor {
    screen: DiffScreen,
    lines: Vec<String>,
    /// The alt-screen guard, held for its Drop (ALT_EXIT restores
    /// the main screen when the session ends). Underscore-named: a
    /// pure RAII field is never read, only dropped.
    _alt: Option<AltScreen>,
    guard: bool,
}

impl Monitor {
    /// Open the session: enter the alt screen and paint the prelude
    /// frame. `prelude(width, height)` composes at the open-time
    /// probe's real terminal size and is invoked ONLY on the TTY path
    /// — a pipe never sees chrome bytes. An empty prelude (the `-v`
    /// trace-first sequence) paints nothing but still primes the
    /// diff screen, so the first live frame owns the whole screen.
    pub fn open<P: FnOnce(usize, usize) -> Vec<String>>(prelude: P) -> Self {
        match AltScreen::enter() {
            Ok(alt) => {
                let (w, h) = match winsize() {
                    Some((cols, rows)) => (cols as usize, rows as usize),
                    None => (80, 24),
                };
                let mut session = Monitor {
                    screen: DiffScreen::new(),
                    lines: prelude(w, h),
                    _alt: Some(alt),
                    guard: true,
                };
                // The prelude IS frame 0: emit through the session's
                // own diff screen so the first live frame diffs
                // against it (the morph) instead of painting over a
                // clear.
                let mut stdout = RawStdout;
                session.screen.emit(&mut session.lines, &mut stdout);
                session
            }
            Err(_) => Monitor {
                screen: DiffScreen::new(),
                lines: Vec::with_capacity(48),
                _alt: None,
                guard: false,
            },
        }
    }

    /// Run the live loop. Consumes the session; the alt screen
    /// restores when it drops. Same contract the monitor loop always
    /// carried: exits on q (the ONLY quit key, NIGHT-hunt-16), t
    /// cycles the theme, and the render closure refills the line
    /// vector each beat — the diff engine emits only what changed.
    pub fn run<F: FnMut(&mut Vec<String>)>(mut self, refresh_interval: Duration, render: F) {
        run_loop(
            &mut self.screen,
            &mut self.lines,
            self.guard,
            refresh_interval,
            render,
        );
        // self drops here: AltScreen::drop writes ALT_EXIT and
        // restores the main screen.
    }
}

// NIGHT-strict-1: the monitor terminal-contract pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired across
// trees exactly like the diff-engine pins in diff.rs.
#[cfg(test)]
#[path = "../../test/terminal/mouse_contract_tests.rs"]
mod mouse_contract_tests;
