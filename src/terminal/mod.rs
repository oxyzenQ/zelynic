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
//! (`DiffScreen::force_repaint`): a partial rewrite would leave the
//! unrewritten rows selectable, exactly the "still can copy some
//! text" the owner reported. Since NIGHT-hunt-26 the beat's
//! rewrite carries NO screen erase — the rewrite itself is the
//! selection killer, and an erase between renders opened the blank
//! window the owner read as an intermittent flash on long-running
//! monitors (see diff.rs for the mechanism). Honest physics
//! boundaries, documented not hidden: (a) an X11-style terminal
//! that mirrors a COMPLETED selection into the PRIMARY clipboard
//! at button release can still catch what re-accumulates after
//! the last beat — terminal-side, beyond any Linux application's
//! reach; (b) a Select All + Copy fired inside a single beat lands
//! before the next rewrite; (c) pasted bytes that do reach stdin
//! are drained like any other inert input (NIGHT-hunt-16 q-only
//! quit contract unchanged; NIGHT-boost-18 added the t theme key —
//! an action key, never a quit key; its uppercase twin T was
//! retired by NIGHT-engrave-2 at the owner's "better only simple
//! 't'" call: one key, one direction, modulo wraparound). The
//! contract is pinned three ways in
//! test/terminal/mouse_contract_tests.rs (byte-level pins over the
//! sequences below, the beat value and the loop scheduler, and a
//! source-tree scan that fails if any `\x1b[?` mode outside
//! {1049, 25, 1000, 1002, 1006} ever appears in src/ — the ONE
//! exception being the emergency reset contract src/term_reset/mod.rs,
//! whose default-restoring mode set {2026, 2004, 1004, 7, 1003,
//! 1015} is honored only inside that file), plus the whole-frame
//! repaint pins in test/terminal/diff_tests.rs.
//!
//! NIGHT-improve-2: the monitor loop renders through the diff-based
//! engine ([`DiffScreen`], see `diff.rs`) — only rows that changed
//! since the previous frame are emitted, in ONE write syscall. The
//! former per-refresh full redraw (screen wipe + every line + one
//! flush per line) is gone.

//! NIGHT-boost-28 (the interactive-stdio guard): the monitor is a
//! TTY application — raw mode, alt screen, mouse tracking, 50ms
//! key drains — and it now REFUSES to start when either stdio
//! stream is not a terminal. The hazard the owner hit live:
//! `sudo zelynic ee | grep` — stdin stays the real terminal while
//! stdout is the pipe, so the old enter path put the REAL terminal
//! into raw mode (echo off, ISIG off — Ctrl+C dead) while every
//! alt-screen byte and frame painted into the pipe, and the loop
//! spun forever holding root, eBPF, and a /proc cadence: a garbled
//! terminal plus a hidden root process, the worst failure shape a
//! critical-infra tool can take. `require_interactive()` is the one
//! gate both the CLI handler and [`AltScreen::enter`] call (the
//! handler refuses BEFORE root/BPF work; enter is the structural
//! backstop for any future monitor surface), and the stdin twin
//! covers redirected input (`ee < /dev/null`): keys can never
//! arrive, and without it the frames would paint on the MAIN screen
//! (no alt screen could be entered). One-shot report surfaces
//! (status, list-apps, the enforcement verbs, doctor) stay pipe-safe
//! by design: broken-pipe-safe writers, `--print-json` scripting,
//! no terminal state — the audit found no other interactive
//! surface in the tree.

mod beat;
mod diff;
mod guard;
mod raw;
mod screen;

// NIGHT-improve-29 (the 500-LOC cap split, the screen.rs precedent):
// the beat scheduler contract — the selection-guard cadence, the
// Beat enum, next_beat — lives in beat.rs; the names stay
// resolvable from this module (the path-wired mouse pins import
// them from `super::`, and run_loop uses them below).
pub(crate) use beat::{beat_epoch, next_beat, Beat};
// The beat constant itself is beat.rs-internal on the runtime path
// (only next_beat reads it); the mouse pins assert it, so the name
// rides this module only in test builds.
#[cfg(test)]
pub(crate) use beat::SELECTION_GUARD_BEAT;
// The pure epoch twin: production reaches it through beat_epoch;
// only the boot-edge pins name it directly, so the re-export rides
// test builds only (the -D warnings contract).
#[cfg(test)]
pub(crate) use beat::beat_epoch_at;

// NIGHT-boost-33: the violent-death terminal guard (kill -9, pkill)
// lives in guard.rs — the screen.rs one-file-per-contract precedent.

// NIGHT-boost-28 (the 500-LOC cap split): the alt-screen contract —
// enter/exit bytes, the termios guard, the interactive-stdio gate —
// lives in screen.rs; the private use keeps the names resolvable
// from the path-wired pins (they import from `super::`, this
// module).
// require_interactive re-exports pub(crate): the eagle-eyes handler
// calls it by the terminal:: path (NIGHT-boost-28).
pub(crate) use screen::require_interactive;
// The ALT byte contracts stay name-reachable for the path-wired
// mouse pins (they import from `super::` — this module).
use screen::AltScreen;
#[cfg(test)]
use screen::{ALT_ENTER, ALT_EXIT};

pub use diff::DiffScreen;
pub use raw::RawStdout;
// NIGHT-hunt-15: the canonical TIOCGWINSZ probe lives in the
// terminal layer's raw-IO home (raw.rs since NIGHT-ultimate-2, the
// diff.rs cap split); the limiter's terminal_width/terminal_height
// and the render engine both route through it, so the unsafe ioctl
// surface exists exactly once.
pub(crate) use raw::winsize;

use anyhow::Result;
use std::io::{self, Read};
use std::time::{Duration, Instant};

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

/// Drain pending input (non-blocking) and classify the leading byte
/// of what is NOT a background answer. The generalization of the
/// old `should_quit`: same read, same first-byte rule, three
/// recognized keys instead of one. NIGHT-boost-32: the live ask's
/// tracker consumes an OSC 11 reply riding the chunk (across
/// chunks, within its patience) and the LEFTOVER bytes classify
/// under the same first-byte contract — a `q` behind a reply tail
/// still quits, the swallow the old fixed-16-byte drain could
/// take. A completed answer parks in the theme layer; the bool
/// half of the return says the stored color CHANGED (the caller
/// forces the follow repaint).
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
/// another shell is `pkill zelynic` — the guard (NIGHT-boost-33)
/// restores the terminal itself; and since NIGHT-hunt-31 the
/// in-place recovery is `zelynic --reset-terminal` (the emergency
/// five-layer reset, see term_reset at the crate root) — no second
/// shell, no re-opened terminal. `stty sane` stays the manual
/// fallback.
pub(crate) fn drain_input(ask: &mut raw::BgAsk) -> (InputAction, bool) {
    let mut buf = [0u8; 64];
    let n = io::stdin().read(&mut buf).unwrap_or(0);
    let (action, reply) = ask.absorb(&buf[..n], Instant::now());
    let changed = match reply {
        Some(rgb) => crate::output::theme::set_terminal_bg(Some(rgb)),
        None => false,
    };
    (action, changed)
}

/// The monitor loop shared by every session shape (NIGHT-boost-25
/// lifted it out of `run_alt`): q-only quit, t theme cycle, 50ms
/// wakes with the resize-reactive force render, the guard beats,
/// the diff-based emission, the live background follow
/// (NIGHT-boost-32) — and the quiet death on a dead sink
/// (NIGHT-ultimate-2): a failed emission ends the session (the
/// loop breaks, the alt screen restores via Drop), so a piped
/// monitor whose reader left can never spin forever holding root,
/// eBPF, and a /proc walk cadence.
fn run_loop<F: FnMut(&mut Vec<String>)>(
    screen: &mut DiffScreen,
    lines: &mut Vec<String>,
    guard: bool,
    refresh_interval: Duration,
    mut render: F,
) {
    // NIGHT-improve-8: the guard runs only where a selection can
    // exist — the TTY path. Always true from the session since
    // NIGHT-boost-28 (Monitor::open succeeds only on an interactive
    // stdio pair); the false arm remains the pure function's
    // pin-only domain (see next_beat).
    let mut last_render = crate::terminal::beat_epoch(refresh_interval); // render immediately on first iteration
    let mut last_guard = Instant::now();
    // NIGHT-boost-14 resize reactivity: the geometry the last
    // render targeted. Every 50ms wake probes the terminal size
    // (one ioctl — the canonical winsize) and a change forces a
    // Render beat within one wake, so resizing is felt at once
    // even at `--interval 60` instead of at the next refresh
    // tick. The render closure and the diff engine re-probe on
    // their own; this loop-level probe only decides WHEN.
    // NIGHT-hunt-26: a TRANSIENT probe failure (a mid-resize 0x0
    // report, an ioctl hiccup) holds the last known geometry for
    // the force decision — a None-vs-Some flip used to force a
    // wrong-geometry render whose reset flash the next wake undid.
    // A real resize still lands within one wake of the probe
    // reporting the new size.
    let mut last_geo = winsize();
    // NIGHT-boost-32: the live background ask — one 8-byte query
    // per BG_ASK_INTERVAL, the answer absorbed by the input drain
    // (zero stall: a slow answer rides the stream, never a poll).
    // A changed answer parks in the theme layer and forces the
    // repaint below — a mid-session background change (alacritty's
    // live config reload) is followed within one ask.
    let mut bg_ask = raw::BgAsk::new();
    let mut last_ask = crate::terminal::beat_epoch(raw::BG_ASK_INTERVAL);
    loop {
        // NIGHT-boost-18: one drain, two recognized keys — q
        // quits, t cycles the theme (the uppercase twin retired
        // by NIGHT-engrave-2). The cycle result and the live
        // background answer both feed the beat scheduler's force
        // flag below: same-wake repaint.
        let (action, bg_switched) = drain_input(&mut bg_ask);
        let theme_switched = match action {
            InputAction::Quit => break,
            InputAction::ThemeNext => {
                crate::output::theme::cycle(1);
                true
            }
            InputAction::None => false,
        };

        // Sticky geometry (NIGHT-hunt-26): a None probe stands down
        // for one wake — the screen holds its last frame until the
        // probe recovers, no forced wrong-size render.
        let geo = winsize().or(last_geo);
        let force = geo != last_geo || theme_switched || bg_switched;
        match next_beat(last_render, last_guard, refresh_interval, guard, force) {
            Beat::Render => {
                lines.clear();
                render(lines);
                let mut stdout = RawStdout;
                screen.emit(lines, &mut stdout);
                // The quiet death (NIGHT-ultimate-2): a failed
                // emission — the reader of a piped monitor closed,
                // the sink filled — ends the session instead of
                // spinning forever on discarded writes. The check
                // sits AFTER the beat bookkeeping-independent emit so
                // one bad frame is enough; a healthy write costs
                // one bool load.
                if screen.sink_dead() {
                    break;
                }
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
                // Same quiet-death check as the render beat: a
                // guard rewrite into a dead sink is a dead
                // monitor (NIGHT-ultimate-2).
                if screen.sink_dead() {
                    break;
                }
                last_guard = Instant::now();
            }
            Beat::Sleep => {}
        }

        // NIGHT-boost-32: the live background ask rides after the
        // beat — one best-effort 8-byte write; the answer, whenever
        // it lands, is absorbed by the next wake's drain. A silent
        // terminal costs only the write.
        if last_ask.elapsed() >= raw::BG_ASK_INTERVAL {
            bg_ask.send();
            last_ask = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A live-monitor terminal session opened with the smooth-loading
/// prelude (NIGHT-boost-25, the owner's masterclass loading audit):
/// `Monitor::open` enters the alt screen and paints the caller's
/// prelude frame the moment the command starts, so the BPF load
/// reads as the product loading, not the terminal freezing. The
/// prelude rides the SAME DiffScreen the live loop uses (the first
/// live frame diffs against it — every row rewrites in place, no
/// clear, no blank flash), and a load failure drops the session
/// with ALT_EXIT restoring the main screen for the branded error.
///
/// NIGHT-boost-28: the silent pipe fallback is GONE — with
/// `require_interactive()` gating both the handler and `enter()`,
/// a non-interactive stdio refuses loudly BEFORE any terminal
/// state is taken, and a termios failure inside `enter()`
/// propagates as the honest error it is. Every monitor invocation
/// is interactive, or it never starts.
///
/// The alt screen (and every mode ALT_ENTER touched) restores when
/// the session drops: mouse modes off, main screen back, cursor
/// visible — and since NIGHT-boost-33 the violent-death guard holds
/// the same contract for the deaths a Drop can never run for.
pub struct Monitor {
    screen: DiffScreen,
    lines: Vec<String>,
    /// The alt-screen guard, held for its Drop (ALT_EXIT restores
    /// the main screen when the session ends). Underscore-named: a
    /// pure RAII field is never read, only dropped.
    _alt: AltScreen,
    /// The violent-death terminal guard (NIGHT-boost-33): a forked
    /// child parked on a pipe that restores the terminal when the
    /// monitor dies without its own Drop (kill -9, pkill). Dropped
    /// AFTER `_alt`, so the clean-exit byte stands the child down.
    _term_guard: Option<guard::TerminalGuard>,
    /// The selection guard runs only where a selection can exist —
    /// always true now: `Monitor::open` only succeeds on a fully
    /// interactive stdio pair (NIGHT-boost-28).
    guard: bool,
}

impl Monitor {
    /// Open the session: enter the alt screen and paint the prelude
    /// frame. `prelude(width, height)` composes at the open-time
    /// probe's real terminal size. An empty prelude (the `-v`
    /// trace-first sequence) paints nothing but still primes the
    /// diff screen, so the first live frame owns the whole screen.
    ///
    /// NIGHT-boost-28: returns `Result` — a non-interactive stdio
    /// (piped or redirected) or a termios failure refuses here with
    /// the branded message instead of degrading into the silent
    /// pipe session; no chrome byte ever reaches a non-terminal.
    pub fn open<P: FnOnce(usize, usize) -> Vec<String>>(prelude: P) -> Result<Self> {
        // NIGHT-boost-33: arm the violent-death guard FIRST — the
        // forked child must snapshot the SHELL's termios before raw
        // mode lands. None (no tty, no fork) is fail-open:
        // insurance, never a precondition.
        let mut term_guard = guard::TerminalGuard::arm();
        let alt = AltScreen::enter()?;
        // The alt screen is live: the monitor's Drop owns the restore
        // now, so the guard's Drop sends the stand-down byte (the
        // open-failure path keeps the guard in restore mode).
        if let Some(g) = term_guard.as_mut() {
            g.note_alt_live();
        }
        // NIGHT-boost-26: the frame's background follows the
        // terminal — the OSC 11 query rides the raw mode enter()
        // just took (the answer is not newline-terminated) and the
        // alt screen it just switched to. A terminal that stays
        // silent keeps the pre-boost-26 rendering: no background
        // escape at all. The 100 ms ceiling bounds the wait for the
        // silent ones; local terminals answer in single digits.
        // NIGHT-boost-32: this is the FIRST paint's ask — the live
        // ask in run_loop keeps the follow current from here on.
        crate::output::theme::set_terminal_bg(raw::query_terminal_bg());
        let (w, h) = match winsize() {
            Some((cols, rows)) => (cols as usize, rows as usize),
            None => (80, 24),
        };
        let mut session = Monitor {
            screen: DiffScreen::new(),
            lines: prelude(w, h),
            _alt: alt,
            _term_guard: term_guard,
            guard: true,
        };
        // The prelude IS frame 0: emit through the session's
        // own diff screen so the first live frame diffs
        // against it (the morph) instead of painting over a
        // clear.
        let mut stdout = RawStdout;
        session.screen.emit(&mut session.lines, &mut stdout);
        Ok(session)
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
        // self drops here: AltScreen::drop restores the main screen,
        // then the terminal guard stands its child down (boost-33).
    }
}

// NIGHT-strict-1: the monitor terminal-contract pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired across
// trees exactly like the diff-engine pins in diff.rs.
#[cfg(test)]
#[path = "../../test/terminal/mouse_contract_tests.rs"]
mod mouse_contract_tests;

#[cfg(test)]
// NIGHT-ultimate-2: the quiet-death pins — a failed emission marks
// the screen dead (sticky), the guard beat detects it too, idle
// frames cannot trip it, and a healthy sink never does. The
// run_loop beat-checks are the loop-level wiring whose live proof
// is the owner-host battery (the harness owns stdin, so the loop
// itself is not unit-pinnable — the guard_tests discipline).
#[path = "../../test/terminal/sink_death_tests.rs"]
mod sink_death_tests;
