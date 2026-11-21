// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The loading indicator (night-dragon-maintenance-4): a live
//! elapsed/total spinner for the surfaces that HOLD — the one-shot
//! eagle-eyes depth report's traffic-focus window above all, where a
//! 10s/30s capture previously printed one announce line and then sat
//! silent, reading as a hang (the owner's exact complaint: a window
//! that captures events must show that data is being processed).
//!
//! Contract:
//! - stderr only, TTY only. When stderr is not a terminal the
//!   spinner is an inert shell that emits zero bytes — the piped
//!   byte contract every output surface answers to holds untouched
//!   (pinned by [`self_tests::piped_stderr_starts_an_inert_shell`]).
//! - the frame rides the capability ladder like every other tier
//!   (grey — subordinate progress, never a headline), so NO_COLOR /
//!   CLICOLOR=0 land plain glyphs and the forced lanes land color.
//! - [`Spinner::stop`] joins the worker AFTER its final line-erase,
//!   so whatever prints next renders from a clean line; [`Drop`]
//!   routes every early return through the same erase (the window's
//!   failure paths degrade to the census with a note, never with a
//!   spinner corpse mid-line).
//! - the tick budget is one short stderr write per 120ms — noise
//!   next to the window itself, and stdout stays byte-clean.

use std::io::{IsTerminal as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The braille dot cycle — width-1 glyphs (the width discipline's
/// narrowest class), the classic spinner shape.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const TICK: Duration = Duration::from_millis(120);

/// Erase the spinner line: carriage return + EL (erase in line).
const ERASE_LINE: &str = "\r\x1b[2K";

pub(crate) struct Spinner {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Spinner {
    /// Start the spinner, or return an inert shell when stderr is
    /// piped (the zero-byte contract). `total_secs` is the budget the
    /// label announces — the clock reads `elapsed / total` until the
    /// budget passes, then plain elapsed (a window that overruns
    /// stays honest instead of pinning at the cap).
    pub(crate) fn start(label: String, total_secs: u64) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self {
                stop: Arc::new(AtomicBool::new(false)),
                worker: None,
            };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            let mut frame = 0usize;
            while !stop_flag.load(Ordering::Relaxed) {
                let elapsed = started.elapsed().as_secs();
                let clock = if total_secs > 0 && elapsed < total_secs {
                    format!("{elapsed}s / {total_secs}s")
                } else {
                    format!("{elapsed}s")
                };
                eprint_safe!(
                    "{}{} {} {}",
                    ERASE_LINE,
                    crate::output::grey(FRAMES[frame % FRAMES.len()]),
                    label,
                    crate::output::grey(&clock)
                );
                frame += 1;
                std::thread::sleep(TICK);
            }
            // The final erase rides the WORKER (before join returns):
            // whatever prints next — the report, the failure note —
            // renders from a clean line on every exit path.
            let _ = std::io::stderr().write_all(ERASE_LINE.as_bytes());
            let _ = std::io::stderr().flush();
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    /// Stop the spinner and wait for the final erase to land.
    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop();
    }
}

// ── The loading lane (night-ux-orion-1) ─────────────────────────────
//
// Ported byte for byte from the estate's reference (zejtron's
// night-ux-orion-1/2 loading lane): the same tables, the same
// bracket grammar, the same lazy threshold and cadence — the
// masterclass face the estate agreed on, so a --check-update or a
// big-data load reads identically across the family. The one
// deliberate delta is the paint seat: zejtron's lane rides its own
// fixed Grammar tier, this tree's lane rides [`crate::output::grey`]
// — the active theme's Grey slot at the probed capability, the same
// role (a narration dimmer than every ledger byte), adaptive through
// zelynic's theme ladder instead of one fixed grey. The tables, the
// grammar, the thresholds, and the fallback detection are the
// reference's own; the pins hold them.

/// The lazy threshold: an operation that lands inside 100 ms never
/// draws - the fast paths keep their byte-for-byte silence, and the
/// indicator appears only when the wait is real. The owner's
/// auto-detect law, one constant.
const LAZY: Duration = Duration::from_millis(100);

/// The frame period: ten frames per second, the braille sweep's
/// smooth cadence - fast enough to read as motion, slow enough that
/// a slow fetch's redraw cost is noise.
const FRAME_PERIOD: Duration = Duration::from_millis(100);

/// The stop-flag poll slice: the redraw thread never sleeps longer
/// than one slice, so a `finish` that lands mid-sleep joins within
/// a slice instead of a whole sleep leg.
const POLL: Duration = Duration::from_millis(25);

/// The braille sweep both helix strands ride: the classic ten-frame
/// dot walk, one cell wide, clockwise.
const SWEEP: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// The DNA helix: two strands, counter-phase. `HELIX[i]` pairs
/// `SWEEP[i]` with `SWEEP[9 - i]` - strand one runs the sweep
/// forward while strand two runs it backward, the two anti-parallel
/// streams the metaphor wants (the request out, the answer back) -
/// and the strands never collide: the pair is distinct at every
/// frame because `i = 9 - i` has no integer answer. Written out as
/// literals so the table is the pin, not a computation.
const HELIX: [&str; 10] = ["⠋⠏", "⠙⠇", "⠹⠧", "⠸⠦", "⠼⠴", "⠴⠼", "⠦⠸", "⠧⠹", "⠇⠙", "⠏⠋"];

/// The wave (one strand, the linear shape): the bare sweep. Kept
/// for a future linear site - the estate's law ships the helix as
/// the one loading face for parallel big-data loads.
const WAVE: [&str; 10] = SWEEP;

/// The ASCII floor: the rotating dash. NO_COLOR terminals and
/// terminals without a Unicode locale land here automatically -
/// the fallback is detection, never a flag, which is what separates
/// a CLI that carries its aesthetics from one that forces them.
const ASCII: [&str; 4] = ["-", "\\", "|", "/"];

/// The style seat a loading site claims: the helix is the estate's
/// one loading face (two anti-parallel strands - the parallel big
/// data load's own metaphor), the wave stays reserved for a future
/// site that wants a single strand.
#[derive(Clone, Copy)]
pub(crate) enum Style {
    /// Two counter-phase braille strands - the DNA helix.
    Helix,
    /// One braille strand - the linear wave.
    #[allow(dead_code)]
    Wave,
}

impl Style {
    fn frames(self) -> &'static [&'static str] {
        match self {
            Style::Helix => &HELIX,
            Style::Wave => &WAVE,
        }
    }
}

/// The Unicode probe, pure: a locale that names UTF-8 in any of its
/// usual spellings. Best-effort by design - an exotic locale
/// spelling degrades to the ASCII floor, never to garbage bytes.
fn unicode_ok(locale: Option<&str>) -> bool {
    locale.is_some_and(|l| {
        let lower = l.to_ascii_lowercase();
        lower.contains("utf-8") || lower.contains("utf8")
    })
}

/// The locale probe: LC_ALL, then LC_CTYPE, then LANG - the
/// standard precedence, first set value wins.
fn locale() -> Option<String> {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
}

/// The style ladder, pure: NO_COLOR or a non-Unicode locale lands on
/// the ASCII floor; otherwise the site's own seat. The loading
/// lane's gate deliberately differs from the capture spinner's - the
/// owner's night-ux-orion-1 law keeps the indicator alive on a
/// NO_COLOR terminal (as the unpainted dash) because a hang looks
/// like a hang with or without color.
fn frames_for(no_color: bool, locale: Option<&str>, chosen: Style) -> &'static [&'static str] {
    if no_color || !unicode_ok(locale) {
        &ASCII
    } else {
        chosen.frames()
    }
}

/// The loading line's shape: the estate's bracket grammar, the frame
/// riding where the seconds ride - one grammar, every surface, no
/// drift.
fn spinner_line(label: &str, frame: &str) -> String {
    format!("[{label}... {frame}]")
}

/// The rendered line for a slot: the table wraps, the line rides
/// the bracket grammar. Pure - the thread's draw is exactly this
/// string behind a carriage return, so the pins hold the bytes the
/// terminal sees.
fn render_slot(label: &str, frames: &[&str], slot: usize) -> String {
    spinner_line(label, frames[slot % frames.len()])
}

/// The lazy slot clock, pure: an operation younger than the lazy
/// threshold has no frame yet (None - nothing has ever been drawn),
/// and an older one names the frame slot the elapsed time pins.
/// Deterministic: the slot is a pure function of elapsed time, so a
/// redraw that lands late repeats a frame instead of skipping the
/// sequence.
fn frame_slot(elapsed: Duration) -> Option<usize> {
    if elapsed < LAZY {
        None
    } else {
        Some(((elapsed - LAZY).as_millis() / FRAME_PERIOD.as_millis()) as usize)
    }
}

/// One loading-lane write, errors swallowed: `eprint!` panics when
/// the write fails, and the indicator is decoration - a stderr that
/// cannot take the line must not cost the run its verdict.
#[cfg(not(test))]
fn loader_write_raw(bytes: &str) {
    let _ = std::io::stderr().write_all(bytes.as_bytes());
}

/// The test lane's sink: the machine's exact bytes, per test thread.
/// The production path above is the only other writer - the tests
/// pin the draw contract without touching the battery's stderr.
#[cfg(test)]
fn loader_write_raw(bytes: &str) {
    LOADER_DRAWN.with(|buffer| buffer.borrow_mut().extend_from_slice(bytes.as_bytes()));
}

#[cfg(test)]
thread_local! {
    /// The bytes this test thread's loading lane drew since the last
    /// clear.
    static LOADER_DRAWN: std::cell::RefCell<Vec<u8>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// The drawn bytes of this test thread, for the shape pins. The
/// machine's grammar is ASCII, so the bytes are always valid UTF-8.
#[cfg(test)]
fn loader_test_drawn_bytes() -> String {
    LOADER_DRAWN.with(|buffer| String::from_utf8_lossy(&buffer.borrow()).into_owned())
}

/// Clear the test sink between draws, per test.
#[cfg(test)]
fn loader_test_clear_drawn() {
    LOADER_DRAWN.with(|buffer| buffer.borrow_mut().clear());
}

/// The loading lane's machine (night-ux-orion-1): a background
/// thread redraws one stderr line while an indeterminate operation
/// blocks - the network fetch behind `--check-update`, the one-shot
/// depth report's walk of the kernel's maps - and the caller's
/// `finish` stops it and erases the line before any verdict prints.
/// The thread never draws before the lazy threshold (a fast path's
/// stderr stays byte for byte silent, its finish erases nothing), a
/// slow one shows the DNA helix (the ASCII floor when the terminal
/// drops it), and every write failure is swallowed by the noise law.
/// A non-terminal stderr arms the inert machine - a piped run pays
/// one gate probe and nothing else, byte for byte.
pub(crate) struct Loader {
    /// The thread's stop flag: set by `finish`, checked every cycle.
    stop: Arc<AtomicBool>,
    /// The thread's drawn flag: set before the first frame's write.
    /// The clear rides this truth - an operation that landed inside
    /// the lazy threshold drew nothing, so its finish writes no
    /// bytes at all.
    drawn: Arc<AtomicBool>,
    /// The redraw thread, when the gate allowed one.
    handle: Option<JoinHandle<()>>,
    /// The drawn line's CELL width: the bracket prefix's bytes plus
    /// the frame's cell count (the tables are width-stable, so the
    /// first frame names it; a braille strand is three bytes per
    /// cell, and the clear blanks cells, not bytes).
    width: usize,
}

impl Loader {
    /// Arm the loading lane for an indeterminate operation. The
    /// frames come from the style ladder (the helix seat unless the
    /// terminal drops to the ASCII floor); the first draw happens
    /// only when the operation crosses the lazy threshold, inside
    /// the thread.
    pub(crate) fn arm(label: &'static str, style: Style) -> Loader {
        // The piped-run law: a captured stderr never sees narration,
        // no matter what the color environment promises.
        if !std::io::stderr().is_terminal() {
            return Loader {
                stop: Arc::new(AtomicBool::new(false)),
                drawn: Arc::new(AtomicBool::new(false)),
                handle: None,
                width: 0,
            };
        }
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let frames = frames_for(no_color, locale().as_deref(), style);
        // The width law: the tables are width-stable, so the first
        // frame names the line's CELL width.
        let width = spinner_line(label, "").len() + frames[0].chars().count();
        let stop = Arc::new(AtomicBool::new(false));
        let drawn = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread_drawn = Arc::clone(&drawn);
        let handle = std::thread::spawn(move || {
            let armed = Instant::now();
            let mut drawn_slot: Option<usize> = None;
            loop {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                let elapsed = armed.elapsed();
                if let Some(slot) = frame_slot(elapsed) {
                    if drawn_slot != Some(slot) {
                        thread_drawn.store(true, Ordering::Relaxed);
                        loader_write_raw(&format!(
                            "\r{}",
                            crate::output::grey(&render_slot(label, frames, slot))
                        ));
                        drawn_slot = Some(slot);
                    }
                    // Sleep toward the next slot boundary, never past
                    // the stop flag's next check.
                    let in_slot = (elapsed - LAZY).as_millis() % FRAME_PERIOD.as_millis();
                    let rest = FRAME_PERIOD.as_millis() - in_slot;
                    std::thread::sleep(Duration::from_millis(rest.max(1) as u64).min(POLL));
                } else {
                    // Below the lazy threshold: sleep toward it in
                    // poll slices, so the stop flag's check keeps its
                    // cadence and a fast operation's join never waits
                    // out the whole remaining fraction.
                    std::thread::sleep((LAZY - elapsed).min(POLL));
                }
            }
        });
        Loader {
            stop,
            drawn,
            handle: Some(handle),
            width,
        }
    }

    /// Stop the redraw thread and erase the line entirely: the
    /// drawn CELL width blanked with spaces, the cursor back at
    /// column zero, before any verdict prints. The join guarantees
    /// the thread's last write lands before the clear does. The
    /// clear rides the drawn truth: an operation that landed inside
    /// the lazy threshold never drew, so its finish is byte-silent -
    /// the fast path's stderr is untouched, byte for byte.
    pub(crate) fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if self.drawn.load(Ordering::Relaxed) && self.width > 0 {
            loader_write_raw(&format!("\r{}\r", " ".repeat(self.width)));
        }
        // The consumed loader's drop must stay silent: the width's
        // zero is the drop guard's own "already handled" truth.
        self.width = 0;
    }
}

impl Drop for Loader {
    /// Every early return routes through the same erase (`finish`'s
    /// body): a failed fetch or a refused map open degrades to its
    /// error with a clean line, never with a spinner corpse mid-line
    /// (the capture lane's own Drop contract, mirrored). The happy
    /// path's bytes are unchanged: `finish` consumes the loader and
    /// zeroes the width, so its drop is the no-op shell.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if self.drawn.load(Ordering::Relaxed) && self.width > 0 {
            loader_write_raw(&format!("\r{}\r", " ".repeat(self.width)));
        }
    }
}

// The loading lane's pins live beside the capture lane's (cosmostrix
// Pattern C), #[path]-wired like every output-layer pin.
#[cfg(test)]
#[path = "../../test/output/loader_tests.rs"]
mod loader_tests;

// The spinner pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired like every output-layer pin. The test
// process's stderr is piped, so the TTY guard's inert-shell lane is
// the pinned behavior — the animated lane needs a terminal and stays
// a live-behavior contract (the guard itself is the byte contract).
#[cfg(test)]
#[path = "../../test/output/spinner_tests.rs"]
mod self_tests;
