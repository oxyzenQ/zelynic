// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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

// The spinner pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired like every output-layer pin. The test
// process's stderr is piped, so the TTY guard's inert-shell lane is
// the pinned behavior — the animated lane needs a terminal and stays
// a live-behavior contract (the guard itself is the byte contract).
#[cfg(test)]
#[path = "../../test/output/spinner_tests.rs"]
mod self_tests;
