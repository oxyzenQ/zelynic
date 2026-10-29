// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The SIGHUP graceful exit (night-peak-lts FIX-5): the eagle-eyes
//! monitor takes the terminal-closed signal through the same Drop
//! chain a `q` press rides, instead of the kernel's default action.
//!
//! ## Why this exists
//!
//! The external audit's operational find: a `zelynic ee` left running
//! under a terminal that vanished burned 281 CPU-hours over twelve
//! days — an orphan the tool never chose to be. The violent-death
//! guard (NIGHT-boost-33) already cleans the TERMINAL on every
//! parent death, SIGHUP included: the setsid child sees the pipe EOF
//! and restores termios, the alt screen, the cursor. What the default
//! SIGHUP disposition skipped was the PROCESS-side grace — the parent
//! died mid-frame with no [`crate::commands::monitor`] cleanup, so
//! the observer's detach never ran and the session's own bookkeeping
//! ended at the kernel's whim.
//!
//! ## The shape
//!
//! One atomic flag, one async-signal-safe handler: the handler
//! stores `true` and nothing else (the one operation both the C
//! standard and every Rust build guarantee is signal-safe on an
//! atomic). The session loop wakes every 50 ms (the resize-reactive
//! beat scheduler's own cadence, NIGHT-boost-14) and checks the
//! flag at the top of each wake — so a delivered SIGHUP exits
//! through `InputAction::Quit`'s exact break point within one wake,
//! and everything `q` does, the Drop chain does: the alt screen
//! restores, the guard child takes the clean byte and stands down
//! without a second restore, the observer detaches, `main` exits 0.
//!
//! The residual orphan shapes are the ones where the kernel never
//! delivers the signal at all — a multiplexer's detached pane, a
//! `disown`ed job, a terminal that dies without HUPing its group.
//! No in-process handler can see a signal that is not sent; the
//! guard child's EOF restore covers what those shapes do to the
//! terminal, and `pkill zelynic` covers the process.

use std::sync::atomic::{AtomicBool, Ordering};

/// The one-flag state. Relaxed is enough: the flag carries no
/// ordering contract with any other memory — the loop reads it
/// between frames, where even a delayed visibility costs one wake.
static HUP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The handler. Async-signal-safe by construction: one atomic store,
/// no allocation, no locks, no libc calls. The signal number is
/// unnamed (the same handler serves whichever signal was armed).
extern "C" fn on_hup(_sig: i32) {
    HUP_REQUESTED.store(true, Ordering::Relaxed);
}

/// Arm the SIGHUP handler for this process. Called once, before the
/// session loop starts (the [`super::Monitor::open`] path, beside the
/// violent-death guard's own fork — the two insurance policies arm
/// together or not at all).
///
/// `SA_RESTART` keeps every in-flight syscall (the input drain, the
/// beat sleep, the render's writes) restarting across a delivered
/// SIGHUP — the flag, not an EINTR, is the delivery mechanism, so
/// nothing else in the loop learns the signal existed.
pub(crate) fn arm() {
    // SAFETY: sigaction(2) with a handler in static storage and a
    // zeroed mask (no signal is blocked inside the handler; the
    // handler touches one atomic). Overwriting the default SIGHUP
    // disposition is the point of this module.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = on_hup as *const () as usize;
        act.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGHUP, &act, std::ptr::null_mut());
    }
}

/// Did a SIGHUP land since the last check? The session loop asks
/// every wake; a `true` answer breaks the loop into the same exit
/// chain the `q` key owns.
pub(crate) fn requested() -> bool {
    HUP_REQUESTED.load(Ordering::Relaxed)
}

#[cfg(test)]
// The arm-and-flag pins (night-peak-lts FIX-5): the live proof is
// the battery's SIGHUP leg (a real TUI on a real pty reaped as exit
// 0, the kill-tui family's discipline — a unit harness owns no tty
// to run the monitor in). What a unit CAN pin is the mechanism: arm
// installs a handler (a raise without one would kill this test
// process outright) and the flag flips within the 500 ms contract
// the finding named.
#[path = "../../test/terminal/hup_tests.rs"]
mod hup_tests;
