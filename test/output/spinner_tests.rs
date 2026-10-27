// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The spinner pins (night-dragon-maintenance-4): the loading
//! indicator's byte contract. The test process's stderr is piped, so
//! `Spinner::start` must take the inert lane — zero bytes to the
//! pipe, a worker that never spawns, and stop/drop that stay no-ops.
//! The animated TTY lane is live behavior (a terminal it needs); the
//! guard itself IS the contract the piped surfaces depend on.

use super::*;

#[test]
fn piped_stderr_starts_an_inert_shell() {
    // The depth report's window runs the spinner around its attach +
    // poll + sleep span; piped output must see none of it.
    let mut spinner = Spinner::start("capturing traffic window".to_string(), 10);
    assert!(
        spinner.worker.is_none(),
        "a piped stderr must never spawn the spinner worker"
    );
    // stop() on the inert shell is a clean no-op (the Drop path of
    // every early return in the window ride the same code).
    spinner.stop();
}

#[test]
fn stop_is_idempotent_on_the_inert_shell() {
    let mut spinner = Spinner::start("x".to_string(), 0);
    spinner.stop();
    spinner.stop();
    assert!(spinner.worker.is_none());
}

#[test]
fn drop_on_the_inert_shell_is_a_clean_noop() {
    // The window's failure paths (attach/baseline/poll) return early;
    // the Drop impl must erase nothing and panic nowhere when piped.
    {
        let _spinner = Spinner::start("dropping".to_string(), 30);
    }
}
