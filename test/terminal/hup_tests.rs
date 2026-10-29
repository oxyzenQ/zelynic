// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The SIGHUP flag pins (night-peak-lts FIX-5). The live end-to-end
//! proof — a real eagle-eyes session on a real pty exiting 0 on a
//! delivered SIGHUP — is the battery's SIGHUP leg (the kill-tui
//! family's seat: a unit harness owns no tty and no root). These
//! pins hold the mechanism the battery rides.

use super::*;

/// The contract the finding named: a delivered SIGHUP is visible to
/// the loop within 500 ms. arm() installs the handler first — the
/// raise that follows would kill this test process on the default
/// disposition, which is its own (violent) proof the arm ran. The
/// flag is process-global and the test suite shares one process, so
/// no pre-raise `false` assert lives here: another test's raise may
/// have landed first, and the pin's job is delivery-within-deadline,
/// not exclusive ownership of the flag.
#[test]
fn delivered_hup_flips_the_flag_within_500ms() {
    arm();
    // SAFETY: raise(2) of a signal this process has a handler for.
    unsafe { libc::raise(libc::SIGHUP) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        if requested() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("SIGHUP was delivered but the flag never flipped within 500ms");
}

/// The loop's read side: `requested()` is the one call run_loop
/// makes, so the pin names the exact function the break rides (a
/// rename upstream fails here before it silently unwires the loop).
#[test]
fn requested_is_the_loop_facing_reader() {
    // Delivery is not asserted — a parallel test may own that. The
    // pin is the call shape: the function exists, is callable from
    // the loop's context, and answers a bool.
    let _ = requested();
}
