// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The monitor loop's beat scheduler (NIGHT-improve-29 split, the
//! screen.rs one-file-per-contract precedent — terminal/mod.rs sat
//! at the owner's 500-LOC cap and the hunt-31 reset notes pushed it
//! over): the selection-guard cadence, the Beat enum, and the pure
//! `next_beat` decision — the contract test/terminal/
//! mouse_contract_tests.rs pins (render outranks guard, the guard
//! clock never resets on a render, the disabled-guard arm never
//! guards, a resize forces a Render beat).

use std::time::{Duration, Instant};

/// Selection-guard beat (NIGHT-improve-8): the cadence on which the
/// monitor loop re-emits the whole frame while the box runs, so no
/// terminal-side selection can outlive one beat. Mouse tracking
/// cannot reach the terminal's Shift+click bypass (terminal-side,
/// no escape sequence switches it off) — but a selection dies the
/// moment its cells are rewritten, and 100 ms sits under the
/// fastest deliberate human select-then-copy round trip
/// (double-click plus an immediate Ctrl+Shift+C lands around
/// 200 ms). Cost: one whole-frame rewrite per beat (~1.4 KB on
/// the classic 80x24 frame), pinned by the diff tests; the loop
/// wakes at 50 ms granularity, so a beat lands within 100..150 ms.
pub(crate) const SELECTION_GUARD_BEAT: Duration = Duration::from_millis(100);

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
pub(crate) enum Beat {
    /// A fresh frame: poll + render closure + diff emit.
    Render,
    /// A selection-guard repaint: re-emit the last frame in full.
    Guard,
    /// Nothing owed — sleep.
    Sleep,
}

/// The monitor loop's scheduler, pure so the contract pins can
/// hold it. `guard` is false on the retired pipe-fallback's
/// scheduler shape — the arm stays part of the pure function's
/// domain (the pins exercise it) even though NIGHT-boost-28 made
/// the monitor refuse non-interactive stdio before the loop can
/// ever run there: a pipe has no selection machinery, and flooding
/// one with whole-frame beats would only multiply the output
/// volume. `resized` forces a Render beat regardless of the refresh
/// clock (NIGHT-boost-14).
pub(crate) fn next_beat(
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
