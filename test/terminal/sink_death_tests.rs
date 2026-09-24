// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// Sink-death contract pins (NIGHT-ultimate-2) — the quiet-death
// mechanism that ends a monitor whose output sink died: a piped
// `zelynic eagle-eyes | head -3` used to leave a root process
// spinning at the refresh cadence forever (Rust ignores SIGPIPE,
// every write discarded, eBPF attached, /proc walks on schedule)
// because the diff engine's emission errors were discarded with no
// consequence. The screen now records the first failed write in a
// sticky flag the monitor loop reads after every beat. These pins
// drive the mechanism through the deterministic size-injectable
// cores (emit_at / force_repaint_at, the guard_tests discipline —
// no TIOCGWINSZ dependence); the loop-level wiring is the two
// sink_dead checks in run_loop, whose live proof is the owner-host
// battery's lane (a run_loop pin would need a real stdin, and the
// harness owns stdin).

use std::io::Write;

use super::DiffScreen;

/// A sink that fails every write the way a dead reader does
/// (EPIPE-class): the pin's stand-in for `zelynic ee | head` after
/// head exits.
struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "pin: the reader is gone",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deterministic frame content, the guard_tests convention.
fn lines_of(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|r| r.to_string()).collect()
}

/// A failed emission marks the screen dead — the mechanism the
/// monitor loop's beat-check reads. The emission itself must not
/// panic (the println_safe parity half of the contract).
#[test]
fn failing_emission_marks_the_screen_dead() {
    let mut screen = DiffScreen::new();
    let mut lines = lines_of(&["frame one", "frame two"]);
    let emitted = screen.emit_at(80, 24, &mut lines, &mut FailingSink);
    assert!(emitted > 0, "a fresh frame has bytes to write");
    assert!(screen.sink_dead(), "a failed write must set the death flag");
}

/// The guard-beat path detects death too: force_repaint rides the
/// same emission tail, so a dead sink during a copy-guard rewrite
/// is a dead monitor on the next check — not an infinite rewrite
/// loop into /dev/null-class sinks.
#[test]
fn guard_repaint_into_failing_sink_marks_the_screen_dead() {
    let mut screen = DiffScreen::new();
    let mut lines = lines_of(&["frame one"]);
    let healthy = screen.emit_at(80, 24, &mut lines, &mut Vec::new());
    assert!(healthy > 0);
    assert!(!screen.sink_dead());
    // The guard repaint re-emits the painted frame in full — into
    // a sink whose reader left.
    let _ = screen.force_repaint_at(80, 24, &mut lines, &mut FailingSink);
    assert!(
        screen.sink_dead(),
        "the guard beat must notice the dead sink"
    );
}

/// Healthy sinks never trip the flag — the happy path (every real
/// terminal and every live pipe reader) is indistinguishable from
/// before: frames, idle frames, and guard beats all stay alive.
#[test]
fn healthy_sink_never_marks_death() {
    let mut screen = DiffScreen::new();
    let mut lines = lines_of(&["frame one"]);
    screen.emit_at(80, 24, &mut lines, &mut Vec::new());
    // Idle repeat: no bytes, no write, still alive.
    screen.emit_at(80, 24, &mut lines, &mut Vec::new());
    // Guard repaint: full rewrite, healthy sink.
    screen.force_repaint_at(80, 24, &mut lines, &mut Vec::new());
    assert!(
        !screen.sink_dead(),
        "a live sink must never be reported dead"
    );
}

/// Idle frames write nothing, so they cannot detect (or false-trip)
/// death: an unchanged frame into a dead sink stays flag-clean —
/// only a REAL write that fails is evidence. This also pins why
/// the loop checks after the beat's emit, not before it: the death
/// surfaces on the next frame that has bytes.
#[test]
fn idle_frame_writes_nothing_and_never_trips_the_flag() {
    let mut screen = DiffScreen::new();
    let mut lines = lines_of(&["frame one"]);
    screen.emit_at(80, 24, &mut lines, &mut Vec::new());
    // The swap contract: the caller's vector now holds the PREVIOUS
    // frame — clear and refill for the next beat (the loop's own
    // discipline). Identical content: the diff engine's idle fast
    // path — zero bytes, zero syscalls — so even a dead sink sees
    // no write.
    let mut lines = lines_of(&["frame one"]);
    let emitted = screen.emit_at(80, 24, &mut lines, &mut FailingSink);
    assert_eq!(emitted, 0, "an idle frame emits nothing");
    assert!(
        !screen.sink_dead(),
        "no write happened, so no death can be reported"
    );
}

/// The flag is sticky: once a sink has died, a later healthy write
/// (a re-attached reader, a test sink swap) never resurrects it.
/// EPIPE-class errors do not heal; the loop must leave, not sample
/// the sink again.
#[test]
fn death_flag_is_sticky() {
    let mut screen = DiffScreen::new();
    let mut lines = lines_of(&["frame one"]);
    screen.emit_at(80, 24, &mut lines, &mut FailingSink);
    assert!(screen.sink_dead());
    // A subsequent healthy emission must not clear the verdict.
    let mut again = lines_of(&["frame two"]);
    screen.emit_at(80, 24, &mut again, &mut Vec::new());
    assert!(screen.sink_dead(), "a death verdict must never be un-dead");
}
