// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Selection-guard engine pins (NIGHT-improve-8) — kept in the
//! repo's single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C)
//! and #[path]-wired from src/terminal/diff.rs, beside the diff
//! engine pins. Split out of diff_tests.rs when the guard pins
//! pushed that file past the 500-LOC cap: one file per contract,
//! the same #[path] discipline the identity/ split set.

use super::*;

fn screen() -> DiffScreen {
    DiffScreen::new()
}

fn sink() -> Vec<u8> {
    Vec::new()
}

fn lines_of(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|s| s.to_string()).collect()
}

/// The guard's whole point: after an IDLE frame (the diff engine
/// correctly emits nothing — its contract), the guard still
/// re-emits the whole frame. A terminal-side selection survives a
/// diff-idle tick untouched; only a whole-frame rewrite clears it,
/// which is the exact hole the guard exists to close.
#[test]
fn guard_repaint_beats_the_idle_fast_path() {
    let mut s = screen();
    let rows = ["one", "two", "three"];
    let mut lines = lines_of(&rows);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out); // first frame
    out.clear();

    // Idle tick: byte-identical content, zero bytes — the engine's
    // idle fast path. A selection would outlive this tick.
    let mut idle = lines_of(&rows);
    let n = s.emit_at(80, 24, &mut idle, &mut out);
    assert_eq!(n, 0, "idle frame must stay free");
    assert!(out.is_empty());

    // Guard beat: the whole frame goes back out — every row, no
    // screen erase (NIGHT-hunt-26: the rewrite is the selection
    // killer; the erase only opened the blank flash window).
    let mut stale = lines_of(&rows); // swap scratch (receives the stale shadow)
    let g = s.force_repaint_at(80, 24, &mut stale, &mut out);
    assert!(g > 0, "the guard must re-emit a painted frame");
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.starts_with("\x1b[H"), "home prefix, got {text:?}");
    assert!(
        !text.contains("\u{1b}[J"),
        "NIGHT-hunt-26: a guard beat never erases the screen, got {text:?}"
    );
    assert!(text.contains("one\x1b[K\ntwo\x1b[K\nthree\x1b[K\n"));
    assert!(
        !text[3..].contains(";1H"),
        "no per-row MoveTo in the guard repaint"
    );
}

/// The guard's repaint is the reset stream MINUS the screen erase
/// (NIGHT-hunt-26): a fresh screen's first paint of the same lines
/// and a guard beat over an already-painted identical frame produce
/// the same stream except the first-frame's 3-byte erase-below —
/// the beat rewrites every row in place and never blanks the
/// screen, while a true reset (unknown screen state) still erases.
/// Pinned on a non-shrinking frame — the guard's variant can also
/// carry the below-frame tail erase when the frame shrank, which a
/// virgin first paint never has.
#[test]
fn guard_repaint_is_the_reset_stream_minus_the_erase() {
    let mut fresh = screen();
    let mut flines = lines_of(&["x1", "x2"]);
    let mut fout = sink();
    let fresh_bytes = fresh.emit_at(80, 24, &mut flines, &mut fout);
    assert!(
        fout.starts_with(b"\x1b[H\x1b[J"),
        "a true reset still erases (unknown screen state)"
    );

    let mut guarded = screen();
    let mut glines = lines_of(&["x1", "x2"]);
    let mut gout = sink();
    guarded.emit_at(80, 24, &mut glines, &mut gout);
    gout.clear();

    let mut scratch = lines_of(&["old"]); // non-empty: exercises the swap
    let guard_bytes = guarded.force_repaint_at(80, 24, &mut scratch, &mut gout);

    // The guard stream is the reset stream with exactly the
    // 3-byte ERASE_BELOW removed: HOME + every row, byte-for-byte.
    let mut expected: Vec<u8> = fout[..3].to_vec();
    expected.extend_from_slice(&fout[6..]);
    assert_eq!(gout, expected, "guard beat == reset stream minus the erase");
    assert_eq!(fresh_bytes, guard_bytes + ERASE_BELOW.len());
}

/// NIGHT-hunt-26 regression pin: the guard repaint NEVER emits the
/// screen erase — the blank window between an erase and the
/// rewrite is the intermittent flash the owner reported on
/// long-running monitors (grown frames cross the pty write-chunking
/// boundary, letting the terminal's frame clock catch the split).
/// Pinned across both regimes; the below-frame tail clear (a
/// shrunk frame's below-screen hygiene, blank rows only) remains
/// the reset family's own tool and is out of this pin's scope.
#[test]
fn guard_repaint_never_blanks_the_screen() {
    // Normal regime.
    let mut s = screen();
    let mut lines = lines_of(&["hold", "still"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();
    let mut scratch = Vec::new();
    s.force_repaint_at(80, 24, &mut scratch, &mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        !text.contains("\u{1b}[J"),
        "normal regime: no erase in the guard stream, got {text:?}"
    );

    // Tall regime.
    let mut t = screen();
    let mut tlines: Vec<String> = (0..12).map(|i| format!("r{i}")).collect();
    let mut tout = sink();
    t.emit_at(80, 12, &mut tlines, &mut tout);
    tout.clear();
    let mut tscratch = Vec::new();
    t.force_repaint_at(80, 12, &mut tscratch, &mut tout);
    let ttext = String::from_utf8_lossy(&tout).to_string();
    assert!(
        !ttext.contains("\u{1b}[J"),
        "tall regime: no erase in the guard stream, got {ttext:?}"
    );
    assert!(
        ttext.contains("r11\x1b[K"),
        "every visible row still rewrites"
    );
}

/// The guard leaves the shadow contract intact: after a beat, the
/// caller's buffer is back to the stale scratch it handed in (the
/// double swap is an involution), and the NEXT idle frame is still
/// zero bytes — the beat did not poison the diff, which also proves
/// the shadow still holds the current frame.
#[test]
fn guard_repaint_preserves_the_shadow_contract() {
    let mut s = screen();
    let rows = ["a", "b"];
    let mut lines = lines_of(&rows);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);

    let mut scratch = lines_of(&["stale"]);
    s.force_repaint_at(80, 24, &mut scratch, &mut out);
    assert_eq!(scratch, lines_of(&["stale"]), "caller buffer untouched");

    out.clear();
    let mut idle = lines_of(&rows);
    let n = s.emit_at(80, 24, &mut idle, &mut out);
    assert_eq!(n, 0, "idle frames stay free after a guard beat");
}

/// Guard beats are idempotent: a second beat with no render between
/// them re-emits the full frame again — a selection made between
/// beats dies at the next one, which is the guarantee the loop
/// sells.
#[test]
fn consecutive_guard_beats_both_reemit() {
    let mut s = screen();
    let rows = ["p", "q"];
    let mut lines = lines_of(&rows);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);

    let mut scratch = Vec::new();
    let first = s.force_repaint_at(80, 24, &mut scratch, &mut out);
    assert!(first > 0);

    out.clear();
    let second = s.force_repaint_at(80, 24, &mut scratch, &mut out);
    assert!(second > 0, "a second beat must also re-emit");
    assert_eq!(first, second, "beats are byte-identical");
}

/// Never-drawn screen: the guard emits nothing — nothing has been
/// painted, so there is nothing to protect (the loop's first Render
/// outranks every Guard anyway).
#[test]
fn guard_repaint_before_first_frame_is_free() {
    let mut s = screen();
    let mut out = sink();
    let mut scratch = Vec::new();
    let n = s.force_repaint_at(80, 24, &mut scratch, &mut out);
    assert_eq!(n, 0);
    assert!(out.is_empty());
}

/// Tall regime: the guard repaint keeps the no-trailing-LF rule — a
/// beat must never scroll the screen (the improve-6 invariant holds
/// under the guard's whole-frame rewrite too).
#[test]
fn guard_repaint_tall_regime_never_scrolls() {
    let mut s = screen();
    let mut lines: Vec<String> = (0..10).map(|i| format!("g{i}")).collect();
    let mut out = sink();
    s.emit_at(80, 10, &mut lines, &mut out); // tall regime first frame
    out.clear();

    let mut scratch = Vec::new();
    s.force_repaint_at(80, 10, &mut scratch, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("g9\x1b[K"), "last visible row repainted");
    assert!(!text.ends_with('\n'), "a guard beat must not scroll");
    assert_eq!(text.matches('\n').count(), 9, "h-1 separators only");
}
