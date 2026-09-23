// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the NIGHT-improve-7 monitor terminal contract: the
//! monitor TAKES the pointer while the box runs, and gives it back
//! on exit. Kept in the repo's single test/ tree (NIGHT-hunt-17,
//! cosmostrix Pattern C) and #[path]-wired from src/terminal/mod.rs.
//!
//! This contract SUPERSEDES the NIGHT-strict-1 mouse clause (the
//! strict-1 alt-screen + cursor-restore pins survive unchanged): box
//! mode displays private data — cgroup names, PIDs, remote endpoints
//! — and the owner rule is that none of it is copyable while the
//! monitor runs. Mouse tracking (1000 press/release, 1002 button-drag,
//! 1006 SGR encoding) moves the pointer into the application, so
//! click-drag selects nothing and middle-click paste never lands in
//! the monitor's stdin. These pins make it a CONTRACT instead of an
//! accident, so no future commit can silently hand the pointer back
//! to the terminal:
//!
//! 1. Byte-level pins over `ALT_ENTER` / `ALT_EXIT` — the only DEC
//!    private modes the monitor may ever touch are 1049 (alternate
//!    screen), 25 (cursor visibility), and the mouse-tracking trio
//!    1000/1002/1006, and every mode enabled on enter is restored on
//!    exit.
//! 2. A source-tree scan: any `ESC[?` (DEC private mode) literal that
//!    appears anywhere in `src/` must be one of the five allowed
//!    modes. Adding `ESC[?1003h` (any-motion tracking — a stdin flood
//!    with no extra selection coverage over 1002), `ESC[?1005h` /
//!    `ESC[?1015h` (legacy mouse encodings), `ESC[?1004h` (focus
//!    reporting), or `ESC[?2004h` (bracketed paste) anywhere in the
//!    shipped source fails this test with the file and mode listed.
//! 3. NIGHT-improve-8 selection-guard pins: the guard beat value and
//!    the loop scheduler (`next_beat`) — mouse tracking cannot reach
//!    the terminal's Shift+click bypass, so the loop re-emits the
//!    whole frame on the beat and no selection can outlive it; the
//!    scheduler pins hold the ordering (render outranks guard, the
//!    guard clock never resets on a render, the non-TTY fallback
//!    never guards).
//!
//! Why this matters: dropping the mouse modes would re-expose the
//! monitor's private rows to plain click-drag selection; adding an
//! unlisted mode would take over a terminal capability the monitor
//! does not need; stretching or dropping the guard beat would let a
//! terminal-side Shift+click selection survive long enough to copy.
//! The owner rule is exactly the five modes, no more, no less, and
//! a beat no selection outlives.

use super::{next_beat, Beat, ALT_ENTER, ALT_EXIT, SELECTION_GUARD_BEAT};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The exact enter bytes: alternate screen on, cursor hidden, mouse
/// tracking on (1000/1002/1006 — NIGHT-improve-7). Any delta here is a
/// behavior change on every monitor startup and must be a deliberate,
/// reviewed edit.
#[test]
fn alt_enter_bytes_pinned() {
    assert_eq!(
        ALT_ENTER,
        b"\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1002h\x1b[?1006h"
    );
}

/// The exact exit bytes: mouse tracking off (reverse of the enter),
/// alternate screen off, cursor shown. The exit must restore EVERY
/// mode the enter touched — a restore mismatch here is how TUIs leave
/// terminals wedged (or, on this contract, leave the pointer captured
/// after exit).
#[test]
fn alt_exit_bytes_pinned() {
    assert_eq!(
        ALT_EXIT,
        b"\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?1049l\x1b[?25h"
    );
}

/// Extract every DEC private mode number from an escape byte
/// sequence: the digits following each `ESC[?` prefix.
fn dec_private_modes(seq: &[u8]) -> Vec<u32> {
    let mut modes = Vec::new();
    let mut i = 0;
    while i + 2 < seq.len() {
        if seq[i] == 0x1b && seq[i + 1] == b'[' && seq[i + 2] == b'?' {
            let start = i + 3;
            let mut end = start;
            while end < seq.len() && seq[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                let digits = std::str::from_utf8(&seq[start..end]).unwrap_or("");
                if let Ok(n) = digits.parse::<u32>() {
                    modes.push(n);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    modes
}

/// The strict mouse contract, byte level: the only DEC private
/// modes in the monitor's enter/exit sequences are 1049, 25, and the
/// mouse-tracking trio 1000/1002/1006. Any-motion 1003 (stdin flood,
/// no extra selection coverage), legacy encodings 1005/1015, focus
/// 1004, and bracketed paste 2004 are all absent — the monitor takes
/// EXACTLY the pointer, nothing more.
#[test]
fn monitor_takes_pointer_and_fully_restores() {
    for seq in [ALT_ENTER, ALT_EXIT] {
        let modes = dec_private_modes(seq);
        assert!(
            modes
                .iter()
                .all(|m| matches!(m, 1049 | 25 | 1000 | 1002 | 1006)),
            "unexpected DEC private mode(s) {modes:?} in monitor sequence — \
             the NIGHT-improve-7 contract allows only 1049, 25, 1000, 1002, \
             and 1006"
        );
    }
    // And the full restore: every mode the enter enabled is undone.
    assert!(ALT_EXIT.windows(8).any(|w| w == b"\x1b[?1049l"));
    assert!(ALT_EXIT.windows(6).any(|w| w == b"\x1b[?25h"));
    assert!(ALT_EXIT.windows(8).any(|w| w == b"\x1b[?1000l"));
    assert!(ALT_EXIT.windows(8).any(|w| w == b"\x1b[?1002l"));
    assert!(ALT_EXIT.windows(8).any(|w| w == b"\x1b[?1006l"));
}

/// Source-tree scan: no DEC private mode outside
/// {1049, 25, 1000, 1002, 1006} may
/// appear as a literal in any `src/**/*.rs` file. The scan looks for
/// the six-character source text `\x1b[?` (backslash-x-1-b-lb-question
/// — how a raw escape literal is spelled in Rust source), then reads
/// the digits that follow. Comments that merely NAME a mode in prose
/// (e.g. "ESC[?1000h") do not trip this pin; only real byte-sequence
/// literals do. The needle comparison is byte-level on purpose: a
/// `&str` slice would panic on a backslash in prose that happens to
/// sit a few bytes before a multi-byte character (NIGHT-hunt-30 —
/// src/ebpf/embedded.rs's doc comment quoting its `"ZELF-30" + NUL`
/// magic next to an em-dash hit exactly that).
#[test]
fn source_tree_has_only_sanctioned_dec_modes() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let mut offenders: Vec<String> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![src];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                scan_source_file(&path, &mut offenders);
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "NIGHT-improve-7 violation: non-sanctioned DEC private mode \
         literal(s) found in src/ (the monitor's terminal takeover is \
         exactly {{1049, 25, 1000, 1002, 1006}} — anything else grabs a \
         capability the monitor does not need, or re-exposes the box \
         to selection):\n  {}",
        offenders.join("\n  ")
    );
}

/// Scan one source file for `\x1b[?NNNN` literals and record any mode
/// outside {1049, 25, 1000, 1002, 1006} as an offender string
/// "file:line: mode NNNN".
fn scan_source_file(path: &Path, offenders: &mut Vec<String>) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let needle = "\\x1b[?";
    let bytes = text.as_bytes();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if bytes[i] == b'\\'
            && i + needle.len() <= bytes.len()
            && &bytes[i..i + needle.len()] == needle.as_bytes()
        {
            let start = i + needle.len();
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                let mode: u32 = text[start..end].parse().unwrap_or(0);
                if !matches!(mode, 1049 | 25 | 1000 | 1002 | 1006) {
                    offenders.push(format!(
                        "{}:{}: mode {}",
                        path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                            .unwrap_or(path)
                            .display(),
                        line,
                        mode
                    ));
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

/// NIGHT-improve-8: the selection-guard beat value is the contract —
/// "no selection outlives one beat" is only as strong as the beat
/// is short. 100 ms sits under the fastest deliberate human
/// select-then-copy round trip (double-click plus an immediate
/// Ctrl+Shift+C lands around 200 ms) while costing one whole-frame
/// rewrite per beat (~1.4 KB on the classic 80x24 frame).
#[test]
fn selection_guard_beat_pinned() {
    assert_eq!(SELECTION_GUARD_BEAT, Duration::from_millis(100));
}

/// The loop scheduler contract (NIGHT-improve-8): a due render
/// outranks a due guard (fresh content is also the strongest
/// selection killer), the guard fires on its own clock between
/// renders (a diff-only render never resets it — unchanged rows
/// stay selectable, the hole the guard closes), and the non-TTY
/// fallback never guards (a pipe has no selection machinery; the
/// beats would only flood it).
///
/// NIGHT-boost-14 resize pin: a geometry change forces a Render
/// beat mid-interval — the layout adapts within one 50ms wake,
/// never at the next refresh tick (up to 60s at `--interval 60`).
#[test]
fn next_beat_orders_render_guard_sleep() {
    let refresh = Duration::from_secs(1);
    let now = Instant::now();

    // Fresh loop: the first frame is due immediately.
    assert!(matches!(
        next_beat(
            now - refresh - Duration::from_millis(1),
            now,
            refresh,
            true,
            false
        ),
        Beat::Render
    ));

    // Mid-interval, beat not yet due: sleep.
    assert!(matches!(
        next_beat(
            now - Duration::from_millis(500),
            now - SELECTION_GUARD_BEAT + Duration::from_millis(20),
            refresh,
            true,
            false
        ),
        Beat::Sleep
    ));

    // Mid-interval, beat due: guard.
    assert!(matches!(
        next_beat(
            now - Duration::from_millis(500),
            now - SELECTION_GUARD_BEAT,
            refresh,
            true,
            false
        ),
        Beat::Guard
    ));

    // Both due: render wins.
    assert!(matches!(
        next_beat(
            now - refresh,
            now - SELECTION_GUARD_BEAT - Duration::from_millis(50),
            refresh,
            true,
            false
        ),
        Beat::Render
    ));

    // Non-TTY fallback: the guard clock can be far past due and
    // the beat still never fires.
    assert!(matches!(
        next_beat(
            now - Duration::from_millis(500),
            now - Duration::from_secs(10),
            refresh,
            false,
            false
        ),
        Beat::Sleep
    ));

    // NIGHT-boost-14: a resize mid-interval renders IMMEDIATELY —
    // both on the guarded TTY path and the non-TTY fallback (the
    // geometry probe is loop-level; the fallback cannot actually
    // resize, but the scheduler contract is size-blind).
    assert!(matches!(
        next_beat(
            now - Duration::from_millis(500),
            now - SELECTION_GUARD_BEAT + Duration::from_millis(20),
            refresh,
            true,
            true
        ),
        Beat::Render
    ));
    assert!(matches!(
        next_beat(now - Duration::from_millis(500), now, refresh, false, true),
        Beat::Render
    ));
}

/// The q-only quit contract (NIGHT-hunt-16, pinned as a byte-level
/// decision by NIGHT-boost-14 at the owner's "make sure only shortkey
/// 'q' for quit" directive): 'q' leading the drained chunk quits;
/// uppercase, Ctrl+C, standalone ESC, every escape-sequence head
/// (arrow, mouse SGR, scroll wheel), and 'q' buried inside a chunk
/// do not.
#[test]
fn quit_is_q_first_byte_only() {
    use super::quit_from_chunk;

    // The one quit byte.
    assert!(quit_from_chunk(b"q"));
    assert!(quit_from_chunk(b"quit"));
    // Uppercase is a different key.
    assert!(!quit_from_chunk(b"Q"));
    // Ctrl+C (0x03) and ESC (0x1b): drained, never quit.
    assert!(!quit_from_chunk(&[0x03]));
    assert!(!quit_from_chunk(&[0x1b]));
    // Escape-sequence heads: arrows, SGR mouse, scroll.
    assert!(!quit_from_chunk(b"\x1b[A"));
    assert!(!quit_from_chunk(b"\x1b[<0;10;10M"));
    assert!(!quit_from_chunk(b"\x1b[64;1;1;64;1;1"));
    // 'q' inside an escape sequence body is not a quit — the head
    // byte speaks, not the tail.
    assert!(!quit_from_chunk(b"\x1bq"));
    // Empty chunk: nothing drained, nothing quit.
    assert!(!quit_from_chunk(b""));
}
