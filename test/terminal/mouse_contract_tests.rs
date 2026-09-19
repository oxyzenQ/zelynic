// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the NIGHT-strict-1 monitor terminal contract: the
//! monitor never captures the mouse or the clipboard. Kept in the
//! repo's single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C) and
//! #[path]-wired from src/terminal/mod.rs.
//!
//! The functional requirement is already how zelynic behaves (mouse
//! tracking was never enabled); these pins make it a CONTRACT instead
//! of an accident, so no future commit can silently take over the
//! terminal's native selection and paste:
//!
//! 1. Byte-level pins over `ALT_ENTER` / `ALT_EXIT` — the only DEC
//!    private modes the monitor may ever touch are 1049 (alternate
//!    screen) and 25 (cursor visibility), and every mode enabled on
//!    enter is restored on exit.
//! 2. A source-tree scan: any `ESC[?` (DEC private mode) literal that
//!    appears anywhere in `src/` must be one of the two allowed
//!    modes. Adding `ESC[?1000h` (mouse click tracking),
//!    `ESC[?1002h` (button-drag tracking), `ESC[?1003h` (any-motion
//!    tracking), `ESC[?1006h` (SGR mouse), `ESC[?1004h` (focus
//!    reporting), or `ESC[?2004h` (bracketed paste) anywhere in the
//!    shipped source fails this test with the file and mode listed.
//!
//! Why this matters: any of those modes would break the owner rule
//! that click-drag selection and middle-click / Ctrl+Shift+V paste
//! keep working while the monitor runs — the terminal hands the
//! pointer to the app the moment mouse tracking is on (the classic
//! htop experience: selection stops working until you hold Shift).

use super::{ALT_ENTER, ALT_EXIT};
use std::path::{Path, PathBuf};

/// The exact enter bytes: alternate screen on, cursor hidden,
/// nothing else. Any delta here is a behavior change on every
/// monitor startup and must be a deliberate, reviewed edit.
#[test]
fn alt_enter_bytes_pinned() {
    assert_eq!(ALT_ENTER, b"\x1b[?1049h\x1b[?25l");
}

/// The exact exit bytes: alternate screen off, cursor shown. The
/// exit must restore EVERY mode the enter touched — a restore
/// mismatch here is how TUIs leave terminals wedged.
#[test]
fn alt_exit_bytes_pinned() {
    assert_eq!(ALT_EXIT, b"\x1b[?1049l\x1b[?25h");
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
/// modes in the monitor's enter/exit sequences are 1049 and 25.
/// 1000-1006/1015 (mouse tracking), 1004 (focus), 2004 (bracketed
/// paste) are all absent — the terminal's own selection cursor and
/// paste handling stay in the terminal's hands.
#[test]
fn monitor_never_enables_mouse_capture() {
    for seq in [ALT_ENTER, ALT_EXIT] {
        let modes = dec_private_modes(seq);
        assert!(
            modes.iter().all(|m| *m == 1049 || *m == 25),
            "unexpected DEC private mode(s) {modes:?} in monitor sequence — \
             the NIGHT-strict-1 contract allows only 1049 and 25"
        );
    }
    // And the full restore: both halves of the enter are undone.
    assert!(ALT_EXIT.windows(8).any(|w| w == b"\x1b[?1049l"));
    assert!(ALT_EXIT.windows(6).any(|w| w == b"\x1b[?25h"));
}

/// Source-tree scan: no DEC private mode outside {1049, 25} may
/// appear as a literal in any `src/**/*.rs` file. The scan looks for
/// the six-character source text `\x1b[?` (backslash-x-1-b-lb-question
/// — how a raw escape literal is spelled in Rust source), then reads
/// the digits that follow. Comments that merely NAME a mode in prose
/// (e.g. "ESC[?1000h") do not trip this pin; only real byte-sequence
/// literals do.
#[test]
fn source_tree_has_no_mouse_capture_sequences() {
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
        "NIGHT-strict-1 violation: non-allowed DEC private mode literal(s) \
         found in src/ (each of these takes over the terminal's native \
         mouse selection / paste while the monitor runs):\n  {}",
        offenders.join("\n  ")
    );
}

/// Scan one source file for `\x1b[?NNNN` literals and record any mode
/// outside {1049, 25} as an offender string "file:line: mode NNNN".
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
            && &text[i..i + needle.len()] == needle
        {
            let start = i + needle.len();
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                let mode: u32 = text[start..end].parse().unwrap_or(0);
                if mode != 1049 && mode != 25 {
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
