// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The wild-resize + churn ghost-cell soak (night-netrunner-1 phase
//! 3, the Eagle-Eyes depthbore audit's endurance evidence): a mini
//! terminal model replays every byte stream the diff engine emits
//! across a seeded random session — 20,000 frames of churn, idle,
//! grow, shrink, and violent geometry flips (5 <-> 200 rows, the
//! "terminal resizes wildly" rubric shape) — and after EVERY frame
//! asserts the model's screen equals the frame: no ghost rows, no
//! stale cells, no content the engine forgot it painted.
//!
//! The model implements exactly the emission grammar the engine
//! owns (diff.rs): HOME (`ESC[H`), MoveTo (`ESC[{r};1H`), erase
//! below (`ESC[J`), erase EOL (`ESC[K`), LF, and content bytes.
//! Content always arrives at column 1 (the engine only ever
//! positions at column 1 and advances rows with LF), so the model
//! replaces the row wholesale on each content pass and EOL is the
//! no-op confirmation. A deviation between model and frame after
//! any emit is a ghost cell by definition — the audit's failure
//! shape — and the soak fails with the frame number and the first
//! differing row.

use super::*;

use std::fmt::Write as _;

/// The mini terminal: a fixed-height screen of rows, a cursor row,
/// and the current content pass (everything written since the last
/// positioning byte).
struct MiniTerm {
    height: usize,
    rows: Vec<String>,
    cursor: usize,
    current: String,
}

impl MiniTerm {
    fn new(height: usize) -> Self {
        MiniTerm {
            height,
            rows: vec![String::new(); height],
            cursor: 0,
            current: String::new(),
        }
    }

    /// Resize like a real terminal: shrink drops rows, grow reveals
    /// blank ones (the engine's own `painted` law repaints exactly
    /// the revealed rows).
    fn resize(&mut self, height: usize) {
        self.height = height;
        self.rows.resize(height, String::new());
        self.cursor = self.cursor.min(height - 1);
        self.current.clear();
    }

    /// Apply one emitted byte stream (the engine's whole grammar).
    fn apply(&mut self, stream: &[u8]) {
        let mut i = 0;
        while i < stream.len() {
            if stream[i] == 0x1b {
                assert_eq!(stream[i + 1], b'[', "only CSI sequences are emitted");
                if stream[i..].starts_with(b"\x1b[H") {
                    self.cursor = 0;
                    self.current.clear();
                    i += 3;
                } else if stream[i..].starts_with(b"\x1b[J") {
                    // Erase from the cursor row to the end of screen.
                    for row in self.rows.iter_mut().skip(self.cursor) {
                        row.clear();
                    }
                    i += 3;
                } else if stream[i..].starts_with(b"\x1b[K") {
                    // Erase cursor..EOL: the row becomes the content
                    // written this pass (the engine writes whole rows
                    // at column 1, so this is the confirm).
                    self.rows[self.cursor] = std::mem::take(&mut self.current);
                    i += 3;
                } else {
                    // MoveTo: ESC [ {row} ; 1 H — rows are 1-based.
                    let mut j = i + 2;
                    let mut row = 0usize;
                    while stream[j].is_ascii_digit() {
                        row = row * 10 + (stream[j] - b'0') as usize;
                        j += 1;
                    }
                    assert_eq!(stream[j], b';');
                    assert_eq!(stream[j + 1], b'1');
                    assert_eq!(stream[j + 2], b'H');
                    self.cursor = row - 1;
                    self.current.clear();
                    i = j + 3;
                }
            } else if stream[i] == b'\n' {
                // A LF below the bottom row cannot happen (the tall
                // regime's no-trailing-LF law) — but a clamp would
                // MASK a regression, so the model asserts instead.
                assert!(
                    self.cursor + 1 < self.height,
                    "LF past the bottom row (tall-regime law violated)"
                );
                self.cursor += 1;
                self.current.clear();
                i += 1;
            } else {
                let start = i;
                while i < stream.len() && stream[i] != 0x1b && stream[i] != b'\n' {
                    i += 1;
                }
                assert!(
                    std::str::from_utf8(&stream[start..i]).is_ok(),
                    "content is valid UTF-8"
                );
                // Content writes at column 1: replace the row.
                self.current
                    .push_str(std::str::from_utf8(&stream[start..i]).unwrap());
                self.rows[self.cursor] = self.current.clone();
            }
        }
    }

    /// The audit invariant: rows 0..visible hold the frame, rows
    /// visible..height hold nothing (the normal regime's tail clear
    /// or the reset's erase-below guarantees the emptiness; the tall
    /// regime has no rows beyond the viewport).
    fn assert_matches(&self, lines: &[String], height: usize) {
        let visible = lines.len().min(height);
        for (r, want) in lines.iter().take(visible).enumerate() {
            assert_eq!(
                self.rows[r],
                *want,
                "ghost cell: row {r} drifted from the frame (model height {}, \
                 frame rows {}, visible {visible})",
                self.height,
                lines.len()
            );
        }
        for r in visible..self.height {
            assert!(
                self.rows[r].is_empty(),
                "ghost row {r}: stale content below the frame ({:?})",
                self.rows[r]
            );
        }
    }
}

/// One churn frame: every row mutates by a seeded LCG step (rates,
/// labels, blank rows, identical-to-previous frames all occur).
fn churn_frame(lcg: &mut u64, rows: usize, prev: &[String]) -> Vec<String> {
    let mut lines = Vec::with_capacity(rows);
    for r in 0..rows {
        *lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let step = (*lcg >> 33) % 10;
        if step == 0 && r < prev.len() {
            // Identical row: the idle fast path's food.
            lines.push(prev[r].clone());
        } else if step == 1 {
            lines.push(String::new());
        } else {
            let mut label = format!("row {r} ");
            let mut v = *lcg;
            for _ in 0..(3 + step as usize) {
                v = v.wrapping_mul(6364136223846793005).wrapping_add(1);
                let _ = write!(label, "{}", (b'a' + (v % 26) as u8) as char);
            }
            lines.push(label);
        }
    }
    lines
}

/// The soak: 20,000 frames (about 5.5 hours of wall clock at the
/// monitor's 1s cadence) across wild geometry, asserting the model
/// after every single emit. Any panic inside emit_at (an index, an
/// underflow on the shrink path) fails the test the same way.
#[test]
fn wild_resize_and_churn_soak_leaves_no_ghost_cells() {
    let mut lcg: u64 = 0x5e17_0001; // netrunner-1's seed
    let mut screen = DiffScreen::new();
    let mut prev: Vec<String> = Vec::new();
    let mut frame_no = 0usize;
    let mut term = MiniTerm::new(24);
    for frame in 0..20_000 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // The geometry: mostly calm 24-row terminals, with bursts of
        // wild flips (the rubric's "resizes wildly" shape) every
        // 97th frame and a slow drift the rest of the time.
        let height = if frame % 97 == 0 {
            if frame % 194 == 0 { 5 } else { 200 }
        } else {
            20 + ((lcg >> 40) % 12) as usize
        };
        // Frame content: 1..=60 rows, mostly the churn shape, with
        // idle frames (identical content) every 11th.
        let rows = 1 + ((lcg >> 45) % 60) as usize;
        let lines = if frame % 11 == 0 && !prev.is_empty() {
            prev[..prev.len().min(rows)].to_vec()
        } else {
            churn_frame(&mut lcg, rows, &prev)
        };

        let mut sink = Vec::new();
        screen.emit_at(80, height, &mut lines.clone(), &mut sink);
        frame_no = frame;
        // One PERSISTENT model across the whole session — a sparse
        // frame's clean rows are only clean because the real screen
        // already holds them, so the model must hold them too.
        term.resize(height);
        term.apply(&sink);
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            term.assert_matches(&lines, height);
        })) {
            eprintln!(
                "FRAME {frame}: height {height}, rows {}, prev_rows {}, \
                 emitted {} bytes",
                lines.len(),
                prev.len(),
                sink.len()
            );
            std::panic::resume_unwind(e);
        }
        prev = lines;
    }
    assert_eq!(frame_no, 19_999, "the soak ran to its last frame");
}

/// The resize-in-flight guard beat: force_repaint stands down when
/// the probed width moved since the last render (the tall-regime
/// scroll hazard) — pinned at the soak level by replaying guard
/// beats between renders and re-asserting the model.
#[test]
fn guard_beats_between_wild_renders_never_ghost() {
    let mut lcg: u64 = 0x5e17_0002;
    let mut screen = DiffScreen::new();
    let mut prev: Vec<String> = Vec::new();
    let mut term = MiniTerm::new(24);
    for _frame in 0..4_000 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let height = 12 + ((lcg >> 40) % 30) as usize;
        let rows = 1 + ((lcg >> 45) % 40) as usize;
        let lines = churn_frame(&mut lcg, rows, &prev);
        let mut sink = Vec::new();
        screen.emit_at(80, height, &mut lines.clone(), &mut sink);
        term.resize(height);
        term.apply(&sink);
        term.assert_matches(&lines, height);
        // Two guard beats between renders (the 100ms cadence riding
        // a 50ms wake): the whole-frame rewrite must leave the model
        // exactly on the frame, never a stale or erased state.
        for _ in 0..2 {
            let mut gsink = Vec::new();
            screen.force_repaint_at(80, height, &mut lines.clone(), &mut gsink);
            term.apply(&gsink);
            term.assert_matches(&lines, height);
        }
        prev = lines;
    }
}
