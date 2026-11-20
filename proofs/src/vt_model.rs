// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z10 rung 2 (D8, the no-corruption theorem): the
//! minimal VT state machine the emission law is checked against. The
//! diff engine's own doc claim — "apply the emitted diff to the
//! previous screen and you get exactly the new frame" — becomes here
//! a mechanical check instead of a prose hope: for EVERY frame pair
//! in the theorem's domain, `apply(emit_diff(prev, next), prev) ==
//! next`, where `apply` is this model and `emit_diff` is the real
//! engine's own bytes (src/terminal/diff.rs, included by #[path] in
//! lib.rs — the fuzz harnesses' include law, the same discipline the
//! ebpf cores ride).
//!
//! The grammar the model implements is exactly the emission set the
//! engine owns (diff.rs's three constants plus its two structural
//! bytes): HOME (`ESC[H`), MoveTo (`ESC[{r};1H`, column 1 only),
//! erase below (`ESC[J`), erase EOL (`ESC[K`), LF, and content
//! bytes. Content always arrives at column 1 and the cursor is only
//! ever positioned at row starts, so the model replaces a row
//! wholesale on each content pass and `ESC[K` is the commit — the
//! same semantics the standing soak model runs
//! (test/terminal/diff_soak_tests.rs), restated here as a law
//! library so BOTH instruments (the proptest sampler and the kani
//! for-all harness) check the engine against one implementation.
//!
//! The model is deliberately STRICT, and the strictness is part of
//! the theorem: any escape sequence outside the grammar above (a
//! full-screen `ESC[2J`, a private-mode toggle, a column-bearing
//! MoveTo, an unterminated CSI) panics. The engine never emits any
//! of those — its source carries no such constant — so under a
//! content alphabet free of ESC bytes a panic can only mean the
//! emission grammar itself grew a token the theorem never vetted.
//! The no-corruption claim and the grammar-purity claim are thus one
//! check, not two.
//!
//! Honest scope (the appendix rule the golden vectors set): rows in
//! the theorem's domain carry plain payload bytes and complete SGR
//! spans (`ESC[...m` — the render layer embeds style bytes in rows,
//! so the model passes them through into the row payload verbatim;
//! a style change is a row change, exactly the engine's own model).
//! Rows never carry ESC sequences other than complete SGR spans —
//! the render layer's rows are styled text, and a payload that
//! impersonates a cursor move or an erase would be indistinguishable
//! from engine tokens in the byte stream. The theorem's boundary is
//! that render-layer contract, stated here, never hidden.

/// The minimal terminal: a fixed-height screen of raw row payloads,
/// a cursor row, and the current content pass (everything written
/// since the last positioning byte).
pub struct VtTerm {
    height: usize,
    rows: Vec<Vec<u8>>,
    cursor: usize,
    current: Vec<u8>,
}

impl VtTerm {
    /// The sampled tier's session token budget: 64 rows, each up to
    /// one content chunk plus 4 embedded SGR spans plus the K commit
    /// plus the LF (6 tokens), plus the reset, tail, and guard
    /// tokens — far past the widest session the strategies generate.
    pub(crate) const SAMPLED_BUDGET: usize = 720;

    /// The for-all tier's bounded-domain budget: 3 rows x (chunk,
    /// K, LF) = 9, plus the HOME/reset tokens and the tail's
    /// MoveTo+J pairs — the domain's own bound, stated and verified
    /// (the widest emission in that domain carries 15 tokens).
    pub(crate) const FORALL_BUDGET: usize = 16;

    /// A blank screen of `height` rows: the physical state a fresh
    /// monitor session starts from (the engine's own `ever_drawn`
    /// posture — the first frame must paint everything).
    pub fn new(height: usize) -> Self {
        assert!(height >= 1, "the model's screen is at least one row");
        VtTerm {
            height,
            rows: vec![Vec::new(); height],
            cursor: 0,
            current: Vec::new(),
        }
    }

    /// Resize like a real terminal: shrink drops the bottom rows,
    /// grow reveals blank ones at the bottom (the standing soak
    /// model's semantics — the engine's `painted` law repaints
    /// exactly the rows a grow reveals, and a shrink's revealed rows
    /// ride the tail clear).
    pub fn resize(&mut self, height: usize) {
        assert!(height >= 1, "the model's screen is at least one row");
        self.height = height;
        self.rows.resize(height, Vec::new());
        self.cursor = self.cursor.min(height - 1);
        self.current.clear();
    }

    /// Apply one emitted byte stream — the engine's whole grammar,
    /// strictly. Anything else is a theorem violation. The parser is
    /// one token per step under a stated budget (the tier's domain
    /// bound — see `apply_bounded`); the sampled tier's sessions ride
    /// this entry point with the session budget.
    pub fn apply(&mut self, stream: &[u8]) {
        self.apply_bounded(stream, Self::SAMPLED_BUDGET);
    }

    /// The bounded entry point: the same parser (the same `step` per
    /// token), under the caller's stated token budget. The kani
    /// harness calls this with the for-all domain's budget — a small
    /// concrete bound the solver unrolls exactly, instead of a
    /// byte-length loop whose unwind cost is the stream's full shape
    /// (the measured lesson: the 4 GB census sandbox went
    /// out-of-memory twice before the token-budget restructure — the
    /// budget IS part of the theorem's stated domain).
    pub fn apply_bounded(&mut self, stream: &[u8], budget: usize) {
        let mut pos = 0;
        for _step in 0..budget {
            if pos >= stream.len() {
                return;
            }
            pos = self.step(stream, pos);
        }
        panic!("grammar violation: stream exceeds the token budget {budget}");
    }

    /// One token at `stream[pos]`: one escape sequence, one LF, or
    /// one content run (a run of plain bytes up to the next ESC or
    /// LF). Returns the index past the token. Every step consumes at
    /// least one byte, so the token budget bounds the byte count too.
    fn step(&mut self, stream: &[u8], i: usize) -> usize {
        if stream[i] == 0x1b {
            self.apply_escape(stream, i)
        } else if stream[i] == b'\n' {
            // A LF below the bottom row would SCROLL the screen —
            // the tall regime's no-trailing-LF law exists precisely
            // to prevent it. A clamp would mask a regression, so
            // the model asserts instead (the soak model's shape).
            assert!(
                self.cursor + 1 < self.height,
                "grammar violation: LF past the bottom row (the tall-regime law)"
            );
            self.cursor += 1;
            self.current.clear();
            i + 1
        } else {
            // Content pass: the run of plain bytes up to the next
            // ESC or LF, written at column 1 — the row becomes the
            // payload accumulated this pass (progressive
            // overwrite; the ESC[K commit makes it final).
            let start = i;
            let mut j = i;
            while j < stream.len() && stream[j] != 0x1b && stream[j] != b'\n' {
                j += 1;
            }
            self.current.extend_from_slice(&stream[start..j]);
            self.rows[self.cursor] = self.current.clone();
            j
        }
    }

    /// One escape sequence at `stream[i] == ESC`. Returns the index
    /// past the sequence. The accepted set is the engine's emission
    /// grammar plus content-borne complete SGR spans; every other
    /// shape panics (the strictness IS the grammar-purity law).
    fn apply_escape(&mut self, stream: &[u8], i: usize) -> usize {
        assert!(
            i + 1 < stream.len() && stream[i + 1] == b'[',
            "grammar violation: ESC not followed by CSI"
        );
        // Scan the parameters up to the final byte (0x40..=0x7E — the
        // CSI final-byte range; parameter bytes are digits and
        // semicolons only in everything this model accepts).
        let mut j = i + 2;
        while j < stream.len() && matches!(stream[j], b'0'..=b'9' | b';') {
            j += 1;
        }
        assert!(
            j < stream.len(),
            "grammar violation: unterminated CSI sequence"
        );
        let final_byte = stream[j];
        let params = &stream[i + 2..j];
        match final_byte {
            b'H' => {
                if params.is_empty() {
                    // Bare `ESC[H` — HOME, cursor to row 1, col 1
                    // (the sequential/reset path's positioning).
                    self.cursor = 0;
                    self.current.clear();
                } else {
                    // MoveTo `ESC[{r};1H` — column 1 only, rows 1-based.
                    assert!(
                        params.len() >= 2
                            && params[params.len() - 2] == b';'
                            && params[params.len() - 1] == b'1',
                        "grammar violation: MoveTo is row-start only (ESC[{{r}};1H)"
                    );
                    let row = parse_decimal(&params[..params.len() - 2]);
                    assert!(row >= 1, "grammar violation: MoveTo row 0");
                    assert!(
                        row <= self.height,
                        "grammar violation: MoveTo row {row} past the viewport {}",
                        self.height
                    );
                    self.cursor = row - 1;
                    self.current.clear();
                }
            }
            b'J' => {
                // Erase below: cursor row..end of screen. The engine
                // emits it bare (HOME+J reset, MoveTo+J tail clear) —
                // a parameterized J (the full-screen 2J included) is
                // exactly the token the engine must never grow.
                assert!(
                    params.is_empty(),
                    "grammar violation: parameterized ESC[J (the ESC[2J class) is outside the grammar"
                );
                for row in self.rows.iter_mut().skip(self.cursor) {
                    row.clear();
                }
                self.current.clear();
            }
            b'K' => {
                // Erase EOL: the row becomes the content written this
                // pass (the engine writes whole rows at column 1, so
                // this is the commit — the erased tail is blank).
                assert!(params.is_empty(), "grammar violation: parameterized ESC[K");
                self.rows[self.cursor] = std::mem::take(&mut self.current);
            }
            b'm' => {
                // A complete SGR span riding inside a row payload: the
                // render layer's style bytes, passed through verbatim
                // into the current pass (a style change is a row
                // change — the engine's own content model).
                self.current.extend_from_slice(&stream[i..=j]);
            }
            _ => panic!(
                "grammar violation: CSI final byte {final_byte:#x} is outside the emission grammar"
            ),
        }
        j + 1
    }

    /// The conformance predicate: rows 0..visible hold exactly the
    /// frame's rows (byte-exact payloads), rows visible..height hold
    /// nothing — no ghost rows, no stale cells. `height` is the
    /// geometry the emission was addressed to (the model must have
    /// been resized to match before or after the stream, mirroring
    /// the real terminal).
    pub fn matches(&self, frame: &[String], height: usize) -> bool {
        if self.height != height {
            return false;
        }
        let visible = frame.len().min(height);
        for (r, want) in frame.iter().take(visible).enumerate() {
            if self.rows[r].as_slice() != want.as_bytes() {
                return false;
            }
        }
        self.rows[visible..].iter().all(|row| row.is_empty())
    }
}

/// Parse a nonempty decimal parameter (no leading zeros in anything
/// the grammar accepts — the engine's own push_decimal never emits
/// them, and the strict parser keeps that law).
fn parse_decimal(bytes: &[u8]) -> usize {
    assert!(!bytes.is_empty(), "grammar violation: empty MoveTo row");
    let mut value = 0usize;
    for &b in bytes {
        assert!(
            b.is_ascii_digit(),
            "grammar violation: non-digit MoveTo row"
        );
        value = value * 10 + (b - b'0') as usize;
    }
    value
}
