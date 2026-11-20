// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z10 rung 2 (D8, the no-corruption theorem): the
//! sampled tier. One session property carries the four emission laws
//! over wide frames — thousands of shrinkable cases per run, the
//! same instrument tier the ebpf cores' property_tests.rs names:
//!
//!  1. THE conformance law: for every frame the session emits,
//!     `apply_terminal(emit_diff(prev, next), prev) == next` — the
//!     model's screen equals the frame after every single emit,
//!     including the session's first (the previous screen is the
//!     blank state a fresh monitor starts from). Any deviation is a
//!     ghost row or a stale cell — the corruption class
//!     PHILOSOPHY.md calls the one a monitoring tool cannot
//!     apologize its way out of.
//!  2. The absence law: no emission ever carries `ESC[2J` — the
//!     full-screen erase whose alt-screen exit side effect wipes
//!     scrollback (the hazard the engine's never-2J rule exists
//!     for). Grammar violations beyond that ride the model's strict
//!     parser: any token outside the engine's emission set panics.
//!  3. The idle law: an identical frame at identical geometry emits
//!     ZERO bytes — the waiting monitor holds its frame for free.
//!  4. The one-write law: the engine issues at most ONE batched
//!     write per frame, and the returned byte count is exactly the
//!     bytes the write carries (the syscall-layer reading — one
//!     write(2) whenever the sink accepts the batch whole — is the
//!     binary's RawStdout contract, documented in raw.rs).
//!
//! The domain: rows up to 64 per frame at heights 1..=40 and widths
//! 40..=200 — wide frames (the tall regime, growth, shrink, idle,
//! and width resizes all occur naturally in the generation), with
//! content-borne complete SGR spans included per the model's scope
//! note (vt_model.rs). The for-all counterpart over the bounded 4x16
//! domain is kani_terminal.rs.

use std::io::Write;

use proptest::prelude::*;

use crate::diff_core::DiffScreen;
use crate::vt_model::VtTerm;

/// A row payload: printable text with optional embedded complete SGR
/// spans (`ESC[...m` — the render layer's style bytes ride inside
/// rows; the model passes them through verbatim). No ESC otherwise,
/// no LF, no other control bytes — the domain boundary vt_model.rs
/// states (a payload impersonating a cursor move or an erase would
/// be indistinguishable from engine tokens in the byte stream).
fn row() -> impl Strategy<Value = String> {
    // string_regex is infallible for a valid pattern; the unwrap is
    // a setup assertion, not a runtime branch.
    let pattern =
        "[A-Za-z0-9 .:/+|_-]{0,24}(?:\u{1b}\\[[0-9;]{0,9}m[A-Za-z0-9 .:/+|_-]{0,24}){0,4}";
    proptest::string::string_regex(pattern).expect("row pattern is a valid regex")
}

/// A frame: 0..=64 rows (wide frames — the tall regime's food).
fn frame() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(row(), 0..=64)
}

fn geometry() -> impl Strategy<Value = (usize, usize)> {
    (40usize..=200, 1usize..=40)
}

/// The counting sink: the one-write law's instrument. Every
/// `write_all` the engine issues lands as exactly one `write` call
/// here (the sink consumes the whole batch), so the call count IS
/// the batch count the engine issued.
#[derive(Default)]
struct CountSink {
    calls: usize,
    bytes: usize,
    stream: Vec<u8>,
}

impl Write for CountSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.bytes += buf.len();
        self.stream.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The absence law, directly: the byte sequence `ESC[2J` must never
/// appear in any emission (the model's parser also rejects it — this
/// scan names the law in the failure report).
fn carries_full_screen_erase(stream: &[u8]) -> bool {
    stream.windows(4).any(|w| w == b"\x1b[2J")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// THE no-corruption theorem, sampled over wide frames: a
    /// three-frame session with independently generated geometry and
    /// content (first frames, resizes, tall regimes, grows, shrinks,
    /// idle repeats all occur naturally), asserting after EVERY emit
    /// that the model's screen equals the frame — plus the three
    /// structural laws on each emission.
    #[test]
    fn emission_conformance_holds_across_sessions(
        f0 in frame(), f1 in frame(), f2 in frame(),
        g0 in geometry(), g1 in geometry(), g2 in geometry(),
    ) {
        let frames = [f0, f1, f2];
        let sizes = [g0, g1, g2];
        let mut screen = DiffScreen::new();
        let mut term = VtTerm::new(sizes[0].1);
        let mut prev: Option<(Vec<String>, (usize, usize))> = None;
        for k in 0..3 {
            let (w, h) = sizes[k];
            let mut lines = frames[k].clone();
            let mut sink = CountSink::default();
            let emitted = screen.emit_at(w, h, &mut lines, &mut sink);

            // Law 1: apply(emit(prev, next), prev) == next. The model
            // rides the session's real geometry — a sparse frame's
            // clean rows are only clean because the screen holds
            // them, so the model must hold them too.
            term.resize(h);
            term.apply(&sink.stream);
            prop_assert!(
                term.matches(&frames[k], h),
                "frame {k} at {w}x{h}: the emitted diff does not rebuild the frame \
                 (a ghost row or stale cell — the corruption class the theorem forbids)"
            );

            // Law 2: no ESC[2J, ever (and the strict parser above
            // already panicked on any other out-of-grammar token).
            prop_assert!(
                !carries_full_screen_erase(&sink.stream),
                "frame {k}: the emission carries ESC[2J — the never-2J rule is broken"
            );

            // Law 3: the one-batched-write rule, and the return value
            // is the byte count the write carried.
            prop_assert!(sink.calls <= 1, "frame {k}: {} write batches in one frame", sink.calls);
            prop_assert_eq!(sink.calls, usize::from(emitted > 0), "frame {}: write batch vs emitted", k);
            prop_assert_eq!(sink.bytes, emitted, "frame {}: written bytes vs the reported count", k);

            // Law 4: identical frame, identical geometry -> zero
            // bytes (the idle fast path). Repaint flags are never
            // raised in this session (no guard beat), and the width
            // match rules out a reset, so identical content must
            // idle.
            if let Some((prev_frame, prev_size)) = &prev
                && frames[k] == *prev_frame
                && sizes[k] == *prev_size
            {
                prop_assert_eq!(
                    emitted, 0,
                    "frame {}: an identical frame at identical geometry emitted {} bytes", k, emitted
                );
            }
            prev = Some((frames[k].clone(), sizes[k]));
        }
    }
}
