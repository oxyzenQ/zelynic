// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z10 rung 2 (D8, the no-corruption theorem): the
//! for-all tier. One harness turns the emission law into a
//! machine-checked theorem: for EVERY frame pair in the stated
//! domain — two frames of up to 3 rows, each row up to 8 bytes,
//! each screen 1..=3 rows tall — applying the engine's emitted diff
//! to the previous screen yields exactly the next frame, no
//! emission ever leaves the grammar (the model's strict parser
//! panics on any token outside the engine's emission set, the 2J
//! class included), the idle fast path answers zero bytes for an
//! identical frame at identical geometry, and every frame carries
//! at most one batched write.
//!
//! The domain's honest boundaries, stated per the Z6 rule:
//! - Content is a two-symbol alphabet (`a`, `b`) plus empty rows:
//!   the alphabet keeps the string-equality circuits inside the
//!   solver's budget while remaining a real content domain (rows
//!   differ, repeat, shrink, and go blank). SGR-bearing rows — the
//!   render layer's embedded style bytes — ride the sampled tier
//!   (terminal_laws.rs), which covers the wide frames and the width
//!   resizes; the for-all tier carries the bounded core.
//! - The size is the MEASURED one, not the aspirational one, and the
//!   lane is the MEASURED one too: the census ran FOUR local
//!   attempts (4x16 at unwind 120, then 3x8 at 72, then 3x8 after
//!   the parser's token-budget restructure, then 2x6 at unwind 44)
//!   and every one measured the solver OUT OF MEMORY inside about
//!   two and a half minutes on the 4 GB / 2 CPU census sandbox — the
//!   engine's own symbolic heap (the frame vectors the emission
//!   swaps and clones, the emission buffer, the model's rows), not
//!   one shrinkable circuit, is the weight. Per-loop unwind
//!   annotations are unstable on this toolchain generation (the
//!   stmt_expr_attributes gate rejects them), so the one unwind
//!   bound is every loop's bound, the parser is one token per step
//!   under a stated budget (the model's `apply_bounded`, the
//!   domain's own 16-token bound), and the domain ships at 3x8 /
//!   unwind 68 — the biggest of the census shapes — as a NIGHT-LANE
//!   harness: the solver-bound tier the per-push lane cannot afford
//!   is exactly what proofs-night.yml's 300-minute matrix seats
//!   exist for (the Z6 move, the census recorded in both lane
//!   headers). The hosted runner decides; a red there is a finding,
//!   never a skip. The wide frames and the width resizes ride the
//!   sampled tier, which carries the emission laws per-push. A
//!   toolchain generation that carries per-loop unwinds, or a
//!   smaller engine-heap footprint, reopens the per-push seat and
//!   the larger domain.
//! - The screen width is pinned at the column bound (8) across the
//!   harness's two emits: a width change forces the reset path,
//!   whose full repaint is the trivial branch; the interesting
//!   circuits (the tall regime, the `painted` bookkeeping, the
//!   sparse/sequential crossover, the tail clear) all live in the
//!   height axis, which is fully symbolic.
//! - Frame pairs are checked after a first emission from the blank
//!   screen — the session shape every monitor starts in (prev =
//!   blank, next = the first frame) plus the steady-state hop the
//!   theorem names.

use std::io::Write;

use crate::diff_core::DiffScreen;
use crate::vt_model::VtTerm;

/// The domain's row bound: up to 3 rows per frame.
const ROWS: usize = 3;

/// The domain's column bound: each row is up to 8 bytes.
const COLS: usize = 8;

/// The counting sink: the one-batched-write law's instrument (the
/// sink consumes every batch whole, so the call count IS the batch
/// count the engine issued).
#[derive(Default)]
struct CountSink {
    calls: usize,
    stream: Vec<u8>,
}

impl Write for CountSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.stream.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One arbitrary frame: up to ROWS rows, each up to COLS bytes from
/// the two-symbol alphabet. The row count and the byte lengths are
/// symbolic — the harness quantifies over the WHOLE bounded domain,
/// not a sample of shapes.
fn any_frame() -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for _ in 0..ROWS {
        let bytes: [u8; COLS] = kani::any();
        for b in &bytes {
            kani::assume(*b == b'a' || *b == b'b');
        }
        let len: usize = kani::any();
        kani::assume(len <= COLS);
        // SAFETY: every byte is assumed to be `a` or `b` (ASCII), so
        // the buffer is valid UTF-8 by construction — the assumes
        // directly above are the contract the unsafe block leans on.
        // The build takes the CONCRETE-length array whole and
        // truncates after: a symbolic-length slice copy unrolls its
        // allocation loop for the full unwind budget per row, the
        // exact measurement overhead that pushed the first census
        // attempts out of memory (the harness's library-model cost is
        // part of the theorem's budget — the Z6 census's own lesson).
        let mut row = unsafe { String::from_utf8_unchecked(bytes.to_vec()) };
        // ASCII-only content: truncation is always on a char boundary.
        row.truncate(len);
        rows.push(row);
    }
    let n: usize = kani::any();
    kani::assume(n <= ROWS);
    rows.truncate(n);
    rows
}

/// THE no-corruption theorem: emission conformance holds for every
/// frame pair in the bounded domain.
///
/// The unwind bound: the harness's largest true loop bound is the
/// emission stream's byte length (the model's apply loop consumes
/// at least one byte per iteration; the widest emission this domain
/// produces is the sparse-path upper shape, 3 runs of MoveTo plus
/// row bytes plus the tail clear, under 70 bytes), so one bound
/// covers the model's loops, the engine's row loops, and the sink's
/// buffer growth alike — measured, with every other loop's true
/// bound far under it.
#[kani::proof]
#[kani::unwind(68)]
fn emission_conformance_holds_for_all_small_frames() {
    let prev = any_frame();
    let next = any_frame();
    let height: usize = kani::any();
    kani::assume(height >= 1 && height <= ROWS);
    let next_height: usize = kani::any();
    kani::assume(next_height >= 1 && next_height <= ROWS);

    // The session shape: blank screen, first frame, steady-state hop.
    let mut screen = DiffScreen::new();
    let mut term = VtTerm::new(height);

    let mut first = prev.clone();
    let mut first_sink = CountSink::default();
    let first_emitted = screen.emit_at(COLS, height, &mut first, &mut first_sink);
    term.apply_bounded(&first_sink.stream, VtTerm::FORALL_BUDGET);
    assert!(
        term.matches(&prev, height),
        "the first frame does not rebuild the blank screen exactly"
    );
    // The first-frame reset contract: a fresh screen's geometry is
    // unknown, so the first emission can never idle — it always
    // paints (and always through exactly one batched write).
    assert!(
        first_emitted > 0,
        "the first frame idled on an unpainted screen"
    );
    assert_eq!(
        first_sink.calls,
        usize::from(first_emitted > 0),
        "the first frame's write batch"
    );

    let mut hop = next.clone();
    let mut hop_sink = CountSink::default();
    let hop_emitted = screen.emit_at(COLS, next_height, &mut hop, &mut hop_sink);
    term.resize(next_height);
    term.apply_bounded(&hop_sink.stream, VtTerm::FORALL_BUDGET);
    assert!(
        term.matches(&next, next_height),
        "THE no-corruption law: apply(emit(prev, next), prev) != next"
    );

    // The one-batched-write law, both frames, and the idle law on the
    // hop: identical frame at identical geometry must emit zero
    // bytes.
    assert!(
        first_sink.calls <= 1,
        "multiple write batches in the first frame"
    );
    assert!(hop_sink.calls <= 1, "multiple write batches in one frame");
    assert_eq!(
        hop_sink.calls,
        usize::from(hop_emitted > 0),
        "write iff bytes"
    );
    if next == prev && next_height == height {
        assert_eq!(hop_emitted, 0, "the idle fast path emitted bytes");
    }
}
