// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z10 rung 2 (D8, the no-corruption theorem): the
//! for-all tier. One harness states the emission law as a theorem:
//! for EVERY frame pair in the stated domain — two frames of up to 3
//! rows, each row exactly 8 bytes, each screen 1..=3 rows tall —
//! applying the engine's emitted diff to the previous screen yields
//! exactly the next frame, no emission ever leaves the grammar (the
//! model's strict parser panics on any token outside the engine's
//! emission set, the 2J class included), the idle fast path answers
//! zero bytes for an identical frame at identical geometry, and
//! every frame carries at most one batched write.
//!
//! The domain's honest boundaries, stated per the Z6 rule:
//! - Content is a two-symbol alphabet (`a`, `b`) in full-width rows
//!   plus empty rows (the row count is symbolic, 0..=ROWS): the
//!   alphabet keeps the string-equality circuits inside the solver's
//!   budget while remaining a real content domain (rows differ,
//!   repeat, and go blank). Variable row lengths and SGR-bearing
//!   rows — the render layer's embedded style bytes — ride the
//!   sampled tier (terminal_laws.rs), which covers the wide frames
//!   and the width resizes; the for-all tier carries the bounded
//!   core.
//! - The size is the MEASURED one, not the aspirational one, and the
//!   lane is the MEASURED one too: the census now spans TWO machines
//!   and ELEVEN shapes, and every one of them is a wall. The first
//!   census (the previous session): 4x16 at unwind 120, 3x8 at 72
//!   before and after the parser's token-budget restructure, 2x6 at
//!   unwind 44 — each out of memory inside about two and a half
//!   minutes on the 4 GB / 2 CPU census sandbox. The 2026-11-21
//!   census extended it in both directions: on the sandbox, 2x8@68,
//!   3x4@68, 1x8@68, 2x4@36, 2x6@44, 1x4@36, and even 1x4@24 and
//!   1x1@16 — the MINIMAL domain — all die in the kernel's global
//!   OOM killer (dmesg: cbmc, anon-rss 3.35 GB, the sandbox's own
//!   ceiling); and the hosted 16 GB / 4 CPU runner killed the 3x8@68
//!   seat mid-symbolic-execution twice (runs 44727607551 and
//!   44876980805, both at the 24-25 minute mark, no solver verdict
//!   printed, siblings alive past 27 minutes). The measured law: the
//!   weight is INVARIANT to the domain dimensions — it is the
//!   engine's own symbolic heap (the frame vectors the emission
//!   swaps and clones, the emission buffer's growth, the model's
//!   rows, and the panic-path machinery the direct indexings carry),
//!   not one shrinkable circuit, so no domain shrink reaches a
//!   verdict. Per-loop unwind annotations are unstable on this
//!   toolchain generation (the stmt_expr_attributes gate rejects
//!   them), and the full-width row shape (this file's `any_frame`)
//!   already removed the measured-heaviest single path — the
//!   symbolic-length `truncate`'s slice-index panic branch — with
//!   the variable-length dimension riding the sampled tier. The seat
//!   therefore sits OUT of the night matrix until one of the named
//!   levers lands: per-loop unwinds on a toolchain generation that
//!   carries them, a proof-friendly indexing form inside the engine
//!   (behavior-preserving, its own signed round), or the lemma
//!   decomposition the workflow header names. The theorem's
//!   statement lives here, compiles clean under cfg(kani), and the
//!   conformance evidence per-push rides the sampled tier and the
//!   golden vectors.
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

/// One arbitrary frame: up to ROWS rows, each EXACTLY COLS bytes from
/// the two-symbol alphabet. The row count and the screen heights are
/// symbolic — the harness quantifies over the whole bounded row-count
/// and height domain. The variable-byte-length dimension left the
/// for-all domain by measurement: the row-length `truncate` carries a
/// symbolic slice-index panic path whose `core::fmt` machinery alone
/// balloons the symbolic execution past every ceiling measured (the
/// 2026-11-21 census: every shape from 1x4@24 to 3x8@68 exceeded the
/// census sandbox's 3.2 GB with it, the hosted 16 GB runner included),
/// while full-width rows — the terminal's own common case — weigh
/// nothing. Variable lengths ride the sampled tier (terminal_laws.rs),
/// which covers them per-push on the wide frames.
fn any_frame() -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for _ in 0..ROWS {
        let bytes: [u8; COLS] = kani::any();
        for b in &bytes {
            kani::assume(*b == b'a' || *b == b'b');
        }
        // SAFETY: every byte is assumed to be `a` or `b` (ASCII), so
        // the buffer is valid UTF-8 by construction — the assumes
        // directly above are the contract the unsafe block leans on.
        // The build takes the CONCRETE-length array whole: no
        // symbolic-length slice copy, no slice-index panic path, no
        // fmt machinery — the census's measured weight, gone.
        rows.push(unsafe { String::from_utf8_unchecked(bytes.to_vec()) });
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
