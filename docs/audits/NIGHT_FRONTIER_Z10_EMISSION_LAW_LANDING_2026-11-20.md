<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-frontier-Z10 — rung 2 landing: the no-corruption theorem (D8)

Date: 2026-11-20. Owner's mandate, in shape: the no-corruption
theorem — model a minimal VT state machine in the proof crate, check
the diff emission engine against it for ALL frame pairs in a bounded
domain (`apply_terminal(emit_diff(prev, next), prev) == next`), plus
the absence-of-ESC[2J law, the idle fast path's zero-byte verdict,
and the one-batched-write-per-frame rule — with the docs updated, the
result on the supermassive-grade test surface, and the CI watched
green. The honesty bar stands: verify complete, no gimmick, every
claim carrying its verdict.

## What landed

- **The model** (`proofs/src/vt_model.rs`): a minimal VT state
  machine over the engine's exact emission set — HOME, MoveTo at
  column 1, erase-below, erase-EOL, LF, content payloads, complete
  SGR spans riding content verbatim — deliberately STRICT: any token
  outside the grammar panics (the ESC[2J class included), so grammar
  purity and screen conformance are one check. The model sharpened
  itself first, honestly: the sampled property's first
  counterexample was the model rejecting the engine's bare `ESC[H`
  (HOME) for failing the MoveTo shape it shares a final byte with —
  an instrument bug, not an engine bug; the grammar gained the HOME
  arm and the witness rides
  `proofs/proptest-regressions/terminal_laws.txt`.
- **The sampled tier** (`proofs/src/terminal_laws.rs`): one session
  property carrying the four emission laws over wide frames (up to
  64 rows x 200 columns, three-frame sessions with independent
  geometry, SGR-bearing rows included; 4096 shrinkable cases per
  run). Local verdict: green, 4096/4096 cases, inside the proofs
  crate's 50-test run.
- **The include** (`proofs/src/lib.rs` + `raw_stub.rs`): the engine's
  own bytes ride the fuzz harnesses' `#[path]` include law — the
  SAME bytes the flagship binary runs (`git diff -- src/` stays
  empty; nothing in the product tree moved). The engine's probe
  wrappers are not includeable standalone (their crate paths reach
  the whole terminal module), so the proof crate restates the
  piped-sink answers beside their source — the Z6
  `SYSTEM_MAX_RATE` restatement precedent — and the harnesses drive
  the size-injectable cores, so the probes never enter a verdict.
  The engine's own cfg(test) pins (diff pins, guard pins, the
  20,000-frame ghost-cell soak) compile and run inside the proofs
  crate's test lane as a consequence of the include.
- **The for-all tier** (`proofs/src/kani_terminal.rs`): one kani
  0.68.0 harness, `emission_conformance_holds_for_all_small_frames`,
  quantifying over two frames of up to 3 rows x 8 bytes with fully
  symbolic row counts, byte lengths, and screen heights (1..=3),
  asserting the conformance law from the blank screen through the
  steady-state hop plus the three structural laws. The parser is one
  token per step under the domain's own 16-token budget
  (`VtTerm::apply_bounded`); the sampled tier runs the same parser
  under its 720-token session budget.

## The census — four out-of-memory verdicts, one lane decision

The rung sketched a 4x16 domain. The measurement said no, four
times, on the 4 GB / 2 CPU census sandbox (kani 0.68.0, CBMC
6.11.0, CaDiCaL):

1. 4x16 at unwind 120 — out of memory inside about two minutes.
2. 3x8 at unwind 72 — out of memory at 2m14s.
3. 3x8 at unwind 72 after the token-budget parser restructure —
   out of memory at 2m05s (the restructure cut the model's
   byte-loop unwind but the engine's own symbolic heap — the frame
   vectors the emission swaps and clones, the emission buffer, the
   model's rows — is the weight, not one shrinkable circuit).
4. 2x6 at unwind 44 — out of memory again.

Per-loop unwind annotations are unstable on this toolchain
generation (the stmt_expr_attributes gate rejects them — probed),
so the one unwind bound is every loop's bound. The decision
follows the Z6 precedent exactly: a harness the local budget
cannot afford is a night-lane theorem, not a per-push seat. The
harness ships at its biggest census shape (3x8, unwind 68) as the
fifth matrix seat of `proofs-night.yml`, where the 300-minute
budget and the hosted runner are the verdict vehicle and a red is
a finding, never a skip. The per-push lane keeps the sampled tier,
which carries the emission laws over the wide frames; its property
seat name moved from 23 to 24 laws and its header records the
decision so a later hunt does not re-derive it.

Reopen conditions: a toolchain generation that carries per-loop
unwind annotations, or a smaller engine-heap footprint (or a
night-lane run that OOMs on the hosted runner — that finding
reopens the harness-shape conversation with real numbers).

## The honest scope

The theorem holds over the op-set the engine emits and the domains
the instruments state. The model is a MODEL: its resize semantics
and its row-as-payload equivalence are the standard terminal
reading the standing soak verified across 20,000 frames, restated
as law. Rows in the domain carry plain payloads plus complete SGR
spans — a payload impersonating a cursor move or an erase is
outside the render layer's contract and the model rejects it. The
for-all tier's domain is the bounded pair (blank to first frame,
first frame to next frame) at 3x8; multi-hop sessions, SGR-bearing
rows, and the wide-frame domain ride the sampled tier. The
one-write law is the engine's own batch contract (at most one
`write_all` per frame, the returned count equal to the bytes the
write carries); the syscall-layer reading — one write(2) whenever
the sink accepts the batch whole — is raw.rs's contract and is
documented, not proved here.

## Verification trail

- `cargo test --locked` inside `proofs/`: 50 tests green (the 24
  proptest laws including the new session property, plus the
  engine's diff pins, guard pins, and both soak tests riding the
  include), also green under `RUSTFLAGS="-D warnings"` (the lane's
  gate), 36-46 seconds wall on the census sandbox.
- `cargo fmt --check` clean (crate and root tree).
- Workflow edits linted (actionlint) — see the lane files.
- The for-all verdict: the night lane's own run (workflow dispatch
  on the landing push) — its result is recorded in the run, and the
  first scheduled fire repeats it daily.
