<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-frontier-Z11 — the zero-heap frame ladder, stages 1-3 (the counting allocator's ratchet)

Date: 2026-11-21. Session scope: RUNG 3 — close the allocation
ladder Z4 named (border wrap pair, footer owned-Vec builders, detail
tree contracts, title_bar internals, grid_line, the per-frame bg
escape) until the frame's floor reaches its measured floor, pin
every landing, prove the visuals did not move.

## The instrument and the law

The allocation lens (Z4) is a counting global allocator in the test
binary; the pin (`steady_state_frame_composition_allocates_zero`)
takes the QUIETEST of 32 busy frames (a contamination-free window —
the honest statistic when the battery runs tests in parallel) and
holds it under FLOOR. The law: a commit that closes a named site
LOWERS the floor in the same commit. The floor's trail this session:
240 → 200 (stage 1) → 130 (stage 2) → 110 (stage 3a) → 50 (stage 3b).

## The stages

1. Stage 1 (title bar + grid + sweep memo): into-twins for
   title_bar_into, push_swept_bar, grid_line_into, push_rail_escape,
   push_sweep_run; the frame path pops pooled rows; the memo hit
   appends instead of cloning. 164 → 150.
2. Stage 2 (border wrap): the per-row composition happens IN the
   pooled row's own buffer (mem::take, fit in place, splice in
   place, the rails through the twin, the buffer returns with its
   capacity) — the old shape built three owned Strings per row and
   even discarded the pooled buffer it was handed. The closing row
   and the per-frame background escape ride retained scratches.
   150 → 100. The drift-guard pin (in-place fit vs the reference
   fit over a hostile row set) caught two wrong box-drawing escapes
   in the port's first run — the guard's job, done before landing.
3. Stage 3a (detail tree): push_detail_lines + the holder/endpoint/
   steady-rate twins; the per-cgroup owned Vec<String> of
   format!-built Strings gone. 100 → 86.
4. Stage 3b (footer): every footer row (headline, census, total
   usage, deep legend, the peak/avg arrival pair, the limit line,
   the identities note, the status legend, the signature stamp)
   writes into a pooled row; format_uptime_into, push_session_rate,
   status_line_into join the Z4 twins. 86 → 34.

## The A/B (the owner's law)

frame-bench.py, quick window vs quick window (the full-10s windows
differ in average because the fixture's session totals grow — the
honest pair is the same window on both sides), before b21d345,
after a3387d2: bytes/frame 1919.0 both sides; emit bytes/frame
682.1 vs 682.2; density gini 0.3263 vs 0.3265; frame entropy
3.3526 vs 3.3515; dirty cells 113.5 vs 113.8; fps ~5015 vs ~4948
(machine noise). Visual parity held; the allocation floor dropped
164 → 34 (4.8x) across the same boundary.

## The honest remainder (named, staged for the next session)

- The detail tree's holders' walk scratch (the outer Vec plus one
  Vec per holder) — a handful of events per frame.
- The signature engraving's internals (the output layer's identity
  seat — one String per frame).
- The focus view's own tree (full_detail_lines, the ranked board's
  Vec) — outside this pin's window; it earns its own lens when the
  focus frame gets one.

## Validation trail

- 204 render pins green (the byte-exact parity the ladder never
  broke), the drift guard included.
- cargo check --all-features --tests: zero warnings.
- The CI batch on the stages' commits went green (Gate-keepers,
  Proofs, Miri, CodeQL, Security Audit, CI, Fuzz, netrunner,
  Supermassive family, Verify).

## The CI watch's own finds (pre-existing, named for the owner)

- The noble 6.8 GA kernel's fast lane re-failed the non-binding
  overhead tripwire across runs with a byte-identical payload
  (+53.2%, then +43.9%, against a 07:34 green on the same bytes):
  the measured overhead straddles the cap on that runner class —
  the test's own "bursty contention" residual, now measured. Three
  data points above are the cap-vs-runner conversation's numbers.
- The floor-kernel engine leg caught a REAL coherence race the
  ladder did not touch (the eBPF bytes are identical to the
  morning's greens): `leg 2 download.size: exact bounds incoherent:
  min 146 > max 0` — the histogram's exact min/max volatile
  replace words read crossed at report time (run 44889620885, the
  engine test - low specs shard). The check-then-store discipline
  has a cross-CPU window; a kernel-side session owns the fix.
  Both finds are recorded here because a red lane that names a
  real race is the battery working, not the battery failing.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
