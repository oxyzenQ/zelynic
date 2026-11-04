<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Eagle-Eyes Depthbore Audit — 2026-11-04 (night-netrunner-1 phase 3)

The deep audit of the `eagle-eyes` monitoring mode the owner ordered:
production-grade for ultra-long endurance, bugs found and fixed, no
over-engineering. Rubric: stability and crash, resource usage (zero
idle cost), scalability, safety, ultra-long endurance. Every verdict
carries a file:line proof. Two real bugs surfaced and both are fixed
in the same commit that carries this audit; the rest of the surface
verified clean against its own documented contracts.

## The audit table

| Rubric | Verdict | Evidence (file:line) |
|--------|---------|----------------------|
| **Stability and crash** — `unwrap()` in the render loop | CLEAN | The render closure folds poll errors as a one-frame tolerance (`src/commands/monitor.rs:361-367` — `Err(_) => Default::default()`, prev-stats only rewritten on success, so the recovery frame's delta spans the skipped interval over its own measured span). The input drain never panics (`src/terminal/mod.rs:244-250` — `read(..).unwrap_or(0)`). The render family holds zero `unwrap()`/`expect()` on the live path; the one indexing site (`src/ebpf/render/border.rs:397`, `lines[0]` in `wrap`) is safe by construction — all three call sites push the title bar first (`loading.rs:54`, `focus.rs:131`, `eagle.rs:228`) before `wrap` runs. |
| **Stability and crash** — wild terminal resize | FIXED + PINNED | The ghost-cell bug below (endurance row) was reachable exactly through a wild resize sequence; the fix and the 20,000-frame soak pin it. The hunt-26 sticky geometry already held the transient 0x0 probe (`src/terminal/mod.rs:297-299`, `src/terminal/diff.rs:235-239`); `winsize()` refuses 0x0 outright (`src/terminal/raw.rs:36-40`). |
| **Stability and crash** — cgroup vanishes mid-read | CLEAN | BPF map iteration copies values kernel-side (LRU eviction is a restart, discriminated at `src/ebpf/loader/delta.rs:54-60` — never a phantom). A vanished cgroup loses its identity entry; the board filter hides it (no entry AND no window traffic, `src/ebpf/render/focus.rs:65-82`), and retirement frees its slot behind a 3-frame grace and the empty-identity signal guard (`src/ebpf/render/session.rs:283-321`). The /proc walk skips every vanished pid (`src/ebpf/connections.rs:151-166` — all `let Ok(..) else continue`), and the pidfd lifecycle closes every fd it opens (`src/ebpf/connections.rs:404-410` local duplicate, `:424-431` per-pid handle; the drop-recursion regression is pinned at `connections.rs:345-356`). |
| **Resource usage** — sleeps when no keys pressed | CLEAN (documented design) | The loop is a 50 ms fixed-wake beat scheduler, not a busy spin: `std::thread::sleep(50ms)` every wake (`src/terminal/mod.rs:389`), the wake does one non-blocking stdin drain (raw mode VMIN=0/VTIME=0, `src/terminal/raw.rs:171-172`), one TIOCGWINSZ ioctl, and a pure beat decision (`src/terminal/beat.rs:75-89`). A blocked read would freeze resize reactivity — the wake IS the design (the hup contract bounds delivery under 500 ms at the 50 ms cadence, `src/terminal/hup.rs:31-33`). Idle cost: a few syscalls per 50 ms plus the 100 ms selection-guard whole-frame rewrite (~1.4 KB, the anti-selection physics the owner ordered at NIGHT-improve-8). |
| **Resource usage** — zero per-frame heap allocations | CLEAN (layered) | The EMISSION engine is allocation-free end to end: shadow swap, reused dirty flags and run table, one buffer, one write syscall (`src/terminal/diff.rs:141-192` — NIGHT-blade-16 closed the last two engine allocations). The COMPOSITION layer allocates its line Strings per frame by contract (the line-building shape, `src/ebpf/render/eagle.rs:89-91`), the two buffers stay warm via the swap discipline (`diff.rs:411`), and the cost is the instrumented number: 5,138-5,156 fps through the real render path, emit ratio 0.35 (`scripts/bench/frame-bench.py --quick`, measured on this audit's tree). SmallVec was deliberately not introduced — the zero-new-dependency posture stands. |
| **Scalability** — 1,000 cgroups (sort/lookup shape) | CLEAN | The ranked board is an O(n log n) sort with a deterministic tiebreak (`src/ebpf/render/session.rs:376-380`), bounded at `MAX_TRACKED_CGROUPS` = 4096 with dead-row retirement so the bound stays reachable-honest (`session.rs:156`, `:283-321`). The poll's ingress merge rides a u32→position index, O(n), explicitly replacing the former O(egress x ingress) linear find (`src/ebpf/loader.rs:344-357`). Per-row delta lookup is O(summary) per VISIBLE row only (viewport-bounded, ~30 rows — `src/ebpf/render/eagle.rs:424-426`), never rows x rows. The board filter builds its active set lazily on first miss (`focus.rs:71-79`). |
| **Safety** — integer overflows in rate calculations | FIXED | The rate math is f64-division with a saturating `as` cast (`src/ebpf/render.rs:310-316`, the boost-22 audit's own contract); the session folds are saturating u128 (NIGHT-lts-5, `session.rs:227-247`); the baseline lane is integer-only with saturating/checked arithmetic (`src/ebpf/render/baseline.rs:190-197`, `:287-291`). THE GAP THE AUDIT CLOSED: the loader's per-frame machine-wide totals still used plain `+=` — the one surface the boost-16 saturating discipline missed; two half-space-coherent deltas (each < 2^63 by the discriminator) add past u64::MAX arithmetically — debug panic, release wrap-to-small. All four totals now saturate (`src/ebpf/loader.rs:324-337` egress, `:373-380` ingress). |
| **Ultra-long endurance** — ghost cells over days | FIXED + SOAKED | BUG FOUND: the diff engine's idle fast path returned zero bytes without clamping `painted` when the terminal resized between identical-content frames — a shrink (28→25 rows) left `painted = 28` over a 25-row viewport, and the next grow trusted the stale bound: a row whose content matched the stale shadow was skipped while the physical screen held older content (the audit soak's frame 7602: row 26 ghosted beside live traffic). Fixed: the idle path clamps the painted bound to the current geometry (`src/terminal/diff.rs:303-323`). Evidence: `test/terminal/diff_soak_tests.rs` — a mini terminal model replays every emitted stream across 20,000 seeded frames of churn, idle, grow, shrink, and violent 5↔200-row flips (the "resizes wildly" shape), plus 4,000 frames with interleaved guard beats, asserting screen == frame after EVERY emit; both soaks green post-fix. |
| **Ultra-long endurance** — rate ring leak over 100k frames | CLEAN | The ring is a fixed 8-slot x 128-byte HASH value per policy root — no growth, ever (`src/ebpf/limiter/rate_ring.rs:22,41-48`); the baseline lane retains exactly the read's key set every frame (`src/ebpf/render/baseline.rs:299-302`), so a swept root's state dies with its ring row; the lane's streak map is retained under the same law (`baseline.rs:383-386`). The engine's buffers survive the session at fixed capacity (shadow swap, reused flags/runs, `diff.rs:141-192`); the connection cache is rebuilt wholesale per TTL with vanished cgroups dropping out (`src/ebpf/connections.rs:145-146, 269-275`); `join_prev` is bounded by the census's cookie set (`src/commands/monitor.rs:349, 414`). 20,000-frame soak + the frame bench ran leak-flat. |

## The two fixes, in one breath

1. **The ghost cell (diff engine, endurance).** `DiffScreen::emit_at`'s
   idle fast path held the frame for free without noticing the
   terminal had resized between frames; a shrink-then-idle left
   `painted` claiming rows the viewport no longer showed, and the
   regrow skipped a row the shadow said was clean. One clamp
   (`self.painted = self.painted.min(height)`) restores the struct's
   own documented invariant ("rows at or beyond this index have never
   been painted and are dirty by definition"). The soak proves it
   across 24,000 randomized frames.

2. **The plain `+=` totals (loader, safety).** The boost-16 audit
   saturated the session path and missed the loader's four
   machine-wide totals; the coherence discriminator bounds each delta
   below 2^63, and two of those add past the u64 ceiling. Saturating
   adds, the same discipline one module over.

## What was verified and left alone

The surface is the product of twenty-plus audits (boost-22 overflow,
boost-28 interactive-stdio, boost-33 violent death, hunt-26 flash,
hunt-34 panel retirement, lts-3 measured span, lts-5 wrap coherence,
mitigate-1 data explosion, improve-72 panel floor, ultimate-2 sink
death) — each contract re-verified at its file:line during this pass
and left standing. No new dependencies, no new abstractions: two
one-site fixes, one soak test, this record.

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
