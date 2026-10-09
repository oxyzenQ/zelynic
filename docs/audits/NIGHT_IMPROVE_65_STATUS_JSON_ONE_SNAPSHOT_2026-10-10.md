<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-65 audit — one snapshot, one document, one instant

> Audit date: 2026-10-10 (night-improve-65, after night-improve-64).
> Scope: the owner's ask — a depth pass over the print-json family
> (code, output quality, precision, LTS). Method: walk every surface
> that emits JSON (the writer primitive, the status document, the
> depth document, the empty-state documents, the doctor report),
> verify each against its own documented contract, fix at the root,
> pin the fixed boundary, and leave the field names exactly as the
> stable v11/v24 scripting contracts spell them.

## 1. The find: the status document's three clocks

`status_json` was documented pure — hunt-22's wording, "extracted so
the scripting contract ... is unit-pinnable without capturing
stdout" — and the caller already did the right thing:
`print_status_json` takes one snapshot pair (`wall_now_ns()`,
`monotonic_ns()`) and passes both in as parameters. The builder then
silently ignored its own discipline twice: the watchdog verdict
compared the deadline against a FRESH `monotonic_ns()` read (not the
passed `mono_now_ns`), and the rate-ring series took a second fresh
read as its `now`. Three clock reads per document, two of them
internal and undocumented.

The precision risk is the boundary straddle: the snapshot's instant
and the internal reads are microseconds apart, and any deadline,
window edge, or ring-stamp boundary that falls between them splits
the document's own story — the watchdog could read `expired` while a
window judged against the earlier snapshot still reads `active`, or
a ring slot could count as live for the series while the window
family disagrees about which second "now" is. A script parsing the
one-line document gets one instant of truth per field family, and
the families could contradict each other about that instant.

The purity break had a second cost, paid by the tests: the watchdog
pin's expired case leaned on the comment "monotonic_ns() is far
beyond 1 by now" — the test KNEW the function read the real clock
and passed a deadline of 1 to guarantee it, and the rate-ring join
pin leaned on "window 0 stamps are stale under ANY now the builder
samples". Both pins worked around the exact defect instead of
pinning the contract.

## 2. The fix: the snapshot is the now

One law, three sites: the watchdog comparison, the ring series'
`now`, and the window family all judge against the caller-passed
`mono_now_ns`. The builder no longer reads any clock — the document
is assembled at ONE instant, the parts cannot disagree, and the
"pure" in the doc comment is true again. The `wall_now_ns` half of
the snapshot was already honored (the window wall-instant
reconstruction); only the monotonic half leaked.

No field name, field order, vocabulary, or skip-rule changed — the
scripting contract is byte-identical modulo the boundary cases the
old code got internally wrong. The `watchdog` vocabulary stays
`enforcing` / `active` / `expired` (the improve-60 reference's table
owns the spelling).

## 3. The pins: the boundary, not the workaround

The watchdog pin family now owns the exact boundary: deadline
exactly AT the snapshot instant reads `expired` (the deadline was
reached — `d > now` is false at equality), one nanosecond before it
reads `active`. The expired case is a pinned instant
(`mono_now = 2` against deadline `1`), not a hope about the host's
uptime. The rate-ring join pin stamps a stale window-0 slot and a
live window-1 slot under a pinned `now` of eight windows: the join,
the oldest-first shape, the live count, and the completed-window
peak are all exact, and the stale stamp's bytes are provably never
counted nor double-booked onto the current window. 11 display_json
pins green, 893 bin + 58 integration green, clippy and rustfmt
clean.

## 4. The rest of the family, audited and left alone

- The writer primitive (`output::print_json`, boost-3): already the
  compact single-line contract — `serde_json::to_writer` straight
  into the locked stdout, no intermediate String, broken-pipe-safe.
  Peak for its job; untouched.
- The depth document (`render/depth_json.rs`): struct assembly
  only, no I/O, no clock reads — the module's own "pure" claim
  verified true. The clones are the borrowed-to-owned boundary of a
  once-per-invocation document, not a hot path; untouched.
- The empty-state documents (`status` clean / stale-pins, monitor.rs)
  and the doctor report: all ride the unified primitive with static
  shapes; nothing to optimize.
- The night-during window join and the improve-40-b per-direction
  floor/ceil split: the absent-lens discipline (absent is honestly
  absent, never a fabricated zero) holds on every row.

No frame A/B, on the record: every touched path is outside the
monitor's render loop — the print-json family is a one-shot
scripting surface, not the frame engine (the improve-60 precedent
for exactly this class of change).
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
