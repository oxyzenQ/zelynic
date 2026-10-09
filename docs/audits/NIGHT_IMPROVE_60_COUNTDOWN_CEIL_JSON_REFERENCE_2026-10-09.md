<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-60 audit — the countdown that rounded its own promise away

> Audit date: 2026-10-09 (night-improve-60, after night-improve-59).
> Scope: the owner's three asks off one transcript — a `--during 5h`
> checked minutes after apply read "(4h left)", the `status
> --print-json` output needed complete documentation (the owner read
> `window_secs: 8` against the 5-hour policy and could not tell
> which number owned the expiry), and the `--during` ceiling cuts
> from 10y to 5y. Method: reproduce the arithmetic from the
> transcript first, fix at the root, pin the boundary, then document
> the scripting surface field-by-field so the confusion has nowhere
> to live again.

## 1. The 4h that was 5h (the countdown ceil)

The owner's transcript, re-derived: `s brave 200kb --during 5h`
applied at 16:34:45 local, `status` read at 16:34:50 — 4h59m55s
remaining — and the table printed "4h left". The window was never
short (the end instant matched apply + 5h exactly); the countdown
renderer `format_duration_compact` FLOORED to the unit, and a
5h-minus-seconds remainder floored to 4h. A countdown that
understates what remains reads like time was lost — the exact
wrong story for a table whose one job is to say how long the
promise still holds.

The fix is one law, applied to every tier: CEIL to the unit the
remainder still holds (saturating arithmetic — a u64-extreme input
cannot panic a debug build). 4h59m59s reads "5h", the promise it
was set as; an exact 3h still reads "3h"; the sub-minute tier
still prints seconds so a short trial reads its own countdown.
The pin family re-pins the owner's exact shape (5h minus one
second) plus the tier edges (45.5s reads "46s", 59.5s reads
"60s" — the honest "you still hold the next unit"). The five
worded lifetime shapes re-ran unchanged: their pins use exact
units, which ceil maps to themselves.

## 2. The 10y ceiling cuts to 5y

The owner's call, one constant: `DURING_MAX_NS` is now five fixed
365-day years (was ten). A longer promise is a forever-limit
wearing a date; `--during` is for trials and time-boxes, and five
years is the outer edge of either. The grammar block, the refusal
wording ("the ceiling is 5y"), the flag docs, the `--help`
reference, the schema header, README/GUIDE/USAGE all speak the new
bound in one spelling; the pins re-pin the boundary itself (5y
parses, 6y refuses; the refused-shape list gains both). Rows
written by older builds at 10y keep their promises — a grammar
change never narrows a map; only the FLAG's reach trimmed.

## 3. The JSON reference, completed

The owner's find in one sentence: `rate_ring.window_secs: 8` sat
beside a 5h `--during` window in the same pretty-printed document,
and nothing in the docs said the two "window" words own different
clocks. The reference now carries:

- a complete field table for the status document — root
  (`watchdog`, `active_limits`), every limit-row field (identity,
  rates, the per-socket markers, the guarantee pairs merged and
  split, the four lifetime counters, `rate_ring`, `window`), each
  with its shape and its honest-absence rule;
- the two-clocks callout: `rate_ring.window_secs` is ALWAYS 8 —
  the span of the traffic history (eight one-second slots), never
  a countdown, never an expiry; the policy's own clock is
  `window` (`kind`, `state`, the wall instants), whose remaining
  lifetime is `end_wall_ns` minus now;
- jq recipes for both clocks — the seconds-left readout the human
  table prints, and the ring's average delivered rate over its own
  horizon;
- the stale `watchdog: "clean"` hunt-find: the vocabulary is
  `enforcing` / `active` / `expired` — "clean" is a value no build
  ever emitted; the sentence now names the real one.

The JSON field names themselves are untouched — the v11 stable-API
contract holds; this task only documented it.

## 4. What was measured and what was not

No frame A/B ran for this task, on the record: every touched path
(the status table's lifetime line, the parse bounds, the docs) is
outside the monitor's render loop — `format_duration_compact` has
exactly one caller (`window_lifetime_line`, the status visit's
row detail), and a frame benchmark that never renders the changed
code would measure noise. The pin battery (`display_tests`,
`during_user_tests`, `display_json_tests`) is the verification
lane; fmt and clippy the hygiene lane.
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
