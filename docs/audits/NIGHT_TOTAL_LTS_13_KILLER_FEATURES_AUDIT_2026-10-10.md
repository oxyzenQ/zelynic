<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-13 depth audit — the killer-features pass, the verification round

> Audit date: 2026-10-10 (NIGHT-total-lts-13, after lts-14's
> all-infra round). Scope: the owner's ask — depth audit focused on
> the killer features, the limiter and the monitoring/eagle-eyes
> tree, total LTS, honest; peak-skip and continue. Audited at
> 85e15a5. Method: the perstage read the all-infra round budgeted
> here — the duplicate-pattern dragon hunt across the root repo
> (the lts-14 residual), then the fresh reads of the newest killer
> surfaces (the bloomberg-cut eagle command, the live monitor loop,
> the session fold, the countdown ceil, the guarantee bracket math),
> each against its own pins, with the full 893-test battery green
> before the record.

## 1. The mandate

The owner's ask: the killer features — the limiter engine and the
monitoring/eagle-eyes tree — read at depth, peak-skip honestly, and
continue. lts-12's round (the unicode bidi fix, the char_width
miscount, the lock-posture matrix, the fold-ordering law) set a high
bar; the delta since is improve-59's bloomberg cut, improve-60's
countdown ceil and 5y trim, improve-61's arrow marker and compact
rate figures, improve-62's v6 family tags, improve-64's pin lattice,
and lts-14's three module splits.

## 2. The dragon hunt — zero real duplicates

The cross-tree function-name census found one candidate,
`print_pin_state` — and it is the cfg-gated pair the dormant-lane
discipline requires (the ebpf build's real collector beside the
half-life stub), the repo's standing pattern, not a duplicate. The
signature-shape census (same arity-and-type families) finds the
expected `format_*` helpers, each pinned to one module by the
module map. The judgment: the tree carries no copy-paste pairs, no
parallel implementations of the same law, no drift-prone twins —
the one shared law both surfaces speak (collect_display_data for
the table and the JSON document) is shared BY DESIGN through one
function. The hunt the lts-14 round deferred closes empty-handed,
which is the honest finding.

## 3. The eagle-eyes command surface — PEAK

The command layer (commands/eagle.rs, the bloomberg-cut tree) holds
its discipline end to end: the launch-time existence gate refuses a
target that names nothing BEFORE any TUI or report exists (the
verifier-lineage mandate), the depth report's per-id scans are all
map joins (the O(ids x rows) census scan the fleet-scale spec paid
is gone — policy maps read once for the whole report, the stats and
baseline joins collect to HashMaps), the miss/match separation
keeps the duplicate-token and duplicate-id shapes honest (the
dinner-18 false-miss fix pinned), and every absence renders as
absence — no fabricated rows, no fabricated zeros, the honest
ledger joins riding Option end to end.

## 4. The live monitor loop — PEAK

The hot loop (commands/monitor.rs, the frame engine's driver) is
the most-cited engineering in the repo and the read holds: the
rate-math clock divides by the MEASURED poll-to-poll span (lts-3's
law — the nominal-interval era doubled the very spike it recovered
from), the one-frame tolerance folds an empty frame on a transient
map error while the baseline stays untouched so the recovery frame
spans exactly the gap it covers, the cookie join is differenced
with saturating arithmetic before it parks (the research-7 movers
fold — every on-screen dl/ul figure is per-second over the same
denominator the rate columns use), and the rare
poll-ok-join-err-recovery frame renders an UNDERESTIMATE — the safe
direction, the family can never show a fake burst above the policy.
The scroll state steps before the render at the wake cadence, the
session clock and the baseline lane ride the same frame as the
poll. Nothing to tighten.

## 5. The session fold and the countdown — PEAK

The session totals accumulate in u128 with saturating adds (the
"past the quettabyte" ceiling on the ledger the header documents —
no wrap class exists for any session horizon). The countdown
renderer (improve-60's fix) CEILS to the unit the remainder still
holds with a saturating ceil_div (a u64-extreme input cannot panic
a debug build), and the pins hold the owner's exact shape: 5h
minus a breath reads "5h", an exact 3h reads "3h", the sub-minute
tier prints seconds. The window lifetime line reconstructs wall
instants through the same offset pair the JSON twin uses — one
vocabulary, two surfaces.

## 6. The limiter's guarantee bracket — PEAK

The floor/ceil family (improve-40 / improve-40-b) is pinned at the
unit level in drr_guarantee_tests: the floor raises the split to
its epoch share, the ceiling lowers it, the lone drawer binds, the
contradiction resolves with the ceiling winning, the stockpile
tracks the ceiling quantum, and idle-sibling borrowing stays capped.
The full battery re-ran green before this record: 893 passed, 0
failed (the limiter, render, session, and pin families all in).
The kernel datapath itself was byte-pinned through the prebuilt
parity lane at every commit since lts-12's verdict — the strongest
class of evidence this repo owns.

## 7. The verdict table

| Area | Verdict | Note |
|---|---|---|
| Duplicate-pattern dragon hunt | CLEAN, zero finds | the one candidate is the cfg-gated dormant-lane pair, the standing pattern |
| Eagle-eyes command surface | PEAK | existence gates, map joins, honest absences — the bloomberg-cut tree read fresh |
| Live monitor loop | PEAK | measured spans, saturating movers fold, underestimate-safe recovery |
| Session fold | PEAK | u128 saturating, the quettabyte ceiling documented |
| Countdown ceil | PEAK | improve-60's law held, saturating, owner-shape pinned |
| Guarantee bracket | PEAK | the six drr pins green in the 893 battery |
| Limiter kernel datapath | PEAK, skipped | byte-pinned through prebuilt parity per commit (lts-12's standing verdict) |
| Full test battery | GREEN | 893 passed / 0 failed fresh at 85e15a5 |

## 8. This audit's own honest residuals

- The live eBPF enforcement legs (the VM matrix's limiter rows, the
  realnet precision windows) remain CI-owned — no root, no KVM on
  this host; the supermassive battery's verdict on the pushed tree
  is the record to watch.
- The eagle-eyes TUI's interactive keys (the six-key scroll family)
  are pinned at the state-machine level; the terminal-event layer
  itself is exercised by the rig suites in CI, not on this host.
- No code changed in this round: the audit is the record. A frame
  A/B would measure a tree this round did not touch — skipped by
  the docs-only rule.
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
