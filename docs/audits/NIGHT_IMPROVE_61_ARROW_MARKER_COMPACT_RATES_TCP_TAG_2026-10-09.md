<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-61 audit — the arrow lands where the owner pointed

> Audit date: 2026-10-09 (night-improve-61, after night-improve-60).
> Scope: the owner's correction of night-improve-59's landing plus
> the two finds riding the same transcript — the `=>` glyph belongs
> on the SECTION HEADER marker (not the footer legend), the dl/ul
> suffix figures must be compact (not the 10-column estate), and
> the endpoint lines must name `tcp` (not only `udp`). Method: one
> revert, one lane re-cut with the column arithmetic moved honestly,
> one field law rewritten, one tag family completed — every pin
> re-pinned, every doc surface re-spelled, the A/B protocol run on
> the record.

## 1. The revert (the footer legend)

Night-improve-59 spelled the footer legend's section-switch
affordance `=> section`. The owner's correction, verbatim intent:
that was the wrong surface — the legend returns to its
improve-58 spelling `↑↓ scroll - ←→ section`, and the `=>` glyph
lives where he actually pointed it: the marker beside the focused
section's title. One spelling per surface, both pinned.

## 2. The marker lane (the triangle glyph to `=>`, two columns to three)

The focus marker the owner circled — the glyph at the left of
`top process` / `baseline · policy aggregate` that moved with the
left/right arrows — was the `▸` triangle, single-width, that his
terminal renders as an unreadable dot. The owner's exact reading:
`=> top process`. The honest cut widens the shared marker lane to
THREE columns (`=>` plus its air column, `   ` when unfocused) —
a 2-column lane cannot carry a 2-column glyph AND its air — and
everything that shares the lane moves with it:

- the table's rows, scroll notes, and placeholder lines (eagle);
- the baseline panel's header, rows, and note;
- `render::plan_eagle_columns`' rank reserve, 6 → 7 — the
  degradation ladder's boundaries move with the air they buy
  (the TOTAL column now starts at width 54, was 53; the two-column
  layout at 43, was 42), the label column returns the column the
  lane took, and the numeric cells land on the same terminal
  columns they always did;
- the right gutter keeps its breathing pair (the lane is the
  marker's estate now, not the rank's mirror — the symmetry
  comment says so honestly).

The pins: the boundary pins (54/53, label arithmetic `- 7 -`),
the header pins (`│=> top process` focused, `│   top process`
not), the row pins (`│    1`), the dock pin, the snug-frame
detail test (width 58 now — the TOTAL boundary moved under it),
the placeholder pin, and the baseline panel's focused-header pin.

## 3. The compact rate field (the suffix is not a table column)

Night-improve-59 padded every `[dl X | ul Y]` suffix figure into a
fixed 10-column budget (the Bloomberg cut, bought against a
recorded -7.7% fps / +7.4% dirty tier-crossing jitter). The
owner's transcript circled the dead air twice:
`[dl    166 B/s | ul      8 B/s]` is not a column a reader can
align — the remote endpoint before the figures already varies per
row — so the padding bought nothing the eye could use. The field
law is rewritten: every figure renders at its own natural SI
width, `[dl 166 B/s | ul 8 B/s]`, one canonical renderer on both
surfaces (the live suffix and the depth report), the honest
`0 B/s` zero leg unchanged. The TABLE's rate columns keep their
fixed cells — improve-13's law lives where every row shares the
column; the suffix never did. The A/B ran after the landing
(below) so the cost of the width churn is on the record, not
assumed away.

## 4. The `tcp` tag (the unnamed default, named)

The live monitor's endpoint lines tagged udp and raw but
left TCP — the protocol most rows speak — untagged (the lean-TCP
default). The owner's find, his own transcript: a QUIC-era browser
showed `udp 32.189.222.32:443` beside bare TCP remotes, reading
like UDP was the only protocol worth naming. Every displayable
endpoint now names its proto (tcp / udp / raw, each followed by its air column), the depth
report's `<remote> <proto> <state> [figures]` vocabulary complete
on the live tree. The tag family's pins gained the TCP spellings
across the eagle tree, the focus view, and the compact fixture.

## 5. The A/B (post-landing, the owner's protocol)

Baseline captured on the pre-change tree (post-60, 5a7cbfd) with
`./scripts/bench/frame-bench.py --save`, the after-capture on the
landed tree, the harness the frame-bench protocol owns (10s render
budget, synthetic ConnectionMap so the suffix figures and the
marker lane both render). The numbers are reported in the session
record beside this audit: density, entropy, fps, dirty cells —
the compact field trades the fixed-width churn for natural-width
churn on tier crossings; the lane costs one column of label; the
tcp tag costs four columns of detail line. Nothing here is
assumed — the frame harness measured it.

## 6. What was deliberately NOT touched

The footer's own two-space prefix family (the census, the story,
the status line) — the marker lane is the TABLE's estate; the
focus view's detail indentation (its own family); the depth
report's row format (already spoke the proto); the JSON surfaces
(no field changed); the version (the owner's call alone).
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
