<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-59 audit — the => legend, and the Bloomberg cut's two finds

> Audit date: 2026-10-09 (night-improve-59, after night-improve-58).
> Scope: the owner's two asks — the swipe indicator/legend should
> use `=>` (not the arrow pair that reads as dots on his
> terminal), and a depth audit to push the eagle-eyes monitor mode
> to peak "like a bloomberg terminal", with the explicit guard:
> if it is already at peak, skip — no over-engineering. Method:
> walk every render surface against the Bloomberg standard (dense
> but disciplined, stable columns, honest units, zero waste),
> land only what the walk proves, and record the at-peak verdicts
> for everything else.

## 1. The legend (the owner's exact glyph, 3382e44)

The footer's status line now spells the section-switch
affordance `=> section` — the left/right arrow pair rendered as
unreadable dots on the owner's terminal, and the ASCII pair
carries the "this leads to the other section" reading on every
font ever shipped. The scroll arrows stay (`↑↓ scroll`): the
owner asked about the swipe indicator specifically, and his
terminal draws the vertical pair fine. One spelling, the
engrave-3 law's only home, the pins and USAGE/BRANDING samples
re-spelled with it.

## 2. The depth walk — what the audit found at peak

The Bloomberg standard, surface by surface, and the verdict each
earned (the "if peak skip" guard — these are the skips, named so
the next audit does not re-walk them):

| surface | verdict | the why |
|---|---|---|
| the table's numeric columns | peak | right-aligned, the fixed 10-column RATE budget (improve-13), the tier ladder pinned by engrave-era tests |
| the compression ladder | peak | 6-column rank reserve, 1-column gaps, blanks drop before grips before the frame (render.rs's degradation ladder) |
| the diff engine | peak | scroll-free, wrap-coherent, one syscall per frame — the frame budget the estate already measured |
| the theme/border/chroma family | peak | 12 palettes, OSC 11 background follow, the brand rails interpolate the active theme per row |
| the arrival-rates vocabulary | peak | research-7 landed it on both surfaces; every dl/ul figure is a per-second arrival rate comparable against the policy on sight |
| the loading morph, the scroll notes, the focus view | peak | the one-row morph, the window-is-the-budget notes, the deep detail — each pinned by its own family |
| the endpoint rate suffixes | **the find** | see section 3 — the figures shifted columns frame to frame, and a zero leg spoke a policy verdict |

## 3. The two finds (both real, both landed, 3382e44)

**Find 1 — the steady rate field.** Every `[dl X | ul Y]` suffix
figure on both eagle-eyes surfaces (the live monitor's detail
lines, the depth report's endpoint rows) now lands right-aligned
in the estate's fixed 10-column RATE budget — improve-13's own
width, "999.9 KB/s" the widest the SI ladder renders. The
arrival-rates landing recorded -7.7% fps and +7.4% dirty cells
from one cause (shifting suffix widths re-dirtying whole lines
every time a rate crossed a tier); the fixed budget kills the
jitter at the root — the digits move, the columns never do. One
canonical renderer (detail::steady_rate_field) serves both
surfaces; the vocabulary cannot drift again.

**Find 2 — the honest zero leg.** A mover that moved bytes on one
direction only rendered the quiet leg as `format_rate(0)`'s
"BLOCKED" — a POLICY verdict on the observer's surface, the exact
sin the footer's own documented law forbids ("`0 B/s`, never
`BLOCKED` — that is the limiter's policy verdict, and the observer
does not judge"). Both surfaces shared the bug; the steady field
carries the honest zero with it.

## 4. The bench fixture's blind spot (closed the hard way, 821455b)

The A/B of the steady field came back +2.3% dirty — against the
design — and the number was deterministic, so it was true. The
walk to the cause found the harness's own hole: the cookie-map
absolutes stepped by a CONSTANT per-frame delta, so every fixture
rate was frozen frame over frame — rate churn (the real-world
churn the steady field exists to steady) was invisible, and the
only measured detail-line churn was the busy-toggle shift (the
fixture's 33%-duty busy pattern, churn by design). The fixture
now steps its deltas on a 3-frame cycle (rates change frame to
frame and cross SI tiers), still a pure function of (cookie,
frame) so the A/B stream stays frozen.

**The honest arithmetic, both sides recorded.** On the fixture's
busy-heavy stream the steady field prices at +2.3 dirty
cells/frame (a wider suffix shifting on every toggle — 0.67
toggles per line per frame at 33% duty). On a real host the mix
inverts: rates change every frame (the steady field's win, the
recorded -7.7%/+7.4% cost it removes) and busy is rare (a
congestion signal, not a resident state). The fixture can now
measure both sides; the audit records both numbers and names the
mix each belongs to.

## 5. Pins and gates

8 bracket assertions re-spelled onto the budget (the ranked-tree
cap, the focus ranking, the depth rows), 2 new pins (the steady
field's matrix with the tier-promotion edge and the
every-figure-is-10-columns contract; the quiet leg's honest zero
with the BLOCKED prohibition), USAGE's boxed samples re-rendered
in the steady field with the frame border width preserved. 885
binary tests green, check-all in cap, gate-keepers 18/18,
versions untouched (v50.0.0-beta.1 — the owner decides bumps).

## 6. The verdict

The monitor mode was one finds-class away from peak and is there
now: every figure is a per-second arrival rate (research-7), the
rate columns are steady frame to frame and never speak a policy
verdict (this audit), the legend is the owner's glyph, the
six-key contract rides the frame (improve-58), and everything
else the walk touched was already pinned at peak by its own
family. No new concepts, no new columns, no over-engineering —
the Bloomberg cut is two renders and a glyph.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths or symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
