<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# NIGHT_PRIVATE_RESEARCH_7 — The Arrival-Rates Pass (2026-10-09)

> Owner ask (chat, paraphrased intent): "should I delete dl/ul from
> top process, or keep and improve it?" — approved as "simple,
> masterclass to look at, but useful" (keep + improve, never delete).

## The find (the owner's own transcript)

The owner read three figures wrong in one session, and every one of
them was the renderer's fault, not the data's:

1. **Bytes-per-window displayed where a rate was expected.**
   `[dl 771.1 KB]` over an invisible 3s window reads as a rate until
   mentally divided — the owner computed "this is breaking 1 Mbps
   even though I limited it to 100 KB/s" from a figure whose true
   rate was 257 KB/s.
2. **Arrival semantics unlabeled.** The eagle-eyes figures count what
   ARRIVED (pre-verdict, retransmits included, drops not yet
   subtracted) — so an arrival above the policy is the demand the
   limit absorbed, not a bypass. Nothing on screen said so.
3. **The live view's per-socket figures were since-attach totals.**
   The cookie maps carry ABSOLUTE counters (loader.rs `socket_bytes`),
   and the monitor installed them raw — a socket that downloaded
   700 MB an hour ago pinned itself above every current mover in the
   bytes-desc ranking forever. DeepSeek's own decode ("per 3s window")
   was wrong for the live surface too: the transcript's confusion is
   the proof the contract was unreadable.

The limiter was never bypassed — `status` booked 210 MB of drops the
whole time. The display owed that answer on sight.

## The fix (four render-layer changes, zero eBPF changes)

| Surface | Before | After |
|---|---|---|
| Depth header | `network traffic (30s focus): dl 1.2 MB · ul 33.3 KB` | `network traffic (30s focus · arrival): dl 40.0 KB/s · ul 1.1 KB/s` |
| Depth endpoint suffix | `[dl 1.2 MB \| ul 28.2 KB]` | `[dl 40.0 KB/s \| ul 940 B/s]` — the window's own seconds |
| Enforcement line | `limited — dl 200.0 KB/s · ul 200.0 KB/s` | `limited (shaping) — …` when the window's bracketing ledger reads saw the dropped counter MOVE (blocked/unlimited never tagged — blocked drops by definition, the tag would be noise) |
| Live endpoint suffix | `[dl 771.1 KB \| ul 21.6 KB]` (since attach) | `[dl 257 KB/s \| ul 7 KB/s]` — the frame's movers differenced against the previous folded join, divided by the MEASURED poll-to-poll span |

Plus the footer speed pair relabeled to the same vocabulary:
`total max dl | ul` / `total avg dl | ul` → `peak arrival dl | ul` /
`avg arrival dl | ul` — the owner's third confusion (`total max dl =
1.1 MB/s` against a 100 KB/s policy) answered by the label itself.

### The design decisions on the record

- **The live fold is untied from the poll.** `join_prev` advances on
  every SUCCESSFUL join read, so the delta always spans exactly the
  gap between joins. The rare poll-ok-join-err-recovery frame renders
  a two-gap numerator over a one-gap span — an UNDERESTIMATE, the
  safe direction: this pass exists so the family never shows a fake
  burst above the policy. An Err keeps the previous frame's movers
  (the leaderboard's own one-frame tolerance).
- **Movers only.** The fold keeps sockets that moved either direction
  nonzero THIS frame; a connected-but-quiet socket keeps its lean row
  (absence is the "quiet now" signal) — and the two-slot ranked cap
  now ranks by CURRENT movement, closing the stale-heavy-socket
  pinning the absolute join carried.
- **The shaping verdict is a bracket delta, not a guess.**
  `window_dropped_bytes(closing, baseline)` = the ledger's dropped
  counter across the window's bracketing reads (the handler reads the
  pinned stats map twice — one extra read per report). Missing rows
  count as zero booked; a swept-and-reborn counter reads zero, never
  negative.
- **The accounting line moved to the closing bracket.** It used to
  render the PRE-window ledger — a 30s report under-reported its own
  enforcement by 30 seconds of drops. It now renders as-of-print,
  window included.
- **The JSON document is unchanged** (stable v11 scripting shape):
  `window_secs` + `download_bytes`/`upload_bytes` per endpoint;
  machines derive rates, the text renders them.

### The uniform rule (now enforced by vocabulary)

| Surface | Question it answers | Unit |
|---|---|---|
| eagle-eyes (live + depth) | "what is happening NOW" | per-second arrival rates |
| status / accounting | "what happened SINCE the pin" | cumulative totals + drop share |

## Pins

- `window_dropped_bytes_is_the_bracket_delta` — the delta, the still
  counter, the swept row, the fresh pin, the reborn counter (never
  negative).
- `report_lines_tag_the_shaping_window` — quiet window carries no
  tag; `window_dropped > 0` tags `limited (shaping)`.
- `enforcement_words_and_sentences_match_the_verdicts` — extended:
  unlimited/blocked never tagged, the mixed limited arm carries it.
- `window_figures_divide_by_the_windows_own_seconds` — the owner's
  exact transcript shape: 1.2 MB over 30s renders 40.0 KB/s, the
  endpoint riding the same denominator.
- detail/depth suffix pins re-spelled to per-second forms; footer
  label pins re-spelled across six files.

Battery: 881 binary + 58 integration green (3 new pins), fmt + clippy
clean on both feature lanes, LOC caps held (report.rs 536, eagle.rs
565, commands/eagle.rs 582, monitor.rs 513 — all under 600).

## The A/B, recorded honestly (the owner's 10s protocol)

Full-budget pair: fps 5618.8 → 4968.6 (-11.6%), dirty 75.9 → 84.1
(+10.8%). A controlled same-conditions re-run (quick budget, both
sides freshly compiled, back-to-back): fps 5451.0 → 5031.0 (-7.7%),
dirty 91.1 → 97.8 (+7.4%) — reproducible, not noise (identical
back-to-back runs hold 0.02%). The deterministic frame diff (fixed
LCG + fixed span make frame content a pure function of the frame
index) pins the mechanism: on frames whose detail lines shift with
the leaderboard reorder, before churned 301 cells vs after 326 —
the per-second suffix lines are ~6 cells wider (the two `/s`), so a
shifted line dirties more cells — and on frames without detail-line
movement the churn is byte-identical (149 = 149). The fps and dirty
deltas carry the same signature (-7.7% vs +7.4%): the render path
is not slower, the diff engine does proportionally more work on the
wider shifting lines. The bench's own emit metric agrees in the
favorable direction: the suffix text is now STABLE frame-to-frame
(the bench's constant-delta fixture renders constant rates), so the
engine actually EMITS less (-2.7% bytes/frame).

At the real monitor's 1 fps cadence the absolute cost is 98 cells of
3200 per frame — 3% of the screen, imperceptible. Accepted as the
width price of the uniform per-second vocabulary (the only
alternative — a compact `660.0K/s` spelling — would fragment the
one-vocabulary law the pass exists to enforce). The movers fold
itself (one differencing pass over the frame's cookies) rides inside
the same budget.

## What was deliberately NOT done

- **dl/ul not deleted from top process** — per-endpoint attribution
  is the product; the pain was width-solvable by improve-58's scroll,
  not by removing the answer.
- **No per-socket allowed/dropped** — the limiter books its ledger
  per cgroup, not per socket; coupling the observer to verdicts would
  be a new map + a new hook for a figure the accounting line already
  answers in aggregate (the no-bloat law).
- **No dual display** (`771 KB · 257 KB/s`) — one figure per cell; the
  totals ride `--print-json`.

## Named residuals

1. **Sub-second rates round to `0 B/s`** — a socket that moved 1-14
   bytes over a 30s window renders the honest rounded `0 B/s` (the
   live view's 1s span can never hit it: a mover's rate is ≥ 1 B/s).
   Accepted: the alternative (a floor) would lie.
2. **The transcript's other wrong decode stands unguarded** —
   DeepSeek's "per 3s window" reading of the LIVE view was wrong
   before this pass (it was since-attach); now the live view IS
   per-frame, so the wrong decode is accidentally the truth. The
   residual is documentation-shaped: the glossary carries it.
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
