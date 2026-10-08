<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-38 audit — eagle eyes walked to peak: the owner's transcript decoded, the max line's wobble, and the cap that could hide the answer

> Audit date: 2026-10-08 (NIGHT-hunt-38 + NIGHT-improve-56). Scope:
> the owner's ask — a total depth audit of eagle eyes to peak, the
> masterclass monitoring pass, sparked by a suspected
> bug/inconsistency in the leaderboard's endpoint rows:
>
> ```
> 2 cg:86806 (brave +22)
> L brave (1352258) 7 sockets:
>      47.239.88.7:443 [d1 126.6 KB | ul 61.4 KB]  <-- what this mean? need documented
>      32.189.222.32:443 [dl 26.4 KB | ul 25.2 KB]
> ```
>
> "not just that one but include total max/avg dl/ul need audit and
> others too." Method: the transcript decoded row by row against the
> render chain, then the whole chain walked with fresh eyes —
> session state, leaderboard, detail tree, focus view, footer
> census, the join, the ladders. Three finds fixed this task (two
> code, one doc); the rest of the surface audited clean. Audited at
> bd8de0e (post hunt-37).

## 1. The transcript, decoded (the owner's "what this mean?")

| The line | What it is |
|---|---|
| `2 cg:86806 (brave +22)` | Rank 2 on the session leaderboard. `cg:86806` — the cgroup's identity, raw ID form (the /proc walk resolved its comm but the label keeps the ID home); `(brave +22)` — 23 processes hold sockets inside this cgroup: the named one plus 22 more (`label_with_count`'s splice, NIGHT-boost-21). |
| `L brave (1352258) 7 sockets:` | The rank row's detail tree — `L` is the terminal's rendering of the `└` box glyph. One socket-holding process (`brave`, pid 1352258) with 7 displayable endpoints; the ranked tree's cap shows the two hungriest (see find 2 — before this audit it showed the two WALK-FIRST ones). |
| `47.239.88.7:443 [dl 126.6 KB \| ul 61.4 KB]` | One endpoint: the remote peer, and the bytes THAT socket moved since the monitor attached — **dl** = download (the socket received), **ul** = upload (it sent), SI one-decimal. The per-socket join (NIGHT-boost-26): the kernel books per-cookie bytes in both hooks' LRU maps, the observer point-looks-up the cookies the /proc walk resolved. |

**The `d1` verdict: not a bug — the audit's honest first answer.**
An exhaustive search returns zero `d1` anywhere in the tree; one
format string (`detail::endpoint_text`) prints every endpoint row
the frame carries, and the owner's own transcript shows the SAME
string transcribed `d1` on one row and `dl` on the next — the
lowercase-L-read-as-one font confusion, not a render defect. But
the confusion itself is a real defect of discoverability: the
vocabulary was documented only inside USAGE's ranked-table prose,
the glossary had no entry, and the suffix's horizon (since monitor
attach) was mislabeled on the depth report's page (find 3). The
masterclass answer is documentation the owner can reach from the
screen: the glossary now carries `dl`/`ul` (with the
lowercase-L-not-one decode), the endpoint suffix, the `+N` label
suffix, `[busy]`, and the `udp` tag — and USAGE decodes the pair
inline at every place it renders.

## 2. Find 1 (fixed): the max line wobbled with the current frame's span

**The bug.** The footer's `total max dl | ul` line rendered
`rate_bps(peak_bytes, CURRENT_span)`: the session state stored the
peak as raw per-frame BYTES, and the footer converted it to a rate
with the span of whatever frame was rendering. Two defects ride
that shape:

- **The wobble**: a span jitter (a slow poll, a busy host) restated
  the historical peak on every render — the max line moved on
  frames that set no new peak, exactly the "inconsistent data"
  class the owner suspected.
- **The misstatement**: the honest peak RATE is
  `max(delta_i / span_i)` over frames; `max(delta_i) / span_now`
  is a different number whenever spans vary — a 1000-byte frame
  over a slow 10s poll ran at 100 B/s, but the old form rendered
  it as 1000 B/s on any later 1s frame, ten times its truth.

**The fix.** The peak is now tracked as a RATE at fold time:
`note_frame` receives the frame's own measured span and stores
`max(peak, rate_bps(delta, span))` — each peak divided by the span
IT was measured over, fixed forever, rendered by the footer with
no conversion. A later frame's span cannot reach it. The zero-span
guard (the loading frame's shape) notes nothing. Pinned by two new
session pins: `peaks_are_rates_at_their_own_spans_not_bytes` (the
1000-B/10s vs 500-B/1s discrimination) and
`a_quiet_slow_frame_never_restates_the_peak` (the wobble itself).

## 3. Find 2 (fixed): the ranked tree's cap could hide the answer

**The bug.** The live leaderboard's detail tree caps each
process's expansion at two endpoints — chosen in WALK order (the
order the /proc census produced them), while the focus view and
the depth report rank endpoints bytes-desc (the 2.4 promise: "the
hungriest endpoint first"). Truncation without ranking is the
worst place to skip the law: with 7 sockets and the eater walked
third, the cap showed two quiet endpoints and buried the answer —
the owner's own transcript shape. The ranked view is exactly where
a truncated reader asks "which of the 7 is eating?".

**The fix.** The sort is extracted (`rank_endpoints_by_bytes`)
and the ranked tree's cap now ranks bytes-desc before it truncates
— one law, both trees, extracted so they cannot drift. The header
still carries the honest count (`7 sockets:`), and the byteless
tail keeps its stable walk order behind the traffic-carriers. The
existing boost-26 pin stays green byte-for-byte (its fixture's
eater was also walk-first); a new pin
(`the_ranked_tree_cap_shows_the_hungriest_endpoints`) drives the
owner's exact shape — three quiet sockets walked first, the eater
walked LAST — and asserts the cap shows the eater first.

## 4. Find 3 (fixed): the depth docs mislabeled the suffix's horizon

USAGE's `--depth` section said the endpoint suffix carries
"per-socket session totals with the same horizon as the table's
TOTAL column" — wording pasted from the live view's story. The
depth report's figures are the FOCUS WINDOW's bytes (default 3s,
`--focus` widens it; `TrafficEndpoint.dl` is "window download
bytes" in the source). The same suffix shape, two different
horizons — and the docs stated the wrong one. Fixed: the depth
section names its own window and cross-references the live
monitor's since-attach horizon; the glossary's suffix entry names
both so the family reads as one vocabulary with per-surface
horizons. The stale "the ranked table's capped expansions keep the
walk order" contrast sentence (also in the depth section, and also
wrong after find 2) rides the same fix.

## 5. The clean table (walked, skip-and-noted)

| Surface | Verdict |
|---|---|
| `SessionAcc` / `absorb` — the u128 saturating fold, wrap-coherent deltas, the admission bound | clean (lts-5/boost-16 lineage re-verified) |
| `retire_dead` + the board filter | clean (hunt-34/mitigate-1, re-verified) |
| The AVG line — the same per-direction legs the grand totals, divided by the same uptime the total row renders | clean: the three-line paragraph shares legs and clock by construction |
| The grand/census — packets (session horizon), cgroups (the frame's own board scope), SI compact ladders | clean |
| `top_consumer` — strictly-greater byte ranking, walk order on ties, honest degradation to the label | clean (dinner-6) |
| The endpoint join — lifetime per-cookie maps, point lookups, one-frame tolerance on error, lean byteless rows | clean (boost-26) |
| The focus view — labeled horizons (per-poll deltas, the combined rate, lifetime, the baseline lane) | clean |
| Column planning — the numeric widths fit both the rate and total ladders (NUM_W 10 vs `999.9 MB/s` / `1023.9 EB`) | clean |
| The detail caps — DETAIL_LINE_CAP 4 with the honest `+N more` note, ENDPOINT_SHOWN 2 with the count in the header | clean by design; the cap's SELECTION now ranked (find 2) |
| The tier ladder, the pinned footer, the border/dock composition | clean (engrave lineage) |

## 6. The verdict

The owner's suspicion was two-thirds right: no glyph bug (the
transcript's own inconsistency proves the font read), but the max
line genuinely wobbled and the ranked tree's cap could genuinely
hide the eater — both fixed with the focus view's own laws, both
pinned. The third find is the one the owner asked for by name:
the vocabulary now carries its decode everywhere a reader can
reach — the glossary's five new entries, USAGE's inline decode at
both surfaces, and the horizon split named honestly. Eagle eyes
stands at peak: every figure on the frame names its horizon and
its scope, the max is the loudest moment's own rate, and what a
cap hides is never the answer.

Empirical, fresh on this tree: check-all green (834 + 3 new
render pins), gates 17/17; the A/B frame bench byte-identical
where it counts (bytes/frame +0.0%, emit/dirty/gini/entropy within
host noise) — the changes reorder what a cap selects, never how a
row renders.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every .md — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
