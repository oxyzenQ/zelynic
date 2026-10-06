<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-mitigate-1 / improve-51 audit — the data-explosion question, every counter surface answered with arithmetic (1 trillion packets, a 10-year monitor)

> Audit date: 2026-10-07 (NIGHT-mitigate-1 + NIGHT-improve-51). Scope:
> the owner's verbatim intent — "owner see what if the data explode
> e.g on eagle eyes mode monitoring owner see on footer under title
> top consumer '15.9M packets + 16 cgroups' if the packets reach
> 1 trillion can zelynic have durability, reliable, and ultra long
> endurance? even the monitor is running 10 years on server? not
> just that one but all need depth audit too" — so not just the
> census line: every numeric surface the monitor owns, read at the
> 1-trillion-packet and 10-year-uptime horizons, with the wrap
> arithmetic, the memory bounds, and the render ladders each surface
> rides. Method: the source read surface by surface (kernel booking
> in `ebpf/src/stats.rs`, the delta layer in
> `src/ebpf/loader/delta.rs`, the session accumulator in
> `src/ebpf/render/session.rs`, every formatter in
> `src/ebpf/limiter/format.rs`, every render consumer of a counter),
> each claim pinned to the line that owns it, each horizon computed
> from the code's own constants. Audited at 22a4471 (v20.0.0-era
> tree, run 232 green). Status: the arithmetic answer is YES by
> construction with orders of magnitude to spare — and the audit
> still found two real gaps, one display-side and one
> endurance-side, both closed by this task's commits.

## 1. The mandate and the method

The owner watched the footer's census line — `15.9M packets +
16 cgroups` — and asked the only question that matters at that
surface: what happens when the numbers stop being small. The
question has three separate parts and they must not be conflated,
because they fail differently:

1. **Arithmetic durability** — does any counter overflow, wrap,
   panic, or silently corrupt at 1e12 packets, or at any figure a
   10-year monitor can actually produce?
2. **Memory endurance** — does anything the monitor owns grow with
   uptime, so a 10-year session dies of accumulation rather than
   arithmetic?
3. **Render durability** — does every surface that prints a
   counter stay readable at the same horizons (the engrave-7
   lesson: a raw u64 that explodes the line explodes the reader's
   trust with it)?

Each surface below answers all three. The verdict arithmetic is
computed from the code's own constants — `CgroupStats`'s u64 pair,
`SessionAcc`'s u128 legs, the format ladders' tier sets — not from
estimates.

## 2. The headline numbers, up front

The owner's named figure, 1 trillion packets, and the 10-year
uptime, against every ceiling the code carries:

| surface | width | ceiling | 1T packets (1e12) | 10 years at line rate | verdict |
|---|---|---|---|---|---|
| kernel per-cgroup packet counter | u64 | 1.8446744e19 (18.4E) | 18.4 million x below | 4.73e14 at 1.5 Mpps = 39,000 x below | durable |
| kernel per-cgroup byte counter | u64 | 18.4 EB | n/a | 18.4 EB at 1 Tbps = 4.7 years — wraps, wrap-coherent | durable (delta layer) |
| session packet accumulator | u64, saturating | 18.4E | 18.4 million x below | 9.46e14 (both directions) = 19,500 x below | durable |
| session byte legs | u128, saturating | 3.4e38 (340M QB) | n/a | 3.9e20 B at 1 Tbps = 8.7e17 x below | durable |
| footer census render | format_count | "18.4E" terminal | "1.0T packets" | "473.4T packets" | readable |
| board TOTAL / footer grand | format_bytes_wide | uncapped past QB | n/a | "390.0 EB" / past ZB | readable |

The 10-year column uses the code's own line-rate figures (the
`session.rs` lts-5 note's 1.5 Mpps; the physics ceiling of a
100 GbE small-packet stream is 148.8 Mpps, and even THERE the
packet counters hold 390 x margin over a decade — see section 3).

## 3. The packet counters — the named question

The booking side (`ebpf/src/stats.rs`): per-cgroup
`CgroupStats { packets, bytes }`, both u64, both Relaxed
`fetch_add` RMW on 8-aligned offsets. `fetch_add` WRAPS at
u64::MAX rather than saturating — the deliberate, documented
choice (the wrap horizon note in `book_packet`): a wrapping
producer is recoverable, a panicking one hangs the CPU in the
no_std `loop {}` handler. The wrap horizon for packets:
1.8446744e19 / (1.5e6 packets/s) = 1.23e13 s = **389,000 years**
of single-cgroup line rate. The fastest deployed hardware
(148.8 Mpps, 100 GbE minimum-size) wraps one cgroup's counter
after **3,930 years**. A 10-year monitor at that rate sits
390 x below the wrap. One trillion packets sits 18.4 million x
below it. The owner's number is not close to any cliff.

The delta side (`src/ebpf/loader/delta.rs`): even when a byte
counter DOES wrap (the byte leg wraps in years, not millennia —
section 4), `wrap_coherent_delta` reads it exactly: modulo-2^64
subtraction, the inverse of the kernel's `fetch_add` booking,
exact for every true per-interval delta under 2^63 (9.2 EB per
POLL — 73 Pbps, nine orders past any deployed link). The
half-space discriminator then classifies a backwards step past
2^63 as the LRU eviction restart it actually is (dinner-6's E1
rider) and reads the fresh accumulator — the 18-exabyte wrap
phantom is retired by construction, pinned in the wrap pins.

The accumulator side (`src/ebpf/render/session.rs`): the session
packet counter folds both directions' deltas per frame,
`saturating_add` per the boost-16 discipline — a saturated
counter reads as its honest ceiling ("18.4E" on the census line),
never panics (debug), never wraps (release). The u64 choice is
the lts-5 decision, documented with its own arithmetic: 2^64
packets is 389,000 years at 1.5 Mpps — the byte legs were the
only reachable ceiling, and they were widened to u128 instead.

The render side: the footer census line rides `format_count`
(NIGHT-engrave-7, the counter-explosion hardening — the direct
ancestor of this audit's mandate): decimal SI tiers, one decimal,
exact integer tenths in u128, terminal at E, "1.0T" at the
owner's named figure, "18.4E" at saturation, small counts exact
and unpunctuated. The line is width-bounded by the ladder, not by
the counter.

## 4. The byte counters — the wrap the 10-year monitor CAN reach

The kernel byte counters wrap first at the horizons the code
itself documents: 18.4 EB through ONE cgroup is 208 days at
MAX_RATE (1 TB/s, `types.rs`'s 8-TbE-class headroom), 4.7 years
at 1 Tbps, so a decade-long monitor pinned at 1 Tbps rides
through two wraps per cgroup. This is the one wrap the audit's
math says is REACHABLE, and it is the one the code is already
built around:

- the delta layer stays modulo-exact across every wrap (lts-5);
- the eviction-restart discriminator keeps the LRU lane's
  restarts reading as restarts (total-lts-5);
- the session legs are u128 (lts-5) — the fold's honest ceiling
  is 3.4e38 B, 8.7e17 times the 10-year 1-Tbps figure;
- the board's TOTAL column and the footer's grand row render
  through `format_bytes_wide` (the u128 twin, ladders B through
  QB, uncapped tail "340282366.9 QB" at u128::MAX), so the
  session surfaces can SAY "1.0 ZB" and mean it — pinned.

The focus view's `lifetime` row is the one surface that reads the
kernel's RAW cumulative counters (the pre-delta horizon, since
pin): it renders through the u64 ladder with a saturating sum
(boost-16), so a post-wrap counter restarts from its wrap — the
row reads the kernel's own truth, and the session surfaces carry
the wrap-coherent truth. Two horizons, both honest, both
documented at their render sites.

## 5. Memory and endurance — the 10-year state inventory

Every state carrier the monitor loop owns, read for growth
against uptime:

| carrier | owner | bound | growth with uptime |
|---|---|---|---|
| observer counter maps (dl/ul) | kernel, LRU 4096 | 128 KiB payload + LRU node overhead | none — idle entries age out |
| socket cookie maps (dl/ul) | kernel, LRU 4096 | 2 x 4096 x 8 B keys/values | none — dead sockets age out |
| policy/bucket/stats/window/ring maps | kernel, HashMap 1024 | fixed | none — occupancy bounded by policy legs, stale rows swept by the reclaim path |
| leaf/flow/debt/pool LRU families | kernel, LRU 4096 each | fixed | none — the documented posture |
| loader prev-stats (dl/ul) | userspace, clear-rebuild per poll | mirrors the kernel map's live set | none — `clear()` then re-`insert` |
| session leaderboard | userspace, cap 4096 | ~300 KB | none by cap (see section 7) |
| ConnectionMap cache + join | userspace, TTL 3s clear-rebuild | live processes | none |
| IdentityMap | userspace, TTL clear-rebuild | live processes | none |
| BaselineLane | userspace, `retain(live)` per refresh | live policy roots (1024) | none |
| render frame lines | userspace, transient per frame | terminal height | none |

The clocks: `monotonic_ns` u64 (584-year horizon at ns
resolution; a 10-year run consumes 1.7% of it); the ring windows
(`baseline.rs`) divide a u64 ns now by the window width, so the
window index itself is a u64 with the same horizon; the session
uptime is a `Duration` (u64 seconds) rendered by
`format_uptime`'s days tier — a 10-year run reads `3652d:15h`,
eight columns, no overflow, every compression tier intact (a
years tier remains a cosmetic owner option, not a safety one).
The rate conversions (`rate_bps`, `rate_bps_wide`) divide in f64
and cast back with Rust's saturating `as` — a figure past the
u64 rate domain saturates rather than becoming garbage; the
peaks they convert are per-frame deltas under the delta layer's
own half-space bound.

The one-frame tolerance (a transient map-read error folds an
empty frame and re-arms the span clock only on success) is the
10-year reliability posture for transient faults: no data loss,
no double count, no live-TUI death on a hiccup.

## 6. Finding A — the focus view's raw packet figures (improve-51)

The engrave-7 hardening walked the census line onto the SI ladder
but missed the focus view's per-direction rows: `focus.rs` prints
the per-poll packet deltas RAW in the parens —
`download  5.0 MB (2244843)`. The figure is a DELTA (bounded by
one poll interval, so it is display honesty at stake, not
arithmetic safety — a 60 s interval at 148.8 Mpps carries 8.9e8
packets, a 9-digit figure on a row whose byte sibling renders in
6). Every other count surface in the render tree already rides
the ladder (the footer census, the "+N more hidden" notes, the
detail tree's process/socket suffixes, the census line of the
depth report); the focus view is the one surface the walk missed.
The fix: both parens figures route through `format_count`, pinned
at the exploded figure. The commit is display-only — no
arithmetic, no layout, no layout budget changes (the ladder's
output is strictly narrower than the raw figure it replaces).

## 7. Finding B — the leaderboard freeze (mitigate-1)

The userspace bound `MAX_TRACKED_CGROUPS` (4096) predates the
kernel maps' LRU lane: at introduction it mirrored a HASH map's
hard ceiling; since the dinner-6 E1 rider the kernel counts any
LIVE cgroup (idle entries age out), and the userspace bound
stands alone — as a FREEZE. Past 4096 DISTINCT cgroups in one
session, `admits` refuses every fresh cgroup forever: the first
4096 own the board for the rest of the monitor's life, dead or
alive.

The 10-year arithmetic: a systemd-scope-churning host (a CI
runner with per-job scopes, a container host, a login server)
produces hundreds of distinct cgroup LIFETIMES per day — 100
/day is 36,500 in a year, 365,000 in a decade. The freeze lands
in the first weeks-to-months, and from that frame on the monitor
is silently blind: the kernel still counts the fresh cgroup (the
LRU lane always has room for the live), the observer still
delivers its deltas, and the leaderboard refuses the fold —
fresh apps never board, the footer census never counts them, the
grand total never includes them. The USAGE limitation 11 tail
documents the freeze and names the posture question an owner
decision: "mirror the LRU and retire the least-recently-active
row, or keep the freeze". This task's mandate — durability,
reliability, ultra long endurance — is that decision being made.

The mitigation, dead-row retirement: a row retires from the
leaderboard only when the frame's own display filter would hide
it anyway — no identity entry AND no traffic that frame —
sustained for a 3-frame grace, and only while the identity walk
itself is alive (a non-empty map: a failed walk is a signal loss,
not proof of universal death, and retires nothing). The
liveness rule is the `board_rows` filter's own rule (identity
present OR in the window's active set), so the retirement is
display-neutral by construction: a retired row was already
invisible that frame. The footer grand sums the post-filter
board, so the retirement is grand-neutral too. The memory bound
is unchanged (4096 entries before, 4096 after). The ONE thing
the retirement changes is the thing the freeze broke: a fresh
cgroup finds a slot again, because the dead hold none. The
board's semantics — rank by what an app ate this session — are
untouched for every live row.

The honest residual, stated rather than engineered around: a
host with MORE than 4096 concurrently-live-with-traffic cgroups
still overflows the kernel LRU itself, and limitation 11's
best-effort posture stands (the userspace bound now mirrors the
kernel bound's semantics — live things keep their rows, dead
things age out — instead of freezing on the first 4096 ever
seen). The leaderboard contract's one true loss: a retired row's
history leaves the board when it dies — the same loss the
display filter already imposed (the row was invisible), now
made consistent at the accumulator.

## 8. The closure map

| finding | fix | commit shape | pins |
|---|---|---|---|
| A — focus view raw packet figures | route both parens through `format_count` | focus.rs one-line pair + pin | the exploded-figure pin (2.2M shape) in the focus tests |
| B — the leaderboard freeze | `SessionState::retire_dead`, the board-filter-mirroring retirement with a 3-frame grace, the identity-signal guard, and the cap gate (the pass engages only at a full board — the frame-bench regression the ungated shape measured, closed) | session.rs + the eagle call site + USAGE limitation 11 tail + the session module docs | the retirement family: the gate, grace, slot-freeing at cap, signal-loss guard, streak reset, traffic-without-identity liveness |

## 9. Verification

- The new pins (section 8) green on the host build — six retirement
  pins (the gate, the grace, the slot-freeing, the signal-loss
  guard, the streak reset, the liveness mirror) and the two focus
  ladder pins.
- The full existing render family pins green (footer, census,
  eagle, focus, detail, session, wrap, format families) — no
  existing contract moved (820 passed, 0 failed on the host
  battery).
- `build.sh check-all -q` clean inside the 2-minute cap;
  gate-keepers green.
- The supermassive batteries are untouched by construction (no
  harness change in this task); the live proof for the
  retirement rides the next scheduled run of the existing
  batteries, and the unit pins carry the contract.
- Benchmark A/B: RUN (non-docs change with a render surface) —
  the full 10s frame bench, two samples per side on this sandbox:
  the FIRST shape (the pass running every frame) measured a REAL
  -7.6% on the render path's fps (7134 vs 6562, outside the ±1%
  same-tree noise band) — the per-frame candidate walk over the
  accumulator costs ~10us/frame on this VM, pure waste below the
  cap where retirement changes nothing. The fix is the cap gate:
  the pass engages only when the board sits at MAX_TRACKED_CGROUPS
  (the one state where a freed slot changes anything), the gate
  closing clears the streak era, and the gated A/B reads 7133.5 vs
  7082.0 fps (-0.7%, inside the noise band) with every visual
  metric byte-equivalent (density gini +0.0001, frame entropy
  -0.0009, dirty cells -0.1%). At the cap itself the 4096-row
  walk rides a 1s-plus poll cadence where it is noise. The
  measurement is the audit's own honesty: the regression was
  found, the gate closed it, and both numbers ride the commit.

## 10. The residuals that stay, by name

- The kernel LRU's documented best-effort under 4096+
  concurrently-live-with-traffic cgroups (limitation 11) — the
  verifier's finite map sizes, accepted and documented, not
  chaseable.
- The focus `lifetime` row reads the kernel's raw wrap-truth
  (two horizons, both honest — section 4).
- `format_uptime`'s days tier at decade scale reads `3652d:15h` —
  safe in every budget; a years tier is an owner cosmetic call.
- The delta layer's unreachable corner (a restart whose gap is
  itself past 2^63) keeps the modulo reading — documented in
  `delta.rs`, never worse than the pre-audit behavior.
- The u32 cgroup-id space (4.29e9 lifetimes) outlives any real
  host by the `stats.rs` note's own arithmetic — the id wrap is
  the one horizon no monitor survives to see.
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
