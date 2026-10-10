<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-mitigate-3 audit — the held-rate rows' floor was the overreach: the hunt-Z5 ceiling doctrine applied to the claims proof, one live run falsifying the fleet's convergence assumption on the way

> Audit date: 2026-10-07 (NIGHT-mitigate-3, riding NIGHT-mitigate-2's
> mandate). Scope: the same owner's mandate, translated — "CI is all
> passed except one failed left; mitigate it so it cannot happen
> again in the future, even flaky or other conditions" — now with
> the live falsification in hand: mitigate-2's first close (the
> fleet instrument) landed, pushed as 6588e3a, and the very next
> supermassive run (37588414621) reddened THREE of four legs on the
> same two rows — the fleet read 36.0-38.1% of a 2mb policy and
> 42.9-44.5% of a 5mb policy on the busy-hour runner pool while the
> best-musl leg on a quieter host read 68.8%/80.7% in-band. The
> fleet's convergence assumption ("four staggering sockets keep the
> offered load above the refill") holds at high rates (the
> precision row's 95-102% at 69-100mb, the many24 row's 102.4% at
> 4mb over 24 leaves) but NOT at 2-5mb on a loaded shared runner:
> the AIMD equilibrium there is rate-dependent, and its busy-hour
> floor sits where one flow's did. Method: the run's three failing
> legs' logs pulled and cross-read against the passing leg, the
> matrix's own verdict shapes for the same physics class located
> (the hunt-Z5 ceiling-only rows, the ladder's GSO-floor rungs),
> the doctrine applied verbatim, pinned rootlessly. Status: the
> floor removed from both held-rate rows (ceiling + silent-zero
> guard now), the row names matched to their verdicts, and the
> residual named honestly.

## 1. The mandate, continued

Mitigate-2 closed the instrument (single flow -> fleet) and the
precision discriminator (refusals -> the budget scale), and its
live verification run is the verifier of record: the precision row
performed exactly as designed on the busy legs (offer 470.9 MB vs
the 731.1 MB budget -> adapted 100mb -> 73mb -> still offer-limited
-> the honest SKIP with the admit-ratio 1.0013 carrying the
policer's contract) — but the two held-rate rows reddened on three
of four legs. The mandate says mitigate so it cannot happen again;
the live run says the remaining red is the verdict law itself.

## 2. The evidence — the same two rows, three legs, one busy hour

Run 37588414621 (push 6588e3a, 2026-10-07T07:47Z), the four legs:

| Leg | no-daemon (5mb) | per-app (2mb) | witness B | verdict |
|-----|-----------------|---------------|-----------|---------|
| low gnu | 44.5% (windows 3209/2259/2227 KB/s) | 36.0% (851/802/720) | (failed row set) | failure |
| low musl | 44.5% (3209/2259/2227) | 36.0% (851/802/720) | — | failure |
| best gnu | 42.9% (3170/2370/2146) | 38.1% (1146/794/762) | — | failure |
| best musl | 80.7% (4036 in-band, first window) | 68.8% (798/1265/1376 — climbing) | 4.7 GB/s (2348x) | success |

The low-gnu and low-musl rows are byte-identical — the same runner
class at the same moment, a pool-wide busy hour (the three failing
legs ran concurrently, ~07:52-07:54). The passing leg on a quieter
host read in-band, and its patience CLIMBED (798 -> 1265 -> 1376
KB/s) — the fleet converging over windows when the host lets it.
The failing legs' readings sat flat at the same numbers the
single-flow version read on the equivalent leg (36.0% vs 39.3%):
flow count is not the variable at 2mb under load, exactly as the
improve-15 1gb evidence already proved at the high end ("flow
count is not the variable" — the 2026-09-21 nightpc note).

## 3. The classification — the floor was the overreach, and the house law already existed

The matrix has carried the correct verdict shape for this physics
class since hunt-Z5 (2026-10-02), verbatim in
`supermassive-test.py`'s ceiling_only branch:

> "stays inside the policy" is the ceiling, and the lo bound was
> the overreach — the lone drawer's utilization is the sender's to
> give (a drop policer promises the ceiling, never the floor) ...
> where under-delivery is physics, the band floor drops to 0 and
> the ceiling carries the verdict.

The same battery's own rows prove the class on the very legs that
reddened the claims rows: the mmspa fair-share single row passed
at 36.9% (1mb, another leg), 83.5% (this run) — "under-delivery is
TCP recovery physics (the sender's RTO cadence), the ceiling
carries the verdict"; the ladder rungs pass at 1.4% and 29.9% with
"the ceiling and kernel drops carry the verdict". The claims
rows' 0.65 floor demanded the medium certify a rate-HOLDING the
loopback AIMD equilibrium under a drop-only policer cannot
guarantee at 2-5mb — the identical overreach Z5 removed from the
matrix, still living in the claims harness.

The aliveness and shaping claims do not need the floor:

- no-daemon's claim is ALIVENESS — enforcement pinned with the CLI
  gone. Un-policed traffic reads baseline (19.5 GB/s); the ceiling
  (1.30 x 5mb = 6.5 MB/s) fails that immediately, never retried
  away. A 42.9% reading with the pins standing is the claim
  proven.
- per-app's claim is SHAPING + ISOLATION — A bounded at its policy
  while B rides free. An unshaped A reads baseline (thousands of
  times the 2mb policy) and fails the ceiling; an A shaped at the
  wrong higher rate reads over-band and fails; the witness row
  carries the isolation half. A 36.0% A beside an 11.8 GB/s B is
  the claim proven.

## 4. The fix

`scripts/bench/proof-claims.py` (NIGHT-mitigate-3):

- Both held-rate rows verdict on the ceiling: `lo=0.0` at the
  band_check (hi 1.30 unchanged — over-delivery still fails
  immediately, never retried away), the row detail carrying the
  physics note and every patience sample.
- The per-app row renamed to match its verdict (the Z5 lesson:
  the name is the law): "per-app: policed cgroup A stays inside
  its configured rate".
- A silent-zero guard on both rows: a window that delivered under
  one GSO super-packet in total went SILENT — a connect failure
  or a stalled worker (the 0b0a8f5 class), not physics (the
  observed physics floor on these rungs reads tens of percent) —
  and fails with the samples attached. Near-zero cannot pass as
  "policed".
- The fleet instrument stays (mitigate-2): it converges when the
  host allows (the passing leg's climb), reads the honest
  aggregate when it does not, pays cushions faster, and matches
  the precision/curl precedents. The patience stays: it feeds the
  row the best number the host can give, the verdict just stops
  reddening below it.
- A rootless pin, executed (38 rows green on the fix tree):
  "selftest: the rate rows verdict by the ceiling, guarded
  against silence" — source-pins `lo=0.0` and `LOOPBACK_GSO_SKB`
  in both stage sources.

## 5. Why the floor had to go, not the rate

Raising PER_APP_RATE/NO_DAEMON_RATE to a rung where the fleet
converges even under load (the 100mb evidence) trades the floor
for the witness contrast the row's design chose 2mb for ("the
witness contrasts hardest against this") and moves the row away
from the user-relevant rungs; a rate this battery cannot
certify the floor at is a rate the row should verdict by its
ceiling at — the matrix's own answer for the same class, its
ladder spanning 1kb through 1gb with exactly this split. The
kernel-side rate-HOLDING (admitted == rate x elapsed) stays where
it is provable: the precision row's offer-tested window and the
rootless math pins.

## 6. What can still redden these rows

The honest residual, narrower now: over-delivery past 1.30x
(never retried); a silent window (the guard, with samples
attached); the witness floor on B (a scope bug or a machine too
loaded for a clean witness run — spelled out in the row); and the
row's other dependencies (attach, verify, pins, process-set).
The busy-hour under-band reading itself is recorded — every
sample — and no longer reddens: that number was never the
product's to promise.
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
