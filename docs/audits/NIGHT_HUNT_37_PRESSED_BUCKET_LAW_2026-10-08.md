<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-37 rider v2 audit — the pressed-bucket law: a window that never had the load can never convict the policer

> Audit date: 2026-10-08 (NIGHT-hunt-37 followup, the CI's red
> legs). Scope: the owner's ask — fix the three red supermassive
> legs on a11b8b1 (best-gnu, best-musl, low-gnu: "3 failing and 7
> successful checks", every leg 16-19 minutes in). Method: the
> failing jobs' logs pulled through the Actions API and read row by
> row against the rider's own code path, then the same walk for the
> claims battery's precision row (best-gnu's second red), then the
> two prior runs (8398b95, bd8de0e) checked for the same shapes.
> Two finds, one law family, both fixed and pinned. Audited at
> a11b8b1 (the rider v1 commit itself).

## 1. The red legs, decoded

All three supermassive legs failed on ONE row — `real internet:
strict download at 2mb` — and the row's own kernel numbers told a
story the verdict ignored:

| Leg | measured | ledger allowed (of a 30 MB budget) | drops | accounting |
|---|---|---|---|---|
| low-gnu | 394.6 KB/s (19.7%) | 5,999,099 B (20%) | 13 pkts | bpf 5,999,099 vs client 5,918,310 (101.4%) |
| best-gnu | 628.0 KB/s (31.4%) | 9,543,832 B (32%) | 18 pkts | bpf 9,543,832 vs client 9,420,719 (101.3%) |
| best-musl | 380.3 KB/s (19.0%) | 5,780,091 B (19%) | 14 pkts | bpf 5,780,091 vs client 5,704,832 (101.3%) |

The strict 2mb policy holds a 30 MB budget over the 15 s window.
Every leg's ledger shows the same shape: the policer admitted
(everything that arrived — the accounting rows sit at 101%), the
drops were 13-18 packets of burst-edge noise (a pressed bucket at
this geometry refuses on the order of twenty THOUSAND packets —
the QUIC row's 4,957 drops on a tenth the budget shows the scale),
and the arrivals integrated to 19-32% of the budget. The bucket
was never pressed. The path sagged — the shared-runner egress
oscillates at minute scale, three legs at once inside a two-minute
window — and recovered by re-probe time (the CDN bursts back in
under a second; the strict-upload row measured 105-107% seconds
later, the restore row 5.0 MB/s).

## 2. Find 1 (fixed): the rider v1 convicted on the re-probe alone

**The bug.** a11b8b1's rider re-probes the unpoliced path on an
under-band window and holds that "a path that feeds leaves the
FAIL standing" — the re-probe is the whole verdict. But a re-probe
that feeds names the path healthy NOW; it cannot retroactively
feed a window whose arrivals never pressed the bucket. The minute
sag recovered inside the re-probe's own window, the rider read
"feeds", and three legs filed a path measurement as an enforcement
failure — exactly the false conviction class the rider was built
to close. The pre-window gate cannot catch it (the sag starts
mid-window, bd8de0e's lesson) and the post-window re-probe cannot
pardon it (the sag ends mid-re-probe): the window's OWN ledger is
the only evidence that was there when it happened.

**The fix — the pressed-bucket law.** The under-band branch now
reads the ledger row BEFORE the policy clears (the row dies with
the policy) and weighs the window's own arrivals —
`bytes_allowed + bytes_dropped`, the same row the enforcement
proofs already read, riding back out of `enforcement_proofs` for
the download lane and read directly for the upload and sweep
lanes. A window whose arrivals never pressed the bucket at the
floor's scale (`realnet_window_pressed`: arrived >= BAND_LO x
rate x window — the same floor constant the verdict judges the
client by, no new threshold) is an instrument-floor row WHATEVER
the re-probe says: the policer admitted ~everything that came,
the row measured the path, and the re-probe only names the sag
(recovered, held, or worker-fault — all three named, all three
SKIP). A PRESSED window — the path DID feed the policer at the
verdict's own scale, drops at enforcement scale — keeps v1's
one-sided law verbatim: re-probe sags to a SKIP with the sag
named, re-probe feeds and the FAIL stands. An unreadable ledger
row (the proofs already FAIL loudly when the row is lost) cannot
claim the not-pressed defense — v1's law decides alone; an
evidence-loss never becomes a pardon. The collapse corner defends
itself: a drop-happy policer that starves TCP into sagging books
its drops into the arrivals number, and the pressed verdict
stands.

## 3. Find 2 (fixed): the claims precision row certified a touch, not a hold

**The bug.** The claims battery's precision row (best-gnu's
second red, 14.124% against a 12.0% bound; bd8de0e's low-gnu leg
carried the same shape one run earlier at 15.231%) certifies the
"real regression signature" when the window's hook-level offer
(admitted + refused) integrated up to the configured budget —
`offered >= expected`, zero margin. The a11b8b1 shape: offered
667,192,690 B against a 650,243,554 B budget — **+2.6%, a
touch**. A converged-but-sagging 4-flow fleet at that margin
leaves the bucket under-fed at every AIMD dip (the unspent refill
reads as under-admission — 1.4 default_bursts of deficit against
a bound that carries one) while its burst instants still refuse
108.8 MB at the instantaneous tokens. The v2 line-touch filed
the host's fleet sag as the token-math regression.

**The fix — the certification v3 rides the adaptation's own
constant.** `PRECISION_ADAPT_MARGIN` (0.8) already sizes the
offer-limited re-attempt to give the fleet 25% headroom over the
refill; the v3 certification demands the same headroom the
adaptation designs in: `offered >= expected / 0.8`. One family,
one constant, no new threshold. A sustained surplus (the healthy
shape) rides the refill exactly and certifies; a touch does not
present the budget and rides the offer-limited family to its
honest SKIP with the designed-vs-delivered margin named. The
real-regression path survives both ways a fast host produces it:
the offer holds 25%+ over the budget at attempt 1 (certified,
same-rate re-attempt, FAIL on the attempt that produced it), or
the offer-limited first window adapts and the held ceiling
certifies the adapted window (82 MB/s fleet over a 65mb rate
certifies; the observed legs' 66.7 MB/s over 65mb never did).

## 4. The verdict

The rider v1's law was half right: the re-probe's one-sidedness
(the over-band side never re-probes) was sound, but the
under-band side put the whole verdict on a path measurement made
seconds AFTER the window, blind to the window's own ledger. The
v2 law seats the verdict where the evidence was: the bucket that
never saw its band cannot be convicted of failing to deliver it,
and the bucket that was pressed has no re-probe excuse. The same
family closes the claims row's line-touch: a budget touched is
not a budget presented. Both lanes now carry the same doctrine —
the instrument's own numbers decide what the instrument measured
— and every SKIP names both figures.

Empirical, fresh on this tree: the supermassive v1 self-test
37/0/0 (two new pins: the pressed-bucket law on the exact
a11b8b1 leg figures, and the stages-weigh-arrivals source shape),
the claims self-test 38/0/0 (the discriminator pin re-seated on
the designed-headroom line with the a11b8b1 and bd8de0e shapes
pinned False), ruff check + format clean, codespell clean. The
live supermassive legs' green belongs to the next CI run — the
same run that carried the red.
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
