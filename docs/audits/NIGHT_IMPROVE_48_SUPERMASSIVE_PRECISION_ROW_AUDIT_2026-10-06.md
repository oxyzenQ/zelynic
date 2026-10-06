<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-improve-48 depth audit — the supermassive completeness question, the precision proof-claim's red CI lane root-caused and closed

> Audit date: 2026-10-06 (NIGHT-improve-48). Scope: the owner's
> suspicion, verbatim intent — "supermassive test is still not
> complete, owner see missing like test proof-claim 0.00%, and
> others need depth audit too" — answered three ways: (1) the CI
> evidence pulled for the exact thing the owner saw (the red
> precision proof-claim row on the supermassive runs), (2) the
> root cause isolated by physics (the instrument's starved
> window, not the policer, not a missing test), (3) the fix
> landed with pure-function pins, and the other four headline
> claims plus the whole supermassive lane inventory audited for
> the same class on the same evidence. Audited at 3becf5d
> (v20.0.0-era tree, one commit past improve-46's 47e68dc).
> Method: the GitHub Actions API logs for runs 219-228 (jobs,
> steps, the full vm.log tails), the proof-claims.py stage read
> line by line against its failing numbers, the physics
> re-derived from the drop-only bucket contract the math pins
> already hold, and the fresh self-test run (36 rows green)
> after the fix. Status: ONE real gap found and closed — the
> precision LIVE row could fail red on a starved host window
> with the policer holding its contract perfectly — and the
> completeness question answered honestly: every other lane was
> green on the same runs, the five headline claims' mechanisms
> all exist and run where the ledger says they run.

## 1. The mandate

The owner looked at the supermassive CI and saw red. The
suspicion: the test estate is "still not complete" — a missing
test for the proof-claim 0.00%, and other lanes that need depth
audit too. This audit treats the suspicion as a bug report with
a reproduction trail, not a vibe: the exact failing runs were
pulled, the exact failing row isolated, and the failure
signature classified against the row's own physics before any
fix was written.

## 2. The find — the CI evidence

The supermassive workflow's recent history (the Dragon Guard -
Supermassive runs, 2026-10-06):

| run | commit | verdict | the failing lane |
|-----|--------|---------|-------------------|
| 219 | 5458ccc | failure | all four legs |
| 221 | 30f3791 | failure | both best-specs legs |
| 222 | 25c44c4 | success | — |
| 224 | 609f79d | failure | both best-specs legs |
| 225 | 71352fd | success | — |
| 228 | 3becf5d | failure | both best-specs legs |

Run 228 (the most recent, the improve-44 fixpass commit) is the
run the owner saw. Its best-specs legs (gnu and musl, both
booting the dynamically-resolved latest kernel 7.3.0-8-generic)
failed exactly one probe out of the whole lane inventory:

```
MASS-RESULT: supermassive v1 - limiter matrix (full, server-first) — PASS
MASS-RESULT: AMMSP vs legacy v11.0.0 - subtree coverage delta (>= 99%) — PASS
MASS-RESULT: supermassive v2 - survival battery (full, server-first) — PASS
MASS-RESULT: supermassive v3 - container depth battery (full) — PASS
MASS-RESULT: supermassive v4 - CLI depth battery (full, rootless) — PASS
MASS-RESULT: rig suite - reload / crash recovery / race condition — PASS (x3)
MASS-RESULT: claims proof (live, quick) — FAIL
MASS-VERDICT: FAIL (1 probe(s) failed)
```

Inside the claims proof, the failing row is the precision claim
— the one the owner named:

```
X precision: long-run token accounting vs configured rate —
  admitted 787430460 B over 10.0s vs configured rate x time
  1000510671 B — error 21.297% (bound 12.0%) ... attempts:
  14.186%, 21.297% (the under-side re-attempt)
```

Run 224's best-specs legs read the same shape at 29.775%
(attempts 18.203%, 29.775%). The same runs' low-specs legs
(booting the impish 5.13.0-52 floor kernel) read the same row
GREEN at 3.606% — and run 222's best-specs legs, on the SAME
7.3.0-8 kernel as the red legs, read 1.921% green. The
isolation: same commit, same harness, same kernel generation on
both sides of the verdict — the variable is the shared runner's
hour. The vm.log of run 222 even carries the smoking gun in the
kernel log: `clocksource: Watchdog remote CPU 2 read timed out` —
the runner host itself was CPU-starved during that (passing)
run.

## 3. The physics — the row was failing on the host's poverty, not the policer

The three evidence rows the stage prints tell the whole story,
read together:

1. `OK precision: TCP-level throughput` — configured 100.0
   MB/s, measured 69.9-78.4 MB/s (the 4-flow aggregate under the
   policer; the row's band floor is 65%, so it passed).
2. `OK precision: kernel-admitted bytes match client-received
   bytes` — ratio 1.004-1.005 (the hook admitted what the client
   received, one-to-one, the improve-12 discipline holding).
3. `X precision: long-run token accounting vs configured rate`
   — admitted 21.297-29.775% UNDER the configured budget, past
   the 12% bound, on both re-attempts.

The drop-only bucket's contract (pinned rootlessly in
test/ebpf/limiter/math_tests.rs): admitted = min(offer,
refill) at (nearly) every instant, plus or minus one
default_burst of bank wander. Corollary: an under-band window
means the OFFER integrated under the refill — the fleet could
not push the configured rate through the policer during those
ten seconds. A policer cannot under-admit a saturated offer
(the over-side of the same row fails the moment it does); the
failing windows' offers sat at 70-78% of the rate with nothing
refused — the kernel's drop counter in those windows read zero
(the starved bytes were never offered at all).

The 4-flow aggregate that the round-3 closure built as THE
instrument (the matrix's high-rung law: one AIMD flow rides its
own 95-96% ceiling, the aggregate rides the refill) needs CPU
headroom to keep its offered load above the refill at every
instant. On a contended shared runner — the best-specs legs run
the longest battery sequence, the host is shared, the archive
kernel's loopback TCP shape has its own AIMD recovery
dynamics — the aggregate sags below the rate for ten seconds
straight. The instrument starves; the row blamed the policer
and failed the lane. That is the exact false-failure class the
quick-row closure v2 already met once (the GIL find: "the
HARNESS's own throttle, not enforcement") — this audit found its
third member: the fleet's own CPU ceiling on a starved host.

## 4. The fix — discriminate before verdicting, adapt once, skip honestly

The precision stage now reads BOTH counters (bytes_allowed AND
bytes_dropped) at each window edge — one status read, the
midpoint estimator's spawn pricing unchanged — and the
under-band branch discriminates before it does anything else:

| the under-band window's shape | what it means | what the row does |
|------------------------------|---------------|------------------|
| zero refusals in the window | the offer itself integrated under the refill — the instrument starved; the policer held (the admit-ratio row proves every offered byte passed) | adapts once: the re-attempt rides 80% of the starved window's own admitted rate (zero refusals made admitted==offered, so the number IS the offer — 25% headroom for the fleet to saturate the refill again), floored at the loopback GSO-safe 5mb, capped at the configured rate; a second starve — or an offer below the floor — records the honest SKIP: a window this host cannot saturate measures the offer, not the policer |
| refusals present, still under-band | the bucket refused the surplus AND under-admitted the refill — the real regression signature this row exists to catch | keeps the old same-rate patience (a mixed transient gets its second window; a systematic break stays red on both), then FAILS with the refused-surplus evidence in the row detail |

The verdict discipline is unchanged where it was already
honest: in-band and over-band fail or pass on the attempt that
produced them, every attempt's error rides the row detail, the
adaptation trail prints (the first rate, the adapted rate, the
starved window's offer), and the three evidence rows print on
every verdict. The pure functions
(precision_window_starved, precision_adapt_rate) are pinned by
three new self-test rows on the exact CI shapes: 78.4mb
adapts to 62mb, 69.9mb to 55mb, a 200mb offer caps at the
configured rate, offers below 5mb fund no re-attempt (the
SKIP), and zero refusals vs one refusal sit on opposite sides
of the discriminator. The engine self-test reads 36 passed, 0
failed, ruff check and format clean, gate-keepers 16/16.

What the fix deliberately does NOT do: lower the 100mb rate for
every host (the strong proof stays on healthy hosts — the
adaptation only ever fires on a demonstrated starve), add
probe traffic (the starved window's own counters carry the
evidence — no witness worker, no extra lane), or round any
number away (the SKIP prints the error, the attempts, the
offer, and the adaptation trail verbatim).

## 5. The others — every other lane and claim on the same evidence

The owner's "and others need depth audit too" — this audit
swept everything else the failing runs carried:

**The other four headline claims on the same failing runs:**
no-daemon, pure-eBPF, per-app, and footprint all read green on
runs 224 and 228's failing legs — their rows either ride the
one-sided patience (no-daemon, per-app: the under-side window
re-samples bounded, the quick-row closure v2's discipline) or
measure structure and rusage (pure-eBPF's ruleset snapshot,
footprint's wait4 counters), none of them price a 100mb
saturation premise. The failure was isolated to the one row
whose instrument needs a saturated offer.

**The claims-to-supermassive coverage map, verified present and
running:**

| claim | LIVE row (proof-claims, runs in both VM legs) | battery rows | rootless pins |
|-------|-----------------------------------------------|--------------|---------------|
| 1 no-daemon | stage_no_daemon (PASS on 224/228) | v1 reload/sustain rows | pin.rs pinned-link surface |
| 2 pure-eBPF | stage_pure_ebpf (PASS) | engine self-test, every leg | nft/tc normalization pins |
| 3 per-app | stage_per_app + witness worker (PASS) | v1 strict-multi shared-bucket rows | witness-floor pins |
| 4 precision 0.00% | stage_precision, now with the discriminator | v1 accounting rows ("BPF accounting matches client bytes") | math_tests.rs + the budget-covers pair |
| 5 footprint | stage_footprint (PASS) | — | verdict-math/stats-knob-plan self-test pins + diff_tests idle-frame |

The wiring itself works: the failing runs' logs show the
claims proof executing LIVE inside both VM legs (init.sh's
NIGHT-lts-6 block) — the row the owner saw missing-green is
present, running, and now honest about its instrument.

**The lane inventory on the failing runs:** kernel checks,
-V, doctor, four engine self-tests, --reset-terminal, the v1
limiter matrix (full, server-first), the AMMSP subtree delta,
the v2 survival battery, the v3 container depth battery, the
v4 CLI depth battery (155 rows), the three rig suites — every
one PASS on runs 224/228. Nothing else in the estate was red.

## 6. The verdict

Is the supermassive test "still not complete"? The honest
answer: its COVERAGE was never the gap — every claim, feature,
and surface the estate promises a mechanism for has one, and
every lane but one was green on the exact runs the owner saw.
The gap was the precision LIVE row's INSTRUMENT ROBUSTNESS on
shared runners — the third member of the harness-throttle
family (GIL, cold-start, now the starved fleet) — and it is
closed by this audit's fix: the row now distinguishes its own
poverty from the policer's, adapts once to what the host can
honestly offer, and skips with the full trail when it cannot
measure. The 0.00% contract itself never moved: the token
math stays pinned rootlessly, the LIVE row keeps printing its
actual residual, and a real under-admission with refusals
still fails red on the attempt that produced it.

The adjacent open item, recorded for honesty: the
charger-core-1c probe-lane bug (the proof stages' --no-probe
bypass, docs/audits/NIGHT_UPGRADE_CHARGER_CORE_1C_PROBE_CI_FIND)
stays OPEN pending a root machine to debug — unchanged by this
audit, tracked where it lives.

## 7. The live proof — run 229, all four legs green

The fix commit (6e80916) triggered the supermassive workflow
on push (scripts/bench/proof-claims.py rides the trigger
paths): run 229, the first run of the discriminating row,
COMPLETED SUCCESS on all four legs — both best-specs (the
legs that were red) and both 5.13 floor legs, MASS-VERDICT:
PASS on each. The best-specs gnu leg's precision row, the
exact row this audit exists for, read:

```
OK precision: TCP-level throughput — configured 100.0 MB/s,
   measured 90.1 MB/s (90.1%)
OK precision: kernel-admitted bytes match client-received
   bytes — ratio 1.0028
OK precision: long-run token accounting vs configured rate —
   error 9.691% (bound 12.0%) — attempts: 13.068%, 9.691%
```

The first window read 13.068% under-band — a MIXED window
(refusals present: the mostly-saturated instants dropped, the
starved gaps under) — and the discriminator routed it down the
real-signature path: the old same-rate patience, the second
window read 9.691% in-band, the row passed with both attempts
in its trail. The best-specs musl leg read 8.431% in-band on
its first window (single attempt, no re-attempt needed). The
starved shape that killed runs 224/228 did not recur on this
run's hosts — but its honest path (adapt once, then SKIP with
the evidence) is pinned by the self-test rows and waits for
the next starved hour, where it will measure what the host
offered instead of blaming the policer for it.

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
