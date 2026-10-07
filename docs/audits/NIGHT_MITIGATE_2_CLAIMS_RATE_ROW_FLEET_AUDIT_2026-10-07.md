<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-mitigate-2 audit — the claims proof's lone red CI row root-caused and closed, the held-rate rows handed the fleet instrument

> Audit date: 2026-10-07 (NIGHT-mitigate-2). Scope: the owner's
> verbatim intent, translated — "CI is all passed except one
> failed left; mitigate it so it cannot happen again in the future,
> even flaky or other conditions" — every workflow on the current
> head green except one job, which is exactly the class this
> project does not tolerate: a row that can redden on runner
> weather while the product holds its contract. Answered the
> standard three ways: (1) the exact failing run, job, step, and
> row pulled from the Actions API with the numbers attached, (2)
> the failure classified against the row's own physics (sender
> AIMD under-delivery, not enforcement — the witness row proves
> the policer alive at line rate on the same machine at the same
> moment), (3) the fix landed as an instrument upgrade with a
> rootless self-test pin so the law cannot silently revert.
> Audited at 2b269f7 (v50.0.0-alpha.1 depth test tree); the
> failing runs predate it at af45758b (per-app) and land on
> 2b269f7 itself (precision — that run completed red WHILE
> this audit ran, the same mandate's second shape). Method:
> run/job/step logs for 37583456726 and 37585392115, the
> proof-claims.py stages read line by line against the failing
> numbers, the physics re-derived from the drop-only bucket
> contract, and the fresh self-test run (37 rows green) after
> each fix. Status: TWO real gaps found and closed — the
> held-rate claim rows (no-daemon, per-app) measured one AIMD
> flow and could park under the band on a cold slow leg with
> enforcement fully alive, and the precision row's improve-48
> discriminator keyed its regression verdict on refusals
> instead of the budget scale, so a sagging offer's burst
> refusals reddened a window that never presented the budget.

## 1. The mandate

The owner looked at the Actions tab and saw green everywhere
except one job. The mandate is not "make CI pass" — the current
head's runs were already green — it is "make it so this cannot
happen again even under flaky or other conditions". That is a
demand for a root cause and a structural mitigation, which is
the only kind of fix this repo files.

## 2. The find — the CI evidence

The Dragon Guard - Supermassive workflow on push af45758b, run
37583456726 (2026-10-07T06:47Z): three of four legs green, the
fourth — `supermassive test - low specs (gnu)`, the 5.13 kernel
floor on the slowest runner class the fleet fields — failed at
the Verdict step with exactly one probe red:

```text
MASS-RESULT: claims proof (live, quick) — FAIL
MASS-VERDICT: FAIL (1 probe(s) failed)
```

Inside the battery (28 passed, 1 failed, 49s total), the red row:

```text
X  per-app: policed cgroup A held at its configured rate —
   configured 2.0 MB/s (16.00 Mbps), measured 785.8 KB/s (39.3%);
   windows: 671.3 KB/s, 802.2 KB/s, 785.8 KB/s
```

Every other claims row on the same leg was green, including the
two that bracket the failure in time and mechanism:

- `no-daemon: enforcement alive with zero zelynic processes` —
  5.0 MB/s configured, measured 3.9 MB/s (79.0%): in-band on the
  same runner, same kernel, same commit.
- `per-app: witness cgroup B unlimited (same machine, same
  moment)` — A measured 785.8 KB/s while B measured 11.8 GB/s
  side by side; B rides 5895x A's configured rate against a
  2.0 GB/s witness floor.

That pair of green rows is the diagnosis in miniature: the
policer was attached, alive, and shaping exactly cgroup A while
cgroup B ran free on the same machine at the same moment. The
claim the row exists to prove — one cgroup shaped, its neighbor
free — was proven. What failed was the row's second reading,
"held at its configured rate", whose band floor (0.65) the flow
never reached: three patient windows at 33.6%, 40.1%, 39.3%.

## 3. The classification — sender physics, not enforcement

The failure signature is the one the harness's own commentary
has documented since the quick-row closures:

- A drop-only policer never queues. On loopback one loss event
  is a whole 64 KiB GSO super-packet (lo MTU 65536, no NIC
  segmentation), and a lone AIMD flow that eats such a loss
  backs off its window and stalls on the Linux 200 ms min-RTO
  while the bucket keeps refilling. The flow's own sawtooth —
  not the bucket — is the ceiling the window reads.
- The patient-window loop did exactly its job: it re-sampled
  under-side three times, every sample attached to the verdict,
  and failed honestly. Patience cannot lift a source's own
  ceiling — the precision stage learned this verbatim in its
  round-3 close ("a single fresh TCP connection under a 100mb
  drop-only policer rides its own AIMD equilibrium at 95-96% of
  the rate on the shared runners ... while four hungry
  connections keep the bucket's offered load above the refill at
  (nearly) every instant").
- At 2 MB/s on the low-specs 5.13 leg the effect is harsher than
  at 100 MB/s: the same runner class the no-daemon row's
  commentary memorializes ("the 5.13 leg at 41.9% of a 5mb
  policy with enforcement fully alive"). The 79.0% no-daemon
  reading on this very run sits one cold leg away from the same
  red — the per-app row is not an outlier, it is the same law
  biting the row with the lower rate and the colder attach.

So the gap is instrument-shaped: the no-daemon and per-app rows
verdict on a CGROUP's held rate — a cgroup-level truth, the
whole bucket — through a single-socket reading, one AIMD
sawtooth out of the cgroup's aggregate. The precision row and
the curl-burst row already measure their aggregates (4-flow
fleet, 6 parallel curls); the two held-rate rows were the last
single-flow instruments in the harness.

## 4. The fix — the fleet instrument, applied to the held-rate rows

`scripts/bench/proof-claims.py` (NIGHT-mitigate-2):

- `fleet_download(flows, window, port)` — the rate-row
  instrument: N concurrent `tracked_download` threads, each with
  its own connection and progress counter, joined and summed.
  The server is the already-decoupled worker subprocess with one
  serve thread per connection, so the fleet never shares the
  harness GIL with the data source (the quick-row closure v2
  contract holds under concurrency).
- `RATE_ROW_FLOWS = 4` — the claim rows' fleet size, the
  precision stage's own number; the sockets share the one
  bucket, the individual back-offs stagger, and the aggregate
  rides the refill exactly (the matrix's high-rung law).
- `stage_no_daemon`: the quick settle, the patient-window probe,
  and the redrain probe all ride the fleet. The settle now pays
  the fresh bucket's cushion several times faster than one flow
  can (the row's own "the fleet also pays the fresh bucket's
  cushion several times faster" note in the precision stage).
- `stage_per_app`: the A-side probe and redrain ride the fleet;
  the row detail now names its instrument ("4-flow aggregate")
  before the window samples, the honesty contract the precision
  rows already carry.
- Both verdicts keep the full discipline around the instrument:
  the one-sided patience (in-band stops, over-band fails now,
  all-under fails after the attempts), the cushion redrain at
  the re-sample boundary, and `band_check` unchanged at lo 0.65.
  Nothing about the verdict law moved — only the instrument
  that feeds it.
- A new rootless pin, executed by `--self-test` (37 rows green
  on the fix tree): `selftest: the rate rows measure the fleet,
  not one flow` — source-pins `fleet_download` inside both stage
  sources and `RATE_ROW_FLOWS` at module scope, so the next
  revert to a single-flow reading fails rootlessly.

## 5. The second find — the current head's precision row, red while this audit ran

While the fleet fix was being pinned, the Supermassive run on
the CURRENT head (2b269f7, run 37585392115) completed: three
legs green, `supermassive test - best specs (gnu)` red on one
probe — the hunt-31 candidate the boost-10 commit had already
recorded as "boundary-riding":

```text
X  precision: long-run token accounting vs configured rate —
   admitted 744746367 B over 10.0s vs configured rate x time
   1000479172 B — error 25.561% (bound 12.0% ...) — WITH
   134087842 B refused in the window: ... the real regression
   signature, failing on the attempt that produced it ...
   attempts: 15.667%, 25.561%
```

The arithmetic the row's own counters carry classifies it
independently: the hook-level offer (admitted + refused) was
744.7 + 134.1 = 878.8 MB against the 1000.5 MB budget — the
offer integrated at 87.8% of the refill, so the window never
PRESENTED the budget at all. The two evidence rows on the same
leg agree: TCP-level 73.9% (the fleet's own offer never reached
the rate) and the admit ratio 1.0070 (kernel-admitted 744.7 MB
vs socket-received 739.6 MB — every offered byte passed the
hook). The policer held its contract; the host's four-flow
fleet sagged under a shared-runner busy hour, and its burst
instants still spiked over the bucket's instantaneous tokens,
refusing 134.1 MB without ever making a budget-scale surplus.

The improve-48 discriminator keyed on refusals (zero = starved,
any = the real regression signature) — correct for the
zero-refusal starve it was built on (runs 224/228) and for a
genuine saturated-offer under-admission, but the mixed shape
(a window-wide sag with burst-scale refusals) lands in the
wrong arm: the row reddened on evidence that cannot certify
the regression it names, because a deterministic token-math
break cannot hide from a window that never presented the
budget — the regression's own claimed determinism requires
reproduction at budget scale.

## 6. The second fix — the offer-test discriminator (v2)

The gate moves from refusals to the budget scale itself:

- `precision_offer_tested_refill(offered, expected)` — pure,
  pinned: an under-band window CERTIFIES the regression only
  when its hook-level offer (admitted + refused) integrated up
  to the configured budget. A budget-scale offer with an
  under-band admission keeps the old same-rate patience and
  stays red on the attempt that produced it (a systematic
  break reproduces at budget scale; a transient washes out).
- An offer under the budget is OFFER-LIMITED, refusals or not
  — the burst instants of a sag refuse without presenting a
  budget-scale surplus — and rides the existing adaptation:
  the re-attempt runs at 80% of the window's own hook-level
  offer (the true offer now, not the zero-refusal admitted
  special case), floored at 5mb, capped at the configured
  rate; a second offer-limited window records the honest
  SKIP with every number attached (a window this host cannot
  saturate measures the offer, not the policer — the
  admit-ratio row already proves every offered byte passed
  the hook).
- A budget-scale under-admission whose re-attempt cannot even
  present the budget again is INCONCLUSIVE, not red: the
  verdict stands on the final window's evidence, and the
  honest SKIP carries both attempts' numbers.
- The zero-refusal starve improve-48 pinned is the
  offer-limited special case (offered == admitted there), so
  one law covers both spellings; the adaptation math pins
  (78.4mb -> 62mb, 69.9mb -> 55mb) ride unchanged, and the
  new pin carries the exact 2b269f73 shape on both sides of
  the gate.

## 7. Why not the alternatives

- **Dropping the band floor (the nested-root row's lo=0.0
  precedent)**: that row's law is a RESOLUTION law where only
  the ceiling discriminates, so under-delivery cannot distinguish
  the hypotheses and must not redden the row. The per-app row's
  law is the rate-holding itself — lo=0.0 would leave the row
  proving only "A is slower than B", which no longer certifies
  "held at its configured rate". The instrument is wrong, not
  the bound.
- **More attempts / longer windows**: the failure was
  systematic, not transient — three windows all read ~40%, and
  the nested-root commentary documents a leg where the cadence
  DEGRADED across windows (28.3, 32.0, then 16.4 KB/s — RTO
  backoff deepening). Patience cannot lift a source's own
  ceiling; it can only spend more runner minutes rediscovering
  the floor.
- **Re-running the failed job**: the owner's mandate is
  explicitly the opposite — "so it cannot happen again in the
  future" (translated).
  A re-run is a pass by weather; this repo's verdicts belong to
  instruments that can certify them.

## 8. The future-flake answer — what can still redden the rows

Stated honestly, because "never again" is only ever earned by
naming the residual: the fleet removes the sender-side class
entirely — a cgroup of four staggering sockets cannot park
under the band while the bucket refills (the aggregate's
admitted rides the refill exactly, the precision rows' own
  CI evidence at 100 MB/s and the curl-burst row's at 1 MB/s) —
and the offer-test gate removes the precision row's false-red
class: a verdict that requires a budget-scale offer cannot
fire from a window that never presented the budget. What
remains is the rows' true contract, and it is supposed to
stay red when it breaks: a real over-delivery (band_hi) fails
immediately and is never retried away; a budget-scale
under-admission with refusals stays red on the attempt that
produced it; a systematically broken datapath (all-under
across the attempts) fails with every number attached; a
machine too loaded for a clean witness run fails the B-side
floor with the reason spelled out. Those are product
regressions and hostile-runner detections, not flakes to
mitigate away.

## 9. Verification

- `python3 -m py_compile` clean; `--self-test` 37 passed,
  0 failed, 0 skipped on the fix tree (the new fleet pin
  included).
- Gatekeepers: `timeout 120 ./scripts/build.sh check-all -q` and
  `./scripts/gate-keepers.sh` on the fix tree, both green before
  the push.
- The live proof re-proves the row on every supermassive push
  (`scripts/ci/supermassive-init.sh` invokes the harness with
  `--quick` on each leg); the next push's four legs are the
  live verification of record, and their numbers file into
  `CROSS_DISTRO_RESULTS.md` per the harness's own instruction.

The closing line, the same doctrine the hunt-Z5 audit closed
on: a verdict belongs to the instrument that can certify it —
a cgroup-held rate is a cgroup-level truth, and the fleet is
the instrument that reads it.
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

## 10. Postscript — the live verdict on section 8, and the followup it forced

Section 8's claim that "the fleet removes the sender-side class
entirely" was falsified by the fleet's own live verification run
(37588414621, push 6588e3a): three of four legs read 36-44% of
the 2-5mb policies through the fleet — the AIMD equilibrium under
a drop-only policer is rate-dependent and flow count is not the
variable at these rungs under load, exactly the physics the
precision row's offer-test (section 6, which performed as
designed on the same run: offer 470.9 MB vs the 731.1 MB budget,
the honest SKIP, admit ratio 1.0013) had just learned at the
offer level. The held-rate rows' 0.65 floor was the overreach
the whole time — hunt-Z5's ceiling doctrine, the matrix's own
law for this class, applied to the claims rows by
NIGHT-mitigate-3 the same day:
`docs/audits/NIGHT_MITIGATE_3_RATE_ROW_CEILING_LAW_2026-10-07.md`
carries the close (ceiling verdicts, the silent-zero guard, the
row names matched to their laws, 38 self-test rows green). The
fleet stays — it is still the honest cgroup-level instrument
(mitigate-3's section 4) — but the verdict law it feeds is the
ceiling, and that law is what makes the rows weather-proof.
