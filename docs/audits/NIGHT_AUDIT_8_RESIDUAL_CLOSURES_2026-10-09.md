<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-audit-8 audit — the last two residuals, and the red era they were hiding

> Audit date: 2026-10-09 (night-audit-8). Scope: the owner's call —
> "all residual should closed" — over the hunt-43 audit's two
> remaining owner-call residuals: the alive-unresolvable-quiet
> root and the status-visit unpin ladder. Method: walk each
> residual to its root, land the closure, then hunt the landings
> — and the hunt found the biggest thing either audit had missed:
> the supermassive workflow has been RED since run 281 (044ca58,
> 2026-10-08 20:25 UTC), every push failing through run 292, its
> three causes sitting in plain sight the whole time.

## 1. Residual #2 — the alive-unresolvable-quiet root (closed, twice)

**The residual.** A root whose processes all entered a cgroup
namespace after its apply is observationally identical to a dead
one on both walking signals — the namespaced /proc view hides its
members from the identity walk, a quiet app hides it from the
ring — and the hunt-43 sweep retired it with the dead, taking its
standing policy with it.

**The first cut (075551e) — honest retraction.** The belt read
cgroup.events (`populated <0|1>`, the kernel's subtree-liveness
verdict, immune to the namespace trick) and gated retirement on
memberless-or-gone. The cut closed the residual — and opened a
worse hole the same hour: a MEMBERLESS standing directory also
retired, and an empty-but-kept cgroup is a policy the owner armed
on purpose (the pre-provisioned bed, the supermassive fleet's
every apply). Retiring it in the same breath as its creation is
exactly the enforcement loss the residual came to close.

**The second cut (b284eec) — the law.** The death proof is the
ONE retirement law: a root retires only when no identity entry
stands and a complete cgroupfs census walk proves its directory
GONE — the cgroup object itself destroyed, nothing can ever join
it or deliver from it again. A standing directory keeps the
policy whatever its state: the alive-unresolvable root, the
pre-provisioned bed, the kept scope directory — enforcement
preserved over bookkeeping, the estate's fail-open posture
completed. Death subsumes the silence question (nothing can
deliver from a destroyed cgroup, so Silent legs and the absent
lens's Unknown legs alike pass under it), and the core reduces to
three lines: no identity, no Traffic leg, directory proven gone.
The census is built only when a candidate asks for it (no Traffic
leg and an identity miss — the healthy host pays nothing), and a
root the walking lanes name but the death proof keeps gets its
own verbose hold line — the "one grep away" diagnosis the hunt-43
audit promised.

**The real-world shapes the law serves.** The owner's zombies are
all directory-gone shapes — the systemd scope (rmdirs at job
end), the exited container, the closed session — and they retire
on the death proof alone. The kept-directory shapes are all
policies the owner wants standing, and they stand.

## 2. Residual #3 — the status-visit unpin ladder (closed)

The no-residue ladder (`unpin_if_no_policies`, the verified-zero
contract NIGHT-hunt-20 owns: the count is READ, never assumed — a
read failure keeps the pins and warns) joins the status visit's
tail, under the sweep lock the visit already holds. A sweep that
takes the last policies no longer leaves the empty skeleton
pinned until the next u/recover/apply-era (eec4042).

## 3. THE FIND — the supermassive red era (runs 281-292)

The CI history the session opened: run 280 (77940e9, pre-hunt-42)
green; run 281 (044ca58, hunt-42's HEAD) red; every push since
red or cancelled through run 292 (075551e). The previous night's
"live CI proof" never actually landed — the hunt-43 series runs
(282-286) were all cancelled mid-flight by the next push, and
every later run inherited the failure. Three causes, one per
landing:

1. **The orphan-census stage harvested its own proof** (born
   044ca58). The stage's `status_json()` verification visit
   between the bpftool delete and the recover step IS a collector
   (hunt-30/hunt-34's law: every mutation-capable visit reaps) —
   its census sweep collected the orphaned bucket_dl before the
   recover step could report it, so recover's "Census: N orphaned
   state entries reclaimed" line never fired. The verification
   block was vestigial anyway (it computed and discarded);
   removed — the bpftool exit code is the row-gone truth, the
   recover step is the collector under proof.
2. **The zombie sweep retired fresh policies on empty beds**
   (born 9f928ac, hunt-43). An apply to an empty-but-standing
   cgroup — the supermassive beds, pre-provisioning anywhere —
   met the two-signal predicate at its own apply tail (no
   identity entry, never-delivered ring silence) and the sweep
   deleted the policy the apply had just written. The first cut's
   memberless lane kept the hole open; the second cut's
   death-proof law closes it at the root: a standing directory
   holds, full stop.
3. **The zombie-sweep stage never proved death.** Its bed 'e'
   kept standing after the client exited — no systemd ever
   cleaned it, and the belt (correctly) held the policy. The
   stage now rmdirs the bed after the client exits (the
   systemd-scope shape: the job's cgroup is destroyed when the
   job ends), so the death proof can fire and the retirement
   rides the census: directory gone from a complete walk.

All three repairs landed in one push (b284eec + eec4042 +
d579d44); the workflow's verdict is the record this audit will
point at.

## 4. The night hunting its own landing

The first cut (075551e) was pushed, bench-tested, gated green —
and wrong. The second cut is smaller than the first (the
cgroup.events reader and the id-to-path census are gone; the
original id-set census of 0c3ba04 carries the whole law), which
is the over-engineering guard working as designed: the first cut
solved the residual with new machinery; the second cut found the
law already in the estate and the residual closed with less code
than the bug it replaced. The audit family's oldest lesson, one
more time: land, then hunt the landing.

## 5. Pins and A/B

The decision matrix re-pinned for the law: the standing directory
holds the residual's exact shape AND the pre-provisioned bed;
Traffic vetoes even against the death proof; the absent-lens
rescue rides the belt (Unknown legs retire on Gone alone); the
block lane retires through death and holds on a standing
directory; the trace separates the rows whose lenses also read
their silence from the rows only the death proof could reach; the
hold line names the standing directory. 883 binary tests green.
Frame bench A/B (10s, fixed-seed, first cut vs second cut): every
visual metric in its noise band — bytes/frame identical 1919,
density gini +0.0%, frame entropy -0.0%, dirty cells +0.1% (the
sweep is not in the render path at all; fps -0.8% is the shared
host's run-to-run band, the hunt-43 precedent). The second cut is
strictly a sweep-law change: what it holds, it held before it
landed; what it retires, the first cut retired louder.

## 6. Named residuals (the honest boundary)

1. **The census's cgroup-namespace view, inherited.** The census
   trusts the walker's own view of the mount (0c3ba04's named
   residual, unchanged): a zelynic instance inside a cgroup
   namespace sees its subtree, and a root outside that view reads
   as gone. The manual `recover` scan keeps its lane.
2. **The kept-directory zombie.** A delivered-then-dead root
   whose directory lingers (systemd rmdir failed, a hand-kept
   bed) now waits for the manual recover scan — the honest price
   of never retiring a policy the owner armed on a cgroup that
   still exists. Recover's report names it; the owner decides.
3. **A census past the bounds holds every candidate.** A tree
   past the 4096-visit ceiling is inconclusive, and fail-closed
   means no retirement that visit — the pre-existing walk
   contract, now load-bearing for every retirement.
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
