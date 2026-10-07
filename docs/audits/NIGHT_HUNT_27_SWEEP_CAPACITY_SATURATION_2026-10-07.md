<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-27 audit — deep hunt past the leaderboard fix

> Audit date: 2026-10-07 (NIGHT-hunt-27). Scope: the owner's ask —
> "hunt more critical/hidden bugs until peak", with the leaderboard
> 4096-cap freeze (NIGHT-mitigate-1's retire_dead) as the named
> example of the class to keep hunting. Method: enumerate every
> fixed-capacity resource and the freeze/refusal class the
> leaderboard bug exemplified, then walk the interaction boundaries
> (apply ladders, sweeps, guards, parsers, persistence) with fresh
> eyes. One critical find fixed this task; the rest of the surface
> audited clean, with two named residuals left for the owner's
> call. Audited at f5530c6 (post improve-50).

## 1. The find (fixed): the sweeps' whole-abort at the 1024 ceiling

**The bug.** `strict-all` and `block-all` ride the best-effort
`apply_group` — whose write loop, since the hunt-19 fix, aborts and
rolls back the WHOLE invocation on the first leg failure. That is
the correct contract for genuine failures. But the policy family's
maps are 1024-row HashMaps (the capacity class the improve-50
decision audit's cap map names), so on a host past 1024 live user
cgroups — the exact "host server padat" shape the improve-31 note
documents, a big Kubernetes node or a per-job-scope CI runner — leg
1025's insert ALWAYS fails, and the sweep refuses EVERYTHING, every
run, with zero enforcement:

- strict-all on a dense host: error, exit non-zero, nothing
  limited — forever. The operator has no path forward (the sweep
  has no "as many as fit" mode).
- The design inconsistency is the tell: an app that EXITS between
  snapshot and write is tolerated (skip, continue — the best-effort
  comment in the handler says exactly that), but the capacity
  ceiling aborts the whole fleet. The one failure a dense host
  hits deterministically is the one the sweep cannot tolerate.

SAFETY_ANALYSIS.md's own Finding 1 names this exact reachability
("map full at 1024 entries — reachable via strict-all/block-all on
cgroup-dense systemd desktops") while documenting the rollback as
the fix for the invisible-partial-apply trap — the dense-host
consequence (total refusal) was the unexamined tail of that trade.

**The fix (capacity-admitting sweep).** `apply_group_sweep` — the
sweep twin of `apply_group`, sharing the exact write discipline
(the ledgered loop, the atomic rollback on genuine failures, the
group reclaim, the memo invalidation) but owning its admission
policy:

1. resolve + dedup (unchanged, first-seen order);
2. read both direction maps' live rows (read-only, pre-mutation);
   free = min over the two maps of `POLICY_MAP_CAPACITY - live`
   (a leg needs a slot in each direction it writes; the min is the
   conservative bound for any -d/-u mix);
3. admit every already-live id (an overwrite costs no new slot —
   re-limitting a limited host never refuses), plus fresh ids
   first-seen while free lasts; the remainder is returned as
   `saturated`;
4. write the admitted list; the handler warns once
   (improve-30's one-line contract) naming what landed, what did
   not, and the one command that makes room
   (`unstrict-all`); when the sweep enforced NOTHING
   (applied == 0), exit non-zero with a dedicated
   at-capacity error — never a success, never the generic
   no-match wording (the apps ARE there; the ROOM is not).

The EXPLICIT lists keep their whole-refusal contract untouched:
strict-multi (apply_group_atomic) and block-multi refuse whole
past 1024 — every segment there is the operator's own claim, and
the improve-50 cap-crossing stage PINS that refusal as the
product's honest boundary.

Two silent-no-op holes in the same handlers closed alongside:
both sweeps ignored the applied count entirely, so a fully-stale
snapshot (every member exited between walk and write — the exact
race the best-effort design tolerates) printed the success
epilogue with NOTHING enforced. Both now carry the applied==0
no-match error, dinner-11's contract.

**Pins.** The pure admission rule (`capacity_admit` — live ids
free, fresh first-seen, truncation, order preservation) and the
`POLICY_MAP_CAPACITY == 1024` mirror (the kernel-side map class,
the burst-bound mirror's both-sides-pin discipline) live in
test/ebpf/limiter/policy_tests.rs. The A/B frame benchmark
(b2d2719 vs HEAD) shows the render lane untouched: gini/entropy
identical to noise, fps within noise.

## 2. Audited clean (the hunt's negative results)

Every capacity/freeze class in the product, checked against the
leaderboard bug's shape:

| resource | cap | past-cap behavior | verdict |
|---|---|---|---|
| userspace leaderboard | 4096 | dead rows retire (mitigate-1) | clean |
| observer dl/ul counter maps | LRU 4096 | live-with-traffic counted, idle ages out | clean |
| socket cookie maps | LRU 4096 | same LRU lane | clean |
| AMMSP leaf-cache memos | LRU 4096 | evicts, no freeze | clean |
| policy family (buckets/stats/window too) | 1024 | sweeps saturate (this task), explicit lists refuse clean | clean |
| group buckets | 256 | member degrades to its own bucket at the group's rate — never unlimited (lts-7), dead groups reclaimed | clean |

Interaction boundaries walked with fresh eyes: the during
wall-clock bridge (saturating arithmetic, dormancy law, the
span/daily kinds, UTC-only documented), the eBPF refill math
(burst bound u64-proof, SMP CAS window ownership, stall-fountain
closed), the /proc/net parsers (bounds-safe, field order verified
against the kernel format), the operation lock (flock, root-only
0700 dir), snapshot/restore (temp+rename atomic write, schema
refusal), the suggestion engine (bounds-safe Levenshtein/Jaro),
the update checker (root refusal, hourly swarm bound, untrusted
tag handling), the bypass shadow audit (saturating, wrap-coherent
deltas). clippy clean on every lane; no TODO/FIXME markers
anywhere in src/ or ebpf/src/.

## 3. Named residuals (owner's call, not fixed — the
over-engineering guard)

1. **Name-list resolution is O(N x /proc).** `resolve_target` on
   a `ProcessName` walks /proc once per name, and
   `check_root_catch_all_resolved` walks once more per name — so
   `strict-multi brave:curl:...` with a THOUSAND names costs ~2000
   full /proc walks (the same quadratic class the improve-50
   danger-loop fix closed for NUMERIC ids). Not fixed: the
   fleet-scale lane is numeric (list-apps ids — the shape the
   cap-crossing stage and every scripted consumer uses), the
   human lane is 2-10 names, and batching name resolution means
   restructuring resolve_target's per-name contract for a shape
   nobody has hit. Named here so the day someone files "sm with
   500 names is slow", the diagnosis is one grep away.
2. **Live sweep-saturation proof absent from CI.** The admission
   arithmetic and the write discipline are unit-pinned, but the
   warn/error rows past 1024 are not crossed LIVE (the VM fleets
   stay under the ceiling; a live row would need 1024+
   uid-dropped sleepers — the improve-49 drop lane's machinery at
   16x its current scale). The improve-50 stage crosses the
   ceiling for the EXPLICIT lane only. Cost/benefit says wait for
   the owner's call: the composition (pinned admission + pinned
   write loop + thin handler) carries the risk.
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
