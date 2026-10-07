<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-28 audit — the name-resolution one-walk fix

> Task date: 2026-10-07 (NIGHT-hunt-28). Scope: the owner's call on
> hunt-27's named residual #1 — "resolusi nama O(N x /proc)" — the
> name-list lane's quadratic walk class. This task closes that
> residual where it lives (the enforce-family's name lists), names
> the one shard it deliberately leaves (the removal lane), and adds
> no new hunt surface: the walk arithmetic is the whole story. Fixed
> at 7b23e52 (post hunt-27).

## 1. The residual, closed: name lists walked /proc once per name

**The shape.** Hunt-27's residual #1, verbatim: `resolve_target`
on a `ProcessName` walked /proc once per name, and
`check_root_catch_all_resolved` walked once more per name — so
`strict-multi brave:curl:...` with a thousand names cost ~2000
full /proc walks before the first map write ever ran. The same
quadratic class the improve-50 fix closed for NUMERIC ids
(`check_dangerous_targets_multi`'s one-walk sharing), left open
for names because the fleet-scale lane is numeric and the human
lane is 2-10 names. The owner has now called it.

**The sites, before the fix** (the full walk-count table):

| Lane | Walks before | Walks after |
|---|---|---|
| strict-multi, N names | 2N (N guard + N atomic pre-flight) | 2 (1 guard snapshot + 1 batch) |
| block-multi, N names | 2N (N guard + N group resolve) | 2 |
| eagle-eyes depth, N names | N (per-token resolve_name) | 1 |
| strict/block/unstrict single, 1 name | 2 (guard + apply) | 2 (unchanged cost, shared walker) |
| sweeps (strict-all/block-all, pure ids) | 0 | 0 (empty name list never walks) |

On the dense-server shape improve-31 documents (~8200 processes
in /proc), a thousand-name multi was ~2000 walks x ~8200 comm
reads ≈ 16.4 million reads of pure guard overhead before
enforcement began. After the fix the whole name population costs
one walk's comm reads (a cgroup read lands only on a wanted
name's pids — the same short-circuit the per-name walk always
owned), whatever N grows to.

**The fix — one walker, every spelling.** The walk moved one layer
down: `identity::name_walk::resolve_name_set` is the single /proc
walk every name resolution in the estate rides (the canonical
boundaries `pid_comm` + `pid_cgroup_id`, NIGHT-optimized-1, kept
exactly — a prctl-spoofed comm can still never match one thing and
display another). It answers a SET of names in one pass, returning
per lowercased name the matched `(pid, cgroup_id)` pairs in walk
order — the exact evidence the per-name walk collected. Three
reductions ride it, and the batched twins:

- `resolve_target`'s ProcessName arm (the single lanes) — one walk,
  one trace, one `matched_pairs_to_ids` reduction (dedup
  first-seen, the aria2c/alacritty shape). Cost and output
  byte-identical to the arm it replaces.
- `resolve_target_list` (NEW, the multi lanes' batched twin) —
  strict-multi's atomic pre-flight (`apply_group_atomic` phase 1)
  and block-multi's `resolve_group_ids` resolve the whole target
  list through ONE walk, per-target resolutions in TARGET order,
  each name keeping `resolve_target`'s verbose trace (the trace
  line is a BTreeMap render, so pair order is invisible in the
  output anyway). The CgroupId arm never walked and still does
  not; the Container arm keeps its own URI machinery at its list
  position; the identity refresh that rode per name rides once
  for the batch (the TTL gate made the per-name repeats no-ops by
  construction).
- `check_root_catch_all_resolved` (the hunt-Z3 guard) — the whole
  name population resolves in ONE snapshot before the target
  loop; the verdict order (first target resolving to the root
  wins) and wording are untouched. Pure-id lists collect no
  names, so the sweeps still pay zero walks.
- eagle-eyes depth — the '/'-separated spec's names resolve in
  ONE snapshot before the token loop; `resolve_name` itself is
  now a thin wrapper over the walker, so the probe lane, the
  `ss <name>` lane, and every batch lane share one matching
  implementation — the no-drift law, pinned.

**The walk-count proof the pins hold.** The pure reduction (dedup
first-seen, order kept), the live walk against the test process's
own comm (guarded the improve-50 way: the hybrid-v1 runner class
where `pid_cgroup_id` honestly resolves nothing asserts the honest
absence instead), the empty-list no-walk contract, and the
single-vs-set agreement (eagle's `resolve_name` and the batch
snapshot must return the same ids — the drift-class fence). The
guard's existing hunt-Z3 pins now run through the batched path
unchanged, plus one new pin: a clean multi-name list flows
friction-free and the root id after clean names still refuses at
its list position.

## 2. The honest boundary: the removal lane's shard, left named

`unstrict-multi` (um) with N names still resolves per name:
`remove_limits` loops `limiter.unstrict`, each resolve walking
/proc once. N walks, not 2N — the removal lane runs no
root-catch-all guard (removal is the safe direction) — and the
human shape is 2-10 names. Batching it means restructuring
unstrict's per-target contract (the failed-list and superseded
accumulators, the dead-group sweep's per-target cadence, the
partial-failure abort semantics of the remove loop), which is a
different surgery on critical removal machinery for a lane no
scripted consumer has filed a shape against. Named here so the
day one does, the diagnosis is one grep away — the same residual
discipline hunt-27 modeled.

## 3. Addendum (NIGHT-hunt-29, same day): the shard closed

The owner called the removal lane's shard (the "hunt until
nothing remains" directive), and it closed without the accumulator
restructure the boundary feared. The find while implementing: the per-target
contract could be preserved EXACTLY by splitting the resolve from
the removal — `unstrict` = `resolve_target` + `remove_ids` (the
verbatim removal body), and `unstrict_multi` = ONE
`resolve_target_list` walk + the per-target `remove_ids` with the
loop's own abort semantics (first partial failure stops the
remaining targets with the same Err), each target keeping its own
failed list, superseded ledger, dead-group sweep, and memo bump —
the cadence the boundary documented as the risk turned out to be
the thing that makes the split safe. `remove_limits` (the shared
front half of unstrict-single AND unstrict-multi) parses the whole
list and rides `unstrict_multi`; the single spelling pays one walk
exactly as before, and a thousand-name `um` drops from a thousand
walks to one. The during window's expiry path (during_map's
per-cgroup-id unstrict calls) is unaffected by construction — the
CgroupId arm never walked. The family's file move: the split put
reclaim.rs past the limiter family's 500-line owner cap, so the
unstrict family (resolve + remove) moved to its own file
(unstrict.rs, 171 lines; reclaim.rs back to 356) — the house
precedent, one cohesive concern out. Every output line, the
abort path, and the counting unit are the loop's own, verbatim;
the existing reclaim pins (partial-failure wording, dead-group
rule) and the resolve_target_list pins carry the semantics, with
the supermassive VM lane covering the removal rows end to end.

## 4. Verification

- 832 unit + 48 integration tests green (five new pins, one
  environment-hardened live pin).
- clippy and fmt clean on every lane.
- The render lane is untouched by construction (command-handler
  resolve paths only); the A/B frame benchmark confirms it.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every .md file — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
