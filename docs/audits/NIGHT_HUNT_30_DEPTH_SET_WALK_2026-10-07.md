<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-30 audit — the depth report's per-id class, closed

> Task date: 2026-10-07 (NIGHT-hunt-30). Scope: the owner's
> "hunt until nothing remains" directive, continued past hunt-29's
> removal-lane closure. Method: the quadratic-class sweep the
> one-walk family owns (per-item /proc walks, per-item full-map
> reads, per-item linear joins), then the panic/cast/swallow
> classes over the surfaces the capacity hunts had not walked.
> One find family fixed this task — the eagle-eyes depth report
> resolved N cgroups then paid THREE per-id taxes; the rest of the
> swept surface audited clean. Fixed at b305638 (post hunt-29).

## 1. The find (fixed): the depth report's three per-id taxes

**The shape.** `eagle-eyes --depth` resolves its '/'-separated
spec to N cgroup ids, then rendered the report per id — and every
per-id step was an O(N x something) tax:

| Per-id step | Before | After |
|---|---|---|
| `depth::deep_collect(id)` — the facts walk | N full /proc walks (each reading EVERY pid's cgroup for membership) | ONE set walk |
| `enforcement_for(id)` — the policy verdict | N x 2 FULL policy map reads (1024-row maps), each with a linear find | 2 map reads, one join |
| `stats_rows.find` — the ledger join | O(N x 1024) linear scans | one map join |

On the dense-server shape (~8200 processes), a multi-cgroup
target (brave resolves to ~30 cgroups) paid 30 full /proc walks
of pure membership overhead — ~246k cgroup-file reads — before
the report's own data reads (per-member stat/comm/status) ran at
all. A fleet-scale spec (the improve-31 shape, hundreds of ids)
paid minutes of membership overhead for a report whose data is
per-member anyway. The same quadratic class improve-50 closed
for numeric ids, hunt-28 for names, hunt-29 for removal — the
depth report was the class's last N x /proc site.

**The fix — the set walk, and the joins.**

- `identity::depth_walk::deep_collect_set(ids)` — the walk moved
  out of depth.rs (the LOC-cap split: depth.rs rode 500 exactly)
  and answers a SET of ids in ONE pass: membership through the
  canonical `pid_cgroup_id` boundary, a pid outside the wanted
  set costs its cgroup read and nothing more (the single walk's
  own short-circuit), member facts through the same
  `process_facts` layer (the per-pid reads ARE the data — they
  stay per-member, linear in the data volume). The clock reads
  (hz, uptime, boot epoch) happen once for the set, not once per
  id. `deep_collect` becomes the single-id spelling over the set
  walk (pathwalk's first arm keeps its exact cost); two tokens
  naming the same cgroup now share ONE facts snapshot instead of
  two walks racing process churn.
- `enforcement_join` — the policy maps read ONCE before the
  report loop (both directions, into id-keyed maps; the read
  failures still propagate before any row renders, the hunt-22
  contract), the per-id verdict a pure map lookup.
- The stats ledger join — one `HashMap` build, the per-id row a
  lookup. (A 4M-compare scan on a fleet-scale spec, for nothing.)

**The pins.** Three new pins in depth_walk_tests.rs: the
empty-set no-walk contract, the live walk against the test
process's own cgroup (guarded the improve-50 way — the hybrid-v1
runner class asserts the honest absence), and the
single-vs-set agreement (deep_collect and the set walk collect
the same members — the drift fence). The moved pure parsers keep
their depth.rs pins; the report's rendering keeps its rendering
pins; the supermassive VM lane covers the depth rows end to end.

## 2. The class sweep (the "nothing remains" pass)

- **Per-item /proc walks**: every `read_dir`/`fs::read` site in
  src/ audited for loop context. The remaining sites are
  single-shot (recover, capabilities, cleanup's pin census), the
  canonical walkers themselves (identity refresh, TTL-gated;
  name_walk; depth_walk; the danger guard's one walk), per-member
  data reads (process_facts, connections), or single-lane by
  construction (the container resolver — strict-single only; the
  probe's residency poll — one child, deadline-bounded). The
  `user_name` per-member /etc/passwd read is linear in the member
  count (the data volume, not N x /proc) — noted, left (the
  over-engineering guard).
- **Panics/unwraps in production code**: every site is either
  test-gated or a provable loop invariant (probe_role's
  connect-loop expect). Clean.
- **Integer casts**: `ino() as u32` is the documented ID-width
  decision (SAFETY_ANALYSIS); char/fd casts are domain-bounded.
  Clean.
- **Silent error swallows on limiter writes**: none (the hunt-20
  ledger discipline holds).
- **Lock/TOCTOU**: hunt-27's clean walk re-checked against the
  new lanes — no mutation moved outside the flock'd handlers.

## 3. Residuals

None named. The one-walk family is closed across every site the
class sweep found: numeric ids (improve-50), names (hunt-28),
removal (hunt-29), depth facts + joins (this task). The
un-audited remainder is the eBPF kernel side beyond hunt-27's
capacity/SMP math walk — the honest boundary for a userspace
hunt; the VM lanes pin its behavior.
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
