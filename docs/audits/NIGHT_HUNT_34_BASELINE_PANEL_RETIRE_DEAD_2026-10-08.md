<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-34 audit — the baseline panel's retire_dead, and the eagle-eyes chain walked to peak

> Audit date: 2026-10-08 (NIGHT-hunt-34). Scope: the owner's ask —
> the eagle-eyes leaderboard freeze was fixed (NIGHT-mitigate-1's
> retire_dead), but the section below the cgroup process table, the
> "baseline · policy aggregate" panel, still carried no such
> mitigation; audit all of eagle eyes to peak-LTS, minimal bugs.
> Method: walk the panel's whole chain — the TUI lane
> (render/baseline.rs), the pinned-map reader, the kernel ring maps,
> and every removal path that touches them — against the
> leaderboard's freeze shape; then walk the rest of the render tree
> with fresh eyes for the same class. One find fixed this task; the
> rest of the surface audited clean. Audited at 7133498
> (post audit-4's glossary).

## 1. The find (fixed): the census-bounded state no sweep could name

**The bug.** The baseline panel renders whatever the RING READ
carries — the lane folds every key the pinned ring maps hold, every
frame, and renders a verdict row per key. The ring maps themselves
are plain 1024-slot pinned HashMaps whose occupancy claim is
"bounded by the policy census" (`ebpf/src/bin/limiter.rs` — the
comment family bucket/ring/stats/window all share). Every removal
path reclaims its own rows (`reclaim_cgroup_state`; NIGHT-hunt-Z4
added the rings to it), but the claim had no enforcer for the
residue: a reclaim that FAILS (best-effort by contract — a warned
delete) or a crash between the policy delete and the state delete
leaves the row behind with no policy naming it. And nothing ever
collects it:

- `recover` walks orphan POLICIES — a ring whose policy is already
  gone has no row to walk. The residue is invisible to the one
  command whose job is crash hygiene.
- The status JSON joins rings by POLICY row, so the JSON surface
  never shows them — but the TUI lane has no such join, and the
  panel does.

Two consequences, one visible and one structural:

1. **Ghost rows.** A leaked ring entry renders a permanent row —
   `cg:NNN  steady 0 B/s` — on the panel below the cgroup process
   table: the stale slots fold as quiet zero samples (a real
   sample, by the lane's own law), the EMA converges to zero, and
   the identity lookup falls back to the bare id. The row survives
   every frame for the life of the pin epoch.
2. **The census freeze.** Each leaked entry holds one of 1024
   slots until, on a churning host (crash-adjacent removals
   accumulating, or a host upgraded from a pre-hunt-Z4 build whose
   maps arrived already polluted), fresh policy roots' rings
   silently fail to create — `get_ring_ptr`'s fail-open skip (the
   monitor never gates a verdict), so enforcement is unaffected,
   but the baseline panel stops learning for every NEW policy: the
   exact leaderboard-freeze class NIGHT-mitigate-1 closed on the
   userspace board, un-mitigated on the kernel side. This is the
   panel's retire_dead, missing.

**The fix (the orphan-census sweep).** `sweep_census_orphans`
(`src/ebpf/limiter/reclaim.rs`) — the reclamation family's newest
collector, named for the claim it enforces: read the policy census
(both direction maps), then walk each census-bounded family for
keys no live leg owns and delete them under the family's own gate:

| family | gate | why |
|---|---|---|
| `cgroup_bucket_dl` / `rate_ring_dl` | no dl policy row | the per-direction state dies with its own leg (the `-d`-only removal law) |
| `cgroup_bucket_ul` / `rate_ring_ul` | no ul policy row | the mirror leg |
| `cgroup_limiter_stats` / `policy_window` | no row in EITHER direction | the combined state, `reclaim_cgroup_state`'s both-gone flag |

The gates mirror `reclaim_cgroup_state`'s own per-family flags
verbatim — the sweep can never remove state a live leg still owns.
Fail-closed on proof (an unreadable POLICY map proves nothing dead
and stands the whole sweep down, the `reclaim_dead_groups`
posture); best-effort on collection (an unreadable family map
skips just that family, warns, and the next visit retries; a
failed delete warns and never fails the caller). The LRU families
(leaf buckets, flow buckets, socket maps, ECN debt, the MMSPA
memo) are deliberately untouched — the LRU owns their lifecycle,
and the leaf maps' keys are not policy roots (the predicate would
be wrong there, not just unnecessary).

**Placement — the window sweep's own law.** The sweep rides
exactly the sites `sweep_expired_windows_best_effort` rides, the
"CLI is the daemon" law's mutation-capable visits: the apply
family's tails (`apply_single`, `write_group_legs` — shared by
`apply_group` and `apply_group_sweep` — and `apply_group_atomic`),
the status visit (try-locked, hunt-30's law), and `recover` —
where it runs after the window pass and before the orphan scan, so
the early "nothing to recover" return sweeps too, and its count
reports beside the Windows line. The apply-time placement is also
the freeze lifter: a fresh policy's ring that failed to create on
a polluted map self-heals — the sweep frees the slot in the same
visit's tail, and `get_ring_ptr` retries on the next packet.

Not placed in `unstrict` (the window sweep is not either): the
residue originates in a FAILED reclaim of that same moment — the
next mutation-capable visit collects it, the hunt-30 law's own
wording ("the row stays, awaiting the next sweep").

**Pins.** The pure decision core (`census_orphans` — the per-leg
gates, the either-leg survival, the empty-census crash-tail shape,
sorted deterministic output) and the verbose trace wording live in
`test/ebpf/limiter/reclaim_tests.rs`, `#[path]`-wired
(Pattern C). Six for six green on the host build.

**A/B.** The frame bench (before 7133498 vs the fixed tree,
identical fixed-seed harness): fps 5727.0 -> 5633.5 (-1.6%,
run-to-run noise on the shared build host), density_gini
0.3218 -> 0.3221, frame_entropy 3.2064 -> 3.2049, dirty cells
82.4 -> 82.3, emit bytes/frame 536.9 -> 536.4 — every metric
inside its noise band, as expected: the sweep rides CLI mutation
tails and never touches the render path (the mitig gate's own
discipline, held for free this time — the sweep is not per-frame
at all).

## 2. Audited clean (the hunt's negative results)

The rest of the eagle-eyes chain, walked against the freeze/leak
class and the render tree's no-I/O, no-panic contract:

| surface | verdict | the why |
|---|---|---|
| the baseline lane (render/baseline.rs) | clean | a HashMap retained against the live ring read per frame — no cap to freeze, no row without a ring behind it; the ghost problem lived one level down (fixed above) |
| the fold (judge-then-update EMA, window dedupe, pre-boot checked_sub) | clean | pinned in the baseline test trees; a spike cannot mask itself |
| the session leaderboard (session.rs) | clean | retire_dead landed (mitigate-1), u128 saturating folds, tie-stable sort |
| the ranked composition (eagle.rs) | clean | fold -> retire -> resolve -> note ordering pinned; the row budget counts detail lines; the over-height pin pops lowest ranks first |
| the focus view + board filter (focus.rs) | clean | the filter's predicate is the retirement's predicate — one law, both pinned |
| the footer (footer.rs) | clean | saturating sums throughout, tier ladder pinned (lts-9 re-verified) |
| top consumer (rank.rs) | clean | byte-ranked with the honest walk-order fallback (dinner-6) |
| targets/border/loading (render helpers) | clean | small, pure, pinned; `char as u32` at border.rs:308 is the CJK width family — never a wrap |
| connection detail (connections.rs) | clean | TTL-memoized (3s) behind the per-frame poll — bounded staleness, documented |
| the eagle command gate (commands/eagle.rs) | clean | launch existence gate + interactive-stdio gate + per-frame re-resolution (lts-9 re-verified) |
| index arithmetic (baseline.rs:285 `series.bytes[i]`) | clean | i bounded by the const slot count — no unbounded index anywhere in the render tree (no unwrap/expect/panic in non-test render code) |

## 3. Named residual (owner's call, not fixed — the over-engineering guard)

1. **Live orphan-census proof absent from CI.** The sweep's
   decision core is unit-pinned and the walk rides lanes every
   other reclaim already exercises, but the end-to-end shape (a
   ring whose policy is gone, collected by the next visit) is not
   crossed LIVE — it would need a VM stage that applies, force-
   fails a reclaim, and visits again. The improve-50 supermassive
   fleet could carry it the day the owner wants it; the
   composition (pinned core + pinned lanes + thin table) carries
   the risk meanwhile. Named here so the day a leaked-ring report
   arrives, the diagnosis is one grep away.
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
