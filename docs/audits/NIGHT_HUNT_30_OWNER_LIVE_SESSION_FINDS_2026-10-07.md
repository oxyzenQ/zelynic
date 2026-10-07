<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-30 audit — the owner's live session, four finds, four closures

> Audit date: 2026-10-07 (NIGHT-hunt-30). Scope: the owner's live
> bug-hunt session on the pro machine (the terminal record pasted as
> cosmos.log, 19:03-20:19 WIB) — four finds, each one an echo the
> owner typed at the moment he hit the bug (translated per the
> pure-English docs rule; the session transcript itself is the
> evidence, quoted by timestamp).
> Audited at c1a42b0's parent a965430 lineage (v50.0.0-alpha.1; the
> owner's own build was cb3e3c8, a local-unpushed state — origin
> main stood at cb0c0ae, night-hunt-29's docs rider; every find
> reproduced against cb0c0ae's source before the fix was written).
> Method: the session read end to end, every echo mapped to its
> code path (rg-first, the heavy-tree discipline), each fix landed
> as its own code commit with its own verification block, the
> gatekeeper pair green on every commit.
> Status: four finds, four closures, zero declined candidates; the
> honest residuals on the record (section 7).

## 1. The mandate

The owner ran the flagship binary through its paces for eighty
minutes and filed what he found the way he always does — an echo
at the exact moment the bug bit. The instrument table:

| # | The ask (the owner's echo, translated) | The instrument this audit used |
|---|----------------------------------------|-------------------------------|
| 1 | "the brave on status should gone but this need manual" (20:14; also 19:07: "should expired and the limit on status is none limit but that still have stale 100kb") | the sweep's call-site census (rg sweep_expired_windows): the lazy sweep rode the apply family only — status, recover, and snapshot never collected an expired row |
| 2 | "should strict single is single and multi is multi / so when only using sm brave should print exit error need more target" (19:44-19:45) | the colon-grammar boundary (validate_multi_targets): one segment — or one name spelled twice — flowed through as a list |
| 3 | "what mean window secs 1 / should window secs 1 minute / or 2 minute" (19:18-19:19) | the status JSON's rate_ring builder: window_secs carried the per-slot width (1) beside an eight-entry series — the label read as the span |
| 4 | "run strict multi and all without verify like using single why? / need verify for multi and all strict mode" (19:59) | the probe's call-site census: run_enforcement_probe had exactly one caller (strict-single); the multi and the sweep printed "applied" and hoped |

What the session also PROVED healthy (the negative results the
audit owes the record): the `--during` grammar's refusal wording
(the 2mm typo tip at 19:03), the rate bounds ladder (0.01kb below
minimum, 10tb above maximum), the atomic strict-multi refusal on
an unresolvable member (`sm brave:xs`), the snapshot/restore
round-trip preserving a span's absolute wall instants ("wow
amazing", 20:19), and `unstrict-all`'s no-residue teardown. None
of those surfaces were touched.

## 2. Find 1 (the core): the visit sweep

**The shape.** `ss brave 100kb --during 2m` at 19:03; at 19:07 the
browser measured 3.3 Mbps (the kernel had stopped policing — the
window comparator's own verdict) while `status` rendered the stale
100.0 KB/s row as an ACTIVE limit, twice, with the lifetime line
naming the truth the surface would not act on: "expired ...
(awaiting sweep)". The sweep existed — night-during's "the CLI is
the daemon" — but only the apply family drove it
(policy.rs/atomic.rs, three call sites). Between applies, the
expired row sat in the maps indefinitely: counted in the census
line, rendered with its stale rate, dying only when a mutating
command happened to run or the owner manually unstrict'd it. The
owner ran `status` five times across twenty minutes watching it
not leave; `recover` (19:20) read the same rows as "4 policies
across 2 cgroups, all live" — "nothing to recover".

**The fix (c1a42b0).** The law completed: every mutation-capable
VISIT reaps what its own clock says is dead.

- `status` (commands/monitor.rs): after the identity refresh, a
  try-lock (never block — the lock is non-blocking by design, so a
  concurrent operation holding it skips the sweep silently and the
  row renders with its honest "awaiting sweep" line, collected by
  the next quiet visit) drives the sweep before BOTH render
  surfaces — the human table and `--print-json`, so automation's
  `active_limits` counts live windows only. The sweep's unstrict
  traces on stderr name what was collected (the same audit trail
  the applies print).
- `recover` (commands/recover.rs): the window-death pass runs
  BEFORE the orphan scan, under the lock recover already owns. An
  expired row is not crash residue (its cgroup is alive, its clock
  is over); the pass is named in the doctor report ("Windows: N
  expired row(s) swept (window-death, not crash residue)") and
  stays best-effort per the sweep's own contract — the orphan
  census below still propagates its reads.
- `snapshot` (commands/persist_run.rs): the sweep runs before the
  census read (lock already owned), so an expired row never rides
  the state file as a live limit — a restored dead span would land
  as born-expired, "awaiting sweep" again one reboot later.
- `sweep_expired_windows_best_effort` (src/ebpf/limiter/policy.rs):
  pub(super) -> pub — the read visits join the apply family as
  callers.

The sweep path itself is untouched: the existing unstrict
machinery with its state reclaim, group supersession, and memo
bump. The applies' behavior is unchanged — same driver, more of
them. `eagle-eyes` was deliberately NOT wired: it is a long-lived
TUI reading the observer's maps, not a limiter visit.

## 3. Find 2: the grammar rung

**The shape.** `sm brave 100kb` (19:43) applied cleanly —
strict-multi on ONE target. The multi lane exists for group limits
(one rate shared across a colon list); a single target there is
the single verb's lane wearing the wrong flag.

**The fix (49d0127).** `validate_multi_targets` (the one boundary
all three -multi verbs share: strict-multi, block-multi,
unstrict-multi) refuses a list that carries fewer than 2 DISTINCT
targets — a single segment, or one name spelled twice (a
`brave:brave` group is one app, not a fleet). The refusal is
parse-time and names the verb (derived from each caller's example
param, so each family's error reads its own lane), the
requirement, and both exits as tips: the single verb with a
runnable command, or a grown list. The strict-single /
block-single / unstrict-single lanes are untouched; numeric and
cg: display-form segments ride the list as they always did.

## 4. Find 3: the lens label

**The shape.** The status JSON's rate_ring object printed
`"window_secs":1` beside a `bytes` array of eight entries
(19:17-19:19). The field carried the per-slot width — each ring
slot covers one second — but beside a series it reads as the
window the series spans, and a consumer computing the horizon's
average rate as `sum(bytes) / window_secs` overcounted
eight-fold. The horizon itself is the documented eight seconds
(the shared core's RING_SLOTS x RING_WINDOW_NS design, the kernel
object untouched): the label, not the lens, was wrong.

**The fix (a965430).** `window_secs` now names the SPAN the series
covers — RATE_RING_SLOTS (8), the eight one-second slots the
bytes array spans — so the division is honest and the field
matches the array it annotates. The per-slot granularity is
`bytes.len()` (one sample per second), documented on the field and
in the scripting reference's rate_ring section (the example
updated with it). The scripting-contract rule held: no field
renamed, no field removed — one value corrected with its
semantics documented.

## 5. Find 4: the parity lane

**The shape.** strict-single verified its enforcement
(NIGHT-upgrade-charger-core-1-b, "applied is a claim, VERIFIED is
a measurement"); `sm` and `sa` (19:42-19:57, the whole session)
printed "applied" and hoped.

**The fix (3abd7d4).** Both verbs carry the self-proving
verification lane now, each through its own honesty contract:

- strict-multi probes the FIRST colon member after the atomic
  apply — the atomic contract guarantees that member landed (one
  miss aborts the whole list), so the measurement reads the
  group's fresh shared bucket, and the report's own multi-leaf
  note names the per-cgroup ledger the group spans. The lock's
  scope became the APPLY, not the probe (strict-single's own
  dinner-28 contract, one lane over); the FAILED-first ordering
  and the probe-boundary pin re-check mirror the single's law.
- strict-all probes the FIRST applied app when the whole fleet
  landed (saturated == 0). A saturated sweep skips the probe with
  a named note instead of measuring a lane that may not have
  landed: the skipped member could be the very lane the probe
  would name, and an unlimited path reads FAILED by its own
  numbers — a verdict built on a guess, the exact shape the
  honesty contracts forbid. An app that exited between snapshot
  and write resolves to nothing at probe time and reads
  UNVERIFIED, the honest stand-down.
- Both verbs carry `--no-probe` (the scripted apply-only shape,
  the single's own flag parity), wired through the dispatch and
  the dormant lane.

## 6. Verification evidence

Per-commit, the full local pair: `cargo test` 839 + 51 / 0 failed
after each of the four code commits (the new pins:
`multi_list_single_target_is_the_single_verbs_lane` for find 2;
the `rate_ring_field_joins_series_by_cgroup` span assertion for
find 3); `cargo fmt --check` clean; `cargo clippy --all-targets`
clean; the dormant build (`--no-default-features`) compiles
(find 4's dispatch wiring); 23/23 gatekeepers on every commit
(the fresh-clone environment's umask artifacts — 466 files at 664
— repaired once via check-permissions.sh --fix before the first
commit, and markdownlint re-pinned to CI's v0.18.1; both
environment repairs, zero content diff). The LOC caps read clean
after every commit (strict.rs peaked at 509, safety.rs at 589,
both under the 600-line law).

The benchmark decision, on the record: the A/B frame bench was
skipped per the boost-10 precedent — all four fixes are CLI
surface (parse, JSON assembly, handler wiring); the render
engine, the frame harness, and the eBPF objects are byte-untouched,
and a benchmark over an unchanged binary is wasted energy.

## 7. Honest residuals

- The live sweep-on-status / sweep-on-recover / probe-on-multi
  lanes need a root machine to exercise end to end (this pass ran
  in an unprivileged sandbox; the owner's pro machine and the CI
  supermassive matrix own the live verify). The wiring is the
  same unstrict machinery the applies have driven since v23 —
  the risk surface is the three call sites, not the sweep.
- `um brave` (unstrict-multi on one target) now refuses with the
  list-verb error, where it used to remove the named target. The
  refusal is loud, parse-time, and teaches `us brave` — the
  grammar rule the owner asked for, applied to the shared boundary
  by symmetry. If the owner wants the removal lane lenient, the
  rung is one guard away from -multi-verbs-except-unstrict.
- The `ee` command's `--interval` bounds (1s..60s) and `recover`'s
  missing `--interval` (the owner probed both, 19:13/19:31) were
  read as intended behavior, not bugs: recover is a one-shot verb,
  and the live monitor owns the interval.
- Find 3's `window_secs` semantics correction changes a VALUE
  automation may have depended on — in the direction of truth
  (1 -> 8 with the division now honest), documented in the
  scripting reference; the field name and the document shape are
  unchanged.
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
