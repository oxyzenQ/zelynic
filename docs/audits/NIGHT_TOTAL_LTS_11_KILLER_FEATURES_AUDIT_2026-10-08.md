<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-11 depth audit — the killer-features pass, round five

> Audit date: 2026-10-08 (NIGHT-total-lts-11). Scope: the owner's ask —
> depth audit focused on the killer features (the limiter and the
> monitoring/eagle-eyes), then the UX CLI/flag surface, then the other
> Rust code, total LTS, honest. Audited at 9b2b1d6 (hunt-37 rider v2's
> HEAD; v50.0.0-alpha.1). Method: five killer-features rounds in four
> nights (lts-3, lts-5, lts-7, lts-9) plus hunt-38's same-night peak
> walk read the engines line by line — so this round hunted the DELTA
> none of those rounds could have seen (the seven commits after
> lts-9's read point 39b5b2e: the lts-8 family's sweep/gate/index
> riders, audit-4's glossary, hunt-34's orphan-census sweep, hunt-35's
> help masterclass, hunt-36's depth closures, hunt-37's CI riders,
> hunt-38's peak walk — every one self-audited with pins at landing)
> under the CROSS-CUTTING invariant lenses those self-audits do not
> apply: the lock-posture matrix across every new sweep call site, the
> fold-ordering consistency law, the help-mirror-vs-truth recheck
> after a full rewrite, the pipe-contract sweep, and the
> overflow/underflow/division/indexing scans across the whole src
> tree. Status: ZERO new finds — the first killer-features round to
> return a clean sheet — and the instruments that produced it are on
> the record below so the verdict is verification, not fatigue.

## 1. The mandate

The owner's ask: killer features first — the limiter engine, the
eagle-eyes monitor — then UX/CLI, then the remaining Rust code, under
the five infra areas and the peak-skip protocol. The instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash over the limiter and the monitor | the delta's crash-pattern classes re-read line-class (reclaim.rs's 187 new lines read whole, every map delete routed through the family's best-effort warn lane, zero new unwrap/expect/panic in the delta — the classic-class scans below confirm zero in the whole tree); the full battery fresh (837 + 53 / 0 failed, 4 ignored, at HEAD) |
| 2 | Code hygiene across the killer-feature dirs | the retired-vocabulary and dead-code spot checks over the delta surfaces (zero `window_persist` reach, zero retired verbs in the suggestion dictionary — lts-9's sweep verdicts re-anchored); the render tree's module discipline intact (every pin family #[path]-wired in the single test tree) |
| 3 | Optimization of the hot paths | no hot path touched by the delta outside hunt-38's own A/B-verified reordering (the render frame path carries hunt-38's byte-identical A/B — 1,919.0 bytes/frame, emit/dirty/gini/entropy within host noise); this round changes no code at all, so no A/B was run (docs-only, the rule's own skip) |
| 4 | Security hardening at the feature surfaces | the lock-posture matrix (below), the sweep's unlink semantics (remove_file never follows a symlink; remove_dir refuses non-empty), the /proc and JSON surfaces untouched by the delta |
| 5 | LTS stability of the feature contracts | the census-sweep law's callers walked end to end (apply family, status visit, recover — every site under the operation lock or its honest try-lock degrade); the peak-rate law's fold-time contract re-derived from the source |

## 2. The lock-posture matrix — the lens no self-audit applied

Hunt-34's orphan-census sweep (`sweep_census_orphans`) deletes map
entries whose policy census read says no live leg owns them. A sweep
that deletes while an apply concurrently writes is a TOCTOU class the
delta's own audit never checked: a census read before an apply
commits, then a delete after it, would remove a FRESH policy's bucket
(fail-open enforcement loss). The matrix, read at every call site:

| Call site | Posture | Verdict |
|---|---|---|
| `strict.rs` apply lanes (policy.rs 113/323, atomic.rs 243) | `lock::acquire()` held for the operation (commands/strict.rs:185, 389) | SOUND — census read and deletes serialize against applies |
| `recover.rs:121` | `lock::acquire()` at handler entry (:52) | SOUND |
| `monitor.rs:70` status visit | try-lock (`.ok()`); on contention the sweep silently skips and the render shows the honest current state | SOUND — the degrade is the documented hunt-30 contract |
| The eagle TUI | lockless by design (read-only observation; see section 7) | NOTED — pre-existing architecture, honest degradation both directions |

The verdict: the sweep's TOCTOU window does not exist on any lane
that can interleave with an apply, because every apply-family caller
serializes under the same flock the sweep rides.

## 3. The fold-ordering law — session state re-derived from source

The eagle render chain's ordering contract (the class hunt-38's
wobble fix lived in): `absorb` folds the frame's deltas into the
session accumulator FIRST (even an Err poll folds an empty summary,
leaving the board intact), `retire_dead` runs behind the identity
guard, `note_frame` then notes the watched-set aggregate into the
peak RATES using the SAME `admits` gate the accumulator folds with —
so the totals and the peaks can never tell different stories about
which cgroups counted — and the render reads the accumulated figures.
The peak math re-derived: `rate_bps` guards the zero interval
(`secs <= 0.0` returns 0, so a loading frame notes nothing), the
f64 division carries the u64 range losslessly for one-decimal SI
(boost-22's audit, re-verified against the saturating-cast
discipline), `max` needs no saturating arithmetic by construction,
and the footer renders the stored peaks with no conversion — a later
frame's span jitter has no reach into the figure. SOUND, every leg.

## 4. The help mirror vs the machine truth — after the masterclass rewrite

Hunt-35 rewrote the help surface whole (173 changed lines) — the
exact shape that drifted once before (lts-9's find: the help line
advertising the retired `restore` as a fifth JSON surface). This
round re-checked every claim the new help makes against its machine
truth, the drift class's whole surface:

| Help claim | Machine truth | Verdict |
|---|---|---|
| `--print-json` surfaces: status, list-apps, eagle-eyes --depth, doctor | `cli/scope.rs` `JSON_SURFACE_COMMANDS` (33) + the dispatcher predicate (40-47) | MATCH |
| `--focus <1s-30s>`, `1s..30s default 3s` | `parse_focus_window` (limiter/parse.rs:121) — `1..=30`, default 3 at eagle.rs:342-345 | MATCH |
| `--interval 1s..60s` | `parse_monitor_interval` (parse.rs:101) — `1..=60` | MATCH |
| `--color-mode 0, 16, 8/256, 24/32` | `parse_color_mode` (output/color.rs:216) — the same five spellings, the same four capabilities | MATCH |

Zero drift. The masterclass pins (masterclass_pins.rs, help_pins.rs —
12 functions) plus the negative pin lts-9 added guard the class; this
round's recheck is the read-side verification that the pins and the
prose still agree with the code.

## 5. The cross-tree classic-class scans

- **Broken-pipe contract**: zero raw `println!`/`eprintln!` anywhere
  in src/ — every user-facing write routes through the
  `println_safe!`/`eprintln_safe!` macro family (33 files).
- **Underflow**: zero unchecked subtraction on unsigned types in the
  delta; the accumulator family is saturating-add throughout.
- **Division**: every division site in src/ is either an f64/f32
  constant ladder (chroma, suggestion similarity), a guarded rate
  (`rate_bps`'s zero-interval law), or a width computation whose
  operands are structurally positive (the column planner's ladder
  arms — the narrow fallback pins the label to its minimum and never
  subtracts).
- **Indexing**: the `[0]`-class sites read in context — all guarded
  by length asserts (info/mod.rs's stamp-shape pin) or structurally
  non-empty (pipe fds, the suggestion matrix's own invariants).
- **Column-width ceilings**: NUM_W 10 holds both ladders' worst
  cases (`1023.9 EB` at 8 columns, `18.4 EB/s` at 9) — hunt-38's
  clean-table claim re-verified against the source constants.

## 6. The verdict table

| Area | Verdict | Note |
|------|---------|------|
| Limiter removal/reclamation (reclaim.rs + the sweep's four call sites) | SOUND, read whole | lock matrix clean; fail-closed on unreadable census; best-effort warn lanes unchanged |
| Limiter kernel datapath | PEAK, skipped | byte-pinned through the delta (prebuilt parity re-proven per commit); lts-3/5/7 territory |
| Monitor session state (peak-rate law) | SOUND, re-derived | fold ordering, admits-gate sharing, zero-span guard, saturating ceilings |
| Render tree (footer, detail, eagle, loading) | PEAK | hunt-38's line-by-line plus its A/B; zero delta since |
| UX CLI/flag surface | MATCH, zero drift | the four-surface mirror table above; the pin family guards the class |
| Other Rust (output, terminal, info, cli) | CLEAN | pipe contract, division, underflow, indexing scans across the whole tree |
| Battery | GREEN | 837 + 53 / 0 failed, 4 ignored, fresh at HEAD; fmt clean; clippy --all-targets clean |

## 7. This audit's own honest residuals

- The eagle TUI's lockless read posture beside a concurrent
  `cleanup` (unpin_all) degrades the OBSERVER honestly (error
  frames, the one-frame tolerance) and cannot corrupt the limiter's
  state — but the degradation direction is pre-existing
  architecture, not a delta regression; read and noted here rather
  than engineered, per the peak-skip protocol (an owner-invoked
  total pin destruction racing a read-only observer is the
  documented intent of `cleanup`, not a defect it carries silently).
- The live eBPF legs (crash-recovery, race, reload, endurance,
  limiter-depth, the supermassive matrix) remain CI-owned — this
  rootless host cannot attach an observer; the seam re-reads stand
  in for the live shapes, the same residual every killer-features
  round since lts-3 carries.
- The A/B benchmark was skipped by the rule's own docs-only carve-out:
  this round changes zero code — there is no B to measure against
  this A. The verification instruments are the battery, the pins,
  and the source re-derivations on the record above.

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
