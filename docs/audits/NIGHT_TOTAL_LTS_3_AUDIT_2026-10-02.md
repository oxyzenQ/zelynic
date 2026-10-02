<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-3 depth audit — the killer-features pass

> Audit date: 2026-10-02 (NIGHT-total-lts-3). Scope: the owner's ask
> narrowed the total-infra lens to the product's two killer surfaces
> first — the limiter engine and the eagle-eyes monitor — then the
> UX/CLI surface, then the remaining Rust code, under the same five
> infra areas (stability & crash, code hygiene, optimization,
> security hardening, LTS stability) and the peak-skip protocol.
> Audited at 8eb357b with the closes riding 24f2bc5, 2c617d1, and
> bc9c8a0 (v20.0.0-beta.1; the eBPF enforcement object byte-pinned
> throughout — every commit's pre-built parity gate proved it).
> Method: three parallel feature-level deep dives, each reading the
> actual engine code line by line rather than re-running the
> instrument-level sweeps of lts-2 — the limiter engine by the lead
> auditor (math.rs, DRR, AMMSP, the datapath), the eagle-eyes render
> tree and the CLI/UX surface by two dedicated read passes. Status:
> the limiter and the monitor answer SOUND at peak; two real finds
> in the UX surface (an argv-forensics walk that mis-descends on
> the two-token `--color-mode` form, and a help synopsis that
> drifted off the live parse surface at flag level) — both closed
> with fixes and new pins in this audit's own commits.

## 1. The mandate

The owner's ask: depth-audit the killer features, then the UX, then
the rest — total LTS, honest. Three deep dives, five areas each:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash over the limiter and the monitor | line-by-line reads of the enforcement math (math.rs, DRR, AMMSP, the datapath program) and the render tree; the full test battery fresh (650 + 47 / 0 failed after the closes) |
| 2 | Code hygiene across the killer-feature dirs | the render-tree zombie census (manual call-graph), the CLI zombie census (every flag invoked live), the stale-comment hunt (the argv walk's own comment was the find) |
| 3 | Optimization of the hot paths | the per-packet arithmetic read for the kernel side (the fill-detect bound, the saturating DRR family); the full-budget frame-bench fresh after the closes — bytes/frame byte-exact at 1,919.0 |
| 4 | Security hardening at the feature surfaces | the kernel-side trust-boundary chain re-read (the pol_sane clamp before any math, the per-socket cookie-0 fallback, the group-lane degradation); the rate parser's live edge-case battery (20+ hostile inputs, all u128-checked) |
| 5 | LTS stability of the feature contracts | the pin batteries extended (three argv-walk pins, one flag-level help pin — 647 -> 650 unit, 46 -> 47 integration); the gate sequencing seam found and closed |

## 2. The limiter engine — SOUND, read to the metal

The per-packet core, read line by line:

- **The token-bucket math (ebpf/src/math.rs, 617 lines).** The
  SMP-safe window ownership (one CPU credits [last, now] through a
  CAS; the loser's window is a subset — each nanosecond paid once);
  the stall-fountain close (now < last within 1 s skips, beyond 1 s
  heals with no credit — the clock-skew hammer's own find, fenced);
  the clamp family (seeded tokens above burst, the post-add cap,
  the frac_rem < NS_PER_SEC sanitize — each hostile stored field
  clamped to the healthy value the math itself would store).
- **The overflow chain, verified end to end.**
  `MAX_ENFORCABLE_BURST = u64::MAX / (2 * NS_PER_SEC)` bounds the
  fill-detect multiply; the kernel datapath clamps `burst_bytes`
  to it BEFORE any arithmetic runs (bin/limiter.rs, the pol_sane
  gate — a hostile map write meets the bound before the math);
  `refill_credits`' exact branch only executes while
  `elapsed < fill_ns`, which bounds `elapsed * rate_bps` by
  2 *burst* NS_PER_SEC by construction — bounds, not checks, the
  documented math.rs discipline. `elapsed` itself is capped at 1 s
  and `saturating_sub`'d against the last stamp.
- **The consume path.** `try_consume`'s four written-out CAS
  attempts (never looped — the verifier posture) with the
  never-over-allow invariant per attempt; a fully lost consume
  drops (the safe verdict), and a fetch_sub-and-revert shape was
  rejected in the design docs precisely because its transient
  underflow would hand a concurrent clamp a huge value to misread.
- **DRR (drr.rs + drr_flow.rs, 1092 lines).** Const-fn pure
  arithmetic, every cap saturating, the u12 field ceilings packed
  with saturating ops, epoch deltas via `wrapping_sub` (correct
  for modulo arithmetic), the ledger room overflow-free by
  construction — the math.rs fill_ns discipline, applied again.
- **AMMSP (ammsp.rs + ammsp_resolve.rs, 466 lines).** The memo
  word `(generation << 32) | root` — u32 fields into u64, no
  packing overflow possible; the one-map-per-direction split and
  the generational retire ride the schema pins.
- **The datapath program (bin/limiter.rs, 793 lines).** The
  pol_sane clamp; the per-socket lane's cookie-0 fallback to the
  cgroup's shared DRR budget (never an unlimited pass — the
  attribution gap stays policed); the group lane's
  map-full degradation to the individual bucket at the group's
  rate (over-admission against the shared-bucket intent, never
  the unlimited fail-open it replaced — the belt behind the
  userspace reclaim).

Peak-skips honored: the lts-8 retry calibration (28x), the
boost-38 SMP rewrite, the security-3 clamp family, the Z1
single-direction bypass fix, the Z6 law arithmetic audit — all
re-verified by reading, none re-performed.

## 3. The eagle-eyes monitor — SOUND, the ladder re-proven

The dedicated render-tree read (all 15 files of src/ebpf/render/
plus the command wiring, ~5,300 LOC) re-verified the render
totality ladder **line by line with zero counterexamples**: every
subtraction site sits under its own guard (the census in the
agent's report names each — eagle.rs's six saturating sites and
the board-length guard, focus.rs's clear-at-zero, baseline.rs's
hidden-row guard, border.rs's pad-under-width, width.rs's
w==0 early return, report.rs's zero-arrival guard before the
division). Zero live panic candidates, zero zombie code (the
manual call-graph confirms every render function transitively
reachable), zero integer truncation in the layout math (u16
geometry widens to usize at the probe boundary).

One LOW cosmetic observation, filed for the owner's decision
only: the title bar's degenerate-branch pass-through — on
terminals narrower than the prefix+core (~≤23 cols ranked,
~≤44-47 focus, label-length dependent), row 0 over-wraps and
shifts the sequential emission's alignment. No panic; the
identity-over-geometry intent is pinned in the tree
(`title_bar` keeps the full core); the narrow-width frame shape
is unpinned end-to-end (the width pins run at 80 cols). The
options — fit row 0 in wrap() or pin the narrow-title shape —
are a design call, not a defect; the audit records the seam and
does not engineer it unprompted.

## 4. The UX surface — two finds, both closed live

**Find 1 (24f2bc5 + the bc9c8a0 fmt rider): the argv-forensics
walk mis-descends on the two-token `--color-mode` form.** The
walk's own comment still asserted every top-level flag is boolean
— an invariant that died the day `--color-mode <MODE>` (boost-23)
became the sole value-taker, and nothing re-audited the walk
against it. Reproduced live A/B on the same binary: the `=-form`
rendered the correct strict-single usage while the space form
rendered the ROOT usage (the bare MODE value token was mistaken
for the subcommand candidate), and the worst shape — a MODE
value that names a real subcommand — rendered a usage line for a
command the parser never entered (`--color-mode status ss ...`
answered "Usage: zelynic status"). Exit code, error text, and
suggestion tip were correct on every shape; only the regenerated
usage line lied. The close: the walk now consumes the two-token
form's value exactly the way the parser does (a pending-value
state that eats the next bare token, including one that names a
real subcommand), the stale comment now names --color-mode as
the documented sole exception, and three pins join the argv
battery (the space-form descent, the value-that-names-a-command
shape, the =-form control). The usage-line surface pins stayed
byte-identical on every previously-pinned shape.

**Find 2 (2c617d1): the curated --help drifted off the live
parse surface at flag level.** `--per-socket` and `--no-probe`
parse, are USAGE.md-documented, and are argv-pinned — but the
in-binary help never mentioned either: the per-socket lane (the
server shape) had no in-binary discovery path, and the doc was
ahead of the help (USAGE.md's synopsis already carried
`[--per-socket]`). The close: the synopsis now matches the doc
token for token, the block documents both flags in the help's
own voice, a per-connection-cap example joins the list, and a
flag-level completeness pin joins help_pins — the existing pins
fenced command/alias/group completeness; flag completeness was
the exact gap this find rode.

The rate parser's hostile-input battery (20+ edge cases run
live: empty, 0, fractional-below-min, 22-digit overflow,
unicode digits, case-twins, trailing garbage, signs, inner
whitespace, 41-decimal fractions) — every row checked u128
arithmetic with no silent acceptance, no truncation, no panic,
each rejection carrying its tip. The suggestion engine's Jaro
math guards every division; the retired-surface redirects all
fire live. Zero zombie flags.

## 5. Optimization — PEAK, the bench re-anchored post-change

The fresh full-budget frame-bench after this audit's own code
commits (the strongest no-regression proof an audit can run —
its own changes in the build):

| Metric | Post-close (this audit) | Pre-close baseline | Reading |
|--------|------------------------|--------------------|---------|
| fps (render path) | 7,125.6 | 7,077.9 | in class (host noise) |
| bytes/frame | 1,919.0 | 1,919.0 | **byte-exact** — the render path untouched by the closes |
| emit bytes/frame | 512.4 | 512.3 | in class |
| dirty cells/frame | 40.1 | 40.0 | in class |
| density gini | 0.3501 | 0.3502 | in class |
| frame entropy | 3.0275 | 3.0287 | in class |

The kernel side stays byte-pinned with no performance reason to
touch it (every commit's parity gate re-proved it). The closes
touch the CLI error path and the help text — not the frame path —
and the byte-exact bytes/frame is the measurement that proves it.

## 6. Security hardening — the feature surfaces re-read

- The kernel trust-boundary chain: pol_sane clamps hostile
  policy fields before any math; cookie-0 packets stay policed at
  the cgroup lane; the group-lane degradation never fails open.
- The rate parser: all hostile inputs rejected with tips, all
  arithmetic u128-checked (the 22-digit overflow, the
  sub-byte-rounding case, the mantissa precision bound).
- The argv surface: non-UTF-8 rejected by clap; the new walk
  logic adds no indexing (a pending-value boolean, no slice
  arithmetic).
- Peak-skips honored: the sanitize_comm boundary, the exec-site
  trio, the pin namespace finiteness — lts-2's rows re-read where
  the feature dives touched them, all holding.

## 7. LTS stability — the seam the audit itself hit

The closes extended every fence they touched: 647 -> 650 unit
pins, 46 -> 47 integration pins, all green. The full battery
after the closes: 650 + 47 passed / 0 failed / 1 + 3 ignored;
check-all -q all green; gate-keepers 22/22.

One process seam, found by this audit's own final gate run and
closed on the spot: the lts-2 audit report shipped with working-
tree mode 664 (the sandbox umask) — the lts-2 permission gate
had run before the file was git-tracked, so the gate never saw
it; this audit's post-commit run caught it and the gate's own
--fix restored the 644 contract. No git-state impact (git tracks
only the exec bit); the seam is recorded here because the next
auditor on a umask-002 host will hit it the same way, and
because it is the honest answer to "why did a green gate leave a
red file": the gate's own header claims untracked files are
included — the lts-2 sequence (gate, then write, then commit)
skipped past it. The lts-3 sequence (write, gate, commit,
re-gate) does not.

## 8. The verdict table

| Area | Verdict | The one-line evidence |
|------|---------|----------------------|
| 1. Stability & crash | SOUND | the limiter math read to the metal (window CAS, clamp family, fill-detect bound); the render ladder zero counterexamples; 650+47 fresh; bytes/frame byte-exact post-close |
| 2. Code hygiene | two finds, both closed | the argv walk's stale boolean-only assumption and the help's flag-level drift — fixed with pins; the render and CLI zombie censuses clean |
| 3. Optimization | PEAK (skip) | the exact-branch product bounded by construction (no check overhead to remove); frame-bench byte-exact after the audit's own changes |
| 4. Security hardening | SOUND | the kernel clamp chain re-read; the rate parser's hostile battery all-reject; the new walk logic adds no new surface |
| 5. LTS stability | SOUND + one seam closed | pins extended on every touched fence; the gate-then-write sequencing seam documented and the mode restored |

## 9. This audit's own honest residuals

- Live eBPF stress still rides the CI legs (kernel 5.10 host,
  rootless): the pushes carrying the three closes are the next
  live verdicts — the enforcement object is byte-pinned through
  all of them (the commit gate re-proved parity per commit).
- The title-bar narrow-width seam (Section 3) is recorded for the
  owner; this audit deliberately does not choose between the two
  closes (fit row 0 vs pin the narrow shape) — a repo at peak
  takes design calls from its owner, not its auditor.
  [CLOSED by NIGHT-improve-36: the owner chose the fit-row-0 close.
  The bar now ALWAYS lands on exactly `width` columns — the core
  truncates with an ellipsis (the same fit_to_width contract every
  label carries) before the bar overflows, so row 0 never wraps and
  never shifts the rows below. At the pinned widths (80, 40) the
  output is byte-identical to the former path; the change only
  touches the narrow tail. A width-ladder pin (0..=80) locks the
  contract.]
- The 3-b render agent's footer micro-observation (the
  unresolved-identity arm builds `label_with_count` up to twice
  per frame) is already frozen into the 1919.0 bench figure —
  removing it would change bytes/frame for zero visible gain,
  the exact trade the byte-parity discipline exists to refuse.
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
