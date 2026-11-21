<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-fly-1 — the CI speed law lands (the 15-minute ceiling, the schedule ban) and the stale sweep rides with it

Date: 2026-11-22. Session scope: the owner's estate law — no CI run
past 15 minutes, no schedule on a test lane (every test is
trigger-by-commit on main; only maintenance- and publish-critical
lanes keep a clock) — enforced with measurements, plus the stale-doc
sweep the owner's own terminal proof demanded (the GPG expected
output names the primary UID the key actually signs with).

## The law, and the number that proves it was needed

The owner's words: heavy CI (kani/loom, supermassive) running past 15
minutes, hanging or stuck for 30-60, is fatal for the owner; every
lane must be micro-split so it stays fast; the exception is
maintenance-critical CI (release, crates.io, publish) which may keep
its schedule.

The estate already had the fatal shape on tape: the nightly kani
solver-bound tier's single scheduled fire (run 44896512098,
2026-11-21) burned its full 300-minute cap and died CANCELLED with
not one solver verdict printed — 300.6 minutes of runner for zero
findings. No cap change can fix a tier whose slowest harness cannot
decide inside any sane window; the tier retired (see Find 1).

## Find 1: the solver-bound night tier retires (the vehicle failed by measurement)

proofs-night.yml carried four one-harness matrix jobs at
`timeout-minutes: 300` on a daily cron. The measurement chain, whole:
the local census measured the harnesses unfinished at ten minutes and
undecided under bitwuzla/cvc5/z3; the hosted per-push attempt was
cancelled at 59m44s still inside its first harness; and the nightly
vehicle's one and only scheduled fire burned the full 300 and was
cancelled with zero verdicts. A budget the ceiling can never afford
is not a verdict vehicle — under the new law it is not even a legal
one. The workflow is deleted; the four theorem statements stay wired
in the proofs sources (census-recorded, not lost); the per-push
conformance evidence rides the sampled property tier, the loom
census, the golden vectors, and the six decidable kani theorems. The
named levers that bring the tier back: lemma decomposition, or
per-loop unwinds on a toolchain that carries them — a proof-shape
change with its own signed round, then a matrix of one-harness jobs
inside 15 minutes. proofs.yml's header, INNOVATIONS.md's proof-layer
section, and CLAIMS_VERIFICATION.md's proof row carry the record.

## Find 2: the schedule ban lands (five clocks retired, one lane converted)

The NIGHT-improve-9 "one clock for every scheduled workflow" design
(daily 03:07 UTC slots, weekly Monday/Sunday variants) is retired for
every test lane. The trigger census after the sweep:

- audit.yml, codeql.yml, fuzz.yml, miri.yml: `schedule:` removed;
  push + pull_request stay unfiltered (dispatch where it existed).
- supermassive-verify.yml: schedule removed, `push:` ADDED — the
  privileged verify lane joins the per-push estate. The move is
  measured, not hopeful: its single hosted scheduled fire (run
  44896405423, 2026-11-21) completed green in 7.2 minutes wall, so
  the lane fits the ceiling with doubled headroom and every push now
  gets the live runtime verification instead of a daily slot.
- fuzz.yml's weekly deep session (900s/target) moved to the dispatch
  button's `deep` input at 600s/target — the 900s shape plus setup
  could not legally fit the 15-minute ceiling; 600s plus setup does.
- The exempt set keeps its clocks by the law's own language:
  maintenance.yml (the Monday dependency sweep),
  reproducible.yml (the D4 publish-provenance re-check).

## Find 3: every test-class cap sits at or under the ceiling

The caps were stale law — build jobs at 30-40 minutes, the
supermassive family at 20-40, all against hosted measurements far
below. The re-cap line (cap -> measured basis, latest green run):

- ci.yml: check 40 -> 15 (3.4m), musl 40 -> 15 (3.7m), musl-arm64
  40 -> 10 (1.9m), ebpf-host 30 -> 10 (1.6m).
- supermassive.yml: stage 20 -> 10 (3.9m), supermassive 15 -> 10
  (all shards <= 4.0m), supermassive-desktop 40 -> 15 (12.9m peak).
- supermassive-container.yml: docker 25 -> 10 (2.0m), iface 20 -> 10
  (1.4m), k8s 30 -> 10 (2.8m), netns 20 -> 10 (1.7m).
- supermassive-e2e.yml: stage 22 -> 10 (3.3m), e2e 12 -> 10
  (<= 4.2m); stage-arm64 already at 10.
- supermassive-server.yml: server-e2e 15 -> 10 (2.4m).
- netrunner-night-c77.yml: stage 20 -> 10 (1.8m),
  critical-simulation 20 -> 10 (1.6m).
- audit 15 -> 10 (4.5-5.7m), codeql 45 -> 10 (4.5-5.4m), fuzz
  35 -> 15 (hosts the deep shape), miri 40 -> 15 (5.8-10.6m hosted
  record), supermassive-verify 60 -> 15 (7.2m).
- proofs.yml's three seats keep their 15 (kani cold-bundle variance).
- release.yml (30), reproducible.yml (30), maintenance.yml (45),
  crates-io.yml (40/30) keep their caps in the exempt set.

No step, pin, or scan shape moved anywhere — this pass changed
triggers, caps, and the words that describe them.

## The gate: three laws, one check

`scripts/gates/check-timeout-caps.py` now enforces the whole law:
every job declares a cap; no cap below the 10-minute floor; no cap
above the 15-minute ceiling outside the exempt set; and a
`schedule:` trigger may appear only in the exempt set. Proven both
ways in-session: the tree passes green, a planted 20-minute cap
fails loudly naming the file:job. docs/RULES.md's "CI Runtime Caps"
section carries the law text with the evidence.

## The stale sweep (the owner's terminal proof, and the doctrine refs)

The owner pasted the real hosted gpg output: the signature names the
primary UID first — `rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>` —
with the cosmic-dragon identity riding the aka line. The stale
surface was the release-notes generator itself (one implementation
for every release body): its Expected line told readers to look for
the second UID. Fixed in the generator, in docs/VERIFY_RELEASE.md
(both UIDs in keyserver order; the expected-output block now the
verbatim two-line shape), and in docs/BRANDING.md's protected
key-data bullet. The schedule-doctrine prose the de-scheduling made
stale (MAINTENANCE.md's guard table, CROSS_DISTRO_RESULTS.md's
verify-lane gate note, DEPENDENCY_AUDIT.md's Monday clock, the two
scripts' shard comments) updated in the same sweep. Historical
records (CHANGELOG, audits, research docs) keep their era-true text:
history is not instruction.

## Verification ledger

- Workflow YAML: all 17 files parse; actionlint green (exit 0).
- Caps gate: 37 jobs, floor-clean, ceiling-clean outside the exempt
  set, no schedule on a test lane; negative probe red as designed.
- The generator's pinned self-test battery green after the Expected
  edit (and the tab-discipline restore ride-along commit).
- The cap basis: every new cap's measured actual printed from the
  hosted run's own job timings (the API record, not estimates).

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
