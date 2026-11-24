<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The night-zen-lts-Z-1 audit — the all-infra pass at the post-speed-law estate

> Audit date: 2026-11-24 (night-zen-lts-Z-1). Scope: all
> infrastructure — the workflow estate, the trigger and cap surface,
> the supply-chain doors, the ledger and parity instruments, the
> scripts tree, and the newest infra deltas (the Z17 proofs matrix,
> the verifier-budget ledger raise, the prebuilt lane's third
> regeneration) — audited at c3bbc58 plus the hardening-5 commits.
> Method: the estate re-censused from the YAML (never remembered),
> the trigger and pin laws grepped live, the tip's own CI verdicts
> read from the runs API and the job logs (13/13 green on the tip,
> zero in-flight runs repo-wide), the ledger's self-test run
> rootless. The honest boundary, stated once: no root, no KVM in the
> seat — the runner-side legs are read from CI's records, and the
> REST API worked under the seat's token (the split the 2026-11-18
> pass met was seat-specific, not a repo defect).

## 1. The workflow estate, censused live

- **17 workflows, 17/17 top-level `permissions:` blocks, 17/17
  `concurrency:` groups** — counted from the tree, matching the
  2026-11-18 census's shape with proofs-night.yml deleted (the FLY_1
  retirement) and the estate otherwise stable.
- **The trigger surface post-schedule-ban**: 13 push-triggered lanes
  (the tip's run set — CI, CodeQL, Gate-keepers, Miri, Security
  Audit, the four Supermassive lanes, C77, Fuzz, Proofs),
  2 scheduled lanes in the exempt set (maintenance.yml
  `0 3 * * 0`, reproducible.yml `37 3 * * 1` — publish- and
  maintenance-critical per the speed law's own language),
  2 release-triggered (release.yml, crates-io.yml). The retired
  `7 3 * * dow` clock appears only inside dated audit records —
  correctly historical.
- **The cap law holds**: 23 jobs at 10 minutes, 9 at 15 (the kani
  seats' cold-bundle variance allowance), the exempt set carrying
  its 30/40/45 — every test-class job at or under the 15-minute
  ceiling, the runtime-caps gate enforcing cap + floor + schedule
  shape in one check.
- **The SHA-pin law holds**: every `uses:` pinned to a commit SHA
  except the three codeql-action lines (init/autobuild/analyze on
  the moving tag) — the exception the codeql.yml comment itself
  documents as the scanner's value.

## 2. The newest infra deltas, verified

- **The proofs.yml 26-seat kani matrix** (6 Z6 + 6 Z12 + 14 Z17: the
  three fidelity pins, the eleven preservation theorems, the shipped
  and quiet belt seats one matrix job each) — the matrix list counted
  at the YAML, the Proofs lane green on the tip, every seat inside
  the 15-minute ceiling (the census's own sweep timings, 1.6-104.4 s
  hosted, wide margin).
- **The verifier-budget ledger raise** (the Z17 +88 dl, run
  45370360921) and **the hardening-5 ratchet** (ul to 132960, run
  45374359811): both rows carry kind/value/source/reason per the
  growth and ratchet laws; the rootless self-test green on the
  edited ledger (6 programs); the tip's verifier-budget job measured
  the pair and passed — "exactly at the pin" on dl, "60 under" on ul
  pre-ratchet, both read from the job's log.
- **The prebuilt lane's third regeneration** (the hardening-5
  comment sync): the tree pin counts comments by design; the refresh
  went through the one writer; the section-level byte-identity proof
  (code and .BTF identical, only DWARF line-info moved) rides the
  task-2 commit; the parity gate green after.

## 3. The finds — one, already fixed; the rest held

The stale-reference sweep over the walk-cost surface found the
enforce_helpers.rs present-tense pair (the hardening-5 find 1) —
fixed by that session's task 2 and recorded there. Beyond it:

- The 03:07-era schedule mentions: every remaining hit sits in a
  dated audit record (ZEN_LTS_2:43, FLY_1:54, SOLID_DEFENSE_1:174)
  — frozen-history class, no edit.
- The CHANGELOG's 141893 rows (the Z14/Z15 ratchet history at
  :193-197 and :246-250): dated records, correct as written.
- The dependency chain (6 direct, 51 root crates, zero git deps,
  zero [patch] sections, the four lockfiles' advisory scans green on
  the tip, the 14-ban deny wall intact): PEAK, nothing to trim.
- The docs index coverage (both halves gate-enforced: every tracked
  audits/ doc and every docs-tree page carries its row): PEAK — and
  this record and its two siblings ride the same gate (their index
  rows landed in the same change).
- The secrets posture (runtime-only token resolution, no standing
  secret in the tree, `persist-credentials: false` on checkouts):
  PEAK.

## 4. The verdict table

| Area | Verdict | Note |
|---|---|---|
| Workflow estate shape | PEAK | 17/17/17, triggers post-ban, caps lawful, pins SHA (one documented exception) |
| Z17-era infra deltas | GREEN, live | the 26-seat matrix, the ledger raise + ratchet, the third lane refresh |
| Ledger instruments | GREEN, live | self-test rootless, growth + ratchet laws followed, CI census agreeing |
| Stale references | 1 FOUND, FIXED | the walk-cost comment (hardening-5 task 2) |
| Dependency chain | PEAK | 6 direct / 51 crates / zero git / zero patch |
| Docs index | PEAK | gate-enforced both halves |
| Supply chain doors | GREEN, live | scans, deny, D4/D2 stamps, SHA pins |
| Scripts tree | PEAK | the quad + ruff + codespell green in CI's battery |

The infra estate holds the masterclass bar: the only find of the
pass was the documented stale-reference class, fixed in its own
commit with the byte-identity proof attached, and every instrument
this seat can run ran green.

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
