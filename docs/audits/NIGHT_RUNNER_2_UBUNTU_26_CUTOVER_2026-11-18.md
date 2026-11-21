<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The night-runner-2 record — the fleet cuts over to Ubuntu 26.04

> Task date: 2026-11-18 (night-runner-2), the same seat as
> night-runner-1 and the day before the #14748 migration window
> closes. Scope: the second half of hunt-26's documented path —
> the cutover of every runner label in the 17-workflow fleet to
> the ubuntu-26.04 family, gated on the phase-1 probe's real CI
> verdict. Method: the probe's green check runs read first from
> the API, then the census re-derived from the YAML (never from
> memory), then the edits in the runner-1 record's own phase-2
> order (labels, then words, then docs), then the wholesale
> battery re-run in this seat. Honesty note: the cutover push's
> own end-to-end verdict was left "pending this push" in §6 until
> its check runs filled it — the fill landed only after the
> evidence existed (the runner-3 seat); this record never speaks
> a green verdict before the evidence exists.

## 1. The census (from the YAML, after the edits)

- 35 runs-on sites, all on the 26.04 family: 30 plain x64 pins
  swapped `ubuntu-24.04` → `ubuntu-26.04` (audit, codeql, crates-io
  ×2, fuzz, gate-keepers, maintenance ×3, miri, netrunner-night-c77
  ×2, proofs-night, proofs ×3, release ×3, supermassive-container
  ×4, supermassive-e2e stage, supermassive-server,
  supermassive-verify, supermassive ×3, ci musl twin), 2 arm pins
  swapped to `ubuntu-26.04-arm` (ci musl-arm64, supermassive-e2e
  stage-arm64), 1 arm64 ternary swapped (supermassive-e2e shards:
  `'ubuntu-26.04-arm' || 'ubuntu-26.04'`), and the 2 matrix arrays
  collapsed to `os: [ubuntu-26.04]` (ci musl twin + eBPF host, per
  blade-3's latest-LTS-only rule — the probe leg earned the whole
  fleet and the floor leg retires with the cutover).
- Zero `ubuntu-latest`, zero non-26.04 hosted labels. The swap
  script verified the counts per file (30 exactly) and verified
  zero plain 24.04 label lines remain anywhere in the YAML.

## 2. The gate that allowed the cutover (probe green in real CI)

The phase-1 probe legs ran on the runner-1 push's own ledger
(42 check runs on 7bc37653): `Musl Static Twin (ubuntu-26.04)` and
`eBPF Host (ubuntu-26.04)` both concluded success in real CI —
the estate's two heaviest compile surfaces (the full musl static
graph with clippy, tests, the debug gate and the pro verification;
the eBPF object graph and its host tests) compiled and passed on
kernel 7.0 / new glibc / new python, not as a smoke test but at
the full job shapes and caps. That is the evidence the cutover
gate demands; runner-1's record §6 rows carry the fill.

## 3. The words follow the fleet (words-behind-the-tree law)

Every present-tense runner claim refreshed in the same commit:

- The four hunt-26 pin-rationale blocks (audit.yml, codeql.yml,
  release.yml validate, maintenance.yml validate): "pinned to
  ubuntu-24.04 ... migrates on 2026-10-19" → "pinned to
  ubuntu-26.04 ... migrated across 2026-10-19 -> 2026-11-19; this
  fleet moved first, matrix-tested (night-runner-1/2), and OS
  upgrades here stay deliberate, matrix-tested changes."
- supermassive.yml's LTS note: the runner rides the latest LTS
  "(ubuntu-24.04 at blade-3, ubuntu-26.04 since night-runner-2's
  fleet cutover — pinned, never a floating label)" — blade-3's
  history kept, the present tense honest.
- The b3sum apt notes (release.yml, gate-keepers.yml,
  supermassive.yml): "Ubuntu 24.04 ships the b3sum package" →
  "Ubuntu 26.04 ships..." — the cargo fallback sentence unchanged
  (it guards exactly the package-drift class the note describes).
- supermassive-verify.yml's runner description: "A GitHub
  ubuntu-26.04 runner is already root-capable, kernel 7.0,
  cgroup v2 unified, /sys/fs/bpf mounted" (was 24.04 / 6.x-7.x).
- The arm64 comments (ci.yml's musl-arm64 proof leg,
  supermassive-e2e.yml's arm64 variant): labels → 26.04-arm.
- ci.yml's blade-3 sentence: "the runner rides the latest LTS
  only (ubuntu-26.04 since night-runner-2)".
- The two matrix comment blocks (musl twin, eBPF host): the
  runner-1 probe rationale replaced by the runner-2 cutover
  rationale — the probe's evidence named, the retirement's rule
  named, the 14748 retirement named, the one-line-away shape kept.

## 4. What stays, named (the non-runner 24.04 surfaces)

- supermassive-server.yml's `ubuntu-24.04-server-cloudimg-amd64.img`
  (the frozen release-20261017 snapshot, SHA-512 verified): a QEMU
  GUEST image, the deliberate pinned guest — not a runner label.
- The jammy 5.15.0 floor kernel debs and the latest-head resolver
  (supermassive/e2e): guest kernels inside the VM pair.
- The ubuntu:22.04 rootfs container and the `SUITE=ubuntu:24.04`
  / `ubuntu:22.04` container pins (supermassive, e2e, netrunner):
  guest userlands, the improve-31 contract.
- The dated/historical sentences that name 24.04 in past-tense or
  frozen-record shape (supermassive.yml's "one era" envelope
  constants and the gnu legs' same-distro rootfs history,
  test/ebpf/limiter/math_smp_tests.rs's 2026-09-25 evidence line,
  CROSS_DISTRO_RESULTS.md's addenda, the archived changelog eras):
  frozen records keep the language of their time.
- README's "a real Ubuntu Server 24.04 CI leg" sentence verified
  still true post-cutover: it names the SERVER lane, whose guest
  image stays 24.04 by design — the sentence was never about the
  runner fleet.
- docs/KERNEL_COMPATIBILITY.md follows the fleet: the distro table
  gains the Ubuntu 26.04 LTS / 7.0 Build-verified row (the CI
  build matrix host since night-runner-2) and keeps 24.04 as a
  "Retired from CI" row (the 21.10-RETIRED row's pattern); the
  kernel checklist's 6.8 item stops claiming the build matrix
  (moved to 26.04's 7.0), no runtime record invented.

## 5. Peak-skips and rejections, with reasons

- NOT keeping a permanent 24.04 matrix leg: blade-3's
  latest-LTS-only rule stands; the kernel span is the supermassive
  VM pair's contract and a duplicate hosted leg buys
  runner-minutes, not coverage (runner-1's record §5, restated
  as the binding rule at cutover time).
- NOT touching the supermassive-server guest image, the jammy
  floor, the 22.04 rootfs, or the SUITE containers: the deliberate
  old-OS surfaces are the point of those tests (guest internals,
  not runner choices).
- NOT refreshing the dated records: frozen history keeps its
  language; only present-tense claims follow the fleet.
- NOT adopting `ubuntu-latest` anywhere: the floating label is the
  estate's anti-lottery contract (hunt-26); determinism beats
  convenience, the LTS move is made deliberately once per LTS.
- NOT changing timeouts/caps/concurrency/permissions: the job
  shapes are unchanged; the label swap is the whole behavioral
  surface, and the wholesale battery re-proved the YAML estate
  (35 jobs capped, permissions, concurrency, the schedule estate)
  in this seat.

## 6. The evidence ledger (filled as the phases land)

| Claim | Evidence | Verdict |
|---|---|---|
| The probe gate | Musl Static Twin (ubuntu-26.04) and eBPF Host (ubuntu-26.04) both success on the runner-1 push's 42-check-run ledger (7bc37653), read from the API in this seat | GREEN |
| 30 plain x64 pins swapped, per-file counts exact | the swap script's own output (30/30, zero leftovers), re-derived by the YAML census | in tree |
| 2 arm pins + ternary + 2 arrays on the 26.04 family | the YAML census: zero non-26.04 hosted labels, zero `ubuntu-latest` | in tree |
| The words follow the fleet | §3's list, every edit reviewed in-place; zero present-tense 24.04 runner claims left in workflows (the census rg) | in tree |
| Guests and dated records untouched | §4's list; `ubuntu-24.04` remains only in guest pins and frozen/past-tense records | in tree |
| Local gates on the cutover tree | the wholesale battery re-run in this seat | pending this commit |
| The fleet green on 26.04 end to end | the cutover push's own check runs | pending this push |

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
