<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-maintenance-2 audit — the CI depth, kernel-span, and from-source pass

> Audit date: 2026-10-27 (night-dragon-maintenance-2). Scope: the
> owner's three asks — (1) the ultimate real CI function: an
> end-to-end realtime depth stresstest of every existing CLI surface
> in real user and root modes across the kernel span, (2) the
> masterclass trigger simplification: every CI lane unfiltered, the
> publish lanes alone keeping their dedicated v* tag trigger, and
> (3) the depth audit for missing low-spec test coverage at the
> documented minimum kernel, real KVM, not blind. Audited at
> 448dc21 (v80.0.0-beta.1 era). Method: the whole workflow estate's
> trigger blocks extracted and diffed against the sibling's mature
> shape; every depth suite's CI execution references swept with
> evidence; every CI build payload's provenance walked against the
> from-source law; the kernel floor cross-checked across the four
> independent docs that state it.

## 1. The mandate

Three asks, one theme: the CI estate should prove what the owner
actually bought — the whole CLI surface, in the modes the tool
really runs in (unprivileged user AND root), on the kernels the
compatibility docs really promise (5.13 floor through the moving
latest) — and the estate should be simple enough that maintaining
it costs less than running it. The sibling project's CI estate
(the mature reference) already carries the shape: unfiltered
push/pull_request triggers everywhere, the publish lanes on their
dedicated v* tags, the E2E surface lane and the kernel-floor
micro-VM lane as separate contracts. This audit walked zelynic's
estate against that shape and recorded every gap honestly before
closing it.

## 2. The trigger audit (ask 2)

Every workflow's `on:` block extracted and classified:

| Workflow | Before | After |
|----------|--------|-------|
| ci.yml | push/PR filtered: branches + six surface globs + self-file | push/PR unfiltered |
| audit.yml | push/PR filtered: branches + toml/lockfile globs + self-file; weekly cron | push/PR unfiltered; weekly cron kept |
| codeql.yml | push/PR filtered: branches + scanner-edition globs + self-file; weekly cron | push/PR unfiltered; weekly cron kept |
| miri.yml | push/PR filtered: branches + six surface globs + self-file; Sunday cron | push/PR unfiltered; Sunday cron kept |
| gate-keepers.yml | push/PR branch-pinned (main only) | push/PR unfiltered (any branch, any tag) |
| supermassive.yml | push filtered: branches + six surface globs + self-file; dispatch | push/PR unfiltered; dispatch kept |
| supermassive-container.yml | push/PR filtered: branches + six surface globs + self-file | push/PR unfiltered |
| crates-io.yml | push tags v* | UNCHANGED — already the dedicated publish trigger |
| release.yml | push tags v* + dispatch | UNCHANGED — already the dedicated publish trigger |
| maintenance.yml | weekly cron + dispatch | UNCHANGED — a clock lane, nothing to filter |

The lineage that produced the filters is kept as the honest record
in the rewritten headers (improve-13's native-paths gate, boost-9's
one-glob law, boost-10's estate spelling): each step shrank the
drift tax, and the tax never reached zero — the spelling had to
stay synchronized across seven workflows, every new consumer
needed a manual glob audit, and the sync cost outgrew the runner
minutes the filter saved. The deliberate exceptions stay exactly
as the owner set them: a publish is the owner's deliberate act,
never a consequence of an arbitrary change (the v* lanes), and the
clock lanes watch external state (the advisory DB, the moving
nightly), not the tree.

Verified: yamllint (repo config) and actionlint clean on all ten
workflows; no `paths:` or `branches:` key remains under any
`on:` block (scripted sweep, not a spot check).

## 3. The kernel-floor audit (ask 3)

The documented floor is 5.13, stated independently in four places:
KERNEL_COMPATIBILITY.md ("5.13 is the oldest kernel in the verified
matrix"), LONGEVITY.md ("The kernel floor is 5.13+"), the
architecture doc ("kernel >= 5.13"), and the README requirements
row. The supermassive lane was NOT blind to it: its low-specs legs
boot the TRUE floor kernel (the impish indri resolver, the frozen
old-releases archive, the last 5.13.0 ABI the pocket carries) on
every push, and its best-specs legs boot the archive's dynamically
resolved latest — the full span, real KVM, per push. The floor
verdict inside the guest is numeric (uname -r major.minor >= 5.13),
so both ends of the span pass the same check.

One stale claim found and fixed on the way: the README's CI
paragraph claimed "the 5.15 floor lane" — a floor that no doc
states and no lane boots. Fixed to 5.13 with the lane description
that actually exists.

The one lane the sibling carries that zelynic does not: the
kernel-witnesses span lane (a below-floor boot proving the live
refusal direction on a real sub-5.13 kernel, plus pinned above-floor
GA witnesses). Recorded as an owner-call candidate, not built this
round — the at-floor direction is already proven strict per push,
the above-floor direction rides the dynamic-latest leg and the
runner-kernel lanes, and the refusal direction below the floor is
pinned by the loader's version gate plus the span verdict family
inside limiter-depth-test. The honest cost of the witness lane is a
fourth KVM lane plus a second frozen-mirror dependency (focal GA
5.4) for a direction no user can reach through supported install
paths.

## 4. The low-spec test-specs audit (asks 1 + 3, the central finding)

The execution-reference sweep (grep for call sites across the
workflow estate, scripts/ci, build.sh, gate-keepers.sh) found the
gap the task predicted: five depth suites with ZERO CI execution
wiring — they existed only as owner-local commands:

| Suite | Contract | CI wiring before |
|-------|----------|------------------|
| scripts/depth/nonroot-depth-test.sh | the FULL command surface as an unprivileged user: refusal ladder, fail-fast validation, no-panic edges; refuses euid 0 by design | none |
| scripts/depth/limiter-depth-test.sh | the realtime depth stresstest: measured rate verdicts cross-checked against the BPF counters, the kernel-span verdict family | none |
| scripts/depth/endurance-test.sh | the LTS clocks amplified: map-slot churn through the caps (any leak exhausts and fails loudly) + the monitor pty soak | none |
| scripts/sandbox/smoke-cli.sh | the whole CLI surface battery as root: every verb, every guard, real policing, leak postconditions | none (local sandbox lane only) |
| scripts/depth/install-flow-test.sh | the install/uninstall lifecycle as root, real package scripts, artifact postconditions | none |

Meanwhile the runner-kernel lanes (ci.yml) proved compile-and-battery
health, and the supermassive lane proved the limiter matrix and the
engine batteries on the kernel span — but the per-surface E2E depth
had no lane at all. The new supermassive-e2e lane closes it: two KVM
micro-VM legs (the 5.13 floor kernel; the archive's dynamically
resolved latest), each running the identical five-suite battery at
identical depth — the USER leg first (setpriv to nobody; the rig's
own euid-0 refusal is the contract), then the root legs the
project's own requirements mandate (Linux 5.13+, cgroup v2, root).
The guest init is canonical-invocations-only (the same house rule
supermassive-init.sh carries: each suite with --binary pinned, each
its own E2E-RESULT row), the verdict rides the E2E-VERDICT sentinel
relay (one namespace over from the supermassive lane's MASS-* so
the greps can never cross-contaminate), and the exit rides the
isa-debug-exit port device. Budgets: low 2400 s, best 1800 s, the
55-minute job cap the wedge-guard relationship needs — headroom,
never less depth.

## 5. The from-source law audit

The owner's law: builds from source go through the pro aliases
(e.g. cargo pro-linux-amd64-v3-gnu), never a bare cargo release
shape. Every CI payload's provenance:

| Lane | Payload | Verdict |
|------|---------|---------|
| release.yml | the four alias tiers (v3/v4 x gnu/musl) | law honored |
| ci.yml | the pro-build verification block (native + v3 + v4, gnu + musl) | law honored (it IS the alias verification) |
| supermassive.yml | the pro-native-gnu flagship (gnu legs) + the pro-native-musl static twin (musl legs) | law honored (aliases, documented pairing) |
| supermassive-e2e.yml (new) | pro-linux-amd64-v3-gnu, RUSTFLAGS composed the ci.yml pro-block way, artifact verified through its embedded build label | law honored |
| supermassive-container.yml | a DEBUG build (cargo build --features ebpf, target/debug) driving the container-resolution battery | reviewed, stays: the lane's contract is the container-native round trip (resolver + enforce), documented in its own header as the gnu-dynamic debug shape; a release-tier payload there is a one-line candidate if the owner wants the tier exercised in the docker/k8s legs too |

The build that made the news: the e2e lane's payload is the
release-tier alias build — the binary the depth suite exercises is
the binary the release page ships, which is the whole point of the
from-source law.

## 6. What was verified

- yamllint (repo .yamllint config) + actionlint: clean on all ten
  workflows, before each commit.
- The unfiltered estate: scripted sweep of every `on:` block — zero
  paths/branches keys remain; crates-io.yml and release.yml
  unchanged (v* only).
- The new guest init: bash -n, shfmt -d, shellcheck clean; the five
  suites' guest contracts checked before wiring (self-managing
  cgroups with fallbacks, internal privilege drop, no QUIC-stack
  dependency on this rootfs).
- The runtime tree is untouched by this task: `git diff 48e201a..HEAD
  -- src/ ebpf/` is empty, so the frame A/B baseline carries over
  by construction; the 10-second bench was still run for the health
  record (fps, density_gini, frame_entropy, dirty_cells all in the
  standing band).

## 7. The verdict summary

| Ask | Verdict | Evidence |
|-----|---------|----------|
| Unfiltered CI, publish on v* only | CLOSED | 82602b7: seven workflows unfiltered, the two publish lanes already dedicated v*, live-doc claims re-spelled |
| E2E realtime depth stresstest, user + root, alias build | CLOSED | 448dc21: the supermassive-e2e lane, five suites, both kernel ends, the v3-gnu alias payload |
| Low-spec tests at the documented minimum kernel, real KVM, not blind | CLOSED | the floor lane was already honest (5.13 strict per push); the missing low-spec coverage was the five unwired depth suites — now wired on the floor kernel leg; the README 5.15 stale claim fixed |
| Kernel-witnesses span lane (below-floor refusal witness) | STILL-OPEN-OWNER-CALL | cost: a fourth KVM lane + a second frozen-mirror dependency; benefit: the live refusal direction on a real sub-5.13 kernel; the direction is currently pinned by the loader gate + the span family |
| Release-tier payload in the container lane | STILL-OPEN-OWNER-CALL | the debug shape is the lane's documented contract; one line changes it if the owner wants the tier there |

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
