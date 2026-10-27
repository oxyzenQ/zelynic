<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2 audit — the all-infra pass

> Audit date: 2026-10-27 (night-dragon-lts-2). Scope: the whole
> infrastructure estate — the twelve-workflow CI/CD family, the
> `scripts/` tree (50 shell files, 16 Python files, the 781-line
> shared harness library, the gate family of 17 checks), the doc
> runnable-path truth, and the userspace security surfaces — against
> the LTS five. Audited at 1eab6ca, three days after
> night-dragon-maintenance-2 rewired the estate's triggers, so this
> pass reads the post-unfiltered shape and hunts the classes the
> gate floor cannot see: zombies, duplicate architecture, stale
> references, Actions injection, clock failure modes. Method: the
> gate floor run first (shellcheck, shfmt, ruff, plus eleven repo
> gates individually), then the deeper censuses the gates do not
> carry. The sibling reference stays zejtron.

## 1. The mandate

Infrastructure is the code that runs when nobody is looking: a
zombie symbol rots silently, a stale path breaks a lane days later,
one event-string interpolation into a shell is the runner itself
compromised, one clock assumption is a verdict family that lies
after a leap. The all-infra pass asked the LTS five of that estate
and accepted the gate floor as the starting point, never as the
verdict.

## 2. The gate floor — all green, first

- shellcheck (CI-pinned v0.10.0): zero findings across every `.sh`
  under `scripts/` (root, depth, ci, sandbox, gates — the full
  estate).
- shfmt (v3.10.0 canon): zero diffs tree-wide.
- ruff + ruff format: zero findings, 16/16 files already formatted.
- Eleven repo gates run individually: check-loc (273 .rs files,
  zero over the 600-line cap), check-scripts-loc (6 self-declared
  LOC_EXEMPT files, zero undeclared), check-headers (464/464),
  check-language (491 files, 0 findings), check-audits-index
  (61/61 indexed), check-actions-pins (HEALTH, 38 kept,
  23 skipped-for-cause), check-name-case (4,963 tokens, 0
  violations), check-version-anti-patterns (116 files, 0),
  check-secret-names (inventory consistent), check-fuzz-includes
  (the 4 included files compile standalone), and
  check-prebuilt-parity (objects + manifest + ebpf pin in parity).

## 3. The dragon hunt — the classes beyond the gates

- Zombie census on the shared library: every public symbol of
  `zelynic_harness_lib.py` traced to consumers across the whole
  tree — all alive (an initial single candidate, `TCP_MIN_RTO_S`,
  resolved to an in-lib consumer at the band-law line; the census
  method's own false positive, corrected and recorded).
- Zombie census on the two biggest shell files
  (`gate-keepers.sh` 926 lines, `build.sh` 687): every function
  defined is invoked — zero dead definitions.
- The versioned supermassive batteries (`-v2/-v3/-v4`) checked as
  the classic superseded-generation pattern and found ALIVE BY
  DESIGN: README and CONTRIBUTING document each as a distinct
  battery (the survival family, the container depth, the CLI
  depth), every `.py` has its `.sh` wrapper present, and the
  LOC_EXEMPT markers carry the tracked-debt rationale. Not
  zombies — architecture.
- `__pycache__` hygiene: gitignored (line 44 of `.gitignore`),
  untracked, working tree clean.
- Stale-reference sweep: every `scripts/` path referenced by any
  workflow resolves; every runnable `./...` path quoted in README,
  USAGE, and GUIDE resolves on disk; the one apparent miss
  (`wait-for-ci.sh.` with a trailing period) was the sweep's own
  regex catching prose punctuation — the file exists and the
  workflow calls it. Zero stale references.
- My own session's residue checked with the same sweep: the
  SUSTAIN_BAND_LO recalibration (0.50 to 0.45) left zero stale
  doc claims — GLOSSARY's plus-or-minus-50% row is the baseline
  lane's departure rule, a different instrument; no user doc
  states the sustain floor.

## 4. Security hardening — the Actions surface

The unfiltered-trigger estate (maintenance-2's own change) raised
the question this pass was built to answer: does any
event-controlled string reach a shell? The sweep found the surface
closed:

- The only `run:` interpolations are `matrix.target`
  (workflow-controlled matrix values) and `github.run_id` /
  `github.run_attempt` (numeric server-assigned fields). No
  branch name, PR title, commit message, or dispatch input
  reaches a shell.
- `github.ref_name` appears only in a display `name:` field.
- Zero `workflow_dispatch` inputs defined anywhere in the estate;
  zero `pull_request_target` (the untrusted-checkout-with-secrets
  trigger) anywhere; no `ACTIONS_ALLOW` overrides.
- Fork PRs ride the default trust model: no secrets are exposed
  to them, and the lanes they trigger need none.

## 5. Optimization — the peak-skip with its reason

The release profile is already at the ceiling (opt-level 3, fat
LTO, one codegen unit, strip, documented `panic = "unwind"`
rationale), the kernel hot path already carries the NIGHT-lts-2
reorder law, and the render surface is governed by the frame A/B
bench protocol with its standing bands. Optimization work that
cannot be benchmarked on this host (no Rust toolchain, no frame
A/B possible) would produce claims the honesty rule forbids — the
dimension is at peak for this pass and was skipped rather than
touched. Profiling data available and used: the repo's own
bench protocol and the CI battery timings.

## 6. LTS stability — the hidden failure modes probed

- The `--during` daily window rides the wall clock by design; the
  comparator is a totality law and the margin law biases
  under-enforcement, so an NTP step degrades toward
  under-limiting, never toward locking a host out. The wall-offset
  bridge re-stamps on every enforcement command's attach-reuse —
  the documented "the CLI visit is the refresh channel" trade;
  the residue (a policy nobody visits across a manual clock step)
  is bounded by the totality law and recorded as reasoned.
- The update-cooldown stamp lives under `XDG_RUNTIME_DIR`
  (tmpfs-backed, reboot-clean) and fails open on a missing or
  broken stamp; a failed curl exchange writes no stamp, so a
  transient infra failure cannot suppress the retry the throttle
  would deny.
- The harness suites read `/proc`, cgroupfs, and bpffs with
  locale-independent parsing; the suite exit carries the verdict
  (the record-only helper law), so one loaded-guest red row cannot
  errexit the battery before its summary.
- The prebuilt-parity pin (objects + manifest + `ebpf/` tree)
  proves the shipped object matches the source tree — the silent
  drift between prebuilt bytes and source, the classic eBPF LTS
  failure mode, is gated shut.

## 7. The verdict summary

| Dimension | Verdict | Evidence |
|-----------|---------|----------|
| Gate floor | GREEN | shellcheck 0, shfmt 0, ruff 0, eleven gates individually green |
| Hygiene (zombies, dups, stale) | PEAK | symbol liveness 100%, wrapper pairs intact, zero stale refs, caches ignored |
| Optimization | PEAK, skipped with reason | profile maxed, reorder law landed; unverifiable micro-opts refused by the honesty rule |
| Security hardening | PEAK | the Actions injection surface closed; the three spawn sites pinned; no untrusted-trigger secrets |
| LTS failure modes | PEAK | totality + margin laws, fail-open stamps, the parity pin gates the drift class |
| Code changes this round | NONE | docs-only audit record; the tree held on every dimension |

The estate held. The honest summary is the negative result: after
maintenance-2's rewiring and this session's six harness commits,
the infrastructure carries zero fix-worthy defects on the LTS
five, every dimension is at peak or documented debt, and the
record's value is the evidence trail that says so mechanically.

Benchmark A/B (10 s visual+perf): skipped by the docs-only rule —
this round changed no binary, no ebpf object, and no harness code;
the prebuilt-parity pin proves the object bytes unchanged, so the
binary's visual and performance metrics cannot move.

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
