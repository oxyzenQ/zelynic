<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-hunt-Z10: the uid-lane sweep (2026-10-03)

The owner's ask, verbatim: after the CI-repair that closed the
supermassive four-leg red, approve the proposed follow-up — audit
the other batteries for the same uid-dependent needle class, "until
all peak no remainings again". This audit is that sweep: every
harness that runs the zelynic binary and asserts on its output,
crossed with every CI leg that runs it and the uid that leg runs
under, read per instrument (no full scan — the precision-per-stage
method the MEDIUM-HEAVY context weight demands), every reachable
shape probed live where the host allows it. The verdict up front,
honestly: **zero remainings — the v4 battery was the class's only
instance, closed at 6eb652d; every other instrument in the repo
already owns a uid discipline.**

## The class (what the Z9 incident taught)

A uid-dependent needle is a test row whose asserted outcome depends
on the execution uid of the harness itself: a row that asserts the
privilege gate's refusal wording ("root required", CAP_BPF, the
sudo tip) can only pass when the harness runs NON-root, and a row
that asserts a past-the-gate outcome (an enforcement attempt, a
resolution, a one-shot report) can only pass when the harness runs
as root. The failure shape the incident exposed: a battery that
runs under BOTH uid shapes across CI legs (rootless in the CI
workflow, root in the supermassive VM's init context) with a row
that knows its needle's lane by neither flag nor skip — green in one
leg, red in the other, with a verdict that lies about the product
in exactly one of them. Two aggravating properties made it worse
than a normal flake: the red leg reads as a product regression (it
is not — the binary is healthy), and the row may be UNSAFE in the
wrong lane (a valid rate past a passing gate is a real enforcement
attempt — v4's own safety-by-construction contract forbids exactly
that, and the Z9 rows were violating it in every VM run, harmless
only because the VM's cgroup fleet has no "brave").

## The method (the leg matrix)

The sweep enumerated every binary-driving instrument in the repo
(the five supermassive batteries, the MMSPA delta harness, the
claims proof, the depth family, the bench family, the nonroot depth
suite, and the Rust test tree), then crossed each with every leg
that runs it and the uid that leg runs under:

- Dragon Guard - CI (the GitHub runner, non-root)
- Dragon Guard - Supermassive (the micro-VM init, root — v1/v2/v3
  need root for their BPF legs, so everything in that init runs as
  root)
- Dragon Guard - Supermassive Container E2E (v3 full under
  `sudo` with the docker/k8s lanes forced)
- Dragon Guard - Gate-keepers (gates only, no batteries)

The same three questions were asked per instrument: which uid shapes
reach it, which rows depend on the uid, and does the row know its
lane (flag, honest skip, fail-fast preflight, refuse-to-run, or
lane-adaptive assertion)?

## The matrix, instrument by instrument (all verified clean)

**v3, the container depth battery — the doctrine holder, fully
lane-aware in BOTH directions.** Stage 2 (the privilege gate) is
the rootless-lane twin: it runs and asserts the "root required"
refusal on every container URI shape when the harness is non-root,
and SKIPs with the honest reason ("the gate cannot be triggered as
root") when it is — the exact doctrine the v4 fix adopted. Stages
3-6 (grammar, resolution, docker E2E, k8s E2E) are the root-lane
twin: they SKIP when non-root with reasons that name what carries
the contract instead ("the privilege gate gates the grammar — stage
2 carries the contract"). Verified live rootless this session: the
full battery renders 8 passed / 0 failed / 4 skipped — stage 2's
five refusal rows firing green against the repo binary, stages 3-6
skipping honestly. Verified live as root by the VM and container
legs (both green at 6eb652d). No row is uid-blind.

**v1, v2, the MMSPA delta harness, and the claims proof —
fail-fast preflights, the other honest discipline.** None of them
can run their batteries rootless and none pretend to: v1 records
the honest FAIL row ("re-run with sudo — BPF needs CAP_BPF") and
exits, v2 and the claims proof print the one-line refusal ("This
test programs the kernel datapath — run with sudo.") and exit 2,
MMSPA refuses with the `--self-test` hint and exits 1 — all four
exit shapes verified live rootless this session (2 / 2 / 1 / 2), so
no CI leg can ever mistake a wrong-uid invocation for a green
verdict. The rootless legs only ever see their `--self-test`
engine smokes (CI runs all five), which are resolution-free and
uid-free by contract. Inside the root-only domain, the empirical
negative evidence is on the record: every one of them ran GREEN in
the supermassive VM at f856ae3 and 6eb652d — a rootless-lane needle
inside any of them would have gone red there exactly the way v4's
three rows did, and nothing did. Belt-and-braces also verified: v2
carries a stage-level uid guard (the bypass shadow-audit stage
skips without the injector's AF_PACKET root), and the claims proof
carries a per-stage root check past its main gate — both honest
skips/fails, not silent passes.

**The depth and bench families — the same fail-fast contract.**
limiter-depth (exit 2, "run with sudo"), endurance (exit 1), and
benchmarking (exit 1) all refuse the wrong uid before any verdict
row exists; crash-recovery, race-condition, and reload all call the
shared `check_root` guard; install-flow is root-lane BY DESIGN (it
pins the root-without-sudo contract of a fresh server or container,
the NIGHT-blade-8 lane). None of them runs in any rootless CI leg.

**nonroot-depth — the inverse guard, lane-perfect.** The suite that
pins the unprivileged contract end to end (the 90-row matrix) does
the opposite refusal: it REFUSES to run as root ("this suite pins
what an unprivileged contract sees — re-run without sudo"), because
euid 0 would invalidate every assertion it owns. Read-verified at
the guard; the suite itself ran 90/90 at this HEAD in the lts-4
pass.

**The Rust test tree — the gold standard, lane-ADAPTIVE.** The
integration suite's uid-dependent tests do not merely skip: they
branch. `euid_is_root()` (integration/main.rs, parsed from
/proc/self/status's Uid line) gates the unprivileged-contract tests
with early returns whose comments state the doctrine ("No-ops under
root (sudo cargo test) where the contract cannot hold"), while
surface_pins and monitor_guard assert a DIFFERENT CORRECT outcome
per lane — under root the piped one-shot monitor report RUNS and
names its target; under non-root the piped monitor refuses with the
interactive-gate wording and the `status --print-json` teaching
tip. The three root+eBPF smoke tests are `#[ignore]`-gated at the
cargo level (explicit opt-in, never silently selected), and the
whole tree carries zero uid-blind gate needles (the sweep grep over
test/ found the only "requires root" strings inside the ignore
markers and comments themselves). cargo test ran green twice this
session (110 unit + 42 integration in check-all). This is the
strongest shape in the repo: not skip-with-reason but
assert-the-right-truth-per-lane.

**v4, the CLI depth battery — the fixed instance, both lanes now
verified.** Rootless: 121 passed / 0 failed / 0 skipped (the CI
leg's shape, green live at 6eb652d). Root: 118 passed / 0 failed /
3 skipped (the VM leg's shape, green live at 6eb652d — the
rootless-lane rows SKIP without executing, the garbage/typo rows
still run because their refusals fire at the parse boundary). The
lane flag, the self-test pin, and the doctrine comments are the
CI-repair commit's record (6eb652d).

## The verdict and the why

Zero remainings. The honest structural reason, not luck: the repo's
battery population splits into exactly two disciplines that both
predate the incident — the batteries that CAN run rootless (v3, v4,
the Rust tree, nonroot-depth) were built lane-aware from their
first CI-leg debut (v3's stage 2 is the original skip-when-root;
NIGHT-hunt-13's Rust gates predate the supermassive legs), and the
batteries that CANNOT run rootless refuse the wrong uid loudly
before any row can lie. The Z9 rows were the one seam where a
rootless-CAPABLE battery gained rows whose needle belonged to the
rootless lane without the lane knowing — the class's single
instance, closed at 6eb652d.

Declined investments on the record: adding a shared
`uid_lane` helper to the harness lib for a class that now has
exactly one consumer (v4's flag) would abstract a doctrine three
harnesses already express three honest ways (skip, refuse,
adapt); writing a uid-matrix smoke that runs every battery under
both uids would re-run root-needing batteries rootless just to
watch them refuse — the refusals themselves are already pinned by
the fail-fast exits this sweep verified live; and hardening v2's
stage-level belt guard into a table-driven lane flag would touch a
battery whose every uid-dependent row is unreachable past its own
main gate. The doctrine is diversity-honest: each instrument owns
the uid shape it can actually hold, and the sweep verified each one
against the leg that exercises it.
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
