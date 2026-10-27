<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2e audit — the kernel clippy lane goes standing

> Audit date: 2026-10-27 (night-dragon-lts-2e, the owner-call the
> lts-2d record left on the table). Scope: wire the now-silent kernel
> clippy instrument as a standing CI lane — the one residual the 2d
> round named and the owner approved, the single deliberate CI touch
> of the session. Audited and executed at e785a11. The sibling
> reference stays zejtron.

## 1. The mandate

The 2c round wired the SAFETY deny gate into `ebpf/Cargo.toml`
(`[lints]`), which binds every clippy invocation anywhere — but no
clippy invocation on the kernel crate was automated anywhere. The 2d
round took the pre-existing warning count to zero and left the
instrument manual-only: "wiring the now-silent kernel clippy as a
standing CI lane is the next owner-call candidate." The owner called
it: the lane goes in, and with it the gate-inventory freeze lifts for
exactly this one lane and nothing else.

## 2. Where the lane lives, and why there

Three CI jobs install the dated nightly pin (`ci.yml` check, musl,
ebpf-host); only one of them owns a direct kernel-crate contract. The
lane went into the **ebpf-host job**, immediately after its direct
crate build step, for four reasons, each a law already on the books:

- **One check, one place** (the NIGHT-improve-13 law): the
  gate-keepers battery's charter explicitly excludes Rust core code
  ("use `cargo clippy` via build.sh check-all for that"), so the
  battery is the wrong home; and a step inside ebpf-host is the only
  shape that adds no second nightly, no second bpf-linker install,
  and no new job.
- **The job is warm**: ebpf-host installs the nightly pin (now with
  the clippy component), installs bpf-linker, and compiles the whole
  crate one step earlier — the clippy pass rides the same
  environment the build just proved.
- **The literal ask**: "standing CI lane" — ci.yml burns on every
  push and every PR (the unfiltered posture, night-dragon-maintenance-
  2), so the instrument now runs on exactly the cadence the tree
  changes.
- **Zero workflow-structure drift**: no new job, no new action
  reference, no pin changes — the step is a `run:` beside the build
  step, so the actions-pin gate and the job graph are untouched.

## 3. The diff — two hunks, no more

1. The ebpf-host job's nightly install gains the `clippy` component
   (`components: rust-src` -> `components: rust-src, clippy`): the
   lane runs the pinned nightly's own clippy-driver, and a component
   the toolchain lacks is a hard error, not a fallback. The check and
   musl jobs keep rust-src only — their nightly drives build.rs's
   nested build and never runs clippy.
2. The new step: `cargo clippy --locked -- -D warnings` with
   `working-directory: ebpf`. `--locked` is the lockfile-freeze
   contract the build step beside it already carries; `-D warnings`
   is the verdict the crate sits at zero under (the lts-2d floor).

The RUSTFLAGS shadow question is answered in the step comment itself:
the workflow-level env (`-D warnings`, NIGHT-strict-2) shadows the
config's `target-cpu=v3`, and for a check-only pass that shadow is
harmless — clippy generates no code, so the BPF_ATOMIC instruction
selection the v3 flag exists for lives entirely in the build step,
which carries the flag explicitly (the NIGHT-boost-38 shape). The
build-std core still compiles from source through rust-src, so the
check is the real one, not a host-triple approximation.

## 4. The verification stack

- The exact step semantics reproduced locally, env included:
  `RUSTFLAGS="-D warnings" cargo clippy --locked -- -D warnings` in
  `ebpf/` — exit 0, zero warnings, no footer (the lts-2d zero
  survives the env-shadowed fingerprint).
- `yamllint -c .yamllint --strict` on the edited workflow: pass.
- `actionlint` on the edited workflow: pass.
- No file under `ebpf/` changed in this round, so the prebuilt tree
  pin is untouched (the parity gate's verdict carries), and no Rust
  source changed, so the fmt/clippy/suite verdicts of the 2d closure
  carry unmodified: 975 passed, 0 failed, 4 ignored, kernel clippy
  zero, both fmts clean.
- The gate-keeper battery runs clean with the new workflow on disk
  (the YAML gates re-lint it wholesale; 24/0 at closure).

## 5. The verdicts

| Surface | Verdict | Basis |
|---------|---------|-------|
| Kernel clippy in CI | STANDING | every push and PR runs the pinned nightly's clippy at `-D warnings`; the crate sits at zero, so the lane is green and the first future warning fails it |
| Gate-inventory freeze | LIFTED FOR THIS LANE ONLY | one workflow, two hunks, no action refs, no new job — the owner's one deliberate CI touch |
| SAFETY gate (lts-2c) | CARRIED FORWARD | the lane enforces the same manifest table the manual instrument did; nothing re-leveled |
| check/musl jobs | UNMOVED | their nightly keeps rust-src only, their steps byte-identical |
| Local floor | UNMOVED | no `ebpf/` or Rust edit; prebuilt pin, suite, fmt, and kernel clippy verdicts carry from the 2d closure |

## 6. Honest residuals

- The lane's first GitHub-hosted run is the push that carries this
  commit — this record proves the step's command, environment, and
  lint set locally under the workflow's exact env semantics; the
  runner-side component install is dtolnay's documented behavior
  with an explicit components list.
- release.yml and maintenance.yml install the same nightly pair but
  gain no clippy step: publish and clock lanes are not the change
  cadence the standing lane exists for, and duplicating the check
  there would break the one-check-one-place law the lane itself
  follows.
- The lane checks the crate as `cargo clippy` sees it (check-only,
  config-rustflags shadowed) — the build step remains the sole
  codegen authority; a lint-free check plus a green build is the
  complete kernel-side verdict, and both now run in the same job.

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
