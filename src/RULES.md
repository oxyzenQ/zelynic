<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# src/ Rules — Structure, Size, and Headers

> The colocated reminder of the rules that govern everything under
> `src/` (and `test/`). The canonical, full policy text lives in
> [docs/RULES.md](../docs/RULES.md); this file exists so a contributor
> standing in the source tree sees the rules without going digging —
> the same convention as cosmostrix's `src/RULES.md`.

## Directory Discipline

- **Root single-file policy (NIGHT-blade-15)**: `src/` root holds
  exactly ONE `.rs` file — `main.rs`. No new `.rs` file may be
  placed directly at `src/` root; every module lives in its
  subsystem directory as `dir/mod.rs` (the cosmostrix Single-File
  Policy convention). `src/term_reset.rs` is the file that drifted —
  moved to `src/term_reset/mod.rs`, module tree unchanged — and the
  rule is enforced, not just written: `scripts/gates/check-loc.sh`
  checks the root layout before it counts a single line.
- `src/` is organized by subsystem directory, each with a `mod.rs`
  that owns module declarations and re-exports: `cli/`, `commands/`,
  `output/`, `ebpf/` (with `limiter/`, `identity/`, `render/`,
  `connections/parse.rs`), `terminal/`, `term_reset/`,
  `capabilities/`, `info/`, `update/`.
- `src/main.rs` stays bootstrap/wiring only — parse, dispatch, exit.
- New modules join an existing directory when they belong to that
  subsystem; a new directory is created only for a genuinely new
  subsystem (a new command goes in `commands/`, a new render surface
  in `ebpf/render/`, a new terminal-mode concern in `terminal/`).
- Splitting a module that grew past the LOC cap is a COHESION split:
  the pieces share a theme (see `ebpf/identity/` → walk + tally +
  sanitize, `terminal/diff.rs` + `test/terminal/diff_tests.rs`),
  re-exported from
  the parent `mod.rs` so call sites keep resolving. Never split by
  slicing a function in half.

## Source File Size Cap

- Hard cap: **500 lines per `.rs` file** over `src/**` AND `test/**`
  (recursive) plus `build.rs`; a file that cannot be split declares
  `// LOC_EXEMPT: <one-line justification>` at the top (tracked
  migration debt — no hardcoded exemption list, markers live with
  the file).
- Tests live under the single top-level `test/` tree (NIGHT-hunt-17,
  cosmostrix Pattern C): unit pins are `#[path]`-wired from the module
  they pin (`test/terminal/diff_tests.rs`), the A/B frame harness from
  `test/ebpf/render/bench.rs`, and cross-binary contract pins live in
  `test/integration/` (one binary, split by surface, the only `[[test]]`
  target — `autotests = false`).

The full policy (soft targets, enforcement script, scope details)
lives once in [docs/RULES.md](../docs/RULES.md).

## Every File Carries Its License

- Every `.rs` file starts with the copyright + SPDX header
  (`// Copyright (C) 2026 rezky_nightky` /
  `// SPDX-License-Identifier: GPL-3.0-only`), enforced by
  `scripts/gates/check-headers.sh`; every living `.md` file carries the
  stale-data disclaimer block (`scripts/gates/inject-disclaimer.sh`).

## When You Touch This Tree

Run the gates before committing — the two commands and what each runs
  live once in [CONTRIBUTING.md](../CONTRIBUTING.md)
  (`build.sh check-all` + `gate-keepers.sh`). Frame-level render
  changes additionally get the 10s A/B benchmark
  (`scripts/bench/frame-bench.py`) — protocol in the script header.
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
