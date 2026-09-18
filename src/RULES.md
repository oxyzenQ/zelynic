<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# src/ Rules — Structure, Size, and Headers

> The colocated reminder of the rules that govern everything under
> `src/` (and `tests/`). The canonical, full policy text lives in
> [docs/RULES.md](../docs/RULES.md); this file exists so a contributor
> standing in the source tree sees the rules without going digging —
> the same convention as cosmostrix's `src/RULES.md`.

## Directory Discipline

- `src/` is organized by subsystem directory, each with a `mod.rs`
  that owns module declarations and re-exports: `cli/`, `commands/`,
  `output/`, `ebpf/` (with `limiter/`, `identity/`, `render/`,
  `connections/parse.rs`), `terminal/`, `capabilities/`, `info/`,
  `update/`.
- `src/main.rs` stays bootstrap/wiring only — parse, dispatch, exit.
- New modules join an existing directory when they belong to that
  subsystem; a new directory is created only for a genuinely new
  subsystem (a new command goes in `commands/`, a new render surface
  in `ebpf/render/`, a new terminal-mode concern in `terminal/`).
- Splitting a module that grew past the LOC cap is a COHESION split:
  the pieces share a theme (see `ebpf/identity/` → walk + tally +
  sanitize, `terminal/diff.rs` + `diff_tests.rs`), re-exported from
  the parent `mod.rs` so call sites keep resolving. Never split by
  slicing a function in half.

## Source File Size Cap

- Hard cap: **500 lines per `.rs` file**, enforced by
  `scripts/check-loc.sh` over `src/**` AND `tests/**` (recursive) plus
  `build.rs` (NIGHT-docs-4 — the tests tree is code too).
- A file that legitimately cannot be split self-declares at the top:

  ```rust
  // LOC_EXEMPT: <one-line justification>
  ```

  That marker is tracked migration debt — removing it is deleting the
  comment. There is NO hardcoded exemption list (lists drift; markers
  live with the file).
- Tests live beside what they pin: unit pins in the module (or a
  `*_tests.rs` sibling when the module would otherwise blow the cap),
  cross-binary contract pins in `tests/integration/` (one binary,
  split by surface — same 500-line discipline).

## Every File Carries Its License

- Every `.rs` file starts with the copyright + SPDX header:

  ```rust
  // Copyright (C) 2026 rezky_nightky
  // SPDX-License-Identifier: GPL-3.0-only
  ```

  Enforced by `scripts/check-headers.sh` (wired into
  `scripts/gate-keepers.sh`).
- Every living `.md` file carries the stale-data disclaimer block at
  the bottom — inject with `scripts/inject-disclaimer.sh`.

## When You Touch This Tree

Run the gates before committing (both must pass):

```bash
./scripts/build.sh check-all     # fmt + clippy + tests + policy (2-min local cap)
./scripts/gate-keepers.sh        # 13 checks: lint, policy, versions, disclaimers
```

Frame-level render changes additionally get the 10s A/B benchmark
(`scripts/frame-bench.py`) — protocol in the script header.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
