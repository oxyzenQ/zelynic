<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# seed anchors

The committed corpus definition (the zejtron estate's law, ported with
the fuzz lane in night-dragon-maintenance-5): each directory under
`seeds/` holds hand-built inputs for the fuzz target of the same name,
and the workflow copies them into the working corpus before every run
so the fuzzer starts inside the parser's real paths from run one
instead of spending its budget rediscovering a valid input byte by
byte.

The law the directory name states: a seed is a contract, a discovery
is not. The corpus the fuzzer grows stays untracked (`fuzz/.gitignore`)
— only shapes a maintainer asserts the parser must hold belong in a
commit. The unit-test fixtures each seed mirrors live beside the
parser it protects (`src/ebpf/connections/parse.rs` tests,
`src/ebpf/limiter/during_parse.rs` grammar bounds,
`src/output/sanitize.rs` contract pins); a seed and its fixture are
two expressions of the same tracked definition.

- `proc_net_parser/` — /proc/net/{tcp,tcp6} rows in the exact kernel
  format (established with full queues, LISTEN with zero queues, a v6
  row, and a malformed row the parser must refuse with None).
- `during_spec_parser/` — the --duration grammar's bounds and units:
  the 1s floor, the 5y ceiling, the `mn` month spelling, and a plain
  hours value.
- `sanitize_display/` — the sanitizer's contract families: a clean
  ASCII label that must pass byte-identical, an OSC 52 clipboard-write
  attempt, and an RLO bidi masquerade.

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
