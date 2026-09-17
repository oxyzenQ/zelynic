<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document covers
the build process, project structure, and coding standards.

## Prerequisites

- Rust 1.88+ (stable)
- clang 10+ (compile BPF programs)
- libbpf-dev (BPF headers)
- linux-libc-dev (multiarch kernel headers)
- Linux kernel 5.13+ (cgroup v2 + cgroup.id file)

## Build

```bash
# Compile BPF programs
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/observer.bpf.c -o bpf/observer.bpf.o

# Build Rust binary
cargo build --release --features ebpf
```

## Project Structure

```
src/
  main.rs              — entry point (the only file at src/ root)
  cli/mod.rs           — CLI definition (clap)
  commands/
    mod.rs             — command dispatchers
    help.rs            — --help-all output
    block.rs           — block-* handlers
    cleanup.rs         — unstrict / unstrict-all / recover handlers
    monitor.rs         — status / list-apps / observe / top handlers
    safety.rs          — dangerous-target blocklist + guards
    strict.rs          — strict-single / strict-multi / limit-all handlers
    rates.rs           — CLI rate-string resolution
  ebpf/
    mod.rs             — module exports
    limiter/
      mod.rs           — Limiter struct + lifecycle (attach / open_pinned) + re-exports
      types.rs         — constants + BPF map structs + high-level API types
      format.rs        — rate/duration parsing + formatting helpers
      policy.rs        — apply / resolve / write / delete policy operations
      stats.rs         — status printing + map readers + identity accessors
    identity.rs        — cgroup ID → process name resolution
    loader.rs          — observer BPF loader
    display.rs         — traffic table rendering
    bpf_syscall.rs     — raw bpf() syscall fallback
    lock.rs            — file lock (concurrency guard)
    pin.rs             — BPF pin cleanup
  capabilities/mod.rs  — eBPF support check (doctor)
  output/mod.rs        — capability-aware brand purple styling layer
  info/mod.rs          — version report (-V)
  update/mod.rs        — --check-update
  terminal/mod.rs      — alt-screen box mode

bpf/
  limiter.bpf.c        — token-bucket enforcer (ingress + egress)
  observer.bpf.c       — traffic counter (egress)

scripts/
  build.sh             — check-all orchestration
  gate-keepers.sh      — pre-commit non-code gates (13 checks)
  check-permissions.sh — 644/755 permission guard
  check-loc.sh         — Rust file LOC cap (500, // LOC_EXEMPT: markers)
  check-headers.sh     — license header check (rs/c/h/py/sh/toml/yml/md)
  check-rust-version-sync.sh — toolchain pin == MSRV == CI pin
  rust-version-to.sh   — one-command Rust toolchain bumper
  inject-disclaimer.sh — .md stale-data disclaimer (inject + --check)
  check-policy.py      — copyright + SPDX policy check
  stress-test.sh       — stress suite
  leak-test.sh         — orphan detection after every operation
  distros-depth-test.sh — comprehensive distro suite
  benchmarking.sh      — CPU/memory overhead measurement (wraps benchmarking.py)
```

## Coding Standards

1. **LOC limit**: < 500 lines per `.rs` file (enforced by `scripts/check-loc.sh`, wired into `gate-keepers.sh`; a file that cannot be split self-declares `// LOC_EXEMPT: <reason>`)
2. **Copyright + SPDX**: every source, config, and doc file must have:
   ```
   Copyright (C) 2026 rezky_nightky
   SPDX-License-Identifier: GPL-3.0-only
   ```
   (comments prefixed per language; `.md` uses HTML comments. Enforced by
   `scripts/check-headers.sh`.)
3. **License**: GPL-3.0-only
4. **Rust toolchain**: pinned to a concrete X.Y.Z in `rust-toolchain.toml`
   (never `stable` — dormant-mode policy). Bump with
   `./scripts/rust-version-to.sh <X.Y.Z>`; sync enforced by
   `scripts/check-rust-version-sync.sh`.
5. **No tc/nft/systemd-wrapper**: pure eBPF only on `main`
6. **Fail-safe**: BPF programs return 1 (allow) on every error path
7. **Lowercase units**: rate formats use `kb`, `mb`, `gb` (no uppercase, no `/s`)

## Pre-commit

```bash
./scripts/build.sh check-all
./scripts/gate-keepers.sh
```

`build.sh check-all` runs: cargo fmt --check, cargo clippy --all-features -D warnings,
cargo test --locked, cargo deny check all (skips when not installed),
python3 scripts/check-policy.py, yamllint, codespell, actionlint.

`gate-keepers.sh` runs the non-code gates: bash -n + shellcheck + shfmt on
shell scripts, yamllint + actionlint on workflows, TOML validation, codespell,
SPDX license headers, file permission guard (644 files / 755 executables and
directories), and the repo-wide emoji sweep. Missing tools are skipped with a
warning.

## Branch Strategy

- `main` — pure eBPF v10.x (Dragon Architecture). Maintenance mode.
- `legacy` — v3.1.1 (tc/nft/systemd-wrapper). Final legacy release, no new development.
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
