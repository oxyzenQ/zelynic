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
  main.rs              — entry point
  cli.rs               — CLI definition (clap)
  commands/mod.rs      — command dispatchers
  commands/help.rs     — --help-all output
  commands/block.rs    — block-* handlers
  commands/cleanup.rs  — unstrict / unstrict-all / recover handlers
  commands/monitor.rs  — status / list-apps / observe / top handlers
  ebpf/
    mod.rs             — module exports
    limiter.rs         — Limiter struct + BPF map operations
    limiter_types.rs   — types, constants, helper functions
    identity.rs        — cgroup ID → process name resolution
    loader.rs          — observer BPF loader
    display.rs         — traffic table rendering
    bpf_syscall.rs     — raw bpf() syscall fallback
    lock.rs            — file lock (concurrency guard)
    pin.rs             — BPF pin cleanup
    audit.rs           — JSONL audit log
  ebpf_legacy.rs       — kernel capability detection
  capabilities/mod.rs  — eBPF support check (doctor)
  info.rs              — version report (-V)
  update.rs            — --check-update
  terminal.rs          — alt-screen box mode

bpf/
  limiter.bpf.c        — token-bucket enforcer (ingress + egress)
  observer.bpf.c       — traffic counter (egress)

scripts/
  build.sh             — check-all orchestration
  gate-keepers.sh      — pre-commit non-code gates
  check-permissions.sh — 644/755 permission guard
  check-policy.py      — LOC + copyright + SPDX check
  stress-test.sh       — stress suite
  leak-test.sh         — orphan detection after every operation
  distros-depth-test.sh — comprehensive distro suite
  benchmarking.sh      — CPU/memory overhead measurement (wraps benchmarking.py)
```

## Coding Standards

1. **LOC limit**: < 1000 lines per file (enforced by `check-policy.py`)
2. **Copyright + SPDX**: every source file must have:
   ```
   // Copyright (C) 2026 rezky_nightky
   // SPDX-License-Identifier: GPL-3.0-only
   ```
3. **License**: GPL-3.0-only
4. **No tc/nft/systemd-wrapper**: pure eBPF only on `main`
5. **Fail-safe**: BPF programs return 1 (allow) on every error path
6. **Lowercase units**: rate formats use `kb`, `mb`, `gb` (no uppercase, no `/s`)

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
