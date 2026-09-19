<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document covers
the build process, project structure, and coding standards.

## Prerequisites

- Rust 1.98+ (pinned to a concrete version in `rust-toolchain.toml`)
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

# Native-CPU host builds (cosmostrix pro-native lineage; see README
# "Native-CPU host builds" for the full contract)
cargo pro-native-gnu    # host CPU, dynamic (glibc)
cargo pro-native-musl   # host CPU, static (musl)
```

## Project Structure

```
src/
  main.rs              — entry point (the only file at src/ root)
  cli/
    mod.rs             — CLI definition (clap) + brand clap styles
    ux.rs              — CLI UX contract: clap error bridge, help footer,
                          exit codes, rate/duration typo tips
    suggestion.rs      — suggestion engine (edit distance + case-insensitive
                          Jaro for flag rescue)
  commands/
    mod.rs             — dispatchers + shared root/ebpf guards
    help.rs            — --help reference (single authority; the man
                          renderer was removed in NIGHT-hunt-12)
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
    identity/
      mod.rs           — cgroup ID → process name resolution + the canonical
                          /proc boundary helpers (pid_cgroup_id / pid_comm)
      tally.rs         — majority-vote representative pick (per-cgroup comm tally)
      sanitize.rs      — comm control-char sanitize (terminal-injection guard)
    connections.rs     — per-cgroup process + socket detail (eagle eyes)
      connections/parse.rs — /proc/net + fd-symlink parsers
    render.rs          — responsive render engine for observe/top (NIGHT-hunt-7)
      render/          — observe / top / detail frame renderers + bench fixture
    loader.rs          — observer BPF loader
    display.rs         — traffic table rendering
    bpf_syscall.rs     — raw bpf() syscall fallback
    lock.rs            — file lock (concurrency guard)
    pin.rs             — BPF pin cleanup
  capabilities/mod.rs  — eBPF support check (doctor)
  output/
    mod.rs             — capability-aware brand styling layer + broken-pipe-safe
                          print macros + suggestion white semantic
    labeled.rs        — line-aware labeled error/warning renderer
  info/mod.rs          — version report (-V)
  update/mod.rs        — --check-update
  terminal/
    mod.rs           — alt-screen box mode + the monitor loop
    diff.rs          — diff-based render engine (NIGHT-improve-2, the
                        cosmic-dragon-engine adaptation: shadow, dirty
                        runs, single write syscall, idle zero-emit;
                        NIGHT-improve-6: top-aligned scroll-free tall
                        regime); unit pins in test/terminal/diff_tests.rs

bpf/
  limiter.bpf.c        — token-bucket enforcer (ingress + egress)
  observer.bpf.c       — traffic counter (egress)

scripts/
  build.sh             — check-all orchestration
  gate-keepers.sh      — pre-commit non-code gates (14 checks)
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
  nonroot-depth-test.sh — unprivileged contract matrix (NIGHT-hunt-13)
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
8. **Dependency discipline** (NIGHT-hunt-6 supply-chain rule): every
   direct dependency needs live call sites and an entry in
   `docs/DEPENDENCY_AUDIT.md`; feature lists are trimmed to the modules
   actually used (`default-features = false` + explicit features, see
   the `clap`/`nix` entries in `Cargo.toml`); zero-call-site deps get
   removed, not kept "for later". No time crates — wall-clock math is
   the Hinnant civil-from-days algorithm in `build.rs` (chrono is
   banned in `deny.toml`; re-adding it fails CI). `deny.toml` runs the
   full feature graph (`all-features = true`), so the eBPF subtree is
   inside every advisories/licenses/bans check.

## Pre-commit

```bash
./scripts/build.sh check-all
./scripts/gate-keepers.sh
```

`build.sh check-all` runs the Rust-side gates: toolchain check, cargo fmt
--check, cargo clippy --all-targets --all-features -D warnings, cargo test,
cargo audit + cargo deny (both skip with a warning when not installed),
the repository policy check (check-policy.py), and the version-string
anti-pattern check.

`gate-keepers.sh` runs the 14 non-code gates: bash -n + shellcheck + shfmt
on shell scripts, yamllint + actionlint on workflows, TOML validation,
codespell, SPDX license headers (check-headers.sh), file permission guard
(644 files / 755 executables and directories), the repo-wide emoji sweep,
the 500-line Rust LOC cap (check-loc.sh), the toolchain-pin sync check
(check-rust-version-sync.sh), clang-format on the BPF C sources (the
exact eBPF Build CI command), and the documentation disclaimer check
(inject-disclaimer.sh). Missing tools are skipped with a warning.

## Branch Strategy

- `main` — pure eBPF v11.x (Dragon Architecture). Maintenance mode.
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
