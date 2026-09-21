<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document covers
the build process, project structure, and coding standards.

## Prerequisites

- Rust 1.98+ (pinned to a concrete version in `rust-toolchain.toml`)
- The eBPF nightly pin + bpf-linker 0.11.1 — one-time, one command:
  `./scripts/bootstrap-ebpf.sh` (idempotent, and it self-repairs a
  damaged toolchain install; `--check` reports status only)
- A kernel that can run zelynic — the requirement line and the full
  compatibility matrix live once in
  [docs/KERNEL_COMPATIBILITY.md](docs/KERNEL_COMPATIBILITY.md)

## Build

The build commands (plain release and the pro-native host aliases)
live once in the README — [Install from source](README.md#install-from-source)
and [Native-CPU host builds](README.md#native-cpu-host-builds) — the
same commands apply for contributors. One contributor-specific note:
the alias-injected `-C target-cpu=native` tunes the HOST binary only
(build.rs strips it from the nested eBPF build, NIGHT-hunt-28), so
bpfel objects stay identical no matter which alias built them.

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

ebpf/                   — the pure-Rust BPF source (aya-ebpf; NIGHT-improve-1
                          phase 3): nightly-only crate, built by build.rs's
                          nested cross-build and embedded into the binary
  src/main.rs           — the observer programs (egress + ingress traffic
                          counters, throttle, events)
  src/bin/limiter.rs    — the token-bucket enforcer (enforce_dl ingress +
                          enforce_ul egress, nine PIN_BY_NAME maps)

scripts/
  build.sh             — check-all orchestration
  gate-keepers.sh      — pre-commit non-code gates (15 checks)
  check-permissions.sh — 644/755 permission guard
  check-loc.sh         — Rust file LOC cap (500, // LOC_EXEMPT: markers)
  check-headers.sh     — license header check (rs/c/h/py/sh/toml/yml/md)
  check-rust-version-sync.sh — toolchain pin == MSRV == CI pin
  rust-version-to.sh   — one-command Rust toolchain bumper
  inject-disclaimer.sh — .md stale-data disclaimer (inject + --check)
  check-policy.py      — copyright + SPDX policy check
  supermassive-test.sh — one-click supermassive test (NIGHT-master-2,
                renamed from brutal-stress-test in NIGHT-improve-11; wraps
                supermassive-test.py: light ~2 min / --heavy 5+ min
                modes sweeping the whole command surface — strict/block/
                unstrict x single/multi/all, curl burst download + upload,
                rate ladder 1kb..1tb adaptive to hardware, five dedicated
                target cgroups plus a never-policed hq cgroup for the
                harness itself (one policed hook per stream,
                NIGHT-improve-12), --self-test engine smoke for
                CI/containers)
  leak-test.sh         — orphan detection after every operation
  distros-depth-test.sh — comprehensive distro suite
  nonroot-depth-test.sh — unprivileged contract matrix (NIGHT-hunt-13)
  limiter-depth-test.sh — flagship limiter depth stress test (NIGHT-master-1;
                wraps limiter-depth-test.py: self-contained loopback traffic,
                dedicated test cgroup, measured rate accuracy + kernel-drop
                proof + BPF accounting cross-check + drift guard + reload
                cycles; the tool for validating a new distro)
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

`gate-keepers.sh` runs the 15 non-code gates: bash -n + shellcheck + shfmt
on shell scripts, yamllint + actionlint on workflows, TOML validation,
codespell, SPDX license headers (check-headers.sh), file permission guard
(644 files / 755 executables and directories), the repo-wide emoji sweep,
the 500-line Rust LOC cap (check-loc.sh), the toolchain-pin sync check
(check-rust-version-sync.sh), rustfmt on the ebpf/ crate (the exact
eBPF Build CI command — the former clang-format gate retired with the
C sources in NIGHT-improve-1 phase 3), and the documentation disclaimer
check (inject-disclaimer.sh). Missing tools are skipped with a warning.

## Branch Strategy

The branch table lives once in the
[README](README.md#branches) — `main`, pure eBPF v11.x, maintenance
mode (branch history and the retired `intergalaxion` note are in
[docs/DRAGON_ARCHITECTURE.md](docs/DRAGON_ARCHITECTURE.md)).
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
