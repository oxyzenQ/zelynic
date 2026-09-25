<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document covers
the build process, project structure, and coding standards.

## Prerequisites

- Rust 1.98+ (pinned to a concrete version in `rust-toolchain.toml`)
- The eBPF nightly pin + bpf-linker 0.11.1 — one-time, one command:
  `./scripts/dev/bootstrap-ebpf.sh` (idempotent, and it self-repairs a
  damaged toolchain install; `--check` reports status only)
- A kernel that can run zelynic — the requirement line and the full
  compatibility matrix live once in
  [docs/KERNEL_COMPATIBILITY.md](docs/KERNEL_COMPATIBILITY.md)

## Build

The build commands (plain release, the pro-native host aliases, and
the arch-baseline release aliases) live once in the README —
[Install from source](README.md#install-from-source),
[Native-CPU host builds](README.md#native-cpu-host-builds), and
[Arch-baseline release builds](README.md#arch-baseline-release-builds-v3--v4) —
the same commands apply for contributors. One contributor-specific
note: the alias-injected `-C target-cpu=` flag (native or x86-64-v3/v4)
tunes the HOST binary only (build.rs strips it from the nested eBPF
build, NIGHT-hunt-28), so bpfel objects stay identical no matter
which alias built them.

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
    monitor.rs         — status / list-apps / eagle-eyes handlers
    safety.rs          — dangerous-target blocklist + guards
    strict.rs          — strict-single / strict-multi / strict-all handlers
    rates.rs           — CLI rate-string resolution
  ebpf/
    mod.rs             — module exports
    limiter/
      mod.rs           — Limiter struct + lifecycle (attach / open_pinned) + re-exports
      types.rs         — constants + BPF map structs + high-level API types
      format.rs        — rate/duration parsing + formatting helpers
      policy.rs        — apply / resolve / write / delete policy operations
      stats.rs         — status printing + map readers + identity accessors
      reclaim.rs       — bucket/stats slot reclamation on unstrict/recover
                         (the LTS budget, NIGHT-improve-10)
    identity/
      mod.rs           — cgroup ID → process name resolution + the canonical
                          /proc boundary helpers (pid_cgroup_id / pid_comm)
      tally.rs         — majority-vote representative pick (per-cgroup comm tally)
      sanitize.rs      — comm control-char sanitize (terminal-injection guard)
    connections.rs     — per-cgroup process + socket detail (eagle eyes)
      connections/parse.rs — /proc/net + fd-symlink parsers
    render.rs          — responsive render engine for eagle-eyes (NIGHT-hunt-7)
      render/          — eagle / detail / focus frame renderers
    loader.rs          — observer BPF loader
    embedded.rs        — aligned, build-validated embedding of both BPF
                         objects (NIGHT-hunt-29/30)
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
  src/math.rs           — the enforcement arithmetic (refill, fill-detect,
                          fractional carry, clamps): pure core, #[path]-
                          shared with the userspace test tree (depthbore-1)
  src/bin/limiter.rs    — the token-bucket enforcer (enforce_dl ingress +
                          enforce_ul egress, nine PIN_BY_NAME maps)

scripts/
  build.sh             — check-all orchestration
  gate-keepers.sh      — pre-commit non-code gates (17 sections)
  check-permissions.sh — 644/755 permission guard
  check-loc.sh         — Rust file LOC cap (500, // LOC_EXEMPT: markers)
  check-scripts-loc.sh — scripts LOC cap (1000, # LOC_EXEMPT: markers)
  check-headers.sh     — license header check (rs/c/h/py/sh/toml/yml/md)
  check-language.sh    — English-only language gate (non-Latin scripts +
                        Indonesian vocabulary detector; NIGHT-hunt-19)
  check-rust-version-sync.sh — toolchain pin == MSRV == CI pin, plus
                        the eBPF nightly pin family (ebpf/rust-toolchain.toml
                        == workflow installs == build.rs == install/uninstall;
                        NIGHT-lts-9)
  check-release-parity.sh — release -C codegen token parity: the four
                        pro-linux-amd64-* aliases in .cargo/config.toml
                        match the release workflow matrix rustflags
                        (NIGHT-lts-9 — a local release-shape build IS
                        the release shape)
  harness_lib.sh       — shared colored-harness helpers (log_* /
                        check_* / counters; sourced by the three
                        colored root-run harnesses, NIGHT-hunt-21 —
                        the bash twin of zelynic_harness_lib.py)
  rust-version-to.sh   — one-command Rust toolchain bumper
  inject-disclaimer.sh — .md stale-data disclaimer (inject + --check)
  check-policy.py      — copyright + SPDX policy check
  supermassive-test.sh — one-click supermassive test (NIGHT-master-2,
                renamed from brutal-stress-test in NIGHT-improve-11; wraps
                supermassive-test.py: one root mode, the 5+ min matrix
                (light retired in NIGHT-improve-19; --self-test is
                rootless) sweeping the whole command surface — strict/block/
                unstrict x single/multi/all, curl burst download + upload,
                rate ladder 1kb..1tb adaptive to hardware, five dedicated
                target cgroups plus a never-policed hq cgroup for the
                harness itself (one policed hook per stream,
                NIGHT-improve-12), --self-test engine smoke for
                CI/containers)
  setup.sh             — the lazy one-command pipeline (NIGHT-improve-18:
                bootstrap + pro-native-gnu build, --musl twin opt-in,
                rootless self-test, the sudo supermassive matrix, then
                a next-steps menu; every phase idempotent)
  nonroot-depth-test.sh — unprivileged contract matrix (NIGHT-hunt-13)
  crash-recovery-test.sh — `recover` on stale pins + crash cycles
                        (NIGHT-cleanup-2: kept — the recover-on-stale
                        contract has no other e2e coverage)
  race-condition-test.sh — cross-process lock contract under
                        concurrent CLI invocations (NIGHT-cleanup-2:
                        kept — Rust unit tests cover lock logic only)
  reload-test.sh         — rate change during ACTIVE traffic (the
                        no-gap combo supermassive's separate reload
                        and sustain stages do not produce)
  limiter-depth-test.sh — flagship limiter depth stress test (NIGHT-master-1;
                wraps limiter-depth-test.py: self-contained loopback traffic,
                dedicated test cgroup, measured rate accuracy + kernel-drop
                proof + BPF accounting cross-check + drift guard + reload
                cycles; the tool for validating a new distro)
  proof-claims.sh      — honesty harness (NIGHT-boost-8; wraps
                proof-claims.py: proves the four README headline
                claims live — no daemon, pure eBPF, per-app
                per-cgroup, precision 0.00% with its honest live
                residual; --self-test engine smoke for CI)
  benchmarking.sh      — CPU/memory overhead measurement (wraps benchmarking.py)
```

## Coding Standards

1. **LOC limit**: < 500 lines per `.rs` file (enforced by `scripts/gates/check-loc.sh`, wired into `gate-keepers.sh`; a file that cannot be split self-declares `// LOC_EXEMPT: <reason>`)
2. **Copyright + SPDX**: every source, config, and doc file must have:
   ```
   Copyright (C) 2026 rezky_nightky
   SPDX-License-Identifier: GPL-3.0-only
   ```
   (comments prefixed per language; `.md` uses HTML comments. Enforced by
   `scripts/gates/check-headers.sh`.)
3. **License**: GPL-3.0-only
4. **Rust toolchain**: pinned to a concrete X.Y.Z in `rust-toolchain.toml`
   (never `stable` — dormant-mode policy). Bump with
   `./scripts/dev/rust-version-to.sh <X.Y.Z>`; sync enforced by
   `scripts/gates/check-rust-version-sync.sh`.
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
9. **English-only language**: comments, docs, script text, and string
   literals are pure English (chat may be mixed-language; committed
   artifacts never are). Non-Latin scripts appear only as
   marker-declared Unicode fixtures (`// NON_LATIN_FIXTURE:`).
   Enforced by `scripts/gates/check-language.sh` (gate-keepers section 14;
   the CI `gatekeepers` job runs the whole script wholesale).

## Pre-commit

```bash
./scripts/build.sh check-all
./scripts/gate-keepers.sh
```

`build.sh check-all` runs the Rust-side gates: toolchain check, cargo fmt
--check, cargo clippy --all-targets --all-features -D warnings, cargo test,
cargo audit + cargo deny (both skip with a warning when not installed),
the repository policy check (check-policy.py), and the version-string
anti-pattern check. The `-q` / `--quiet` flag cuts the output down to
the essentials — per-check OK lines, warnings, failures, no banners — and is
the exact shape the CI "build.sh check-all -q" job runs (NIGHT-boost-7;
renamed from "Lint & Test" in NIGHT-boost-11): the gate
CI enforces and the gate the owner runs before a commit are one
invocation, so the two can never drift apart.

`gate-keepers.sh` runs the 17 non-code gate sections — the shell triad
(bash -n + shellcheck + shfmt) on shell scripts, yamllint + actionlint
on workflows, TOML validation,
codespell, SPDX license headers (check-headers.sh), file permission guard
(644 files / 755 executables and directories), the repo-wide emoji sweep,
the 500-line Rust LOC cap (check-loc.sh), the toolchain-pin sync check
(check-rust-version-sync.sh — both pin families, the stable toolchain and
the eBPF nightly, NIGHT-lts-9), rustfmt on the ebpf/ crate (the exact
CI-parity command the Gate-keepers workflow runs — the former
clang-format gate retired with the C sources in NIGHT-improve-1
phase 3), the documentation disclaimer
check (inject-disclaimer.sh), the test-tree discipline (NIGHT-hunt-17:
every .rs test file under the single `test/` tree), the English-only
language gate (check-language.sh), the python lint + format gate
(ruff, NIGHT-improve-13 cosmostrix parity: ruff check with the explicit
.ruff.toml rule set + ruff format --check at the scripts/ house width,
line 100), the 1000-line scripts LOC cap (check-scripts-loc.sh,
NIGHT-lts-2), and the release -C parity gate
(check-release-parity.sh, NIGHT-lts-9: the local pro-linux-amd64-*
aliases match the release matrix's codegen tokens). Missing tools
are skipped with a warning locally; the
Gate-keepers workflow (.github/workflows/gate-keepers.yml, unfiltered —
every push, docs-only included) runs the entire script wholesale with
every tool installed, so each section — current and future — is
enforced on every push. The build workflows carry the complementary
contract (NIGHT-boost-9, cosmostrix filter lineage): ci.yml's
`paths:` filter covers the surfaces its jobs compile or execute —
the Rust trees, the cargo manifests, deny.toml, and the whole
`scripts/**` tree as ONE directory glob (never a list of hardcoded
filenames: every new script a CI step consumes is covered without a
filter edit, and a missed edit would mean a silently skipped run);
every other change (docs, lint configs) rides the Gate-keepers
workflow alone and skips the compilers it cannot affect.

The third contract is the Supermassive workflow
(.github/workflows/supermassive.yml, NIGHT-ultimate-3's re-issued
label consolidated in NIGHT-improve-31; see the retired e2e.yml /
e2e-kernel-floor.yml headers in git history for the two-workflow
era): where the other workflows prove the CI-shaped surfaces with
CI-shaped steps, supermassive.yml proves the OWNER-FACING path —
it runs `scripts/setup.sh` itself (rustup resolving the toolchain
pin, bootstrap installing the dated nightly + bpf-linker into
$HOME, the static musl flagship twin) and then BOTH supermassive
batteries inside a KVM micro-VM (the ubuntu:22.04 container as its
userland), under two resource envelopes DERIVED from the runner at
boot time (NIGHT-improve-33, the owner's "cpu core, ram, etc don't
set fixed let dynamic"; the small envelope is renamed low —
NIGHT-blade-3) — low specs (a quarter of the cores
floored at 1 + an eighth of the RAM floored at 1024 MB, booting the
TRUE documented floor kernel: impish indri 5.13 from the frozen
old-releases archive) and best specs (every core + three quarters
of the RAM, booting the archive's LATEST kernel, resolved
dynamically at run time — the dists index, each Release's
Date+Codename, the two newest distinct codenames, and the newest
generic unsigned image across their main + -updates pockets wins
via sort -V) — so the kernel span (5.13 floor to latest head) and
the machine span are proven per push. Its `paths:` filter is the
binary-shaping surface plus the harness itself (src/, ebpf/, the
cargo manifests, the toolchain pins, the setup/bootstrap/linker
scripts, the supermassive tree, the shared lib, the CI init
scripts, and the workflow's own file); `workflow_dispatch` fires
the whole pair on demand — the pre-release machine-qualification
run.

The fourth contract is the release pipeline itself
(.github/workflows/release.yml, hardened in NIGHT-lts-9): a tag
push builds the four arch-baseline packages under invariants the
workflow enforces by itself, fail-closed. The version contract
holds at TWO levels — Cargo.toml's package version must equal the
tag BEFORE any compile cost is spent (the pre-build check), and
the built artifact must name the tag's version in its own self
report AFTER the build (the v3 legs execute `-V` and grep the
`zelynic: vX.Y.Z` header; the AVX-512 v4 legs, which a runner may
be unable to execute, grep the embedded version literal in the
bytes). The toolchain contract covers BOTH pin families: the
stable toolchain via RUST_VERSION (checked by
check-rust-version-sync.sh) and the dated eBPF nightly across all
nine of its sites — the workflow installs, build.rs's
EBPF_TOOLCHAIN const, install.sh, uninstall.sh, and
ebpf/rust-toolchain.toml as the authority (a half-bumped pin means
CI installs one nightly while build.rs invokes another). The
signing contract confines the GPG passphrase to the two steps that
use it — it never enters GITHUB_ENV, so no later step (including
the third-party upload-artifact action) ever sees it; only the
public key id crosses steps. And the parity contract
(check-release-parity.sh, gate 17) keeps the local
`cargo pro-linux-amd64-*` aliases' -C codegen tokens equal to the
release matrix's rustflags, so the README's "a local build
reproduces the release artifact's optimization tier" is enforced,
not asserted.

## Branch Strategy

The branch table lives once in the
[README](README.md#branches) — `main`, pure eBPF v11.x, maintenance
mode (branch history and the retired `intergalaxion` note are in
[docs/COSMIC_DRAGON_ARCHITECTURE.md](docs/COSMIC_DRAGON_ARCHITECTURE.md)).
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
