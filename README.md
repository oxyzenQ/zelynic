<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

<p align="center">
  <img src="assets/zelynic-logo-master.png" alt="zelynic logo" width="260">
</p>

<h1 align="center">zelynic</h1>

<p align="center">
  <strong>Per-app network rate limiter and traffic monitor for Linux. Pure eBPF. Silent but killer.</strong>
</p>

<p align="center">
  One of the first open-source Linux bandwidth managers built around a pure eBPF datapath
  with per-application rate limiting, live traffic monitoring, fractional precision, and
  zero-daemon enforcement.
</p>

<div align="center">

> Run anything you like. Launch whatever you want.\
> The dragon counts every byte that leaves the den —\
> and the ledger never lies.

</div>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

---

## Why zelynic?

Traditional tools limit interfaces. zelynic limits **applications**.

Brave can be limited to 100 KB/s while Firefox runs at full speed — all on the
same WiFi interface. No `tc`, no `nftables`, no `LD_PRELOAD`, no daemon.

### What makes zelynic sharp

| Edge | Detail |
|------|--------|
| **Pure eBPF datapath** | Zero intermediaries. The kernel IS the rate limiter. |
| **Pinned bpf_links** | Enforcement survives process exit — no daemon, no battery drain. |
| **Fractional precision** | 0.00% rate error, sub-byte token accumulation (benchmarks: docs/PERFORMANCE.md). |
| **Schema migration** | BPF struct changes auto-detected + auto-cleaned on upgrade. |
| **Crash recovery** | `zelynic recover` detects + removes orphaned BPF pins. |
| **Discovery workflow** | `zelynic top` (live box) finds bandwidth hogs — other limiters can't discover. |
| **Box mode** | In-place refresh, clean exit, responsive layout; selection/copy physics documented in the [USAGE FAQ](docs/USAGE.md#faq) (NIGHT-hunt-7, improve-7/8). |
| **Always-live monitors** | `observe`/`top` run live until you press `q` — no timers, no snapshot mode. |
| **Diff-based rendering** | Only changed rows are emitted — one write syscall per frame, idle frames cost zero I/O (NIGHT-improve-2). |
| **Refresh control** | `--interval 1s..60s` on `observe`/`top`, with a live RATE column. |
| **Eagle-eyes detail** | Monitor rows name the processes and endpoints INSIDE a cgroup — `curl (4012) -> 142.250.191.78:443` (NIGHT-hunt-8). |
| **Strict dependency diet** | 7 direct deps, 54 lockfile crates, every one justified in [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md). |

### Dependency policy (supply chain)

Dependencies are attack surface (NIGHT-hunt-6): every direct dependency
needs live call sites recorded in
[docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md), features are trimmed
to what is actually used, and time crates are banned (`-V`'s build stamp
is computed in `build.rs`). `cargo deny check all` runs over the full
feature graph in CI — the rules and evidence live in the audit doc and
[CONTRIBUTING.md](CONTRIBUTING.md), told once there.

### vs traditional tools

| Tool | Technology | Per-app? | Daemon? | Precision |
|------|-----------|----------|---------|-----------|
| `tc` | HTB/TBF qdisc | Per-interface | No | Integer |
| `nftables` + `tc` | Mark + shape | Complex setup | No | Integer |
| `wondershaper` | tc wrapper | Global only | No | Integer |
| `trickle` | LD_PRELOAD | Dynamic only | No | Integer |
| **zelynic** | **Pure eBPF** | **Per-cgroup** | **No** | **0.00%** |

## Quick Start

New here? Skim the [Complete Usage Guide](docs/USAGE.md) — especially its
[honest limitations](docs/USAGE.md#honest-limitations--read-this) section
before relying on a limit.

### Requirements

- Linux kernel 5.13+, cgroup v2, root — the full matrix and why each
  piece is needed: [docs/KERNEL_COMPATIBILITY.md](docs/KERNEL_COMPATIBILITY.md)
- Python 3 for the test/benchmark scripts (stdlib only)

Unsure about your kernel? `zelynic doctor` says yes or no with the exact
reason ([Kernel Compatibility](docs/KERNEL_COMPATIBILITY.md) has the full
matrix and troubleshooting).

### Install from a release (recommended)

Each release ships a self-contained tarball — the pure-Rust eBPF objects
are embedded in the binary, so no toolchain, no clang, no cargo is needed
on the target machine:

```bash
tar -xzf zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz   # or -musl for old glibc
cd zelynic-vX.Y.Z-linux-amd64-gnu
./install.sh --user                                # ~/.local/bin (default)
# or: ./install.sh --system                        # /usr/bin (sudo internally)
```

Each release tarball carries three checksums (SHA-512 + BLAKE2b-512 +
SHAKE256). Verify before installing — the one-liners live in
[Release Verification](#release-verification) below and in
[docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md), told once there.

### Install from source

Building needs the pinned Rust toolchain (rustup installs the exact
version from `rust-toolchain.toml`) plus the eBPF nightly pair — and
one command readies the whole host: the prerequisites, the PATH fix,
and the flagship binary itself (NIGHT-improve-16):

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic

# One-time host setup, COMPLETE: the dated nightly pin from
# ebpf/rust-toolchain.toml + the bpf-linker 0.11.1 prebuilt into
# ~/.local/bin (no sudo, no system LLVM) + the PATH fix persisted
# to ~/.profile + the flagship build — bootstrap ends ready to test:
./scripts/bootstrap-ebpf.sh
# (binary lands in target/pro-native-gnu/zelynic)

# Plain release-profile build (the manual alternative — the BPF
# objects are built pure-Rust, aya-ebpf nested nightly build in
# build.rs, and embedded into the binary):
cargo build --release --features ebpf
```

#### Native-CPU host builds

For a binary compiled specifically for the host CPU (maximum
performance on the machine it runs on, cosmostrix `pro-native`
lineage):

```bash
# Dynamic linking (glibc) — lands in target/pro-native-gnu/zelynic
cargo pro-native-gnu

# Static linking (musl) — lands in
# target/x86_64-unknown-linux-musl/pro-native-musl/zelynic
cargo pro-native-musl
```

Both aliases build the full flagship binary (`--features ebpf`,
same optimization tier as release) with `-C target-cpu=native`, and
report their build label in the version output:

```bash
$ ./target/pro-native-gnu/zelynic -V
Build: local-native-gnu (<hash>)
Build-time: 9/18/2026 01:30 (UTC)
```

The `Build-time` line is stamped at compile time in `build.rs` — UTC
only, no time crate in the dependency tree (see the
dependency policy above).

A native build never clobbers `target/release/zelynic` — the separate
profile names keep both binaries side by side. The `-C
target-cpu=native` tune applies to the host binary only: build.rs
strips host-CPU and host-linker rustflags from the nested eBPF
build's environment before invoking it (NIGHT-hunt-28), so the bpfel
objects are identical no matter which alias built them. Note: a
native binary only runs on the CPU family it was compiled for; ship
the plain release build for distribution.

### Usage

Every command, once — flags live in `--help`, formats in
[Rate Formats](#rate-formats), the full workflows in
[docs/USAGE.md](docs/USAGE.md):

```bash
# Limit one app — positional rate sets BOTH download + upload
sudo zelynic strict-single brave 100kb        # 'strict' is the shorthand
sudo zelynic strict-single firefox -d 1mb -u 500kb   # per-direction

# Group limit — several apps share ONE rate
sudo zelynic strict-multi brave:curl:pacman 1mb

# Every user app at once (system apps excluded unless --force)
sudo zelynic limit-all 500kb

# Block apps from the internet entirely
sudo zelynic block-single brave
sudo zelynic block-multi brave:curl
sudo zelynic block-all

# Live monitors (box mode, q to quit) — top talkers / all traffic
sudo zelynic top --interval 2s
sudo zelynic observe --cgroup 73386   # zoom into one cgroup

# Unlock — one app / a group / everything
sudo zelynic unstrict-single brave
sudo zelynic unstrict-multi brave:curl
sudo zelynic unstrict-all            # emergency reset

# State: active limits, apps with cgroup IDs, eBPF support
sudo zelynic status --print-json | jq '.limits[]'
sudo zelynic list-apps
sudo zelynic doctor

# Recover from a crash (clean orphaned BPF pins)
sudo zelynic recover
```

Monitors are always live; the CLI surface is frozen (v11) — the
removed surfaces (`man`, `completions`, `unblock`, `-i/--info`,
`--live`, `--duration`) exit with a usage error on purpose. Command
semantics, quit keys, and recipes: [docs/USAGE.md](docs/USAGE.md);
`--help` is the single flag reference.

Global flags work on every command: `-v/--verbose` (diagnostic trace),
`--print-json`, `--help`, `-V/--version`, and `--check-update` — which
**refuses to run as root** (a plain network fetch must not ride sudo;
full privilege matrix: [docs/SAFETY_ANALYSIS.md](docs/SAFETY_ANALYSIS.md)).

## Rate Formats

Lowercase units only (decimal SI: 1 KB = 1000 bytes):

| Format | Meaning |
|--------|---------|
| `500b` | 500 bytes/second |
| `100kb` | 100 kilobytes/second |
| `1mb` | 1 megabyte/second |
| `1gb` | 1 gigabyte/second |
| `100gb` | 100 gigabytes/second |
| `1tb` | 1 terabyte/second |

**Bounds**: minimum 1 KB/s, maximum 1 TB/s, both overridable with
`--allow-dangerous` (told once — parsing details and error tips live
in `--help` and [docs/USAGE.md](docs/USAGE.md)).

Monitor `--interval` accepts the same duration formats, bounded to
1s..60s (a live monitor is neither a spam flood nor a screenshot) —
see [docs/USAGE.md](docs/USAGE.md) `observe`/`top`.

## Limitations (honest)

zelynic is deliberately small and stateless — the full eleven-item
list, with examples and the exact snapshot rule, lives in
[USAGE.md](docs/USAGE.md#honest-limitations--read-this). In one
breath: rules are a snapshot (new apps need a re-run), limits do not
survive reboot, name resolution needs the app running, one name can
match several cgroups, rates are decimal SI per direction, monitoring
surfaces need root too, and status counters are cumulative evidence.

## Safety Features

- **Rate bounds guard**: 1 KB/s..1 TB/s, `--allow-dangerous` overrides
- **Fail-safe BPF**: returns "allow" on any error path (never blocks on failure)
- **Dangerous target protection**: 57 system processes blocked by default
- **Overflow detection**: absurd rates show a friendly warning, not wrapped values
- **File lock**: prevents concurrent operations from corrupting BPF state
- **Kernel version detection**: graceful fallback for kernel < 5.7 (legacy bpf_prog_attach)

(Fire-and-forget, crash recovery, and schema migration are already in
the feature table above; the full audit trail is
[docs/SAFETY_ANALYSIS.md](docs/SAFETY_ANALYSIS.md).)

## Architecture

**Dragon Architecture** — pure eBPF, no intermediaries:

```
┌───────────────────────────────────────────────────┐
│  Layer 4 — CLI                                    │
│  strict-single / block / top / observe / status   │
├───────────────────────────────────────────────────┤
│  Layer 3 — Aggregation (delta, sort, format)      │
├───────────────────────────────────────────────────┤
│  Layer 2 — Identity (/proc → cgroup ID)           │
├───────────────────────────────────────────────────┤
│  Layer 1 — Map Interface (aya, pinned maps)       │
├───────────────────────────────────────────────────┤
│  Layer 0 — BPF (kernel)                           │
│  cgroup_skb/ingress + cgroup_skb/egress           │
└───────────────────────────────────────────────────┘
```

## Philosophy

**Boring and silent but killer.**

zelynic is a Linux utility that is simple from the user's perspective,
but powerful under the hood. The interface rarely changes. Features don't
explode. Every release makes it slightly more stable, slightly faster,
slightly easier to maintain.

### What zelynic IS

- **Single CLI binary** — no daemon, no service, no config file
- **Pure eBPF** — no tc, no nft, no wrappers
- **Small codebase** — minimal dependencies, easy to audit
- **Predictable behavior** — same input → same output, every time
- **Linux-only at runtime** — the `ebpf` feature is a no-op
  elsewhere; BSD/macOS and Windows are out of scope, ever

### What zelynic will NEVER be

- No TUI (terminal user interface)
- No systemd service dependency
- No `config.toml` (CLI flags only)
- No daemon mode
- No REST API
- No non-Linux support

### Stable API (from v11.0.0)

Starting with v11.0.0, the CLI surface is frozen. No breaking changes
to commands, flags, or output format. Future releases focus on:
- Bug fixes
- Kernel compatibility updates
- Performance improvements (internal, no API changes)

### Maintenance Mode (from v11.0.0)

> **Zelynic v11 marks the beginning of maintenance mode. Future releases
> prioritize stability, compatibility, performance, and bug fixes over
> feature expansion.**

No new features unless critical for security or compatibility.
Release cadence slows to "when needed".

### Release channels

Stable releases are tagged `vX.Y.Z`. Pre-release builds are restricted to
four channels — `dev`, `nightly`, `alpha`, `beta` (e.g. `v11.0.0-dev.1`).
CI rejects any other suffix and never marks a pre-release as "latest".

## Branches

| Branch | Purpose | Status |
|--------|---------|--------|
| `main` | Pure eBPF v11.x (Dragon Architecture) | Maintenance mode |

## Contributing

PRs and issues are welcome. The bar is the gate suite — build, test,
conventions, and the full script inventory are documented once in
[CONTRIBUTING.md](CONTRIBUTING.md); project conventions also live in
[docs/RULES.md](docs/RULES.md).

## Security

zelynic runs as root and programs the kernel datapath, so security is
part of the product. Found something? **Report it privately** — the
policy, supported versions, and what counts as a vulnerability live in
[SECURITY.md](SECURITY.md); the audit trail and the privilege matrix
(who needs root where, and the one surface that refuses it) live in
[docs/SAFETY_ANALYSIS.md](docs/SAFETY_ANALYSIS.md).

## Documentation

- [Complete Usage Guide](docs/USAGE.md) — every command, workflows, honest limitations, troubleshooting (the flagship reference)
- [Security Policy](SECURITY.md) — reporting, scope, supported versions
- [Dragon Architecture](docs/DRAGON_ARCHITECTURE.md) — design + principles
- [Kernel Compatibility](docs/KERNEL_COMPATIBILITY.md) — requirements + distro matrix
- [Performance Metrics](docs/PERFORMANCE.md) — deep benchmark results + targets
- [Cross-Distro Results](docs/CROSS_DISTRO_RESULTS.md) — the 6-distro validation record
- [Dependency Audit](docs/DEPENDENCY_AUDIT.md) — every direct dependency justified
- [Release Verification](docs/VERIFY_RELEASE.md) — checksum verification
- [Contributing Guide](CONTRIBUTING.md) — gates, conventions, script inventory

## Test Results

Verified on 6 distributions — every one passed the depth and leak
suites, and real enforcement was measured against live browsers
(the full record, per-distro details, and the accuracy table live in
[docs/CROSS_DISTRO_RESULTS.md](docs/CROSS_DISTRO_RESULTS.md), told
once there):

| Distro | Kernel | Binary | Enforcement |
|--------|--------|--------|-------------|
| Arch Linux | 6.18 | GNU | brave 100kb → 730 Kbps |
| CachyOS VM | 7.1 | MUSL | chromium 360kb → 3.0 Mbps |
| Ubuntu 26.04 | 7.0 | GNU | firefox 100kb → 650 Kbps |
| Fedora 44 | 6.19 | GNU | firefox 100kb → 690 Kbps |
| Ubuntu 21.10 | 5.13 | MUSL | GeckoMain 100kb → 770 Kbps |
| Debian 13 | 6.12 | MUSL | firefox-esr 900kb → 7.0 Mbps |

Want to depth-verify your own machine (or a VM, or a friend's distro)?
One command, no external test server — loopback traffic in an isolated
test cgroup, measured rate accuracy, kernel-drop proof, BPF accounting,
sustained stability, residue (NIGHT-master-1):

```bash
sudo ./scripts/limiter-depth-test.sh          # full run (~2 min)
sudo ./scripts/limiter-depth-test.sh --quick  # fast pass (~45s)
```

Want to supermassive-test the whole command surface — single/multi targets,
strict/block/unstrict, curl burst download + upload, the full rate range
1kb to 1tb (skipping rungs the hardware cannot feed), every rate-guard
function (bounds, typo tip, dangerous blocklist, plain-number,
--allow-dangerous override), and both per-direction buckets
(-d / -u / asymmetric -d+-u)? One click (NIGHT-master-2):

```bash
sudo ./scripts/supermassive-test.sh                # light (~2 min)
sudo ./scripts/supermassive-test.sh --heavy        # supermassive (5+ min)
./scripts/supermassive-test.sh --self-test          # engine smoke, no root
```

The harness always tests the checkout's own build: repo target
outputs resolve first (newest build wins), and a version GATE
refuses any binary whose `-V` doesn't match the checkout's
Cargo.toml — a stale distro install can never masquerade as the
build under test (NIGHT-improve-16).

## Release Verification

Each release ships three checksums: classical SHA-512 + quantum-resistant
BLAKE2b-512 + SHAKE256. The universal check is one command —

```bash
sha512sum -c zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.sha512sum
```

— and the two quantum-resistant one-liners plus the algorithm rationale
live in [docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md), told once there.

## Support

zelynic is an open-source project built and maintained independently by [rezky_nightky (oxyzenQ)](https://github.com/oxyzenQ).

If this project helped you, or tamed your bandwidth, you can support future maintenance here:

[![Support me on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/rezky)

### Crypto donations

Owner-verified receive addresses (rezky_nightky / oxyzenQ). All three passed offline cryptographic verification (EIP-55 mixed-case checksum for Ethereum, bech32m witness-v1 for Taproot, base58-to-32-byte ed25519 key for Solana). Always double-check the address on screen before sending — network mismatches (e.g., sending USDT-ERC20 to a Solana address, or sending BTC to a non-Taproot address) will permanently lose funds.

- **Solana** — `SOL` / `USDT` (SPL) on Solana mainnet: `88umzS7abaToaGQVgTVXt5SnuvcjTw2jPSM6Ha2JYmXM`
- **Ethereum** — `ETH` / `USDT` (ERC-20) / `USDC` (ERC-20) on Ethereum mainnet: `0x1bCbA21c07B5636a942De27AA7Ee8283cEDb4C3D`
- **Bitcoin** — `BTC` on Taproot (P2TR, bech32m, `bc1p`-prefixed — verified Taproot, not native SegWit): `bc1p88nqysn4p8u9zxwz2pyxs5pl77wllcrk6ca2r2l3ryr3863hxkys5vdkze`

Support is optional. The project remains open-source.

## Intellectual Property & Trademark

**zelynic** is the exclusive intellectual property of
**rezky_nightky (oxyzenQ)**. Source code is licensed under
**GPL-3.0-only** (see [LICENSE](LICENSE)); the name, logo, and branding
(the Marks) are governed by [TRADEMARK.md](TRADEMARK.md), are NOT
covered by the GPL, and are reserved by the owner. This project is
**NOT for sale** — unauthorized rebranding, relicensing, or
source-code theft is strictly prohibited.

The short version of the fork policy: unmodified redistribution with
attribution is allowed under the GPL; forks and derivatives must
rename away from "Zelynic", drop the logo/artwork, and attribute the
original. The binding detail lives once in
[TRADEMARK.md](TRADEMARK.md) (§2 permitted uses, §3–§4 approval +
renaming rules), including the suggested attribution format and how to
request permission.

For trademark licensing or written permission, contact
**rezky_nightky (oxyzenQ)** — <https://github.com/oxyzenQ>.

Copyright (C) 2026 rezky_nightky (oxyzenQ). All rights reserved.

## License

GPL-3.0-only

## Author

**rezky_nightky (oxyzenQ)** — built with curiosity, not pressure.

---

<p align="center">
  <em>Simple from the user's perspective. Powerful under the hood.</em>
</p>
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
