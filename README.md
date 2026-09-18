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
| **Pinned bpf_links** | Enforcement survives process exit. No daemon, no battery drain. |
| **Fractional precision** | 0.00% rate error. Sub-byte token accumulation. Others lose ~0.7%. |
| **Schema migration** | BPF struct changes auto-detected + auto-cleaned on upgrade. |
| **Crash recovery** | `zelynic recover` detects + removes orphaned BPF pins. File lock prevents corruption. |
| **Discovery workflow** | `zelynic top` (live box) finds bandwidth hogs. Other limiters can't discover. |
| **Box mode** | In-place refresh with a clean exit — zero scrollback pollution, no TUI. Responsive layout adapts to any terminal size (NIGHT-hunt-7). |
| **Always-live monitors** | `observe`/`top` run live until you press q — no timers, no snapshot mode (NIGHT-hunt-12). |
| **Refresh control** | `--interval 1s..60s` on `observe`/`top` — realtime cadence you choose, with a live RATE column computed from the interval. |
| **Eagle-eyes detail** | Monitor rows name the processes and endpoints INSIDE a cgroup — `curl (4012) -> 142.250.191.78:443` under a row labeled alacritty (NIGHT-hunt-8). |
| **Strict dependency diet** | 7 direct deps, 54 lockfile crates, every one justified in [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md). |

### Dependency policy (supply chain)

zelynic treats dependencies as attack surface (NIGHT-hunt-6). The rules:

- Every direct dependency has live call sites, recorded in
  [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md).
- No time crates: the `Build-time` stamp in `-V` is computed by Howard
  Hinnant's civil-from-days algorithm in `build.rs` (chrono was removed
  with zero call sites — it kept 27 crates in the lockfile for nothing,
  and is now banned in `deny.toml`).
- `cargo deny check all` runs over the full feature graph (including the
  eBPF subtree) in CI; re-adding chrono fails the build.

### vs traditional tools

| Tool | Technology | Per-app? | Daemon? | Precision |
|------|-----------|----------|---------|-----------|
| `tc` | HTB/TBF qdisc | Per-interface | No | Integer |
| `nftables` + `tc` | Mark + shape | Complex setup | No | Integer |
| `wondershaper` | tc wrapper | Global only | No | Integer |
| `trickle` | LD_PRELOAD | Dynamic only | No | Integer |
| **zelynic** | **Pure eBPF** | **Per-cgroup** | **No** | **0.00%** |

## Quick Start

### Prerequisites

- Linux kernel 5.13+ (cgroup v2 + `cgroup.id` file + bpf_link support)
- Root access (BPF requires `CAP_BPF`)
- `clang` (compile BPF programs)
- `libbpf-dev` (BPF headers)

### Build

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic

# Compile BPF programs (same command as CI; the -I flag resolves
# multiarch kernel headers on Debian/Ubuntu)
ARCH="$(uname -m)"
clang -O2 -g -target bpf -I"/usr/include/${ARCH}-linux-gnu" \
  -c bpf/observer.bpf.c -o bpf/observer.bpf.o
clang -O2 -g -target bpf -I"/usr/include/${ARCH}-linux-gnu" \
  -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o

# Build Rust binary
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

The `Build-time` line is stamped at compile time by the Hinnant
civil-from-days algorithm in `build.rs` — UTC only, no time crate in
the dependency tree (see the dependency policy above).

A native build never clobbers `target/release/zelynic` — the separate
profile names keep both binaries side by side. Note: a native binary
only runs on the CPU family it was compiled for; ship the plain
release build for distribution.

### Usage

```bash
# Limit a single app (both download + upload = 100kb)
# ('strict' is the shorthand for strict-single)
sudo zelynic strict-single brave 100kb
sudo zelynic strict brave 100kb

# Limit per-direction
sudo zelynic strict-single firefox -d 1mb -u 500kb

# Limit multiple apps sharing one rate (group limit)
sudo zelynic strict-multi brave:curl:pacman 1mb

# Limit ALL user apps
sudo zelynic limit-all 500kb

# Find what's eating your bandwidth (live box, q to quit)
sudo zelynic top

# Live top with a 2s refresh instead of the 5s default
sudo zelynic top --interval 2s

# Monitor traffic in alt screen (UL + DL, clean terminal)
sudo zelynic observe

# Same monitor, calmer cadence + rate column scaled to the interval
sudo zelynic observe --interval 5s

# Zoom into one cgroup: full process + endpoint detail
sudo zelynic observe --cgroup 73386

# Block an app from internet entirely
sudo zelynic block-single brave

# Check active limits
sudo zelynic status

# JSON output (for scripts)
sudo zelynic status --print-json | jq '.limits[]'

# Remove one app's limit
sudo zelynic unstrict brave

# Remove ALL limits (emergency)
sudo zelynic unstrict-all

# Recover from crash (clean orphaned pins)
sudo zelynic recover

# Check eBPF support
sudo zelynic doctor
```

## Commands

```
strict-single <target> [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
              ('strict' is the shorthand for strict-single)
strict-multi  <a:b:c>  [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
limit-all              [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
block-single <target> [--force]
block-multi  <a:b:c>   [--force]
block-all              [--force]
unstrict <target>       ('unstrict-single' is an alias)
unstrict-multi <a:b:c>
unstrict-all
recover
status [--print-json]
list-apps [--print-json]
observe [--cgroup <id>] [--interval <1s-60s>]
top [--limit N] [--interval <1s-60s>]
doctor [--print-json]
```

Monitors are always live (NIGHT-hunt-12): the former `--live`/`--duration`
timers — and the `man`, `completions`, `unblock`, `-i/--info` surfaces —
are removed. `--help` is the single reference; quit a monitor box with
`q` (Ctrl+C also exits).

Global flags work on every command: `-v/--verbose` (diagnostic trace),
`--print-json`, `--help`, `-V/--version`, and `--check-update` — which
**refuses to run as root**: it is a plain network fetch, so re-run it
without `sudo` (see docs/SAFETY_ANALYSIS.md for the full privilege
matrix).

## Rate Formats

Lowercase units only (decimal SI: 1 KB = 1000 bytes):

| Format | Meaning |
|--------|---------|
| `500b` | 500 bytes/second |
| `100kb` | 100 kilobytes/second |
| `1mb` | 1 megabyte/second |
| `1gb` | 1 gigabyte/second |
| `100gb` | 100 gigabytes/second |

**Bounds**: minimum 1 KB/s, maximum 100 GB/s. Both overridable with `--allow-dangerous`.

## Refresh Intervals

`--interval` (observe, top) accepts the same duration formats — plain
seconds, `2s`, `1m` — but must land between 1s and 60s: below 1s spams
full-frame redraws, above 60s stops being a live monitor.
Out-of-range values fail fast with the bounds in the message.

### Inside a cgroup (NIGHT-hunt-8)

BPF counters are per-cgroup, and on systemd a whole terminal
session shares one cgroup — a row labeled `alacritty` may be
carrying `curl` traffic. Monitor rows therefore show what lives
inside: a `+N` process-count suffix on the label, and per-process
socket detail lines with remote endpoints (TCP/UDP, busy flags).
`observe --cgroup <id>` zooms in with the uncapped view, and
`list-apps` carries PROCS/SOCKETS columns so the multi-tenancy is
visible at discovery time.

## Safety Features

- **Min-rate guard**: rejects rates below 1 KB/s (prevents bricking apps)
- **Max-rate guard**: rejects rates above 100 GB/s (unreasonable defaults)
- **Fire-and-forget**: `strict-single` exits 0, limit persists in background
- **No residue**: `unstrict-all` removes all pin files + directory
- **Fail-safe BPF**: returns "allow" on any error path (never blocks on failure)
- **Dangerous target protection**: 57 system processes blocked by default
- **Overflow detection**: absurd rates show friendly warning, not wrapped values
- **Crash recovery**: `zelynic recover` detects + cleans orphaned BPF pins
- **File lock**: prevents concurrent operations from corrupting BPF state
- **Schema migration**: BPF struct changes auto-detected + auto-cleaned on upgrade
- **Kernel version detection**: graceful fallback for kernel < 5.7 (legacy bpf_prog_attach)

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
- **Linux-first** — BSD/macOS source support OK, never anything else

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
| `legacy` | v3.1.1 (tc/nft/systemd-wrapper) | Final legacy release, no new development |

## Documentation

- [Dragon Architecture](docs/DRAGON_ARCHITECTURE.md) — design + principles
- [Kernel Compatibility](docs/KERNEL_COMPATIBILITY.md) — requirements + distro matrix
- [Performance Metrics](docs/PERFORMANCE.md) — deep benchmark results + targets
- [Migration to v4.0](docs/MIGRATION_V4.md) — v3.x → v4.0 guide
- [Release Verification](docs/VERIFY_RELEASE.md) — checksum verification

## Test Results

Verified on 6 distributions (all pass 17/17 depth + 13/13 leak tests):

| Distro | Kernel | Binary | Enforcement |
|--------|--------|--------|-------------|
| Arch Linux | 6.18 | GNU | brave 100kb → 730 Kbps |
| CachyOS VM | 7.1 | MUSL | chromium 360kb → 3.0 Mbps |
| Ubuntu 26.04 | 7.0 | GNU | firefox 100kb → 650 Kbps |
| Fedora 44 | 6.19 | GNU | firefox 100kb → 690 Kbps |
| Ubuntu 21.10 | 5.13 | MUSL | GeckoMain 100kb → 770 Kbps |
| Debian 13 | 6.12 | MUSL | firefox-esr 900kb → 7.0 Mbps |

## Release Verification

Each release ships **three** checksums: classical SHA-512 + quantum-resistant
BLAKE2b-512 + SHAKE256. Full instructions in
[docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md).

```bash
# Classical (universal)
sha512sum -c zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.sha512sum

# Quantum-resistant — BLAKE2b (fastest, in coreutils)
b2sum -c zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.b2sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "OK" || echo "FAILED"
```

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

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
