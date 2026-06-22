<p align="center">
  <img src="assets/zelynic-logo-master.png" alt="zelynic logo" width="260">
</p>

<h1 align="center">zelynic</h1>

<p align="center">
  <strong>Per-process network shaping and bandwidth control for Linux.</strong>
</p>

<p align="center">
  Built on <code>tc</code>, <code>nftables</code>, and cgroup v2 to make per-process network behavior visible, predictable, and controllable from the terminal.
</p>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

---

## Overview

zelynic is a Rust CLI tool for **observing and controlling network bandwidth per process on Linux**.

It provides:

- real-time per-process bandwidth monitoring
- traffic shaping using Linux `tc` (HTB qdisc)
- packet classification via `nftables`
- process-aware control using `cgroup v2`
- live terminal dashboard similar to `htop`, focused on network usage

This tool is designed for **system-level observability and control**, not application-level networking.

## Core Capabilities

- **Per-process bandwidth control** — Attach bandwidth limits directly to running processes using cgroup-aware classification. (`zelynic strict`)
- **Traffic shaping engine** — Powered by Linux `tc` (HTB qdisc) for deterministic rate limiting.
- **Packet marking & routing control** — Uses `nftables` for classifying and tagging traffic flows.
- **Real-time network observability** — Built on `ss` + kernel metrics for live throughput tracking. (`zelynic list --live`)
- **QoS priority shaping** — Assign priority tiers instead of hard limits; idle bandwidth redistributes automatically. (`zelynic qos`)
- **Auto-throttle daemon** — Background mode that enforces thresholds when aggregate usage spikes. (`zelynic auto`)
- **Threshold alerts** — Watch bandwidth and alert when limits are exceeded. (`zelynic watch`)
- **Named profiles** — Reusable bandwidth profiles (gaming, streaming, background). (`zelynic profile`)
- **TUI dashboard** — htop-like interface showing process network usage, active limits, and live throughput per PID.

## Architecture

zelynic operates through three system layers:

```
┌─────────────────────────────────────────────────────────┐
│  Process Layer (cgroup v2)                              │
│  Maps processes to controllable network groups          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  Classification Layer (nftables)                        │
│  Marks packets based on process group identity          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  Shaping Layer (tc / HTB)                               │
│  Enforces bandwidth policies at kernel level            │
└─────────────────────────────────────────────────────────┘
```

## Philosophy

zelynic follows three principles:

- **Visibility First** — Every network action must be observable per process.
- **Deterministic Control** — Bandwidth behavior must be predictable under load.
- **Kernel-Aligned Design** — Leverages Linux-native primitives instead of reinventing networking logic.

## Quick Start

```bash
# List per-process network usage (default view)
zelynic list

# Real-time TUI dashboard (htop for network)
zelynic list --live

# Apply bandwidth limits to a process
zelynic strict -d 500kb -u 500kb brave
zelynic strict --preset gaming discord
zelynic strict -d 1mb firefox

# QoS priority shaping (no hard limits, priority-based)
zelynic qos high brave
zelynic qos low wget

# Show active limits
zelynic status

# Remove limits from a process
zelynic unstrict brave

# Refresh a limit after the target process respawns
zelynic refresh brave

# Plan a systemd scope wrapper (dry-run, non-mutating)
zelynic run --dry-run -d 500kbit -u 500kbit -- helium

# Auto-throttle daemon (background, threshold-based)
zelynic auto --download 100mb --upload 50mb

# Inspect host capabilities (read-only)
zelynic backend doctor
```

## Use Cases

- Limit bandwidth per application
- Control background process network usage
- Enforce QoS-like behavior locally
- Debug network-heavy processes
- Observe per-process network spikes
- Auto-manage bandwidth on unattended systems

## Safety Model

- No silent modifications — every change is logged and reversible.
- All `zelynic run` actions are simulated by default (`--dry-run`); live execution requires explicit opt-in.
- `zelynic strict` is the only validated active limiter path; `zelynic run --execute` remains experimental and non-mutating until live execution is deliberately implemented.
- Use `zelynic strict --diagnose` to print target PID selection, cgroup v2, nftables, and tc diagnostics when validating a new host.

## Requirements

- Linux with **cgroup v2** (uniform hierarchy)
- `nftables` ≥ 1.0
- `iproute2` / `tc` ≥ 5.10
- `systemd` (for `zelynic run` scope planning)
- Root or `CAP_NET_ADMIN` for active limiting (`zelynic strict`, `qos`, `auto`); read-only commands (`list`, `status`, `backend`) work unprivileged

See [docs/distro-matrix.md](docs/distro-matrix.md) for the full distribution support matrix with validation status.

## Installation

### From source

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic
./scripts/build.sh check-all
./scripts/install.sh
```

### From release tarball

Download the latest tarball and checksum from [releases](https://github.com/oxyzenQ/zelynic/releases), verify, extract, and run `./install.sh`.

### Shell completions

```bash
zelynic completions bash    # or zsh, fish
zelynic man                 # generate man page
```

## Documentation

- [Validation reports](docs/validation.md) — validated hosts and methodology
- [Distro matrix](docs/distro-matrix.md) — distribution support status
- [Scope Lab](docs/scope-lab.md) — `zelynic run` design and probe findings
- [Ledger inspect (phase 14)](docs/v3.1-phase-14-ledger-inspect-user-docs-examples-polish.md) — fixture-driven ledger inspection docs
- [Ledger export (phase 18)](docs/v3.1-phase-18-ledger-export-user-docs-examples-polish.md) — JSON export gate design
- [CHANGELOG](CHANGELOG.md) — release history

## Project Status

`zelynic strict` is validated on tested modern cgroup v2 hosts (CachyOS/Arch with kernel 6.18+, nftables 1.1+, tc 7.0+). Other modern systemd + cgroup v2 distributions are candidates pending explicit validation. See the [distro matrix](docs/distro-matrix.md) for details.

## License

GPL-3.0-only. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Linux-first • cgroup-aware • process-level control</sub><br>
  <sub>Part of the <a href="https://github.com/oxyzenQ">oxyzenQ</a> ecosystem.</sub>
</p>
