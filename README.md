> **Project status: active again**
>
> Zelynic is active again after the v2.0.0 Renaissance release. Core features such as monitor, list, profile, watch, QoS, auto-throttle, Backend Doctor, and per-process bandwidth limiting through `zelynic strict` have been validated on a modern Arch/CachyOS cgroup v2 host.
>
> **Validation scope:** strict limiting is validated on tested modern cgroup v2 systems, including CachyOS/Arch with kernel `6.18.33-1-cachyos-lts`, nftables `v1.1.6`, tc/iproute2 `7.0.0`, pure cgroup v2, and interface `wlp1s0`. This is not yet a universal all-distro guarantee.
>
> **Troubleshooting:** use `zelynic strict --diagnose ...` to print target PID selection, cgroup v2, nftables, and tc diagnostics when validating a host.

<p align="center">
  <img src="assets/zelynic-logo.png" alt="zelynic logo" width="240">
</p>

<h1 align="center">zelynic</h1>

<p align="center">
  <strong>Easy userspace bandwidth manager for Linux.</strong>
</p>

<p align="center">
  Monitor, shape, and inspect per-process network bandwidth from one focused terminal tool.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.1.0-7C3AED?style=flat-square&labelColor=111827" alt="Version v2.1.0">
  <img src="https://img.shields.io/badge/license-GPL--3.0-E040FB?style=flat-square&labelColor=111827" alt="GPL-3.0 license">
  <img src="https://img.shields.io/badge/platform-Linux%20x86__64-8B5CF6?style=flat-square&labelColor=111827" alt="Platform Linux x86_64">
  <img src="https://img.shields.io/badge/Rust-1.88+-A855F7?style=flat-square&labelColor=111827" alt="Rust 1.88+">
  <img src="https://img.shields.io/badge/status-active-22C55E?style=flat-square&labelColor=111827" alt="Status active">
</p>

zelynic is a Rust CLI tool for monitoring, limiting, and shaping per-process network bandwidth on Linux. It uses Linux traffic control (`tc`) with HTB qdisc, `nftables` for packet marking, and `cgroup v2` for process-aware rate limiting. Real-time monitoring is powered by `ss`, while the built-in TUI dashboard provides a live, htop-like view of network traffic.


---

## Renamed from Oxy

Zelynic was previously named Oxy. The old repository and package name were `oxy`, and the command is now `zelynic`. Runtime state, cgroups, and nftables identifiers now use the `zelynic` namespace; v2.0.0-era `oxy` runtime artifacts are treated as legacy cleanup targets.

## Renaissance Validation

The v2.0.0 Renaissance release validates `zelynic strict` on tested modern cgroup v2 systems. On CachyOS/Arch with kernel `6.18.33-1-cachyos-lts`, nftables `v1.1.6`, tc/iproute2 `7.0.0`, pure cgroup v2, and interface `wlp1s0`, Brave bandwidth limiting was observed within the expected range for both byte-based and bit-based limits.

This does not guarantee identical behavior on every Linux distribution. Hosts need cgroup v2, nftables, and tc support, and `zelynic strict --diagnose` should be used when validating or troubleshooting a new environment. See [docs/validation.md](docs/validation.md) for details.

## Backend Doctor

Zelynic detects host capabilities and recommends the safest available backend. The read-only Backend Doctor checks kernel, cgroup, nftables, tc, conntrack, systemd, and eBPF signals without modifying nftables, tc, or cgroups:

```bash
zelynic backend              # Summary and eBPF capability check
zelynic backend doctor       # Detailed capability matrix
zelynic backend doctor --json
```

The v2.2 development line also includes `zelynic run --dry-run` groundwork for
a future systemd scope wrapper mode. It prints the planned scope/cgroup wiring
and preview-only `systemd-run` launch command without launching a process or
modifying nftables, tc, cgroups, or state. User scope is the default planning
mode to avoid accidental system Polkit prompts; system scope can be previewed
explicitly with `--scope-mode system`. `zelynic run --execute` is gated as an
experimental opt-in and currently stops at a non-mutating not-implemented
boundary after printing an execution preflight. Full live limiting still needs a
privilege handoff design because user-scope launch and root-required limiter
attachment have different requirements. The likely future model is
launch-then-attach: systemd starts the command, then Zelynic attaches discovered
PIDs with the existing strict backend.

Support matrix:

| Host type | Status |
|-----------|--------|
| Arch/CachyOS pure cgroup v2 | Tested |
| Modern systemd + cgroup v2 distros | Expected |
| Older Ubuntu/Debian, hybrid cgroup, containers, WSL, non-systemd distros | Partial/unknown |
| systemd-scope backend, cgroup v1 fallback, eBPF backend | Future |

## Features

- **Monitor** bandwidth usage per process/program with cumulative and real-time rates
- **Limit** download and/or upload speeds per process with tc + nftables + cgroup v2
- **Experimental run planning** — preview future systemd scope wrapper wiring without runtime changes
- **QoS priority shaping** — assign high/low priority tiers instead of hard limits
- **TUI dashboard** — live bandwidth monitor with sparklines, scrolling, and dual RX/TX graphs
- **Auto-throttle daemon** — background mode that auto-limits when thresholds are exceeded
- **Watch & alert** — background monitor with desktop notifications on bandwidth thresholds
- **Bandwidth profiles** — save, load, and apply named bandwidth limit presets
- **Bandwidth logging** — snapshot and review historical bandwidth usage
- **Shell completions** — bash, zsh, fish, elvish, powershell
- **Man page generation** — roff format for system manual installation
- **Interface management** — auto-detect or explicitly specify network interfaces
- **Strict CLI validation** — invalid commands, interfaces, and values are rejected with clear errors
- Supports multiple bandwidth units: `byte/bs`, `kb`, `mb`, `gb`, `kbit`, `mbit`, `gbit`
- Built-in presets: `gaming`, `streaming`, `background`
- Clean, colored terminal output (respects `NO_COLOR`)
- JSON output mode for scripting integration
- Persistent state across invocations (survives restarts)

## Requirements

- **Linux** (kernel 5.4+ recommended for full cgroup v2 support)
- **Root privileges** (for bandwidth limiting, QoS, and auto-throttle operations)
- **iproute2** package (provides `tc` and `ip` commands)
- **nftables** (for packet marking on download limiting)
- **Rust 1.88+** (for building from source)

## Installation

### Download Release

Download the latest release from [GitHub Releases](https://github.com/oxyzenq/zelynic/releases):

```bash
# Download and extract
curl -sL https://github.com/oxyzenq/zelynic/releases/latest/download/zelynic-v2.1.0-x86_64-linux.tar.gz | tar xz

# Install system-wide
sudo install -Dm755 zelynic-v2.1.0-x86_64-linux/zelynic /usr/local/bin/zelynic
```

Verify the download with SHA256 checksums published alongside each release.

Release naming convention:

- Tag: `v2.1.0`
- Title: `Zelynic v2.1.0 Backend Doctor`

### From Source

```bash
git clone https://github.com/oxyzenq/zelynic.git
cd zelynic
cargo build --release

# Install system-wide
sudo install -Dm755 target/release/zelynic /usr/local/bin/zelynic
```

### Quick Build

```bash
cargo build --release
sudo install -Dm755 target/release/zelynic /usr/local/bin/zelynic
```

### Shell Completions

```bash
# Bash
zelynic completions bash | sudo tee /usr/share/bash-completion/completions/zelynic > /dev/null

# Zsh
zelynic completions zsh > ~/.zsh/completions/_zelynic

# Fish
zelynic completions fish > ~/.config/fish/completions/zelynic.fish
```

## Usage

### Quick Reference

```
zelynic [FLAGS] [COMMAND] [ARGS]

FLAGS:
    -i, --info              Print detailed package information
    -v, --ver               Print version (short)
    -V, --version           Print version (long)
    --help-all              Show comprehensive help with all commands and examples
    --iface [INTERFACE]     Specify network interface (no value = list available)
    --no-color              Disable colored output

COMMANDS:
    list                    List network bandwidth usage per process
    strict                  Set bandwidth limits for a process
    unstrict                Remove all bandwidth limits
    refresh                 Refresh an existing limit after process respawn
    status                  Show active bandwidth limits
    clean                   Clean up orphaned bandwidth limits
    profile                 Manage named bandwidth profiles
    qos                     QoS priority-based bandwidth shaping
    watch                   Monitor and alert on bandwidth threshold
    auto                    Auto-throttle daemon mode
    log                     Bandwidth usage history
    backend                 Show backend info and capability checks
    completions             Generate shell completions
    man                     Generate man page
```

### List Network Usage

Show all programs/ports with active bandwidth usage:

```bash
# List all processes with bandwidth usage (default)
zelynic list

# Real-time TUI dashboard (like htop for network)
zelynic list --live

# Live mode with custom refresh interval (2 seconds)
zelynic list --live --interval 2

# Sort by highest to lowest bandwidth usage
zelynic list --high-to-low-usage-net

# Show individual socket connections per process
zelynic list --verbose

# Output as JSON for scripting
zelynic list --json
```

### Limit Bandwidth (strict)

Apply download and/or upload speed limits to a specific process:

```bash
# Limit both download and upload
sudo zelynic strict -d 500kb -u 500kb brave

# Limit only download (omit -u)
sudo zelynic strict -d 1mb firefox

# Limit only upload (omit -d)
sudo zelynic strict -u 250kb 1234

# Limit by PID
sudo zelynic strict -d 1mb -u 1mb 8100

# Use a preset profile
sudo zelynic strict --preset gaming discord
sudo zelynic strict --preset background steam
sudo zelynic strict --preset streaming zoom
```

> **Note:** PID 0 (kernel idle thread) and user names (e.g., `root`) cannot be limited. zelynic targets processes by PID or binary name. PID 0 is not a userspace process and has no network sockets or cgroup association.

Re-limiting without `unstrict` first is supported — old rules are auto-cleaned:

```bash
sudo zelynic strict -d 500kb brave       # apply limit
sudo zelynic strict -d 10mb brave        # auto-overrides to 10mb
```

Reloads, tabs, and child processes normally remain limited while the browser
process tree stays inside the target cgroup. If the application is closed
completely and reopened, run `refresh` to move the new PIDs into the existing
limit without duplicating nftables or tc rules:

```bash
sudo zelynic refresh brave
```

Strict applies to new connections after the target has been moved into the
Zelynic cgroup. An already-running download or speed test can keep using its
existing socket until the request reconnects. Apply `zelynic strict` before
starting the network activity, or reload/restart the target's network request
after strict is applied. Zelynic does not flush conntrack entries or forcibly
reset existing connections by default.

### Remove Bandwidth Limits (unstrict)

Remove all bandwidth restrictions from a process:

```bash
# By process name
sudo zelynic unstrict brave

# By PID
sudo zelynic unstrict 8100
```

When available, strict records the process's original cgroup before moving it.
`unstrict` tries to restore live PIDs to that recorded cgroup safely; if the
destination cannot be validated, Zelynic warns and falls back to the Zelynic
parent cgroup instead of guessing systemd paths.

### Show Active Limits

```bash
zelynic status
```

### Clean Up Orphans

Remove tc/cgroup rules for processes that have already exited:

```bash
sudo zelynic clean
```

### Network Interface

Auto-detect is used by default. Explicitly specify an interface with `--iface`:

```bash
# List available interfaces
zelynic --iface

# Use a specific interface for any command
zelynic --iface wlan0 list --live
sudo zelynic --iface eth0 strict -d 1mb brave
sudo zelynic --iface enp3s0 qos high firefox
```

For strict limits, the interface is auto-detected when `zelynic strict` is applied by reading the current default route. If the host later switches from WiFi to Ethernet, VPN, tethering, or another default route, upload shaping can remain attached to the old interface. For now, run `sudo zelynic unstrict <target>` and re-apply `zelynic strict` after the network changes. `zelynic status` warns when saved limits are attached to a different interface than the current default route.

### QoS Priority Shaping

Assign priority tiers instead of hard limits. High priority processes get bandwidth first; idle bandwidth from low-priority processes redistributes automatically:

```bash
# High priority for browser
sudo zelynic qos high brave

# Low priority for download manager
sudo zelynic qos low wget

# Show current QoS assignments
zelynic qos status

# Clear all QoS rules
sudo zelynic qos reset
```

### Profile Management

Save and load custom bandwidth profiles:

```bash
# Save a profile
zelynic profile save slow --dl 50kb --ul 50kb
zelynic profile save streaming --dl 5mb --ul 2mb

# Apply a profile
sudo zelynic profile apply slow steam

# List all profiles
zelynic profile list

# Delete a profile
zelynic profile delete slow
```

### Watch & Alert

Monitor a process and send a desktop notification when bandwidth exceeds a threshold:

```bash
# Alert when wget rate exceeds 500KB/s
zelynic watch -a 500kb wget

# Check every 30 seconds
zelynic watch -a 5mb firefox -i 30
```

### Auto-Throttle Daemon

Continuously monitor and automatically apply limits when thresholds are exceeded:

```bash
# Auto-limit when download exceeds 100MB/s and upload exceeds 50MB/s
sudo zelynic auto --download 100mb --upload 50mb

# Kill heavy processes instead of limiting
sudo zelynic auto --download 80mb --kill firefox

# Run as a background daemon
sudo zelynic auto --daemon
```

### Bandwidth Logging

Record and review historical bandwidth usage:

```bash
# Show recent history
zelynic log

# Record a snapshot of current state
zelynic log --snapshot

# Show last hour
zelynic log --last 1h

# JSON output for analysis
zelynic log --json
```

### Presets

Built-in presets for common use cases:

| Preset | Download | Upload | Use Case |
|--------|----------|--------|----------|
| `gaming` | 50 mb/s | 50 mb/s | Low latency, prioritizes responsive gameplay |
| `streaming` | 10 mb/s | 5 mb/s | Balanced for video calls and streaming |
| `background` | 500 kb/s | 100 kb/s | Minimal bandwidth for background downloads |

## Supported Units

| Unit | Description | Example |
|------|-------------|---------|
| `b`, `byte`, `bs` | Bytes per second | `100bs`, `500byte` |
| `kb`, `kbs` | Kilobytes per second (1 KB = 1024 B) | `500kb`, `2kbs` |
| `mb`, `mbs` | Megabytes per second (1 MB = 1024 KB) | `1mb`, `50mbs` |
| `gb`, `gbs` | Gigabytes per second (1 GB = 1024 MB) | `1gb`, `2gbs` |
| `kbit`, `kbits` | Kilobits per second | `100kbit`, `500kbits` |
| `mbit`, `mbits` | Megabits per second | `10mbit`, `100mbits` |
| `gbit`, `gbits` | Gigabits per second | `1gbit` |

> **Note:** Minimum rate is **1 KB/s** (1024 B/s). Values below this are rejected because the Linux kernel's HTB scheduler cannot accurately enforce sub-KB/s rates due to clock tick granularity.

## Architecture

zelynic works by combining several Linux kernel features:

### Bandwidth Monitoring

Uses the `ss` (socket statistics) command to discover all active TCP/UDP sockets on the system, maps them to their owning processes via `/proc` filesystem, and extracts per-socket byte counters (available on kernels 4.6+).

### Bandwidth Limiting

Uses a layered approach:

1. **Cgroup v2** — Places target PIDs in `/sys/fs/cgroup/zelynic/target_<name>`.
2. **nftables socket matching** — Matches target sockets with `socket cgroupv2`.
3. **Packet and conntrack marks** — Marks target flows so upload and download can be identified.
4. **tc fw filter + HTB class** — Shapes upload/egress traffic on the selected interface.
5. **nftables input policer** — Limits marked download/ingress responses with `limit/drop`.

### How It Works

```text
Upload / egress
  Process PID
    -> cgroup v2 target (/sys/fs/cgroup/zelynic/target_<name>)
    -> nft output: socket cgroupv2 match
    -> meta mark / ct mark
    -> tc fw filter
    -> HTB class
    -> network interface

Download / ingress
  Process opens connection
    -> nft output marks socket/flow
    -> conntrack mark is stored

  Incoming response
    -> nft input matches ct mark
    -> nft limit/drop policer
    -> process receives limited download
```

## Package Information

```bash
# Print version
zelynic -v

# Print detailed info
zelynic -i
```

**Example output of `zelynic -i`:**
```
Version: v2.1.0
Build: linux-x86_64 (ad36a81)
Copyright: (c) 2026 Rezky_nightky
License: GPL-3.0
Source: https://github.com/oxyzenq/zelynic
```

## Building

```bash
# Recommended local quality gate for Rust/core changes
./build.sh check-all

# Build release binary
./build.sh release

# Full CI pipeline (checks + release build)
./build.sh ci
```

Manual fallback:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check all
```

See [docs/supply-chain.md](docs/supply-chain.md) for dependency policy and supply-chain check details.

## License

GNU General Public License v3.0 — Copyright (c) 2026 Rezky_nightky

See [LICENSE](LICENSE) for details.

## Author

**Rezky_nightky** — [GitHub](https://github.com/oxyzenq)
