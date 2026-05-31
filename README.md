> **Project status: paused**
>
> This project is currently paused. Core features such as monitor, list, profile, watch, QoS, and auto-throttle are functional, but per-process bandwidth limiting through `zelynic strict` is not fully stable because of a cgroup v2 and nftables integration issue.
>
> **Known issue:** the `nftables socket cgroupv2 level N == <inode>` expression fails at runtime with `cgroupv2 path fails: No such file or directory`. The `level` keyword is required by nftables syntax, but the cgroup inode resolution does not currently match what the kernel expects for path lookup.
>
> **Future investigation:**
>
> * Investigate cgroup v2 inode resolution versus nftables path lookup behavior
> * Consider systemd slice integration instead of manual cgroup path management
> * Evaluate alternative packet classification methods such as `meta cgroup`
> * Test across newer Linux kernels with improved cgroup v2 socket matching support

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
  <img src="https://img.shields.io/badge/version-v2.0.0-7C3AED?style=flat-square&labelColor=111827" alt="Version v2.0.0">
  <img src="https://img.shields.io/badge/license-GPL--3.0-E040FB?style=flat-square&labelColor=111827" alt="GPL-3.0 license">
  <img src="https://img.shields.io/badge/platform-Linux%20x86__64-8B5CF6?style=flat-square&labelColor=111827" alt="Platform Linux x86_64">
  <img src="https://img.shields.io/badge/Rust-1.88+-A855F7?style=flat-square&labelColor=111827" alt="Rust 1.88+">
  <img src="https://img.shields.io/badge/status-paused-F59E0B?style=flat-square&labelColor=111827" alt="Status paused">
</p>

zelynic is a Rust CLI tool for monitoring, limiting, and shaping per-process network bandwidth on Linux. It uses Linux traffic control (`tc`) with HTB qdisc, `nftables` for packet marking, and `cgroup v2` for process-aware rate limiting. Real-time monitoring is powered by `ss`, while the built-in TUI dashboard provides a live, htop-like view of network traffic.


---

## Renamed from Oxy

Zelynic was previously named Oxy. The old repository and package name were `oxy`, and the command is now `zelynic`. Zelynic currently preserves legacy oxy runtime paths and nft/cgroup identifiers for backward compatibility. These may migrate in a future major release with a safe migration path.

## Features

- **Monitor** bandwidth usage per process/program with cumulative and real-time rates
- **Limit** download and/or upload speeds per process with tc + nftables + cgroup v2
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
curl -sL https://github.com/oxyzenq/zelynic/releases/latest/download/zelynic-v2.0.0-x86_64-linux.tar.gz | tar xz

# Install system-wide
sudo install -Dm755 zelynic-v2.0.0-x86_64-linux/zelynic /usr/local/bin/zelynic
```

Verify the download with SHA256 checksums published alongside each release.

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
    status                  Show active bandwidth limits
    clean                   Clean up orphaned bandwidth limits
    profile                 Manage named bandwidth profiles
    qos                     QoS priority-based bandwidth shaping
    watch                   Monitor and alert on bandwidth threshold
    auto                    Auto-throttle daemon mode
    log                     Bandwidth usage history
    backend                 Show backend and eBPF support status
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

### Remove Bandwidth Limits (unstrict)

Remove all bandwidth restrictions from a process:

```bash
# By process name
sudo zelynic unstrict brave

# By PID
sudo zelynic unstrict 8100
```

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

1. **HTB qdisc** — Hierarchical Token Bucket queueing discipline provides the rate-limiting mechanism
2. **Traffic classes** — Each limited process gets its own tc class with configurable rate/ceil
3. **Cgroup v2** — Tags traffic originating from specific processes using socket cgroupv2 classification
4. **nftables** — Marks packets in prerouting for download (ingress) direction
5. **tc filters** — Routes tagged traffic to the appropriate class for enforcement

### How It Works

```
                    Upload (egress)
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   Process   │────>│  Cgroup v2   │────>│  socket        │
│   (PID)     │     │  (legacy oxy) │     │  cgroupv2 tag  │
└─────────────┘     └──────────────┘     └───────┬────────┘
                                                  │
                                                  v
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│  Network    │<────│  tc filter   │<────│  tc HTB qdisc  │
│  Interface  │     │  (cgroup     │     │  (rate limit)  │
│  (eth0)     │     │   match)     │     │                │
└─────────────┘     └──────────────┘     └────────────────┘

                    Download (ingress)
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│  Network   │────>│  nftables    │────>│  tc HTB qdisc  │
│  Interface  │     │  (prerouting │     │  (rate limit)  │
│  (eth0)     │     │   mark)      │     │                │
└─────────────┘     └──────────────┘     └────────────────┘
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
Version: v2.0.0
Build: linux-x86_64 (ad36a81)
Copyright: (c) 2026 Rezky_nightky
License: GPL-3.0
Source: https://github.com/oxyzenq/zelynic
```

## Building

```bash
# Quick quality checks
./build.sh check-all

# Build release binary
./build.sh release

# Full CI pipeline (checks + release build)
./build.sh ci
```

## License

GNU General Public License v3.0 — Copyright (c) 2026 Rezky_nightky

See [LICENSE](LICENSE) for details.

## Author

**Rezky_nightky** — [GitHub](https://github.com/oxyzenq)
