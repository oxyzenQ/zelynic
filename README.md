<p align="center">
  <strong>oxy</strong>
</p>

<p align="center">
  <em>Easy userspace bandwidth manager for Linux</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-linux__x86__64-orange" alt="Platform">
  <img src="https://img.shields.io/badge/rust-1.88%2B-DEA584" alt="Rust">
</p>

<p align="center">
  <a href="#installation">Install</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#commands">Commands</a> &middot;
  <a href="#changelog">Changelog</a>
</p>

---

oxy is a CLI tool for monitoring and limiting per-process network bandwidth on Linux.
It uses `tc` (HTB qdisc) + `nftables` + `cgroups` for rate limiting, and `ss` for real-time bandwidth monitoring.

## Features

- **Live TUI** — Real-time bandwidth dashboard with sparklines and scrolling (`oxy list --live`)
- **Per-process limiting** — Download/upload speed limits via `oxy strict`
- **Preset profiles** — One-command limits: `oxy strict --preset gaming discord`
- **QoS priority** — Priority tiers instead of hard limits (`oxy qos high/low`)
- **Auto-throttle** — Background daemon for automatic bandwidth management
- **Named profiles** — Save and apply custom profiles (`oxy profile`)
- **Bandwidth alerts** — Desktop notifications on threshold (`oxy watch`)
- **Verbose mode** — Per-connection IP/port/protocol breakdown
- **JSON output** — Scripting integration via `--json`
- **Interface selection** — `--iface` flag with validation and auto-detection
- **Shell completions** — Bash, Zsh, Fish, PowerShell
- **Man page** — Generated via `oxy man`

## Requirements

- Linux (kernel 4.6+ for per-socket byte tracking)
- Root privileges for `strict`/`unstrict`/`qos`/`clean` operations
- `iproute2` package (provides `tc`, `nft`, `ss`)
- Rust 1.88+ (for building from source)

## Installation

### Download (Recommended)

```bash
# Install via install script
curl -fsSL https://raw.githubusercontent.com/oxyzenq/oxy/main/install.sh | sh

# Or download from GitHub Releases
# https://github.com/oxyzenq/oxy/releases
```

### Build from Source

```bash
git clone https://github.com/oxyzenq/oxy.git
cd oxy
cargo build --release
sudo install -Dm755 target/release/oxy /usr/local/bin/oxy
```

### Package Manager (Coming Soon)

## Quick Start

```bash
# Monitor all network usage
oxy list

# Real-time TUI dashboard
oxy list --live

# Limit a process
sudo oxy strict -d 1mb -u 500kb brave

# Use preset
sudo oxy strict --preset gaming discord

# Remove limits
sudo oxy unstrict brave

# Comprehensive help
oxy --help-all
```

## Commands

### `oxy list` — Monitor Bandwidth

```bash
oxy list                          # Table view (default)
oxy list --live                   # Real-time TUI dashboard
oxy list --live 2                 # 2-second refresh interval
oxy list --live --interval 3      # Explicit interval
oxy list --verbose                # Per-connection breakdown
oxy list --json                   # JSON output
```

**TUI controls:** `q`/`Esc` quit, `j`/`k` or `↑`/`↓` scroll, `Ctrl+C` quit

### `oxy strict` — Limit Bandwidth

```bash
sudo oxy strict -d 500kb -u 500kb brave     # Both directions
sudo oxy strict -d 1mb firefox               # Download only
sudo oxy strict -u 250kb -d only 1234       # Upload only (keyword 'only')
sudo oxy strict --preset gaming discord     # Use preset profile
sudo oxy strict --preset background steam
```

**Presets:**

| Name | Download | Upload | Use case |
|------|----------|--------|----------|
| `gaming` | 50 MB/s | 50 MB/s | Low latency priority |
| `streaming` | 10 MB/s | 5 MB/s | Video calls |
| `background` | 500 KB/s | 100 KB/s | Downloads, updates |

Re-limiting the same process auto-cleans old rules — no need to `unstrict` first.

### `oxy unstrict` — Remove Limits

```bash
sudo oxy unstrict brave            # By process name
sudo oxy unstrict 1234             # By PID
```

### `oxy status` — Show Active Limits

```bash
oxy status
```

### `oxy clean` — Remove Orphaned Limits

```bash
sudo oxy clean                     # Clean up exited process rules
```

### `oxy qos` — Priority-Based Shaping

```bash
sudo oxy qos high brave            # High priority (gets bandwidth first)
sudo oxy qos low wget              # Low priority (gets leftovers)
sudo oxy qos status                # Show QoS assignments
sudo oxy qos reset                 # Clear all QoS rules
```

### `oxy profile` — Named Profiles

```bash
oxy profile save slow --dl 50kb --ul 50kb
sudo oxy profile apply slow steam
oxy profile list
oxy profile delete slow
```

### `oxy watch` — Bandwidth Alerts

```bash
oxy watch -a 500mb wget            # Alert when > 500MB total
oxy watch -a 1gb firefox -i 30     # Check every 30 seconds
```

### `oxy auto` — Auto-Throttle Daemon

```bash
sudo oxy auto --download 100mb --upload 50mb    # Auto-limit when exceeded
sudo oxy auto --download 80mb --kill firefox   # Kill heavy users
sudo oxy auto --status                           # Check daemon status
```

### `oxy log` — Bandwidth History

```bash
oxy log                            # Show recent history
oxy log --snapshot                 # Record current state
oxy log --last 1h                  # Show last hour
oxy log --json                     # JSON output
```

### `oxy backend` — Backend Info

```bash
oxy backend                        # Check eBPF/tc support
```

### Global Options

```bash
--iface                            # List available interfaces
--iface wlp1s0                     # Use specific interface
--iface eth0 list --live           # Interface + command
--no-color                         # Disable colored output
```

## Supported Units

| Unit | Description | Example |
|------|-------------|---------|
| `byte`, `bs` | Bytes per second | `500bs` |
| `kb` | Kilobytes per second | `500kb` |
| `mb` | Megabytes per second | `1mb` |
| `gb` | Gigabytes per second | `1gb` |
| `kbit` | Kilobits per second | `100kbit` |
| `mbit` | Megabits per second | `10mbit` |
| `gbit` | Gigabits per second | `1gbit` |

## Architecture

```
Monitoring:
  ss -tuneiH → parse_ss_output() → build_inode_cache(/proc/*/fd/)
  → aggregate_by_process() → display (table/JSON/TUI)

Limiting (tc + nftables + cgroups):
  Upload:    Process → nftables (mark by UID) → tc fw filter → HTB class
  Download:  NIC → nftables (socket cgroupv2 / meta skuid / ct mark) → limit rate

State:  /run/oxy/state.json (per-PID limit records)
Cgroups: /sys/fs/cgroup/oxy/ (per-UID on v2, per-PID on v1/hybrid)
```

## License

MIT License — Copyright (c) 2026 rezky_nightky
