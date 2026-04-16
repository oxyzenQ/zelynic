# oxy

<p align="center">
  <strong>Easy userspace bandwidth manager for Linux</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-linux-orange" alt="Platform">
  <img src="https://img.shields.io/badge/rust-1.88%2B-DEA584" alt="Rust">
</p>

oxy is a CLI tool written in Rust that provides an easy-to-use interface for monitoring and limiting per-process network bandwidth on Linux. It leverages Linux traffic control (`tc`) with HTB qdisc and cgroups for rate limiting, and the `ss` utility for real-time bandwidth monitoring.

---

## Features

- **Monitor** bandwidth usage per process/program
- **Limit** download and/or upload speeds per process
- **Sort** processes by bandwidth usage (highest to lowest)
- **Release** bandwidth restrictions instantly
- Supports multiple bandwidth units: `byte/bs`, `kb`, `mb`, `gb`, `kbit`, `mbit`, `gbit`
- Persistent state across invocations (survives restarts)
- Clean, colored terminal output

## Requirements

- **Linux** (kernel 4.6+ recommended for full byte tracking)
- **Root privileges** (for bandwidth limiting operations)
- **iproute2** package (provides `tc` and `ip` commands)
- **Rust 1.88+** (for building from source)

## Installation

### From Source

```bash
git clone https://github.com/oxyzenq/oxy.git
cd oxy
cargo build --release

# Install system-wide
sudo cp target/release/oxy /usr/local/bin/
```

### Quick Build

```bash
cargo build --release
sudo cp target/release/oxy /usr/local/bin/
```

## Usage

### List Network Usage

Show all programs/ports with active bandwidth usage:

```bash
# List all processes with bandwidth usage
oxy list --usage-all

# List processes sorted by highest to lowest bandwidth usage
oxy list --high-to-low-usage-net
```

### Limit Bandwidth (strict)

Apply download and/or upload speed limits to a specific process:

```bash
# Limit both download and upload
sudo oxy strict -d 500kb -u 500kb brave

# Limit only download
sudo oxy strict -d only -u 500kb firefox

# Limit only upload
sudo oxy strict -d 500kb -u only brave

# Limit by PID
sudo oxy strict -d 1mb -u 1mb 8100

# Limit only download with a specific rate
sudo oxy strict -d 2mb -u only 8100
```

### Remove Bandwidth Limits (unstrict)

Remove all bandwidth restrictions from a process:

```bash
# By process name
sudo oxy unstrict brave

# By PID
sudo oxy unstrict 8100
```

### Package Information

```bash
# Print version
oxy -V

# Print detailed info
oxy -i
```

**Example output of `oxy -i`:**
```
Version: v1.0.0
Build: linux-x86_64 (ad36a81)
Copyright: (c) 2026 rezky_nightky
License: MIT
Source: https://github.com/oxyzenq/oxy
```

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

## Architecture

oxy works by combining two Linux kernel features:

### Bandwidth Monitoring
Uses the `ss` (socket statistics) command to discover all active TCP/UDP sockets on the system, maps them to their owning processes via `/proc` filesystem, and extracts per-socket byte counters (available on kernels 4.6+).

### Bandwidth Limiting
Uses a layered approach:
1. **HTB qdisc** — Hierarchical Token Bucket queueing discipline provides the rate-limiting mechanism
2. **Traffic classes** — Each limited process gets its own tc class with configurable rate/ceil
3. **Cgroup net_cls** — Tags traffic originating from specific processes using cgroup classification
4. **tc filters** — Routes tagged traffic to the appropriate class for enforcement

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   Process   │────>│  Cgroup      │────>│  net_cls       │
│   (PID)     │     │  (oxy/pid) │     │  classid tag   │
└─────────────┘     └──────────────┘     └───────┬────────┘
                                                  │
                                                  v
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│  Network    │<────│  tc filter   │<────│  tc HTB qdisc  │
│  Interface  │     │  (cgroup     │     │  (rate limit)  │
│  (eth0)     │     │   match)     │     │                │
└─────────────┘     └──────────────┘     └────────────────┘
```

## Limitations

- **Root required**: Bandwidth limiting operations require root privileges
- **cgroup net_cls**: Best results on systems with cgroup v1 hybrid mode; pure cgroup v2 systems may have limitations with per-process download limiting
- **Ingress limiting**: Download (ingress) limiting is applied globally on the interface ingress; per-process ingress limiting requires eBPF or nftables with marks
- **Byte tracking**: Per-socket cumulative byte counters require kernel 4.6+

## License

MIT License — Copyright (c) 2026 rezky_nightky

See [LICENSE](LICENSE) for details.

## Author

**rezky_nightky** — [GitHub](https://github.com/oxyzenq)
