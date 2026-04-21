# Getting Started with oxy

Welcome to **oxy**, the easy userspace bandwidth manager for Linux.

## Prerequisites

- **Linux** with kernel 4.6+ (for per-socket byte tracking)
- **iproute2** package (provides `tc`, `nft`, `ss`)
- **Root access** for bandwidth limiting operations (`strict`, `unstrict`, `qos`, `clean`)

### Verify Prerequisites

```bash
uname -r                    # Kernel 4.6+
which tc ss nft             # iproute2 tools
rustc --version             # Only if building from source (1.88+)
```

## Installation

### Install Script (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/oxyzenq/oxy/main/install.sh | sh
```

### Build from Source

```bash
git clone https://github.com/oxyzenq/oxy.git
cd oxy
cargo build --release
sudo install -Dm755 target/release/oxy /usr/local/bin/oxy
```

### GitHub Releases

Download from [Releases](https://github.com/oxyzenq/oxy/releases) — includes SHA256 checksums.

## Verify Installation

```bash
oxy -i
```

```
Version: v2.0.0
Build: linux-x86_64 (abc1234)
Copyright: (c) 2026 Rezky_nightky
License: MIT
Source: https://github.com/oxyzenq/oxy
```

## Quick Start

### 1. Monitor Bandwidth

```bash
oxy list                          # Table of all processes
oxy list --live                   # Real-time TUI (recommended)
oxy list --live 2                 # 2-second refresh
```

### 2. Limit a Process

```bash
sudo oxy strict -d 500kb -u 500kb brave
```

### 3. Check Active Limits

```bash
oxy status
```

### 4. Remove Limits

```bash
sudo oxy unstrict brave
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| `ss command failed` | `sudo apt install iproute2` |
| `root privileges required` | Use `sudo` for limiting commands |
| `no default route found` | Ensure system is connected to a network |
| `unknown interface 'X'` | Run `oxy --iface` to list available interfaces |

## Next Steps

See the [Usage Guide](usage.md) for complete command reference.
