# Getting Started with zelynic

Welcome to **zelynic**, the easy userspace bandwidth manager for Linux.

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

### GitHub Releases

```bash
# Download and extract the release archive
curl -sL https://github.com/oxyzenQ/zelynic/releases/latest/download/zelynic-v2.2.0-x86_64-linux.tar.gz | tar xz

# Install for the current user
install -Dm755 zelynic-v2.2.0-x86_64-linux/zelynic "$HOME/.local/bin/zelynic"
```

Verify the download with the SHA512 checksums published alongside each release.

### Build from Source

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic
cargo build --release
install -Dm755 target/release/zelynic "$HOME/.local/bin/zelynic"
```

Release archives are available from [Releases](https://github.com/oxyzenQ/zelynic/releases).

## Verify Installation

```bash
zelynic -i
```

```
Version: v2.2.0
Build: linux-x86_64 (abc1234)
Copyright: (c) 2026 rezky_nightky (oxyzenQ)
License: GPL-3.0
Source: https://github.com/oxyzenQ/zelynic
```

## Quick Start

### 1. Monitor Bandwidth

```bash
zelynic list                          # Table of all processes
zelynic list --live                   # Real-time TUI (recommended)
zelynic list --live 2                 # 2-second refresh
```

### 2. Limit a Process

```bash
sudo zelynic strict -d 500kb -u 500kb brave
```

### 3. Check Active Limits

```bash
zelynic status
```

### 4. Remove Limits

```bash
sudo zelynic unstrict brave
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| `ss command failed` | `sudo apt install iproute2` |
| `root privileges required` | Use `sudo` for limiting commands |
| `no default route found` | Ensure system is connected to a network |
| `unknown interface 'X'` | Run `zelynic --iface` to list available interfaces |

## Next Steps

See the [Usage Guide](usage.md) for complete command reference.
