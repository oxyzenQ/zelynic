# Getting Started with oxy

Welcome to **oxy**, the easy userspace bandwidth manager for Linux. This guide walks you through installation, first-time setup, and basic usage.

## Prerequisites

Before installing oxy, make sure your system meets the following requirements:

### System Requirements

- **Operating System**: Linux (any distribution with kernel 4.6+)
- **Rust Toolchain**: Rust 1.75 or later (for building from source)
- **iproute2**: The `tc` and `ip` commands must be available
- **Root access**: Required for bandwidth limiting (`strict`/`unstrict`) commands

### Checking Prerequisites

Run these commands to verify your system is ready:

```bash
# Check kernel version (4.6+ recommended)
uname -r

# Check if tc is available
which tc

# Check if ip is available
which ip

# Check if ss is available (for monitoring)
which ss

# Check Rust version (if building from source)
rustc --version
```

## Installation

### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/oxyzenq/oxy.git
cd oxy

# Build in release mode (optimized binary)
cargo build --release

# The binary will be at: target/release/oxy
# Install system-wide (optional)
sudo cp target/release/oxy /usr/local/bin/

# Verify installation
oxy -V
```

### Option 2: Install Without Git

```bash
# Download and extract the source archive
# Then build:
cd oxy
cargo build --release
sudo cp target/release/oxy /usr/local/bin/
```

### Installing Rust (if needed)

If you don't have Rust installed, use rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## First-Time Verification

After installation, run the info command to verify everything is working:

```bash
oxy -i
```

Expected output:
```
Version: v1.0.0-stable.1
Build: linux-x86_64 (xxxxxxxx)
Copyright: (c) 2026 rezky_nightky
License: MIT
Source: https://github.com/oxyzenq/oxy
```

## Quick Start

### 1. Monitor Bandwidth Usage

List all processes that are currently using the network:

```bash
oxy list --usage-all
```

This shows a table with PID, process name, connection count, and bandwidth usage for each process.

### 2. Sort by Highest Usage

Find the top bandwidth consumers:

```bash
oxy list --high-to-low-usage-net
```

### 3. Limit a Process

Apply bandwidth limits to a specific process (requires root):

```bash
# Limit Brave browser to 500 KB/s download and upload
sudo oxy strict -d 500kb -u 500kb brave

# Limit Firefox to 1 MB/s download only
sudo oxy strict -d 1mb -u only firefox

# Limit by PID
sudo oxy strict -d 2mb -u 2mb 8100
```

### 4. Remove Limits

Remove all bandwidth restrictions:

```bash
sudo oxy unstrict brave
```

## Troubleshooting

### "ss command failed"

Install the iproute2 package:
```bash
# Debian/Ubuntu
sudo apt install iproute2

# Fedora
sudo dnf install iproute

# Arch
sudo pacman -S iproute2
```

### "root privileges required"

Bandwidth limiting operations need root access. Use `sudo`:
```bash
sudo oxy strict -d 500kb -u 500kb brave
```

### "no default route found"

Ensure your system is connected to a network:
```bash
ip route show default
```

### "net_cls controller not available"

On pure cgroup v2 systems, the net_cls controller may not be available. Upload limiting will still work, but per-process download limiting may be limited. Consider enabling cgroup v1 hybrid mode.

## Next Steps

Read the [Usage Guide](usage.md) for detailed command references and advanced usage patterns.
