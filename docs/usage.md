# oxy Usage Guide

Complete reference for all oxy commands, options, and usage patterns.

## Command Reference

### `oxy list` — Monitor Bandwidth Usage

Displays a table of all processes with active network connections and their bandwidth statistics.

#### Options

| Flag | Description |
|------|-------------|
| `--usage-all` | Show all programs/ports with bandwidth usage |
| `--high-to-low-usage-net` | Sort by highest to lowest bandwidth usage |

#### Examples

```bash
# Show all network activity
oxy list --usage-all

# Find top bandwidth consumers
oxy list --high-to-low-usage-net
```

#### Output Columns

| Column | Description |
|--------|-------------|
| PID | Process ID |
| PROCESS | Process name |
| CONN | Number of active connections |
| DOWNLOAD (RX) | Total bytes received |
| UPLOAD (TX) | Total bytes sent |
| TOTAL | Sum of download + upload |

#### Color Coding

- **Green**: Low usage (< 10 MB)
- **Yellow**: Medium usage (10-100 MB)
- **Red**: High usage (> 100 MB)
- **Dimmed**: No data available (kernel < 4.6 or inactive sockets)

---

### `oxy strict` — Apply Bandwidth Limits

Apply download and/or upload speed limits to a specific process.

#### Syntax

```
oxy strict [OPTIONS] <TARGET>
```

#### Options

| Flag | Description | Example |
|------|-------------|---------|
| `-d`, `--download` | Download speed limit | `-d 500kb` |
| `-u`, `--upload` | Upload speed limit | `-u 1mb` |
| `<TARGET>` | Process name or PID | `brave`, `8100` |

#### Usage Patterns

**1. Limit both download and upload:**
```bash
sudo oxy strict -d 500kb -u 500kb brave
```

**2. Limit only download (keep upload unlimited):**
```bash
sudo oxy strict -d 1mb -u only firefox
```

**3. Limit only upload (keep download unlimited):**
```bash
sudo oxy strict -d only -u 500kb brave
```

**4. Limit by PID:**
```bash
sudo oxy strict -d 2mb -u 2mb 8100
```

**5. Different limits for download and upload:**
```bash
sudo oxy strict -d 5mb -u 1mb transmission
```

**6. Use bit-based units:**
```bash
sudo oxy strict -d 10mbit -u 5mbit steam
```

---

### `oxy unstrict` — Remove Bandwidth Limits

Remove all bandwidth restrictions that were previously applied to a process.

#### Syntax

```
oxy unstrict <TARGET>
```

#### Examples

```bash
# Remove limits by process name
sudo oxy unstrict brave

# Remove limits by PID
sudo oxy unstrict 8100
```

This command removes all tc classes, tc filters, and cgroup rules associated with the target process, restoring full bandwidth access.

---

### `oxy -V` — Print Version

```bash
oxy -V
# Output: oxy v1.0.0-stable.1
```

---

### `oxy -i` — Print Package Info

```bash
oxy -i
```

Output:
```
Version: v1.0.0-stable.1
Build: linux-x86_64 (3c74245)
Copyright: (c) 2026 rezky_nightky
License: MIT
Source: https://github.com/oxyzenq/oxy
```

---

## Supported Units

### Byte-Based Units (1 unit = 1024^n bytes)

| Unit | Aliases | Multiplier | Example |
|------|---------|------------|---------|
| Bytes/sec | `b`, `byte`, `bytes`, `bs` | 1 | `500bs` |
| Kilobytes/sec | `kb`, `kbs`, `kb/s` | 1024 | `500kb` |
| Megabytes/sec | `mb`, `mbs`, `mb/s` | 1,048,576 | `2mb` |
| Gigabytes/sec | `gb`, `gbs`, `gb/s` | 1,073,741,824 | `1gb` |

### Bit-Based Units (1 unit = 1024^n bits)

| Unit | Aliases | Multiplier (bytes) | Example |
|------|---------|-------------------|---------|
| Kilobits/sec | `kbit`, `kbits` | 128 | `100kbit` |
| Megabits/sec | `mbit`, `mbits` | 131,072 | `10mbit` |
| Gigabits/sec | `gbit`, `gbits` | 134,217,728 | `1gbit` |

---

## Advanced Usage

### Limiting Multiple Processes

You can apply limits to different processes independently:

```bash
# Limit Brave browser
sudo oxy strict -d 2mb -u 1mb brave

# Limit Firefox
sudo oxy strict -d 1mb -u 500kb firefox

# Limit a download manager
sudo oxy strict -d 5mb -u 2mb transmission
```

### Using PID Instead of Name

When multiple instances of a program are running, use the PID to target a specific one:

```bash
# Find the PID
ps aux | grep brave

# Apply limit to specific PID
sudo oxy strict -d 1mb -u 500kb 8100
```

### Removing All Limits

To remove all active limits on the system:

```bash
# List active limits first
cat /run/oxy/state.json

# Remove each one individually
sudo oxy unstrict brave
sudo oxy unstrict firefox
```

### Monitoring Changes

Apply a limit and then monitor the effect:

```bash
# Terminal 1: Apply limit
sudo oxy strict -d 500kb -u 500kb brave

# Terminal 2: Monitor bandwidth
watch -n 1 'oxy list --high-to-low-usage-net'
```

---

## How Bandwidth Limiting Works

### Technical Overview

oxy uses the following Linux kernel features:

1. **HTB qdisc (Hierarchical Token Bucket)**: A queueing discipline that provides hierarchical rate limiting with burst support
2. **Traffic classes**: Each limited process gets its own class with a guaranteed rate (`rate`) and maximum burst rate (`ceil`)
3. **Cgroup net_cls**: Tags outgoing packets with a class ID based on the process's cgroup membership
4. **tc filters**: Routes tagged packets to the appropriate class for enforcement

### Rate Limiting Details

- The `rate` parameter sets the guaranteed bandwidth
- The `ceil` parameter allows temporary bursting up to 110% of the set rate
- A 15KB burst buffer is configured for smooth traffic shaping
- Upload (egress) limiting is precise and per-process
- Download (ingress) limiting uses ingress policing which applies at the interface level

### State Persistence

oxy stores its state in `/run/oxy/state.json`. This allows:
- Tracking which processes have active limits
- Proper cleanup when limits are removed
- Surviving daemon restarts (state persists until explicitly removed)

---

## Common Scenarios

### Throttling a Download

```bash
sudo oxy strict -d 2mb -u only transmission
```

### Limiting Video Streaming Quality

```bash
sudo oxy strict -d 5mb -u 500kb firefox
```

### Preventing a Process from Hogging Bandwidth

```bash
sudo oxy strict -d 1mb -u 500kb docker
```

### Giving Priority to a Specific Application

Limit background processes to free up bandwidth for your main application:

```bash
sudo oxy strict -d 500kb -u 250kb updates
sudo oxy strict -d 500kb -u 250kb backup
# Your main app gets the remaining bandwidth
```
