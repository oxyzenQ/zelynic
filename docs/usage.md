# oxy Usage Guide

Complete reference for all oxy commands, options, and usage patterns.

## Command Reference

### `oxy list` — Monitor Bandwidth

Displays processes with active network connections and bandwidth statistics.

```bash
oxy list                          # Table view (default)
oxy list --live                   # Real-time TUI dashboard
oxy list --live 2                 # 2-second refresh
oxy list --live --interval 3      # Explicit interval
oxy list --verbose                # Per-connection breakdown
oxy list --json                   # JSON for scripting
```

**TUI controls:** `q`/`Esc` quit, `j`/`k` or `↑`/`↓` scroll, `Ctrl+C` quit

**Output columns:** Status (● limited / ○ free), PID, Process, RX/s, TX/s, History sparkline, RX Total, TX Total

---

### `oxy strict` — Apply Bandwidth Limits

```bash
sudo oxy strict -d 500kb -u 500kb brave     # Both directions
sudo oxy strict -d 1mb firefox               # Download only
sudo oxy strict -u 250kb -d only 1234       # Upload only (keyword 'only')
sudo oxy strict -d 2mb -u 2mb 8100          # By PID
sudo oxy strict -d 10mbit -u 5mbit steam    # Bit-based units
sudo oxy strict --preset gaming discord     # Preset profile
```

**Presets:**

| Name | Download | Upload | Use case |
|------|----------|--------|----------|
| `gaming` | 50 MB/s | 50 MB/s | Low latency priority |
| `streaming` | 10 MB/s | 5 MB/s | Video calls |
| `background` | 500 KB/s | 100 KB/s | Downloads, updates |

Re-limiting the same process auto-cleans old rules.

---

### `oxy unstrict` — Remove Limits

```bash
sudo oxy unstrict brave            # By name
sudo oxy unstrict 1234             # By PID
```

---

### `oxy status` — Active Limits

```bash
oxy status
```

---

### `oxy clean` — Remove Orphaned Limits

```bash
sudo oxy clean
```

---

### `oxy qos` — Priority-Based Shaping

```bash
sudo oxy qos high brave            # High priority (bandwidth first)
sudo oxy qos low wget              # Low priority (leftovers only)
sudo oxy qos status                # Show QoS assignments
sudo oxy qos reset                 # Clear all QoS rules
```

---

### `oxy profile` — Named Profiles

```bash
oxy profile save slow --dl 50kb --ul 50kb
sudo oxy profile apply slow steam
oxy profile list
oxy profile delete slow
```

---

### `oxy watch` — Bandwidth Alerts

```bash
oxy watch -a 500mb wget            # Alert when > 500MB total
oxy watch -a 1gb firefox -i 30     # Check every 30 seconds
```

---

### `oxy auto` — Auto-Throttle Daemon

```bash
sudo oxy auto --download 100mb --upload 50mb
sudo oxy auto --download 80mb --kill firefox
sudo oxy auto --status
```

---

### `oxy log` — Bandwidth History

```bash
oxy log                            # Recent history
oxy log --snapshot                 # Record current state
oxy log --last 1h                  # Last hour
oxy log --json                     # JSON output
```

---

### `oxy backend` — Backend Info

```bash
oxy backend
```

---

## Global Options

```bash
--iface                            # List available interfaces
--iface wlp1s0                     # Use specific interface
--iface eth0 list --live           # Interface + command
--no-color                         # Disable colored output
-i, --info                         # Package information
-v, --ver                          # Short version
-V, --version                      # Long version
--help-all                         # Comprehensive help
```

## Supported Units

| Unit | Description | Example |
|------|-------------|---------|
| `byte`, `bs` | Bytes per second | `500bs` |
| `kb` | Kilobytes per second (1024 B) | `500kb` |
| `mb` | Megabytes per second (1024 KB) | `1mb` |
| `gb` | Gigabytes per second (1024 MB) | `1gb` |
| `kbit` | Kilobits per second | `100kbit` |
| `mbit` | Megabits per second | `10mbit` |
| `gbit` | Gigabits per second | `1gbit` |

## Architecture

```
Monitoring:
  ss -tuneiH → parse_ss_output() → build_inode_cache(/proc/*/fd/)
  → aggregate_by_process() → display (table/JSON/TUI)

Limiting:
  Upload:    Process in target cgroup → nftables socket cgroupv2 mark
             → tc fw filter → HTB class
  Download:  Egress mark → conntrack mark → nftables input ct mark
             → limit rate

State:  /run/oxy/state.json
Rules:  /run/oxy/oxy.nft

Note: `oxy strict` intentionally avoids UID-only matching (`meta skuid`)
for enforcement because it can affect unrelated processes owned by the same user.
```
