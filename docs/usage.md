# zelynic Usage Guide

Complete reference for all zelynic commands, options, and usage patterns.

## Command Reference

### `zelynic list` — Monitor Bandwidth

Displays processes with active network connections and bandwidth statistics.

```bash
zelynic list                          # Table view (default)
zelynic list --live                   # Real-time TUI dashboard
zelynic list --live 2                 # 2-second refresh
zelynic list --live --interval 3      # Explicit interval
zelynic list --verbose                # Per-connection breakdown
zelynic list --json                   # JSON for scripting
```

**TUI controls:** `q`/`Esc` quit, `j`/`k` or `↑`/`↓` scroll, `Ctrl+C` quit

**Output columns:** Status (● limited / ○ free), PID, Process, RX/s, TX/s, History sparkline, RX Total, TX Total

---

### `zelynic strict` — Apply Bandwidth Limits

```bash
sudo zelynic strict -d 500kb -u 500kb brave     # Both directions
sudo zelynic strict -d 1mb firefox               # Download only
sudo zelynic strict -u 250kb -d only 1234       # Upload only (keyword 'only')
sudo zelynic strict -d 2mb -u 2mb 8100          # By PID
sudo zelynic strict -d 10mbit -u 5mbit steam    # Bit-based units
sudo zelynic strict --preset gaming discord     # Preset profile
```

**Presets:**

| Name | Download | Upload | Use case |
|------|----------|--------|----------|
| `gaming` | 50 MB/s | 50 MB/s | Low latency priority |
| `streaming` | 10 MB/s | 5 MB/s | Video calls |
| `background` | 500 KB/s | 100 KB/s | Downloads, updates |

Re-limiting the same process auto-cleans old rules.

Process-name matching is intentionally conservative: text targets match
`/proc/<pid>/comm`, the `/proc/<pid>/exe` basename, or the argv[0] basename
exactly, with safe aliases such as `brave` matching `brave-browser`. Zelynic
does not select unrelated shells or terminals just because their full command
line contains the target word. Use a numeric PID when exact targeting is needed.

---

### `zelynic unstrict` — Remove Limits

```bash
sudo zelynic unstrict brave            # By name
sudo zelynic unstrict 1234             # By PID
```

---

### `zelynic status` — Active Limits

```bash
zelynic status
```

---

### `zelynic clean` — Remove Orphaned Limits

```bash
sudo zelynic clean
```

---

### `zelynic qos` — Priority-Based Shaping

```bash
sudo zelynic qos high brave            # High priority (bandwidth first)
sudo zelynic qos low wget              # Low priority (leftovers only)
zelynic qos status                # Show QoS assignments
sudo zelynic qos reset                 # Clear all QoS rules
```

---

### `zelynic profile` — Named Profiles

```bash
zelynic profile save slow --dl 50kb --ul 50kb
sudo zelynic profile apply slow steam
zelynic profile list
zelynic profile delete slow
```

---

### `zelynic watch` — Bandwidth Alerts

```bash
zelynic watch -a 500mb wget            # Alert when > 500MB total
zelynic watch -a 1gb firefox -i 30     # Check every 30 seconds
```

---

### `zelynic auto` — Auto-Throttle Daemon

```bash
sudo zelynic auto --download 100mb --upload 50mb
sudo zelynic auto --download 80mb --kill firefox
sudo zelynic auto --status
```

---

### `zelynic log` — Bandwidth History

```bash
zelynic log                            # Recent history
zelynic log --snapshot                 # Record current state
zelynic log --last 1h                  # Last hour
zelynic log --json                     # JSON output
```

---

### `zelynic backend` — Backend Info

```bash
zelynic backend
zelynic backend doctor
zelynic backend doctor --json
```

`zelynic backend` keeps the short active-backend and eBPF summary. `zelynic backend doctor` prints a read-only capability matrix and deterministic backend scores. Zelynic detects host capabilities and recommends the safest available backend; it does not claim that strict limiting works on every Linux distribution without validation.

Support matrix:

| Host type | Status |
|-----------|--------|
| Arch/CachyOS pure cgroup v2 | Tested |
| Modern systemd + cgroup v2 distros | Expected |
| Older Ubuntu/Debian, hybrid cgroup, containers, WSL, non-systemd distros | Partial/unknown |
| systemd-scope backend, cgroup v1 fallback, eBPF backend | Future |

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

State:  /run/zelynic/state.json
Rules:  /run/zelynic/zelynic.nft

Note: `zelynic strict` intentionally avoids UID-only matching (`meta skuid`)
for enforcement because it can affect unrelated processes owned by the same user.
```

Runtime state, generated nftables rules, cgroups, and nftables identifiers use
the `zelynic` namespace.
