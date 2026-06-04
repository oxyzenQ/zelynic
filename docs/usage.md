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

### `zelynic refresh` — Refresh Respawned Targets

```bash
sudo zelynic refresh brave
```

Reloads, tabs, and child processes normally remain limited while they stay in
the existing target cgroup. If a browser or app is closed completely and
reopened, the new top-level PIDs start in the normal system cgroup. `refresh`
requires an existing active strict state, discovers current matching PIDs, moves
only missing live PIDs into the existing target cgroup, and avoids duplicating
nftables tables, tc classes, or tc filters.

If no active state exists, run `zelynic strict` first or re-run `zelynic strict`
to replace the old limit intentionally.

If the target is not running yet, `refresh` preserves the active limit state and
waits for you to relaunch the target before trying again.

---

### Existing Connections

`zelynic strict` applies to new connections after the target is moved into the
Zelynic cgroup. An already-running download, stream, or speed test may continue
on its existing socket until the request reconnects. For predictable results,
apply strict before starting the network activity, or reload/restart the target's
network request after strict is applied.

Zelynic does not flush conntrack entries or forcibly reset existing connections
by default.

---

### `zelynic run` — Experimental Systemd Wrapper Planning

```bash
zelynic run --dry-run -d 500kbit -u 500kbit -- echo hello
zelynic run --dry-run --target helium -d 500kbit -- helium
zelynic run --dry-run --scope-mode system -d 500kbit -- helium
zelynic run --execute -d 500kbit -u 500kbit -- helium
```

`run` is v2.2 groundwork for a future systemd scope wrapper mode. Today it is
safe by default: `--dry-run` validates the target, rates, and command, prints
the planned scope, future Zelynic attach target, preview-only `systemd-run`
launch command, PID discovery handoff, and launch-then-attach flow, then exits
without launching a process or modifying nftables, tc, cgroups, or state.
User scope is the default planning mode to avoid accidental system Polkit
prompts; system scope is available only as explicit preview via
`--scope-mode system`. `--execute` is an explicit experimental opt-in, but live
execution is still not implemented in this pass and stops at a non-mutating
boundary. Its preview includes an execution preflight explaining why full live
limiting is blocked or future-only for the selected scope mode. Running
`zelynic run` without either flag errors clearly.

Full live limiting still needs a privilege handoff design: user-scope launch is
good for GUI/session ownership, but applying cgroup/nft/tc limits generally
requires root. System-scope launch will require root and explicit opt-in so
Zelynic does not accidentally trigger desktop Polkit prompts.

The rendered command is for review; future live code must preserve structured
argv instead of executing a shell string.

The systemd scope and `/sys/fs/cgroup/zelynic/target_<target>` are not the same
cgroup in the current design. Future v2.2 work is expected to launch through
systemd first, discover the launched PIDs, then reuse the existing strict attach
backend.

See [systemd-wrapper-design.md](systemd-wrapper-design.md) for the design notes
and risk list.

---

### `zelynic unstrict` — Remove Limits

```bash
sudo zelynic unstrict brave            # By name
sudo zelynic unstrict 1234             # By PID
```

When strict state includes the process's original cgroup, `unstrict` attempts to
restore live PIDs to that cgroup before removing the target cgroup. If the
original destination no longer exists or cannot be validated safely, Zelynic
does not guess systemd paths; it warns and uses the Zelynic parent cgroup as the
safe fallback when possible. Zelynic also refuses to restore a PID into a
Zelynic-managed target cgroup, which prevents re-applied limits from trapping
processes inside stale target cgroups during `unstrict`.

---

### `zelynic status` — Active Limits

```bash
zelynic status
```

`zelynic status` also warns when active strict limits are attached to an
interface that differs from the current default route. This can happen after
switching between WiFi, Ethernet, VPN, tethering, or other network paths.

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
-V, --version                      # Complete version and build information
--check-update                     # Check the latest upstream release
--check-updated                    # Alias for --check-update
--help-all                         # Comprehensive help
```

When `--iface` is not provided, Zelynic auto-detects the interface at command
execution time from `ip route show default`. Strict upload shaping is attached
to the interface chosen when the limit is applied. If the default route changes
later, run `sudo zelynic unstrict <target>` and re-apply `zelynic strict` on the
current interface.

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
