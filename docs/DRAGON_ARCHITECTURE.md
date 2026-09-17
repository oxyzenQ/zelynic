<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Dragon Architecture

> Pure eBPF. Single hooking layer. No combined tools. Linux-only.

## Why

zelynic's legacy stack mixed three enforcement mechanisms — `tc` (traffic
control qdiscs), `nft` (nftables), and `systemd-run` cgroup moves — to achieve
per-process network shaping. Each tool has its own:

- config format (qdisc class IDs vs nft chain names vs systemd unit properties)
- failure mode (tc silently drops rules on interface rename, nft requires root
  + cap_net_admin, systemd-run requires logind + PAM cooperation)
- observability gap (tc stats don't match nft counters don't match cgroup
  traffic — three numbers, none of them agree)

Coordinating three tools is a maintenance nightmare. Worse, it leaks: a `tc`
rule applied to `wlp1s0` survives a WiFi reconnect and silently shapes the
wrong interface. An `nft` chain survives a service restart and blocks traffic
to a process that no longer exists.

**Dragon Architecture eliminates the coordination problem by using exactly one
mechanism: eBPF.** The kernel already knows which cgroup sent each packet. BPF
lets us observe, count, and (future) shape that traffic in-kernel — no
userspace tool coordination, no format mismatches, no leaked state.

## Principles

1. **Pure eBPF.** All kernel-level operations are BPF programs. No `tc`, no
   `iptables`, no `nft`, no `systemd-run` cgroup tricks. If a feature can't be
   done in BPF, it doesn't belong in zelynic.

2. **Single Hooking Layer.** All observation and enforcement happens at BPF
   hook points (`cgroup_skb`, `sock_ops`, `xdp`, `tc`-cls-act-BPF — but
   **never** `tc`-qdisc). One program type per concern. No multi-tool glue.

3. **Userspace-Composable.** BPF programs expose state via maps. Userspace
   reads maps, applies policy, writes back. **No daemons** — every zelynic
   invocation is a one-shot: attach BPF, do work, detach, exit.

4. **Fail-Safe by Design.** If userspace dies, BPF programs continue running
   with the last-known policy. If a BPF program errors, it returns `1` (allow)
   — never block traffic on failure. Shaping is a privilege, not a right;
   availability trumps enforcement.

5. **Observable, not Magic.** Every packet seen, every decision made, every
   byte counted. The observer is the source of truth — the limiter is a
   consumer of the observer's data. No black boxes, no "trust me bro"
   enforcement.

6. **Linux-First, Linux-Only.** No portable abstractions. cgroup v2, BPF, kernel ≥ 5.13.
   Embrace the platform. BSD/macOS source compiles but `ebpf` feature is
   no-op. Windows is not supported and never will be.

## Layered Structure

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4 — Presentation                                 │
│  CLI / JSON                                            │
│  src/commands/, src/cli/                             │
├─────────────────────────────────────────────────────────┤
│  Layer 3 — Aggregation                                  │
│  delta computation, summary, sorting                    │
│  src/ebpf/loader.rs (CounterSummary)                    │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — Identity Resolution (userspace)              │
│  cgroup ID → process name / uid / path                  │
│  src/ebpf/identity.rs (IdentityMap)                     │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — Map Interface                                │
│  typed access to BPF maps (HashMap, RingBuf, PerCpu)    │
│  src/ebpf/loader.rs (read_counters, poll_events)        │
├─────────────────────────────────────────────────────────┤
│  Layer 0 — BPF Programs (kernel)                        │
│  cgroup_skb/egress observer → cgroup_counters map       │
│  cgroup_skb ingress+egress limiter → token-bucket       │
│  bpf/observer.bpf.c, bpf/limiter.bpf.c                  │
│  (future: policer.bpf.c)                                │
```

### Layer 0 — BPF Programs (kernel)

The BPF program is the **only** kernel-level component. It hooks
`cgroup_skb/egress`, reads `bpf_get_current_cgroup_id()`, and updates a hash
map keyed by cgroup ID. Per-cgroup stats: packet count, byte count.

Contract:
- Program returns `1` (allow) on every path — never block.
- Map updates use `BPF_ANY` (create-or-update).
- No ring buffer spam: events throttled to 1 per 100 packets per cgroup.

### Layer 1 — Map Interface

Userspace reads BPF maps via `aya`. The map interface is typed:
`BpfHashMap<u32, CgroupStatsRaw>` — keys are cgroup IDs, values are the
`#[repr(C)]` struct that matches the BPF-side `struct cgroup_stats`.

This layer is the **only** place that touches BPF maps directly. Everything
above it works with Rust types.

### Layer 2 — Identity Resolution (userspace)

BPF returns raw cgroup IDs (`cg:73386`). Humans need `cg:73386 (firefox)`.
This layer walks `/proc/*/cgroup` + `/sys/fs/cgroup{path}/cgroup.id` to build
a reverse map: cgroup ID → `ProcessIdentity { pid, uid, comm, cgroup_path }`.

Refresh policy: 10s TTL by default. Refresh is best-effort — if `/proc` walk
fails, labels fall back to raw `cg:{id}`. The BPF program is unaffected.

### Layer 3 — Aggregation

`poll_and_summarize()` reads current map state, computes deltas against the
previous poll, and produces a `CounterSummary`. This is where rate
calculations, top-N sorting, and threshold detection live.

### Layer 4 — Presentation

CLI output (`CounterSummary::print()`), JSON output (`--print-json`).
This layer never touches BPF directly — it consumes `CounterSummary` +
`IdentityMap` and renders.

## Roadmap

Dragon Architecture is the mainline: `main` carries the pure-eBPF v10
line. The legacy `tc`/`nft`/`systemd-wrapper` code is frozen on the
`legacy` branch (final v3.1.1, no new development).

### Done
- [x] Layer 0: `bpf/observer.bpf.c` — cgroup_skb/egress counter
- [x] Layer 1: `read_counters()` direct map read
- [x] Layer 2: `IdentityMap` with /proc reverse-lookup + 10s TTL refresh
- [x] Layer 3: `CounterSummary` with delta computation + sorting
- [x] Layer 4: `print(&IdentityMap)` with human-readable labels
- [x] Layer 0: `bpf/limiter.bpf.c` — cgroup_skb token-bucket enforcer (ingress + egress)
- [x] Layer 0: `bpf_skb_cgroup_id(skb)` for correct cgroup attribution
- [x] Layer 1: `apply_single()` + `apply_group()` write to policy maps
- [x] Layer 1: `read_stats()` reads from `cgroup_limiter_stats` map
- [x] Layer 1: BPF map pinning (`/sys/fs/bpf/zelynic/*`) for fire-and-forget
- [x] Layer 2: Direct /proc lookup for process name → cgroup ID resolution
- [x] Layer 4: `strict-single` / `strict-multi` / `unstrict` / `status` CLI
- [x] Layer 4: Lowercase units (kb/mb/gb) + positional rate + per-direction (-d/-u)
- [x] Fail-safe: BPF returns 1 (allow) on every error path
- [x] Watchdog: BPF auto-disables if zelynic crashes (30s timeout)
- [x] Min-rate guard: rejects < 1 KB/s (prevents bricking apps)
- [x] Fire-and-forget: strict commands exit 0, limit persists via child process
- [x] No residue: `unstrict-all` kills child + removes all pin files
- [x] Override: re-running strict replaces old rate (no duplicates)
- [x] Legacy code removed: ~17,000 LOC → ~3,600 LOC (79% reduction)
- [x] Verified: real enforcement on Arch Linux, kernel 6.18, AMD Ryzen 7

### Next (Phase W5 — Production Hardening)
- [x] Cross-distro testing — 6 distros verified (see CROSS_DISTRO_RESULTS.md)
- [ ] Kernel version testing (5.13, 6.12, 6.18+ verified; 6.1/6.6 LTS pending)
- [x] Stress test: `scripts/stress-test.sh`
- [x] Benchmark: `scripts/benchmarking.sh` (CPU/memory overhead — see PERFORMANCE.md)
- [x] Layer 4: `--print-json` output for tooling integration

### Future ideas (unscheduled — v10 is maintenance mode)
- [ ] Layer 0: `bpf/policer.bpf.c` — DSCP marking via `sock_ops`
- [ ] Layer 0: XDP ingress counter (separate from cgroup_skb)
- [ ] Layer 2: cgroup path → systemd unit name resolution
- [ ] Layer 0: per-process (not just per-cgroup) enforcement

## Non-Goals

- **No Windows support.** Ever.
- **No macOS/BSD support for the `ebpf` feature.** Source compiles, feature
  is no-op.
- **No daemon mode.** Every invocation is one-shot. Fire-and-forget pins
  BPF programs + links to bpffs — the kernel enforces with zero zelynic
  processes running. `unstrict-all` removes the pins; a reboot clears
  them (bpffs is not persistent across boots).
- **No combined-tool fallback.** If BPF can't do it, zelynic doesn't do
  it. The legacy `tc`/`nft` code is frozen on the `legacy` branch for
  users who need it; `main` is pure eBPF.
- **No REST API / MCP / TUI-as-server.** CLI + config + exit codes. That's it.

## Branch Strategy

- `main` — pure eBPF v10.x (Dragon Architecture). Maintenance mode.
- `legacy` — v3.1.1 (`tc`/`nft`/`systemd-wrapper`). Final legacy release,
  no new development.
- `intergalaxion` — **deleted** (was 44 commits of planning docs, 0 BPF
  programs). Superseded by the Dragon Architecture rewrite which ships
  real code.

## Naming

"Dragon Architecture" — because a dragon pack operates with clear layering:
scouts (observer), hunters (limiter), alpha (policy). Each role is distinct,
each contributes to the pack's survival. No member tries to do everything
alone.

Also: the agent persona behind this work is `dragonzen`. The architecture
inherits the name.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
