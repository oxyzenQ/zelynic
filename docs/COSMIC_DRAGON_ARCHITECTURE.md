<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Cosmic Dragon Architecture

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

**Cosmic Dragon Architecture eliminates the coordination problem by using exactly one
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
│  CLI / JSON, responsive monitor rendering               │
│  + diff-based emission (NIGHT-improve-2)                │
│  src/commands/, src/cli/, src/ebpf/render.rs            │
│  src/terminal/ (alt screen + DiffScreen)                │
├─────────────────────────────────────────────────────────┤
│  Layer 3 — Aggregation                                  │
│  delta computation, summary, sorting                    │
│  src/ebpf/loader.rs (CounterSummary)                    │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — Identity Resolution (userspace)              │
│  cgroup ID → process name / uid / path                  │
│  + per-cgroup process/socket detail (NIGHT-hunt-8)      │
│  src/ebpf/identity/ (IdentityMap)                       │
│  src/ebpf/connections.rs (ConnectionMap)                │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — Map Interface                                │
│  typed access to BPF maps (HashMap, RingBuf, PerCpu)    │
│  src/ebpf/loader.rs (read_stats_map, poll_and_summarize)│
├─────────────────────────────────────────────────────────┤
│  Layer 0 — BPF Programs (kernel)                        │
│  cgroup_skb/egress observer → cgroup_counters map       │
│  cgroup_skb ingress+egress limiter → token-bucket       │
│  ebpf/ (aya-ebpf: observer + limiter, pure Rust)        │
│  (future: a policer program, same pure-Rust ebpf/)       │
```

### Layer 0 — BPF Programs (kernel)

The BPF programs are the **only** kernel-level component. The observer
hooks `cgroup_skb/egress` + `cgroup_skb/ingress` (two programs, two
counter maps), reads `bpf_skb_cgroup_id()` — the cgroup of the
**socket owner**, not the current task — and updates a hash map
keyed by cgroup ID. Per-cgroup stats: packet count, byte count.

Contract:
- Program returns `1` (allow) on every path — never block.
- Map updates use `BPF_ANY` (create-or-update).
- No ring buffer at all: the C-era events ringbuf (1 event per 100
  packets per cgroup, never read by userspace) was dropped at
  NIGHT-boost-34 — kernel 6.8's cgroup_skb helper wall rejected the
  event branch's get_current_* calls, and the payload fed nothing
  (docs/PURE_RUST_EVALUATION.md delta 5, the resolved hunt finding).
  The observer's helper set is now map ops + `bpf_skb_cgroup_id` +
  `bpf_get_socket_cookie`, all cgroup_skb-legal across the whole
  5.13+ span.

### Layer 1 — Map Interface

Userspace reads BPF maps via `aya`. The map interface is typed:
`BpfHashMap<u32, CgroupStatsRaw>` — keys are cgroup IDs, values are the
`#[repr(C)]` struct that matches the BPF-side `struct cgroup_stats`.

This layer is the **only** place that touches BPF maps directly. Everything
above it works with Rust types.

### Layer 2 — Identity Resolution (userspace)

BPF returns raw cgroup IDs (`cg:73386`). Humans need `cg:73386 (firefox)`.
This layer walks `/proc/*/cgroup` + `stat(2)` on `/sys/fs/cgroup{path}`
(the kernfs inode IS the cgroup ID) to build
a reverse map: cgroup ID → `ProcessIdentity { pid, uid, comm, cgroup_path }`.

The representative name per cgroup is chosen by MAJORITY VOTE
(NIGHT-hunt-10): the comm hosting the most live processes names the
cgroup (ties break to the lowest PID). The old first-pid-wins rule let
a lone `chrome_crashpad` label a cgroup whose other ~30 processes were
all `brave` — `status` then showed the browser's actual traffic carrier
as `(chrome_crashpad)`, and removing that "helper" silently removed
brave's enforcement. Unreadable comms never outvote real ones.

Refresh policy: 10s TTL by default. Refresh is best-effort — if `/proc` walk
fails, labels fall back to raw `cg:{id}`. The BPF program is unaffected.

Layer 2.5 — Connection detail (NIGHT-hunt-8): `ConnectionMap` joins
/proc/net/{tcp,tcp6,udp,udp6} with per-PID fds and the identity
resolution to answer "which process inside this cgroup is actually
talking, and to where". Userspace-only, TTL-cached (3s), best-effort
like Layer 2 — a stripped /proc yields no detail lines, never errors.

### Layer 3 — Aggregation

`poll_and_summarize()` reads current map state, computes deltas against the
previous poll, and produces a `CounterSummary`. This is where rate
calculations, top-N sorting, and threshold detection live.

### Layer 4 — Presentation

CLI output (`src/ebpf/render.rs`, the responsive monitor engine, NIGHT-hunt-7),
JSON output (`--print-json`).
This layer never touches BPF directly — it consumes `CounterSummary` +
`IdentityMap` and renders. Monitor frames flow through the diff-based
engine (`terminal/diff.rs`, NIGHT-improve-2 — the cosmic-dragon-engine
adaptation from cosmostrix): the renderer builds logical lines, the
engine diffs them against the previous frame's shadow, and emits only
the changed rows in one write syscall — idle frames emit nothing and
the screen is never wiped mid-session. The tall regime (frame >=
terminal height, every terminal at or under the render cap) is
top-aligned and scroll-free (NIGHT-improve-6): the emission paints
the first min(rows, height) lines without a trailing linefeed, so
the title bar never drifts and an idle frame costs zero I/O at every
height.

## Roadmap

Cosmic Dragon Architecture is the mainline: `main` carries the pure-eBPF v11
line.

### Done
- [x] Layer 0: `ebpf/src/main.rs` — cgroup_skb/egress counter
- [x] Layer 1: `read_counters()` direct map read
- [x] Layer 2: `IdentityMap` with /proc reverse-lookup + 10s TTL refresh
- [x] Layer 3: `CounterSummary` with delta computation + sorting
- [x] Layer 4: `print(&IdentityMap)` with human-readable labels
- [x] Layer 0: `ebpf/src/bin/limiter.rs` — cgroup_skb token-bucket enforcer (ingress + egress)
- [x] Layer 0: `bpf_skb_cgroup_id(skb)` for correct cgroup attribution
- [x] Layer 1: `apply_single()` + `apply_group()` write to policy maps
- [x] Layer 1: `read_stats()` reads from `cgroup_limiter_stats` map
- [x] Layer 1: BPF map pinning (`/sys/fs/bpf/zelynic/*`) for fire-and-forget
- [x] Layer 2: Direct /proc lookup for process name → cgroup ID resolution
- [x] Layer 4: `strict-single` / `strict-multi` / `unstrict` / `status` CLI
- [x] Layer 4: Lowercase units (kb/mb/gb) + positional rate + per-direction (-d/-u)
- [x] Fail-safe: BPF returns 1 (allow) on every error path
- [x] Watchdog hook in the enforcer (dormant by design — never armed, deadline 0 = enforcing forever; preserved for a future `--timeout`)
- [x] Min-rate guard: rejects < 1 KB/s (prevents bricking apps)
- [x] Fire-and-forget: strict commands exit 0, limits persist via pinned maps + bpf_links (no child, no daemon)
- [x] No residue: `unstrict-all` removes all pin files and reclaims map slots
- [x] Override: re-running strict replaces old rate (no duplicates)
- [x] Verified: real enforcement on Arch Linux, kernel 6.18, AMD Ryzen 7

### Next (Phase W5 — Production Hardening)
- [x] Cross-distro testing — 6 distros verified (see CROSS_DISTRO_RESULTS.md)
- [ ] Kernel version testing (5.13, 6.12, 6.18+ verified; 6.1/6.6 LTS pending)
- [x] Stress test: `scripts/supermassive/supermassive-test.sh` (NIGHT-master-2, renamed from brutal-stress-test in NIGHT-improve-11; retired the legacy `scripts/stress-test.sh`)
- [x] Benchmark: `scripts/bench/benchmarking.sh` (CPU/memory overhead — see PERFORMANCE.md)
- [x] Layer 4: `--print-json` output for tooling integration

### Future ideas (unscheduled — v11 is maintenance mode)
- [ ] Layer 0: `ebpf/src/bin/policer.rs` — DSCP marking via `sock_ops` (pure Rust, like the other two programs)
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
  it. `main` is pure eBPF.
- **No REST API / MCP / TUI-as-server.** CLI + config + exit codes. That's it.

## Branch Strategy

- `main` — pure eBPF v11.x (Cosmic Dragon Architecture). Maintenance mode.
- `intergalaxion` — **deleted** (was 44 commits of planning docs, 0 BPF
  programs). Superseded by the Cosmic Dragon Architecture rewrite which ships
  real code.

## Architecture audit (NIGHT-improve-17, 2026-09-22)

Peak-stability / easy-maintenance / strong-structure verdict, from the
audits that touched every layer this session:

- **Layer discipline holds (no spaghetti)**: the four-layer shape is
  enforced by the module tree itself — commands reach the terminal
  layer only through its top-level module surface (monitor.rs's
  `crate::terminal`), cli touches the eBPF layer only through
  `ebpf::limiter`'s public re-exports (the feature-gated typo-rescue
  validators), and the eBPF crate (ebpf/) shares layout with
  userspace only through the `#[path]`-wired math.rs twin (pure
  core, no aya dependency). The NIGHT-optimized-2 pass
  cross-referenced all 363 functions: zero dead,
  zero duplicate bodies in the map-reader family; the remaining
  intentional duplication (bash/python harness twins) is documented at
  both sites.
- **One acquisition path per resource**: every u32-keyed limiter map
  flows through `with_u32_map` (hunt-20), every pinned map open flows
  through the pin.rs helpers (improve-10/optimized-2), every /proc comm
  read flows through the canonical sanitizer (cybersecurity-1/2). One
  contract per resource class is the anti-spaghetti invariant.
- **Error contracts are symmetric**: map reads propagate on both
  directions (hunt-22/optimized-2 closed the last swallow), deletes
  distinguish absent from failed (hunt-20), and the harness verdicts
  never fabricate (hunt-32: the divisor now measures the real span).
- **Known limits, documented not hidden**: the nightly eBPF toolchain
  quarantine (NIGHT-lts-1, docs/STABILITY.md), the loopback GSO physics
  (sub-skb band floors, min-RTO cushion), and the 1024-entry map
  ceilings are each written down where a maintainer trips over them.
- **Structure debt retired this session**: 683 lines of superseded
  scripts and 90 net lines of dead build modes removed (cleanup-2/3) —
  the tree now contains only paths something calls.

## Naming

"Cosmic Dragon Architecture" (renamed from "Dragon Architecture",
NIGHT-improve-17) — because a dragon pack operates with clear layering:
scouts (observer), hunters (limiter), alpha (policy). Each role is distinct,
each contributes to the pack's survival. No member tries to do everything
alone. The pack was raised to the cosmic register the project already
lives in: the GPG signing identity is the cosmic dragon, the render engine
lineage is the cosmic-dragon-engine (cosmostrix), and the agent persona
behind this work is `dragonzen` — one identity, one name.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
