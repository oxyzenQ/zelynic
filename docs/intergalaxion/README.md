# Intergalaxion Engine — Experimental eBPF Branch

> **This is an experimental branch only.**
> Main remains the stable v3.1.0 release line.

## Branch Purpose

The `intergalaxion` branch is a laboratory for bootstrapping the **Intergalaxion Engine** —
the future core engine for zelynic. The goal is to evolve zelynic from a userspace-only
bandwidth manager into an eBPF-native observability and control plane, starting with a
pure eBPF observer-first approach.

This branch is **observer-only**. It does not enforce, block, drop, or mutate any kernel
state. The eBPF backend exists as a compile-safe model skeleton with no live program
attach, no runtime side effects, and no changes to existing stable CLI behavior.

## Relationship to Main

- **Main** is frozen as the stable v3.1.0 release line.
- The `intergalaxion` branch is branched from tag `v3.1.0`.
- No tags, releases, or package publications from this branch.
- No changes to v3.1.0 release artifacts.
- No changes to existing usage/ledger JSON schemas.
- No changes to existing stable CLI behavior.

## Design Principles (Phase I-0)

| Principle | Status |
|---|---|
| Observer-only | Yes — no enforcement, no packet drop |
| No packet drop | Yes — `packet_drop_enabled` always `false` |
| No block/allow commands | Yes — no new CLI commands |
| No quota | Yes — `quota_enabled` always `false` |
| No enforcement | Yes — `enforcement_enabled` always `false` |
| No nft/tc backend | Yes — only eBPF model skeleton |
| No procfs fallback backend | Yes — observer-only model |
| No kernel mutation | Yes — `mutation_performed` always `false` |
| Cgroup as identity anchor | Cgroup path is used as identity anchor, not as enforcement target |

## Module Tree

```
src/intergalaxion_engine/
  mod.rs              — Engine state and top-level types
  identity/mod.rs     — Process and cgroup identity model
  telemetry/mod.rs    — Telemetry sample and summary models
  ledger_bridge/mod.rs— Bridge from eBPF events to stable ledger
  safety/mod.rs       — Safety invariant checks
  backends/mod.rs     — Backend abstraction
  backends/ebpf/mod.rs — eBPF backend re-exports
  backends/ebpf/capability.rs — Capability detection model
  backends/ebpf/events.rs    — Event kind model
  backends/ebpf/maps.rs      — BPF map plan model
  backends/ebpf/observer.rs  — Observer and attach state model
  backends/ebpf/probe.rs     — Probe descriptor model
  tests.rs            — Deterministic tests (no root required)
```

## What This Branch Does NOT Add

- No new `block` or `allow` CLI command.
- No new `quota` CLI command.
- No nft/tc backend or fallback.
- No live eBPF program attach (no `aya` runtime usage).
- No packet drop capability.
- No enforcement capability.
- No runtime mutation of nft/tc/cgroup/PID state.
- No changes to existing `zelynic --version` output.
- No changes to existing `ledger inspect` or `ledger export` behavior.
- No public `intergalaxion` CLI subcommand.

## Success Criteria for I-0

1. Compile-safe engine skeleton that builds without warnings.
2. Safe capability model that defaults to unavailable.
3. Observer model that defaults to inactive.
4. Live attach is gated behind an explicit flag (not yet implemented).
5. All deterministic tests pass without root privileges.
6. Existing stable CLI behavior is unchanged.

## Legacy Branch

The legacy branch is **deferred** until the Intergalaxion eBPF approach proves itself
through successful phases (I-0, I-1, and beyond). No legacy branch will be created
until the eBPF observer demonstrates stable, correct telemetry collection on
real hardware.

## Next Phase

**I-1 — eBPF Capability Detector**: Runtime detection of eBPF kernel support,
BPF filesystem availability, CAP_BPF checks, and kernel config validation —
producing a structured capability report used to decide whether the observer
can be activated.
