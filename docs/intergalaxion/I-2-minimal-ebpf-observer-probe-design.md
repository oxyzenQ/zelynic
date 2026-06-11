# I-2 — Minimal eBPF Observer Probe Design

> **This is an experimental branch only.**
> Main remains stable v3.1.0. Legacy branch is deferred.

## Phase

**I-2 — Minimal eBPF Observer Probe Design**

I-2 defines probe design/model only. No live kernel operations occur.

## What I-2 Adds

Probe plan model structs that describe a future observer probe configuration:

- `EbpfProbeKind` — Noop, SocketObserver, CgroupSkbObserver, TracepointObserver
- `EbpfProbeSafetyMode` — ModelOnly, CompileOnly, AttachDisabled
- `EbpfProbePlan` — Full probe configuration with safety gates
- `EbpfObserverProbeDesign` — Composite of plan + event kind + map plan + observer state
- `validate_probe_plan_safety()` — Rejects any plan enabling live kernel operations
- Factory helpers: `minimal_socket_observer_probe_plan()`, `minimal_cgroup_skb_observer_probe_plan()`, `minimal_tracepoint_observer_probe_plan()`

## Hard Rules (I-2)

- no eBPF attach
- no eBPF program load
- no eBPF map create
- no eBPF map pin
- no packet drop
- no enforcement
- no block/allow/quota
- no nft/tc fallback
- no nft/tc backend
- no public CLI
- no kernel mutation
- no dependency changes

## Safety Model

All default probe plans have:

- `safety_mode = ModelOnly`
- `program_load_enabled = false`
- `attach_enabled = false`
- `map_create_enabled = false`
- `map_pin_enabled = false`
- `packet_drop_enabled = false`
- `enforcement_enabled = false`
- `mutation_enabled = false`

The validator (`validate_probe_plan_safety`) rejects any plan that enables any of the above flags.

## Cgroup Usage

Cgroup may be referenced as an identity/attachment concept in the CgroupSkbObserver probe kind. It is never mutated, never used for enforcement, and never used for packet dropping.

## Capability Detector Continuity

The capability detector from I-1 remains read-only. Its defaults (unavailable) are unchanged.

## Success Criteria

1. Probe plan model exists and compiles.
2. Unsafe probe plans are rejected by the validator.
3. Observer design stays model-only (no live operations).
4. Existing CLI remains unchanged (version, ledger, help).

## Files Changed

| File | Purpose |
|---|---|
| `src/intergalaxion_engine/backends/ebpf/probe_plan.rs` | New: probe plan model, validator, factory helpers |
| `src/intergalaxion_engine/backends/ebpf/mod.rs` | Extended: register probe_plan module |
| `src/intergalaxion_engine/tests.rs` | Extended: ~40 new I-2 deterministic tests |
| `docs/intergalaxion/I-2-minimal-ebpf-observer-probe-design.md` | New: this document |

## Next Phase

**I-3 — eBPF Event Schema and Ring Buffer Model**: Define the event schema for observer output, ring buffer layout for streaming events from kernel to userspace, and a compile-safe ring buffer model.
