# I-32 — Brave 100KB/s Local Limit Lab Plan

**Phase**: I-32 (Intergalaxion Engine)
**Branch**: intergalaxion (experimental)
**Base**: main stable v3.1.0

## Purpose

First concrete local lab plan for limiting Brave browser to 100KB/s download
and 100KB/s upload. Model-only, dry-run only. No actual tc/ifb/cgroup execution.
No packet drop. No enforcement. No public CLI exposure.

This phase answers concretely:

1. How do we identify Brave? — By process name "brave" or "brave-browser"
2. How do we place Brave into a controllable local lab scope? — Via cgroup attribution with tc qdisc
3. Which backend path should be used first? — Linux tc-based local lab backend
4. What commands would be rendered for dry-run? — tc qdisc/class/filter + IFB ingress redirect
5. What rollback would be rendered? — Remove qdisc, delete IFB device, remove ingress filter
6. What exact safety gates are required before live apply? — Root, explicit experimental ack, no public CLI
7. What should the future live command look like? — Described in Future Commands section

## Scope

Lab plan model only. Not a release. Not a public feature. Not a live enforcement
engine. Not a kernel module. Not a packet filter. It is a concrete plan with
dry-run rendered commands that are never executed.

## No Mutation

I-32 performs zero system mutation:
- No tc execution
- No IFB device creation
- No cgroup writes
- No packet drop
- No enforcement
- No persistence
- No release
- No public CLI

## Brave 100KB/s Target

- Download limit: 100KB/s (102400 bytes/sec)
- Upload limit: 100KB/s (102400 bytes/sec)
- Target process: brave or brave-browser
- Backend: Linux tc (traffic control)

## Backend Design

### Upload Shaping (egress)
- Path: tc egress qdisc (HTB)
- Class with rate limit applied to egress path
- cgroup filter for Brave process attribution
- Status: Planned, not yet proven

### Download Shaping (ingress)
- Path: IFB (Intermediate Functional Block) ingress redirect
- Create IFB device, redirect ingress traffic from real interface to IFB
- Apply HTB rate limit on IFB device
- Status: Planned, requires IFB ingress attribution proof

### Why Download Is Harder

Per-app download limiting requires redirecting ingress traffic through an IFB
device and attributing it to a specific process cgroup. This is significantly
more complex than egress shaping because:
- Ingress traffic arrives before the kernel routes it to a process
- Attribution requires either cgroup matching or flow-based classification
- IFB redirect adds complexity and a second qdisc layer

I-32 honestly marks download as "requires IFB ingress attribution proof" rather
than claiming success without proof. Live apply is forbidden in I-32.

## Types

1. BraveLimitDirection (2 variants): Download, Upload
2. BraveLimitBackend (4 variants): TcEgress, TcIngressIfb, CgroupScopedTc, Unsupported
3. BraveLimitTargetStatus (4 variants): Unknown, Candidate, Ready, Blocked
4. BraveLimitLabPlanStatus (5 variants): Draft, DryRunReady, Blocked, LiveApplyForbidden, Unsupported
5. BraveLimitLabDecision (8 variants): Stop, RenderDryRun, RequireInterface, RequireBraveIdentity, RequireRootForFutureApply, RequireIfbForDownload, RejectLiveApply, RejectPublicCli
6. BraveLimitCommandStep (5 fields): label, command, requires_root, mutates_system, rollback
7. BraveLimitLabPlanInput (15 fields): target, interface, rates, pid/cgroup, dry-run/live flags, mutation allowances
8. BraveLimitLabPlan (30 fields): status, decision, backends, commands, rollback, safety flags, findings

## Helper Functions

1. `default_brave_limit_lab_plan_input()` — safe defaults targeting brave with 100KB/s rates
2. `build_brave_limit_lab_plan(input)` — builds plan, renders dry-run commands, never executes
3. `validate_brave_limit_lab_plan(plan)` — rejects any plan violating I-32 safety invariants
4. `parse_limit_rate_bytes_per_sec(rate)` — parses "100KB/s" to 102400 bytes/sec
5. `brave_limit_lab_plan_status_label(status)` — maps status to string
6. `brave_limit_backend_label(backend)` — maps backend to string
7. `brave_limit_target_status_label(status)` — maps target status to string

## Rate Parser

Accepts: "100KB/s", "100kb/s", "100KiB/s" — all parse to 102400 bytes/sec.
Rejects: empty, zero, negative, unsupported units (MB/s, GB/s, etc.).
Convention: 1 KB = 1024 bytes (binary).

## Dry-Run Commands (rendered but never executed)

### Upload (tc egress):
- `tc qdisc replace dev <iface> root handle 1: htb default 10`
- `tc class add dev <iface> parent 1: classid 1:10 htb rate 102400bps`
- `tc filter add dev <iface> protocol ip parent 1: prio 1 cgroup`

### Download (IFB ingress):
- `ip link add ifb-zelynic-brave type ifb`
- `ip link set ifb-zelynic-brave up`
- `tc qdisc add dev <iface> ingress`
- `tc filter add dev <iface> ingress protocol ip parent ffff: prio 1 flower action mirred egress redirect dev ifb-zelynic-brave`
- `tc qdisc add dev ifb-zelynic-brave root handle 1: htb`
- `tc class add dev ifb-zelynic-brave parent 1: classid 1:10 htb rate 102400bps`

### Rollback:
- `tc qdisc delete dev <iface> root`
- `ip link delete ifb-zelynic-brave`
- `tc qdisc delete dev <iface> ingress`

All commands rendered with `mutates_system=false` and `requires_root=true` for
tc/ip steps. No command is executed in I-32.

## Safety Invariants

- `release_allowed` = false (always)
- `must_remain_experimental` = true (always)
- `live_apply_allowed` = false (always)
- `public_cli_exposed` = false (always)
- `tc_mutation_performed` = false (always)
- `ifb_mutation_performed` = false (always)
- `cgroup_mutation_performed` = false (always)
- `packet_drop_performed` = false (always)
- `persistence_performed` = false (always)
- `fake_limit_success_detected` = false (always)
- `download_limit_claimed_without_ifb_proof` = false (in validated plan)
- `upload_limit_claimed_without_tc_proof` = false (in validated plan)

## Future Commands (not implemented in I-32)

Dry-run (experimental only, hidden):
```
zelynic intergalaxion limit brave --download 100KB/s --upload 100KB/s --interface <iface> --dry-run
```

Live apply (experimental only, requires root and ack, not implemented):
```
sudo zelynic intergalaxion limit brave --download 100KB/s --upload 100KB/s --interface <iface> --apply --i-understand-this-is-experimental
```

Neither command is exposed in public help in I-32.

## Constraints

- No tag, release, publish, version bump, or main merge
- No public stable CLI
- No enforcement in default build
- No packet drop in default build
- No tc/ifb/cgroup backend currently active
- No ledger persistence for lab plans
- No mutation in default build
- All files under 1000 LOC

## Files

- `src/intergalaxion_engine/backends/ebpf/brave_limit_lab_plan.rs` — models and helpers
- `src/intergalaxion_engine/tests_i32.rs` — deterministic tests
- `docs/intergalaxion/I-32-brave-100kbps-local-limit-lab-plan.md` — this document
