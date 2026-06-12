# I-35 — Brave tc/IFB Dry-Run Wiring Plan

**Phase**: I-35 (Intergalaxion Engine)
**Branch**: intergalaxion (experimental)
**Base**: main stable v3.1.0

## Purpose

Connects I-32 Brave 100KB/s limit plan, I-33 Brave identity scope proof,
and I-34 Brave cgroup scope dry-run plan into a concrete tc/IFB wiring plan.
Renders the exact command sequence that would limit Brave upload/download to
100KB/s. Dry-run only. This phase does not execute commands.

## Scope

tc/IFB dry-run wiring rendering only. Not a rate limiter. Not a release. Not
a public feature. Not a packet filter. Not an enforcement engine. It answers:
"What exact tc/IFB command sequence would be rendered to limit Brave
upload/download to 100KB/s later?"

## Consumed Evidence

1. I-32 BraveLimitLabPlan — 100KB/s upload/download rate configuration
2. I-33 BraveIdentityScopeProof — identity readiness with PID + cgroup evidence
3. I-34 BraveCgroupScopeDryRunPlan — scope readiness with dry-run steps

## No Mutation

I-35 performs zero system mutation:
- No tc execution
- No ip execution
- No IFB creation
- No qdisc creation
- No filter creation
- No cgroup mutation
- No packet drop
- No enforcement
- No persistence
- No /proc scan
- No /sys/fs/cgroup read or write
- No release
- No public CLI

Live apply is forbidden in I-35. No live commands are executed.
Upload/download live limit is not proven in I-35.

## Upload Wiring (tc egress HTB)

Renders upload command intent:
- tc qdisc replace dev <iface> root handle 1: htb default 10
- tc class add dev <iface> parent 1: classid <cgroup_class_id> htb rate 102400bps
- tc filter add dev <iface> protocol ip parent 1: prio 1 cgroup

## Download Wiring (IFB ingress redirect)

Renders download command intent:
- ip link add <ifb_name> type ifb
- ip link set <ifb_name> up
- tc qdisc add dev <iface> ingress
- tc filter add dev <iface> ingress protocol ip parent ffff: prio 1 flower action mirred egress redirect dev <ifb_name>
- tc qdisc add dev <ifb_name> root handle 1: htb
- tc class add dev <ifb_name> parent 1: classid 1:10 htb rate 102400bps

## Rollback Wiring

Renders rollback command intent:
- tc qdisc delete dev <iface> root (upload rollback)
- tc qdisc delete dev <iface> ingress (download rollback)
- tc qdisc delete dev <ifb_name> root (download rollback)
- ip link delete <ifb_name> (download rollback)

## Honesty

Download limiting is harder than upload. I-35 renders the IFB ingress path
honestly but does not claim download live proof. I-35 distinguishes:
- command intent rendered (dry-run step exists)
- dry-run wiring ready (all preconditions met)
- live apply allowed (always false)
- live limit proven (always false)

## Types

1. BraveTcIfbDirection (2 variants): Upload, Download
2. BraveTcIfbWiringBackend (4 variants): TcEgressHtb, TcIngressIfbRedirect, CgroupFilter, Unsupported
3. BraveTcIfbWiringStatus (5 variants): Draft, DryRunReady, Blocked, LiveApplyForbidden, Unsupported
4. BraveTcIfbWiringDecision (10 variants): Stop, RenderUploadTcEgress, RenderDownloadIfbIngress, RenderFullDryRun, RequireReadyIdentity, RequireReadyScope, RequireInterface, RejectLiveApply, RejectPublicCli, RejectMutation
5. BraveTcIfbWiringStepKind (11 variants): RenderTcRootQdisc, RenderTcClass, RenderTcCgroupFilter, RenderIngressQdisc, RenderIfbLinkAdd, RenderIfbLinkUp, RenderIngressRedirect, RenderIfbRootQdisc, RenderIfbClass, RenderRollback, RenderNoop
6. BraveTcIfbDryRunStep (7 fields): label, kind, direction, command, requires_root, mutates_system, rollback
7. BraveTcIfbDryRunWiringInput (20 fields): limit_plan, identity_proof, scope_plan, interface, ifb_name, cgroup_class_id, rates, flags, mutation allowances
8. BraveTcIfbDryRunWiringPlan (35 fields): status, decision, backends, readiness flags, step vectors, safety flags, findings

## Helper Functions

1. `default_brave_tc_ifb_dry_run_wiring_input()` — safe defaults with I-32 + I-33 + I-34
2. `build_brave_tc_ifb_dry_run_wiring_plan(input)` — builds plan, renders steps, never executes
3. `validate_brave_tc_ifb_dry_run_wiring_plan(plan)` — rejects any plan violating I-35 safety invariants
4. `brave_tc_ifb_direction_label(direction)` — maps direction to string
5. `brave_tc_ifb_wiring_backend_label(backend)` — maps backend to string
6. `brave_tc_ifb_wiring_status_label(status)` — maps status to string
7. `brave_tc_ifb_wiring_decision_label(decision)` — maps decision to string
8. `brave_tc_ifb_wiring_step_kind_label(kind)` — maps step kind to string

## DryRunReady Requirements

- limit_plan validates
- identity_proof validates
- scope_plan validates
- identity_proof.identity_ready=true
- scope_plan.dry_run_ready=true
- interface is present
- cgroup_class_id is present
- download/upload rates parse to 102400 bytes/sec
- explicit_dry_run=true
- explicit_live_apply=false
- public_cli_requested=false
- No tc/ip/ifb/filter/qdisc apply
- No cgroup mutation
- No packet drop
- No persistence
- No fake upload/download/wiring success

## Safety Invariants

- `release_allowed` = false (always)
- `must_remain_experimental` = true (always)
- `live_apply_allowed` = false (always)
- `public_cli_exposed` = false (always)
- All operation flags false (tc_apply, ip_apply, ifb_create, filter_create, qdisc_create, cgroup_mutation, packet_drop, persistence)
- `upload_live_limit_proven` = false (always)
- `download_live_limit_proven` = false (always)
- `fake_upload_limit_success_detected` = false (always)
- `fake_download_limit_success_detected` = false (always)
- `fake_wiring_success_detected` = false (always)
- All rendered steps mutates_system=false

## Constraints

- No tag, release, publish, version bump, or main merge
- No public stable CLI
- No enforcement in default build
- No packet drop in default build
- No tc/ifb/cgroup backend currently active
- No ledger persistence for wiring plans
- No mutation in default build
- All files under 1000 LOC

## Future Target

I-36 — Brave Upload Live-Apply Readiness Gate

## Files

- `src/intergalaxion_engine/backends/ebpf/brave_tc_ifb_dry_run_wiring.rs` — models and helpers
- `src/intergalaxion_engine/tests_i35.rs` — deterministic tests
- `docs/intergalaxion/I-35-brave-tc-ifb-dry-run-wiring-plan.md` — this document
