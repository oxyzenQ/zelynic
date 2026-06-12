# I-34 — Brave cgroup Dry-Run Scope Renderer

**Phase**: I-34 (Intergalaxion Engine)
**Branch**: intergalaxion (experimental)
**Base**: main stable v3.1.0

## Purpose

Renders a deterministic cgroup/systemd scope plan for Brave, using
fixture-provided identity evidence from I-33 and limit plan from I-32.
Dry-run only. This phase does not execute commands, create cgroups, move
processes, or interact with systemd. It renders the plan only.

## Scope

Cgroup/systemd scope dry-run rendering only. Not a rate limiter. Not a
release. Not a public feature. Not a packet filter. Not an enforcement
engine. It answers: "How would Zelynic place Brave into a controllable
local lab scope?"

## Consumed Evidence

1. I-33 BraveIdentityScopeProof — identity readiness and candidate info
2. I-32 BraveLimitLabPlan — limit configuration and dry-run commands

## No Mutation

I-34 performs zero system mutation:
- No /proc scan
- No /sys/fs/cgroup read or write
- No cgroup creation
- No process move
- No systemd-run execution
- No systemd query
- No tc/ifb execution
- No packet drop
- No enforcement
- No persistence
- No release
- No public CLI

Live apply is forbidden in I-34. No live commands are executed.

## Scope Strategies

### ExistingCgroup
Renders inspection steps for an existing cgroup where Brave is already placed.
Reads cgroup.procs, verifies PID membership. No mutation intent.

### SystemdUserScope
Renders systemd-run intent for creating a transient user scope:
`systemd-run --user --scope --unit zelynic-brave-limit --property Slice=zelynic.slice brave`
Rollback: stop the transient scope.

### DedicatedLabCgroup
Renders intent for a dedicated lab cgroup at a clearly named path:
`/sys/fs/cgroup/zelynic/intergalaxion/brave-limit`
Creates directory, moves process via echo to cgroup.procs.
Rollback: move process back, remove directory.

## Future Target

Brave browser, 100KB/s download, 100KB/s upload. I-34 prepares the scope
where Brave can be placed before future tc/IFB limiting is wired.

## Types

1. BraveCgroupScopeStrategy (4 variants): ExistingCgroup, SystemdUserScope, DedicatedLabCgroup, Unsupported
2. BraveCgroupScopeStatus (6 variants): Draft, DryRunReady, Blocked, AmbiguousIdentity, LiveApplyForbidden, Unsupported
3. BraveCgroupScopeDecision (9 variants): Stop, RenderExistingCgroupScope, RenderSystemdUserScope, RenderDedicatedLabCgroup, RequireReadyIdentity, RejectAmbiguousIdentity, RejectLiveApply, RejectPublicCli, RejectMutation
4. BraveCgroupScopeStepKind (6 variants): InspectExistingScope, RenderSystemdScope, RenderDedicatedCgroup, RenderProcessMove, RenderRollback, RenderNoop
5. BraveCgroupScopeDryRunStep (6 fields): label, kind, command, requires_root, mutates_system, rollback
6. BraveCgroupScopeDryRunInput (16 fields): identity_proof, limit_plan, scope_name, strategy, dry-run/live flags, mutation allowances
7. BraveCgroupScopeDryRunPlan (32 fields): status, decision, strategy, scope_name, steps, rollback, safety flags, findings

## Helper Functions

1. `default_brave_cgroup_scope_dry_run_input()` — safe defaults with I-33 identity + I-32 limit plan
2. `build_brave_cgroup_scope_dry_run_plan(input)` — builds plan, renders steps, never executes
3. `validate_brave_cgroup_scope_dry_run_plan(plan)` — rejects any plan violating I-34 safety invariants
4. `brave_cgroup_scope_strategy_label(strategy)` — maps strategy to string
5. `brave_cgroup_scope_status_label(status)` — maps status to string
6. `brave_cgroup_scope_decision_label(decision)` — maps decision to string
7. `brave_cgroup_scope_step_kind_label(kind)` — maps step kind to string

## DryRunReady Requirements

- identity_proof validates and is ready (not ambiguous)
- limit_plan validates
- Target is Brave with selected PID and cgroup path
- explicit_dry_run=true, explicit_live_apply=false
- public_cli_requested=false
- No proc scan, cgroup read, systemd query, cgroup create, process move, mutation, persistence
- No fake scope or identity success

## Safety Invariants

- `release_allowed` = false (always)
- `must_remain_experimental` = true (always)
- `live_apply_allowed` = false (always)
- `public_cli_exposed` = false (always)
- All operation flags false (proc_scan, cgroup_read, systemd_query, cgroup_create, process_move, cgroup_mutation, persistence)
- `fake_scope_success_detected` = false (always)
- `fake_identity_success_detected` = false (always)

## Constraints

- No tag, release, publish, version bump, or main merge
- No public stable CLI
- No enforcement in default build
- No packet drop in default build
- No tc/ifb/cgroup backend currently active
- No ledger persistence for scope plans
- No mutation in default build
- All files under 1000 LOC

## Files

- `src/intergalaxion_engine/backends/ebpf/brave_cgroup_scope_dry_run.rs` — models and helpers
- `src/intergalaxion_engine/tests_i34.rs` — deterministic tests
- `docs/intergalaxion/I-34-brave-cgroup-dry-run-scope-renderer.md` — this document
