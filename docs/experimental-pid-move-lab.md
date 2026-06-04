# Zelynic v2.8 Experimental PID Move Lab — Design Document

This document captures the design for the v2.8.0 Experimental PID Move Lab,
the first milestone in Zelynic that may eventually perform real cgroup writes
from the Scope Runner. The v2.8 phase 1 is **design-only**: it produces this
document and updates related documentation but introduces no runtime changes.

## Purpose

v2.8 is the first lab that may eventually perform real cgroup writes. The
design is intentionally conservative and incremental:

- The first real write must be **cgroup-only** — a `mkdir` under
  `/sys/fs/cgroup/zelynic/` with no PID movement.
- No bandwidth limiting in v2.8 early phases.
- No nftables/tc/state mutation in early phases.
- Every write step is explicit, operation-owned, and has a rollback story
  before it is implemented.
- Live limiter attach from the Scope Runner remains not implemented in v2.8.

The v2.7 Experimental Attach Lab established the pure models for the gate
checklist, move-only executor skeleton, target cgroup preflight, cgroup
environment diagnostics, and operation journal preview. v2.8 builds on those
models to define the exact boundary where real writes begin and how each
write step is validated and rolled back.

## Phase Ladder

v2.8 is decomposed into five sequential phases. Each phase must pass CI, pass
a local root smoke matrix, and be documented before the next phase begins.

### Phase 1: Design Only (Completed)

- Produce this design document.
- Update `docs/scope-lab.md`, `docs/systemd-wrapper-design.md`, and
  `CHANGELOG.md` with cross-references.
- No runtime changes. No Rust code modifications.
- This phase establishes the safety gates, write boundaries, rollback rules,
  forbidden behaviors, manual smoke strategy, and success criteria that all
  subsequent phases must follow.

### Phase 2a: Mkdir-Only Executor Skeleton (Completed)

- Add a pure, non-mutating mkdir-only executor skeleton to the experimental
  attach gate output in `src/systemd_wrapper/mkdir_transaction.rs`.
- The skeleton models the exact future mkdir-only write sequence:
  1. Create/prepare `/sys/fs/cgroup/zelynic` (namespace directory).
  2. Create/prepare `/sys/fs/cgroup/zelynic/target_<name>` (target cgroup).
  3. Verify target cgroup directory exists.
  4. Cleanup target cgroup only if operation-owned and empty.
- No PID movement. No `cgroup.procs` write. No nftables/tc/state writes.
- The skeleton is hard-blocked: output includes `status: skeleton only; not
  executed`, `execution: blocked`, and `first real write: not enabled in this build`.
- The canonical safety footer is rendered once (not duplicated).
- Local validation passed: 328 unit tests + 4 integration tests, 5 ignored,
  clippy clean, policy PASS, fmt clean.

### Phase 2b: Actual Mkdir-Only Experiment (Completed)

- Implemented the first real-write experiment in `src/systemd_wrapper/mkdir_executor.rs`.
- When `--mkdir-live` is present with all existing gates, the command:
  1. Launches the transient systemd scope as the current root probe does.
  2. Discovers PID/control group as usual.
  3. Runs existing read-only safety checks as usual.
  4. Creates/prepares `/sys/fs/cgroup/zelynic` (namespace directory).
  5. Creates/prepares `/sys/fs/cgroup/zelynic/target_<name>` (target cgroup).
  6. Verifies the target cgroup directory exists.
  7. Removes the target cgroup only if it is empty, operation-owned, and safe.
  8. Leaves `/sys/fs/cgroup/zelynic` in place (namespace directory).
- New `--mkdir-live` flag requires all existing experimental consent flags
  (`--execute`, `--scope-mode system`, `--probe-live`, `--attach-live`,
  `--experimental-single-pid-attach`, `--i-understand-this-moves-pids`,
  `--rollback-required`).
- No PID movement. No `cgroup.procs` write. No nftables/tc/state writes.
- Cleanup only removes empty, operation-owned target cgroups. On uncertainty,
  the target is left in place and reported.
- Tests use temp directories; no live `/sys/fs/cgroup` in unit tests.
- The `--attach-live` path remains hard-blocked and non-mutating when
  `--mkdir-live` is absent.

### Phase 2b.1: Output Honesty Fix (Completed)

- Fixed misleading canonical safety footer when `--mkdir-live` is active.
- The old footer "No nftables, tc, Zelynic cgroup, or state changes were
  made" is replaced with truthful wording:
  "No nftables, tc, or Zelynic state changes were made." and
  "Mkdir-only cgroup preparation was performed."
- Added explicit honest lines to the mkdir experiment section output:
  "No cgroup.procs write was performed." and
  "Parent namespace may remain: /sys/fs/cgroup/zelynic".
- Added honest error message for `--mkdir-live` + `--attach-live`:
  "Mkdir-only experiment completed; experimental PID move is not
  implemented yet."
- Normal non-mkdir paths preserve the existing canonical safety footer
  unchanged. No runtime behavior change.

### Phase 2c: Validation Report + Release Prep (Completed)

- Produced validation report (`docs/v2.8-phase-2c-validation-report.md`)
  documenting the first real write (mkdir-only), output honesty,
  non-root gate verification, and root mkdir-live smoke validation.
- Updated this design document with phase status markers.
- No runtime changes. Docs/report only.

### Phase 3a: Single PID Move + Rollback Design (Current Phase)

- Produced design document
  (`docs/v2.8-phase-3a-single-pid-rollback-design.md`)
  specifying the first actual PID move experiment.
- The design specifies: root-only, system-scope-only, single disposable PID
  (`sleep 3` or `sleep 10`), immediate rollback, no limiter attach, no
  nft/tc/state mutation, no persistent state write, no multi-PID process
  trees, no user scope, no long-running apps, no browser/terminal/desktop
  processes, no bandwidth limiting claim.
- Includes exact 10-step transaction model: gate re-evaluation, PID
  liveness recheck, original cgroup validation, target cgroup preparation,
  move PID to target, verify in target, record move success, rollback PID
  to original, verify restored, cleanup target cgroup.
- Includes failure policy: every failure after move attempts rollback,
  rollback failure reported loudly, no retry loops, no limiter attach even
  if move succeeds, no cleanup of non-empty cgroups, no cleanup outside
  `/sys/fs/cgroup/zelynic`.
- Includes test plan: unit tests for transaction model, output honesty
  tests, gate tests (non-root blocked, user-scope blocked, multi-PID
  blocked, zelynic/self PID blocked, invalid original cgroup blocked),
  cleanup safety tests. Root smoke test deferred to future implementation.
- No runtime changes. Docs/design only.
- Live PID movement is still not implemented.

### Phase 3: Single PID Move-Only + Immediate Rollback (Not Started)

- Design-only. Does not implement PID movement.
- Produces design documentation for the move sequence, rollback protocol,
  and verification steps.
- The first actual PID move (when eventually implemented in a future
  phase) must be root-only, system-scope-only, single disposable PID
  (e.g., `sleep 3`), with immediate rollback, no limiter attach, no
  nftables/tc/state mutation, and no persistent state write.

### Phase 2: Target Cgroup `mkdir`-Only Experiment

- Introduce a narrow, guarded code path that creates
  `/sys/fs/cgroup/zelynic/` (if absent) and
  `/sys/fs/cgroup/zelynic/target_<name>` — and nothing else.
- No PID movement. No `cgroup.procs` write.
- No nftables/tc/state writes.
- The `mkdir` path requires every safety gate defined in this document.
- After the child process exits, the created cgroup must be removed only if
  it is empty and operation-owned.
- Local root smoke must confirm the cgroup appears and disappears, and that
  no other system state is modified.

### Phase 3: Single PID Move-Only + Immediate Rollback (Future)

- Design-only next. Does not implement PID movement.
- Must produce design documentation for the move sequence, rollback
  protocol, and verification steps before any code is written.
- When eventually implemented, the first actual PID move must be:
  root-only, system-scope-only, single disposable PID (e.g., `sleep 3`),
  with immediate rollback, no limiter attach, no nftables/tc/state
  mutation, and no persistent state write.
- See the phase 3 section above for the full move sequence design.
- Local root smoke must confirm the PID moves to the target, is restored to
  the original cgroup, and the target cgroup is cleaned up.

### Phase 4: Rollback Failure Simulation / Stale PID Handling

- Introduce tests and guarded paths for edge cases:
  - PID exits between move and rollback.
  - Original cgroup becomes unavailable after capture.
  - Target cgroup is not empty on cleanup.
  - Rollback `cgroup.procs` write fails.
- No limiter attach. No nftables/tc/state writes.
- All failure modes must be reported honestly.
- If rollback cannot safely complete, leave diagnostics and do not attempt
  risky cleanup.

### Phase 5: Validation Report and Release Prep

- Produce a validation report documenting all local smoke tests across
  phases 2 through 4.
- Produce release notes for v2.8.0.
- Confirm CI remains green.
- Confirm docs are honest that live limiter attach is still not implemented.
- Commit and push release documentation to main.

## Strict Safety Gates for Any Future Write

Every future write path in v2.8 must require **all** of the following gates.
Missing any single gate must block the write unconditionally. The gate
evaluation order must match the list below.

### Required Flags

| Gate | Requirement | Enforcement |
|------|-------------|-------------|
| `--execute` | Must be set | Clap `requires` |
| `--scope-mode system` | Must be `system` | Probe gate |
| `--probe-live` | Must be set | Clap `requires` |
| `--attach-live` | Must be set | Clap `requires` |
| `--experimental-single-pid-attach` | Must be set | Clap `requires` / gate check |
| `--i-understand-this-moves-pids` | Must be set | Clap `requires` / gate check |
| `--rollback-required` | Must be set | Clap `requires` / gate check |
| `--mkdir-live` | Must be set for real mkdir experiment | Clap `requires` / runtime gate |

### Required Runtime Conditions

| Gate | Requirement | Source |
|------|-------------|--------|
| Root / euid == 0 | Must be root | Probe gate |
| Discovered PID count == 1 | Exactly one PID in scope `cgroup.procs` | Live probe result |
| PID liveness == alive | `/proc/<pid>` must exist at gate time | PID safety check |
| Self-protection == allowed | PID must not be zelynic or already-managed | PID safety check |
| Original cgroup captured | `/proc/<pid>/cgroup` read must succeed | Live probe result |
| Rollback target valid | Captured path must be under cgroup v2, not under `/zelynic` | Original cgroup model |

### Required Model Conditions

| Gate | Requirement | Source |
|------|-------------|--------|
| Target cgroup path under `/sys/fs/cgroup/zelynic/` | Path must not contain `..` or escape namespace | Target cgroup preflight |
| Operation journal preview available | Journal must have a deterministic operation ID | Operation journal model |
| Operation owner is `zelynic-scope-runner` | Owner label must match expected value | Operation journal model |
| Mutation mode is `move-only` | Mode must be explicitly `move-only`, not `attach` | Executor model |
| nft/tc/state disabled | These subsystems must not be enabled for v2.8 writes | Executor model |

Any gate failure must block before any write is attempted. The gate checklist
must be re-evaluated immediately before the first write, not cached from probe
time. PIDs may exit between discovery and the write moment; liveness must be
rechecked.

## First Real Write Boundary

The first write in v2.8 phase 2 is the narrowest possible mutation: creating
empty cgroup directories. This is the `mkdir`-only experiment.

### What Phase 2 May Write

- Create `/sys/fs/cgroup/zelynic/` if it does not already exist. This is the
  Zelynic cgroup namespace directory. It must only be created if absent and
  must not modify any existing directory metadata.
- Create `/sys/fs/cgroup/zelynic/target_<name>` as the target cgroup for the
  operation. The `<name>` is derived from the sanitized target name used in
  the scope probe. The directory must be empty after creation.

### What Phase 2 Must NOT Write

- No PID movement.
- No write to `cgroup.procs` in any cgroup.
- No nftables rules, chains, or tables.
- No tc qdisc, class, or filter changes.
- No Zelynic state file writes (e.g., `/run/zelynic/state.json`).
- No systemd unit modification beyond the probe scope.
- No modification to any cgroup outside `/sys/fs/cgroup/zelynic/`.

### Verification After Phase 2 Write

After the target cgroup is created, the code must verify:

- The directory exists.
- The directory is empty (no PIDs in its `cgroup.procs`).
- The directory is under the Zelynic namespace.

If any verification fails, the write must be rolled back (directory removed)
and the failure must be reported honestly.

### Cleanup After Phase 2

After the child process exits and the scope transitions to inactive/dead:

- Remove `/sys/fs/cgroup/zelynic/target_<name>` only if it is empty and
  operation-owned.
- Do not remove `/sys/fs/cgroup/zelynic/` if it existed before the operation
  or if it contains other cgroups.
- If removal fails, leave the directory and report the failure. Do not
  attempt recursive or forced removal.

## PID Move-Only Boundary

Phase 3 introduces the first PID movement. This is a move-and-immediately-rollback
operation, not a persistent move. The PID must visit the target cgroup and
return to its original cgroup within the same operation.

### Future Phase 3 Sequence

1. Re-evaluate every safety gate from the gate checklist.
2. Recheck PID liveness at the moment of move.
3. Verify the original cgroup path is still valid and accessible.
4. Write the single PID to `/sys/fs/cgroup/zelynic/target_<name>/cgroup.procs`.
5. Read `/sys/fs/cgroup/zelynic/target_<name>/cgroup.procs` to verify the PID
   appears.
6. Write the single PID to the original cgroup's `cgroup.procs` (rollback).
7. Read the original cgroup's `cgroup.procs` to verify the PID is restored.
8. Remove `/sys/fs/cgroup/zelynic/target_<name>` only if empty and safe.

### What Phase 3 Must NOT Do

- No limiter attach (no nftables, no tc, no bandwidth enforcement).
- No multi-PID moves.
- No persistent PID placement (the PID must be restored before the operation
  returns).
- No state file writes.

## Rollback Rules

Rollback is the most critical safety mechanism in v2.8. Every write must have
an explicit, tested rollback path before the write is implemented.

### Rollback Target

- The rollback target must be captured before any move. It is the PID's
  original cgroup path read from `/proc/<pid>/cgroup` during the live probe.
- The rollback target must be a valid cgroup v2 path under the cgroup
  filesystem root. It must not be under `/zelynic/` (restoring into a
  Zelynic-managed target would be unsafe).
- If the original cgroup cannot be captured (e.g., PID already exited), the
  move must not proceed.

### Rollback Timing

- Rollback must happen immediately after the test move. There is no
  persistent move in v2.8.
- The window between move and rollback should be as short as possible. No
  sleep, no network call, no user prompt between move and rollback.
- If the rollback write fails, the code must report the failure honestly and
  leave diagnostics. It must not silently ignore the failure or attempt
  untested recovery.

### Rollback Scope

- Rollback must not remove non-owned state. Only cgroups and state that were
  created by the current operation may be touched during cleanup.
- Cleanup may only remove the operation-owned target cgroup, and only if it
  is empty and safe to remove.
- Failures must be reported honestly. If cleanup cannot confirm the target
  cgroup is empty, it must leave it and report the condition.
- If rollback cannot safely complete, leave diagnostics and do not attempt
  risky cleanup. A leftover empty cgroup directory is safer than an
  incorrect forced removal.

## Forbidden Behavior

The following behaviors are explicitly forbidden in v2.8 and must not be
introduced in any phase:

- **No multi-PID moves:** v2.8 is single-PID only. Discovered PID count must
  equal exactly 1.
- **No process-name attach:** PIDs must come from the live scope probe
  (`cgroup.procs`), not from process-name resolution.
- **No user-scope mutation:** All writes require system scope and root.
  User-scope live execution must remain blocked.
- **No nftables/tc in v2.8 early phases:** Phases 2 through 4 must not touch
  nftables rules, tc qdisc, classes, or filters. Bandwidth enforcement is
  out of scope for v2.8.
- **No persistent state writes:** No `/run/zelynic/state.json` or other
  persistent state files before an explicit state design is completed.
- **No background mutation:** All writes must occur synchronously within the
  operation lifecycle. No background threads, no deferred cleanup, no async
  mutation.
- **No automatic cleanup of unknown cgroups:** Cleanup must only touch
  operation-owned cgroups. Zelynic must never scan for or remove cgroups it
  did not create in the current operation.
- **No deleting external cgroups:** Cgroups outside `/sys/fs/cgroup/zelynic/`
  must never be modified or removed by the Scope Runner.
- **No ignoring rollback failures:** If a rollback step fails, the failure
  must be reported. Silently continuing after a failed rollback is
  forbidden.

## Manual Smoke Strategy

Each v2.8 phase that introduces a write must be validated with a manual root
smoke test on a real cgroup v2 host. The smoke strategy is designed to
minimize risk:

### Command Selection

- Use a disposable command only, e.g., `sleep 3`, `sleep 10`, or `true`.
- System-scope only (`--scope-mode system`).
- Root only (euid == 0).
- Full experimental consent bundle required:
  `--experimental-single-pid-attach --i-understand-this-moves-pids --rollback-required`.

### Inspection After Command

- Inspect `ActiveState` and `SubState` of the scope unit via `systemctl show`.
- Confirm the scope transitions to `inactive/dead` after the child exits.
- In phase 2 and later: inspect target cgroup state only if created by the
  operation. Confirm it is empty and removed after cleanup.
- Confirm no leftover scope unit.

### Post-Operation Verification

- Confirm no leftover scope: `systemctl list-units --type=scope | grep zelynic`
  should return nothing.
- Confirm no limiter active: `zelynic status` should show no active limits.
- Confirm no nftables/tc/state mutation: `nft list table inet zelynic`,
  `tc qdisc show`, and `/run/zelynic/` should be unchanged from pre-operation
  state.

### Non-Root Gate Verification

The non-root smoke test with all experimental consent flags must remain
blocked:

```bash
zelynic run --execute --scope-mode system --probe-live --attach-live \
  --experimental-single-pid-attach --i-understand-this-moves-pids \
  --rollback-required -d 500kbit -u 500kbit -- sleep 30
# Expected: "Scope Runner live probe requires root (euid == 0)."
# No scope launched, no mutation.
```

## Success Criteria for v2.8

v2.8 is considered successful when all of the following are true:

- Every real write introduced in v2.8 is explicit and operation-owned. There
  are no implicit side effects, no background mutations, and no writes to
  paths outside the Zelynic namespace.
- Every write has a rollback story. Before any write is implemented, the
  rollback path is documented, tested in unit tests, and validated in a local
  root smoke test.
- Every phase has a local root smoke matrix. Each smoke test documents the
  exact command, expected behavior, post-operation state, and observed results.
- CI remains green across all phases. Every new code path has corresponding
  unit tests, gate tests, and output-wording tests.
- Documentation is honest that live limiter attach is still not implemented.
  The Scope Runner in v2.8 can create empty cgroups (phase 2) and move a
  single PID with immediate rollback (phase 3), but it does not apply
  bandwidth limits, modify nftables/tc, or write persistent state.
- No PID is left in a Zelynic cgroup after any operation completes.
- No cgroup directory is left behind unless removal was unsafe, in which case
  the failure is documented.

## Current Status

v2.8 phase 3a is the current phase. It produces a design document for
the single PID move + immediate rollback experiment. No runtime changes are
introduced. Live PID movement remains not implemented.

| Property | Status |
|----------|--------|
| PID movement | Not implemented (phase 3a: design documented) |
| Cgroup directory creation | Phase 2b: mkdir-only with --mkdir-live (first real write) |
| Output honesty | Phase 2b.1: truthful footer for --mkdir-live path |
| `cgroup.procs` write | Not implemented (phase 3a: design documented) |
| Limiter attach | Not implemented |
| nftables/tc/state changes | Not implemented |
| `--attach-live` | Hard-blocked / non-mutating |
| Phase 3a (PID move design) | Current: `docs/v2.8-phase-3a-single-pid-rollback-design.md` |
| Validation report | Phase 2c: `docs/v2.8-phase-2c-validation-report.md` |

## Next Milestone After v2.8

The v2.8 Experimental PID Move Lab proves that Zelynic can safely perform a
single-PID cgroup move with immediate rollback. After v2.8 is validated:

- **v2.9 or later** may explore limiter attach from the Scope Runner, but only
  after PID move and rollback are proven reliable across multiple hosts and
  edge cases. The first limiter attach would likely be a single-PID move with
  persistent placement and nftables/tc enforcement, with rollback still
  available.
- **v3.0** remains the milestone for runtime path migration and backend
  abstraction stabilization. The current tc/nftables/cgroup backend would
  remain the only active backend until v3.0.
- **eBPF** remains future work with no timeline. It is not in scope for v2.8
  or v2.9.

The incremental approach ensures each mutation type is validated in
isolation before combining them. The pure models from v2.7 (executor
skeleton, target preflight, cgroup diagnostics, operation journal) provide the
safety groundwork for the v2.8 real write path.
