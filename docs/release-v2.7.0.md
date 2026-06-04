# Zelynic v2.7.0 Experimental Attach Lab

Zelynic v2.7.0 "Experimental Attach Lab" extends the Scope Runner with a
comprehensive set of pure, non-mutating models that document every safety gate,
consent flag, write sequence, rollback plan, and operation journal that a future
single-PID move-only attach experiment would require. This release does NOT
implement live PID movement, does NOT create cgroup directories, does NOT write
`cgroup.procs`, does NOT apply nftables or tc changes from the Scope Runner,
and does NOT persist any operation journal. The `--attach-live` flag remains
hard-blocked. `zelynic strict` remains the only validated active limiter path.

## Summary

The v2.7.0 release covers five feature phases and one CLI refactor phase, all
merged to main with CI green. Phase 1 introduces explicit consent flags and an
experimental attach gate checklist. Phase 1.1 refactors the CLI module to stay
under the 1000 LOC policy limit. Phase 2 adds a move-only executor skeleton
that models the exact future write order for a single-PID cgroup move and
immediate rollback. Phase 3 adds target cgroup preflight with future filesystem
path validation. Phase 4 adds cgroup environment diagnostics. Phase 5 adds an
operation journal preview with deterministic operation IDs, ownership labels,
and rollback boundaries. Every phase is model-only — no live mutation is
performed in any phase.

## What Changed

### Phase 1: Experimental Attach Gate Checklist

- Added three explicit consent flags for a future single-PID, move-only
  attach experiment:
  - `--experimental-single-pid-attach`
  - `--i-understand-this-moves-pids`
  - `--rollback-required`
- Added a pure gate checklist that evaluates all existing Scope Runner gates
  plus the three consent flags, single-PID constraint, valid original cgroup
  capture, PID liveness, self-protection, model-only transaction plan,
  move-only mutation mode, and nftables/tc/Zelynic state disabled.
- The gate is pure/model-only and remains blocked. Even with all flags set
  and all checklist items passing, the final result is
  "Experimental PID move is not implemented yet."

### Phase 1.1: CLI Refactor

- Split `src/cli.rs` from approximately 998 LOC to approximately 522 LOC.
- Moved CLI tests to `src/cli/tests.rs`.
- Deduped the experimental gate safety footer so it is rendered once instead
  of duplicated across multiple output paths.

### Phase 2: Move-Only Executor Skeleton

- Added a pure, non-mutating model of the future single-PID cgroup move and
  immediate rollback sequence.
- Documents target cgroup preparation, `cgroup.procs` writes, verification,
  rollback, and safe cleanup in a deterministic step-by-step model.
- The future write sequence is modelled, not executed. No PID movement, no
  `cgroup.procs` write, no target cgroup creation, no limiter attach, and
  no nftables/tc/state mutation is performed.

### Phase 3: Target Cgroup Preflight

- Added a pure model for future target cgroup path validation and
  `cgroup.procs` write-target previews.
- Validates that the target path is under `/sys/fs/cgroup/zelynic/`, blocks
  unsafe paths (parent traversal, paths outside namespace, cgroup root).
- Parent and target cgroup creation status is marked as "future creation needed."
- Performs no live cgroup reads or writes. No `mkdir`, no `cgroup.procs`
  write, no PID movement.

### Phase 4: Cgroup Environment Diagnostics

- Added a pure parser/model for sample `/proc/self/mountinfo` cgroup v2 mount
  facts.
- Models cgroup v2 mount path (preferably `/sys/fs/cgroup`), mount mode
  (read-write, read-only, unknown), missing mount detection, and unexpected
  mount path reporting.
- No live mountinfo read in the Scope Runner output path.
- `cgroup.procs` writes remain blocked.

### Phase 5: Operation Journal Preview

- Added a pure operation journal model for the future move-only executor.
- Includes deterministic preview operation IDs derived from target, PID list,
  and mode.
- Operation owner: `zelynic-scope-runner`.
- Operation mode: `move-only`.
- Ordered journal events from `planned` through `blocked_not_executed`.
- Rollback boundary: operation-owned state only. External or non-owned state
  must not be removed.
- State writes: blocked.
- Journal is model-only and not persisted. No Zelynic state file is written.

## Safety Guarantees

This release maintains strict safety boundaries. The following are explicitly
documented and verified:

- **`--attach-live` remains hard-blocked:** Even with root, all required flags,
  and all experimental consent flags set, the command returns "Experimental
  PID move is not implemented yet." No PID movement or attach operation is
  performed.
- **No PID movement:** The Scope Runner does not move discovered PIDs into any
  Zelynic target cgroup. The move-only executor skeleton models the future
  sequence but does not execute it.
- **No cgroup directory creation:** No Zelynic target cgroup directory is created
  during any phase. The target cgroup preflight marks creation as "future work."
- **No `cgroup.procs` write:** No `cgroup.procs` file is written during any
  phase. Both target and rollback write paths remain blocked.
- **No nftables/tc changes:** The Scope Runner does not add, modify, or remove
  any nftables rules, tc qdisc state, or tc filters.
- **No Zelynic state writes:** No Zelynic state file is written. The operation
  journal is model-only and not persisted.
- **No limiter attach:** The Scope Runner does not call `zelynic strict` or the
  limiter attach execution path. Bandwidth limiting is not active from the
  Scope Runner.
- **Honest output wording:** Output includes canonical safety footer confirming
  no PID was moved, no limiter attach was performed, no nftables/tc/Zelynic
  cgroup/state changes were made, and bandwidth limiting is not active.
- **Cleanup integrity:** After the child process exits, the transient systemd
  scope transitions to inactive/dead. No Zelynic artifacts remain on the system.

## What Is Still Not Implemented

- **Live PID movement:** Discovered PIDs are reported but never moved into
  Zelynic cgroups.
- **Cgroup directory creation:** Zelynic target cgroup directories are not
  created by the Scope Runner.
- **`cgroup.procs` write:** Neither the target nor the rollback `cgroup.procs`
  is written.
- **Limiter attach from Scope Runner:** `zelynic strict` is never called from
  the Scope Runner path.
- **nftables/tc/Zelynic state changes:** No network or cgroup state is
  modified by the Scope Runner.
- **Operation journal persistence:** The journal preview is rendered in output
  but never written to disk.
- **User-scope live runner:** `--probe-live` with user scope remains blocked
  pending privilege/session handoff design.
- **Live `zelynic run --execute`** (without `--probe-live`): Remains
  non-mutating, returns "Live systemd wrapper execution is not implemented yet."

## Validation Summary

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo test --locked` — all tests passed
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `python3 scripts/check-policy.py` — all files under 1000 LOC, all headers
  present
- `git diff --check` — no whitespace errors

Root smoke tests passed:

- `sudo zelynic run --execute --scope-mode system --probe-live --attach-live
  --experimental-single-pid-attach --i-understand-this-moves-pids
  --rollback-required -d 500kbit -u 500kbit -- sleep 30` — launched
  transient systemd scope, discovered ControlGroup and PID, captured original
  cgroup, rendered all preflight/gate/checklist sections (attach preview,
  attach safety preflight, PID safety checks, future attach transaction plan,
  experimental attach gate, move-only executor skeleton, target cgroup
  preflight, cgroup environment diagnostics, operation journal preview), printed
  canonical safety footer, returned "Experimental PID move is not implemented
  yet.", no PID moved, no limiter attach, no nftables/tc/Zelynic cgroup/state
  changes, unit cleanup inactive/dead.

Non-root smoke tests passed (correctly blocked):

- `zelynic run --execute --scope-mode system --probe-live --attach-live
  --experimental-single-pid-attach --i-understand-this-moves-pids
  --rollback-required -d 500kbit -u 500kbit -- sleep 30` — "Scope Runner
  live probe requires root (euid == 0)." No systemd scope launched, no
  mutation.

A dedicated validation report is available at
[docs/validation-reports/experimental-attach-v2.7.md](docs/validation-reports/experimental-attach-v2.7.md).

## Upgrade Notes

- No configuration or state migration is needed for this release. Existing
  `zelynic strict` limits, profiles, and runtime state continue to work
  unchanged.
- The `--experimental-single-pid-attach`, `--i-understand-this-moves-pids`,
  and `--rollback-required` flags are new additions to `zelynic run`. Existing
  `zelynic run --dry-run` and `zelynic run --execute` behavior is preserved.
- The binary may still print v2.6.0 until a version bump is applied. This is
  expected for this release-prep phase.
- CLI refactor (phase 1.1) is a pure code organization change with no behavior
  change for end users.

## Next Roadmap

The next milestone after v2.7.0 is expected to be **v2.8.0 Experimental PID
Move Lab** (or equivalent future milestone). The first real write in that
milestone must remain:

- Single-PID only.
- Move-only (no bandwidth enforcement during the move step).
- Immediate rollback to the captured original cgroup.
- No nftables/tc/Zelynic state creation or modification.
- Operation-owned and journaled for precise cleanup.

This incremental approach ensures each mutation type is validated in isolation
before combining them. The pure models introduced in v2.7.0 (executor skeleton,
target preflight, cgroup diagnostics, operation journal) provide the safety
groundwork for that future milestone.

## Release Compare

Use the previous stable release baseline:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.6.0...v2.7.0
```
