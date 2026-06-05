# Zelynic v2.8.0 Experimental PID Move Lab

Zelynic v2.8.0 "Experimental PID Move Lab" is a **safety/research milestone**
release that extends the Scope Runner with comprehensive design documentation,
pure non-mutating models, failure simulation, and a guarded real writer seam —
all in preparation for a future first real PID move experiment. This release does
NOT implement live PID movement, does NOT write `cgroup.procs`, does NOT attach
a limiter from the Scope Runner, does NOT mutate nftables or tc state, does NOT
persist any operation state, and does NOT enable any CLI path for live PID move.
The `--attach-live` flag remains hard-blocked. `zelynic strict` remains the
only validated active limiter path.

## Release Positioning

v2.8.0 is explicitly positioned as a safety/research milestone, not a real PID
movement release. The work across five major phases (phases 1 through 5)
establishes the design foundation, safety gates, failure simulation coverage,
and guarded writer seam that any future real PID move would require. Real PID
movement must remain a separate future explicit post-v2.8 phase with its own
entry criteria, design, review, and validation.

## Summary

The v2.8.0 release covers five major feature phases and numerous sub-phases,
all merged to main with CI green. Phase 1 introduces the design document
defining safety gates, write boundaries, and rollback rules. Phase 2 introduces
the mkdir-only executor experiment for cgroup directory creation without PID
movement. Phase 3 designs the single PID move + immediate rollback sequence and
builds the executor seam and output audit. Phase 4 introduces comprehensive
failure simulation with 12 failure scenarios, fake writer injection, and a
render/output matrix. Phase 5 defines first real move readiness, produces an
operator checklist, designs the guarded real writer, and concludes with an RC
freeze validation index. Every phase is model-only — no live PID movement is
performed in any phase.

## What Changed

### Phase 1: Design Document (v2.8 Experimental PID Move Lab)

- Produced the master design document (`docs/experimental-pid-move-lab.md`)
  defining safety gates, write boundaries, rollback rules, forbidden
  behaviors, manual smoke strategy, and success criteria for all subsequent
  phases.
- Defined the phase ladder: five sequential phases, each requiring CI pass,
  local validation, and documentation before the next begins.
- No runtime changes. Design/documentation only.

### Phase 2: Target Cgroup mkdir-Only Experiment

- **Phase 2a**: Added a pure, non-mutating mkdir-only executor skeleton
  modeling the exact future mkdir-only write sequence (namespace prepare,
  target cgroup create, verify exists, cleanup if empty and operation-owned).
- **Phase 2b**: Implemented the first real-write experiment (`mkdir_executor.rs`)
  that creates Zelynic cgroup directories when `--mkdir-live` is present with
  all gates. No PID movement, no `cgroup.procs` write, no nft/tc/state changes.
- **Phase 2b.1**: Fixed misleading safety footer when `--mkdir-live` is active.
  Replaced "No nftables, tc, Zelynic cgroup, or state changes were made" with
  truthful wording: "Mkdir-only cgroup preparation was performed."
- **Phase 2c**: Produced validation report documenting the first real write,
  output honesty, and non-root gate verification.

### Phase 3: Single PID Move-Only + Immediate Rollback Design

- **Phase 3a**: Produced design document specifying the first actual PID move
  experiment — root-only, system-scope-only, single disposable sleep PID only,
  immediate rollback, no limiter attach, no nft/tc/state mutation. Includes
  exact 10-step transaction model and failure policy.
- **Phase 3b**: Aligned the existing `move_transaction.rs` skeleton with the
  phase 3a 10-step transaction model. Added 14 new tests.
- **Phase 3c**: Added `move_executor.rs` as the model-only executor seam — the
  structural bridge between the gate checklist and the future live write path.
  Validates all hard gates and always returns blocked. Added 22 seam tests.
- **Phase 3d**: Audited and locked output honesty for all experimental attach
  and move executor seam paths. Added 22 new tests across three modules.
- **Phase 3e**: Produced release-readiness freeze report documenting 7 explicit
  freeze safety guarantees and phase 4 entry criteria.

### Phase 4: Rollback Failure Simulation

- **Phase 4a**: Produced failure simulation design document defining 12 failure
  scenarios (F1-F12), 9 universal failure rules, PID location label taxonomy,
  and comprehensive test plan.
- **Phase 4b**: Implemented failure simulation model and 73 tests in
  `failure_simulation/` (mod.rs + tests/mod.rs). Pure model code covering all 12
  scenarios with rollback/cleanup decision models and canonical deny lines.
- **Phase 4c**: Added fake writer injection harness in `fake_writer/` that
  simulates cgroup.procs write outcomes with 10 injectable failure modes. Added
  42 tests.
- **Phase 4d**: Added render/output matrix covering every FakeFailureMode (11
  variants) with deterministic, honest, non-mutating rendered output. Added 36
  tests.
- **Phase 4e**: Produced freeze/validation report summarizing phases 4a-4d.
  Total: failure_simulation 151 tests, fake_writer 78 tests, project 604 tests.

### Phase 5: First Real Move Readiness + RC Freeze

- **Phase 5a**: Produced readiness document defining the only acceptable
  future first real PID move smoke with 11 constraints and 14-step manual smoke
  plan.
- **Phase 5b**: Produced operator checklist with exact review-only command
  tables for every smoke step. 12 abort conditions, 11 recovery steps.
- **Phase 5c**: Produced implementation design for the future guarded real PID
  move — CgroupProcsWriter trait, 11 transaction steps, 14 safety gates, output
  honesty contract.
- **Phase 5d**: Added `guarded_real_writer.rs` as the narrow code seam for the
  future guarded real writer. Always returns blocked/not implemented. 45 tests,
  7 canonical deny lines, pure functions only, no I/O.
- **Phase 5e**: Produced freeze/non-exposure audit report proving the seam
  remains internal-only, hard-blocked, and unreachable from any CLI or runtime
  path.
- **Phase 5f**: Refactored guarded_real_writer from 945 LOC single file into
  directory module (mod.rs 216, model.rs 154, render.rs 82, tests.rs 513).
- **Phase 5g**: Produced integration audit with blocked-path proof covering 9
  properties proving no CLI or runtime path can reach the guarded real writer.
- **Phase 5h**: Produced final pre-real-write validation / release gate report
  with 11 explicit freeze guarantees and 13 next-phase entry criteria.
- **Phase 5i**: Produced release-candidate freeze / full validation index
  summarizing the entire v2.8 timeline with 12 final RC safety guarantees and
  explicit RC decision.

### LOC Policy Compliance

- Refactored `src/cli.rs` from ~998 LOC to ~522 LOC (CLI tests moved to
  `src/cli/tests.rs`).
- Refactored `src/systemd_wrapper/guarded_real_writer.rs` from 945 LOC single
  file into directory module with four files, all under 1000 LOC.
- All project files remain under the 1000 LOC policy limit.

## Safety Guarantees

This release maintains strict safety boundaries. The following are explicitly
documented and verified across all phases:

- **No live PID move implemented:** The guarded real writer seam always returns
  blocked/not implemented. No code path performs PID movement. No PID has been
  moved into any Zelynic cgroup.
- **No real cgroup.procs write:** Neither the target nor the rollback
  `cgroup.procs` is written during any phase. The guarded real writer seam
  models the future write boundary without performing any writes.
- **No limiter attach:** The Scope Runner does not call `zelynic strict` or the
  limiter attach execution path. Bandwidth limiting is not active from the
  experimental path.
- **No nftables/tc/Zelynic state mutation:** No network or cgroup state is
  modified by any experimental code path.
- **No persistent state write:** No Zelynic state file is written. The operation
  journal is model-only and not persisted.
- **No CLI enablement for live PID move:** The `--attach-live` flag remains
  hard-blocked. Even with root, all required flags, and all experimental
  consent flags set, the command returns "not implemented yet."
- **Guarded real writer seam is hard-blocked:** The seam (`guarded_real_writer/`)
  is internal-only (`pub(crate)`), has no CLI command, no runtime path, no
  I/O, no filesystem/proc/sys access. All result fields are hardcoded
  non-mutating.
- **Failure simulation is fake/model-only:** All failure simulation code
  (`failure_simulation/`, `fake_writer/`) is pure, in-memory, test-only, and
  does not touch the real system.
- **Mkdir-live remains mkdir-only:** The `--mkdir-live` path only creates
  cgroup directories and cleans up empty operation-owned targets. No PID
  movement, no `cgroup.procs` write.
- **Honest output wording:** All output includes canonical safety disclaimers
  confirming no PID was moved, no limiter attach was performed, no nftables/tc/
  Zelynic cgroup/state changes were made, and bandwidth limiting is not active.

## What Is Still Not Implemented

- **Live PID movement:** Discovered PIDs are reported but never moved into
  Zelynic cgroups. The guarded real writer seam models the future boundary
  without performing any writes.
- **Real cgroup.procs write:** Neither the target nor the rollback
  `cgroup.procs` is written. The seam always returns blocked.
- **Limiter attach from Scope Runner:** `zelynic strict` is never called from
  the Scope Runner path. No bandwidth limiting from the experimental path.
- **nftables/tc/Zelynic state changes:** No network or cgroup state is
  modified by any experimental code path.
- **Operation journal persistence:** The journal preview is rendered in output
  but never written to disk.
- **User-scope live runner:** `--probe-live` with user scope remains blocked.
- **Live `zelynic run --execute`** (without `--probe-live`): Remains
  non-mutating, returns "not implemented yet."

## Validation Summary

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `cargo test --locked guarded_real_writer` — 45 tests passed
- `./build.sh check-all` — 645 tests passed, 84 files
- `python3 scripts/check-policy.py` — all files under 1000 LOC, all headers
  present
- `git diff --check` — no whitespace errors

## Test Totals

- guarded_real_writer: 45 tests
- failure_simulation: 151 tests
- fake_writer: 78 tests
- project total: 645 tests

## Artifact Inventory

Key source files added in v2.8:

- `src/systemd_wrapper/mkdir_executor.rs` — mkdir-only experiment executor
- `src/systemd_wrapper/move_executor.rs` — model-only executor seam
- `src/systemd_wrapper/failure_simulation/` — failure simulation model + tests
- `src/systemd_wrapper/failure_simulation/fake_writer/` — fake writer harness
- `src/systemd_wrapper/failure_simulation/fake_writer/render_matrix/` — render
  matrix
- `src/systemd_wrapper/guarded_real_writer/mod.rs` — guarded real writer seam
- `src/systemd_wrapper/guarded_real_writer/model.rs` — seam input/result types
- `src/systemd_wrapper/guarded_real_writer/render.rs` — seam render function
- `src/systemd_wrapper/guarded_real_writer/tests.rs` — seam tests (45)

Key documentation added in v2.8:

- `docs/experimental-pid-move-lab.md` — master design document
- `docs/v2.8-phase-2c-validation-report.md`
- `docs/v2.8-phase-3a-single-pid-rollback-design.md`
- `docs/v2.8-phase-3d-output-audit.md`
- `docs/v2.8-phase-3e-release-readiness-freeze.md`
- `docs/v2.8-phase-4a-failure-simulation-design.md`
- `docs/v2.8-phase-4e-failure-simulation-freeze.md`
- `docs/v2.8-phase-5a-first-real-move-readiness.md`
- `docs/v2.8-phase-5b-manual-smoke-operator-checklist.md`
- `docs/v2.8-phase-5c-guarded-real-move-implementation-design.md`
- `docs/v2.8-phase-5e-guarded-real-writer-freeze.md`
- `docs/v2.8-phase-5g-guarded-real-writer-integration-audit.md`
- `docs/v2.8-phase-5h-final-pre-real-write-validation.md`
- `docs/v2.8-phase-5i-release-candidate-freeze.md`

## Upgrade Notes

- No configuration or state migration is needed for this release. Existing
  `zelynic strict` limits, profiles, and runtime state continue to work
  unchanged.
- The `--mkdir-live` flag is new in this release. It requires all existing
  experimental consent flags. It only creates cgroup directories — no PID
  movement.
- The experimental consent flags (`--experimental-single-pid-attach`,
  `--i-understand-this-moves-pids`, `--rollback-required`) continue to exist
  as pure gate-check flags with no live effect.
- CLI refactor (split from ~998 LOC to ~522 LOC) is a pure code organization
  change with no behavior change for end users.
- guarded_real_writer refactor (split from 945 LOC to 4 files) is a pure code
  organization change with no behavior change.

## Next Roadmap

The next milestone after v2.8.0 is not defined. Any future real PID move
must satisfy all v2.8 post-RC requirements:

- Separate explicit implementation phase with its own design and review.
- Root-only, system-scope-only, single disposable sleep PID only.
- Original cgroup captured and verified.
- Target under `/sys/fs/cgroup/zelynic/` only.
- Immediate rollback required.
- No limiter attach, no nft/tc/Zelynic state mutation.
- Explicit operator confirmation before any real smoke execution.
- Abort on any ambiguity.

This incremental approach ensures each mutation type is validated in isolation
before combining them. The pure models, failure simulation, fake writer, and
guarded real writer seam introduced in v2.8 provide the safety groundwork for
that future milestone.

## Release Compare

```text
https://github.com/oxyzenQ/zelynic/compare/v2.7.0...v2.8.0
```
