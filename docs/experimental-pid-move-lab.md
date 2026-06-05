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

### Phase 3a: Single PID Move + Rollback Design (Completed)

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

### Phase 3b: Move Transaction Skeleton Alignment (Completed)

- Aligned the existing `move_transaction.rs` skeleton with the phase 3a
  design document's 10-step transaction model.
- Updated operation step descriptions to match phase 3a terminology:
  "planned" for model-only steps, "planned write" for future writes,
  "planned verify" for future verifications, "planned rollback" for future
  rollback writes.
- Added step 7 "record move success (in-memory model update only)" which
  was missing from the original skeleton.
- Added explicit PID liveness recheck step (step 2) and original cgroup
  validation step (step 3) with clear descriptions matching the phase 3a
  design.
- Updated `writes_modelled` list from 5 to 7 items to cover the full
  transaction lifecycle including record and cleanup.
- Added "transaction steps" and "rollback steps" rendering in the skeleton
  output so the 10-step model and 3 rollback steps are visible in gate output.
- Added explicit safety disclaimers in rendered output: "pid movement: not
  performed", "cgroup.procs writes: not performed", "phase: 3b skeleton
  alignment".
- Updated operation journal planned events from 8 to 12 to align with
  the 10-step model (gates re-evaluated, PID liveness rechecked, original
  cgroup validated, target cgroup prepared, move, verification, record,
  rollback restore, rollback verification, target cleanup, blocked).
- Added 14 new tests: PID liveness recheck, original cgroup validation,
  record move success, immediate rollback (3 assertions), target cleanup
  boundary, operation count (10), writes_modelled count (7), rollback
  count (3), output honesty for cgroup.procs and pid movement, phase 3b
  label, transaction steps rendering, rollback steps rendering, empty
  original cgroup blocking.
- All existing 13 move_transaction tests continue to pass.
- No runtime changes. All output remains model-only/skeleton-only/execution-blocked.
- Live PID movement is still not implemented.
- No cgroup.procs write was performed.

### Phase 3c: Executor Seam + Hard Gates (Completed)

- Added `src/systemd_wrapper/move_executor.rs` as the model-only executor
  seam — the structural bridge between the gate checklist and the future
  live write path.
- The executor seam accepts move transaction model inputs and validates
  all hard gates (root, system scope, single PID, original cgroup present
  and non-empty, original cgroup not under `/zelynic/`, target under
  `/sys/fs/cgroup/zelynic/`, rollback consent present).
- Every mutating step returns blocked/not-implemented. The seam explicitly
  states: phase 3c is executor-seam only, live PID move is not implemented,
  no cgroup.procs write was performed, no PID was moved, no limiter attach
  was performed, no nftables/tc/Zelynic state changes were made, no
  persistent state write was performed.
- Even when all gate inputs are valid, the executor returns blocked because
  live PID move is not implemented in this phase.
- Wired the seam into the experimental attach gate output as a preview/
  report section, appearing after the move-only executor skeleton and before
  the mkdir-only executor skeleton.
- Added 22 seam tests: non-root blocked, user scope blocked, multi-PID
  blocked, missing original cgroup blocked, empty original cgroup blocked,
  zelynic-managed original cgroup blocked, invalid target outside namespace
  blocked, missing rollback consent blocked, zero PID edge case, whitespace-
  only original cgroup blocked, executor always blocked even with all valid
  inputs, rendered output never claims attached/limited/enforced, rendered
  output contains "no cgroup.procs write was performed", all required
  disclaimers present, rendered output includes explicit denials, phase 3c
  label, rendered structure (gates/disclaimers), rendered phase and status,
  gate ordering correct, is_safe_target helper tests, gate checklist
  includes seam, seam always blocked via gate, non-root propagates to gate,
  gate output includes seam section, seam ordering in gate output.
- No runtime mutation. No live PID move. No cgroup.procs write. No
  limiter attach. No nft/tc/state changes.

### Phase 3d: Output Audit + Negative-Path Smoke Coverage (Completed)

- Audited and locked output honesty for all experimental attach and move
  executor seam paths before any future real PID move phase.
- Added two new canonical deny lines to the seam disclaimers:
  `Experimental PID move is not implemented yet.` and
  `Bandwidth limiting is not active from this command yet.`
- Added 22 new tests across three modules:
  - `move_executor.rs`: 11 tests — canonical deny-line presence for all
    negative paths (non-root, user scope, multi-PID, missing original
    cgroup), deny-line absence of false claims (bandwidth active, rollback
    performed), comprehensive negative-path mutation claim sweep across 5
    scenarios.
  - `experimental_attach_gate.rs`: 10 tests — negative-path output honesty
    for non-root, user scope, missing consent, multi-PID, missing original
    cgroup; 11-path comprehensive seam disclaimer coverage sweep; not-
    implemented constant wording audit; final status always blocked for all
    negative paths; all-valid path includes seam with all deny lines.
  - `mod.rs`: 7 tests — comprehensive error message honesty for non-root,
    user scope, attach gate, probe gate, both error constants, missing
    probe-live, missing attach-live.
- Updated `scope_probe.rs` footer count assertion to reflect the new
  "Bandwidth limiting is not active" line appearing in both the seam and
  the canonical safety footer.
- Produced output audit document
  (`docs/v2.8-phase-3d-output-audit.md`) documenting the negative-path
  matrix, canonical deny lines, output wording prohibitions, and why this
  phase is still non-mutating.
- No runtime behavior changes. All output remains model-only/skeleton-only/
  execution-blocked. No new code paths, no write operations. Live PID
  movement remains not implemented.

### Phase 3e: Release-Readiness / Freeze Report (Completed)

- Produced release-readiness freeze report
  (`docs/v2.8-phase-3e-release-readiness-freeze.md`).
- Summarizes all completed phases (2b, 2c, 3a, 3b, 3c, 3d) with scope,
  deliverables, and status.
- Documents current validated state: local validation green, CI green,
  root smoke green, version still v2.7.0, no live PID move implemented.
- Documents 7 explicit freeze safety guarantees: no PID move, no cgroup.procs
  write, no limiter attach, no nftables/tc/Zelynic state mutation, no
  persistent state write, no bandwidth limiting from experimental path,
  mkdir-only may create/cleanup target cgroup only.
- Documents phase 4 entry criteria (9 conditions) and artifact inventory.
- No runtime code changes. Docs/report only.

### Phase 4a: Failure Simulation Design (Completed)

- Produced failure simulation design document
  (`docs/v2.8-phase-4a-failure-simulation-design.md`).
- Defines 12 failure scenarios (F1–F12) covering every credible failure
  mode in the 10-step transaction model: failure before target cgroup
  creation, failure after target creation but before PID move, failure
  after PID move but before verification, failure after verification but
  before rollback, failure during rollback write, failure after rollback
  write but before verification, failure during target cleanup, stale/dead
  PID during transaction, original cgroup disappears, target cgroup becomes
  non-empty, permission denied on cgroup.procs write, and unexpected
  EBUSY/ENOENT/EACCES behavior.
- For each scenario documents: expected rollback behavior, expected output
  honesty, expected cleanup behavior, whether target cgroup may remain,
  whether manual recovery is required, and what must never be claimed.
- Defines 9 universal failure rules: no false rollback claims, rollback
  attempted once if move may have occurred, rollback failure reported
  loudly, no limiter attach after partial move, no nft/tc/state write in
  failure path, no deletion of non-empty cgroup, no deletion outside
  /sys/fs/cgroup/zelynic/, no retry loops, PID location explicitly stated.
- Defines PID location label taxonomy: not moved, verified in target,
  verified restored, rollback unverified, unknown.
- Includes test plan: 21 fake filesystem unit tests, 13 fake writer
  injection tests, 13 render tests, 7 canonical deny-line persistence
  tests. No root smoke, no live PID move.
- No runtime code changes. Docs/design only.

### Phase 4b: Failure Simulation Model + Fake Tests (Completed)

- Implemented failure simulation model and comprehensive tests in
  `src/systemd_wrapper/failure_simulation/` (mod.rs + tests/mod.rs).
- Pure model code: 12 failure scenario enum (F1-F12), PID location status
  taxonomy, rollback decision model, cleanup decision model, simulation result
  struct, and canonical deny lines.
- Pure functions: `build_failure_simulation_matrix()`,
  `simulate_failure_scenario()`, `render_failure_simulation_result()`.
- 73 new tests covering: matrix completeness (12 scenarios), PID location
  assertions for each scenario, rollback decision correctness, cleanup
  decision correctness, render output simulation/model-only markers,
  canonical deny lines (live PID move, cgroup.procs write, limiter attach,
  nft/tc/state mutation, persistent state write), no false rollback
  claims, no retry loops, FailureScenario enum helpers, PID location
  label coverage, render structure verification, simulation result field
  correctness, universal failure rules (9 rules from phase 4a),
  determinism, and CleanupDecision helper correctness.
- Module wired into `src/systemd_wrapper/mod.rs` with no CLI path, no
  runtime behavior change.
- No live PID move. No real cgroup.procs write. No limiter attach.
  No nftables/tc/Zelynic state mutation. No persistent state write.
  All simulation is pure model/fake-only.

### Phase 4c: Fake Writer Injection Harness (Completed)

- Added fake writer injection harness in
  `src/systemd_wrapper/failure_simulation/fake_writer/` (fake_writer.rs +
  tests.rs).
- Models fake write operations on cgroup.procs files: fake write PID to
  target, fake verify PID in target, fake write PID back to original,
  fake verify restored, fake cleanup target cgroup.
- Injectable fake failure modes: EACCES on target write, ENOENT on target
  write, EBUSY on target write, EACCES on rollback write, ENOENT on
  rollback write, EBUSY on cleanup, stale/dead PID before write,
  stale/dead PID after target write, original cgroup missing before
  rollback, target cgroup unexpectedly non-empty during cleanup.
- Fake writer result model: operation attempted/succeeded/failed, fake
  errno label, PID location after operation (not moved, verified in target,
  verified restored, rollback unverified, unknown), rollback required,
  manual recovery required, target may remain.
- Pure functions: `simulate_fake_transaction()` models the full 6-step
  transaction with injectable failure at any step boundary.
  `render_fake_transaction_result()` renders structured diagnostic output.
- Canonical deny lines in every rendered output: no real cgroup.procs
  write, no live PID move, no limiter attach, no nft/tc/Zelynic state
  mutation, no persistent state write.
- Tests covering: happy path (target write success, rollback success),
  target write failures (EACCES/ENOENT/EBUSY never claim PID moved,
  no rollback required), failure after target write requires rollback
  attempt, rollback failures report manual recovery required, cleanup
  EBUSY leaves target, non-empty target never deleted, original cgroup
  missing reports loudly, stale PID before write never attempts any write,
  every rendered output denies real cgroup.procs write, every rendered
  output denies live PID move, every rendered output denies limiter
  attach, every rendered output denies nft/tc/state mutation, every
  rendered output says fake/model-only, no retry loop modeled.
- Submodule wired into `failure_simulation/mod.rs`, crate-private,
  test-focused, no CLI command exposed, no runtime behavior change.
- No live PID move. No real cgroup.procs write. No limiter attach.
  No nftables/tc/Zelynic state mutation. No persistent state write.
  All writer simulation is pure fake/in-memory/test-only/model-only.

### Phase 4d: Fake Writer Render/Output Matrix (Completed)

- Added canonical render/output matrix in
  `src/systemd_wrapper/failure_simulation/fake_writer/render_matrix/`
  (render_matrix.rs + tests.rs).
- Covers every `FakeFailureMode` (11 variants) with deterministic,
  honest, non-mutating rendered output.
- For each mode, output includes: phase label (4d), fake/model-only
  statement, failure mode label, fake errno when applicable, per-step
  operation status (target write, target verification, rollback write,
  rollback verification, cleanup), PID location label, rollback required,
  manual recovery required, target may remain.
- 7 canonical deny lines in every output: no live PID move, no real
  cgroup.procs write, no limiter attach, no nft/tc/Zelynic state changes,
  no persistent state write, no CLI path for live PID move, fake/model-only.
- Explicit forbidden claims: no claim of real PID moved, no claim of real
  cgroup.procs written, no claim of real rollback performed, no limiter
  attached, no bandwidth limiting active, no nft/tc/state mutation, no
  cleanup success when cleanup failed.
- Pure functions: `build_full_render_matrix()`, `render_matrix_entry()`,
  `render_matrix_output()`.
- Tests covering: matrix completeness, determinism, phase label presence,
  fake/model-only statement, all 7 canonical deny lines per mode,
  forbidden claim absence, errno label rendering, target write failures
  never claim rollback, rollback failures report manual recovery, cleanup
  EBUSY reports target may remain, non-empty target never claims deletion,
  stale PID before write does not attempt write, stale PID after target
  write requires rollback, PID location in all modes, no retry loop,
  render structure verification, mode-specific correctness assertions.
- Submodule wired into `fake_writer.rs`, crate-private, test-focused,
  no CLI command exposed, no runtime behavior change.
- No live PID move. No real cgroup.procs write. No limiter attach.
  No nftables/tc/Zelynic state mutation. No persistent state write.
  All render output is pure fake/model-only/render-only.

### Phase 4e: Failure Simulation Freeze / Validation Report (Completed)

- Produced freeze/validation report
  (`docs/v2.8-phase-4e-failure-simulation-freeze.md`) summarizing all
  phases 4a–4d work.
- Report covers: phase 4a design (12 failure scenarios, 9 universal rules),
  phase 4b model + 73 tests, phase 4b test wiring fix, phase 4c fake writer
  harness + 42 tests, phase 4c format fix, phase 4d render/output matrix +
  36 tests.
- Current test totals: failure_simulation 151, fake_writer 78, project 604.
- Current validation state: `./build.sh check-all` passed, CI green, security
  audit passed, policy check passed (80 files), version still v2.7.0.
- Explicit freeze guarantees: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/Zelynic state mutation, no persistent state
  write, no CLI enablement for live PID move, all simulation is fake/model-only.
- Phase 5 entry criteria: freeze report complete, CI green, all failure
  simulation tests wired and passing, root smoke commands reviewed before
  execution, first real PID move remains blocked until phase 5, future real
  move must be root-only, system-scope-only, single disposable sleep PID only,
  immediate rollback required, no limiter attach, no nft/tc/state mutation.
- Docs/report only. No Rust code changes. No runtime behavior changes.
  No live PID move.

### Phase 5a: First Real Move Readiness / Manual Smoke Plan (Completed)

- Produced readiness document
  (`docs/v2.8-phase-5a-first-real-move-readiness.md`) defining the only
  acceptable future first real PID move smoke.
- Defines 11 constraints for the first real move: root-only,
  system-scope-only, single disposable sleep PID only, immediate rollback
  required, no limiter attach, no nft/tc/Zelynic state mutation, no
  persistent state write, no browser/terminal/desktop process, no user app,
  no multi-PID tree, no bandwidth limiting claim.
- Manual smoke command plan (14 steps): create disposable sleep scope,
  capture PID, capture original cgroup, verify cgroup mount, prepare target,
  verify target empty, write PID to target, verify in target, immediate
  rollback, verify restored, cleanup target, verify no leftover, verify no
  nft/tc/state changes, stop sleep scope.
- Abort conditions (10): PID missing/stale, more than one PID, original
  cgroup missing, original cgroup Zelynic-managed, target outside zelynic
  namespace, target non-empty, cgroup mount read-only, permissions
  unexpected, rollback target unverifiable, ambiguous output.
- Expected output honesty: must state PID moved/restored/unknown/not-moved,
  must state rollback attempted/succeeded/failed, must not claim limiter
  attach, bandwidth limiting, or nft/tc/state mutation. 7 canonical deny
  lines with honest substitutions for real operations.
- Manual recovery: inspect PID cgroup, move back only if original verified,
  leave target if non-empty, never delete outside `/sys/fs/cgroup/zelynic/`,
  stop disposable sleep scope.
- Docs/design only. No Rust code changes. No runtime behavior changes.
  No live PID move. No cgroup.procs write.

### Phase 5b: Manual Smoke Command Review + Exact Operator Checklist (Completed)

- Produced operator checklist document
  (`docs/v2.8-phase-5b-manual-smoke-operator-checklist.md`) with exact
  review-only command tables for every smoke step.
- All commands are for review only; no current Zelynic command performs this
  move; no limiter attach or nft/tc/state mutation is part of this smoke.
- Checklist sections: preflight environment checks (7 items), disposable
  sleep process creation (5 items), PID and cgroup capture (6 items), target
  path verification (5 items), target preparation (3 items), planned PID move
  to target (2 items), planned target verification (3 items), planned
  immediate rollback (2 items), planned rollback verification (3 items),
  planned cleanup (3 items), post-smoke audit (6 items).
- Explicit abort checklist (12 conditions): not root, not system scope, PID
  missing/stale, more than one PID, original cgroup missing, original cgroup
  Zelynic-managed, target outside zelynic namespace, target exists and
  non-empty, cgroup mount read-only, permissions unexpected, rollback target
  unverifiable, any output ambiguous.
- Expected observation table: before/after move, after rollback, after
  cleanup, final state (no limiter, no nft/tc/state, no persistent state).
- Manual recovery checklist (11 steps): inspect PID cgroup, verify original
  exists, verify writable, move back only to verified original, never delete
  non-empty target, never delete outside zelynic, stop sleep scope, report
  PID location honestly.
- Output honesty requirements: must state PID moved/restored/unknown/not
  moved, rollback attempted/succeeded, cleanup status; must never claim
  limiter attach, bandwidth limiting, nft/tc/state mutation, persistent
  state write. 7 canonical deny lines with honest substitutions.
- Docs/design only. No Rust code changes. No runtime behavior changes.
  No live PID move.

### Phase 5c: Guarded Real Move Implementation Design (Completed)

- Produced implementation design document
  (`docs/v2.8-phase-5c-guarded-real-move-implementation-design.md`) for
  the future guarded real PID move.
- Defines the only allowed future live target: root-only, system-scope-only,
  single disposable sleep PID, operation-owned Zelynic target cgroup, immediate
  rollback required, no limiter attach, no nft/tc/Zelynic state mutation,
  no persistent state write, no browser/terminal/desktop/user app, no multi-PID
  tree.
- Proposed code architecture: `CgroupProcsWriter` trait with live writer
  (narrow, isolated, cgroup.procs-only) and fake writer adapter (test-only).
  Live writer has no limiter/nft/tc/state knowledge. Transaction controller
  decides rollback. Renderer reports verified PID location.
- Exact transaction steps (11 steps: pre-flight gates through post-smoke
  audit), 14 safety gates (root, system scope, single PID, PID liveness,
  original cgroup captured/verified/not-Zelynic-managed, target under zelynic/
  empty/operation-owned, cgroup mount writable, rollback consent, no limiter
  path reachable), 12 abort conditions.
- Failure handling: pre-target abort (no rollback), target write failure
  (rollback required), verification failure (rollback required), rollback
  write failure (report loudly, manual recovery), rollback verification
  failure (unverified), cleanup failure (leave and report), never retry.
- Output honesty contract: 6 required fields, 8 forbidden claims, 7
  canonical deny lines with honest substitutions.
- Test strategy: ~66 new unit tests using fake writer, real writer compiled
  but not reachable without all gates, CLI remains blocked, no forbidden
  claims, no limiter/nft/tc/state interaction.
- Root smoke strategy: preflight checks, create target, execute with all
  gate flags, verify output, report, cleanup.
- Docs/design only. No Rust code changes. No runtime behavior changes.
  No live PID move.

### Phase 5d: Guarded Real Writer Seam (Completed)

- Added `src/systemd_wrapper/guarded_real_writer.rs` as the narrow code
  seam for the future guarded real writer. The seam models the future real
  writer boundary without performing any writes.
- Input model: pid, original cgroup path, target cgroup path, root gate,
  system-scope gate, single PID gate, rollback consent gate.
- Result model: status (always blocked), reason, pid location (always not
  moved), rollback attempted (always false), cleanup attempted (always
  false), cgroup.procs writes performed (always false), limiter attach
  performed (always false), nft/tc/state mutation performed (always false).
- 7 canonical deny lines in every output: no live PID move, no real
  cgroup.procs write, no limiter attach, no nft/tc/Zelynic state changes,
  no persistent state write, no CLI path for live PID move, guarded real
  writer seam is hard-blocked.
- Pure functions only: `build_guarded_real_writer_plan()` and
  `render_guarded_real_writer_plan()`. No I/O, no filesystem access, no
  /proc access, no /sys access.
- Gate validation: root, system scope, single non-zero PID, original
  cgroup present and non-empty, original cgroup not under /zelynic/,
  target under /sys/fs/cgroup/zelynic/, rollback consent present.
- Wired into `src/systemd_wrapper/mod.rs` with no CLI command, no runtime
  path exposure, no real filesystem access.
- Tests covering: seam always blocked even when all gates valid, non-root
  blocks, user scope blocks, zero PID blocks, multi-PID blocks, missing
  original cgroup blocks, zelynic-managed original cgroup blocks, target
  outside namespace blocks, missing rollback consent blocks, rendered
  output includes all 7 deny lines, rendered output never claims PID moved,
  rendered output never claims cgroup.procs write, rendered output never
  claims rollback performed, rendered output never claims limiter attach,
  rendered output never claims bandwidth limiting active, rendered output
  never claims nft/tc/state mutation, rendered output says hard-blocked/
  not implemented, negative-path comprehensive mutation sweep, result
  model field correctness, determinism, gate ordering, helper correctness,
  phase label presence, render structure verification.
- No live PID move. No real cgroup.procs write. No limiter attach. No
  nftables/tc/Zelynic state mutation. No persistent state write. No CLI
  path for live PID move. The seam is always hard-blocked.

### Phase 5e: Guarded Real Writer Seam Freeze / Non-Exposure Audit (Completed)

- Produced freeze/non-exposure audit report
  (`docs/v2.8-phase-5e-guarded-real-writer-freeze.md`) summarizing all
  phases 5a–5d work and auditing the guarded real writer seam's non-exposure.
- Phase 5 summary: 5a readiness (11 constraints, 14-step smoke plan, 10 abort
  conditions), 5b operator checklist (7 preflight checks, 12 abort conditions,
  11 recovery steps, output honesty requirements), 5c implementation design
  (CgroupProcsWriter trait, 11 transaction steps, 14 safety gates, 12 abort
  conditions, failure handling, output honesty contract, ~66 test plan), 5d
  guarded real writer seam (945 LOC, 45 tests, 7 gates, 7 canonical deny lines,
  pure functions only, no I/O, no filesystem/proc/sys access).
- Current test state: guarded_real_writer 45 tests passed, total 645 tests
  passed. Binary version remains v2.7.0.
- Explicit seam freeze guarantees: always returns blocked/not implemented, no
  live PID move, no real cgroup.procs write, no rollback write, no cleanup
  mutation, no limiter attach, no nft/tc/Zelynic state mutation, no persistent
  state write, no CLI path enabled, no /proc access, no /sys access, no
  filesystem mutation.
- Non-exposure audit: module registered as internal systemd_wrapper module
  only, no public CLI command uses it, existing attach-live path remains
  hard-blocked, existing mkdir-live path remains mkdir-only, failure_simulation
  remains fake/model-only, fake_writer remains fake/model-only, move_executor
  remains blocked/seam-only, move_transaction remains skeleton/model-only.
- Future phase entry criteria (11 conditions): root-only, system-scope-only,
  single disposable sleep PID only, original cgroup captured and verified,
  target under /sys/fs/cgroup/zelynic only, rollback consent present, rollback
  path reviewed, manual recovery reviewed, exact smoke commands reviewed, no
  limiter/nft/tc/state, explicit operator confirmation before real smoke.
- Docs/report only. No runtime code changes. No Rust source file modifications.
  No live PID move. No cgroup.procs write.

### Phase 5f: Guarded Real Writer LOC Split / Maintainability Refactor (Completed)

- Refactored `src/systemd_wrapper/guarded_real_writer.rs` (945 LOC, single file)
  into a directory module with four files: `mod.rs` (216 LOC, build function +
  helper), `model.rs` (154 LOC, input/result/gate types + canonical deny lines),
  `render.rs` (82 LOC, render function), `tests.rs` (513 LOC, all 45 tests).
- Preserved exact behavior: seam always blocked/not implemented, all result
  fields hardcoded non-mutating, all 7 canonical deny lines present in every
  output, no forbidden claims.
- Preserved API compatibility: `build_guarded_real_writer_plan()` and
  `render_guarded_real_writer_plan()` remain `pub(crate)`. All types
  re-exported via `pub(crate) use model::*` in mod.rs. No CLI exposure.
- All 45 guarded_real_writer tests pass with identical results. Total test
  count remains 645. All files under 1000 LOC. Binary version remains v2.7.0.
- No runtime behavior changes. No new code paths. No filesystem/proc/sys access.
  No live PID move. No cgroup.procs write. No limiter attach. No nft/tc/state
  mutation. No persistent state write. No CLI enablement. Refactor/split only.

### Phase 5g: Guarded Real Writer Integration Audit / Blocked-Path Proof (Completed)

- Produced integration audit / blocked-path proof report
  (`docs/v2.8-phase-5g-guarded-real-writer-integration-audit.md`) proving the
  guarded real writer seam remains internal, hard-blocked, non-mutating, and
  unreachable from any live CLI or runtime path after the 5f split.
- Phase history summary: 5d guarded real writer seam (945 LOC, 45 tests, 7 gates,
  7 canonical deny lines, pure functions only), 5e seam freeze/non-exposure audit,
  5f LOC split into directory module (mod.rs 216, model.rs 154, render.rs 82,
  tests.rs 513).
- Blocked-path proof (9 properties): guarded_real_writer module is internal only
  (private `mod` declaration, `pub(crate)` re-exports only), no CLI command calls
  it, no runtime path calls it, attach-live path remains hard-blocked, mkdir-live
  path remains mkdir-only, move_executor remains blocked, move_transaction
  remains skeleton/model-only, failure_simulation remains fake/model-only,
  fake_writer remains fake/model-only.
- Output/safety proof: 7 canonical deny lines in every rendered output, all
  forbidden claims verified absent (PID moved, cgroup.procs write, rollback
  performed, cleanup mutation, limiter attach, bandwidth limiting active,
  nft/tc/state mutation, persistent state write), all result fields hardcoded
  non-mutating, comprehensive negative-path mutation sweep covers 7 scenarios.
- Future real move activation criteria (9 conditions): separate explicit
  implementation phase, separate explicit CLI gate, separate root smoke review,
  root-only, system-scope-only, single disposable sleep PID only, immediate
  rollback required, no limiter/nft/tc/state, operator must review exact
  commands before execution.
- Current test state: guarded_real_writer 45 tests passed, total 645 tests
  passed. All files under 1000 LOC. Binary version remains v2.7.0.
- Explicit safety confirmation: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/state mutation, no persistent state write, no
  CLI path for live PID move enabled.
- Docs/report only. No Rust source file modifications. No runtime behavior
  changes. No live PID move.

### Phase 5h: Final Pre-Real-Write Validation / Release Gate Report (Completed)

- Produced final pre-real-write validation / release gate report
  (`docs/v2.8-phase-5h-final-pre-real-write-validation.md`) summarizing all
  phase 5 work (5a through 5g) and serving as the release gate before any
  future real cgroup.procs write.
- Phase 5 summary: 5a readiness (11 constraints, 14-step smoke plan, 10 abort
  conditions), 5b operator checklist (review-only commands, 12 abort conditions,
  11 recovery steps, output honesty requirements), 5c implementation design
  (CgroupProcsWriter trait, 11 transaction steps, 14 safety gates, 12 abort
  conditions, ~66 test plan), 5d guarded real writer seam (945 LOC, 45 tests,
  7 gates, 7 canonical deny lines, pure functions only), 5e seam freeze/
  non-exposure audit (11 freeze guarantees, non-exposure verification), 5f LOC
  split (mod.rs 216, model.rs 154, render.rs 82, tests.rs 513, API preserved),
  5g integration audit (9 blocked-path properties, output/safety proof).
- Current validation state: guarded_real_writer 45 tests passed, total 645 tests
  passed, ./build.sh check-all passed, policy check 84 files, all split files
  under 1000 LOC, version still v2.7.0.
- 11 explicit pre-real-write freeze guarantees: no live PID move, no real
  cgroup.procs write, no rollback write, no cleanup mutation, no limiter attach,
  no nft/tc/Zelynic state mutation, no persistent state write, no CLI path
  enabled, no /proc access, no /sys access, no filesystem mutation from
  guarded_real_writer.
- Blocked-path proof summary (9 properties): guarded_real_writer internal-only,
  no CLI command calls it, attach-live hard-blocked, mkdir-live mkdir-only,
  move_executor blocked, move_transaction skeleton/model-only, failure_simulation
  fake/model-only, fake_writer fake/model-only, no runtime path calls it.
- Next-phase entry criteria (13 conditions): separate explicit implementation
  phase, separate explicit operator confirmation, root-only, system-scope-only,
  single disposable sleep PID only, original cgroup captured and verified, target
  under /sys/fs/cgroup/zelynic only, immediate rollback required, rollback path
  reviewed, manual recovery reviewed, exact smoke commands reviewed, no
  limiter/nft/tc/state, abort on ambiguity.
- Explicit safety confirmation: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/state mutation, no persistent state write, no
  CLI path for live PID move enabled.
- Docs/report only. No Rust source file modifications. No runtime behavior
  changes. No live PID move.

### Phase 5i: Release-Candidate Freeze / Full Validation Index (Completed)

- Produced release-candidate freeze / full validation index
  (`docs/v2.8-phase-5i-release-candidate-freeze.md`) covering the entire v2.8
  Experimental PID Move Lab timeline from phase 1 through 5h.
- Full timeline summary: phase 1 design doc only, phase 2 cgroup mkdir-only
  experiment (2a skeleton, 2b executor, 2b.1 output honesty fix, 2c validation),
  phase 3 single PID move-only + immediate rollback (3a design, 3b skeleton
  alignment, 3c executor seam, 3d output audit, 3e freeze), phase 4 rollback
  failure simulation (4a design, 4b model + tests, 4c fake writer, 4d render/
  output matrix, 4e freeze), phase 5 first real move readiness (5a readiness,
  5b operator checklist, 5c implementation design, 5d guarded real writer seam,
  5e seam freeze, 5f LOC split, 5g integration audit, 5h final pre-real-write
  validation).
- Current validation state: guarded_real_writer 45 tests passed, total 645 tests
  passed, ./build.sh check-all passed, policy check 84 files, version bumped
  to v2.8.0.
- 12 final v2.8 RC safety guarantees: no live PID move implemented, no real
  cgroup.procs write implemented, no rollback write implemented, no cleanup
  mutation from guarded_real_writer, no limiter attach, no nft/tc/Zelynic state
  mutation, no persistent state write, no CLI path enabled for live PID move,
  guarded_real_writer remains internal-only and hard-blocked, failure_simulation
  remains fake/model-only, fake_writer remains fake/model-only, mkdir-live
  remains mkdir-only.
- Release-candidate decision: v2.8 can be frozen as a safety/research milestone
  without any live PID movement having been implemented. Future real PID move
  requires a separate explicit post-RC phase with its own entry criteria, design,
  review, and validation. Post-RC requirements: root-only, system-scope-only,
  single disposable sleep PID only, immediate rollback, no limiter/nft/tc/state,
  explicit operator confirmation, abort on ambiguity.
- Explicit safety confirmation: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/state mutation, no persistent state write, no
  CLI path for live PID move enabled.
- Docs/report only. No Rust source file modifications. No runtime behavior
  changes. No live PID move.

### Phase 6: v2.8.0 Release Prep — Version Bump and Release Notes (Completed)

- Bumped version from v2.7.0 to v2.8.0 in Cargo.toml, Cargo.lock, README.md,
  and CHANGELOG.md.
- Updated CHANGELOG.md with v2.8.0 release section including safety/research
  milestone disclaimer.
- Created `docs/release-v2.8.0.md` following the established release notes
  pattern (matching `docs/release-v2.7.0.md`).
- Updated `src/update.rs` with v2.8.0 version comparison test.
- Release notes explicitly state: v2.8.0 is NOT a real PID movement release,
  does NOT write real cgroup.procs, does NOT attach limiter, does NOT mutate
  nftables/tc/Zelynic state, does NOT persist operation state, does NOT enable
  CLI path for live PID move. The guarded real writer seam exists but is
  hard-blocked. mkdir-live remains mkdir-only. failure_simulation and fake_writer
  remain fake/model-only. `zelynic strict` remains the only validated active
  limiter path.
- No new Rust source code. Version metadata and documentation only.
- Explicit safety confirmation: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/state mutation, no persistent state write, no
  CLI path for live PID move enabled.

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

All v2.8 phases are completed. v2.8.0 has been frozen as a
safety/research milestone release. The version has been bumped to v2.8.0.
Release notes are available at `docs/release-v2.8.0.md`.

No live PID movement has been implemented. The guarded real writer seam
remains internal-only and hard-blocked. All experimental code is model-only,
fake/model-only, or mkdir-only. `zelynic strict` remains the only validated
active limiter path.

| Property | Status |
|----------|--------|
| PID movement | Not implemented |
| Cgroup directory creation | Phase 2b: mkdir-only with --mkdir-live (first real write) |
| Output honesty | Phase 3d: canonical 7-deny-line audit across 11 negative paths |
| `cgroup.procs` write | Not implemented |
| Move transaction skeleton | Phase 3b: aligned with 10-step 3a design, 27 tests passing |
| Move executor seam | Phase 3d: 7 canonical deny lines, 33 tests passing |
| Failure simulation design | Phase 4a: completed. 12 scenarios, 9 universal rules, 54 planned tests |
| Failure simulation model | Phase 4b: current. 73 tests, pure model + fake tests. No live PID move |
| Limiter attach | Not implemented |
| nftables/tc/state changes | Not implemented |
| `--attach-live` | Hard-blocked / non-mutating |
| Operation journal | Phase 3b: 12 planned events aligned with 10-step model |
| Phase 4a (failure simulation design) | Current: design-only, no runtime changes |
| Phase 3e (release-readiness/freeze) | Completed: freeze report, docs-only |
| Phase 3d (output audit) | Completed: 22 new tests, output audit doc |
| Phase 3c (executor seam + hard gates) | Completed: `move_executor.rs` + gate integration |
| Phase 3b (skeleton alignment) | Completed: `move_transaction.rs` + `operation_journal.rs` |
| Phase 3a (PID move design) | Completed: `docs/v2.8-phase-3a-single-pid-rollback-design.md` |
| Validation report | Phase 2c: `docs/v2.8-phase-2c-validation-report.md` |

## Next Milestone After v2.8

The v2.8 Experimental PID Move Lab proved that Zelynic can safely design a
single-PID cgroup move with immediate rollback (all model-only/fake-only in
v2.8; no live PID move was implemented).

**v2.9 Network Accounting Lab** is the next milestone. See
`docs/v2.9-network-accounting-lab.md` for the full design document. v2.9 is a
read-only accounting foundation for future quota guard, per-app usage history,
allow/block mode, and eventual eBPF observer backend. Phase 1 is design-only.
No enforcement, no blocking, no quota guard, no eBPF, no PID movement, no
cgroup.procs write, no nft/tc mutation.

- **v2.9**: Network Accounting Lab (read-only accounting design, interface
  counter model, future command surface). Docs/design only for phase 1.
- **v3.x**: Future quota guard / allow-block app mode (requires per-app
  attribution and enforcement backend).
- **v4.x**: Future eBPF observer / classifier backend (requires kernel 5.4+,
  CAP_BPF or root).

The incremental approach ensures each mutation type is validated in
isolation before combining them. The pure models from v2.7 (executor
skeleton, target preflight, cgroup diagnostics, operation journal) provide the
safety groundwork for the v2.8 real write path.
