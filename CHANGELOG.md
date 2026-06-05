# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Attach Safety Preflight**: Added a pure, non-mutating Scope Runner attach
  safety model that documents discovered PID(s), future target cgroup,
  required PID liveness checks, original cgroup capture, self-protection,
  rollback planning, mutation ownership, and live attach blocked status.
- **Original cgroup capture preview**: Added a pure parser/model for sample
  `/proc/<pid>/cgroup` content so future rollback planning can validate cgroup
  v2 paths without reading live `/proc` or moving PIDs.
- **Live original cgroup capture**: Added read-only parsing of `/proc/<pid>/cgroup`
  during the system-scope live probe, reporting honest rollback targets instead
  of claiming capture was not read.
- **PID Safety Model**: Added read-only PID liveness and self-protection checks
  to the Attach Safety preflight output. The live probe now dynamically rejects
  missing PIDs, already-managed PIDs, and the Zelynic process itself.
- **Experimental attach gate checklist**: Added `--experimental-single-pid-attach`,
  `--i-understand-this-moves-pids`, and `--rollback-required` as explicit
  future-consent flags for a single-PID move-only attach experiment. The gate is
  pure/model-only and remains blocked.
- **CLI refactor**: Split `src/cli.rs` from ~998 LOC to ~522 LOC. Moved CLI
  tests to `src/cli/tests.rs`. Deduped experimental gate safety footer.
- **Move-only executor skeleton**: Added a pure, non-mutating model of the
  future single-PID cgroup move and immediate rollback sequence. It documents
  target cgroup preparation, `cgroup.procs` writes, verification, rollback, and
  safe cleanup while keeping execution blocked.
- **Target cgroup environment preflight**: Added a pure model for future target
  cgroup path validation and `cgroup.procs` write-target previews. It keeps
  parent/target creation as future work and performs no live cgroup reads or
  writes.
- **Cgroup environment diagnostics model**: Added a pure parser/model for sample
  `/proc/self/mountinfo` cgroup v2 mount facts, including mount path,
  read-write/read-only mode, missing mount detection, and unexpected mount path
  reporting.
- **Operation journal preview**: Added a pure operation journal model for the
  future move-only executor, including deterministic preview operation IDs,
  operation ownership labels, ordered journal events, rollback boundary, and
  blocked state-write status.
- **v2.7.0 release documentation**: Added validation report
  (`docs/validation-reports/experimental-attach-v2.7.md`) and release notes
  (`docs/release-v2.7.0.md`) for the v2.7.0 Experimental Attach Lab.
- **v2.8 Experimental PID Move Lab design**: Added design document
  (`docs/experimental-pid-move-lab.md`) for the v2.8 first real write path.
  Phase 1 is design-only. The first real write boundary remains cgroup-only,
  single-PID, and rollback-first. No runtime changes.
- **Mkdir-only executor skeleton**: Added pure, non-mutating mkdir-only executor
  skeleton in `src/systemd_wrapper/mkdir_transaction.rs`. Models the exact
  future mkdir-only write sequence (namespace prepare, target cgroup create,
  verify exists, cleanup if operation-owned and empty) while remaining
  hard-blocked. No filesystem writes, no mkdir, no PID movement, no
  cgroup.procs writes, no nftables/tc/state changes. The skeleton renders in
  the experimental attach gate output with `first real write: not enabled in
  this build`.
- **Mkdir-only experiment executor**: Added `src/systemd_wrapper/mkdir_executor.rs`
  with the first real-write experiment for v2.8 phase 2b. When `--mkdir-live`
  is present with all existing gates, creates the Zelynic cgroup namespace
  directory and target cgroup, verifies existence, then cleans up the target
  cgroup if empty and operation-owned. New `--mkdir-live` CLI flag requires
  `--execute`, `--probe-live`, `--attach-live`,
  `--experimental-single-pid-attach`, `--i-understand-this-moves-pids`, and
  `--rollback-required`. No PID movement, no cgroup.procs write, no nftables/tc
  or state changes.
- **Mkdir-live output honesty fix**: Fixed misleading canonical safety footer
  when `--mkdir-live` is active. The old footer claiming "No nftables, tc,
  Zelynic cgroup, or state changes were made" is replaced with truthful
  wording for the mkdir-live path: "No nftables, tc, or Zelynic state changes
  were made." and "Mkdir-only cgroup preparation was performed." The mkdir
  experiment section now includes explicit honest lines: "No cgroup.procs
  write was performed." and "Parent namespace may remain: /sys/fs/cgroup/zelynic".
  The error message for `--mkdir-live` + `--attach-live` is now "Mkdir-only
  experiment completed; experimental PID move is not implemented yet." Normal
  non-mkdir paths preserve the existing canonical safety footer unchanged. No
  runtime behavior change; only output/reporting wording affected.
- **v2.8 phase 2c validation report**: Added validation report
  (`docs/v2.8-phase-2c-validation-report.md`) documenting the first real write
  (mkdir-only), output honesty, non-root gate verification, and root mkdir-live
  smoke validation. Docs/report only; no runtime changes.
- **v2.8 phase 3a single PID move + rollback design**: Added design document
  (`docs/v2.8-phase-3a-single-pid-rollback-design.md`) specifying the first
  actual PID move experiment. Design is root-only, system-scope-only, single
  disposable PID only (`sleep 3`), immediate rollback, no limiter attach, no
  nft/tc/state mutation, no persistent state write, no multi-PID process trees,
  no user scope, no long-running apps, no bandwidth limiting claim. Includes
  exact 10-step transaction model, failure policy (every failure after move
  attempts rollback, rollback failure reported loudly, no retry loops), test
  plan (unit tests, output honesty tests, gate tests, cleanup safety tests),
  and relationship to existing move_transaction.rs skeleton. Docs/design only;
  no runtime behavior changed. Live PID movement remains not implemented.
- **v2.8 phase 3b move transaction skeleton alignment**: Aligned the
  `move_transaction.rs` skeleton with the phase 3a design document's 10-step
  transaction model. Updated operation step descriptions with "planned"
  terminology, added step 7 "record move success", added PID liveness
  recheck and original cgroup validation steps with clear descriptions.
  Updated `writes_modelled` from 5 to 7 items. Added "transaction steps"
  and "rollback steps" rendering to skeleton output for visibility in gate
  output. Added explicit safety disclaimers ("pid movement: not performed",
  "cgroup.procs writes: not performed", "phase: 3b skeleton alignment").
  Updated operation journal planned events from 8 to 12 to align with
  10-step model. Added 14 new tests (PID liveness, original cgroup
  validation, record move success, immediate rollback, target cleanup
  boundary, operation/writes_modelled/rollback counts, output honesty,
  phase 3b label, transaction steps rendering, rollback steps rendering,
  empty original cgroup blocking). Docs/skeleton-only; no runtime behavior
  changed. Live PID movement remains not implemented. No cgroup.procs
  write was performed.
- **v2.8 phase 3c executor seam + hard gates**: Added
  `src/systemd_wrapper/move_executor.rs` as the model-only executor seam —
  the structural bridge between the gate checklist and the future live write
  path. The seam validates all hard gates (root, system scope, single PID,
  original cgroup present and non-empty, original cgroup not under
  `/zelynic/`, target under `/sys/fs/cgroup/zelynic/`, rollback consent
  present) and always returns blocked. Explicit disclaimers: phase 3c is
  executor-seam only, live PID move is not implemented, no cgroup.procs
  write was performed, no PID was moved, no limiter attach was performed,
  no nftables/tc/Zelynic state changes were made, no persistent state
  write was performed. Wired the seam into the experimental attach gate
  output as a preview/report section. Added 22 seam tests covering all
  hard-gate blocking, output honesty, disclaimer presence, and gate
  integration. No runtime mutation. No live PID move. No cgroup.procs
  write. No limiter attach. No nft/tc/state changes.
- **v2.8 phase 3d output audit + negative-path smoke coverage**: Audited
  and locked output honesty for all experimental attach and move executor
  seam paths. Added two new canonical deny lines to the seam disclaimers:
  "Experimental PID move is not implemented yet." and "Bandwidth limiting
  is not active from this command yet." Added 22 new tests across three
  modules: move_executor.rs (11 tests for canonical deny-line presence
  across negative paths, false claim absence, comprehensive mutation
  sweep), experimental_attach_gate.rs (10 tests for negative-path output
  honesty, 11-path seam disclaimer sweep, error constant wording audit,
  final status always blocked), mod.rs (7 tests for error message
  honesty, error constant audit, missing flag path blocking). Updated
  scope_probe.rs footer count for new deny line. Produced output audit
  document. No runtime behavior changes. All output remains non-mutating.
- **v2.8 phase 3e release-readiness / freeze report**: Produced release-
  readiness freeze report (`docs/v2.8-phase-3e-release-readiness-freeze.md`)
  summarizing all completed phases (2b mkdir-only executor, 2c validation
  report, 3a single PID rollback design, 3b move transaction skeleton
  alignment, 3c executor seam + hard gates, 3d output audit + negative-
  path smoke coverage). Documents current validated state (local green, CI
  green, root smoke green, version still v2.7.0, no live PID move). Lists
  7 explicit freeze safety guarantees (no PID move, no cgroup.procs write,
  no limiter attach, no nft/tc/state mutation, no persistent state write,
  no bandwidth limiting from experimental path, mkdir-only may create/
  cleanup target cgroup only). Documents 9 phase 4 entry criteria and full
  artifact inventory. Docs/report only; no runtime code changes.
- **v2.8 phase 4a failure simulation design**: Produced failure simulation
  design document (`docs/v2.8-phase-4a-failure-simulation-design.md`)
  defining 12 failure scenarios (F1-F12) for the future first real single-
  PID move experiment. Covers failure before target cgroup creation, failure
  after target creation but before PID move, failure after PID move but
  before/during/after verification and rollback, stale/dead PID during
  transaction, original cgroup disappears, target becomes non-empty, permission
  denied on cgroup.procs write, and unexpected EBUSY/ENOENT/EACCES. For each
  scenario: rollback behavior, output honesty, cleanup behavior, target
  leftover policy, manual recovery needs, and forbidden claims. Defines 9
  universal failure rules and PID location label taxonomy (not moved, verified
  in target, verified restored, rollback unverified, unknown). Includes test
  plan: 21 fake filesystem unit tests, 13 fake writer injection tests, 13
  render tests, 7 canonical deny-line persistence tests. No root smoke, no
  live PID move. Docs/design only; no runtime code changes.
- **v2.8 phase 4b failure simulation model + fake tests**: Implemented
  pure Rust model code and 73 tests for the 12 failure scenarios from
  phase 4a in `src/systemd_wrapper/failure_simulation/` (mod.rs +
  tests/mod.rs). Pure model code includes: 12 failure scenario enum
  (F1-F12), PID location status taxonomy (not moved, verified in target,
  verified restored, rollback unverified, unknown), rollback decision
  model, cleanup decision model, simulation result struct with canonical
  deny lines, and pure functions (build_failure_simulation_matrix,
  simulate_failure_scenario, render_failure_simulation_result). 73 tests
  cover: matrix completeness, per-scenario PID location/rollback/cleanup
  correctness, render output simulation/model-only markers, canonical
  deny lines (live PID move, cgroup.procs write, limiter attach, nft/tc/state
  mutation, persistent state write), no false rollback claims, no retry
  loops, universal failure rules (9 rules from phase 4a), render structure
  verification, and determinism. Module wired into systemd_wrapper with no CLI
  path and no runtime behavior change. No live PID move, no real
  cgroup.procs write, no limiter attach, no nftables/tc/Zelynic state
  mutation, no persistent state write. All simulation is pure model/fake-only.
- **v2.8 phase 4c fake writer injection harness**: Added fake writer
  injection harness in `src/systemd_wrapper/failure_simulation/fake_writer/`
  (fake_writer.rs + tests.rs) that simulates cgroup.procs write outcomes
  and transaction failures without touching the real system. Models fake
  write operations (write PID to target, verify in target, write PID back
  to original, verify restored, cleanup target) with 10 injectable failure
  modes (EACCES/ENOENT/EBUSY on target write, EACCES/ENOENT on rollback
  write, EBUSY on cleanup, stale PID before/after target write, original
  cgroup missing before rollback, target non-empty during cleanup). Fake
  writer result model captures operation status (attempted/succeeded/failed),
  fake errno, PID location (not moved, verified in target, verified
  restored, rollback unverified, unknown), rollback/recovery/cleanup flags.
  Pure functions `simulate_fake_transaction()` and
  `render_fake_transaction_result()`. Canonical deny lines in every rendered
  output: no real cgroup.procs write, no live PID move, no limiter attach,
  no nft/tc/Zelynic state mutation, no persistent state write. Tests
  covering happy path, all failure modes, deny-line persistence, no retry
  loops, render structure, determinism, and cleanup-safety invariants.
  Submodule wired into failure_simulation/mod.rs, crate-private,
  test-focused, no CLI path, no runtime behavior change. No live PID move,
  no real cgroup.procs write, no limiter attach, no nftables/tc/Zelynic
  state mutation, no persistent state write. All writer simulation is pure
  fake/in-memory/test-only/model-only.
- **v2.8 phase 4d fake writer render/output matrix**: Added canonical
  render/output matrix in `src/systemd_wrapper/failure_simulation/fake_writer/
  render_matrix/` (render_matrix.rs + tests.rs) that covers every
  FakeFailureMode (11 variants) with deterministic, honest, non-mutating
  rendered output. For each mode: phase label (4d), fake/model-only
  statement, failure mode label, fake errno, per-step operation status,
  PID location, rollback/recovery/cleanup flags. 7 canonical deny lines
  (no live PID move, no real cgroup.procs write, no limiter attach, no
  nft/tc/Zelynic state changes, no persistent state write, no CLI path for
  live PID move, fake/model-only). Explicit forbidden claims (no real PID
  moved, no real rollback, no limiter attached, no bandwidth limiting active,
  no nft/tc/state mutation, no cleanup success when cleanup failed). Pure
  functions: `build_full_render_matrix()`, `render_matrix_entry()`,
  `render_matrix_output()`. Tests: matrix completeness, determinism, all 7
  deny lines per mode, forbidden claim absence, errno rendering, target
  write failures never claim rollback, rollback failures report manual
  recovery, cleanup EBUSY leaves target, non-empty target never deleted,
  stale PID before write no operations, stale PID after target write
  requires rollback, PID location in all modes, no retry loop, render
  structure, mode-specific correctness. Submodule wired into fake_writer.rs,
  crate-private, no CLI path, no runtime change. No live PID move, no real
  cgroup.procs write, no limiter attach, no nft/tc/Zelynic state mutation,
  no persistent state write. All output is pure fake/model-only/render-only.
- **v2.8 phase 4e failure simulation freeze/validation report**: Produced
  freeze/validation report (`docs/v2.8-phase-4e-failure-simulation-freeze.md`)
  summarizing phases 4a–4d: phase 4a failure simulation design (12 scenarios,
  9 universal rules, test plan), phase 4b failure simulation model + 73 tests,
  phase 4b test wiring fix, phase 4c fake writer injection harness + 42 tests,
  phase 4c formatting fix, phase 4d fake writer render/output matrix + 36
  tests. Current totals: failure_simulation 151 tests, fake_writer 78 tests,
  project 604 tests. Validation state: `./build.sh check-all` passed, CI green,
  security audit passed, policy check passed (80 files), version still v2.7.0.
  Explicit freeze guarantees: no live PID move, no real cgroup.procs write,
  no limiter attach, no nft/tc/Zelynic state mutation, no persistent state
  write, no CLI enablement for live PID move, all simulation fake/model-only.
  Phase 5 entry criteria defined: freeze report complete, CI green, all tests
  wired and passing, root smoke commands reviewed before execution, first real
  PID move remains blocked until phase 5, future real move must be root-only,
  system-scope-only, single disposable sleep PID only, immediate rollback
  required, no limiter attach, no nft/tc/state mutation. Docs/report only; no
  runtime code changes.
- **v2.8 phase 5a first real move readiness/manual smoke plan**: Produced
  readiness document (`docs/v2.8-phase-5a-first-real-move-readiness.md`)
  defining the only acceptable future first real PID move smoke. 11 constraints:
  root-only, system-scope-only, single disposable sleep PID only, immediate
  rollback required, no limiter attach, no nft/tc/Zelynic state mutation, no
  persistent state write, no browser/terminal/desktop process, no user app, no
  multi-PID tree, no bandwidth limiting claim. 14-step manual smoke command
  plan: create disposable sleep scope, capture PID, capture original cgroup,
  verify cgroup mount, prepare target, verify target empty, write PID to
  target cgroup.procs, verify PID in target, immediate rollback write, verify
  restored, cleanup empty target, verify no leftover, verify no nft/tc/state
  changes, stop sleep scope. 10 abort conditions: PID missing/stale, more than
  one PID, original cgroup missing, original cgroup Zelynic-managed, target
  outside zelynic namespace, target non-empty, cgroup mount read-only,
  permissions unexpected, rollback target unverifiable, ambiguous output.
  Expected output honesty requirements and manual recovery procedures defined.
  Docs/design only; no runtime code changes. No live PID move.

### Changed

- **Experimental gate rendering**: The full experimental gate now includes
  the move executor seam (phase 3c) section between the move-only executor
  skeleton and the mkdir-only executor skeleton, showing gate validation
  results and explicit disclaimers before any future live write path.
- **Future Attach Preview**: Scope Runner attach preview now renders the
  Attach Safety Preflight section while continuing to perform no PID movement,
  limiter attach, nftables/tc changes, Zelynic cgroup changes, or state writes.
- **Attach Safety rendering**: The preflight now explicitly reports original
  cgroup capture from the live probe, displaying honest exact rollback targets
  or "original cgroup capture unavailable/stale" if the PID already exited.
- **Attach-live path**: When the full experimental consent bundle is present,
  the future attach path can render a gate checklist after a successful probe,
  then still returns "Experimental PID move is not implemented yet" without PID
  movement, limiter attach, nftables/tc changes, Zelynic cgroup changes, or
  state writes.
- **Experimental gate rendering**: The full experimental gate now includes the
  move-only executor skeleton so future write ordering is visible without
  duplicating the canonical no-mutation safety footer.
- **Move-only executor output**: The skeleton now renders target cgroup
  preflight details, including the future Zelynic target namespace and
  target/rollback `cgroup.procs` paths, while keeping execution blocked.
- **Target preflight output**: The target cgroup preflight now includes
  model-only cgroup environment diagnostics and explicitly keeps
  `cgroup.procs` writes blocked.
- **Move-only executor output**: The skeleton now renders an operation journal
  preview so future mutation ownership and rollback boundaries are visible
  before any real write path exists.

## [2.5.0] - 2026-06-03 - v2.5.0 Scope Runner

### Changed

- **`run_systemd_wrapper` signature**: Added `attach_live` parameter to
  `run_systemd_wrapper` and `handle_run` for the v2.5 Scope Runner live
  attach gate.
- **Module split**: Refactored `scope_runner.rs` into focused modules
  (`scope_runner.rs`, `scope_probe.rs`, `attach_preview.rs`) to keep files
  under 1000 LOC.

### Added

- **Live attach gate flag**: Added `--attach-live` flag to `zelynic run`
  for an explicit future live limiter attach gate. Requires `--execute`,
  `--probe-live`, `--scope-mode system`, and root. This flag is
  **hard-blocked** — even when all requirements are met, the command fails
  with "Scope Runner live attach is not implemented yet. This build only
  supports live probe and attach preview." No PID movement, no limiter
  attach, no nftables/tc/cgroup/state changes are performed.
- **Attach gate Clap constraints**: `--attach-live` uses Clap
  `requires = "execute"` and `requires = "probe_live"` to reject
  obvious invalid combinations at parse time.
- **Attach gate function**: Added `attach_gate()` in `scope_runner.rs`
  that always returns a hard-blocked "not implemented yet" error.
- **Attach gate tests**: Added unit tests verifying the attach gate always
  hard-blocks, does not claim "attached"/"limited"/"enforced", and does
  not claim mutation. Added integration tests in `mod.rs` verifying that
  `attach_live` without `probe_live` falls through to not-implemented,
  `attach_live` with user scope is blocked by probe gate, and
  `attach_live` with system scope non-root is blocked by probe gate.
- **CLI tests**: Added tests for `--attach-live` parsing, `--attach-live`
  requires `--execute`, `--attach-live` requires `--probe-live`, and
  `--attach-live` defaults to false.
- **Scope Runner live probe**: Added `--probe-live` flag to `zelynic run`
  for a controlled, root-only, system-scope live probe. When invoked as
  `sudo zelynic run --execute --scope-mode system --probe-live -- <command>`,
  Zelynic launches a real transient systemd scope via `systemd-run --scope`,
  queries the scope unit properties via `systemctl show`, reads PID(s) from
  `cgroup.procs`, and reports findings. Does NOT apply bandwidth limits,
  modify nftables, tc, Zelynic cgroups, or state.
- **Scope Runner gating**: The `--probe-live` path requires all three:
  `--execute`, `--scope-mode system`, and root (euid == 0). Missing any
  requirement falls back to existing behavior (not-implemented or
  privilege error).
- **User-scope probe blocked**: `--probe-live` with user scope returns
  "User-scope live runner is not implemented" — user-scope needs
  privilege/session handoff.
- **Scope Runner module**: Added `src/systemd_wrapper/scope_runner.rs`
  containing probe gate logic (`probe_gate`), live probe execution
  (`run_scope_probe`), output rendering (`render_scope_probe_output`),
  and plan builder (`build_probe_systemd_run_plan`). Unit name convention:
  `zelynic-probe-v250-<sanitized_target>`.
- **Probe output wording**: Scope Runner output honestly states "Scope
  Runner live probe", "No limiter attach was performed", "No nftables, tc,
  Zelynic cgroup, or state changes were made", "Bandwidth limiting is not
  active from this command yet", and documents cleanup command.
- **Scope Runner tests**: Added unit tests for gate logic (missing flag
  blocked, user scope blocked, system non-root blocked, system root allowed
  by preflight model), output wording (no limiter claims, no nftables/tc
  claims, no Zelynic cgroup/state claims, cleanup command present), plan
  builder (v2.5 naming, target sanitization, empty command error), command
  rendering, and unit name sanitization safety.
- **CLI tests**: Added tests for `--probe-live` parsing (with execute and
  system), `--probe-live` requires `--execute`, and `--probe-live` defaults
  to false.
- **Future attach preview**: Added non-mutating "Future attach preview"
  section to the Scope Runner live probe output. After successful discovery,
  the preview displays discovered PID(s), future target cgroup path,
  requested download/upload rates, attach source, strict backend label, and
  "preview only; not applied" status. Does NOT move PIDs, create cgroups,
  modify nftables/tc, write state, or call `zelynic strict`.
- **AttachPreview model**: Added `AttachPreview` struct and
  `build_attach_preview` builder in `scope_runner.rs` for constructing the
  preview from probe result data, target name, and bandwidth rates. Uses the
  same sanitization and rate parsing as the dry-run/execute planning path.
- **Attach preview tests**: Added unit tests verifying preview includes
  discovered PIDs, future target cgroup, requested rates, preview-only
  status, no-PID-moved disclaimer, no nftables/tc/cgroup/state disclaimer,
  absence of enforcement words ("enforced", "attached", "limited",
  "active limiter"), safe handling of empty PIDs, unlimited rates when not
  specified, and backward-compatible render without preview.

### Docs

- **Scope Runner section**: Added "Scope Runner Live Probe (v2.5)" section
  to `docs/scope-lab.md` explaining what the probe does, what it does not do,
  requirements, CLI syntax, cleanup, implementation details, unit name
  convention, and user-scope status.
- **Attach preview docs**: Added "Future Attach Preview" subsection to
  `docs/scope-lab.md` explaining the preview-only section, its fields,
  safety disclaimers, what it does not do, implementation, and future
  direction (separate explicit attach gate).
- **Live attach gate docs**: Added "Live Attach Gate (`--attach-live`)"
  section to `docs/scope-lab.md` explaining the hard-blocked future attach
  gate, its requirements, gate order, what it does not do, and the current
  supported live path.
- **Wrapper design update**: Updated `docs/systemd-wrapper-design.md` to
  mention the v2.5 Scope Runner, its `--probe-live` gate, and the
  `--attach-live` hard-blocked future gate.
- **Scope Runner validation report**: Added
  `docs/validation-reports/scope-runner-v2.5.md` documenting six tested
  command scenarios (four non-root blocked, root probe passed, root
  attach-live hard-blocked), observed results, and final status.
- **Release checklist**: Added "Release Checklist (Scope Runner Smoke
  Matrix)" section to `docs/scope-lab.md` with six manual smoke tests
  covering non-root gates, root probe, and attach-live hard-block.
- **Validation report index**: Added "Scope Runner Validation Report"
  type to `docs/validation-reports/README.md`.

### Notes

- `zelynic run --execute` without `--probe-live` remains non-mutating and
  returns "Live systemd wrapper execution is not implemented yet."
- `--attach-live` is hard-blocked in this build. Even with root +
  `--execute` + `--probe-live` + `--scope-mode system`, the command
  returns "live attach is not implemented yet."
- No bandwidth limiting is applied by the Scope Runner.
- `zelynic strict` remains the only validated active limiter path.

## [2.4.0] - 2026-06-03 - v2.4.0 Scope Lab

### Changed

- **ControlGroup-first PID discovery**: Refactored systemd wrapper PID discovery model to prefer ControlGroup + cgroup.procs as the primary discovery path for scope units. MainPID is now optional/diagnostic only; scope units may report MainPID=0 or absent. Based on real probe findings documented in `docs/scope-lab.md`.
- **Dry-run and execute output**: Updated planned flow to describe backgrounded scope launch, ControlGroup path discovery, and cgroup.procs PID reading as the intended 5-step discovery sequence. MainPID is described as optional/diagnostic only in output.
- **Scope-aware discovery wording**: Fixed dry-run and execute plan output to render scope-mode-specific `systemctl` commands. User scope now correctly shows `systemctl --user show <unit> --property ControlGroup` in the PID discovery step. System scope shows `systemctl show <unit> --property ControlGroup`. Previously the wording was hardcoded to one form regardless of scope mode.
- **Launch/discover/attach contract model**: Added `src/systemd_wrapper/contract.rs` as a pure, non-executing data model for the future live run. The contract defines three phases (launch, discover, attach) with privilege requirements and safety gates. All phases are marked as not implemented. The contract is wired into dry-run and execute output as a "Future launch/discover/attach contract" section, keeping output readable without implying live implementation.
- **Scope-aware contract launch privilege**: Fixed the contract model to use scope-mode-specific privilege labels for the launch step. User scope launch shows "user manager"; system scope launch shows "system manager / root-or-polkit". Previously both showed "user", which was inaccurate for system scope where launch requires root or triggers Polkit. Safety gate wording also updated to distinguish user-scope (user manager context) from system-scope (requires root or triggers Polkit).
- **Scope-aware contract discover privilege**: Fixed the contract model to use scope-mode-specific privilege labels for the discover step. User scope discover shows "user manager"; system scope discover shows "system manager / root-or-polkit". Previously both showed "user manager", which was inaccurate for system scope where `systemctl show` runs in the system manager context.

### Added

- **Scope Lab design doc**: Added `docs/scope-lab.md` documenting manual systemd scope probe findings from Arch/CachyOS host, including foreground vs backgrounded scope behavior, ControlGroup availability, cgroup.procs readability, and the ControlGroup-first design rationale.
- **Privilege and session handoff design**: Added a "Privilege and Session Handoff" section to `docs/scope-lab.md` explaining why live execution is blocked (user-scope launch vs root attach privilege boundary, Polkit risks, sudo shell issues) and three candidate future designs (A: user-launch + root-helper, B: explicit sudo/root system scope, C: split launch/attach command pair). All designs are marked as future work, not implemented.
- **ControlGroup-first discovery tests**: Added tests verifying that PID discovery prefers ControlGroup scan even when a valid MainPID is present, that MainPID=0 with valid ControlGroup still uses ControlGroup, and that scope units without MainPID use ControlGroup directly.
- **Scope-aware discovery wording tests**: Added tests verifying user-scope dry-run renders `systemctl --user show` in discovery wording, system-scope dry-run renders `systemctl show` (without `--user`), and execute plans use matching scope-aware wording for both user and system modes.
- **Launch/discover/attach contract tests**: Added tests for the contract model verifying user-scope uses user launch + user systemctl discovery, system-scope uses system launch + system systemctl discovery, discover phase is ControlGroup-first, attach requires root, live execution is always false, and contract has no mutation/execution side effects.
- **Contract render integration tests**: Added tests verifying dry-run and execute output include the contract section, contract steps show correct privilege labels, and existing safety wording is preserved after the contract section.
- **Manual probe recipe in dry-run**: Added a "Manual probe recipe" section to `zelynic run --dry-run` output that provides ready-to-copy/paste shell commands for manually testing the Scope Lab flow. User scope recipe uses `systemd-run --user --scope` with `systemctl --user` inspect/cleanup. System scope recipe includes a warning about root/sudo/Polkit and uses `sudo systemd-run --scope` with `sudo systemctl stop`. The recipe is clearly marked as manual-only and not executed by Zelynic. Omitted from `--execute` output to avoid noise.
- **Manual probe recipe tests**: Added tests verifying user-scope recipe includes backgrounded `systemd-run --user --scope` with trailing `&`, `systemctl --user show` for inspect, `systemctl --user stop` for cleanup, and `cgroup.procs` mention. System-scope tests verify root/sudo/Polkit warning presence, `sudo systemd-run --scope` usage, and `sudo systemctl stop` usage. Additional tests confirm safety wording is preserved after recipe and execute output omits the recipe.

### Docs

- **Launch/discover/attach contract**: Added a "Launch / Discover / Attach Contract" section to `docs/scope-lab.md` explaining the three-phase design contract (launch, discover, attach), its safety properties, privilege implications, and how it appears in dry-run/execute output.
- **Split contract mention**: Updated `docs/systemd-wrapper-design.md` to reference the contract model as the formalization of the launch-then-attach design.
- **Manual probe recipe doc**: Added a "Manual Probe Recipe" section to `docs/scope-lab.md` describing the four-step manual probe recipe added in phase 4, its scope-aware behavior, and its placement in dry-run output.

### Notes

- `zelynic run --execute` remains non-mutating and returns "Live systemd wrapper execution is not implemented yet."
- No live systemd-run execution is implemented in this phase.
- Strict attach still requires root.
- No version bump.

## [2.3.0] - 2026-06-03 - v2.3.0 Distro Matrix

### Added

- **Source policy enforcement**: Added `RULES.md` with project-wide policy rules including a 1000 LOC limit per core code file and mandatory copyright/SPDX headers.
- **Policy checker**: Added `scripts/check-policy.py` for automated policy enforcement as part of the `./build.sh check-all` quality gate.
- **Dependency policy**: Added `deny.toml` for structured cargo-deny checks and `docs/supply-chain.md` documenting the supply-chain policy.
- **Command module extraction**: Extracted command handlers from `src/main.rs` into `src/commands/` module (mod.rs, strict.rs, run.rs, profile.rs, monitor.rs, backend.rs, help.rs), slimming main.rs from 926 to 94 LOC.
- **Distro support matrix**: Added `docs/distro-matrix.md` with distribution support status labels, required capabilities, and validation checklist for tracking which Linux distributions have been validated with Zelynic's strict limiter path.
- **Host fact collector**: Added `scripts/collect-host-facts.sh`, a non-mutating, no-sudo shell script that collects kernel, distro, cgroup, userspace tool, and default route information for host capability assessment.
- **Distro validation flow**: Added a structured two-step validation flow to `docs/validation.md` covering non-root read-only capability checks and privileged strict limiter validation with documentation guidance.
- **Validation report templates**: Added `docs/validation-reports/` with README, per-distro report template, and initial Arch/CachyOS validation report documenting the v2.0.0 strict limiter test results.
- **Release notes**: Added `docs/release-v2.3.0.md` with scope, validation, and caveat notes for this release.

### Notes

- No runtime limiter behavior changes in this release. All commits are documentation, policy enforcement, CI/CD hardening, and code organization.
- Strict limiter path remains validated on tested Arch/CachyOS modern cgroup v2 host only. Fedora/Ubuntu/Debian remain candidate/pending.
- `zelynic run --execute` remains non-mutating. Live systemd-run execution is not implemented.
- `zelynic run` remains experimental groundwork, not a supported active backend.

## [2.2.0] - 2026-06-03 - v2.2.0 Scope Prelude

### Added

- **Experimental run groundwork**: Added `zelynic run` planning for a future systemd wrapper workflow.
- **Dry-run systemd wrapper planning**: `zelynic run --dry-run ...` renders the planned launch command, attach target, PID discovery handoff, and launch-then-attach flow without launching a process or modifying nftables, tc, cgroups, or state.
- **User-scope-first planning**: Run planning now defaults to user scope and previews `systemd-run --user --scope` to avoid surprise system Polkit prompts for GUI/user applications.
- **Scope mode selection**: Added planning-only `--scope-mode <user|system>` so system-scope previews are explicit.
- **Execution preflight**: `zelynic run --execute ...` now prints a non-mutating preflight that explains why live limiting is blocked or future-only for the selected scope/privilege combination.
- **Resolved-PID attach groundwork**: Added an internal strict attach path for already-resolved PIDs, preparing future launch-then-attach integration without changing current strict behavior.
- **Release notes**: Added `docs/release-v2.2.0.md` with scope, caveats, and validation notes for this release.

### Changed

- **Systemd wrapper docs**: Clarified that the future v2.2 model is launch-then-attach, not a native systemd cgroup backend.
- **Module layout**: Split large systemd wrapper and capability modules, and slimmed limiter orchestration so core Rust files stay under 1000 LOC.
- **Run safety wording**: README and usage docs now consistently describe `run` as experimental groundwork and `dry-run` as the safe preview path.

### Fixed

- **Unstrict lifecycle cleanup**: Fixed a lifecycle bug where PIDs already inside Zelynic target cgroups could be recorded as their own original restore destination.
- **Target cgroup removal**: After unstrict, Zelynic now avoids restoring PIDs back into `/sys/fs/cgroup/zelynic/target_<target>`, falls back to `/sys/fs/cgroup/zelynic` when needed, and can remove the emptied target cgroup.

### Notes

- `zelynic run --execute` is still non-mutating in v2.2.0 and returns `Live systemd wrapper execution is not implemented yet.`
- v2.2.0 does not implement live `systemd-run` execution.
- `zelynic strict` remains the currently validated limiter path.
- Systemd wrapper/run mode remains experimental groundwork, not a supported active backend.

## [2.1.0] - 2026-06-02 - v2.1.0 Backend Doctor

### Added

- **Backend Doctor**: Added `zelynic backend doctor` and `zelynic backend doctor --json` for read-only host capability diagnostics and deterministic backend recommendations.
- **Refresh command**: Added `zelynic refresh <target>` to manually move reopened or respawned target PIDs into an existing active limit without duplicating nftables or tc rules.
- **Interface-change warning**: `zelynic status` now warns when active limits are attached to an interface that differs from the current default route.
- **Release notes**: Added `docs/release-v2.1.0.md` with validation notes and caveats for this release.

### Changed

- **Runtime namespace**: Migrated active runtime paths and identifiers from legacy `oxy` names to `zelynic`: `/run/zelynic`, `/run/zelynic/zelynic.nft`, `/sys/fs/cgroup/zelynic`, and `table inet zelynic`.
- **Limiter internals**: Split the limiter implementation into focused modules without intentionally changing strict backend behavior.
- **Supply-chain policy**: Hardened local dependency checks with documented `cargo audit`, `cargo deny`, and `./build.sh check-all` workflow.
- **Strict lifecycle docs**: Documented that `zelynic strict` applies to new connections after cgroup movement; already-running requests may need reload or restart.

### Fixed

- **Unstrict cgroup restore**: `zelynic unstrict` now records and restores original cgroups when safe, falls back conservatively, removes empty target cgroups, and explains kept cgroups.
- **Refresh state preservation**: Mistimed `zelynic refresh <target>` no longer deletes active target state when the app is not currently running.
- **Release wording**: Fixed release/version wording that could produce duplicate `v` prefixes in docs or release titles.

### Notes

- Strict limiting remains validated on tested modern cgroup v2 systems, not all Linux distributions.
- v2.0.0-era `oxy` runtime artifacts are treated as legacy cleanup targets only.
- See `docs/release-v2.1.0.md` for release validation notes.

## [2.0.0] - 2026-06-01 - v2.0.0 Renaissance

### Renaissance Notes

- **Rebrand**: Project renamed from Oxy to Zelynic.
- **Binary rename**: The command is now `zelynic`.
- **License change**: Project license changed to `GPL-3.0-only`.
- **Strict limiter breakthrough**: `zelynic strict` has been validated on tested modern cgroup v2 systems using the tc/nftables/cgroup backend.
- **Strict diagnostics**: `zelynic strict --diagnose` is kept for real-host troubleshooting and now reports selected PID match reasons alongside cgroup, nftables, and tc diagnostics.
- **Process resolver safety**: Fixed false positives where terminal or shell processes could be selected only because their full command line contained the target name.
- **Validated Brave limiting on CachyOS/Arch**:
  - kernel `6.18.33-1-cachyos-lts`
  - nftables `v1.1.6`
  - tc/iproute2 `7.0.0`
  - pure cgroup v2
  - interface `wlp1s0`
- **Real validation results**:
  - `500 KB/s` target produced about `3.1-3.9 Mbps` in browser speed tests.
  - `500 Kbit/s` target produced about `0.28-0.55 Mbps` in Fast.com and Speedtest.net.
- **Compatibility**: Legacy runtime paths and identifiers are intentionally preserved for this release: `/run/oxy`, `/sys/fs/cgroup/oxy`, and `table inet oxy`.
- **Scope**: This release is validated on tested modern cgroup v2 systems; it does not claim universal support across all Linux distributions.

### Added

- **TUI live dashboard** — Real-time bandwidth monitoring with ratatui
  - Braille sparklines for RX/TX history
  - Table scrolling (j/k, arrow keys)
  - Empty state message when no connections
  - Process count in header
  - Ctrl+C clean exit handler
- **`--iface` global flag** — Specify or list network interfaces
  - Auto-detects default interface
  - Validates against available interfaces
  - Works with all commands (`list`, `strict`, `qos`, `profile`, `auto`)
- **`--live N` shorthand** — `zelynic list --live 2` instead of `--live --interval 2`
- **Preset profiles** — `zelynic strict --preset gaming/streaming/background`
- **QoS priority shaping** — `zelynic qos high/low` with HTB priority tiers
- **Named profiles** — `zelynic profile save/apply/list/delete`
- **Auto-throttle daemon** — `zelynic auto` with download/upload thresholds
- **Bandwidth watch** — `zelynic watch --alert` with desktop notifications
- **Bandwidth history** — `zelynic log` with snapshots and rotation
- **Auto-cleanup on re-limit** — `zelynic strict` auto-removes old rules for same target
- **Shell completions** — Bash, Zsh, Fish, Elvish, PowerShell
- **Man page generation** — `zelynic man`
- **`zelynic backend`** — eBPF/tc support detection
- **`zelynic auto --status`** — Check auto-throttle daemon status
- **Strict diagnostics** — `zelynic strict --diagnose` for backend validation and troubleshooting
- **`--help-all`** — Comprehensive help with all commands and examples
- **`--no-color`** — Disable colored output (also respects `NO_COLOR=1`)
- **IPv6 support** — Correct parsing of `[::1]:443` bracket notation

### Changed

- **Breaking**: Version bump from 1.0.0 to 2.0.0
- **Branding**: Project, package, binary, docs, and public examples now use Zelynic/`zelynic`
- **License**: Project now uses GNU GPL v3 via `GPL-3.0-only`
- **Monitoring**: Uses `ss -tuneiH` with per-socket byte counters (kernel 4.6+)
- **Process resolution**: inode-based via `/proc/*/fd/` instead of `/proc/net/tcp`
- **Target resolution**: Process-name matching is now conservative and no longer scans full command-line arguments
- **Rate limiting**: cgroup v2 process grouping with nftables marking and tc HTB shaping for strict limits
- **State persistence**: `/run/oxy/state.json` with JSON-serialized limit records, intentionally kept as a legacy compatibility path
- **CI**: GitHub Actions with lint, test, build, security audit, MSRV check
- **Release**: Tag-triggered release workflow with tar.gz + SHA256 checksum

### Fixed

- IPv6 address parsing in verbose mode (broken for bracket notation)
- Column alignment in process table (truncate_str padding bug)
- Terminal corruption on TUI error (raw mode entered before validation)
- Class ID race condition with `flock(2)` file locking
- Panic hook properly restored after TUI exit
- `zelynic watch` no longer requires root (monitoring is read-only)
- Strict CLI validation — unknown interface names show error with available list
- `zelynic strict` process-name targets no longer select zelynic, sudo, shells, or terminal emulators just because their command line contains the requested target

### Removed

- 205-line legacy crossterm live display (replaced by ratatui TUI)
- Duplicate display function code (consolidated)
- Orphaned `format_rate()` function

## [1.0.0] - 2026-01-01

### Added

- Initial release with tc-based bandwidth limiting
- Process resolution via `/proc/net/tcp` and inode matching
- `zelynic list`, `zelynic strict`, `zelynic unstrict`, `zelynic status` commands
- Basic CLI interface with colored output

[Unreleased]: https://github.com/oxyzenq/zelynic/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/oxyzenq/zelynic/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/oxyzenq/zelynic/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/oxyzenq/zelynic/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/oxyzenq/zelynic/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/oxyzenq/zelynic/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/oxyzenq/zelynic/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/oxyzenq/zelynic/releases/tag/v1.0.0
