# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **v3.0 Live Read-Only Usage Lab design**: Added design document
  (`docs/v3.0-live-read-only-usage-lab.md`) for the v3.0 live read-only usage
  milestone. Phase 1 is design-only: defines the future command contract
  (`zelynic usage`, `zelynic usage --sample`, `zelynic usage --interface`,
  `zelynic usage --json`, `zelynic usage --delta --interval`, `zelynic usage
  --since-start`, `zelynic usage --no-loopback`, `zelynic usage
  --all-interfaces`), all marked as planned/not implemented/read-only/interface
  -level only/not per-app attribution/not quota enforcement/not network blocking.
  Defines the live `/proc/net/dev` reader boundary (may read only
  `/proc/net/dev`, must not read arbitrary files, must not write, must not mutate
  system state, must reuse existing parser, must expose source label honestly as
  live_proc_net_dev, must not claim per-app attribution). Defines output honesty
  requirements (interface-level only, not per-app attribution, no quota enforcement
  active, no network blocking active, no limiter attach performed, no nft/tc
  /Zelynic state mutation performed, no ledger persistence performed, no eBPF
  used, counters may reset after reboot). Defines future JSON output contract
  (schema_version, source, sampled_at if caller-provided, interfaces with
  rx_bytes/tx_bytes/combined_bytes/loopback, totals, honesty flags:
  per_app_attribution=false, quota_enforcement_active=false,
  network_blocking_active=false, persistence_performed=false, ebpf_used=false).
  Phase plan: 7 phases (design, reader seam, live reader tests, CLI preview,
  JSON output, delta sampling design, RC freeze). No Rust code changes, no test
  additions, no live system reads, no CLI command registration in phase 1.
  Updated `docs/v2.9-network-accounting-lab.md` with next-milestone note pointing
  to v3.0. v3.0 does NOT implement eBPF, quota enforcement, network blocking,
  limiter attach, nft/tc mutation, state mutation, filesystem persistence, ledger
  file read/write, PID movement, cgroup.procs write, live /proc or sysfs read, or
  CLI enablement in phase 1. `zelynic strict` remains the only validated active
  limiter path.
- **v3.0 phase 2 live /proc/net/dev reader seam**: Added
  `src/accounting/live_proc_net_dev.rs` with read-only seam model for the future
  `zelynic usage --sample` command. Model types: `LiveProcNetDevReadPlan`
  (source_path hardcoded to `/proc/net/dev`, source_label, read_status
  Planned/Success/Error, filesystem_read_performed=false, filesystem_write_performed
  =false, state_mutation_performed=false, optional parsed snapshot, safe_reason),
  `LiveReadStatus` (Planned, Success, Error). Pure functions:
  `build_live_proc_net_dev_snapshot_from_content(content)` parses injected
  content via existing parser, returns plan with source_label
  `live_proc_net_dev_sample`; `build_live_proc_net_dev_read_plan()` returns
  planned state with source_label `live_proc_net_dev`; `build_live_proc_net_dev_
  error_plan(error)` returns error state; `render_live_proc_net_dev_read_plan()`
  renders human-readable output with 13 honesty disclaimers (read-only
  /proc/net/dev seam, interface-level only/not per-app attribution, no quota
  enforcement active, no network blocking active, no limiter attach performed, no
  nft/tc/Zelynic state mutation performed, no ledger persistence performed, no
  eBPF used, no cgroup mutation, no PID movement, counters may reset after
  reboot/interface reset, filesystem write not performed, state mutation not
  performed). Source path is hardcoded — no arbitrary paths accepted. No live
  filesystem reads — injected content parsing only. No CLI command registered.
  Reader seam is `pub(crate)` only. 35 tests in
  `src/accounting/tests/live_proc_net_dev.rs`: injected content parses via
  existing parser, honest source label, minimal/unusual interface names parse,
  malformed content returns parse errors (no colon, too few fields, non-numeric),
  empty/headers-only content returns empty snapshot, read plan points only to
  /proc/net/dev, read plan does not accept arbitrary path, read plan is planned
  state with live source label, error plan has correct status, injected plan
  flags are correct, render includes read-only seam statement, render denies
  per-app attribution, render denies quota enforcement, render denies network
  blocking, render denies limiter attach, render denies nft/tc/state mutation,
  render denies ledger persistence, render denies eBPF, render denies cgroup
  mutation, render denies PID movement, render warns counters may reset, render
  includes filesystem write not performed, render includes state mutation not
  performed, render includes source path and label, render planned plan shows
  planned status, no CLI command is added (structural), no filesystem write
  APIs used (structural), render shows snapshot summary, render shows empty
  snapshot, render is deterministic, render shows mutation flags, render error
  plan shows error status, loopback detection, large counter handling (u64::MAX).
  No eBPF, no quota enforcement, no network blocking, no limiter attach, no
  nft/tc mutation, no state mutation, no filesystem persistence, no ledger file
  read/write, no PID move, no cgroup.procs write, no sysfs read, no CLI
  enablement, no filesystem write. `zelynic strict` remains the only validated
  active limiter path.
- **v3.0 phase 3 injected live reader backend + read boundary audit**: Extended
  `src/accounting/live_proc_net_dev.rs` with `ContentReader` trait for injecting
  content into the read seam, `InjectedContentReader` (returns injected content,
  simulates successful read), `FakeReadErrorReader` (simulates read failure),
  `read_live_proc_net_dev_with_injected_reader()` exercises full read → parse
  pipeline via injected reader distinguishing read errors ("read error:" prefix)
  from parse errors ("parse error:" prefix) in `read_status`, `read_live_proc_net_dev()`
  performs actual `std::fs::read_to_string` of `/proc/net/dev` (NOT called from CLI
  or unit tests, provided for future phase 4+), `LiveReadError` enum distinguishes
  `ReadFailed` from `ParseFailed` with Display impl, source-level boundary audit
  constants `FORBIDDEN_FS_WRITE_APIS` and `FORBIDDEN_PATHS` for verifying module
  source does not contain forbidden filesystem write APIs or sysfs/cgroup paths.
  `ContentReader` trait has no path parameter — source path is always `/proc/net/dev`
  (hardcoded). 36 new tests in `src/accounting/tests/live_proc_net_dev.rs` (total
  75): fake reader success parses sample content, fake reader failure returns read
  error, fake reader malformed content returns parse error, source path is exactly
  /proc/net/dev, injected reader source path is /proc/net/dev, arbitrary paths not
  accepted by injected reader, no sysfs/cgroup paths in module source (source-level
  audit), no filesystem write APIs in module source (source-level audit), rendered
  injected success/error/parse-error output includes read-only statement, rendered
  error output denies per-app attribution/quota enforcement/network blocking/
  limiter attach/nft-tc-state-mutation/ledger persistence/eBPF/cgroup mutation/
  PID movement, injected reader sets honest source label, injected reader success
  sets filesystem_read_performed=true, read error sets filesystem_read_performed=false,
  ContentReader trait has no path parameter (structural), tests do not read real
  /proc/net/dev (structural), LiveReadError display read-failed/parse-failed.
  No eBPF, no quota enforcement, no network blocking, no limiter attach, no
  nft/tc mutation, no state mutation, no filesystem persistence, no ledger file
  read/write, no PID move, no cgroup.procs write, no sysfs read, no CLI
  enablement, no filesystem write, no arbitrary path read. `zelynic strict`
  remains the only validated active limiter path.
- **v3.0 phase 3b live_proc_net_dev tests LOC split / maintainability refactor**:
  Refactored `src/accounting/tests/live_proc_net_dev.rs` (924 LOC, 75 tests)
  into a directory module with five focused files for maintainability:
  `tests/live_proc_net_dev/mod.rs` (shared imports, test data constants, module
  declarations), `tests/live_proc_net_dev/seam.rs` (phase 2 injected content
  parsing, read plan, loopback detection, large counter tests — 17 tests),
  `tests/live_proc_net_dev/injected_reader.rs` (phase 3 fake reader backend,
  source path, reader flags, LiveReadError display, structural no-path/real-read
  tests — 16 tests), `tests/live_proc_net_dev/render.rs` (all render output
  honesty disclaimer, mutation flag, snapshot summary, determinism, error plan,
  injected-reader and read-error honesty tests — 38 tests),
  `tests/live_proc_net_dev/boundary_audit.rs` (structural/safety boundary tests:
  no CLI command, no filesystem write APIs, source-level sysfs/cgroup/FS write
  audit — 4 tests). Preserved all 75 live_proc_net_dev tests with identical
  behavior. Accounting test count remains 331. Unit test count remains 976.
  No live reader behavior changes, no parser behavior changes, no renderer
  behavior changes, no output wording changes, no public API changes, no CLI
  exposure. All files under 1000 LOC. Refactor/split only. No eBPF, no quota
  enforcement, no network blocking, no limiter attach, no nft/tc mutation, no
  state mutation, no filesystem persistence, no ledger file read/write, no PID
  move, no cgroup.procs write, no sysfs read, no CLI enablement, no filesystem
  write, no arbitrary path read. `zelynic strict` remains the only validated
  active limiter path.
- **v3.0 phase 4 `zelynic usage --sample` CLI gate design**: Produced design/gate
  document (`docs/v3.0-phase-4-usage-sample-cli-gate.md`) defining the activation
  criteria and contract for the future `zelynic usage --sample` command. Defined
  9 activation gates that must be satisfied before CLI registration: phase
  completion, reader seam integrity, no arbitrary path input, output honesty (13
  required disclaimers), no enforcement/blocking/persistence claims, no background
  loop, no JSON until phase 5, manual smoke review, clap integration pattern.
  Defined future implementation plan (4 steps: add Commands variant, add
  dispatch handler, wire into dispatch, validate). Defined relationship to
  existing architecture (reader seam reuse, output contract reuse, distinction
  from `zelynic list --live`). Phase 4 is design-only: no Rust code changes,
  no test additions, no CLI command registration, no live system reads, no
  filesystem writes. No eBPF, no quota enforcement, no network blocking, no
  limiter attach, no nft/tc mutation, no state mutation, no filesystem
  persistence, no ledger file read/write, no PID move, no cgroup.procs write,
  no sysfs read, no CLI enablement, no filesystem write, no arbitrary path
  read. `zelynic strict` remains the only validated active limiter path.
- **v3.0 phase 5 `zelynic usage --sample` read-only single-shot CLI**: Implemented
  the `zelynic usage --sample` command that reads `/proc/net/dev` exactly once,
  parses with the existing reader seam, and renders an honest read-only usage
  preview. Added `Usage { sample: bool }` variant to `Commands` enum in
  `src/cli.rs` with `--sample` as a required flag (clap enforces: `zelynic
  usage` without `--sample` is rejected). Created `src/commands/usage.rs` handler:
  `handle_usage_sample()` calls `read_live_proc_net_dev()` for the single live
  filesystem read, `render_usage_plan()` wraps `render_live_proc_net_dev_read_plan()`
  with CLI prefix; test-only `handle_usage_sample_with_reader()` accepts
  `&dyn ContentReader` for injected reader testing. Wired dispatch in
  `src/commands/mod.rs`. Source path hardcoded to `/proc/net/dev` — no arbitrary
  path input accepted. Output includes all 13 honesty disclaimers: read-only
  /proc/net/dev seam, interface-level only (not per-app attribution), no quota
  enforcement active, no network blocking active, no limiter attach performed,
  no nft/tc/Zelynic state mutation performed, no ledger persistence performed,
  no eBPF used, no cgroup mutation, no PID movement, counters may reset after
  reboot/interface reset, filesystem write not performed, state mutation not
  performed. 25 new tests (3 CLI parse in `src/cli/tests.rs` + 22 handler
  output in `src/commands/usage.rs`): usage_sample_parses, usage_requires_
  sample_flag, usage_help_mentions_sample, fake reader success/read error/parse
  error renders, output includes interface-level only, output denies per-app
  attribution/quota enforcement/network blocking/limiter attach/nft-tc-state-
  mutation/ledger persistence/eBPF/cgroup mutation/PID movement, error output
  includes honesty disclaimers, no-sample handler, no arbitrary path argument,
  output includes source path, counters may reset warning, read-only seam
  statement. All files under 1000 LOC. No eBPF, no quota enforcement, no
  network blocking, no limiter attach, no nft/tc mutation, no state mutation, no
  filesystem persistence, no ledger file read/write, no PID move, no
  cgroup.procs write, no sysfs read, no filesystem write, no arbitrary path
  read, no loop/watch, no JSON output, no delta sampling. Only allowed live
  filesystem read is `/proc/net/dev`. CLI is single-shot only. `zelynic strict`
  remains the only validated active limiter path.
- **v3.0 phase 5b `usage --sample` live CLI validation / output honesty freeze**:
  Produced validation freeze document
  (`docs/v3.0-phase-5b-usage-sample-validation-freeze.md`) freezing the first
  live read-only CLI command before adding JSON, delta sampling, filtering,
  or persistence. Summarized all phases 1-5: design, reader seam, injected
  reader backend, tests split, CLI gate, actual CLI implementation. Documented
  current validation state: usage 52 tests, live_proc_net_dev 75 tests,
  accounting 331 tests, unit 998 tests, integration 4 passed / 5 ignored,
  check-all passed, LOC policy passed. Documented live CLI behavior proof:
  `zelynic usage` without `--sample` rejected by clap (no silent read),
  `--sample` performs one read of `/proc/net/dev`, command exits after one
  sample, no loop/watch, no arbitrary path input, no sysfs read, no ledger
  persistence, no state mutation, no enforcement/blocking. Documented output
  honesty proof: all 13 required honesty disclaimers verified by handler and
  render tests, error output includes all denial disclaimers. Added 3 optional
  phase 5b tests in `src/commands/usage.rs`: `rendered_output_contains_all_
  honesty_lines` (14-line sweep verifying all honesty disclaimers in success
  output), `error_output_contains_all_honesty_lines` (14-line sweep
  verifying all honesty disclaimers in error output), `no_json_delta_interval_
  flags_on_usage_command` (structural test verifying --json, --delta,
  --interval, --interface are all rejected by clap on the usage subcommand).
  Updated docs: lab doc (phase 5 completed, phase 5b current/freeze), phase 4
  gate doc (phase 5b freeze note), CHANGELOG. Phase 5b is validation freeze:
  no new features, no JSON, no delta sampling, no loop/watch, no interface
  filtering, no persistence. Freeze criteria defined for future phase entry.
  No eBPF, no quota enforcement, no network blocking, no limiter attach, no
  nft/tc mutation, no state mutation, no filesystem persistence, no ledger
  file read/write, no PID move, no cgroup.procs write, no sysfs read, no
  filesystem writes, no arbitrary path reads. Only allowed live filesystem
  read is `/proc/net/dev`. CLI remains single-shot only. `zelynic strict`
  remains the only validated active limiter path.
- **v3.0 phase 6 JSON output contract design**: Produced design document
  (`docs/v3.0-phase-6-usage-json-output-contract.md`) defining the JSON output
  schema for future `zelynic usage --sample --json`. Schema defines: schema_version
  (integer, currently 1), command ("usage --sample --json"), source_path
  ("/proc/net/dev"), source_label ("live_proc_net_dev"), sampled_at (string or
  null, caller-provided only, no silent wall-clock timestamp generation),
  interfaces array (per-interface: name, rx_bytes, tx_bytes, combined_bytes,
  rx_packets, tx_packets, loopback), totals (total_rx_bytes, total_tx_bytes,
  total_combined_bytes, interface_count), honesty object (12 boolean flags:
  interface_level_only=true, per_app_attribution=false, quota_enforcement_active=
  false, network_blocking_active=false, limiter_attach_performed=false, nft_tc_
  state_mutation_performed=false, ledger_persistence_performed=false, ebpf_used=
  false, cgroup_mutation_performed=false, pid_movement_performed=false, filesystem_
  write_performed=false, state_mutation_performed=false), warnings array
  (counters may reset, not per-app attribution). Error JSON contract: read_error,
  parse_error, unsupported_flag_error -- all errors retain full honesty flags and
  warnings, errors must not claim partial enforcement or mutation, error object
  mutually exclusive with interface data. CLI behavior contract: --json requires
  --sample (--json without --sample must not read /proc/net/dev), single-shot
  only (no loop/watch/delta/interval), no arbitrary path, no interface filtering
  in v3.0. Honesty disclaimer count standardized to 13 lines (matching render
  function comment; one line contains two substrings checked separately in
  tests). Implementation plan: phase 7 pure JSON model + serialization tests,
  phase 8 wire --json flag, phase 9 JSON validation/freeze, future phase delta
  sampling design. Updated docs: lab doc (phase 5b completed, phase 6 current/
  design, phase plan extended to phases 7-11), phase 5b freeze doc (note pointing
  to phase 6), phase 4 gate doc (note pointing to phase 6), CHANGELOG. Phase 6
  is design-only: no Rust code changes, no test additions, no CLI flag
  registration, no JSON serialization, no runtime behavior changes. No eBPF,
  no quota enforcement, no network blocking, no limiter attach, no nft/tc
  mutation, no state mutation, no filesystem persistence, no ledger file
  read/write, no PID move, no cgroup.procs write, no sysfs read, no filesystem
  writes, no arbitrary path reads. Only allowed live filesystem read is
  `/proc/net/dev`. CLI remains single-shot only. `zelynic strict` remains the
  only validated active limiter path.
- **v3.0 phase 7 pure JSON model + serialization tests**: Added
  `src/accounting/usage_json.rs` (318 LOC) with pure Rust data model and
  serde serialization for the JSON output schema defined in the phase 6 contract.
  Model types: `UsageJsonOutput` (top-level with schema_version, command, source_path,
  source_label, sampled_at via skip_serializing_if, interfaces array, optional
  error, totals, honesty flags, warnings), `UsageJsonInterface` (per-interface:
  name, rx/tx bytes, combined_bytes, rx/tx packets, loopback), `UsageJsonTotals`
  (total_rx/tx/combined_bytes, interface_count), `UsageJsonHonesty` (12 constant
  boolean flags: interface_level_only=true, per_app_attribution=false,
  quota_enforcement_active=false, network_blocking_active=false, limiter_attach_
  performed=false, nft_tc_state_mutation_performed=false, ledger_persistence_
  performed=false, ebpf_used=false, cgroup_mutation_performed=false, pid_movement_
  performed=false, filesystem_write_performed=false, state_mutation_performed=
  false), `UsageJsonError` (type + message), `UsageJsonErrorType` (Read/Parse/
  UnsupportedFlag with serde rename to snake_case). Pure functions:
  `build_usage_json_from_snapshot()` builds from InterfaceCounterSnapshot with
  optional sampled_at (caller-provided only, no silent timestamp generation),
  `build_usage_json_error()` builds error JSON with empty interfaces, zero totals,
  and full honesty flags preserved, `serialize_usage_json()` deterministic pretty
  JSON, `deserialize_usage_json()` for round-trip testing. 41 tests in
  `src/accounting/tests/usage_json.rs` (602 LOC): single/multi-interface builds,
  totals correctness, source path/label, schema version, command, sampled_at omit/
  include, no silent timestamp, all 12 honesty flags, default honesty constants,
  warnings, serialize success/read error/parse error/unsupported flag error,
  round-trip success/error, error preserves all honesty flags, empty interfaces
  on error, empty snapshot, loopback flag, u64::MAX counters with saturating
  combined bytes, determinism, no CLI flag structural, no live read structural,
  no filesystem write structural, deserialize rejects malformed/missing fields,
  serialized JSON includes all 12 honesty flags in both success and error outputs,
  error type display, default warnings count, sampled_at skip_serializing_if. No
  new dependencies (serde/serde_json already present). No CLI flag registration.
  No `--json` in clap. Module registered in `src/accounting/mod.rs` and
  `src/accounting/tests/mod.rs`. Updated docs: lab doc (phase 6 completed, phase 7
  current), phase 6 contract doc (phase 7 implementation note), CHANGELOG. No eBPF,
  no quota enforcement, no network blocking, no limiter attach, no nft/tc mutation,
  no state mutation, no filesystem persistence, no ledger file read/write, no PID
  move, no cgroup.procs write, no sysfs read, no filesystem writes, no arbitrary
  path reads, no delta sampling, no loop/watch. Only allowed live filesystem
  read is `/proc/net/dev`. CLI remains single-shot only. `zelynic strict` remains
  the only validated active limiter path.
- **v3.0 phase 7b JSON model validation / error-type contract freeze**:
  Validation/documentation-only phase confirming the pure JSON output model from
  phase 7 before wiring `--json` to CLI in phase 8. Verified canonical error type
  strings via code inspection and existing tests: `read_error` (via
  `#[serde(rename = "read_error")]`), `parse_error` (via
  `#[serde(rename = "parse_error")]`), `unsupported_flag_error` (via
  `#[serde(rename = "unsupported_flag_error")]`). Clarified documentation
  ambiguity about serde rename behavior: the `UsageJsonErrorType` enum uses
  explicit rename attributes, not automatic snake_case conversion. Confirmed all 12
  honesty flags are constant in v3.0. Confirmed `sampled_at` policy: omitted when
  None (via `skip_serializing_if`), never silently generated. Produced freeze
  document (`docs/v3.0-phase-7b-usage-json-validation-freeze.md`) summarizing
  phase 6 JSON contract design, phase 7 pure JSON model, canonical error type
  strings, 12 honesty boolean flags, sampled_at policy, and freeze criteria for
  phase 8 entry. Updated docs: lab doc (phase 7 completed, phase 7b current/
  freeze), phase 6 contract doc (canonical error type string clarification),
  CHANGELOG. No Rust behavior changes. No new tests. No new code. No `--json`
  CLI flag enabled. No eBPF, no quota enforcement, no network blocking, no limiter
  attach, no nft/tc mutation, no state mutation, no filesystem persistence, no
  ledger file read/write, no PID move, no cgroup.procs write, no sysfs read, no
  filesystem writes, no arbitrary path reads, no delta sampling, no loop/watch.
  Only allowed live filesystem read is `/proc/net/dev`. CLI remains single-shot
  only. `zelynic strict` remains the only validated active limiter path.
- **v3.0 phase 8 wire `usage --sample --json` CLI**: Wired the `--json` flag to the
  `zelynic usage --sample` command for machine-readable JSON output. Added `json: bool`
  flag to `Usage` variant in `src/cli.rs` with `requires = "sample"` (clap rejects
  `--json` without `--sample`). Added `handle_usage_sample(json: bool)` in
  `src/commands/usage.rs` that routes to text or JSON output; `build_json_from_plan()`
  converts `LiveProcNetDevReadPlan` to `UsageJsonOutput` using existing `build_usage_
  json_from_snapshot()` for success and `build_usage_json_error()` for read/parse errors.
  JSON output is printed to stdout only, no human text prefix/suffix. `sampled_at` is
  omitted (None, no silent wall-clock generation). Single-shot only: one read, one
  parse, one JSON output, exit. Text output (`usage --sample`) unchanged — all 13
  honesty lines remain present. 13 new tests in `src/commands/usage.rs`: CLI parse
  `usage --sample --json`, CLI rejects `--json` without `--sample`, no delta/interval/
  interface/watch/path flags, JSON success with fake reader (schema_version, command,
  source_path, source_label, sampled_at omitted, error null, interfaces, totals,
  interface_count), JSON success includes source_path/source_label, JSON success omits
  sampled_at, JSON success includes all 12 honesty flags, JSON read error uses
  `"read_error"`, JSON read error preserves honesty flags, JSON parse error uses
  `"parse_error"`, text output unchanged, CLI remains single-shot, no arbitrary path
  in JSON mode. Updated `src/commands/mod.rs` dispatch and `src/cli/tests.rs` parse
  test. Test counts: usage 109 (was 96, +13), unit 1055 (was 1042, +13). All files
  under 1000 LOC. No eBPF, no quota enforcement, no network blocking, no limiter
  attach, no nft/tc mutation, no state mutation, no filesystem persistence, no ledger
  file read/write, no PID move, no cgroup.procs write, no sysfs read, no filesystem
  writes, no arbitrary path reads, no delta sampling, no loop/watch. Only allowed
  live filesystem read is `/proc/net/dev`. CLI remains single-shot only. `zelynic
  strict` remains the only validated active limiter path.
- **v3.0 phase 8b `usage --sample --json` CLI validation freeze / contract audit**:
  Validation/documentation phase freezing and auditing the first machine-readable
  CLI output before adding delta sampling, filters, persistence, or any future
  automation. Summarized phases 6-8: JSON output contract design (schema_version,
  command, source_path, source_label, sampled_at policy, 12 honesty flags, error
  types read_error/parse_error/unsupported_flag_error, warnings array), pure JSON
  model + serialization tests, JSON model validation / error-type contract freeze,
  `--json` CLI wiring (single-shot, JSON only, no human prefix/suffix, --json
  requires --sample). Documented JSON CLI behavior proof: reads `/proc/net/dev`
  exactly once, prints JSON only, exits after one sample, no loop/watch, no
  delta/interval, no interface filter, no arbitrary path input, no sysfs read, no
  ledger persistence, no state mutation, no enforcement/blocking. Documented JSON
  schema proof: all fields verified by tests (schema_version=1, command="usage
  --sample --json", source_path="/proc/net/dev", source_label="live_proc_net_dev",
  sampled_at omitted, interfaces/totals/honesty/warnings present, error payloads use
  canonical error_type strings). Added 5 optional phase 8b tests in
  `src/commands/usage.rs`: `json_output_starts_with_brace`, `json_output_contains_
  no_human_header`, `json_output_contains_warnings_array`, `json_error_output_starts_
  with_brace`, `json_error_output_contains_no_human_header`. Updated docs: lab doc
  (phase 8 completed, phase 8b current/freeze), phase 6 contract doc (phase 8b
  freezes CLI JSON contract note), phase 7b freeze doc (phase 8b confirms CLI wiring
  note), CHANGELOG. Phase 8b is validation freeze: no new features, no delta
  sampling, no loop/watch, no interface filtering, no persistence. No eBPF, no
  quota enforcement, no network blocking, no limiter attach, no nft/tc mutation,
  no state mutation, no filesystem persistence, no ledger file read/write, no PID
  move, no cgroup.procs write, no sysfs read, no filesystem writes, no arbitrary
  path reads, no delta sampling, no loop/watch. Only allowed live filesystem read
  is `/proc/net/dev`. CLI remains single-shot only. `zelynic strict` remains the
  only validated active limiter path.
- **v3.0 phase 9 delta sampling design for `usage --sample --delta`**: Produced
  design document (`docs/v3.0-phase-9-usage-delta-sampling-design.md`) defining
  the future delta sampling behavior for `zelynic usage --sample --delta`. Defines
  two-sample protocol: first sample reads `/proc/net/dev` exactly once, explicit
  wait duration (future `--interval` flag required), second sample reads
  `/proc/net/dev` exactly once, delta computation via existing `session_delta`
  model from v2.9 (`build_session_delta()`). Defines sampling rules: no silent
  underflow (counter reset → delta=0 with warning), no background loop, no
  daemon, no state persistence, interface-level only, not per-app attribution,
  no quota enforcement, no network blocking, no eBPF, no cgroup mutation, no PID
  movement. Defines future command shape: `zelynic usage --sample --delta`,
  optional future `--interval 5s`, optional future `--json`, no watch/loop mode,
  no arbitrary path, no interface filter. Defines output honesty requirements:
  all 13 existing disclaimers retained, plus delta-specific counter reset
  warnings and incomplete delta acknowledgment. Defines JSON delta contract
  direction: reuse existing 12 honesty boolean flags, add `delta` section only in
  future phase with start/end source labels, interval_seconds (optional), delta
  interfaces (rx_delta_bytes, tx_delta_bytes, combined_delta_bytes,
  rx_delta_packets, tx_delta_packets, reset flags, present_in_start/end),
  delta totals, delta warnings array. Defines phase plan: phase 9 design only,
  phase 10 pure delta output model + render tests, phase 11 CLI gate for
  `--delta`, phase 12 single-shot two-sample delta implementation, phase 13
  delta JSON contract/wiring, phase 14 validation freeze. Updated docs: lab doc
  (phase 8b completed, phase 9 current/design), phase 8b freeze doc (note pointing
  to phase 9 delta design), CHANGELOG. Phase 9 is design-only: no Rust code
  changes, no CLI flag registration, no JSON schema changes, no test additions, no
  runtime behavior changes. No eBPF, no quota enforcement, no network blocking,
  no limiter attach, no nft/tc mutation, no state mutation, no filesystem
  persistence, no ledger file read/write, no PID move, no cgroup.procs write, no
  sysfs read, no filesystem writes, no arbitrary path reads, no delta CLI flag, no
  interval sampling, no loop/watch. Only allowed live filesystem read is
  `/proc/net/dev`. CLI remains single-shot only. `zelynic strict` remains the
  only validated active limiter path.
- **v3.0 phase 10 pure delta output model + render tests**: Added
  `src/accounting/usage_delta.rs` (284 LOC) with pure Rust model and renderer
  for future `zelynic usage --sample --delta` output. Model types:
  `UsageDeltaOutput` (schema_source_label, start/end source labels, per-interface
  delta rows, total_rx_delta_bytes, total_tx_delta_bytes,
  total_combined_delta_bytes, interface_count, warnings array, warning_count),
  `UsageDeltaRow` (interface name, rx/tx/combined delta bytes, human-readable
  formatting via IEC binary prefixes, has_reset flag). Pure functions:
  `build_usage_delta_from_session_delta()` transforms existing `SessionDelta`
  into display-oriented `UsageDeltaOutput`, `render_usage_delta()` renders
  human-readable output with 14 safety disclaimers (future delta output model
  only, no CLI flag enabled yet, no live second sample was taken by this
  model, interface-level only/not per-app attribution, no quota enforcement
  active, no network blocking active, no limiter attach performed, no nft/tc
  /Zelynic state mutation performed, no ledger persistence performed, no eBPF
  used, no cgroup mutation performed, no PID movement performed, filesystem
  write not performed, state mutation not performed, counters may reset after
  reboot or interface reset). Render also includes delta-specific counter
  reset/decrease warnings from `CounterResetWarning` and delta may be
  incomplete warning when resets detected. 33 tests in
  `src/accounting/tests/usage_delta.rs` (487 LOC): builds delta output from
  simple session_delta, totals rx/tx/combined correctly, handles empty delta,
  handles interface added/removed, handles counter reset/decrease warnings,
  render includes future-model-only statement, render says CLI flag not
  enabled yet, render says no live second sample taken by this model, render
  denies per-app attribution/quota enforcement/network blocking/limiter attach/
  nft-tc-state-mutation/ledger persistence/eBPF/cgroup mutation/PID movement/
  filesystem write/state mutation, no CLI flag added structural, no live
  /proc read in tests structural, no filesystem write APIs structural,
  render includes counter reset warnings, render includes delta incomplete
  warning on reset, render includes counters may reset disclaimer, render shows
  interface-level only, human-readable formatting works, zero delta produces
  zero human-readable, render determinism, build determinism, source label is
  model-only, has_reset flag reflects session_delta. Module registered in
  `src/accounting/mod.rs` and `src/accounting/tests/mod.rs`. Updated docs: lab
  doc (phase 9 completed, phase 10 current), phase 9 design doc (phase 10
  implementation note), CHANGELOG. No CLI flag registration. No `--delta` in
  clap. No interval sampling. No loop/watch mode. No interface filtering. No
  persistence. No eBPF, no quota enforcement, no network blocking, no limiter
  attach, no nft/tc mutation, no state mutation, no filesystem persistence,
  no ledger file read/write, no PID move, no cgroup.procs write, no sysfs
  read, no filesystem writes, no arbitrary path reads. Only allowed live
  filesystem read is `/proc/net/dev`. CLI remains single-shot only. All files
  under 1000 LOC. `zelynic strict` remains the only validated active limiter
  path.

- **v3.0 phase 11 `--delta` CLI gate design / blocked flag contract**:
  Produced design/gate document (`docs/v3.0-phase-11-usage-delta-cli-gate.md`)
  defining the CLI gate and activation rules for future
  `zelynic usage --sample --delta`. Defined future command contract
  (`zelynic usage --sample --delta` text output, `zelynic usage --sample
  --delta --json` JSON combo). Defined absolute constraints: interface-level
  only, no per-app attribution, no quota enforcement, no network blocking,
  no persistence, no eBPF, no nft/tc mutation, no cgroup/PID mutation, no
  loop/watch, no arbitrary path, no filesystem write, read-only. Defined
  delta-specific constraints: exactly two reads, bounded wait, no background
  loop, no daemon behavior, counter reset handling, single-shot. Defined 12
  activation gates (phase completion, two-read behavior reviewed, reader seam
  integrity, no arbitrary path input, output honesty verified, no
  enforcement/blocking/persistence claims, no background loop, reset/decrease
  handling reviewed, text output reviewed, JSON output contract reviewed,
  tests prove no persistence/enforcement claims, manual smoke output reviewed).
  Defined initial CLI behavior: preferred docs-only (no `--delta` flag
  registered), hard-blocked flag as fallback (rejected before any I/O).
  Defined that `usage --delta` without `--sample` must not read
  `/proc/net/dev`, `usage --sample --delta --json` must not be enabled until
  phase 13, `--interval` remains unavailable until a future explicit phase.
  Updated docs: lab doc (phase 10 completed, phase 11 current), phase 9
  design doc (phase 11 CLI gate note), CHANGELOG. Phase 11 is design-only: no
  Rust code changes, no CLI flag registration, no live system reads, no
  filesystem writes, no new tests, no new dependencies. No eBPF, no quota
  enforcement, no network blocking, no limiter attach, no nft/tc mutation,
  no state mutation, no filesystem persistence, no ledger file read/write, no
  PID move, no cgroup.procs write, no sysfs read, no filesystem writes, no
  arbitrary path reads. Only allowed live filesystem read is `/proc/net/dev`.
  CLI remains single-shot only. `zelynic strict` remains the only validated
  active limiter path.
- **v3.0 phase 12 `usage --sample --delta` two-sample read-only delta CLI**: Implemented
  actual two-sample read-only delta behavior for `zelynic usage --sample --delta`.
  Added `--delta` flag to `Usage` variant in `src/cli.rs` with `requires = "sample"`
  (clap rejects `--delta` without `--sample`). Created `src/commands/usage_delta.rs`
  (delta handler module, ~820 LOC): `handle_usage_delta()` reads `/proc/net/dev`
  exactly twice via existing `read_live_proc_net_dev()`, waits a bounded default
  duration (1 second) between samples, computes per-interface deltas using existing
  `build_session_delta()` and `UsageDeltaOutput` model from phase 10, renders live
  delta text output with 16 safety disclaimers, and exits. `render_usage_delta_live()`
  replaces phase-10 model-only renderer with live-appropriate text. `--delta --json`
  combination is rejected before any live read (delta JSON deferred to phase 13).
  Existing `usage --sample` text and `usage --sample --json` unchanged. Added test
  infrastructure for injected two-sample delta: `DualSampleReader` trait (fake
  readers for both samples), `SampleSleeper` trait (fake sleeper that counts calls
  without sleeping), `CountingReader` (verifies exactly two reads), `CountingSleeper`
  (verifies exactly one sleep), `FakeDualReader/FakeFailFirstReader/FakeFailSecondReader/
  FakeParseFailFirstReader/FakeParseFailSecondReader` (error injection). 32 new tests
  in `src/commands/usage_delta.rs`: CLI parse `--sample --delta`, CLI rejects `--delta`
  without `--sample`, CLI accepts `--delta --json` (handler rejects), fake reader
  success renders delta output, fake reader called exactly twice, fake sleeper called
  exactly once, read failure on first/second sample reported honestly, parse failure
  on first/second sample reported honestly, counter reset/decrease warning appears,
  output includes interface-level only, output denies per-app attribution/quota
  enforcement/network blocking/limiter attach/nft-tc-state-mutation/ledger
  persistence/eBPF/cgroup mutation/PID movement/filesystem write/state mutation,
  no arbitrary path argument, no loop/watch/interval flags, output includes source
  path, two-sample statement, counters may reset, delta incomplete on reset, all 16
  honesty lines sweep, delta totals correctness, render determinism. Updated tests
  in `src/commands/usage.rs`: removed `--delta` rejection assertion (now accepted),
  updated `cli_remains_single_shot` and `cli_parses_usage_sample_json` for new
  `delta` field. Updated `src/cli/tests.rs` for new `delta` field. Updated
  `src/commands/mod.rs` with `usage_delta` module and delta dispatch. Test counts:
  usage_delta 65 (was 33, +32), usage 179 (was 147, +32), accounting 405 (unchanged),
  unit 1125 (was 1093, +32), integration 4/5, check-all passed. All files under
  1000 LOC. No eBPF, no quota enforcement, no network blocking, no limiter attach,
  no nft/tc mutation, no state mutation, no filesystem persistence, no ledger file
  read/write, no PID move, no cgroup.procs write, no sysfs read, no filesystem
  writes, no arbitrary path reads. Only allowed live filesystem read is
  `/proc/net/dev`. CLI remains finite and single-shot. `zelynic strict` remains
  the only validated active limiter path.
- **v3.0 phase 12b usage delta validation freeze + LOC split / maintainability
  refactor**: Validation/documentation phase freezing and auditing the first
  two-sample delta CLI implementation before adding delta JSON output (phase 13).
  Produced freeze document (`docs/v3.0-phase-12b-usage-delta-validation-freeze.md`)
  summarizing phases 9-12 delta design, model, CLI gate, and implementation; current
  validation state (usage_delta 65 tests, usage 179 tests, live_proc_net_dev 75 tests,
  accounting 405 tests, unit 1125 tests, integration 4/5, check-all passed); delta
  CLI behavior proof (reads /proc/net/dev exactly twice, bounded 1s wait, exits after
  second sample, no loop/watch/interval, no interface filter, no arbitrary path,
  --delta --json rejected, --delta without --sample rejected by clap). Refactored
  `src/commands/usage_delta.rs` (~920 LOC, single file) into a directory module
  with four focused files: `usage_delta/mod.rs` (module doc, submodule declarations,
  re-exports), `usage_delta/handler.rs` (handle_usage_delta, run_delta_live,
  extract_snapshot_from_plan), `usage_delta/render.rs` (render_usage_delta_live
  with 16 safety disclaimers), `usage_delta/tests.rs` (test infrastructure:
  DualSampleReader/SampleSleeper traits, fake readers, counting sleeper/reader,
  run_delta_with_deps + 32 test functions). All 65 usage_delta tests preserved
  with identical behavior and assertions. No output wording changes, no runtime
  behavior changes, no new tests, no new dependencies, no new CLI flags. All
  files under 1000 LOC with comfortable margin for phase 13 work. Updated docs:
  lab doc (phase 12 completed, phase 12b current/freeze), phase 11 gate doc
  (phase 12b implementation frozen before JSON delta note), phase 9 design doc
  (phase 12b validates before JSON delta note), CHANGELOG. Phase 12b is
  validation freeze + refactor/split only: no delta JSON output, no configurable
  interval, no loop/watch mode, no daemon/background behavior, no interface
  filtering, no persistence, no ledger file read/write, no eBPF, no quota
  enforcement, no network blocking, no limiter attach, no nft/tc mutation,
  no state mutation, no PID move, no cgroup.procs write, no sysfs read, no
  filesystem writes, no arbitrary path reads. Only allowed live filesystem
  read is `/proc/net/dev`. CLI remains finite and single-shot. `zelynic strict`
  remains the only validated active limiter path.
- **v3.0 phase 13 delta JSON output contract design**: Design-only phase defining
  the machine-readable JSON schema for future `zelynic usage --sample --delta
  --json`. Produced design document
  (`docs/v3.0-phase-13-usage-delta-json-output-contract.md`) with complete
  schema specification. Defines top-level JSON shape: schema_version (integer,
  currently 1), command ("usage --sample --delta --json"), source_path
  ("/proc/net/dev"), source_label ("live_proc_net_dev"), sample_mode ("delta"),
  sample_count (2), delta_wait_ms (1000), read_count (0/1/2), start_sample
  (summary object or null), end_sample (summary object or null), interfaces
  (per-interface delta array), totals (delta totals with reset/added/removed
  counts), warnings (12 default warnings plus conditional counter reset
  warnings), honesty (19 boolean flags). Defines timestamp policy: timestamps
  intentionally omitted from start_sample/end_sample; no silent wall-clock
  generation; delta_wait_ms provides deterministic gap information. Defines
  per-interface delta object: name, loopback, start_rx_bytes, start_tx_bytes,
  end_rx_bytes, end_tx_bytes, delta_rx_bytes, delta_tx_bytes,
  delta_combined_bytes, start_rx_packets, start_tx_packets, end_rx_packets,
  end_tx_packets, delta_rx_packets, delta_tx_packets, counter_reset_detected,
  interface_added, interface_removed. Defines totals:
  total_delta_rx_bytes, total_delta_tx_bytes, total_delta_combined_bytes,
  interface_count, loopback_interface_count, non_loopback_interface_count,
  counter_reset_count, interface_added_count, interface_removed_count. Defines
  19 honesty flags: 12 constant false (per_app_attribution,
  quota_enforcement_active, network_blocking_active, limiter_attach_performed,
  nft_tc_state_mutation_performed, ledger_persistence_performed, ebpf_used,
  cgroup_mutation_performed, pid_movement_performed, filesystem_write_performed,
  state_mutation_performed, loop_watch_mode, configurable_interval,
  interface_filtering, arbitrary_path_read), 2 constant true
  (interface_level_only, single_shot, delta_json_output), 3 dynamic
  (live_read_performed, read_count). Defines error JSON shape: read_error,
  parse_error, unsupported_flag_error; error payload preserves all honesty flags;
  precise read_count/sample_count behavior for first-read failure (read_count=0,
  live_read_performed=false) vs second-read failure (read_count=1,
  live_read_performed=true). Includes sample success JSON, sample error JSON
  (second read failure, parse failure), sample counter reset warning success
  JSON. Defines relationship to existing snapshot JSON contract. Phase 13 is
  design-only: no Rust code changes, no CLI flag registration, no JSON
  serialization, no runtime behavior changes, no test additions, no new
  dependencies, no implementation of --delta --json, no CLI behavior change, no
  configurable interval, no loop/watch, no daemon, no interface filtering, no
  persistence, no ledger, no eBPF, no quota enforcement, no network blocking,
  no limiter attach, no nft/tc mutation, no state mutation, no PID movement, no
  cgroup.procs write, no sysfs read, no filesystem write, no arbitrary path
  read. Updated docs: lab doc (phase 12b completed, phase 13 current/design),
  phase 12b freeze doc (note that phase 13 designs future delta JSON output only),
  phase 9 design doc (note that JSON contract is being designed after text delta
  freeze), CHANGELOG. No eBPF, no quota enforcement, no network blocking, no
  limiter attach, no nft/tc mutation, no state mutation, no filesystem
  persistence, no ledger file read/write, no PID move, no cgroup.procs write, no
  sysfs read, no filesystem writes, no arbitrary path reads. Only allowed live
  filesystem read is `/proc/net/dev`. CLI remains finite and single-shot.
  `zelynic strict` remains the only validated active limiter path.
- **v3.0 phase 15b usage delta JSON CLI validation freeze + release readiness audit**:
  Validation/documentation/audit phase freezing the newly public `usage --sample
  --delta --json` CLI behavior before any v3.0 release preparation. Produced freeze
  document (`docs/v3.0-phase-15b-usage-delta-json-cli-validation-freeze.md`)
  summarizing phase 13 contract design, phase 14 pure model/serialization, phase
  14b test split, phase 15 CLI wiring, local validation counts (1225+ tests),
  manual jq proof (schema_version=1, command="usage --sample --delta --json",
  sample_mode="delta", sample_count=2, read_count=2, error=null), CI green proof,
  safety boundary, and release readiness assessment. Added 2 cross-command isolation
  tests in `src/commands/usage_delta/tests_json.rs`:
  `delta_json_output_distinct_from_snapshot_json` (proves delta JSON has
  sample_mode=delta, delta_wait_ms, command=...--delta--json, sample_count=2,
  read_count=2, start/end sample objects), `delta_text_output_is_not_json` (proves
  delta text contains human header, does not start with `{`). Confirmed all 19
  required validation checks covered across 32 CLI-level tests and 66 pure model
  tests. Updated docs: lab doc (phase 15 completed, phase 15b current/freeze),
  phase 13 contract doc (phase 15b freezes public CLI behavior after wiring),
  phase 14b freeze doc (phase 15b validates release readiness after CLI wiring),
  CHANGELOG. No JSON schema change. No CLI behavior change. No runtime behavior
  change. No new CLI flags. No new dependencies. Test counts: usage_delta_json 66
  (unchanged), usage_delta 163 (was 161, +2), usage 277 (was 275, +2),
  accounting 471 (unchanged), unit 1227 (was 1225, +2). All files under 1000 LOC.
  No eBPF, no quota enforcement, no network blocking, no limiter attach, no nft/tc
  mutation, no state mutation, no filesystem persistence, no ledger file read/write,
  no PID move, no cgroup.procs write, no sysfs read, no filesystem writes, no
  arbitrary path reads. Only allowed live filesystem read is `/proc/net/dev`. CLI
  remains finite and single-shot. `zelynic strict` remains the only validated active
  limiter path.
- **v3.0 phase 14 pure delta JSON model + serialization tests**: Added
  `src/accounting/usage_delta_json.rs` with pure delta JSON output model for future
  `zelynic usage --sample --delta --json` (model-only, no CLI wiring). Top-level
  `UsageDeltaJsonOutput` with 14 fields: schema_version, command, source_path,
  source_label, sample_mode ("delta"), sample_count, delta_wait_ms (1000),
  read_count, start_sample (Option<DeltaJsonSampleSummary>), end_sample, interfaces
  (Vec<DeltaJsonInterface>), totals (DeltaJsonTotals), warnings (Vec<String>),
  honesty (DeltaJsonHonesty with 19 flags), error (Option<DeltaJsonError>).
  Per-interface `DeltaJsonInterface` with 19 fields: name, loopback,
  start_rx/tx_bytes, end_rx/tx_bytes, delta_rx/tx_bytes, delta_combined_bytes,
  start_rx/tx_packets, end_rx/tx_packets, delta_rx/tx_packets,
  counter_reset_detected, interface_added, interface_removed. `DeltaJsonTotals`
  with 9 fields: total_delta_rx/tx/combined_bytes, interface_count,
  loopback_interface_count, non_loopback_interface_count, counter_reset_count,
  interface_added_count, interface_removed_count. `DeltaJsonHonesty` with 19
  flags: 12 constant boolean from snapshot contract + 7 delta-specific
  (delta_json_output=true, live_read_performed, read_count u32, single_shot=true,
  loop_watch_mode=false, configurable_interval=false, interface_filtering=false,
  arbitrary_path_read=false). Builder functions: `build_delta_json_success` (from
  two InterfaceCounterSnapshot), `build_delta_json_first_read_error`
  (read_count=0, live_read_performed=false, sample_count=0),
  `build_delta_json_second_read_error` (read_count=1, live_read_performed=true,
  sample_count=1, start_sample populated), `build_delta_json_unsupported_flag_error`.
  Serialization: `serialize_delta_json`, `deserialize_delta_json` for deterministic
  pretty-printed round-trip. Added `src/accounting/tests/usage_delta_json.rs`
  with 60+ deterministic unit tests: normal delta success, interface names, start/end
  counter fields, delta bytes/packets computation, totals correctness, loopback/
  non-loopback counts, sample summaries, top-level fields (schema_version, command,
  source_path, source_label, sample_mode, sample_count, delta_wait_ms, read_count),
  counter reset detection, interface added/removed detection, all 19 honesty flags,
  default 13 warnings, first/second/unsupported flag error payloads, error honesty
  flag precision (read_count=0/1/2, live_read_performed), serialization JSON content
  verification, round-trip tests (success, error, counter reset), malformed JSON
  rejection, u64::MAX handling, saturating totals, determinism, zero delta, loopback
  flag, structural no-CLI/no-live-read tests, sample summaries in JSON, multiple
  counter resets on same interface. Updated `src/accounting/mod.rs` and
  `src/accounting/tests/mod.rs` to register the new module and re-export all public
  types/functions. No CLI flag registered. No JSON output wired to CLI. No live
  filesystem reads in tests. No new dependencies. No behavior changes. No eBPF, no
  quota enforcement, no network blocking, no limiter attach, no nft/tc mutation,
  no state mutation, no filesystem persistence, no ledger file read/write, no PID
  move, no cgroup.procs write, no sysfs read, no filesystem writes, no arbitrary
  path reads. Only allowed live filesystem read is `/proc/net/dev`. CLI remains
  finite and single-shot. `zelynic strict` remains the only validated active limiter
  path. Updated docs: lab doc (phase 13 completed, phase 14 current/model-only),
  phase 13 contract doc (phase 14 note), CHANGELOG.
- **v3.0 phase 15 wire `usage --sample --delta --json` CLI from frozen pure model**:
  Wired the frozen phase 14 pure delta JSON model to the CLI, enabling
  `zelynic usage --sample --delta --json` to produce machine-readable JSON output
  from two live `/proc/net/dev` reads. Changed `handle_usage_sample()` in
  `src/commands/usage.rs` to route `--delta --json` to the new
  `handle_usage_delta_json()` in `src/commands/usage_delta/handler.rs` instead of
  rejecting before any live read. Added `handle_usage_delta_json()`,
  `run_delta_live_json()`, and `classify_error()` in
  `src/commands/usage_delta/handler.rs`: performs exactly two reads of
  `/proc/net/dev`, one bounded sleep (1 second), produces valid JSON via frozen
  phase 14 model functions (`build_delta_json_success` for success,
  `build_delta_json_first_read_error` for first-read failure,
  `build_delta_json_second_read_error` for second-read failure). JSON output
  contains schema_version, command ("usage --sample --delta --json"), source_path,
  source_label, sample_mode, sample_count, delta_wait_ms, read_count,
  start_sample/end_sample summaries, interfaces array, totals, warnings, honesty
  (19 flags), and error object. Error JSON correctly classifies read errors vs parse
  errors, and second-read errors report read_count=1 with first sample summary.
  Added `run_delta_json_with_deps()` test injection function and
  `run_delta_json_first_error_deps()` in
  `src/commands/usage_delta/tests_json.rs` (new file). 30 new tests: CLI parse,
  JSON starts with brace, no human header, valid JSON parse, command/source_path/
  source_label/sample_count/read_count/error null verification, interfaces/totals/
  warnings/honesty present, reader called exactly twice, sleeper called exactly once,
  first/second read/parse error JSON structure (read_count, live_read_performed,
  start_sample/end_sample), no live read in tests, no filesystem write APIs,
  no arbitrary path, no interval/watch/interface/path flags, usage --delta still
  rejected by clap, sample_mode delta, delta_wait_ms, start/end sample present,
  error no human text, honesty delta_json_output/single_shot true, all 15 constant
  false flags, totals correctness. `usage --sample` text output unchanged.
  `usage --sample --json` output unchanged. `usage --sample --delta` text output
  unchanged. Updated docs: lab doc (phase 14b completed, phase 15 current),
  phase 13 contract doc (phase 15 implementation note), phase 14b freeze doc
  (phase 15 wires frozen model to CLI), CHANGELOG. Test counts: usage_delta_json
  66 (unchanged), usage_delta 161 (was 131, +30), usage 275 (was 245, +30),
  accounting 471 (unchanged), unit 1221 (was 1195, +26). All files under 1000
  LOC. No eBPF, no quota enforcement, no network blocking, no limiter attach,
  no nft/tc mutation, no state mutation, no filesystem persistence, no ledger file
  read/write, no PID move, no cgroup.procs write, no sysfs read, no filesystem
  writes, no arbitrary path reads. Only allowed live filesystem read is
  `/proc/net/dev`. CLI remains finite and single-shot. `zelynic strict` remains the
  only validated active limiter path.
- **v3.0 phase 14b usage delta JSON validation freeze + test split / maintainability
  refactor**: Validation/documentation/split phase freezing the pure delta JSON model
  and serialization tests from phase 14 before wiring `--delta --json` to CLI.
  Refactored `src/accounting/tests/usage_delta_json.rs` (973 LOC, 66 tests) into
  a directory module with six focused files for maintainability:
  `tests/usage_delta_json/mod.rs` (80 LOC, shared imports, sample data constants,
  parse helper, module declarations),
  `tests/usage_delta_json/success.rs` (489 LOC, 33 tests — success build,
  validation, counter reset, interface add/remove, empty snapshots, u64::MAX,
  saturating, determinism, serialization, round-trip, sample summaries),
  `tests/usage_delta_json/errors.rs` (197 LOC, 17 tests — first/second read error,
  unsupported flag, error warnings, serialization, round-trip error, deserialize
  rejection, error type display),
  `tests/usage_delta_json/warnings.rs` (56 LOC, 6 tests — default 13 warnings,
  counter reset warnings, delta incomplete, not-per-app),
  `tests/usage_delta_json/honesty.rs` (156 LOC, 7 tests — all 19 flags, default
  constants, first/second read error honesty, error preserves all flags, serialized
  JSON honesty),
  `tests/usage_delta_json/safety.rs` (32 LOC, 3 tests — no CLI flag, no live
  /proc/net/dev read, no filesystem write APIs). Preserved all 66 usage_delta_json
  tests with identical behavior. No runtime behavior changes, no model type changes,
  no serialization behavior changes, no output wording changes, no public API
  changes, no CLI exposure, no JSON schema changes. Produced freeze document
  (`docs/v3.0-phase-14b-usage-delta-json-validation-freeze.md`) summarizing phase
  13 contract design, phase 14 pure model/serialization implementation, current test
  counts, CLI still not wired, and why test split was needed. Updated docs: lab doc
  (phase 14 completed, phase 14b current/freeze), phase 13 contract doc (phase
  14/14b notes), CHANGELOG. No eBPF, no quota enforcement, no network blocking,
  no limiter attach, no nft/tc mutation, no state mutation, no filesystem
  persistence, no ledger file read/write, no PID move, no cgroup.procs write,
  no sysfs read, no filesystem writes, no arbitrary path reads. Only allowed live
  filesystem read is `/proc/net/dev`. CLI remains finite and single-shot. All
  files under 1000 LOC. Refactor/split only. `zelynic strict` remains the only
  validated active limiter path.

## [2.9.0] - 2026-06-07 - v2.9.0 Network Accounting Lab

v2.9.0 is a **read-only accounting foundation** release. It does NOT implement
actual filesystem persistence, does NOT read or write any ledger file from disk,
does NOT add a live usage CLI command, does NOT implement quota enforcement, does
NOT block any network traffic, does NOT implement eBPF, does NOT attach limiters
or mutate nftables/tc rules, does NOT move PIDs, does NOT write cgroup.procs,
does NOT touch /sys/fs/cgroup for accounting, and does NOT add any CLI command
for accounting or ledger operations. All v2.9 code is pure model and
serialization tests only. `zelynic strict` remains the only validated active
limiter path.

### Added

- **v2.9 Network Accounting Lab design**: Added design document
  (`docs/v2.9-network-accounting-lab.md`) for the v2.9 read-only accounting
  milestone. Phase 1 is design-only: defines data model, data sources
  (`/proc/net/dev`, sysfs, nftables counters, tc statistics), honesty
  constraints (interface counters are not per-app, PID attribution is
  snapshot-based, counter reset on reboot, read-only must not claim
  enforcement), future command surface (`zelynic usage`, `zelynic quota
  status`, `zelynic limit-background`), phase plan (6 phases), and future
  version roadmap (v3.x quota guard, v4.x eBPF observer). v2.9 is a
  read-only accounting milestone only — no enforcement, no blocking, no quota
  guard, no eBPF, no PID movement, no cgroup.procs write, no nft/tc
  mutation, no persistent state mutation, no CLI changes. `zelynic strict`
  remains the only validated active limiter path.
- **v2.9 phase 2 interface counter model + pure parser tests**: Added
  `src/accounting/` module with pure Rust types and parsers for
  `/proc/net/dev`-style content. Model types: `InterfaceCounter` (interface
  name, RX/TX bytes/packets), `InterfaceCounterSnapshot` (ordered list with
  source label), `ParseError` (structured error enum), `SourceLabel`
  (observational marker). Pure parser `parse_proc_net_dev(content: &str)`
  handles standard `/proc/net/dev` format with header skipping, interface name
  trimming, colon validation, field count validation, u64 parsing with overflow
  detection. Render helper `render_interface_counter_snapshot()` with honesty
  labels: "read-only parsed sample", "aggregate interface traffic, not per-app",
  "No enforcement", "No quota guard", "No per-app attribution". 53 pure unit
  tests: single/multiple interface parsing, header skipping, lo/wlan0/eth0/
  wlp/enp/usb0 name support, whitespace trimming, missing colon/too-few-fields/
  non-numeric/overflow/negative rejection, empty input handling, determinism,
  input order preservation, snapshot aggregation helpers, render output
  honesty verification, error display formatting, design contract verification.
  No CLI command, no live system reads, no filesystem access, no enforcement.
- **v2.9 phase 3 read-only usage preview renderer**: Added
  `src/accounting/usage_preview.rs` with pure model and renderer for the
  future `zelynic usage` command display contract. Model types:
  `UsagePreview` (total RX/TX/combined bytes, interface count, per-interface
  rows with human-readable IEC formatting, source label, attribution scope
  "interface-only", enforcement status "inactive/not implemented"),
  `UsagePreviewRow` (interface name, raw + human-readable RX/TX/total bytes,
  loopback flag). Pure functions: `build_usage_preview(snapshot)` with
  saturating arithmetic, `render_usage_preview(preview)` with comprehensive
  safety disclaimers (read-only, interface-level only, not per-app, no quota
  enforcement, no network blocking, no limiter attach, no nft/tc/state mutation,
  no live /proc/sysfs read), `format_bytes_human(bytes)` for IEC binary prefix
  formatting (B/KiB/MiB/GiB/TiB). 30 pure unit tests: human-readable
  formatting (zero, bytes, KiB, MiB, GiB, TiB, u64::MAX no-panic), preview
  build (one/multiple interface, empty snapshot, order preservation, source
  label, attribution scope, enforcement status, loopback flag, human-readable
  fields), preview render (read-only statement, interface-level only, per-app
  denial, quota/network-blocking/limiter-attach/nft-tc-state-mutation/live
  /proc-sysfs denial, source label, human-readable bytes, empty snapshot,
  determinism), overflow-safe saturating totals (u64::MAX). No CLI command,
  no live system reads, no filesystem access, no enforcement.
- **v2.9 phase 3b accounting tests LOC split / maintainability refactor**:
  Refactored `src/accounting/tests.rs` (949 LOC) into a directory module
  with three focused files: `tests/mod.rs` (36 LOC, shared test constants +
  module declarations), `tests/interface_counters.rs` (637 LOC, 53 parser,
  render, error, and snapshot tests), `tests/usage_preview.rs` (299 LOC, 30
  usage preview build, render, format, and overflow tests). Preserved all 83
  accounting tests with identical behavior. No parser or renderer behavior
  changes, no formatting changes except rustfmt, no public API changes, no
  CLI exposure. All files under 1000 LOC. Refactor/split only. No live
  system reads, no state write, no enforcement, no quota, no eBPF, no
  network blocking, no limiter attach.
- **v2.9 phase 4 session delta model**: Added
  `src/accounting/session_delta.rs` with pure model for computing network usage
  differences between two `InterfaceCounterSnapshot` values. Model types:
  `SessionDelta` (per-interface delta rows, reset warnings, total RX/TX/combined
  delta bytes, interface count, source label, attribution scope
  "interface-level only", enforcement status "inactive/not implemented",
  read-only flag "model-only"), `SessionDeltaRow` (interface name, per-counter
  deltas for RX/TX bytes and packets, reset flags, presence flags),
  `CounterResetWarning` (interface, counter field, start/end values with Display
  formatting). Pure functions: `build_session_delta(start, end)` computes
  per-interface deltas with deterministic ordering (start interfaces first, then
  end-only), explicit counter reset detection (end < start → delta = 0, warning
  emitted, no negative values, no silent underflow), overflow-safe saturating
  totals; `render_session_delta()` renders human-readable output with 7 safety
  disclaimers (read-only session delta model, interface-level only, not per-app
  attribution, no quota enforcement active, no network blocking active, no limiter
  attach performed, no nft/tc/Zelynic state mutation performed, no live /proc or
  sysfs read performed) and counter reset/decrease warnings if present. Tests in
  `src/accounting/tests/session_delta.rs` (33 tests): normal one-interface delta,
  multiple interfaces, totals correctness, zero delta, interface only in end,
  interface only in start, RX/TX byte counter reset detection, RX/TX packet
  counter reset detection, no silent underflow, deterministic output order, render
  read-only/model-only, render per-app denial, render quota enforcement denial,
  render network blocking denial, render limiter attach denial, render nft/tc/state
  mutation denial, render live /proc/sysfs read denial, render reset warnings,
  overflow-safe totals (u64::MAX), saturating totals no panic, no CLI fields
  (structural), empty snapshots, source label, render determinism, render empty
  delta, multiple resets same interface, end-only interface ordering, warning display
  formatting, render source label, render saturating label, combined delta
  saturating add. No CLI command, no live system reads, no filesystem access, no
  enforcement, no eBPF, no network blocking, no limiter attach. Internal/pub(crate)
  only.
- **v2.9 phase 4b documentation count correction**: Fixed session_delta test count
  typo in `CHANGELOG.md` and `docs/v2.9-network-accounting-lab.md`: corrected
  "29 tests" to verified value "33 tests", corrected accounting total from "112
  (83 + 29)" to "116 (83 + 33)". Docs-only correction; no Rust behavior changes,
  no test changes.
- **v2.9 phase 5 local ledger design**: Produced design document
  (`docs/v2.9-phase-5-local-ledger-design.md`) defining the future local usage
  ledger for persistent session and quota tracking. Ledger data model: root
  structure (schema_version, created_at, updated_at, host_id, session_id,
  entries, metadata), LedgerEntry (entry_id, timestamp, entry_type, source_label,
  interface, rx/tx bytes/packets, combined_bytes, reset_detected, reset_details,
  read_only, provenance, reserved target_app/target_cgroup/target_pid fields
  marked not implemented), ResetDetail (counter_field, start/end values, reason),
  QuotaConfigEntry (future, not implemented). Storage boundary: recommended path
  under XDG_DATA_HOME/zelynic/ with atomic write strategy (temp file + fsync +
  rename + verify), corruption handling (schema validation, backup fallback, no
  silent recovery), rotation/cleanup (time-based and size-based, no automatic
  rotation, backup before prune), permission expectations (0600 file, 0700
  directory, no world-readable). Privacy constraints: no secrets, no raw packet
  data, no process command lines without privacy review, no DNS/URLs, no remote
  IP addresses, no individual connection timestamps. Honesty constraints:
  interface counters are not per-app attribution, ledger must not imply
  enforcement, quota guard, network blocking, or eBPF; counters may reset
  after reboot; ledger may be incomplete. Future commands designed (not
  implemented): zelynic usage --session, --since-boot, --interface, --ledger;
  zelynic ledger inspect, ledger clear; zelynic quota status. Future
  implementation roadmap: phase 5 design only, phase 6 pure model +
  serialization tests, phase 7 read-only render/inspect model, phase 8 optional
  explicit persistence, future v3.x quota guard, future v4.x eBPF observer.
  Ledger integrity invariants: monotonic timestamps, schema version consistency,
  host ID consistency, no negative values, combined bytes consistency, read-only
  flag always true. Privacy review requirements defined for pre-phase-8 gate.
  Phase 5 is design-only: no Rust code, no file I/O, no CLI, no tests. No
  enforcement, no eBPF, no network blocking, no limiter attach, no nft/tc
  mutation, no state mutation, no PID movement, no cgroup.procs write, no
  live /proc or sysfs read.
- **v2.9 phase 6 pure ledger model + serialization tests**: Added
  `src/accounting/ledger.rs` (389 LOC) with pure Rust data model and JSON
  serialization for the future local usage ledger. Model types: `Ledger`
  (schema_version, created_at, updated_at, host_id, session_id, entries),
  `LedgerEntry` (entry_id, timestamp, entry_type, source_label, interface,
  rx/tx bytes/packets, combined_bytes, reset_detected, reset_details, read_only,
  provenance, attribution_scope, enforcement_status), `ResetDetail`
  (counter_field, start_value, end_value, reason), `LedgerError` (JsonParse,
  UnsupportedSchemaVersion, Validation, SafetyViolation) with Display impl. Pure
  functions: `new_empty_ledger()`, `add_snapshot_entry()`, `add_session_delta_entry()`,
  `serialize_ledger_to_json()` (deterministic pretty JSON), `deserialize_ledger_from_json()`
  (validates JSON, schema version, required fields, safety constraints: read_only=true,
  attribution_scope="interface-level only", enforcement_status="inactive/not implemented",
  combined_bytes=rx+tx, entry_type in {snapshot,delta}), `render_ledger_summary()` with
  8 safety disclaimers (model only, no fs write, no live /proc/sysfs read, interface-level
  only/not per-app, quota inactive, network blocking inactive, no limiter attach, no
  nft/tc/state mutation). 33 tests in `src/accounting/tests/ledger.rs` (703 LOC):
  empty ledger creation, snapshot entry, session delta entry, serialize empty/with entries,
  deserialize valid, round-trip (with session_id, reset_details), reject malformed JSON,
  reject unsupported schema version, reject active enforcement, reject per-app attribution,
  reject missing required fields, reject entry missing fields, reject read_only=false,
  reject combined_bytes inconsistency, reject unknown entry type, u64::MAX counters,
  render model-only statement, render denies fs write, render denies live /proc/sysfs,
  render denies per-app attribution, render denies quota enforcement, render denies
  network blocking, render denies limiter attach, render denies nft/tc/state mutation,
  render with entries, render with reset entries, deterministic serialization, error
  display, multiple interfaces, saturating overflow, no CLI structural, no fs APIs.
  No new dependencies (serde/serde_json already present). No filesystem I/O, no live
  counter reads, no CLI command, no enforcement, no eBPF, no network blocking, no
  limiter attach, no nft/tc mutation. Accounting tests: 149 (53 + 30 + 33 + 33).
- **v2.9 phase 7 ledger inspect/render model**: Added
  `src/accounting/ledger_inspect.rs` with pure inspection model and renderer
  for the future `zelynic usage --ledger` and `zelynic ledger inspect` display
  contracts. Model type: `LedgerInspect` (total_entries, snapshot_count,
  delta_count, total_rx_bytes, total_tx_bytes, total_combined_bytes, interfaces
  in deterministic sorted order via BTreeSet, reset_warning_count,
  schema_version, created_at, updated_at, host_id, session_id, provenance
  "local ledger inspect model only", attribution_scope "interface-level only",
  enforcement_status "inactive/not implemented", read_only "model-only").
  Pure functions: `build_ledger_inspect(ledger)` computes aggregate statistics
  using saturating arithmetic and collects interfaces in sorted order for
  deterministic output; `render_ledger_inspect(inspect)` produces human-readable
  output with entry breakdown (snapshots/deltas), interface list, aggregate
  totals (saturating, overflow-safe), reset warning count, and attribution/
  enforcement metadata. 9 safety disclaimers in render output: ledger inspect
  model only, no filesystem read performed, no filesystem write performed,
  no live /proc or sysfs read performed, interface-level only (not per-app
  attribution), quota enforcement inactive/not implemented, network blocking
  inactive/not implemented, no limiter attach performed, no nft/tc/Zelynic
  state mutation performed. 30 tests in
  `src/accounting/tests/ledger_inspect.rs`: inspect empty ledger, inspect one
  snapshot entry, inspect one delta entry, inspect mixed entries, counts
  snapshot/delta correctly, totals rx/tx/combined correctly, lists interfaces
  deterministically, interfaces sorted across many, detects reset warnings,
  no reset warnings when none, handles u64::MAX safely, saturating totals
  with large entries, render model-only statement, render denies filesystem
  read, render denies filesystem write, render denies live /proc/sysfs, render
  denies per-app attribution, render denies quota enforcement, render denies
  network blocking, render denies limiter attach, render denies nft/tc/state
  mutation, no CLI structural, no filesystem APIs used, inspect metadata
  fields, render determinism, render empty ledger, render includes reset
  warning count, render with session_id, render includes saturating label.
  No new dependencies. No filesystem I/O, no live counter reads, no CLI
  command, no enforcement, no eBPF, no network blocking, no limiter attach,
  no nft/tc mutation. Accounting tests: 179 (53 + 30 + 33 + 33 + 30).
- **v2.9 phase 8 persistence path design + safe-path model**: Added
  `src/accounting/ledger_path.rs` with pure persistence path planning model
  for future ledger filesystem operations. Model types: `LedgerPathPlan`
  (base_directory, ledger_filename, full_ledger_path, namespace_label,
  path_status, safe_reason, model_only=true, filesystem_read_performed=false,
  filesystem_write_performed=false, persistence_enabled=false), `PathStatus`
  (Accepted, Rejected), `PathError` (EmptyBaseDirectory, EmptyFilename,
  AbsoluteFilename, ParentTraversalInFilename, ParentTraversalInBasePath,
  OutsideNamespace, SuspiciousFilename) with Display impl. Constants:
  `DEFAULT_LEDGER_FILENAME` ("network-ledger-v1.json"),
  `DEFAULT_NAMESPACE_LABEL` ("zelynic"). Pure functions:
  `build_default_ledger_path_plan(base_directory)` uses defaults;
  `build_ledger_path_plan(base, namespace, filename)` validates all inputs
  structurally (string-based, no filesystem access, no std::fs APIs, no
  canonicalization using live filesystem); `render_ledger_path_plan()` produces
  human-readable output with 9 safety disclaimers (persistence path model only,
  no filesystem read was performed, no filesystem write was performed, no
  ledger file was created, no ledger file was read, persistence is not enabled,
  no live /proc or sysfs read was performed, no quota enforcement or network
  blocking is active, no nft/tc/Zelynic state mutation was performed). Path
  boundary: reject empty base, reject empty filename, reject absolute filename,
  reject parent traversal in filename/base, reject outside-namespace paths,
  reject suspicious filenames, allow deterministic default filename. 43 tests
  in `src/accounting/tests/ledger_path.rs`. No new dependencies. No filesystem
  I/O, no live counter reads, no CLI command, no enforcement, no eBPF, no
  network blocking, no limiter attach, no nft/tc mutation. Accounting tests:
  222 (53 + 30 + 33 + 33 + 30 + 43).
- **v2.9 phase 9 persistence I/O contract + hard-blocked seam**: Added
  `src/accounting/ledger_persistence.rs` with hard-blocked persistence I/O
  contract seam for future ledger read/write operations. Model types:
  `LedgerPersistencePlan` (operation, path_plan, persistence_status,
  blocked_reason, model_only=true, filesystem_read_performed=false,
  filesystem_write_performed=false, directory_create_performed=false,
  file_create_performed=false, file_remove_performed=false,
  state_mutation_performed=false, persistence_enabled=false),
  `PersistenceOperation` (ReadLedger, WriteLedger, AtomicReplace, Backup,
  ValidatePath), `PersistenceStatus` (Blocked, Rejected), `PersistenceError`
  (HardBlocked, UnsafePath) with Display impl. Pure functions:
  `build_ledger_read_plan()`, `build_ledger_write_plan()`,
  `build_ledger_persistence_plan()` all return hard-blocked plans; unsafe path
  plans are rejected. `render_ledger_persistence_plan()` produces human-readable
  output with 12 safety disclaimers (hard-blocked seam, no fs read, no fs write,
  no ledger file created, no ledger file read, no ledger file saved, no
  directory created, no file removed, persistence not enabled, no live
  /proc/sysfs read, no quota enforcement or network blocking, no nft/tc/state
  mutation). Always hard-blocks read/write/atomic replace/backup. No std::fs
  APIs. No filesystem I/O. No directory/file creation/removal. 34 tests in
  `src/accounting/tests/ledger_persistence.rs`. No new dependencies. No
  filesystem I/O, no live counter reads, no CLI command, no enforcement, no
  eBPF, no network blocking, no limiter attach, no nft/tc mutation. Accounting
  tests: 256 (53 + 30 + 33 + 33 + 30 + 43 + 34).
- **v2.9 phase 10 persistence seam freeze / non-exposure audit**: Produced
  freeze/audit report (`docs/v2.9-phase-10-persistence-seam-freeze.md`)
  documenting the persistence boundary established in phases 8 and 9. Phase
  summary: phase 5 local ledger design, phase 6 pure ledger model + JSON
  serialization tests, phase 7 ledger inspect/render model, phase 8 persistence
  path design + safe-path model, phase 9 persistence I/O contract + hard-blocked
  seam. Validation state: ledger_path 43 tests, ledger_persistence 34 tests,
  ledger_inspect 30 tests, ledger 33 tests, accounting 256 tests, unit 901
  tests, integration 4 passed / 5 ignored, check-all passed, LOC policy passed.
  Persistence freeze guarantees: ledger_persistence always returns blocked/not
  implemented; persistence_enabled=false; filesystem_read_performed=false;
  filesystem_write_performed=false; directory_create_performed=false;
  file_create_performed=false; file_remove_performed=false;
  state_mutation_performed=false; model_only=true; no ledger file loaded; no
  ledger file saved; no atomic replace completed; no backup completed. Non-
  exposure audit: ledger_path and ledger_persistence are internal model only
  (pub(crate)); no CLI command or runtime path calls persistence modules; no
  filesystem I/O APIs used in accounting persistence modules; existing strict
  limiter remains the only validated active limiter path; accounting remains
  model/read-only foundation; no quota guard or background data guard active.
  Future phase entry criteria before actual persistence: separate explicit
  implementation phase required; safe path plan must be accepted; persistence
  seam must be explicitly unblocked; atomic write strategy reviewed; corruption
  handling reviewed; schema migration reviewed; privacy review completed; no
  per-app attribution claim; no quota/enforcement claim; exact file path
  reviewed before write; explicit operator confirmation before first
  filesystem write. Phase 10 is docs/report only: no Rust code changes, no test
  additions, no runtime behavior changes. No eBPF, no quota enforcement, no
  network blocking, no limiter attach, no nft/tc mutation, no state mutation,
  no actual filesystem persistence, no filesystem read/write, no directory/
  file creation/removal, no PID move, no cgroup.procs write, no live /proc
  or sysfs read, no CLI enablement.
- **v2.9 phase 11 release-candidate freeze / full validation index**: Produced
  release-candidate freeze document
  (`docs/v2.9-phase-11-release-candidate-freeze.md`) summarizing the full
  v2.9 timeline (phases 1 through 10), current validation state, final RC
  safety guarantees, and release-candidate decision. Full phase timeline:
  phase 1 design, phase 2 interface counter model + parser tests (53 tests),
  phase 3 usage preview renderer (30 tests), phase 3b tests LOC split,
  phase 4 session delta model (33 tests), phase 4b count correction, phase 5
  local ledger design, phase 6 pure ledger model + JSON serialization (33
  tests), phase 7 ledger inspect/render model (30 tests), phase 8
  persistence path design + safe-path model (43 tests), phase 9 persistence
  I/O contract + hard-blocked seam (34 tests), phase 10 persistence seam
  freeze / non-exposure audit. Validation state: accounting 256 tests, unit
  901 tests, integration 4 passed / 5 ignored, check-all passed, LOC policy
  passed, version still v2.8.0. Final v2.9 RC safety guarantees: no eBPF, no
  quota enforcement, no network blocking, no limiter attach, no nft/tc
  mutation, no Zelynic runtime state mutation, no actual filesystem
  persistence, no filesystem read/write, no directory/file creation/removal,
  no PID move, no cgroup.procs write, no live /proc or sysfs read, no CLI
  command for accounting/ledger, existing zelynic strict remains the only
  validated active limiter path. Release-candidate decision: v2.9 frozen as
  read-only accounting foundation; does not implement live usage command,
  persistence, quota guard, or allow/block mode; future persistence requires
  separate explicit post-RC phase; future quota/background guard deferred to
  v3.x; future eBPF observer deferred to v4.x. Phase 11 is docs/report only:
  no Rust code changes, no test additions, no runtime behavior changes.

## [2.8.0] - 2026-06-06 - v2.8.0 Experimental PID Move Lab

v2.8.0 is a **safety/research milestone** release. It does NOT implement live
PID movement, does NOT write real `cgroup.procs`, does NOT attach a limiter
from the Scope Runner, does NOT mutate nftables/tc/Zelynic state, does NOT
persist operation state, and does NOT enable any CLI path for live PID move.
The `--attach-live` flag remains hard-blocked. `zelynic strict` remains the
only validated active limiter path. All v2.8 experimental code is model-only,
fake/model-only, or mkdir-only (cgroup directory creation only — no PID
movement).

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
- **v2.8 phase 5b manual smoke operator checklist**: Produced operator
  checklist document (`docs/v2.8-phase-5b-manual-smoke-operator-checklist.md`)
  with exact review-only command tables for the future first real PID move smoke.
  All commands are for review only; no current Zelynic command performs this
  move; no limiter attach or nft/tc/state mutation is part of this smoke.
  Checklist sections: preflight environment checks (7), disposable sleep
  process creation (5), PID/cgroup capture (6), target path verification (5),
  target preparation (3), planned PID move (2), target verification (3),
  immediate rollback (2), rollback verification (3), cleanup (3), post-smoke
  audit (6). Explicit abort checklist (12 conditions): not root, not system
  scope, PID missing/stale, multiple PIDs, original cgroup missing/Zelynic-
  managed, target outside zelynic namespace, target non-empty, cgroup mount
  read-only, permissions unexpected, rollback unverifiable, ambiguous output.
  Expected observation table and manual recovery checklist (11 steps). Output
  honesty requirements with 7 canonical deny lines and honest substitutions.
  Docs/design only; no runtime code changes. No live PID move.
- **v2.8 phase 5c guarded real move implementation design**: Produced
  implementation design document
  (`docs/v2.8-phase-5c-guarded-real-move-implementation-design.md`) for the
  future guarded real PID move. Defines 11 allowed-target constraints
  (root-only, system-scope-only, single disposable sleep PID, operation-owned
  Zelynic target, immediate rollback, no limiter, no nft/tc/state mutation,
  no persistent state write, no browser/terminal/desktop/user app, no
  multi-PID tree). Proposed code architecture: `CgroupProcsWriter` trait with
  narrow live writer (cgroup.procs-only, no limiter/nft/tc/state knowledge)
  and fake writer adapter (test-only). Transaction controller decides rollback,
  renderer reports verified PID location. 11 exact transaction steps
  (pre-flight gates through post-smoke audit), 14 safety gates, 12 abort
  conditions. Failure handling for all scenarios (pre-target, target write,
  verification, rollback write/verification, cleanup) with never-retry rule.
  Output honesty contract (6 required fields, 8 forbidden claims, 7 canonical
  deny lines). Test strategy (~66 unit tests using fake writer, real writer
  compiled but unreachable without all gates, CLI blocked). Root smoke
  strategy. Docs/design only; no runtime code changes. No live PID move.
- **v2.8 phase 5d guarded real writer seam**: Added
  `src/systemd_wrapper/guarded_real_writer.rs` as the narrow code seam for
  the future guarded real writer. The seam models the future real writer
  boundary without performing any writes — always returns blocked/not
  implemented. Input model: pid, original cgroup path, target cgroup path,
  root gate, system-scope gate, single PID gate, rollback consent gate.
  Result model: status (always blocked), reason, pid location (always not
  moved), rollback attempted (always false), cleanup attempted (always
  false), cgroup.procs writes performed (always false), limiter attach
  performed (always false), nft/tc/state mutation performed (always false).
  7 canonical deny lines: no live PID move, no real cgroup.procs write, no
  limiter attach, no nft/tc/Zelynic state changes, no persistent state
  write, no CLI path for live PID move, guarded real writer seam is
  hard-blocked. Pure functions only: `build_guarded_real_writer_plan()` and
  `render_guarded_real_writer_plan()`. No I/O, no filesystem access, no /proc
  access, no /sys access. Gate validation: root, system scope, single
  non-zero PID, original cgroup present and non-empty, original cgroup not
  under /zelynic/, target under /sys/fs/cgroup/zelynic/, rollback consent.
  Wired into `mod.rs` with no CLI command and no runtime path exposure.
  Tests covering: seam always blocked, gate blocking (non-root, user scope,
  zero PID, multi-PID, missing original cgroup, zelynic-managed original
  cgroup, target outside namespace, missing rollback consent), result model
  field correctness, deny line presence (all 7 in every output), forbidden
  claim absence (PID moved, cgroup.procs write, rollback performed, limiter
  attach, bandwidth limiting active, nft/tc/state mutation, hard-blocked/
  not implemented), negative-path comprehensive mutation sweep, determinism,
  gate ordering, helper correctness, phase label, render structure. No live
  PID move, no real cgroup.procs write, no limiter attach, no nft/tc/Zelynic
  state mutation, no persistent state write, no CLI path for live PID move.
  The seam is always hard-blocked and non-mutating.
- **v2.8 phase 5e guarded real writer seam freeze/non-exposure audit**: Produced
  freeze/non-exposure audit report
  (`docs/v2.8-phase-5e-guarded-real-writer-freeze.md`) summarizing phases
  5a–5d and auditing the guarded real writer seam's non-exposure across the
  codebase. Phase 5 summary: 5a readiness (11 constraints, 14-step smoke plan,
  10 abort conditions), 5b operator checklist (7 preflight checks, 12 abort
  conditions, 11 recovery steps), 5c implementation design (CgroupProcsWriter
  trait, 11 transaction steps, 14 safety gates, 12 abort conditions, output
  honesty contract, ~66 test plan), 5d guarded real writer seam (945 LOC, 45
  tests, 7 gates, 7 canonical deny lines, pure functions only, no I/O). Current
  test state: guarded_real_writer 45 tests passed, total 645 tests passed,
  binary version remains v2.7.0. Explicit seam freeze guarantees (11 items):
  always returns blocked/not implemented, no live PID move, no real cgroup.procs
  write, no rollback write, no cleanup mutation, no limiter attach, no nft/tc/
  Zelynic state mutation, no persistent state write, no CLI path enabled, no
  /proc access, no /sys access, no filesystem mutation. Non-exposure audit:
  module registered as internal only, no public CLI command uses it, attach-live
  remains hard-blocked, mkdir-live remains mkdir-only, failure_simulation and
  fake_writer remain fake/model-only, move_executor remains blocked, move_
  transaction remains skeleton/model-only. Future phase entry criteria (11
  conditions): root-only, system-scope-only, single disposable sleep PID only,
  original cgroup captured and verified, target under zelynic only, rollback
  consent present, rollback path reviewed, manual recovery reviewed, exact smoke
  commands reviewed, no limiter/nft/tc/state, explicit operator confirmation
  before real smoke. Docs/report only; no runtime code changes. No live PID move.
- **v2.8 phase 5f guarded real writer LOC split/maintainability refactor**:
  Refactored `src/systemd_wrapper/guarded_real_writer.rs` (945 LOC single file)
  into a directory module with four files: `mod.rs` (216 LOC, build function +
  is_safe_writer_target helper + re-exports), `model.rs` (154 LOC, input/result/
  gate types + canonical deny lines + constants), `render.rs` (82 LOC,
  render_guarded_real_writer_plan function), `tests.rs` (513 LOC, all 45 tests).
  Preserved exact behavior and API compatibility: seam always returns blocked/
  not implemented, all result fields hardcoded non-mutating, all 7 canonical
  deny lines present, no forbidden claims, no CLI exposure. All 45 guarded_
  real_writer tests pass with identical results. Total tests remain 645.
  All files under 1000 LOC. No runtime behavior changes. Refactor/split only.
  No live PID move, no cgroup.procs write, no limiter attach, no nft/tc/state
  mutation, no persistent state write.
- **v2.8 phase 5g guarded real writer integration audit/blocked-path proof**:
  Produced integration audit report
  (`docs/v2.8-phase-5g-guarded-real-writer-integration-audit.md`) proving the
  guarded real writer seam remains internal, hard-blocked, non-mutating, and
  unreachable from any live CLI or runtime path after the 5f split. Blocked-path
  proof covers 9 properties: module is internal only, no CLI command calls it,
  no runtime path calls it, attach-live path remains hard-blocked, mkdir-live
  path remains mkdir-only, move_executor remains blocked, move_transaction
  remains skeleton/model-only, failure_simulation remains fake/model-only,
  fake_writer remains fake/model-only. Output/safety proof documents 7 canonical
  deny lines, all forbidden claims verified absent, all result fields hardcoded
  non-mutating, and comprehensive negative-path mutation sweep. Future real move
  activation requires 9 explicit conditions. Docs/report only; no Rust source file
  modifications. No runtime behavior changes. No live PID move.
- **v2.8 phase 5h final pre-real-write validation/release gate report**:
  Produced final pre-real-write validation / release gate report
  (`docs/v2.8-phase-5h-final-pre-real-write-validation.md`) summarizing all
  phase 5 work (5a through 5g) and serving as the release gate before any future
  real cgroup.procs write. Report covers: phase 5 summary (7 sub-phases), current
  validation state (45 guarded_real_writer tests, 645 total tests, 84 files, all
  under 1000 LOC), 11 explicit pre-real-write freeze guarantees, blocked-path
  proof summary (9 properties), next-phase entry criteria (13 conditions), and
  artifact inventory. Docs/report only; no Rust source file modifications. No
  runtime behavior changes. No live PID move.
- **v2.8 phase 5i release-candidate freeze/full validation index**: Produced
  release-candidate freeze / full validation index
  (`docs/v2.8-phase-5i-release-candidate-freeze.md`) covering the entire v2.8
  Experimental PID Move Lab timeline from phase 1 through 5h. Report covers:
  full timeline summary (phases 1, 2a–2c, 3a–3e, 4a–4e, 5a–5h), current
  validation state (45 guarded_real_writer tests, 645 total tests, 84 files), 12
  final RC safety guarantees, release-candidate decision (v2.8 can be frozen as
  safety/research milestone without live PID movement), future post-RC
  requirements (separate explicit phase, root-only, system-scope-only, single
  disposable sleep PID only, immediate rollback, no limiter/nft/tc/state,
  explicit operator confirmation, abort on ambiguity), and full artifact
  inventory. Docs/report only; no Rust source file modifications. No runtime
  behavior changes. No live PID move.

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

[Unreleased]: https://github.com/oxyzenq/zelynic/compare/v2.9.0...HEAD
[2.9.0]: https://github.com/oxyzenQ/zelynic/compare/v2.8.0...v2.9.0
[2.5.0]: https://github.com/oxyzenq/zelynic/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/oxyzenq/zelynic/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/oxyzenq/zelynic/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/oxyzenq/zelynic/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/oxyzenq/zelynic/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/oxyzenq/zelynic/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/oxyzenq/zelynic/releases/tag/v1.0.0
