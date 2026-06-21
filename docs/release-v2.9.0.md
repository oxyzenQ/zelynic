# Zelynic v2.9.0 Network Accounting Lab

Zelynic v2.9.0 "Network Accounting Lab" is a **read-only accounting foundation**
release that establishes the data model, parsers, renderers, and persistence seam
for future network usage tracking. This release does NOT implement live usage
commands, does NOT read or write any ledger file from disk, does NOT implement
quota enforcement, does NOT block any network traffic, does NOT implement eBPF,
does NOT attach limiters or mutate nftables/tc rules, does NOT move PIDs or write
cgroup.procs, and does NOT add any CLI command for accounting or ledger
operations. `zelynic strict` remains the only validated active limiter path.

## Release Positioning

v2.9.0 is explicitly positioned as a read-only accounting foundation milestone, not
a live usage or enforcement release. The work across eleven phases establishes the
pure data model layer, parser/serializer infrastructure, session delta computation,
ledger model with JSON serialization, ledger inspection rendering, persistence
path planning, and a hard-blocked persistence I/O seam that any future actual
filesystem persistence would require. All accounting code is internal (pub(crate))
only, has no CLI path, performs no filesystem I/O, and uses no std::fs APIs.

## Summary

The v2.9.0 release covers eleven sequential phases, all merged to main with CI
green. Phase 1 introduces the master design document defining data sources, honesty
constraints, and the hard safety boundary. Phase 2 adds the interface counter
parser and model with 53 pure unit tests. Phase 3 adds the usage preview renderer
with 30 tests. Phase 3b refactors accounting tests into a directory module for
maintainability. Phase 4 adds the session delta model with 33 tests. Phase 5
produces the local ledger design document. Phase 6 adds the pure ledger model with
JSON serialization and 33 tests. Phase 7 adds the ledger inspect/render model with
30 tests. Phase 8 adds the persistence safe-path model with 43 tests. Phase 9
adds the hard-blocked persistence I/O seam with 34 tests. Phase 10 produces the
persistence seam freeze and non-exposure audit report. Phase 11 produces the
release-candidate freeze and full validation index. Every phase is model-only and
pure — no live system reads, no filesystem I/O, no enforcement.

## What Changed

### Phase 1: Accounting Design / Read-Only Architecture

- Produced the master design document (`docs/v2.9-network-accounting-lab.md`)
  defining data model, data sources (`/proc/net/dev`, sysfs, nftables counters,
  tc statistics), honesty constraints (interface counters are not per-app, PID
  attribution is snapshot-based, counter reset on reboot, read-only must not claim
  enforcement), future command surface (`zelynic usage`, `zelynic quota status`,
  `zelynic limit-background`), phase plan, and future version roadmap (v3.x quota
  guard, v4.x eBPF observer).
- No runtime changes. Design/documentation only.

### Phase 2: Interface Counter Model + Pure Parser Tests

- Added `src/accounting/` module with pure Rust types and parsers for
  `/proc/net/dev`-style content.
- Model types: `InterfaceCounter`, `InterfaceCounterSnapshot`, `ParseError`,
  `SourceLabel`.
- Pure parser `parse_proc_net_dev(content: &str)` handles standard format with
  header skipping, interface name trimming, colon validation, field count
  validation, u64 parsing with overflow detection.
- Render helper with honesty labels: "read-only parsed sample", "aggregate
  interface traffic, not per-app", "No enforcement", "No quota guard", "No
  per-app attribution".
- 53 pure unit tests. No CLI command, no live system reads, no filesystem access.

### Phase 3: Read-Only Usage Preview Renderer

- Added `src/accounting/usage_preview.rs` with pure model and renderer for the
  future `zelynic usage` command display contract.
- Model types: `UsagePreview`, `UsagePreviewRow`. IEC binary prefix formatting
  (B/KiB/MiB/GiB/TiB).
- Comprehensive safety disclaimers in rendered output: read-only, interface-level
  only, not per-app, no quota enforcement, no network blocking, no limiter attach,
  no nft/tc/state mutation, no live /proc/sysfs read.
- 30 pure unit tests. No CLI command, no live system reads, no enforcement.

### Phase 3b: Accounting Tests LOC Split

- Refactored `src/accounting/tests.rs` (949 LOC) into a directory module with
  three focused files: `tests/mod.rs`, `tests/interface_counters.rs`,
  `tests/usage_preview.rs`.
- Preserved all 83 accounting tests with identical behavior. Refactor/split only.

### Phase 4: Session Delta Model

- Added `src/accounting/session_delta.rs` with pure model for computing network
  usage differences between two snapshots.
- Model types: `SessionDelta`, `SessionDeltaRow`, `CounterResetWarning`.
- Explicit counter reset detection (end < start produces delta = 0 with warning).
- Overflow-safe saturating totals. Deterministic output ordering.
- 33 pure unit tests. No CLI command, no live system reads, no filesystem access.

### Phase 5: Local Ledger Design

- Produced design document (`docs/v2.9-phase-5-local-ledger-design.md`) defining
  the future local usage ledger schema, storage boundary, privacy constraints,
  honesty rules, and implementation roadmap.
- Design-only phase: no Rust code, no file I/O, no CLI, no tests.

### Phase 6: Pure Ledger Model + JSON Serialization Tests

- Added `src/accounting/ledger.rs` with pure Rust data model and JSON
  serialization for the future local usage ledger.
- Model types: `Ledger`, `LedgerEntry`, `ResetDetail`, `LedgerError`.
- Pure functions: `new_empty_ledger()`, `add_snapshot_entry()`,
  `add_session_delta_entry()`, `serialize_ledger_to_json()` (deterministic),
  `deserialize_ledger_from_json()` (validates safety constraints), `render_ledger_summary()`.
- Safety constraints enforced: read_only=true, attribution_scope="interface-level
  only", enforcement_status="inactive/not implemented".
- 33 pure unit tests. No filesystem I/O, no CLI command, no enforcement.

### Phase 7: Ledger Inspect/Render Model

- Added `src/accounting/ledger_inspect.rs` with pure inspection model and
  renderer for future `zelynic usage --ledger` and `zelynic ledger inspect`
  display contracts.
- Model type: `LedgerInspect` with aggregate statistics, sorted interfaces,
  reset warning count, and metadata.
- 9 safety disclaimers in render output.
- 30 pure unit tests. No filesystem I/O, no CLI command, no enforcement.

### Phase 8: Persistence Path Design + Safe-Path Model

- Added `src/accounting/ledger_path.rs` with pure persistence path planning model.
- Model types: `LedgerPathPlan`, `PathStatus`, `PathError`.
- String-based validation only (no filesystem access, no std::fs APIs).
- Path boundary: reject empty base, empty filename, absolute filename, parent
  traversal, outside-namespace paths, suspicious filenames.
- 9 safety disclaimers in render output. 43 pure unit tests.

### Phase 9: Persistence I/O Contract + Hard-Blocked Seam

- Added `src/accounting/ledger_persistence.rs` with hard-blocked persistence I/O
  contract seam.
- Model types: `LedgerPersistencePlan`, `PersistenceOperation`,
  `PersistenceStatus`, `PersistenceError`.
- Always returns hard-blocked/not implemented. No std::fs APIs.
- 12 safety disclaimers in render output. 34 pure unit tests.

### Phase 10: Persistence Seam Freeze / Non-Exposure Audit

- Produced freeze/audit report (`docs/v2.9-phase-10-persistence-seam-freeze.md`)
  documenting the persistence boundary.
- Documents freeze guarantees: persistence_enabled=false, filesystem flags all
  false, model_only=true, no ledger file loaded/saved.
- Non-exposure audit: ledger_path and ledger_persistence are internal (pub(crate))
  only; no CLI or runtime path calls these modules.
- Future phase entry criteria for actual persistence defined.

### Phase 11: Release-Candidate Freeze / Full Validation Index

- Produced RC freeze document (`docs/v2.9-phase-11-release-candidate-freeze.md`)
  summarizing the full v2.9 timeline, validation state, safety guarantees, and
  RC decision.
- Documents that v2.9 is frozen as read-only accounting foundation; does not
  implement live usage, persistence, quota guard, or allow/block mode.
- Future persistence: separate explicit post-RC phase. Future quota/background
  guard: v3.x. Future eBPF observer: v4.x.

### LOC Policy Compliance

- Refactored `src/accounting/tests.rs` from 949 LOC into directory module with
  three focused files, all under 1000 LOC.
- All project files remain under the 1000 LOC policy limit.

## Safety Guarantees

This release maintains strict safety boundaries. The following are explicitly
documented and verified across all phases:

- **No eBPF:** v2.9 does not load, attach, or interact with eBPF programs in any
  way. The eBPF optional dependency remains unused.
- **No quota enforcement:** No traffic is blocked, throttled, or rate-limited by
  any v2.9 code. Quota budget tracking is designed but not implemented.
- **No network blocking:** No network traffic is ever blocked, dropped, or
  rejected by v2.9 code.
- **No limiter attach:** The `zelynic strict` path is not modified by v2.9. No
  accounting code attaches or detaches limiters.
- **No nft/tc mutation:** v2.9 never adds, removes, or modifies nftables rules
  or tc qdisc/filters/classes.
- **No state mutation:** v2.9 does not write Zelynic runtime state.
- **No actual filesystem persistence:** The persistence seam is hard-blocked. No
  ledger file is read from or written to disk. No std::fs APIs are used in
  accounting modules.
- **No filesystem read/write:** No accounting module reads or writes any file.
- **No directory/file creation/removal:** No directories or files are created or
  removed by v2.9 code.
- **No PID move:** v2.9 does not move PIDs or interact with cgroups for
  accounting.
- **No cgroup.procs write:** v2.9 never writes to cgroup.procs files.
- **No live /proc or sysfs read:** All accounting parsers operate on string
  content, not live system files.
- **No CLI enablement:** No new CLI command is added for accounting, ledger,
  usage, or quota operations.

## What Is Still Not Implemented

- **Live usage CLI command:** The `zelynic usage` command is designed but not
  implemented. No CLI path exists for it.
- **Actual filesystem persistence:** The ledger persistence seam always returns
  hard-blocked. No ledger file is ever read from or written to disk.
- **Quota enforcement:** Quota budget tracking is designed but enforcement
  (blocking/throttling when budget is exhausted) is explicitly deferred to v3.x.
- **Per-app attribution:** Interface counters are aggregate only. Per-app
  attribution requires eBPF (deferred to v4.x) or PID-based polling (with
  documented snapshot limitations).
- **Background data guard:** Designed as a future feature with prerequisites:
  per-app attribution, quota enforcement, and explicit user enablement.
- **eBPF observer:** Explicitly deferred to v4.x or later.

## Honesty Constraints

v2.9 enforces strict honesty constraints on all accounting output:

- Interface counters are clearly labeled as aggregate interface traffic, not
  per-app traffic.
- Render output includes "read-only" or "model-only" in every header.
- No output implies that traffic is being blocked, throttled, or shaped.
- No output claims quota enforcement is active.
- Counter reset behavior (reboot, interface down/up) is documented.
- Future commands (zelynic usage, zelynic quota status, zelynic limit-background)
  are explicitly marked as "not implemented" in the design document.

## Validation Summary

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `cargo test --locked accounting` — 256 tests passed
- `cargo test --locked ledger_persistence` — 34 tests passed
- `./scripts/build.sh check-all` — 901 unit tests passed, 4 integration passed / 5
  ignored, 100 files policy check passed
- `git diff --check` — no whitespace errors

## Test Totals

- interface_counters: 53 tests
- usage_preview: 30 tests
- session_delta: 33 tests
- ledger: 33 tests
- ledger_inspect: 30 tests
- ledger_path: 43 tests
- ledger_persistence: 34 tests
- accounting total: 256 tests
- project unit total: 901 tests
- integration: 4 passed, 5 ignored

## Artifact Inventory

Key source files added in v2.9:

- `src/accounting/mod.rs` — module root
- `src/accounting/interface_counters.rs` — interface counter parser/model
- `src/accounting/usage_preview.rs` — usage preview renderer
- `src/accounting/session_delta.rs` — session delta model
- `src/accounting/ledger.rs` — pure ledger model + JSON serialization
- `src/accounting/ledger_inspect.rs` — ledger inspect/render model
- `src/accounting/ledger_path.rs` — persistence safe-path model
- `src/accounting/ledger_persistence.rs` — hard-blocked persistence I/O seam
- `src/accounting/tests/mod.rs` — test module root
- `src/accounting/tests/interface_counters.rs` — 53 parser tests
- `src/accounting/tests/usage_preview.rs` — 30 usage preview tests
- `src/accounting/tests/session_delta.rs` — 33 session delta tests
- `src/accounting/tests/ledger.rs` — 33 ledger tests
- `src/accounting/tests/ledger_inspect.rs` — 30 inspect tests
- `src/accounting/tests/ledger_path.rs` — 43 path tests
- `src/accounting/tests/ledger_persistence.rs` — 34 persistence seam tests

Key documentation added in v2.9:

- `docs/v2.9-network-accounting-lab.md` — master design document
- `docs/v2.9-phase-5-local-ledger-design.md` — ledger design document
- `docs/v2.9-phase-10-persistence-seam-freeze.md` — persistence freeze report
- `docs/v2.9-phase-11-release-candidate-freeze.md` — RC freeze report
- `docs/release-v2.9.0.md` — this release notes document

## Upgrade Notes

- No configuration or state migration is needed for this release. Existing
  `zelynic strict` limits, profiles, and runtime state continue to work
  unchanged.
- No new CLI commands are added. The existing command surface (`zelynic list`,
  `zelynic strict`, `zelynic unstrict`, `zelynic status`, `zelynic clean`,
  `zelynic profile`, `zelynic qos`, `zelynic watch`, `zelynic auto`,
  `zelynic log`, `zelynic backend`, `zelynic run`, `zelynic completions`,
  `zelynic man`) remains unchanged.
- The accounting module is internal only (pub(crate)) and has no CLI path. It
  cannot be accessed from any command-line invocation.
- No new dependencies are added. serde and serde_json were already present in
  Cargo.toml from earlier versions.

## Next Roadmap

The next milestones after v2.9.0 are:

- **Post-RC persistence phase:** A separate explicit phase to unblock the
  persistence seam and implement actual ledger filesystem read/write. Requires
  satisfying all phase 10 entry criteria: safe path plan accepted, atomic write
  strategy reviewed, corruption handling reviewed, schema migration reviewed,
  privacy review completed, explicit operator confirmation before first write.
- **v3.x quota guard:** Quota budget tracking with enforcement (blocking or
  throttling when budget is exhausted). Requires reliable per-app attribution or
  interface-level quota with user consent.
- **v4.x eBPF observer:** Per-app attribution via eBPF programs attached to
  network hooks. Must be read-only (no packet modification). Requires kernel
  5.4+ and CAP_BPF or root.

This incremental approach ensures each capability is validated in isolation before
combining them. The pure models, parsers, renderers, and hard-blocked persistence
seam introduced in v2.9 provide the data foundation for those future milestones.

## Release Compare

```text
https://github.com/oxyzenQ/zelynic/compare/v2.8.0...v2.9.0
```
