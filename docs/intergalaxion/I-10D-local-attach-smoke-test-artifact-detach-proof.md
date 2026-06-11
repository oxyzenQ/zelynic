# I-10D — Local Attach Smoke Test Artifact and Detach Proof

**Phase**: I-10D
**Branch**: `intergalaxion` (experimental only)
**Base**: stable v3.1.0 on `main`

## Summary

I-10D adds pure model types for an eBPF object artifact contract, detach proof, and local lab run recipe for the future minimal live observer attach smoke test. This phase is **disabled by default**, **feature-gated** by `intergalaxion-live-attach-lab`, and **does not perform any live kernel operations** in normal builds or tests.

## Scope

I-10D is experimental branch only. The `main` branch remains stable v3.1.0 with no changes.

## New Models

### EbpfLiveAttachArtifactContract

Describes an eBPF object artifact and its safety constraints:

- `artifact_name` — Human-readable artifact name.
- `artifact_status` — One of: `MissingArtifact`, `DeclaredOnly`, `BuildPlanned`, `BuildReady`, `Unsupported`.
- `object_bytes_embedded` — Whether object bytes are embedded in the binary.
- `object_path_declared` — Whether an object file path is declared.
- `build_target_declared` — Whether a BPF build target is declared.
- `normal_ci_builds_artifact` — Whether normal CI builds the artifact (must be false).
- `normal_tests_require_artifact` — Whether normal tests need the artifact (must be false).
- `feature_required` — The Cargo feature required to enable the artifact.
- `observer_only` — Whether the artifact is observer-only (must be true).
- `enforcement_allowed` — Whether enforcement is allowed (must be false).
- `packet_drop_allowed` — Whether packet drop is allowed (must be false).
- `ring_buffer_required` — Whether a ring buffer is required (must be false).
- `map_pin_required` — Whether map pinning is required (must be false).
- `persistence_required` — Whether persistence is required (must be false).

### EbpfDetachProof

Tracks whether detach was performed correctly after a live attach spike:

- `status` — One of: `NotAttempted`, `DetachPlanned`, `DetachedCleanly`, `DetachFailed`, `ManualCleanupRequired`.
- `detach_required` — Whether detach is required.
- `detach_attempted` — Whether detach was attempted.
- `detach_succeeded` — Whether detach succeeded.
- `attach_was_attempted` — Whether attach was ever attempted.
- `attach_was_successful` — Whether attach was successful.
- `program_unloaded`, `map_unpinned`, `ring_buffer_closed`, `persistence_cleaned` — Cleanup flags.
- `kernel_state_mutated`, `enforcement_performed`, `packet_drop_performed` — Forbidden-operation flags (always false).
- `notes` — Human-readable notes.

### EbpfLocalAttachSmokeRecipe

Combines artifact contract, detach proof, and safety constraints:

- `phase` — Always "I-10D".
- `local_lab_only` — Must be true.
- `feature_required` — Must be "intergalaxion-live-attach-lab".
- `public_cli_allowed` — Must be false.
- `normal_tests_execute_live_attach` — Must be false.
- `normal_ci_executes_live_attach` — Must be false.
- All forbidden-operation flags must be false.

## Safety Invariants

- **No public CLI** — I-10D does not expose any public CLI commands.
- **No enforcement** — No enforcement, no packet drop, no block/allow/quota.
- **No nft/tc fallback** — No nft/tc backend or fallback.
- **No ring buffer open** — No ring buffer is opened.
- **No live kernel event read** — No live kernel events are read.
- **No map pin** — No maps or programs are pinned.
- **No ledger file write** — No persistence, no ledger file writes.
- **No root required for tests** — Normal tests do not require root.
- **Normal tests do not execute live attach** — Live attach is never triggered in normal `cargo test`.
- **Normal CI does not execute live attach** — CI pipelines do not run live attach.
- **Disabled by default** — The `intergalaxion-live-attach-lab` feature is off by default.
- **Existing v3.1 usage JSON schema unchanged** — No changes to the existing usage schema.
- **Existing v3.1 ledger JSON schema unchanged** — No changes to the existing ledger schema.
- **Artifact absence reported honestly** — Missing artifacts are modeled as `MissingArtifact`, not faked.
- **Detach proof does not fake success** — The detach proof defaults to `NotAttempted` and cannot report `DetachedCleanly` without an actual attach having been attempted and a successful detach.

## Validation Rules

### Artifact Contract Validation

- `observer_only` must be true.
- `enforcement_allowed` must be false.
- `packet_drop_allowed` must be false.
- `ring_buffer_required` must be false.
- `map_pin_required` must be false.
- `persistence_required` must be false.
- `normal_ci_builds_artifact` must be false.
- `normal_tests_require_artifact` must be false.
- `artifact_name` must not be empty.
- `feature_required` must not be empty.

### Detach Proof Validation

- `kernel_state_mutated` must be false.
- `enforcement_performed` must be false.
- `packet_drop_performed` must be false.
- `program_unloaded` requires `detach_attempted`.
- `map_unpinned` must be false.
- `ring_buffer_closed` must be false.
- `persistence_cleaned` must be false.
- `attach_was_successful` requires `attach_was_attempted`.
- `detach_succeeded` requires `detach_attempted`.
- `DetachedCleanly` status requires `attach_was_attempted` and `detach_succeeded`.

### Recipe Validation

- `local_lab_only` must be true.
- `public_cli_allowed` must be false.
- `normal_tests_execute_live_attach` must be false.
- `normal_ci_executes_live_attach` must be false.
- All forbidden-operation flags must be false.
- Embedded artifact contract must validate.
- Embedded detach proof must validate.

## Files Changed

- `src/intergalaxion_engine/backends/ebpf/live_attach_artifact.rs` — New: 5 types, 7 helpers.
- `src/intergalaxion_engine/backends/ebpf/mod.rs` — Extended: added `live_attach_artifact` module.
- `src/intergalaxion_engine/mod.rs` — Extended: added `tests_i10d` module.
- `src/intergalaxion_engine/tests_i10d.rs` — New: ~90 deterministic tests.
- `docs/intergalaxion/I-10D-local-attach-smoke-test-artifact-detach-proof.md` — New: this document.

## Next Phase

I-10E — Feature-Gated Local Live Attach Lab Execution, or I-11 — Event Stream Read.
