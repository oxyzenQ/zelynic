# I-10E — Feature-Gated Local Live Attach Lab Execution

**Phase**: I-10E
**Branch**: `intergalaxion` (experimental only)
**Base**: stable v3.1.0 on `main`

## Summary

I-10E adds the first minimal feature-gated local live attach lab execution path. This phase introduces a private lab executor seam that is reachable ONLY behind the `intergalaxion-live-attach-lab` Cargo feature (disabled by default). In the default build, all evaluation paths return safe, inert results with no live kernel operations.

## Scope

I-10E is experimental branch only. The `main` branch remains stable v3.1.0 with no changes.

## New Models

### EbpfLiveAttachLabStatus

10 variants: `FeatureDisabled`, `LabGateRejected`, `ArtifactMissing`, `UnsupportedTarget`, `AttachNotImplemented`, `AttachAttempted`, `AttachSucceeded`, `AttachFailed`, `DetachedCleanly`, `DetachFailed`.

### EbpfLiveAttachLabExecutionInput

Combines I-10C lab input, I-10D artifact contract, I-10D smoke recipe, and explicit safety flags (`require_immediate_detach`, `allow_ring_buffer_open`, `allow_event_stream_read`, `allow_map_pin`, `allow_enforcement`, `allow_packet_drop`, `allow_persistence`).

### EbpfLiveAttachLabExecutionResult

20 fields including status, attach/detach booleans, embedded detach proof, and all forbidden-operation flags (all false in default build).

## Safety Invariants

- **Disabled by default** — gated by `intergalaxion-live-attach-lab`.
- **No public CLI** — I-10E does not expose any public CLI commands.
- **No enforcement** — No enforcement, no packet drop, no block/allow/quota.
- **No nft/tc fallback** — No nft/tc backend or fallback.
- **No ring buffer open** — No ring buffer is opened.
- **No live kernel event read** — No live kernel events are read.
- **No map pin** — No maps or programs are pinned.
- **No ledger file write** — No persistence, no ledger file writes.
- **No root required for tests** — Normal tests do not require root.
- **Normal tests do not execute live attach** — Live attach is never triggered in normal `cargo test`.
- **Normal CI does not execute live attach** — CI pipelines do not run live attach.
- **Existing v3.1 usage JSON schema unchanged** — No changes to the existing usage schema.
- **Existing v3.1 ledger JSON schema unchanged** — No changes to the existing ledger schema.
- **Artifact absence reported honestly** — Missing artifacts are modeled as `ArtifactMissing`, not faked.
- **Detach proof does not fake success** — Fake detach success is rejected by validation.
- **No fake attach success** — `AttachNotImplemented` is returned honestly when all gates pass but real attach is not yet implemented.

## Evaluation Gate Chain

1. Feature gate: `explicit_local_lab_feature_enabled=false` forces `FeatureDisabled`.
2. Immediate detach: `require_immediate_detach=false` forces `LabGateRejected`.
3. Forbidden flags: Any unsafe `allow_*` flag forces `LabGateRejected`.
4. Smoke recipe validation: Unsafe recipe forces `LabGateRejected`.
5. Artifact contract validation: Unsafe contract forces `LabGateRejected`.
6. Executor evaluation (I-10C delegate): Unsafe result maps to corresponding lab status.
7. Artifact availability: `MissingArtifact` or unavailable bytes forces `ArtifactMissing`.
8. Attach not implemented: All gates pass but real attach returns `AttachNotImplemented`.

## Files Changed

- `src/intergalaxion_engine/backends/ebpf/live_attach_lab.rs` — New: 3 types, 4 helpers.
- `src/intergalaxion_engine/backends/ebpf/mod.rs` — Extended: added `live_attach_lab` module.
- `src/intergalaxion_engine/mod.rs` — Extended: added `tests_i10e` module.
- `src/intergalaxion_engine/tests_i10e.rs` — New: ~80 deterministic tests.
- `docs/intergalaxion/I-10E-feature-gated-local-live-attach-lab-execution.md` — New: this document.

## Next Phase

I-10F — Local Live Attach Manual Lab Result Capture, or I-11 — Event Stream Read.
