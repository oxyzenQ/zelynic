# I-12 — Event Stream Reader Boundary, Disabled by Default

## Status

Experimental branch only. This phase is **not** released.

## Branch

`intergalaxion` (branched from stable `main` v3.1.0).

## Summary

Phase I-12 adds a disabled-by-default event stream reader boundary for the
Intergalaxion Engine. This phase defines the executor seam for a future event
stream reader. It does NOT open ring buffers in normal builds. It does NOT read
live kernel events in normal builds. It does NOT expose public CLI. It does NOT
persist anything. It does NOT add enforcement. It does NOT fake reader success.

## Design constraints

- Reader boundary only — not the real event stream reader implementation.
- Feature-gated by `intergalaxion-event-stream-lab` if feature is added.
- Disabled by default — no reader possible without the feature flag.
- No public CLI.
- No normal CI live event read.
- No normal test root requirement.
- No automatic live attach or detach.
- No ring buffer open.
- No live kernel event read.
- No map pin.
- No enforcement.
- No packet drop.
- No block/allow/quota.
- No nft/tc fallback.
- No ledger file write or persistence.
- Existing v3.1 usage JSON schema unchanged.
- Existing v3.1 ledger JSON schema unchanged.
- Reader must not fake success.
- Reader remains not implemented in normal build.

## Models added

| Model | Purpose |
|---|---|
| `EbpfEventStreamReaderStatus` | 10-variant enum for reader boundary state |
| `EbpfEventStreamReaderInput` | Input combining read plan, feature flag, safety flags |
| `EbpfEventStreamReaderResult` | Output with 23 fields, all operation flags always false |

## Helper functions

| Function | Purpose |
|---|---|
| `default_event_stream_reader_input()` | Safe default input (feature disabled) |
| `evaluate_event_stream_reader()` | Pure deterministic evaluator |
| `validate_event_stream_reader_result()` | Validates no unsafe flags |
| `event_stream_reader_status_label()` | Stable human-readable label |
| `execute_event_stream_reader_feature_gated()` | Feature-gated executor seam |

## Evaluation logic

1. Feature disabled → `FeatureDisabled` (always safe).
2. Read plan validation fails → `PlanRejected`.
3. Read plan not future read candidate → `PlanRejected`.
4. Empty operator label → `ManualEvidenceMissing`.
5. `allow_reader_attempt=false` → `ReaderNotImplemented`.
6. Forbidden flags (ring buffer, live read, map pin, persistence) → rejected.
7. Unsupported read mode → `UnsupportedMode`.
8. All gates pass → `FutureReaderReady` (reader not implemented, no execution).

## `main` remains stable

`main` remains frozen at v3.1.0. All Intergalaxion work is on the
`intergalaxion` branch only.

## Next suggested phase

I-13 — Event Stream Fixture Decoder Bridge, or
I-12A — Feature-Gated Reader Lab Dry Run.
