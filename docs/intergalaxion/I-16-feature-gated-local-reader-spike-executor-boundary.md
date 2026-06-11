# I-16 — Feature-Gated Local Reader Spike Executor Boundary

## Phase

I-16 (experimental branch only)

## Status

`intergalaxion` branch. `main` remains stable v3.1.0.

## Purpose

I-16 defines the final executor seam for a future local reader spike. This
phase is executor-boundary only — not the real live event stream reader, not a
ring buffer reader, not a kernel event consumer. It defines feature-gated
executor input/result models and validation, plus an executor function that
refuses safely by default. The normal build/test/CI remains rootless and inert.

## Scope

- Executor-boundary only — no real event stream reading.
- Feature-gated via `intergalaxion-event-stream-lab` Cargo feature.
- Disabled by default — no reader execution possible without explicit feature.
- Consumes I-15A preparation plan.
- Returns honest executor result with explicit statuses.

## Hard constraints

- No public CLI.
- No normal CI live event read.
- No normal test root requirement.
- No automatic live attach.
- No automatic detach.
- No ring buffer open.
- No live kernel event read.
- No map pin.
- No enforcement.
- No packet drop.
- No block/allow/quota.
- No nft/tc fallback.
- No ledger file write.
- No persistence.
- Existing v3.1 usage JSON schema unchanged.
- Existing v3.1 ledger JSON schema unchanged.

## I-15A integration

I-15A PrepReady is required. The executor validates the preparation plan
before representing future execution readiness.

## Requirements

- Cleanup requirement is required.
- Post-run evidence capture is required.
- Executor must not fake reader execution success (no fake reader execution success).
- Executor must not fake live event counts (no fake live event counts).
- No fake reader readiness.

## Models added

- `EbpfEventStreamReaderSpikeExecutorStatus` — 11 variants.
- `EbpfEventStreamReaderSpikeExecutorInput` — 13 fields.
- `EbpfEventStreamReaderSpikeExecutorResult` — 28 fields.
- 5 helper functions for default input, evaluation, feature-gated execution,
  validation, and status labels.

## Executor statuses

| Status | Meaning |
|---|---|
| FeatureDisabled | Cargo feature not enabled |
| PrepRejected | I-15A plan not ready or validation failed |
| ExecutorDisabled | allow_execution_attempt=false |
| ReaderNotImplemented | Reader not yet built |
| FutureExecutionReady | All gates pass, not attempted |
| ExecutionAttempted | Attempt behind feature gate (future) |
| ExecutionSucceeded | Never reachable in I-16 normal build |
| ExecutionFailed | Failure behind feature gate (future) |
| CleanupRequired | Cleanup needed before next run |
| CleanupCompleted | Cleanup done |
| Blocked | Hard safety gate violation |

## Future phases

- I-17 — Local Reader Spike Result Capture
- I-16A — Reader Executor Static Safety Audit
