# I-17 — Local Reader Spike Result Capture

**Phase**: I-17
**Status**: Experimental branch only
**Branch**: `intergalaxion`
**Base**: I-16 (commit `8e12ce5`)

## Overview

I-17 adds a local reader spike result capture model for the Intergalaxion Engine.
This phase captures and validates the result of a future feature-gated local reader
spike. It consumes the I-16 executor result and I-16A executor audit report.

I-17 is **capture-only** — it is not a live reader, not a ring buffer reader, not a
kernel event consumer. The normal build/test/CI remains rootless and inert.

## Design Constraints

* I-17 is experimental branch only.
* `main` remains stable v3.1.0.
* I-17 is local reader spike result capture only.
* Capture-only.
* No public CLI.
* No normal CI live event read.
* No normal test root requirement.
* No automatic live attach.
* No automatic detach.
* No automatic reader execution.
* No ring buffer open from normal build.
* No live kernel event read from normal build.
* No map pin.
* No enforcement.
* No packet drop.
* No block/allow/quota.
* No nft/tc fallback.
* No ledger file write.
* No persistence.
* Existing v3.1 usage JSON schema unchanged.
* Existing v3.1 ledger JSON schema unchanged.
* ExecutionSucceeded is never produced by normal build evaluation.
* Fake reader execution success must be rejected (fake reader execution success rejected).
* Fake live event counts must be rejected (fake live event counts rejected).
* No fake result capture success.

## Models

### EbpfEventStreamReaderSpikeResultStatus

| Variant | Description |
|---|---|
| NotRun | Reader spike was not run |
| FeatureDisabled | Feature is disabled |
| PrepRejected | Preparation was rejected |
| ExecutorDisabled | Executor is disabled |
| ReaderNotImplemented | Reader is not yet implemented |
| FutureExecutionReady | All gates pass; future execution ready |
| ExecutionAttempted | Execution was attempted |
| ExecutionSucceeded | Execution succeeded (captured status only) |
| ExecutionFailed | Execution failed |
| CleanupRequired | Cleanup is required |
| CleanupCompleted | Cleanup completed |
| CleanupFailed | Cleanup failed |
| InvalidCapture | Capture is invalid or inconsistent |

### EbpfEventStreamReaderSpikeEvidenceLevel

| Variant | Description |
|---|---|
| None | No evidence captured |
| OperatorReported | Operator-reported evidence only |
| ExecutorResultCaptured | Executor result captured |
| CleanupEvidenceCaptured | Cleanup evidence captured |
| AuditReady | Full audit-ready evidence |

### EbpfEventStreamReaderSpikeRecommendation

| Variant | Description |
|---|---|
| Stop | Stop and do not proceed |
| FixPreparation | Fix preparation before proceeding |
| FixExecutor | Fix executor before proceeding |
| CaptureCleanupEvidence | Capture cleanup evidence |
| RetryLocalLab | Retry the local lab run |
| ReadyForReaderSpikeReview | Ready for reader spike review |

### EbpfEventStreamReaderSpikeResultCapture

Captures the full result of a local reader spike: executor result, audit report,
operator labels, safety flags, evidence level, and recommendation.

### EbpfEventStreamReaderSpikeResultSummary

Aggregates multiple captures with deterministic status counting and
readiness determination.

## Behavior

* Default capture is NotRun.
* Default capture phase is I-17.
* Default capture has all operation flags false.
* Capture from FeatureDisabled executor result maps to FeatureDisabled.
* Capture from PrepRejected maps to PrepRejected.
* Capture from ExecutorDisabled maps to ExecutorDisabled.
* Capture from ReaderNotImplemented maps to ReaderNotImplemented.
* Capture from FutureExecutionReady maps to FutureExecutionReady with consistency checks.
* Capture from ExecutionAttempted maps to ExecutionAttempted only when attempted=true.
* Capture from ExecutionSucceeded maps to ExecutionSucceeded only when internally consistent.
* Capture from ExecutionFailed maps to ExecutionFailed when attempted=true.
* CleanupCompleted requires cleanup_required=true and cleanup_completed=true.
* FutureExecutionReady must not have attempted=true, reader_started=true, reader_completed=true,
  events_read>0, decode_errors>0, or bridge_records>0.
* Fake reader success detected when ExecutionSucceeded without consistent execution flags.
* Fake live event counts detected when counts are positive but live_event_stream_read=false.

## Validation

Both capture and summary validation reject unsafe flags:
public_cli_exposed, map_pin_performed, enforcement_performed, packet_drop_performed,
mutation_performed, persistence_performed, fake_reader_success_detected,
fake_live_event_counts_detected.

## Safety

* No actual BPF object loading.
* No userspace loader API calls.
* No map creation.
* No ring buffer open from code.
* No live event read from code.
* No map pin from code.
* No filesystem read/write.
* No /proc, /sys, /sys/fs/bpf access.
* No OS root/capability check.
* No cgroup mutation.
* No PID mutation.
* No nft/tc mutation.
* No packet drop.
* No block/allow/quota.
* No public CLI.
* No persistence.
* Normal tests remain rootless.

## Next Phase

Future phase can be I-18 — Reader Spike Result Audit and Release Decision Gate.
