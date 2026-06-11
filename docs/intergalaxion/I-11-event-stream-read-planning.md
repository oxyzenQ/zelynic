# I-11: Event Stream Read Planning

**Phase**: I-11
**Branch**: intergalaxion (experimental)
**Base**: I-10F commit 2fa0c78
**Status**: experimental branch only

## Purpose

I-11 adds a pure planning model for how a future event stream reader
would be allowed, validated, and refused. This phase is planning only
— it does NOT open ring buffers, NOT read live kernel events, NOT
decode a live event stream, NOT expose public CLI, NOT persist anything,
and NOT add enforcement. The reader remains not implemented.

## Constraints

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

## Safety

- Manual capture readiness must come from clean detach evidence.
- Manual capture must not fake event stream readiness.
- Reader remains not implemented in I-11.
- All operation flags must be false for a plan to be valid.
- FutureReadCandidate requires explicit consent and no unsafe flags.

## Models

### EbpfEventStreamReadPlanStatus

Disabled | ManualCaptureNotReady | MissingCleanDetachEvidence | PlanOnly |
FutureReadCandidate | Rejected | UnsupportedTarget | ReaderNotImplemented

### EbpfEventStreamReadMode

PlanningOnly | FutureRingBufferRead | FuturePerfEventRead | Unsupported

### EbpfEventStreamReadPlanReason

code | message | blocking

### EbpfEventStreamReadPlanInput

manual_summary | required_capture_status | read_mode | target_kind |
explicit_event_stream_planning_consent | public_cli_requested | allow_* flags

### EbpfEventStreamReadPlan

status | mode | target_kind | future_read_candidate | reader_implemented |
reasons | manual_summary_ready | clean_detach_required | clean_detach_confirmed |
operation flags (all false in I-11)

## Next Phase

I-12 — Event Stream Reader Boundary, Feature-Gated and Disabled by Default.
