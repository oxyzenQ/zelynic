# I-15A — Feature-Gated Local Reader Spike Preparation

## Status

Experimental branch only. `main` remains stable v3.1.0.

## What I-15A does

I-15A adds a preparation-only model for a future local reader spike. It defines the preparation contract, operator checklist, abort conditions, timeout/event limits, and evidence requirements needed before a future feature-gated event stream reader spike can execute.

This phase is preparation-only. It does not execute any live reader, ring buffer, or kernel event consumer. It depends on the I-15 evidence audit passing before declaring preparation ready.

## What I-15A does NOT do

* No public CLI.
* No normal CI live event read.
* No normal test root requirement.
* No automatic live attach.
* No automatic detach.
* No ring buffer open.
* No live kernel event read.
* No map pin.
* No enforcement.
* No packet drop.
* No block/allow/quota.
* No nft/tc fallback.
* No ledger file write.
* No persistence.
* No fake reader readiness.
* No fake preparation readiness.

## Design constraints

* Preparation-only — not a live reader, not a ring buffer reader.
* Audit readiness from I-15 evidence audit is required before preparation can succeed.
* Feature must remain disabled by default.
* Local lab only.
* Max event and timeout limits are required.
* Post-run evidence capture is required.

## Schema stability

* Existing v3.1 usage JSON schema unchanged.
* Existing v3.1 ledger JSON schema unchanged.
* No version bump.

## Models

* `EbpfEventStreamReaderSpikePrepStatus` — 8 variants: Disabled, AuditNotReady, MissingOperatorConsent, InvalidLimits, PrepReady, PrepRejected, LiveReaderUnsupported, Blocked.
* `EbpfEventStreamReaderSpikePrepStepKind` — 8 variants covering the preparation checklist.
* `EbpfEventStreamReaderSpikePrepStep` — checklist step with id, kind, title, required, completed, manual_only, description.
* `EbpfEventStreamReaderSpikePrepAbortCondition` — abort condition with code, description, blocking.
* `EbpfEventStreamReaderSpikePrepInput` — 21 fields combining I-15 audit report, I-12 reader input, consent, operator label, feature gate, limits, safety flags.
* `EbpfEventStreamReaderSpikePrepPlan` — 24 fields with status, steps, abort conditions, limits, and all operation flags false.

## Preparation readiness criteria

PrepReady requires all of the following:

* I-15 evidence audit indicates `ready_for_reader_spike_preparation=true`.
* Audit report validation passes.
* Explicit reader spike preparation consent is given.
* Operator label is non-empty.
* Feature name is non-empty.
* Feature is expected to be disabled by default.
* Local lab only is true.
* `max_events` is in range [1, 1024].
* `timeout_ms` is in range [1, 60000].
* Clean shutdown is required.
* Post-run evidence capture is required.
* No public CLI requested.
* No live reader allowed.
* No ring buffer open allowed.
* No live event read allowed.
* No map pin allowed.
* No persistence allowed.
* No enforcement allowed.
* No packet drop allowed.

Even when PrepReady, all operation flags remain false: no ring buffer opened, no live event read, no map pin, no enforcement, no packet drop, no mutation, no persistence, no public CLI.

## Next phase

I-16 — Feature-Gated Local Reader Spike Executor Boundary.
