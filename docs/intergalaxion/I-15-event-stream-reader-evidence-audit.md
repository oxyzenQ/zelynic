# I-15 — Event Stream Reader Evidence Audit

## Phase

I-15: Event stream reader evidence audit, audit-only.

## Branch

`intergalaxion` only. `main` remains stable at v3.1.0.

## Summary

Phase I-15 adds an audit-only evidence layer for Intergalaxion event stream reader readiness. This phase audits evidence from I-10F manual lab captures, I-11 event stream read planning, I-12 disabled reader boundary, I-13 fixture decoder bridge, and I-14 reader lab dry run. It decides whether the branch has enough honest evidence to prepare a future feature-gated local reader spike. I-15 is audit-only — it is not a live reader, not a ring buffer reader, and not a kernel event consumer.

## What I-15 adds

* `EbpfEventStreamEvidenceAuditStatus` — 6 variants (Passed, Failed, Warning, Blocked, ReadyForReaderSpikePreparation, NotReady)
* `EbpfEventStreamEvidenceAuditFindingKind` — 8 variants (ManualCapture, ReadPlan, ReaderBoundary, FixtureBridge, DryRun, SafetyInvariant, SchemaInvariant, CliInvariant)
* `EbpfEventStreamEvidenceAuditFinding` — individual finding with code, kind, message, blocking flag, and status
* `EbpfEventStreamEvidenceAuditInput` — combines evidence from I-10F through I-14 with explicit requirements
* `EbpfEventStreamEvidenceAuditReport` — audit outcome with readiness flags, findings, and all operation flags false
* Helper functions: `default_event_stream_evidence_audit_input()`, `evaluate_event_stream_evidence_audit()`, `validate_event_stream_evidence_audit_report()`, `event_stream_evidence_audit_status_label()`, `event_stream_evidence_audit_finding_kind_label()`

## Audit behavior

* Default audit input is safe but not ready for reader spike preparation.
* Default audit report has all operation flags false.
* Audit phase is I-15.
* Audit report is deterministic.
* `ReadyForReaderSpikePreparation` requires all evidence gates to pass.
* Missing clean detach evidence blocks when configured.
* Missing fixture bridge records block when configured.
* Missing dry run completion blocks when configured.
* `ReaderSucceeded` is not treated as readiness in I-15.
* Live event stream read blocks.
* Ring buffer open blocks.
* Map pin blocks.
* Enforcement blocks.
* Packet drop blocks.
* Mutation blocks.
* Persistence blocks.
* Public CLI exposure blocks.
* Schema change flags block.
* Fixture counts are not live kernel event counts.
* No fake audit success.
* No fake reader readiness.

## What I-15 does NOT do

* No normal CI live event read.
* No ring buffer open.
* No live kernel event read.
* No event stream reader start.
* No public CLI exposure.
* No enforcement, no packet drop, no block/allow/quota.
* No nft/tc backend or fallback.
* No map pin.
* No ledger file write.
* No persistence.
* No fake audit success.
* No fake reader readiness.
* No mutation of nft/tc/cgroup/PID state.

## Safety guarantees

* Normal build/test/CI remains rootless and inert.
* No actual BPF object loading.
* No userspace loader API calls.
* No map creation.
* No ring buffer open.
* No live event read.
* No map pin.
* No filesystem read/write.
* No `/proc`, `/sys`, `/sys/fs/bpf` access.
* No OS root/capability check.
* No cgroup mutation.
* No PID mutation.
* No nft/tc mutation.
* No packet drop.
* No block/allow/quota.
* No public CLI.
* No persistence.
* Normal tests remain rootless.

## Existing v3.1 behavior unchanged

* Existing v3.1 usage JSON schema unchanged.
* Existing v3.1 ledger JSON schema unchanged.
* `zelynic --version` remains v3.1.0.
* Ledger inspect/export unchanged.
* Public help unchanged.
* Stable CLI behavior unchanged.

## Audit must not fake

* Audit must not fake reader readiness.
* Audit must not fake live event counts.

## Required evidence

* Clean detach evidence is required when configured.
* Fixture bridge evidence is required when configured.
* Dry run completion is required when configured.
* Fixture counts are not live kernel event counts.

## Next phase

Suggested: I-15A — Feature-Gated Local Reader Spike Preparation.
