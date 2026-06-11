# I-14 — Event Stream Reader Lab Dry Run

## Phase

I-14: Event stream reader lab dry run, feature-gated and disabled by default.

## Branch

`intergalaxion` only. `main` remains stable at v3.1.0.

## Summary

Phase I-14 adds a feature-gated event stream reader lab dry-run model for the Intergalaxion Engine. This phase rehearses the reader path by combining I-12 reader boundary state and I-13 fixture bridge reports. It is a dry run only — not the real event stream reader, not a ring buffer reader, and not a kernel event consumer.

## What I-14 adds

* `EbpfEventStreamDryRunStatus` — 8 variants (FeatureDisabled, ReaderPlanRejected, FixtureReportRejected, DryRunReady, DryRunCompleted, DryRunFailed, LiveReaderUnsupported, Rejected)
* `EbpfEventStreamDryRunMode` — 3 variants (FixtureOnlyDryRun, ReaderBoundaryDryRun, LiveReaderUnsupported)
* `EbpfEventStreamDryRunInput` — combines I-12 reader input/result and I-13 fixture bridge report with explicit safety flags
* `EbpfEventStreamDryRunResult` — deterministic dry-run outcome with fixture counts and all operation flags false
* Helper functions: `default_event_stream_dry_run_input()`, `evaluate_event_stream_dry_run()`, `validate_event_stream_dry_run_result()`, `event_stream_dry_run_status_label()`, `event_stream_dry_run_mode_label()`

## Dry run behavior

* Feature disabled returns `FeatureDisabled` immediately.
* Dry run requires `explicit_dry_run_feature_enabled=true`.
* Dry run requires non-empty operator label.
* Dry run requires reader result validation to pass.
* Dry run requires fixture bridge report validation to pass.
* Dry run requires fixture report `fixture_only=true`.
* Dry run requires reader result not to be `ReaderSucceeded`.
* Dry run requires reader result not to have `live_event_stream_read=true`.
* Dry run rejects `allow_live_reader=true` in I-14.
* Dry run rejects `allow_ring_buffer_open=true`.
* Dry run rejects `allow_live_event_read=true`.
* Dry run rejects `allow_map_pin=true`.
* Dry run rejects `allow_persistence=true`.
* `DryRunCompleted` may report fixture counts, but must not claim live reader success.
* `reported_events_read` equals `fixture_frames_decoded` only when `allow_fixture_counts=true`.
* `reported_decode_errors` equals `fixture_decode_errors` only when `allow_fixture_counts=true`.
* `reported_bridge_records` equals `fixture_bridge_records` only when `allow_fixture_counts=true`.

## Fixture count reporting

Fixture counts are not live kernel event counts. When `allow_fixture_counts=true`, the dry run reports the decoded frame count, decode error count, and bridge record count from the I-13 fixture bridge report. These counts originate from deterministic in-memory fixture data only. No ring buffer is opened, no live kernel events are read, and no reader is started.

## What I-14 does NOT do

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
* No fake live reader success.
* No fake live event counts from fixture counts.
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

## Dry run must not fake

* Dry run must not fake live reader success.
* Dry run must not fake live event counts.

## Next phase

Suggested: I-15 — Event Stream Reader Evidence Audit, or I-15A — Feature-Gated Local Reader Spike Preparation.
