# I-13 — Event Stream Fixture Decoder Bridge

## Status

Experimental branch only. This phase is **not** released.

## Branch

`intergalaxion` (branched from stable `main` v3.1.0).

## Summary

Phase I-13 adds a fixture-only event stream decoder bridge for the Intergalaxion
Engine. This phase proves the future reader-to-decoder-to-bridge path using
deterministic in-memory fixture frames only. It does NOT open ring buffers,
NOT read live kernel events, NOT start the event stream reader, NOT expose
public CLI, NOT add enforcement, and NOT fake decoded event success
or fake bridge success.

## Design constraints

- Fixture-only.
- In-memory only.
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
- Fixture decoder must not fake decoded event success.
- Fixture bridge must not fake ledger bridge success.

## Models added

| Model | Purpose |
|---|---|
| `EbpfEventStreamFixtureStatus` | 9-variant enum for fixture bridge state |
| `EbpfEventStreamFixtureMode` | 3-variant enum for fixture mode |
| `EbpfEventStreamFixtureFrame` | Single fixture frame wrapping raw event frame |
| `EbpfEventStreamFixture` | Collection of fixture frames with safety flags |
| `EbpfEventStreamFixtureBridgeReport` | Report from decode+bridge pipeline |

## Pipeline

1. Extract raw frames from fixture.
2. Decode batch using I-4 `decode_raw_event_batch`.
3. Bridge decoded events using I-4 `bridge_event_to_ledger_record`.
4. Aggregate counts and produce bridge report.

## `main` remains stable

`main` remains frozen at v3.1.0. All Intergalaxion work is on the
`intergalaxion` branch only.

## Next suggested phase

I-14 — Event Stream Reader Lab Dry Run, Feature-Gated and Disabled by Default.
