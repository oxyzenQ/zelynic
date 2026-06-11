# I-4 — In-Memory Event Decoder and Ledger Bridge Model

## Phase

I-4 (experimental branch only). `main` remains stable v3.1.0.

## Scope

I-4 defines in-memory event decoder and ledger bridge model only.

## What I-4 adds

- `EbpfRawEventFrame` — raw event frame model (frame_id, source, payload,
  decode_source_label).
- `EbpfDecodedEventFrame` — decoded frame with typed `EbpfObserverEvent`.
- `EbpfDecodeMode` — ModelOnly, StrictFixture, KernelLiveUnsupported.
- `EbpfDecodeReport` — batch decode report (frames seen/decoded, errors,
  events, safety flags).
- `IntergalaxionLedgerBridgeRecord` — internal bridge record from observer
  event to ledger model (bridge_id, bytes, identity, attribution, provenance).
- `IntergalaxionLedgerBridgeBatch` — batch of bridge records (source, records,
  skipped events, errors, safety flags).
- Helper functions: `decode_raw_event_frame`, `decode_raw_event_batch`,
  `bridge_event_to_ledger_record`, `bridge_event_batch_to_ledger_records`,
  `validate_bridge_record`.

## Safety guarantees

- Decoder is in-memory only: no ring buffer open, no live kernel event read.
- Decoder does not use aya live APIs.
- Decoder does not require root.
- Bridge does not write ledger files.
- Bridge does not persist anything.
- Bridge does not modify existing v3.1 ledger JSON schema.
- Bridge records are internal Intergalaxion model records only.
- Bridge record `read_only` is always true.
- Bridge record `enforcement_status` is always "inactive/not implemented".
- Bridge record `combined_bytes` equals `rx_bytes + tx_bytes` (saturating).
- No actual kernel operation.

## What I-4 does NOT do

- no eBPF attach
- no eBPF program load
- no eBPF map create
- no ring buffer open
- no live kernel event read
- no map pin
- no packet drop
- no enforcement
- no block/allow/quota
- no nft/tc fallback
- no public CLI
- no kernel mutation
- no ledger file write
- no persistence

## Continuity

- I-0 engine skeleton remains unchanged.
- I-1 capability detector remains read-only.
- I-2 probe plan remains attach-disabled.
- I-3 ring buffer plan remains model-only.
- Existing v3.1 ledger JSON schema is unchanged.
- Bridge record is internal Intergalaxion model, not public ledger export.
- Version remains v3.1.0.
- No changes to stable CLI behavior.

## Next phase

I-5 — Live-Readiness Gate for Optional Observer Attach Planning.
