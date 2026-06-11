# I-3 — eBPF Event Schema and Ring Buffer Model

## Phase

I-3 (experimental branch only). `main` remains stable v3.1.0.

## Scope

I-3 defines event schema and ring-buffer model only.

## What I-3 adds

- `EbpfObserverEvent` — pure observer event schema (event_id, kind, timestamp,
  pid, tgid, uid, cgroup_id, socket_cookie, interface_index, rx/tx bytes,
  packet count, direction, verdict, source).
- `EbpfTrafficDirection` — Unknown, Rx, Tx.
- `EbpfObserverVerdict` — ObservedOnly, NoDecision, DroppedUnsupported.
  `DroppedUnsupported` means "this model does not support packet drops",
  not that a packet was dropped.
- `EbpfEventSource` — Model, RingBufferPlanned, KernelLiveUnsupported.
- `EbpfEventBatch` — batch of events with truncated flag and decode errors.
- `EbpfEventBatchSummary` — deterministic summary (event count, totals,
  truncated, decode error count).
- `EbpfRingBufferPlan` — model-only ring buffer plan (map name, max entries,
  all operation flags default false).
- `EbpfRingBufferConsumerState` — model-only consumer state.
- Helper functions: `default_observer_event`, `validate_observer_event`,
  `default_ring_buffer_plan`, `validate_ring_buffer_plan`,
  `summarize_event_batch`.

## Safety guarantees

- Ring buffer plan defaults: consumer_enabled false, kernel_open_enabled
  false, map_create_enabled false, map_pin_enabled false, attach_required
  false, root_required_for_tests false, mutation_enabled false.
- Event verdict never claims packet drop support.
- Event schema is observer-only.
- Batch summary is deterministic.
- No actual kernel operation.

## What I-3 does NOT do

- no eBPF attach
- no eBPF program load
- no eBPF map create
- no ring buffer open
- no map pin
- no packet drop
- no enforcement
- no block/allow/quota
- no nft/tc fallback
- no public CLI
- no kernel mutation

## Continuity

- I-0 engine skeleton remains unchanged.
- I-1 capability detector remains read-only.
- I-2 probe plan remains attach-disabled.
- Version remains v3.1.0.
- No changes to stable CLI behavior or ledger JSON schemas.

## Next phase

I-4 — In-Memory Event Decoder and Ledger Bridge Model.
