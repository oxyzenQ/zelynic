# I-8 — Safe Attach Plan, No Attach Yet

## Scope

I-8 is experimental branch only. `main` remains stable v3.1.0.

## What I-8 defines

- Attach planning **model only** (no live attach).
- Defines how a future attach operation would be planned and audited.
- Three attach target kinds: socket filter, cgroup skb, tracepoint.

## What I-8 does NOT do

- No live attach.
- No userspace loader implementation.
- No eBPF program load.
- No eBPF map create.
- No ring buffer open.
- No live kernel event read.
- No map pin.
- No packet drop.
- No enforcement.
- No block/allow/quota.
- No nft/tc fallback.
- No public CLI.
- No kernel mutation.
- No ledger file write.
- No persistence.

## Existing schemas unchanged

- Existing v3.1 usage JSON schema unchanged.
- Existing v3.1 ledger JSON schema unchanged.

## Relationship to prior phases

- I-7 loader boundary remains disabled by default.
- I-6 program skeleton remains source-only / compile-only.
- I-5 readiness gate provides readiness evaluation.
- Future attach candidate requires: loader future_load_candidate=true, safe skeleton set, safe target, explicit consent, rollback required, no public CLI.

## Next phase

I-9 — First Live Observer Attach, Explicit Gate Only.
