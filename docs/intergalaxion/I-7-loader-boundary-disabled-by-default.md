# I-7 — Loader Boundary, Disabled by Default

## Scope

I-7 is experimental branch only. `main` remains stable v3.1.0.

## What I-7 defines

- Loader boundary **model only** (no userspace loader implementation).
- Loader is **disabled by default** and always disabled in I-7.
- Defines what a future loader would require and what it would refuse.

## What I-7 does NOT do

- No userspace loader implementation.
- No eBPF program load.
- No eBPF attach.
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

- I-6 program skeleton remains source-only / compile-only.
- I-5 readiness gate is used as input to loader boundary evaluation.
- I-6 skeleton set is used as input to loader boundary evaluation.

## Next phase

I-8 — Safe Attach Plan, No Attach Yet.
