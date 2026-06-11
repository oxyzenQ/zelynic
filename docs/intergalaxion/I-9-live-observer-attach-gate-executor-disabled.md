# I-9 — Live Observer Attach Gate, Executor Disabled

## Scope

I-9 is experimental branch only. `main` remains stable v3.1.0.

## What I-9 defines

- Live observer attach gate **model only**.
- Explicit consent bundle for live observer attach.
- Preflight evaluation combining all prior phase models.
- Disabled executor seam — always refuses.

## What I-9 does NOT do

- No real live attach yet.
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

- I-8 attach plan remains plan-only.
- I-7 loader boundary remains disabled by default.
- Future live attach candidate requires all prior phases safe plus full consent bundle.

## Next phase

I-10A — Final Static Safety Audit Before Real Live Attach.
