# I-10A — Final Static Safety Audit Before Real Live Attach

## Scope

I-10A is experimental branch only. `main` remains stable v3.1.0.

## What I-10A defines

- Final static safety audit **model only**.
- Verifies I-0 through I-9 remain safe, inert, hidden, and model-only.
- Prepares the branch for a later I-10B or I-10 real live attach spike, but does not perform that spike.

## What I-10A does NOT do

- No real live attach.
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

- I-9 executor remains disabled.
- I-8 attach plan remains plan-only.
- I-7 loader boundary remains disabled by default.
- All phases I-0 through I-9 are audited for safety invariants.

## Next phase

I-10B — Explicit Local Live Attach Spike, Hard-Gated.
