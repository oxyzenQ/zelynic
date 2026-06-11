# I-10B — Explicit Local Live Attach Spike Runbook and Hard Gate Contract

## Scope

I-10B is experimental branch only. `main` remains stable v3.1.0.

## What I-10B defines

- Live attach spike runbook and hard gate contract **model only**.
- Deterministic operator checklist for future local-lab-only attach spike.
- Abort conditions that force immediate termination.

## What I-10B does NOT do

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

## Hard gate contract

- Future live attach spike must be local lab only.
- Future live attach spike must have explicit operator label.
- Future live attach spike must have cleanup plan.
- Future live attach spike must acknowledge root requirement.

## Relationship to prior phases

- I-10A static audit remains the final safety checkpoint.
- I-9 executor remains disabled.
- Runbook defines the human-operator checklist above all model layers.

## Next phase

I-10C — Minimal Live Attach Executor Spike, Explicit Local Lab Only.
