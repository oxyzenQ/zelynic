# I-5 — Live-Readiness Gate for Optional Observer Attach Planning

**Branch**: intergalaxion (experimental)
**Base**: stable v3.1.0 on main
**Status**: model-only, no live kernel operations

## Purpose

I-5 defines a pure model-only readiness gate that combines I-1 capability
detection, I-2 probe plan safety, I-3 event/ring-buffer model safety, and
I-4 decoder/ledger bridge safety. This phase decides whether a future
observer attach could be planned later, but it must NOT perform attach.

## Safety guarantees

* I-5 is experimental branch only.
* main remains stable v3.1.0.
* I-5 defines model-only live-readiness gate.
* no eBPF attach.
* no eBPF program load.
* no eBPF map create.
* no ring buffer open.
* no live kernel event read.
* no map pin.
* no packet drop.
* no enforcement.
* no block/allow/quota.
* no nft/tc fallback.
* no public CLI.
* no kernel mutation.
* no ledger file write.
* no persistence.
* existing v3.1 usage JSON schema unchanged.
* existing v3.1 ledger JSON schema unchanged.

## Models added

* IntergalaxionReadinessLevel (Blocked / ModelOnly / ObserverCandidate /
  FutureAttachPlanningCandidate)
* IntergalaxionReadinessReason
* IntergalaxionReadinessInput
* IntergalaxionReadinessGate

## Behavior

I-5 only decides whether future attach planning could be considered later.
All operation flags in the gate output remain false. The evaluator is
pure and deterministic.

## Next phase

I-6 — eBPF Program Skeleton, Compile-Only.
