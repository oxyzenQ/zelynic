# I-28 — Reader Lab Next Arc Review Pack

## Phase

I-28 is experimental branch only.

## Scope

I-28 is reader lab next arc review pack only.

This phase consumes evidence from I-21, I-22, I-23, I-24, I-25, I-26, and I-27 to produce a deterministic internal review pack that summarizes whether the selected next arc entry is safe, experimental-only, release-forbidden, and still no-live-reader by default.

It reviews:

- selected fixture-only arc
- selected static-policy arc
- selected manual reader spike checklist arc
- selected reader spike review arc
- rejected live reader arc
- rejected public CLI arc
- rejected release arc
- rejected enforcement arc

## Constraints

next-arc-review-pack only.

not a release.

no tag.

no release.

no publish.

no version bump.

no main merge.

no public CLI.

no normal CI live event read.

no normal test root requirement.

no automatic live attach.

no automatic detach.

no automatic reader execution.

no ring buffer open.

no live kernel event read.

no map pin.

no enforcement.

no packet drop.

no block/allow/quota.

no nft/tc fallback.

no ledger file write.

no persistence.

existing v3.1 usage JSON schema unchanged.

existing v3.1 ledger JSON schema unchanged.

## Invariants

release_allowed is always false.

must_remain_experimental is always true.

live reader arc is not allowed.

public CLI arc is not allowed.

release arc is not allowed.

enforcement arc is not allowed.

## Contradictions

contradictions between I-21 I-22 I-23 I-24 I-25 I-26 I-27 must be rejected.

## Fake Evidence

fake reader execution success must be rejected.

fake live event counts must be rejected.

fake release readiness must be rejected.

fake planning success must be rejected.

fake static policy freeze success must be rejected.

fake static policy review success must be rejected.

fake static policy hardening success must be rejected.

fake policy freeze completion success must be rejected.

fake completion review success must be rejected.

fake next arc entry success must be rejected.

fake next arc review success must be rejected.

## Next Phase

Future phase can be I-29 — Reader Lab Next Arc Static Freeze, or I-28A — Next Arc Review Matrix Freeze.
