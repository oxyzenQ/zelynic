# I-21 — Reader Lab Next Arc Planning

## Status

Experimental branch only. `main` remains stable v3.1.0.

## Phase Summary

I-21 is reader lab next arc planning only. It is planning-only. It is not a release. It adds a deterministic planning model for the next Intergalaxion reader lab arc after the I-20 milestone freeze.

## Constraints

* Planning-only — not a release, not a public feature.
* No tag.
* No release.
* No publish.
* No version bump.
* No main merge.
* No public CLI.
* No normal CI live event read.
* No normal test root requirement.
* No automatic live attach.
* No automatic detach.
* No automatic reader execution.
* No ring buffer open.
* No live kernel event read.
* No map pin.
* No enforcement.
* No packet drop.
* No block/allow/quota.
* No nft/tc fallback.
* No ledger file write.
* No persistence.

## Invariants

* Existing v3.1 usage JSON schema unchanged.
* Existing v3.1 ledger JSON schema unchanged.
* release_allowed is always false.
* must_remain_experimental is always true.
* Live reader next is not allowed in I-21.
* Public CLI next is not allowed in I-21.
* Release path next is not allowed in I-21.

## Fake Detection

* Fake reader execution success must be rejected.
* Fake live event counts must be rejected.
* Fake release readiness must be rejected.
* Fake planning success must be rejected.

## Next Phase

I-22 — Reader Lab Static Policy Freeze, or I-21A — Next Arc Review Pack.
