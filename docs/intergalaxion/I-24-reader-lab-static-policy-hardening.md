# I-24 — Reader Lab Static Policy Hardening

## Phase Summary

I-24 is reader lab static policy hardening only.

This phase hardens the I-21 next arc plan, I-22 static policy freeze, and I-23 static policy review pack by adding deterministic invariant checks and contradiction detection. It confirms that all three evidence layers agree on safety invariants.

## Scope

- static-policy-hardening only.
- not a release.
- no tag.
- no release.
- no publish.
- no version bump.
- no main merge.
- no public CLI.
- no normal CI live event read.
- no normal test root requirement.
- no automatic live attach.
- no automatic detach.
- no automatic reader execution.
- no ring buffer open.
- no live kernel event read.
- no map pin.
- no enforcement.
- no packet drop.
- no block/allow/quota.
- no nft/tc fallback.
- no ledger file write.
- no persistence.
- no fake static policy hardening success.

## Invariants

- main remains stable v3.1.0.
- intergalaxion remains experimental.
- existing v3.1 usage JSON schema unchanged.
- existing v3.1 ledger JSON schema unchanged.
- release_allowed is always false.
- must_remain_experimental is always true.
- live reader next is not allowed.
- public CLI next is not allowed.
- release path next is not allowed.
- public CLI remains clean.
- no enforcement exists.
- no packet drop exists.
- no map pin exists.
- no persistence exists.

## Contradiction Detection

- contradictions between I-21 I-22 I-23 must be rejected.
- any evidence layer claiming release_allowed=true must be rejected.
- any evidence layer claiming must_remain_experimental=false must be rejected.
- any evidence layer claiming live_reader_next_allowed=true must be rejected.
- any evidence layer claiming public_cli_next_allowed=true must be rejected.
- any evidence layer claiming release_path_next_allowed=true must be rejected.

## Fake Evidence Rejection

- fake reader execution success must be rejected.
- fake live event counts must be rejected.
- fake release readiness must be rejected.
- fake planning success must be rejected.
- fake static policy freeze success must be rejected.
- fake static policy review success must be rejected.
- fake static policy hardening success must be rejected.

## Models Added

- EbpfReaderLabStaticPolicyHardeningStatus (7 variants)
- EbpfReaderLabStaticPolicyHardeningDecision (8 variants)
- EbpfReaderLabStaticPolicyHardeningFindingKind (12 variants)
- EbpfReaderLabStaticPolicyHardeningFinding (5 fields)
- EbpfReaderLabStaticPolicyHardeningInput (16 fields)
- EbpfReaderLabStaticPolicyHardeningReport (42 fields)

## Next Phase

Future phase can be I-25 — Reader Lab Policy Freeze Completion Gate, or I-24A — Static Policy Hardening Matrix Freeze.
