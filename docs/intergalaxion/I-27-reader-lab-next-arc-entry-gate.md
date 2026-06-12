# I-27 — Reader Lab Next Arc Entry Gate

I-27 is reader lab next arc entry gate only.

I-27 is experimental branch only. main remains stable v3.1.0.

## Purpose

Phase I-27 decides whether the next reader-lab arc may begin as an internal experimental-only planning/checklist/static-review arc. It consumes evidence from I-21 (next arc plan), I-22 (static policy freeze), I-23 (static policy review pack), I-24 (static policy hardening), I-25 (policy freeze completion gate), and I-26 (completion review pack).

## Safety constraints

I-27 is next-arc-entry-gate only. It is not a release.

- no tag
- no release
- no publish
- no version bump
- no main merge
- no public CLI
- no normal CI live event read
- no ring buffer open
- no live kernel event read
- no map pin
- no enforcement
- no packet drop
- no block/allow/quota
- no nft/tc fallback
- no ledger file write
- no persistence

## Schema stability

- existing v3.1 usage JSON schema unchanged
- existing v3.1 ledger JSON schema unchanged

## Invariants

- release_allowed is always false
- must_remain_experimental is always true

## Disallowed arc entries

- live reader arc is not allowed
- public CLI arc is not allowed
- release arc is not allowed
- enforcement arc is not allowed

## Contradiction detection

- contradictions between I-21 I-22 I-23 I-24 I-25 I-26 must be rejected

## Fake evidence rejection

- fake reader execution success must be rejected
- fake live event counts must be rejected
- fake release readiness must be rejected
- fake planning success must be rejected
- fake static policy freeze success must be rejected
- fake static policy review success must be rejected
- fake static policy hardening success must be rejected
- fake policy freeze completion success must be rejected
- fake completion review success must be rejected
- fake next arc entry success must be rejected

## Allowed next-arc entry choices

- StartFixtureOnlyArc
- StartStaticPolicyArc
- StartManualReaderSpikeChecklistArc
- StartReaderSpikeReviewArc

## Priority ordering

When multiple safe preferences are selected:

1. StartStaticPolicyArc
2. StartFixtureOnlyArc
3. StartManualReaderSpikeChecklistArc
4. StartReaderSpikeReviewArc
