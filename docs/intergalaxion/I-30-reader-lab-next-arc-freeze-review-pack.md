# I-30 — Reader Lab Next Arc Freeze Review Pack

## Phase

I-30 (Intergalaxion Engine)

## Purpose

Consumes I-27 entry gate report, I-28 review pack, and I-29 static freeze
record evidence to produce a deterministic freeze review pack. The freeze
review pack confirms whether the selected safe next arc was frozen correctly
while preserving experimental-only state, release-forbidden state, and all
safety invariants.

## Scope

I-30 is next-arc-freeze-review-pack only. It is not a release. It is not a
public feature. It is not a live reader. It is not a ring buffer reader. It
is an internal deterministic review checkpoint only.

## Evidence consumed

| Evidence | Source Phase | Key field |
|---|---|---|
| EbpfReaderLabNextArcEntryGateReport | I-27 | entry_ready |
| EbpfReaderLabNextArcReviewPack | I-28 | review_ready |
| EbpfReaderLabNextArcStaticFreezeRecord | I-29 | freeze_passed |

## Types

| Type | Variants / Fields |
|---|---|
| EbpfReaderLabNextArcFreezeReviewPackStatus | Draft, Incomplete, Blocked, ReviewReady, ReviewRejected, ExperimentalOnly, ReleaseForbidden |
| EbpfReaderLabNextArcFreezeReviewDecision | Stop, KeepExperimental, ReviewFrozenFixtureOnlyArc, ReviewFrozenStaticPolicyArc, ReviewFrozenManualReaderSpikeChecklistArc, ReviewFrozenReaderSpikeReviewArc, RejectLiveReaderArc, RejectPublicCliArc, RejectReleaseArc, RejectEnforcementArc |
| EbpfReaderLabNextArcFreezeReviewFindingKind | NextArcEntryGate, NextArcReviewPack, NextArcStaticFreeze, ReleaseInvariant, CliInvariant, SchemaInvariant, RuntimeInvariant, KernelInvariant, MutationInvariant, FakeEvidenceInvariant, ReviewInvariant |
| EbpfReaderLabNextArcFreezeReviewFinding | code, kind, message, blocking, status |
| EbpfReaderLabNextArcFreezeReviewPackInput | 15 fields (3 evidence + 3 require + 1 experimental + 2 schema + 5 request + 1 public_cli) |
| EbpfReaderLabNextArcFreezeReviewPack | 47 fields including review_ready, frozen arcs, 13 fake flags |

## Helper functions

1. default_reader_lab_next_arc_freeze_review_pack_input
2. build_reader_lab_next_arc_freeze_review_pack
3. validate_reader_lab_next_arc_freeze_review_pack
4. reader_lab_next_arc_freeze_review_pack_status_label
5. reader_lab_next_arc_freeze_review_decision_label
6. reader_lab_next_arc_freeze_review_finding_kind_label

## Review priority

When multiple frozen safe arcs are selected, the review decision follows
this priority order:

1. ReviewFrozenStaticPolicyArc
2. ReviewFrozenFixtureOnlyArc
3. ReviewFrozenManualReaderSpikeChecklistArc
4. ReviewFrozenReaderSpikeReviewArc

## Hard rules

- release_allowed is always false
- must_remain_experimental is always true
- No live reader, no ring buffer, no enforcement, no mutation
- No nft/tc, no kernel changes, no new CLI commands
- No version bump, no tags, no publish, no main merge
- No fake next arc freeze review success
- No fake next arc static freeze success
- No fake next arc review success
- No fake next arc entry success
- No fake release readiness
- No fake live event counts
- No fake reader execution success
- No fake planning success
- No fake static policy freeze success
- No fake static policy review success
- No fake static policy hardening success
- No fake policy freeze completion success
- No fake completion review success
- No tag/release/publish/version/main merge
- No public CLI
- No normal CI live event read
- No ring buffer open
- No live kernel event read
- No map pin
- No enforcement, no packet drop, no block/allow/quota
- No nft/tc fallback
- No ledger file write/persistence
- Existing v3.1 usage JSON schema unchanged
- Existing v3.1 ledger JSON schema unchanged
- Live reader arc is not allowed
- Public CLI arc is not allowed
- Release arc is not allowed
- Enforcement arc is not allowed

## Testing

See tests_i30.rs for tests covering input safety, ReviewReady with frozen arcs,
priority ordering, release invariants, schema invariants, operation flags,
fake evidence detection across 3 evidence types, evidence validation,
label stability, validation rejection, and source integrity.
