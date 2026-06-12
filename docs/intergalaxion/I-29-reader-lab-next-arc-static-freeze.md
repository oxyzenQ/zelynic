# I-29 — Reader Lab Next Arc Static Freeze

## Phase

I-29 (Intergalaxion Engine)

## Purpose

Consumes I-27 entry gate report and I-28 review pack evidence to produce a
deterministic static freeze record. The static freeze locks the selected next
arc as frozen within the experimental branch, confirming that no release,
no public CLI, no enforcement, no live reader, and no kernel mutation has
occurred or is planned.

## Evidence consumed

| Evidence | Source Phase | Key field |
|---|---|---|
| EbpfReaderLabNextArcEntryGateReport | I-27 | entry_ready |
| EbpfReaderLabNextArcReviewPack | I-28 | review_ready |

## Types

| Type | Variants / Fields |
|---|---|
| EbpfReaderLabNextArcStaticFreezeStatus | Draft, Incomplete, Blocked, Frozen, FreezeRejected, ExperimentalOnly, ReleaseForbidden |
| EbpfReaderLabNextArcStaticFreezeDecision | Stop, KeepExperimental, FreezeFixtureOnlyArc, FreezeStaticPolicyArc, FreezeManualReaderSpikeChecklistArc, FreezeReaderSpikeReviewArc, RejectLiveReaderArc, RejectPublicCliArc, RejectReleaseArc, RejectEnforcementArc |
| EbpfReaderLabNextArcStaticFreezeFindingKind | NextArcEntryGate, NextArcReviewPack, ReleaseInvariant, CliInvariant, SchemaInvariant, RuntimeInvariant, KernelInvariant, MutationInvariant, FakeEvidenceInvariant, FreezeInvariant |
| EbpfReaderLabNextArcStaticFreezeFinding | code, kind, message, blocking, status |
| EbpfReaderLabNextArcStaticFreezeInput | 13 fields (2 evidence + 3 require + 2 schema + 5 request + 1 public_cli) |
| EbpfReaderLabNextArcStaticFreezeRecord | ~43 fields including freeze_passed, frozen arcs, fake flags |

## Helper functions

1. default_reader_lab_next_arc_static_freeze_input
2. build_reader_lab_next_arc_static_freeze_record
3. validate_reader_lab_next_arc_static_freeze_record
4. reader_lab_next_arc_static_freeze_status_label
5. reader_lab_next_arc_static_freeze_decision_label
6. reader_lab_next_arc_static_freeze_finding_kind_label

## Freeze priority

When multiple safe arcs are selected in the I-28 review pack, the freeze decision
follows this priority order:

1. FreezeStaticPolicyArc
2. FreezeFixtureOnlyArc
3. FreezeManualReaderSpikeChecklistArc
4. FreezeReaderSpikeReviewArc

## Hard rules

- release_allowed is always false
- must_remain_experimental is always true
- No live reader, no ring buffer, no enforcement, no mutation
- No nft/tc, no kernel changes, no new CLI commands
- No version bump, no tags, no publish, no main merge

## Frozen conditions

Both evidence records must validate successfully, experimental-only must be
confirmed, at least one safe frozen arc must be true, all forbidden arc
allowances must be false, all 12 fake detection flags must be false, and all
operation flags must be false.

## Fake detection flags

- fake_reader_success_detected
- fake_live_event_counts_detected
- fake_release_readiness_detected
- fake_planning_success_detected
- fake_policy_freeze_success_detected
- fake_policy_review_success_detected
- fake_policy_hardening_success_detected
- fake_policy_completion_success_detected
- fake_completion_review_success_detected
- fake_next_arc_entry_success_detected
- fake_next_arc_review_success_detected
- fake_next_arc_static_freeze_success_detected

## Testing

See tests_i29.rs for 76 tests covering input safety, frozen arc priority,
release invariants, schema invariants, operation flags, fake evidence detection,
evidence validation, label stability, and validation rejection.
