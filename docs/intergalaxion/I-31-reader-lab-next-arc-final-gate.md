# I-31 — Reader Lab Next Arc Final Gate

**Phase**: I-31 (Intergalaxion Engine)
**Branch**: intergalaxion (experimental)
**Base**: main stable v3.1.0

## Purpose

Consumes I-27 next arc entry gate report, I-28 next arc review pack, I-29
next arc static freeze record, and I-30 next arc freeze review pack evidence
to produce a deterministic final gate report. Final gate only, not a release,
not a live reader, not a ring buffer reader. Internal deterministic final
gate checkpoint only.

## Scope

next-arc-final-gate only. Not a release. Not a public feature. Not a live
reader. Not a ring buffer reader. Not a kernel event consumer. It is an
internal deterministic final gate checkpoint only.

## Evidence Consumed

1. I-27 EbpfReaderLabNextArcEntryGateReport
2. I-28 EbpfReaderLabNextArcReviewPack
3. I-29 EbpfReaderLabNextArcStaticFreezeRecord
4. I-30 EbpfReaderLabNextArcFreezeReviewPack

## Types

1. EbpfReaderLabNextArcFinalGateStatus (7 variants)
2. EbpfReaderLabNextArcFinalDecision (10 variants)
3. EbpfReaderLabNextArcFinalFindingKind (12 variants)
4. EbpfReaderLabNextArcFinalFinding (5 fields)
5. EbpfReaderLabNextArcFinalGateInput (17 fields)
6. EbpfReaderLabNextArcFinalGateReport (50 fields)

## Helper Functions

- default_reader_lab_next_arc_final_gate_input()
- build_reader_lab_next_arc_final_gate_report()
- validate_reader_lab_next_arc_final_gate_report()
- reader_lab_next_arc_final_gate_status_label()
- reader_lab_next_arc_final_decision_label()
- reader_lab_next_arc_final_finding_kind_label()

## Final Decision Priority

1. FinalizeStaticPolicyArc
2. FinalizeFixtureOnlyArc
3. FinalizeManualReaderSpikeChecklistArc
4. FinalizeReaderSpikeReviewArc

## Hard Rules

- I-31 is experimental branch only.
- main remains stable v3.1.0.
- I-31 is reader lab next arc final gate only.
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
- existing v3.1 usage JSON schema unchanged.
- existing v3.1 ledger JSON schema unchanged.
- release_allowed is always false.
- must_remain_experimental is always true.
- live reader arc is not allowed.
- public CLI arc is not allowed.
- release arc is not allowed.
- enforcement arc is not allowed.
- fake reader execution success must be rejected.
- fake live event counts must be rejected.
- fake release readiness must be rejected.
- fake planning success must be rejected.
- fake static policy freeze success must be rejected.
- fake static policy review success must be rejected.
- fake static policy hardening success must be rejected.
- fake policy freeze completion success must be rejected.
- fake completion review success must be rejected.
- fake next arc entry success must be rejected.
- fake next arc review success must be rejected.
- fake next arc static freeze success must be rejected.
- fake next arc freeze review success must be rejected.
- fake next arc final gate success must be rejected.

## Testing

See tests_i31.rs for comprehensive deterministic test coverage (75+ tests).
