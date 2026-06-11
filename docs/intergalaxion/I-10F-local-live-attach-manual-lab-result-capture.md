# I-10F: Local Live Attach Manual Lab Result Capture

**Phase**: I-10F
**Branch**: intergalaxion (experimental)
**Base**: I-10E commit 9c35a5a
**Status**: experimental branch only

## Purpose

I-10F adds a pure capture-and-validation model for recording the outcome of
manually-run local lab attempts. This phase does NOT execute live attach,
detach, event reads, ring buffer opens, map pins, or any kernel mutation.
It captures what happened as structured data and validates internal
consistency of that data.

## Constraints

- No public CLI.
- No normal CI live attach.
- No normal test root requirement.
- No automatic live attach.
- No automatic detach.
- No userspace loader implementation change.
- No ring buffer open.
- No live kernel event read.
- No map pin.
- No enforcement.
- No packet drop.
- No block/allow/quota.
- No nft/tc fallback.
- No ledger file write.
- No persistence.
- Existing v3.1 usage JSON schema unchanged.
- Existing v3.1 ledger JSON schema unchanged.

## Safety

- Manual capture must not fake attach success.
- Manual capture must not fake detach success.
- ReadyForEventStreamPlanning requires clean detach evidence.
- All unsafe flags must be false for a capture to be valid.

## Models

### EbpfLiveAttachManualResultStatus

NotRun | FeatureDisabled | ArtifactMissing | UnsupportedTarget |
GateRejected | AttachNotImplemented | AttachAttempted | AttachSucceeded |
AttachFailed | DetachAttempted | DetachedCleanly | DetachFailed |
InvalidCapture

### EbpfLiveAttachManualEvidenceLevel

None | OperatorReported | CommandOutputCaptured | DetachProofCaptured |
AuditReady

### EbpfLiveAttachManualRecommendation

Stop | FixArtifact | FixGate | RetryLocalLab | CaptureDetachProof |
ReadyForEventStreamPlanning

### EbpfLiveAttachManualLabCapture

Records operator label, feature state, artifact status, target kind,
attach/detach outcomes, evidence, safety flags, and recommendation.

### EbpfLiveAttachManualLabSummary

Aggregate counts and readiness determination over multiple captures.

## Next Phase

I-11 (Event Stream Read Planning) or I-10G (Manual Lab Evidence Review).
