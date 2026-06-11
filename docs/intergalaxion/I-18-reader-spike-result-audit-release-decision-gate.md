# I-18 — Reader Spike Result Audit and Release Decision Gate

## Status

Phase I-18 is complete on the `intergalaxion` branch. This phase is
experimental branch only. `main` remains stable v3.1.0.

## Purpose

I-18 is reader spike result audit and internal decision gate only. The
release decision gate does not mean real release. This phase audits the I-17
local reader spike result captures and produces a gate report that decides
whether the branch should stop, fix preparation, fix executor, capture more
evidence, continue local lab only, prepare a future reader spike review, or
remain blocked from any release or public path.

## Design constraints

### Hard invariants

- no tag
- no release
- no publish
- no version bump
- no main merge
- no public CLI
- no normal CI live event read
- no automatic live attach
- no automatic detach
- no automatic reader execution
- no ring buffer open
- no live kernel event read
- no map pin
- no enforcement
- no packet drop
- no block/allow/quota
- no nft/tc fallback
- no ledger file write
- no persistence
- no fake audit success
- no fake release readiness

### Schema stability

- existing v3.1 usage JSON schema unchanged
- existing v3.1 ledger JSON schema unchanged

### Experimental status

- release_allowed is always false in I-18
- must_remain_experimental is always true in I-18
- The intergalaxion branch remains experimental regardless of gate outcome

## Safety rules

- No actual BPF object loading
- No userspace loader API calls
- No map creation
- No ring buffer open
- No live event read
- No map pin
- No filesystem read/write (no ledger file write, no persistence)
- No /proc, /sys, /sys/fs/bpf access
- No OS root/capability check
- No cgroup mutation
- No PID mutation
- No nft/tc mutation
- No packet drop
- No block/allow/quota
- No public CLI
- Normal tests remain rootless
- No normal test root requirement

## Models

### EbpfReaderSpikeReleaseGateStatus

| Variant | Description |
|---|---|
| NotReady | Prerequisites not met |
| Blocked | Hard safety gate blocked |
| Failed | Evaluation failed |
| Warning | Passed with warnings |
| Passed | All checks passed |
| HoldExperimental | Branch must remain experimental |
| ContinueLocalLab | Continue local lab work |
| ReadyForReaderSpikeReview | Ready for reader spike review |
| ReleaseRejected | Release explicitly rejected |

### EbpfReaderSpikeReleaseDecision

| Variant | Description |
|---|---|
| Stop | Do not proceed |
| FixPreparation | Fix preparation first |
| FixExecutor | Fix executor first |
| CaptureMoreEvidence | Capture more evidence |
| ContinueLocalLabOnly | Continue local lab only |
| PrepareReaderSpikeReview | Prepare for reader spike review |
| RejectRelease | Release explicitly rejected |
| KeepExperimental | Keep branch experimental |

### EbpfReaderSpikeReleaseGateFindingKind

| Variant | Description |
|---|---|
| ResultCapture | Result capture finding |
| ResultSummary | Result summary finding |
| SafetyInvariant | Safety invariant finding |
| CliInvariant | CLI invariant finding |
| SchemaInvariant | Schema invariant finding |
| ReleaseInvariant | Release invariant finding |
| CountInvariant | Count invariant finding |
| EvidenceInvariant | Evidence invariant finding |

## Fake detection

- fake reader execution success must be rejected
- fake live event counts must be rejected

## Gate readiness

ReadyForReaderSpikeReview requires all of:

- Result summary validates
- result_summary.ready_for_reader_spike_review is true
- No invalid captures detected
- No fake reader success detected
- No fake live event counts detected
- FutureExecutionReady capture present (when required)
- CleanupCompleted capture present (when required)
- Public CLI hidden
- Usage schema unchanged
- Ledger schema unchanged
- No tag/release/publish/version bump/main merge request
- All safety flags false

Even when ExecutionSucceeded captures are allowed, release is still
rejected. release_allowed is always false. must_remain_experimental is
always true.

## Files changed

| File | Action |
|---|---|
| `src/intergalaxion_engine/backends/ebpf/event_stream_reader_spike_release_gate.rs` | Created |
| `src/intergalaxion_engine/backends/ebpf/mod.rs` | Extended |
| `src/intergalaxion_engine/mod.rs` | Extended |
| `src/intergalaxion_engine/tests_i18.rs` | Created |
| `docs/intergalaxion/I-18-reader-spike-result-audit-release-decision-gate.md` | Created |

## Next suggested phase

I-19 — Reader Spike Review Pack, or I-18A — Release Gate Static Policy Freeze.
