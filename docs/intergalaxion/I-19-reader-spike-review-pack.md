# I-19 — Reader Spike Review Pack

## Status

Phase I-19 is complete on the `intergalaxion` branch. This phase is
experimental branch only. `main` remains stable v3.1.0.

## Purpose

I-19 is reader spike review pack only. review-pack only. not a release.
It gathers evidence from previous reader-spike phases (I-10F through I-18)
into a deterministic internal review pack. It is an internal evidence bundle
and decision summary only.

## Design constraints

### Hard invariants

- no tag
- no release
- no publish
- no version bump
- no main merge
- no public CLI
- no normal CI live event read
- no normal test root requirement
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
- no fake review success
- no fake release readiness

### Schema stability

- existing v3.1 usage JSON schema unchanged
- existing v3.1 ledger JSON schema unchanged

### Experimental status

- release_allowed is always false in I-19
- must_remain_experimental is always true in I-19
- The intergalaxion branch remains experimental regardless of pack outcome

## Safety rules

- No actual BPF object loading
- No userspace loader API calls
- No map creation
- No ring buffer open
- No live event read
- No map pin
- No filesystem read/write
- No /proc, /sys, /sys/fs/bpf access
- No OS root/capability check
- No cgroup mutation
- No PID mutation
- No nft/tc mutation
- No packet drop
- No block/allow/quota
- No public CLI
- No persistence
- Normal tests remain rootless

## Fake detection

- fake reader execution success must be rejected
- fake live event counts must be rejected
- fake release readiness must be rejected

## Models

### EbpfReaderSpikeReviewPackStatus

| Variant | Description |
|---|---|
| Draft | Review pack in draft |
| Incomplete | Evidence incomplete |
| Blocked | Blocked by safety gate |
| ReviewReady | Ready for review |
| ReviewRejected | Review rejected |
| ExperimentalOnly | Must remain experimental |
| ReleaseForbidden | Release forbidden |

### EbpfReaderSpikeReviewPackDecision

| Variant | Description |
|---|---|
| Stop | Do not proceed |
| FixEvidence | Fix evidence first |
| CaptureMoreResults | Capture more results |
| ContinueLocalLab | Continue local lab |
| PrepareManualReaderSpikeReview | Prepare manual review |
| KeepExperimental | Keep experimental |
| RejectRelease | Reject release |

## Files changed

| File | Action |
|---|---|
| `src/intergalaxion_engine/backends/ebpf/event_stream_reader_spike_review_pack.rs` | Created |
| `src/intergalaxion_engine/backends/ebpf/mod.rs` | Extended |
| `src/intergalaxion_engine/mod.rs` | Extended |
| `src/intergalaxion_engine/tests_i19.rs` | Created |
| `docs/intergalaxion/I-19-reader-spike-review-pack.md` | Created |

## Next suggested phase

I-20 — Intergalaxion Reader Lab Milestone Freeze, or I-19A — Review Pack Static Policy Freeze.
