# I-20: Intergalaxion Reader Lab Milestone Freeze

## Phase

I-20 is experimental branch only.

## Scope

I-20 is Intergalaxion reader lab milestone freeze only.

This phase freezes the I-10F through I-19 reader-lab evidence chain into an
internal milestone record. It summarizes and freezes:

* manual lab result capture (I-10F)
* event stream planning (I-11)
* reader boundary (I-12)
* fixture decoder bridge (I-13)
* dry run (I-14)
* evidence audit (I-15)
* reader spike preparation (I-15A)
* executor boundary (I-16)
* executor static audit (I-16A)
* result capture (I-17)
* release decision gate (I-18)
* review pack (I-19)

## Constraints

This phase is milestone-freeze only.

It is not a release.

* no tag.
* no release.
* no publish.
* no version bump.
* no main merge.
* no public CLI.
* no normal CI live event read.
* no normal test root requirement.
* no automatic live attach.
* no automatic detach.
* no automatic reader execution.
* no ring buffer open.
* no live kernel event read.
* no map pin.
* no enforcement.
* no packet drop.
* no block/allow/quota.
* no nft/tc fallback.
* no ledger file write.
* no persistence.

## Schema stability

* existing v3.1 usage JSON schema unchanged.
* existing v3.1 ledger JSON schema unchanged.

## Hard invariants

* release_allowed is always false.
* must_remain_experimental is always true.

## Fake detection

* fake reader execution success must be rejected.
* fake live event counts must be rejected.
* fake release readiness must be rejected.
* fake milestone freeze success must be rejected.

## Safety

No actual BPF object loading. No userspace loader API calls. No map creation.
No ring buffer open. No live event read. No map pin. No filesystem read/write.
No /proc, /sys, /sys/fs/bpf access. No OS root/capability check. No cgroup
mutation. No PID mutation. No nft/tc mutation. No packet drop. No
block/allow/quota. No public CLI. No persistence. Normal tests remain rootless.

## Next phase

Future phase can be I-21 — Reader Lab Next Arc Planning, or
I-20A — Milestone Freeze Static Policy Freeze.
