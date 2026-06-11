# Intergalaxion I-1: eBPF Capability Detector

Phase I-1 lives only on the experimental `intergalaxion` branch.

`main` remains the stable v3.1.0 baseline. This phase does not bump the
version, tag, release, or publish anything.

## Scope

I-1 adds a read-only eBPF capability detector model for the Intergalaxion
Engine. The detector only answers:

> could this host become an observer candidate later?

The detector is split into:

- a pure evaluator
- an injected capability snapshot model
- an optional live snapshot adapter that reads host facts only

Tests use injected snapshots. They do not depend on the real host kernel and
do not require root.

## Read-Only Boundary

The I-1 detector is read-only:

- no eBPF attach
- no eBPF program load
- no eBPF bytecode load
- no eBPF map create
- no map or program pin
- no packet drop
- no enforcement
- no block/allow/quota
- no nft/tc backend
- no nft/tc fallback
- no public CLI
- no stable usage JSON schema change
- no stable ledger JSON schema change

The optional live adapter may only inspect read-only facts such as bpffs
presence, vmlinux BTF presence, effective capability bits, and the
unprivileged BPF sysctl value.

## Readiness Model

`EbpfCapabilitySnapshot` records host facts:

- kernel release, informational only
- bpffs presence
- vmlinux BTF presence
- CAP_BPF effective state
- CAP_SYS_ADMIN effective state
- unprivileged BPF sysctl value
- aya compile-time feature state, informational only

`EbpfReadinessLevel` is conservative:

- `Unavailable`
- `Partial`
- `ObserverReady`
- `AttachCandidate`

Default snapshots are all unknown or missing. Default reports are
`Unavailable`.

`AttachCandidate` is true only when bpffs, vmlinux BTF, and either CAP_BPF or
CAP_SYS_ADMIN are explicitly present in the injected snapshot.

`ObserverReady` is true only when the minimum observer facts are explicitly
present.

There is no enforcement readiness in I-1.

## Non-Goals

I-1 does not add commands, flags, routing, hidden dispatch, backend fallback,
policy decisions, packet handling, or kernel mutation.

It does not change existing stable CLI behavior.

## Next Phase

Suggested next phase:

I-2 — Minimal eBPF Observer Probe Design
