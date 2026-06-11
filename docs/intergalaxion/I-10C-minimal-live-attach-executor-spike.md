# I-10C: Minimal Live Attach Executor Spike, Explicit Local Lab Only

**Branch**: intergalaxion (experimental branch only)
**Base phase**: I-10B (live attach spike runbook and hard gate contract)
**Status**: model-only, observer-only, no kernel mutation

## Scope

I-10C adds the first extremely narrow live attach executor spike boundary
for the Intergalaxion Engine. This phase introduces a feature-gated,
hard-gated executor evaluation model that remains inert in the default
build. No real BPF program loading, attaching, or kernel interaction
occurs in this phase.

## Hard constraints

- Experimental branch only. main remains stable v3.1.0.
- Minimal local live attach spike boundary.
- Disabled by default.
- Feature-gated by `intergalaxion-live-attach-lab` (Cargo feature).
- No public CLI.
- No enforcement.
- No packet drop.
- No block/allow/quota.
- No nft/tc fallback.
- No ring buffer open.
- No live kernel event read.
- No map pin.
- No ledger file write.
- No persistence.
- Existing v3.1 usage JSON schema unchanged.
- Existing v3.1 ledger JSON schema unchanged.
- Normal tests do not require root.
- Normal CI does not perform live attach.

## Models added

- `EbpfLiveAttachExecutorStatus` (10 variants)
- `EbpfLiveAttachLabInput` (10 fields)
- `EbpfLiveAttachExecutorAttempt` (22 fields)

## Helpers added

- `default_live_attach_lab_input()`
- `evaluate_live_attach_lab_attempt()`
- `validate_live_attach_executor_attempt()`
- `live_attach_executor_status_label()`

## Executor behavior

- Feature disabled: returns `FeatureDisabled`, all operation flags false.
- Runbook unsafe: returns `GateRejected`.
- Gate decision unsafe: returns `GateRejected`.
- Gate decision not future candidate: returns `GateRejected`.
- Operator label empty: returns `GateRejected`.
- Detach not required: returns `GateRejected`.
- Allow live attempt false: returns `AttachNotAttempted`.
- Object source missing: returns `ObjectSourceMissing`.
- Object bytes missing: returns `ObjectSourceMissing`.
- All gates pass: returns `FutureAttachReady`, all operation flags remain false.

## Safety invariants

- Default build: feature disabled, no live attach possible.
- Normal tests: rootless, no kernel interaction.
- No ring buffer open in I-10C.
- No event stream read in I-10C.
- No map pin in I-10C.
- No enforcement, no packet drop, no mutation, no persistence.
- No public CLI exposure.
