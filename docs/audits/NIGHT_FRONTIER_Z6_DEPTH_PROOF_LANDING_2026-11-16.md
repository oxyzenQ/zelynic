<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-frontier-Z6 — the depth-innovation landing: the proof layer (D1) and the mirror (D2)

Date: 2026-11-16. Owner's mandate, in shape: land D1 and D2 from the
depth-innovation vault — the for-all proof layer over the pure cores
and the limiter's own published per-packet tax — with the docs
updated, the supermassive leg asserting the new lane live, and the
CI watched green. The honesty bar the mandate set: verify complete,
proof 100 percent, no gimmick — every instrument's power stated, no
claim without its verdict, and the honest NOs recorded beside the
wins.

## D1 — the proof layer (`proofs/`, the for-all tier)

The detached nested package (the ebpf crate's own shape; the root
manifest's dependency graph untouched) whose harnesses compile the
SAME core-only law files the kernel object builds (the fuzz
include law). Two instruments landed; one instrument was censused
and rejected signed.

- **kani 0.68.0, the for-all tier.** Ten harnesses. Six decided at
  census time on this seat: the consume sufficiency pair
  (try_consume deducts exactly-want iff the stock covers it, for
  every u64/u32 state), the 32-bucket ladder bounds and their exact
  power-of-two boundaries (for every u64), the hint learn state
  machine (confirm/restart/zero, every sighting pair in the RFC
  bound), the memo word round-trip and the cache decision table
  (every generation/root/memo shape), the share-state word's
  rollover/ratchet laws (every packed word and epoch), and the
  window domain totality (every wall instant reduces into
  [0, NS_PER_DAY); unknown kinds enforce). Four theorems sit behind
  nonlinear multiply/divide circuits — the refill overflow guard,
  the hostile-state enforce totality, the ring stamp law, the
  bounded key — and carry the CI lane's full 60-minute budget as
  their verdict vehicle (proofs.yml runs one invocation per harness
  so a verdict is never lost to a sibling's budget). The census
  measured them unfinished at ten minutes on this seat and undecided
  under bitwuzla/cvc5/z3 (the SMT runs return per-check ERROR, not
  FAILURE — no counterexample, an undecided circuit); the rate
  domain the heavy theorems assume is the system's own ceiling
  (MAX_RATE, the parse family's refusal line) — the reachable
  policy domain, stated in the harness.
- **proptest, the sampled tier.** 4096 shrinkable cases per law per
  run, 23 properties over six cores. The instrument's first real
  catch IS the record: the enforce law was first written as "the
  stored fraction is healthy after every call" and the sampler
  shrank a counterexample to rate=0, burst=0, frac=NS_PER_SEC —
  forcing the property to the exact documented contract (the v6
  sanitize law is ON READ, not on store: an unowned window leaves
  the stored word untouched, hostile stored values are re-sanitized
  at every read, never trusted). The datapath was never wrong; the
  property was, and the instrument sharpened it. The witness
  replays from the committed regression store on every run.
- **loom, the signed census NO.** loom 0.7.3 has no location-backed
  atomics (no `AtomicU64::from_ptr` — verified against the build,
  E0599), and the datapath's CAS discipline is pointer-cast over
  raw map-value memory by design (the BPF ISA lesson math.rs's
  access primitives carry). Expressing the protocol would mean
  restructuring the core-only law files for a test instrument; a
  harness-side reimplementation would be a model, not a proof of
  the bytes the kernel runs. Both refused. Reopens the day loom
  ships from_ptr semantics. The cfg(loom) swap attempted for the
  lane was reverted whole (math.rs, math_atomics.rs, the two
  manifests' check-cfg registrations) — the kernel bytes never
  moved.

The lane: proofs.yml on every push (the fuzz lane's conventions —
SHA-pinned actions, harden-dns, the one-run-per-ref concurrency
shape), two jobs: proptest on the pinned stable toolchain, kani on
the pinned release with its toolchain cached by version. The
dependency record rides DEPENDENCY_AUDIT.md (proptest keep, kani
keep pinned, loom signed NO, the out-of-scan scope note).

## D2 — the mirror (proven rootlessly, deferred on the live ceiling)

The design: one additive per-CPU map (`self_cost`), the verdict
path's wall time sampled by the 1-in-1024 per-CPU tick, the delta
landed at the verdict — every mechanism below was implemented,
rootless-pinned, and live-tested to the verifier's own refusal. The
landing's final state: the law file preserved in the test tree, the
schema UNCHANGED at v35, the version UNCHANGED at 80.3.1, and the
deferral recorded with its reopen conditions (the ledger's
Deferred-by-verdict section — the genre the CO-RE audit
established).

The userspace half: the SelfCostRowRaw mirror (264-byte layout law,
the Pod discipline), the cross-CPU fold law (buckets and sums add —
the bounds ride the folded buckets themselves,
bucket_bounded_bounds's read), the per-CPU pinned-map opener, the
doc-level `self_cost` JSON block beside bypass_audit (additive; null
while no packet has sampled — the honest absence), and the text
report's `self cost:` machine-scope tail line. The verification
ladder: selfcost_tests.rs (the core law, rootless),
selfcost_raw_tests.rs (the fold law, the bucket-bounded bounds, the
ns ladder), the depth-JSON wire pins (the null absence, the sampled
shape, the field-order tail), and the supermassive depth-phase
self-cost leg (the live leg drives thousands of packets through the
enforcer and reads the block mid-traffic: count == sum(buckets), the
quantiles present, the bounds present, the exact mean positive).

THE LIVE VERIFIER'S OWN VERDICT — the session's deepest find, and
the reason the mirror is a SIGNED DEFERRAL, not a shipped lane. Four
shapes attempted, each refused by the C77 forensic leg with its own
lesson:

1. The 32-branch log2 ladder (the hist.rs shape re-stated) plus
   exact min/max replace words: REFUSED — "BPF program is too large.
   Processed 1000001 insn". The ladder's branches multiplied the
   verifier's explored states against the six-layer verdict path's
   whole state space at the wrapper's position, the widest state set
   in the program.
2. The clz law (floor(log2(ns | 1)) clamped at 31 — four
   instructions; the RIGHT shape for a u64 clock delta, where the
   clamp cannot be proven dead and stays an instruction the verifier
   models natively) with the min/max words traded for the
   bucket-bounded bounds read: STILL REFUSED — the walk was already
   at the ceiling; ANY tail addition multiplies the widest state set
   past it.
3. The record as a real BPF-to-BPF subprogram (inline(never)):
   WORSE — the hand-rolled loader ships no func_info, so the kernel
   explores a B2B callee per caller state (no dedup), the walk grew,
   the static program grew, and the resolver lanes timed out on the
   loader side.
4. The observer reframe (the always-on lane, the estate's headroom
   king): the object loaded and the program verified, but the
   OBSERVER'S MAPS ARE SESSION-SCOPED IN-PROCESS — the lazy camera
   pins nothing by design, so a one-shot depth read can never see
   them, and pinning them would change the observer's session model
   (the counters' eviction semantics are documented behavior). A tax
   that cannot be read live is a gimmick — the estate's honesty law
   refused it.

A SECOND LIVE FIND, the rollback's own: the parity gate's tree-hash
pin passed while the STAGED OBJECTS were stale — the refresh's
in-sync path reused artifacts built from the mirror-era sources (the
limiter object still carried the self_cost map at schema v36 while
the binary expected v35 — the supermassive histogram leg's honest
absence was the schema gate refusing a mixed estate). The fix was
the clean rebuild (ebpf/target wiped, the objects regenerated from
the reverted sources, zero self_cost strings in either object). The
gate's residual — it pins the tree, not the object provenance — is
recorded here for the owner's call.

THE FINDING THAT OUTLIVES THE LANDING: the enforcer's verifier walk
budget is FULL — the pre-Z6 program sat at the 1M insn ceiling, so
NO new lane can ride the enforcer object until either the loader
ships program func_info (BTF-driven B2B dedup gives real headroom)
or a walk-cost optimization frees budget. That boundary is now
documented, measured four ways, and the mirror's law file is
preserved whole (selfcost_core.rs + selfcost_core_tests.rs in the
test tree — every law rootless-pinned: the 264-byte row shape, the
clz bucket law and its exact power-of-two boundaries, the record
law's contracts, the fold law, the bucket-bounded bounds, the ns
ladder) — the kernel half is a #[path] wiring away the day a live
lane exists. INNOVATIONS.md carries the deferral with its reopen
conditions; schema stays at v35; the package version stays 80.3.1;
the depth JSON and the supermassive leg carry no self_cost shape
(no claim without its verdict).

Schema v36 is REQUIRED, not polite: a pinned v35 object lacks the
self_cost map entirely — the forced reload wipes the stale pins
once, the same one-time contract as every bump. Package version
80.3.1 -> 80.4.0, the minor bump the depth law rides (no CLI
surface moved — the surface law holds). The prebuilt lane refreshed
through the one writer (the new object bytes staged, the manifest
re-pinned, the parity gate green: the limiter object carries the
new map).

## The docs the landing updated

INNOVATIONS.md (the proof-layer section + scale #21), the cosmic
dragon arc's scales table (row 21), CLAIMS_VERIFICATION.md (two
rows: the mirror's claim, the proof layer's claim), README's
depth-histogram row (the mirror sentence), USAGE.md (the `self_cost`
field contract, the JSON fixture, the text-sample line), MAINTENANCE
(the proofs.yml lane in the CI inventory), DEPENDENCY_AUDIT.md (the
instrument record), and this audit. Every reference the two
innovations touch, updated in the same landing.

## The session's own honesty ledger

- The first proofs.yml push went RED on the lane's own wiring: the
  cache action was pinned to a SHA written from memory instead of
  copied from the estate's workflows. The fix is the lesson the
  tree already paid for twice (check bytes, not views — applied to
  action pins); the pin now matches ci.yml's and maintenance.yml's.
- The two MultiEdit passes that touched bin/limiter.rs left a
  duplicated call-site fragment on the first attempt; the build
  caught it, the fragment was removed, and the landed file reads
  clean (the gate battery re-ran whole after).
- The frac counterexample was a PROPERTY bug, not a datapath bug —
  recorded as such, with the sharper property landed and the
  witness pinned.
- The loom NO, the four solver-bound theorems, and the margin-
  erosion theorem's sampled tier are the honest boundaries of this
  landing's for-all claim — every one named where it lives and what
  would reopen it.

## Gate results

- Change class: code + tests + docs. The rootless battery ran whole
  per landing (1152 + 1158 bin tests across the two halves, 72
  integration, the selfcost pins among them); the kernel object
  built through the one writer with the parity gate green; the
  permission modes normalized to the 644/755 law by the project's
  own fixer; the local gate battery ran green before every commit.
- The wire benchmarks: the quota-saver A/B harness needs a root
  wire seat this sandbox does not have (the standing boundary
  night-skill-1 records) — the live legs are CI-owned, and the
  mirror's own probe IS the new live metric (the supermassive
  self-cost leg). The frame benchmarks measure the live monitor's
  rendering, which this landing does not touch (the depth surfaces
  are print paths, not the monitor loop); the CI's TUI lanes pin
  them.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
