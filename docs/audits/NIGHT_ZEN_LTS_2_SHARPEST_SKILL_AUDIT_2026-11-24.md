<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The night-zen-lts-Z-2 audit — the sharpest skill at the Z17 tree

> Audit date: 2026-11-24 (night-zen-lts-Z-2, the sharpest-skill
> series' second rung — the first re-proved the core at schema v35 on
> 2026-11-18). Scope: the per-packet kernel enforcement core
> (ebpf/src, 29 files) and its userspace half, audited at c3bbc58 —
> six days and the Z17 storm after the first rung: the gated
> generation belt landed in both flow files, the proofs tier
> restructured around the interleaving model, the prebuilt lane
> regenerated twice, the ledger raised and ratcheted. The audit's
> question: did the storm keep the edge sharp. Method: the belt
> sites read in full at HEAD, the panic census re-run live, the
> division census extended over the Z17 delta, the verifier-price
> question answered by a section-level object compare, the proof
> tiers censused from the workflow. The honest boundary, stated
> once: no root, no BPF attach, no KVM in the seat — the live
> legs are CI's records (the tip's own lanes green), and the
> memory-ordering tier stays the model's stated boundary, not a
> claim this record upgrades.

## 1. The belt — the Z17 landing read at HEAD

Both belt sites carry the zeroed-verdict gate (form A), and both
read as the law their comments claim:

- The leaf belt, ebpf/src/drr_flow.rs:240-247: the generation read
  once, the stale stock read once, the zeroing by CAS with the
  stale==0 short-circuit, and the stamp write GATED on the zeroing
  verdict — a lost CAS never certifies the racing remnant it failed
  to zero, so the next packet's belt re-fires and the zeroing
  converges. The in-code residual is named at the site itself
  (:235-239): a racing draw's in-flight credit inside the belt's
  write window, bounded by one armed take (the quantum), the
  two-word atomicity floor itself.
- The flow belt, ebpf/src/cake_flow.rs:316-324 (`flow_belt`): the
  same shape for the flow bucket, split so drr_flow's lane stays a
  readable sequence; the doc carries the rung-4 falsification
  record (the re-observing form's live-lane collapse) beside the
  landed verdict.
- The primitives (math_atomics.rs:76-87): `gen_stamp_read` /
  `gen_stamp_write` ride `read_volatile` / `write_volatile` — the
  READ_ONCE/WRITE_ONCE discipline, the same contract the tokens
  pair documents; the stamp lives in `frac_rem`, a field the leaf
  arithmetic does not use, so the belt borrows storage without
  touching the budget math.

The falsification record is intact at both tiers: the pre-patch
witnesses pinned in the property lane, the sampler carrying the
ungated family's REACHABLE statistic (the finding was not a
hand-built story), the quiet form standing as the
certified-but-unshippable certificate. The convergence law the live
lanes priced (sustain medians 79-83% post-reshape) matches the
census's numbers.

## 2. The panics, the divisions, the verifier price

- **Panic census: zero.** The unwrap/expect/panic!/unreachable!/
  todo!/unimplemented! family over ebpf/src returns no hits at
  c3bbc58 — the kernel object still cannot panic by construction,
  Z17 code included.
- **Division census: the delta adds none.** The belt is compare +
  CAS + volatile writes; no new divisor exists anywhere in the Z17
  delta, so the 19-site guarded census (every dynamic denominator
  traced to its guard: the drawee `< 2` law, the refill's
  rate-0/elapsed-0 early return, the sparse takes' `learned + 2`)
  carries forward untouched.
- **The verifier price, proven not assumed.** The hardening-5
  comment edit forced a lane refresh; the rebuilt limiter object's
  section table was compared against the shipped bytes: `.text`
  9784 identical, every program section identical, `.BTF` (the
  func shapes the verifier walks) identical, only the DWARF
  line-info class moved. The tip's own budget job measured
  enforce_dl at 141981 — exactly at the raised pin — and enforce_ul
  at 132960, now the ratcheted pin. The ledger's guard is at the
  true collapsed shape on both rows.

## 3. The proof tier standing behind the bytes

- The kani tier: 26 seats (6 Z6 originals, 6 Z12 rebirths, 3
  fidelity pins, 11 preservation theorems including the shipped
  belt's conservative family and the quiet belt's full family) —
  one harness per matrix job, every seat green on the tip, every
  seat inside the 15-minute ceiling.
- The property tier: the three fidelity hammers (4096 shrinkable
  cases each), the chain pin (kernel == driver == actor), the belt
  witness pins in three forms (the legacy falsification, the
  shipped form's class-one close plus its NAMED class-two residual
  asserted with its bound, the quiet form's both-class refusal),
  the 512-seed adversarial sampler asserting the conservative
  family after every micro-step.
- The stated boundaries, unchanged and honest: the memory-ordering
  tier unchecked (value semantics; the kernel's Relaxed/AcqRel
  discipline mirrored at the value level only), the
  live-throughput tier outside the model (the estate's own e2e
  lanes are the instrument that caught the rung-4 shape), the
  two-word belt atomicity floor priced with the quantum-bounded
  residual named.

## 4. The five areas at the sharpest edge

| Area | Verdict | Note |
|---|---|---|
| Stability and crash | PEAK | panic zero, divisions guarded, the belt's residual named and bounded |
| Hygiene | PEAK | the belt reads as the law it is; no zombie, no stale marker, the split at the cap clean |
| Optimization | PEAK | the walk cost ledger-guarded at the collapsed shape; the hot path's price carried by the estate's own gates |
| Security | PEAK | no new input surface; the tamper-evident stamps ride the refreshed objects; the belt's write window bounded and theorem-pinned |
| LTS | PEAK | the floor envelope honest (load-proof gate green on 5.15), the head envelope priced, the boundaries stated, the records current |

The edge held. The storm's newest code arrived with its proof
family, its residual named at the site, and its price in the
ledger — the sharpest-skill bar of the 2026-11-18 rung survives the
Z17 landing intact.

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
