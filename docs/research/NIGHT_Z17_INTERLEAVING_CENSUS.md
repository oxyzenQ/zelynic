<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR Commercial -->

# NIGHT-Z17: The Interleaving Theorem — the census record

The working record of night-frontier-Z17 (D17, the interleaving
theorem): the solver economics that shaped the tier, the two
findings the instruments filed, the one retirement, and the
domain boundaries the claim honestly carries. The ledger entry
([INNOVATIONS.md](../INNOVATIONS.md), D17) is the map; this file
is the record behind it.

## The instrument

Three files in `proofs/src/`:

- `interleave_model.rs` — the World (the shared words the kernel
  runs plus the proof-side shadow ledger) and the invariant laws.
- `interleave_segments.rs` — the five verbs' atomicity units.
  Every RMW is the dual-compiled primitive itself: `tokens_cas`,
  `tokens_fetch_add`, `draw_stamp_take`, `gen_stamp_read/write`,
  `refill_credits`. The debt word rides a Bucket-shaped view so
  its CAS IS `tokens_cas` (identical compare_exchange semantics to
  ecn.rs's private word_cas: AcqRel/Acquire, the same arguments)
  — which also keeps the loom census's zero-stray posture: no
  `from_ptr` text outside the kernel crate's access primitives.
- `interleave_actors.rs` — the micro-step coroutine controllers.
  Each verb instance is an Actor advanced one observation phase or
  one action at a time; the scheduler materializes the
  stale-observation windows exactly as real CPUs do.

The theorem shape is induction over the schedule space: a
corrupted reachable state implies a first invariant-failing
segment from a P-satisfying state, so machine-checking "every
segment preserves P from every P-state" (kani::assume(P) — the
induction hypothesis, stated, never hidden) proves every
interleaving of every length preserves P at every point.

## The invariant P (the "no corrupt state" claim, checkable)

- P1 — the ledger: pool.tokens + leaf.tokens + inflight + spent
  plus paid plus burned equals pool0 + leaf0 + entered, exactly,
  in u128 (the band assume keeps the checker's own arithmetic
  total; the real words' representability is each theorem's
  stated domain). This is the no-lost-refill /
  no-debt-double-pay lemma pair the budget core never had at the
  for-all tier.
- P2 — the debt cap: the debt word never leaves
  [0, ECN_DEBT_CAP] (or its hostile genesis value, unread — the
  v6 sanitize family's posture one word over).
- P3 — the taint coherence: the leaf's stock splits exactly into
  live and dead.
- P4 — the belt's dead law: a currently-stamped leaf holds zero
  dead tokens. THE CARRY carve-outs, both stated in the law: a
  stamp still at its hostile genesis value is not certified (the
  belt has not fired since the map carried that state), and the
  shipped (ungated) belt's family carries P4 in the gated tier
  only — the falsification below is the reason.
- P5 — the stamp bound: no inversion past max(genesis, live).
- P6 — the fraction domain: the pool's fraction in domain or
  hostile-untouched.
- P7 — the absent slot: an unborn leaf carries nothing.
- P8 — the stamp provenance: a stamp that ever moved is a belt
  write, and a belt write is a reading of the live generation —
  `stamp == stamp0 || stamp <= g_live`. This law is what closes
  the mutation's catch-up corner (below) at the LAW level instead
  of hiding it.

## Finding 1 — the shipped belt's stamp write certifies racing remnants

The shipped belt (drr_flow.rs, the six-line leaf belt):

```rust
let stale = tokens_read(bkt);
if stale != 0 {
    let _ = tokens_cas(bkt, stale, 0);
}
gen_stamp_write(bkt, generation);
```

The zeroing CAS's failure is discarded, and the stamp write lands
unconditionally. Under an adversarial interleaving — a racing
consume's remnant or a racing draw's in-flight credit moving the
stock between the belt's read and its CAS — the zeroing loses,
and the stamp write certifies a dead remnant as current-budget
tokens: spendable, one belt episode wide, bounded by the leaf's
stockpile. The conservation ledger holds throughout (the
surviving tokens are real budget, never minted); the violation is
the CERTIFICATION, not the conservation.

The witnesses: deterministic, shrunk, in `interleave_laws.rs`
(`shipped_belt_certifies_a_racing_spend_dead_remnant`,
`shipped_belt_certifies_a_racing_draw_dead_credit`); the sampler's
statistical pin proves the class reachable under random
two-actor schedules (512 seeds, the count reported). The close,
model-side: the GATED stamp segment — write the stamp only when
the zeroing succeeded or the stock read zero; a failed zero keeps
the stamp stale, the next packet's belt re-fires, and the
zeroing converges. Its preservation theorem
(`every_gated_belt_segment_preserves_the_full_laws`) is the fix's
certificate, and both witness pins flip green under it
(`gated_belt_refuses_and_converges_on_both_witness_classes`).

The kernel byte change (six lines in drr_flow.rs and its
cake_flow twin) rides the owner's prebuilt pipeline decision — a
hot-path object change regenerates the prebuilt tree and its
blake3 pin, which is the owner's own gate to run. Until it lands,
the honest claim: the belt's zero claim holds at quiescence, with
a documented adversarial residual (one episode,
stockpile-bounded) the gated form removes.

## Finding 2 — the mutation's catch-up corner (the law's own precision)

The first single-step formulation of P4 failed against the mutate
segment: with a hostile genesis stamp ABOVE the live generation,
the generation's forward bump can land the live generation
exactly on the stored stamp — a "certified" leaf no belt ever
touched, with dead stock the law never zeroed. The class is
unreachable through the model's own verbs (a belt-written stamp
is always at or under the live generation; only the belt writes
stamps), but the single-step tier quantifies over a conservative
over-approximation of the reachable class — the honest fix is
the stamp-provenance law P8, which excludes the impossible
pre-states BY NAME, plus P4's genesis carve-out for the residue
the belt has not yet healed. The corner is why the law reads the
way it does: precision in the claim, not a quiet assume.

## The census (the solver economics, measured)

Environment: the 2-CPU sandbox, kani 0.68.0 / CBMC 6.11.0 — this
estate's conservative bound (the Z12 census posture; hosted
runners decide strictly faster shapes).

- `consume` fidelity: 5.3 s. `debt` pair fidelity: 13 s. Both
  stand as written.
- The refill fidelity, whole-domain shape: no verdict inside ten
  minutes. Decomposition one — the backward-clock lemma (now at
  or behind the stamp): 16 s, verified. The forward-clock lemma:
  no verdict inside ten minutes after the cut; the circuit is
  two full refill_credits pipelines (the division/modulo family
  the Z12 census itself named) over two object copies the solver
  will not common-subexpress, ~63k variables before the first
  propositional reduction pass. RETIRED BY CENSUS, the record
  honest: the forward-clock fidelity rides the sampled tier (the
  4096-case shrinkable hammer plus the chain pin — kernel ==
  direct driver == actor, sampled, in `interleave_laws.rs`). The
  reopen lever, named: a solver generation that
  common-subexpresses equal-argument division pipelines, or the
  refill_credits lemma decomposition at the division level — the
  same door the Z10 emission theorem's header holds.
- The refill preservation family, one-harness union of five
  segment bodies: no verdict inside the seat. Split per segment
  (the Z12 discipline): every one of the five decides in seconds.
- The mutate/init harness's assume, first form
  (`saturating_add <= ceiling`), was VACUOUS at the ceiling — the
  same hole the stock headroom's first form had. Both now carry
  the exact subtraction form. The census found two of these
  vacuous-assume shapes; the band assumes on the shadows were the
  third precision fix (the law predicates must not trap the
  checker on hostile shadow values the real schedules never
  reach).

## The theorem tier as it stands (14 + 1 retired)

Fidelity pins (for all inputs, nothing interleaved):

1. `refill_actor_matches_kernel_refill_window_for_all_backward_clocks`
2. `consume_actor_matches_kernel_try_consume_for_all_inputs`
3. `debt_actors_match_kernel_debt_pair_for_all_inputs`
   — retired: the forward-clock refill lemma (census above).

Single-step preservation (for every P-state, every segment):

4. `every_refill_seed_clamp_segment_preserves_the_laws_for_all_states`
5. `every_refill_window_segment_preserves_the_laws_for_all_states`
6. `every_refill_credit_segment_preserves_the_laws_for_all_states`
7. `every_refill_cap_clamp_segment_preserves_the_laws_for_all_states`
8. `every_refill_frac_write_segment_preserves_the_laws_for_all_states`
9. `every_consume_segment_preserves_the_laws_for_all_states`
10. `every_draw_segment_preserves_the_laws_for_all_states`
11. `every_debt_segment_preserves_the_laws_for_all_states`
12. `every_shipped_belt_segment_preserves_the_conservative_laws_for_all_states`
    (the shipped belt's family — P4 excluded, the finding's shape)
13. `every_gated_belt_segment_preserves_the_full_laws_for_all_states`
    (the gated close's certificate — the full family, P4 included)
14. `every_mutate_and_init_segment_preserves_the_laws_for_all_states`

All fourteen verified on the sandbox (the loop's log is the
record); every one rides its own CI matrix seat (one harness per
job — the estate's shape).

## The property tier (the sampled instruments, per-push)

- Three fidelity hammers (refill, consume, debt pair): 4096
  shrinkable cases each, kernel-vs-machine equivalence.
- The chain pin: `refill_actor_agrees_with_the_direct_driver` —
  kernel == driver (kani, for all inputs, backward clocks) and
  driver == actor (this law, sampled) close the actor to the
  kernel's bytes through the shared segments.
- Two deterministic witness pins + the gated convergence pin.
- The schedule sampler: 512 seeds × 48 micro-steps, two actors,
  the conservative family hard-asserted after every step, the
  gated family's dead-law violations counted zero, the ungated
  family's class counted REACHABLE (the statistical pin that the
  finding is not a hand-built story).

## The boundaries the claim honestly carries

- The memory-ordering tier is unchecked: the model sequentializes
  (value semantics, no memory model), matching the kernels' own
  Relaxed/AcqRel discipline at the value level only.
- The two-word belt atomicity (zero-then-stamp) is the floor the
  finding lives on; the gated form's re-observation closes it
  inside the model's segment atomicity, and the real two-instruction
  gap is named, not assumed away.
- The draw/belt program orders mirror the aya-touching halves'
  bytes (not includeable by the proofs package's core-only law);
  their sequencing is pinned by the segment bytes plus the
  sampler, stated in the model header.
- The shaping words (note_share, the ledger pair) are
  scope-excluded — the documented estimate class, never the token
  conservation.
- The forward-clock refill fidelity is sampled, not for-all (the
  retirement above).

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
