<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR Commercial -->

# NIGHT-Z17: The Interleaving Theorem — the census record

The working record of night-frontier-Z17 (D17, the interleaving
theorem): the solver economics that shaped the tier, the two
findings the instruments filed, the one retirement, the gated
landing's full arc (rung 4 landed the re-observing close, the
estate's own live e2e lane falsified its throughput shape, rung 8
re-shaped the shipped bytes to the zeroed-verdict gate with the
residual named), and the
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
  SHIPPED (zeroed-verdict) belt carries P4 at the conservative
  tier with one named residual — a racing draw's in-flight take
  inside the belt's write window, quantum-bounded (the two-word
  atomicity floor itself). The QUIET (re-observing) machine
  carries P4 outright, certified and unshippable (the falsified
  landing below); the pre-patch (ungated) belt's family carried
  P4 in the gated tier only — the falsification below is the
  reason its bytes changed.
- P5 — the stamp bound: no inversion past max(genesis, live).
- P6 — the fraction domain: the pool's fraction in domain or
  hostile-untouched.
- P7 — the absent slot: an unborn leaf carries nothing.
- P8 — the stamp provenance: a stamp that ever moved is a belt
  write, and a belt write is a reading of the live generation —
  `stamp == stamp0 || stamp <= g_live`. This law is what closes
  the mutation's catch-up corner (below) at the LAW level instead
  of hiding it.

## Finding 1 — the pre-patch belt's stamp write certified racing remnants (the closed class, the priced class, and the named residual)

The pre-patch belt (drr_flow.rs's leaf belt until rung 4, the
six-line shape):

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
(`legacy_belt_certifies_a_racing_spend_dead_remnant`,
`legacy_belt_certifies_a_racing_draw_dead_credit`); the sampler's
statistical pin proves the class reachable under random
two-actor schedules (512 seeds, the count reported). The close
came in two shapes, and the estate's own live lane priced them
both:

- THE GATED (zeroed-verdict) SEGMENT — the SHIPPED bytes since
  rung 8: the stamp write lands when the zeroing CAS won or the
  stock read zero; a lost CAS never certifies the racing remnant
  it failed to zero, and the convergence restores the pre-patch
timing (the stamp lands on the first uncontended episode). It
closes the stockpile-bounded class outright
(`shipped_belt_refuses_the_racing_spend_class_and_converges`) and
carries ONE named residual: a racing draw's in-flight credit can
land inside the belt's own read-to-write window and be stamped
current — bounded by one armed take (the quantum), the two-word
atomicity floor itself
(`shipped_belt_certifies_the_racing_draw_class_the_named_residual`).
Its conservative preservation theorem
(`every_shipped_belt_segment_preserves_the_conservative_laws`)
rides the kani tier beside the quiet form's full one.
- THE QUIET (re-observing) SEGMENT — rung 4's first landing: the
  stamp write also requires the stock to re-observe zero, which
closes the belt's own write window and carries the FULL law P4
(`every_quiet_belt_segment_preserves_the_full_laws`,
`quiet_belt_refuses_and_converges_on_both_witness_classes`).
Certified, and falsified as shippable bytes — the record below.

THE LANDING AND THE LIVE FALSIFICATION (rung 4 -> rung 8, the
same day, owner-approved): rung 4 landed the re-observing form as
the kernel's own bytes (drr_flow.rs's leaf belt and cake_flow.rs's
`flow_belt` twin) with the prebuilt lane regenerated through its
one writer — and the estate's live e2e lanes went RED on the
sustained-throughput rows the model cannot see (value semantics
has no contention physics): the jammy fast lane's sustain median
collapsed 56% -> 11% (the re-attempt 27%), noble 62% -> 12%,
bookworm's first series fell to 14% before its re-attempt
recovered, and the alpine leg's non-binding overhead row measured
+51.9% policy cost with ZERO drops (5.3 GB/s fresh vs 2.6 GB/s
policed under a 16 GB/s cap) — while the same lanes stood green
on the pre-patch object and on the zeroed-verdict object that
followed. The mechanism: under sustained delivery the stock moves
through the re-observation, the belt keeps refusing to stamp,
keeps re-firing, and keeps zeroing freshly drawn budget — the
enforced rate rides the residue. A sandbox convergence probe
over 512 adversarial two-actor schedules converged both forms
(the model's honest boundary: the failure lives below its
abstraction; the live lane is the instrument that measured it).

THE RE-SHAPE (rung 8): the shipped bytes gate the stamp on the
zeroing verdict alone — the stockpile-bounded class stays closed,
the convergence restores the pre-patch timing, and the live lanes
went GREEN (jammy sustain median 83%, noble 60%, alpine 79%,
archive 85% — at or above the pre-patch medians). The prebuilt
lane regenerated again through its one writer: the limiter
re-staged at 925584 bytes, tree pin e2ab7b4b..., the parity gate
green, the observer byte-identical. The honest claim since: the
belt's zero claim holds at quiescence for every schedule, the
stockpile-bounded certification class is closed in the shipped
bytes, and the quantum-bounded in-flight window remains — named,
bounded, and priced: the quiet form closes it completely and
cannot ship.

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

Retired: the forward-clock refill lemma (the census above).

Single-step preservation (for every P-state, every segment) —
eleven theorems, the count the claim carries:

1. `every_refill_seed_clamp_segment_preserves_the_laws_for_all_states`
2. `every_refill_window_segment_preserves_the_laws_for_all_states`
3. `every_refill_credit_segment_preserves_the_laws_for_all_states`
4. `every_refill_cap_clamp_segment_preserves_the_laws_for_all_states`
5. `every_refill_frac_write_segment_preserves_the_laws_for_all_states`
6. `every_consume_segment_preserves_the_laws_for_all_states`
7. `every_draw_segment_preserves_the_laws_for_all_states`
8. `every_debt_segment_preserves_the_laws_for_all_states`
9. `every_shipped_belt_segment_preserves_the_conservative_laws_for_all_states`
    (the shipped belt — the zeroed-verdict gate since rung 8: the
    conservative family, the quantum-bounded residual named)
10. `every_quiet_belt_segment_preserves_the_full_laws_for_all_states`
    (the re-observing close — rung 4's falsified landing, now the
    certified-but-unshippable certificate, the full family P4
    included)
11. `every_mutate_and_init_segment_preserves_the_laws_for_all_states`

The three fidelity pins plus the eleven preservation theorems —
fourteen standing, verified on the sandbox (the loop's log is the
record); every one rides its own CI matrix seat (one harness per
job — the estate's shape). The rung-8 sweep (the re-shaped tree,
2026-11-24): fidelity 3.0 / 5.5 / 13.3 s; the refill family
1.6-99.5 s; consume 36.0 s; draw 26.6 s; debt 104.4 s; the
shipped belt 36.5 s; the quiet belt 28.9 s; mutate/init 2.5 s —
every seat inside the 15-minute estate ceiling with wide margin.
The CI tier priced the landed bytes on the head envelope: the
enforcer's walk measured 141981 / 132960 verified_insns (kernel
7.3.0-11-generic) — the dl pin raised +88 per the growth law (run
45370360921, the gated verdict's honest price), the ul pin
ratcheted to the measured number (run 45374359811, the ratchet
law's encouraged follow-up); the ledger's histories carry both
events, the numbers the ledger owns.

## The property tier (the sampled instruments, per-push)

- Three fidelity hammers (refill, consume, debt pair): 4096
  shrinkable cases each, kernel-vs-machine equivalence.
- The chain pin: `refill_actor_agrees_with_the_direct_driver` —
  kernel == driver (kani, for all inputs, backward clocks) and
  driver == actor (this law, sampled) close the actor to the
  kernel's bytes through the shared segments.
- The belt witness pins, three forms: the two LEGACY pins (the
  pre-patch falsification record), the SHIPPED form's class-one
  close (refuses the racing spend and converges) beside its
  class-two NAMED-residual pin (the quantum-bounded in-flight
  window, asserted with its bound), and the QUIET form's
  both-class refusal (the unshippable certificate's witness).
- The schedule sampler (`interleave_sampler.rs`, split from the
  laws file at the 600-line cap): 512 seeds × 48 micro-steps, two
  actors, the conservative family hard-asserted after every
  step, the shipped (zeroed-verdict) family's dead-law hits
  counted and reported (the named residual's statistical shape;
  the exact interleaving needs the deterministic witness), and
  the pre-patch (ungated) family's class counted REACHABLE (the
  statistical pin that the finding was not a hand-built story —
  and the record of what the gated landing removed from the
  bytes).

## The boundaries the claim honestly carries

- The memory-ordering tier is unchecked: the model sequentializes
  (value semantics, no memory model), matching the kernels' own
  Relaxed/AcqRel discipline at the value level only.
- THE LIVE/THROUGHPUT TIER IS OUTSIDE THE MODEL: the rung-4
  falsification (the re-observing form's convergence collapse)
  was measured by the estate's live e2e lanes, not by the model —
  value semantics has no contention or cache physics, and a
  sandbox convergence probe over 512 adversarial two-actor
  schedules converged both stamp forms. The model proves the
  LAWS; the live lane prices the SHAPES; the rung's own record
  is the honest instrument order.
- The two-word belt atomicity (zero-then-stamp) is the floor the
  finding lives on; the shipped (zeroed-verdict) bytes carry the
  named quantum-bounded residual — a racing draw's in-flight
  take inside the belt's write window — while the quiet form,
  which closes that window completely, is certified and
  unshippable: the floor is priced, not assumed away.
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
