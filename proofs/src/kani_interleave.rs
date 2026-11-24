// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17 (the interleaving theorem): the for-all tier.
//! Two theorem families over the two-CPU segment model:
//!
//!  * THE FIDELITY PINS — the anti-gimmick instrument. For ALL
//!    inputs, running each verb's actor with nothing interleaved
//!    reproduces the kernel function's own final state exactly
//!    (field-for-field on the touched bucket, plus the debt word).
//!    A machine that is a restatement, not the bytes, fails here.
//!    The refill, consume, and debt machines pin against the
//!    includeable kernel functions; the draw and belt machines'
//!    sequencing (the aya-touching halves) is pinned by the
//!    segment bytes themselves (every RMW is the actual primitive)
//!    and the property sampler, the boundary stated in
//!    interleave_model.rs's header.
//!  * THE SINGLE-STEP PRESERVATION THEOREMS — the induction that
//!    carries EVERY schedule length. A corrupted reachable state
//!    implies a first invariant-failing segment from a
//!    P-satisfying state; so machine-checking "every segment
//!    preserves P from every P-state" proves "every interleaving
//!    of every length preserves P at every point" by induction —
//!    the complete for-all claim the interleaving space never had.
//!    The pre-states are quantified with kani::any() fields plus
//!    kani::assume(P) (the induction hypothesis, stated, never
//!    hidden), over a conservative over-approximation of the
//!    reachable schedule class: the single-step tier admits
//!    orders no verb's program order produces, so a green theorem
//!    covers the real coroutine schedules a priori.
//!
//! THE DOMAINS, stated per the standing precedents: burst inside
//! its representability contract (MAX_ENFORCABLE_BURST, the
//! security-3 trust boundary), rate inside the reachable policy
//! ceiling (SYSTEM_MAX_RATE, the parse family's own bound —
//! restated here beside its source the way kani_cores.rs does),
//! the credit's stock headroom (the same representability
//! philosophy the kernel's own burst ceiling carries, extended to
//! the interleaved credited stock), the draw credit's pairing
//! (program order: the credit's d is the actor's own armed take),
//! the belt's monotone generation reading (a reading of the live
//! generation never exceeds it), the mutation's forward-only u32
//! family (the MMSPA memo generation's own width). Each assume is
//! the induction hypothesis of the law it names — the honest
//! posture the Z6 audit set.
//!
//! THE FINDING this instrument filed, its close, and the live
//! lane's verdict on the close's first shape (the research doc
//! records all three): the PRE-PATCH belt's unconditional stamp
//! write could not preserve the dead law P4 — a racing spend's
//! remnant or a racing draw's credit survives the failed zeroing
//! and got stamped current, while the conservation ledger P1 held
//! throughout (the violation was the belt's certification). The
//! gated stamp segment — the SHIPPED bytes since rung 8 — gates the
//! write on the zeroing verdict, closing the stockpile-bounded
//! class; its named residual (a racing draw's in-flight take inside
//! the belt's write window, quantum-bounded) keeps P4 at the
//! conservative tier for the shipped form. The QUIET stamp segment
//! — the re-observing close rung 4 first landed — carries the full
//! law P4 for all states, and the live e2e lane falsified its
//! throughput shape (the belt never converges under sustained
//! delivery; the enforced rate collapses; the census carries the
//! numbers), so it stands as the certified-but-unshippable form:
//! the model-side record of what closing the window completely
//! costs.

use crate::interleave_model::{Target, World};
use crate::interleave_segments::{
    belt_stamp_gated_seg, belt_stamp_quiet_seg, belt_zero_seg, consume_seg, debt_charge_seg,
    debt_pay_forgive_seg, debt_pay_tokens_seg, draw_leaf_credit_seg, draw_pool_take_seg,
    draw_rollback_seg, draw_stamp_seg, init_seg, mutate_seg, refill_cap_clamp, refill_credit,
    refill_frac_write, refill_seed_clamp, refill_window_take,
};
use crate::math_core::{
    Bucket, MAX_ENFORCABLE_BURST, NS_PER_SEC, Policy, refill_window, try_consume,
};

/// The system's policy-rate ceiling (src/ebpf/limiter/types.rs's
/// MAX_RATE, restated beside its source the kani_cores.rs way):
/// the enforcement theorems quantify over the REACHABLE policy
/// domain — no CLI path can write a rate above it.
const SYSTEM_MAX_RATE: u64 = 1_000_000_000_000;

/// The MMSPA generation family's width (the memo word's u32 half —
/// the memo theorem's own domain): the live generation is a u32
/// value the mutations bump forward only.
const GENERATION_MAX: u64 = u32::MAX as u64;

fn any_policy() -> Policy {
    let rate: u64 = kani::any();
    let burst: u64 = kani::any();
    kani::assume(rate <= SYSTEM_MAX_RATE);
    kani::assume(burst <= MAX_ENFORCABLE_BURST);
    Policy {
        rate_bps: rate,
        burst_bytes: burst,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    }
}

/// An arbitrary world — every kernel-visible word AND every shadow
/// symbolic. The preservation harnesses add kani::assume(P) (the
/// induction hypothesis) over this; the fidelity harnesses use it
/// as the hostile starting state.
///
/// The BAND: the shadows are bounded into the checker's own
/// arithmetic domain (each u128 shadow under 2^124, each u64 taint
/// word under a quarter of the u64 range) so every law predicate's
/// sums evaluate exactly — the band sits orders above every value
/// a real schedule can reach (the stock is burst-clamped around
/// 1e10, the counters are sums of u64-bounded words), and inside
/// the band nothing saturates: the law is exact, never wrapped.
fn any_world() -> World {
    let pool = Bucket {
        tokens: kani::any(),
        last_refill_ns: kani::any(),
        frac_rem: kani::any(),
    };
    let leaf = Bucket {
        tokens: kani::any(),
        last_refill_ns: kani::any(),
        frac_rem: kani::any(),
    };
    let debt: u64 = kani::any();
    let debt_bucket = Bucket {
        tokens: debt,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let pool0: u128 = kani::any();
    let leaf0: u128 = kani::any();
    let entered: u128 = kani::any();
    let burned: u128 = kani::any();
    let spent: u128 = kani::any();
    let paid: u128 = kani::any();
    let inflight: u128 = kani::any();
    let dead: u64 = kani::any();
    let live: u64 = kani::any();
    kani::assume(pool0 < (1u128 << 124));
    kani::assume(leaf0 < (1u128 << 124));
    kani::assume(entered < (1u128 << 124));
    kani::assume(burned < (1u128 << 124));
    kani::assume(spent < (1u128 << 124));
    kani::assume(paid < (1u128 << 124));
    kani::assume(inflight < (1u128 << 124));
    kani::assume(dead < u64::MAX / 4);
    kani::assume(live < u64::MAX / 4);
    World {
        pool0,
        leaf0,
        entered,
        burned,
        spent,
        paid,
        inflight,
        pool,
        leaf,
        debt: debt_bucket,
        g_live: kani::any(),
        born: kani::any(),
        dead,
        live,
        stamp0: kani::any(),
        frac0: kani::any(),
        debt0: kani::any(),
    }
}

fn bucket_clone(b: &Bucket) -> Bucket {
    Bucket {
        tokens: b.tokens,
        last_refill_ns: b.last_refill_ns,
        frac_rem: b.frac_rem,
    }
}

// ── THE FIDELITY PINS ──────────────────────────────────────────────

/// FIDELITY, the refill actor (the decomposed pair, the Z12
/// discipline: the whole-domain shape measured past every ceiling
/// on this solver generation — the census rides the research doc).
/// Lemma one, the BACKWARD clocks: for EVERY hostile bucket,
/// policy, and a clock at or behind the stamp, the actor's
/// no-interleaving run leaves the pool bit-identical to
/// refill_window's own bytes — the heal branch and the stale
/// sampler's skip included, no credit ever runs.
#[kani::proof]
fn refill_actor_matches_kernel_refill_window_for_all_backward_clocks() {
    let pol = any_policy();
    let tokens: u64 = kani::any();
    let last: u64 = kani::any();
    let frac: u64 = kani::any();
    let now: u64 = kani::any();
    kani::assume(now <= last);
    let kernel_bkt = Bucket {
        tokens,
        last_refill_ns: last,
        frac_rem: frac,
    };
    let mut kernel = bucket_clone(&kernel_bkt);
    refill_window(&pol, &mut kernel, now);
    let mut w = World::genesis(bucket_clone(&kernel_bkt), kernel_bkt, 0, 0, false);
    crate::interleave_segments::run_refill_direct(&mut w, &pol, now);
    assert_eq!(w.pool.tokens, kernel.tokens, "tokens diverged");
    assert_eq!(
        w.pool.last_refill_ns, kernel.last_refill_ns,
        "stamp diverged"
    );
    assert_eq!(w.pool.frac_rem, kernel.frac_rem, "fraction diverged");
}

/// FIDELITY, the refill actor, lemma two, the FORWARD clocks:
/// RETIRED BY CENSUS, the record honest. The whole-domain shape
/// and the forward-clock lemma both measured undecided on the
/// 2-CPU census sandbox past every local ceiling (the 10-minute
/// seat included): the circuit is two full refill_credits
/// pipelines — the division/modulo family the Z12 census itself
/// named — over two object copies the solver will not
/// common-subexpress, roughly 63k variables before the first
/// propositional reduction pass. The sandbox is this estate's
/// conservative bound BY DESIGN (the Z12 census posture), so the
/// lemma rides no CI seat: the forward-clock fidelity is carried
/// by the sampled tier (the 4096-case shrinkable hammer plus the
/// chain pin — kernel == direct driver == actor, sampled), and
/// the backward-clock lemma above stands verified for all inputs.
/// The reopen lever, named: a solver generation that
/// common-subexpresses equal-argument division pipelines, or the
/// refill_credits lemma decomposition at the division level — the
/// same door the Z10 emission theorem's header holds.

/// FIDELITY, the consume actor: for EVERY hostile bucket and
/// packet, the actor's run answers try_consume's own verdict and
/// leaves the bucket bit-identical.
#[kani::proof]
fn consume_actor_matches_kernel_try_consume_for_all_inputs() {
    let tokens: u64 = kani::any();
    let pkt: u32 = kani::any();
    let kernel_bkt = Bucket {
        tokens,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut kernel = bucket_clone(&kernel_bkt);
    let kernel_allowed = try_consume(&mut kernel, pkt);
    let mut w = World::genesis(bucket_clone(&kernel_bkt), kernel_bkt, 0, 0, true);
    let mut actor = crate::interleave_actors::Actor::new(crate::interleave_actors::Verb::Consume {
        target: Target::Pool,
        want: pkt,
    });
    actor.run_unrolled(&mut w);
    assert_eq!(w.pool.tokens, kernel.tokens, "tokens diverged");
    assert_eq!(actor.verdict, kernel_allowed, "verdict diverged");
    assert!(w.ledger_ok(), "the actor broke its own ledger");
}

/// FIDELITY, the debt pair: for EVERY hostile (stock, debt, packet)
/// the actors' runs leave the pair bit-identical to debt_charge's
/// and debt_pay's own bytes — the charge's landed verdict included,
/// compared directly through the actor's verdict field.
#[kani::proof]
fn debt_actors_match_kernel_debt_pair_for_all_inputs() {
    let stock: u64 = kani::any();
    let debt0: u64 = kani::any();
    let pkt: u32 = kani::any();
    // The kernel pair, charge first, pay second.
    let mut k_tokens = stock;
    let mut k_debt = debt0;
    let k_ptr_t = &mut k_tokens as *mut u64;
    let k_ptr_d = &mut k_debt as *mut u64;
    let charged = crate::ecn_core::debt_charge(k_ptr_d, pkt);
    crate::ecn_core::debt_pay(k_ptr_t, k_ptr_d);
    // The machine pair, same order, same start.
    let pool = Bucket {
        tokens: stock,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let leaf = Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut w = World::genesis(pool, leaf, debt0, 0, true);
    let mut charger =
        crate::interleave_actors::Actor::new(crate::interleave_actors::Verb::DebtCharge {
            pkt_len: pkt,
        });
    charger.run_unrolled(&mut w);
    let mut payer = crate::interleave_actors::Actor::new(crate::interleave_actors::Verb::DebtPay {
        target: Target::Pool,
    });
    payer.run_unrolled(&mut w);
    assert_eq!(w.pool.tokens, k_tokens, "stock diverged");
    assert_eq!(w.debt.tokens, k_debt, "debt diverged");
    assert_eq!(charger.verdict, charged, "the charge verdict diverged");
    assert!(w.ledger_ok(), "the actors broke their own ledger");
}

// ── THE SINGLE-STEP PRESERVATION THEOREMS ──────────────────────────

/// THE refill family's preservation, decomposed per segment (the
/// Z12 discipline: the one-harness union of the five segment bodies
/// measured past the sandbox's seat on this solver generation —
/// the census rides the research doc). Each harness proves ONE
/// segment preserves the full invariant from every P-state; the
/// induction over schedules composes them as ever.
#[kani::proof]
fn every_refill_seed_clamp_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    let pol = any_policy();
    kani::assume(w.laws_ok());
    let seeded_obs: u64 = kani::any();
    refill_seed_clamp(&mut w, pol.burst_bytes, seeded_obs);
    assert!(w.laws_ok(), "the seed clamp broke the invariant");
}

#[kani::proof]
fn every_refill_window_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let last_obs: u64 = kani::any();
    let now: u64 = kani::any();
    let _ = refill_window_take(&mut w, now, last_obs);
    assert!(w.laws_ok(), "the window segment broke the invariant");
}

#[kani::proof]
fn every_refill_credit_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    let pol = any_policy();
    kani::assume(w.laws_ok());
    // The credit's representability headroom, in the EXACT form: the
    // plain saturating_add shape is vacuously true at the u64 ceiling
    // (it saturates to MAX and MAX <= MAX passes), so the subtraction
    // form states the same domain without the hole — the credit the
    // kernel can form stays representable over the current stock.
    kani::assume(w.pool.tokens <= u64::MAX - pol.rate_bps - pol.burst_bytes);
    let elapsed: u64 = kani::any();
    let frac_obs: u64 = kani::any();
    let _ = refill_credit(&mut w, &pol, elapsed, frac_obs);
    assert!(w.laws_ok(), "the credit segment broke the invariant");
}

#[kani::proof]
fn every_refill_cap_clamp_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    let pol = any_policy();
    kani::assume(w.laws_ok());
    let over_obs: u64 = kani::any();
    refill_cap_clamp(&mut w, pol.burst_bytes, over_obs);
    assert!(w.laws_ok(), "the cap clamp broke the invariant");
}

#[kani::proof]
fn every_refill_frac_write_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    // The write's program-order domain: the kernel writes exactly
    // the cap branch's 0 or the credit's new fraction.
    let v: u64 = kani::any();
    kani::assume(v == 0 || v < NS_PER_SEC);
    refill_frac_write(&mut w, v);
    assert!(w.laws_ok(), "the fraction write broke the invariant");
}

/// THE consume family's preservation: for EVERY P-state and every
/// consume segment (any target, any packet, any stale observation),
/// the sufficiency-verified CAS and its shadow pair keep the full
/// invariant — the never-over-allow law's interleaved form: a lost
/// CAS drops, a won CAS moves exactly `want` from the stock into
/// the spent ledger.
#[kani::proof]
fn every_consume_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let target = match kani::any() {
        false => Target::Pool,
        true => Target::Leaf,
    };
    let want: u32 = kani::any();
    let observed_obs: u64 = kani::any();
    consume_seg(&mut w, target, want, observed_obs);
    assert!(w.laws_ok(), "a consume segment broke the invariant");
}

/// THE draw family's preservation: for EVERY P-state and every
/// draw segment (the stamp lock, the pool take, the leaf credit,
/// the rollback), the full invariant holds — the transfer arms
/// in flight and lands in its own segment, and the leaf credit's
/// taint rule is the belt law's own bookkeeping. The pairing
/// assume states program order: the credit's d is the actor's own
/// armed take, and the armed take is representable over the leaf.
#[kani::proof]
fn every_draw_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let quantum: u64 = kani::any();
    let learned: u16 = kani::any();
    let allowance: u64 = kani::any();
    let room: u64 = kani::any();
    let observed_obs: u64 = kani::any();
    let stamp_obs: u64 = kani::any();
    let now: u64 = kani::any();
    let epoch_start: u64 = kani::any();
    let d: u64 = kani::any();
    kani::assume(w.inflight >= u128::from(d));
    // The leaf credit's representability headroom, the exact
    // subtraction form (the saturating shape's ceiling hole closed).
    kani::assume(w.leaf.tokens <= u64::MAX - d);
    let seg: u8 = kani::any();
    match seg % 4 {
        0 => {
            let _ = draw_stamp_seg(&mut w, now, stamp_obs);
        }
        1 => {
            let _ = draw_pool_take_seg(&mut w, quantum, learned, allowance, room, observed_obs);
        }
        2 => draw_leaf_credit_seg(&mut w, d),
        _ => draw_rollback_seg(&mut w, now, epoch_start),
    }
    assert!(w.laws_ok(), "a draw segment broke the invariant");
}

/// THE debt family's preservation: for EVERY P-state and every
/// debt segment (the cap-guarded charge, the pay's token
/// deduction, the pay's forgiveness), the full invariant holds.
/// The charge's guard rides the same observation its CAS compares,
/// so no interleaving slips past the cap; the pay's two segments
/// expose the documented over-pay window instead of assuming it
/// away, and the ledger prices both halves exactly.
#[kani::proof]
fn every_debt_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let target = match kani::any() {
        false => Target::Pool,
        true => Target::Leaf,
    };
    let pkt_len: u32 = kani::any();
    let observed_obs: u64 = kani::any();
    let outstanding_obs: u64 = kani::any();
    let available_obs: u64 = kani::any();
    let pay: u64 = kani::any();
    let fresh_obs: u64 = kani::any();
    let seg: u8 = kani::any();
    match seg % 3 {
        0 => {
            let _ = debt_charge_seg(&mut w, pkt_len, observed_obs);
        }
        1 => {
            let _ = debt_pay_tokens_seg(&mut w, target, outstanding_obs, available_obs);
        }
        _ => debt_pay_forgive_seg(&mut w, pay, fresh_obs),
    }
    assert!(w.laws_ok(), "a debt segment broke the invariant");
}

/// THE shipped belt's conservative preservation — the GATED
/// machine since Z17 rung 8 (the zeroed-verdict gate the live e2e
/// lane re-shaped): for EVERY P-state and every belt segment in the
/// SHIPPED machine (the zeroing CAS and the verdict-gated stamp
/// write, the bytes drr_flow.rs's leaf belt and cake_flow.rs's flow
/// twin run), the invariant holds EXCEPT the dead law P4 — the
/// NAMED residual: a racing draw's in-flight credit can land inside
/// the belt's own read-to-write window and be stamped current,
/// bounded by one armed take (the quantum), the two-word
/// atomicity floor itself. The conservation ledger holds through
/// the belt (the surviving tokens are real budget, never minted);
/// what can break is exactly the certification, one quantum wide,
/// never the conservation. The pre-patch (ungated) belt's own
/// family and its deterministic witnesses ride the property tier —
/// the finding's record; the QUIET form below carries the full law
/// at the model tier the live lane priced.
#[kani::proof]
fn every_shipped_belt_segment_preserves_the_conservative_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let gen_obs: u64 = kani::any();
    kani::assume(gen_obs <= w.g_live);
    let stale_obs: u64 = kani::any();
    let zeroed: bool = kani::any();
    let seg: u8 = kani::any();
    match seg % 2 {
        0 => {
            let _ = belt_zero_seg(&mut w, stale_obs);
        }
        _ => belt_stamp_gated_seg(&mut w, gen_obs, zeroed),
    }
    assert!(
        w.laws_ok_except_dead(),
        "a shipped belt segment broke the conservative invariant"
    );
}

/// THE quiet belt's full preservation (the re-observing close,
/// certified and unshippable): for EVERY P-state and every
/// quiet-form belt segment (the zeroing CAS and the re-observing
/// stamp write), the FULL invariant holds, the dead law P4
/// included — the re-observation closes the belt's own write
/// window, refusing to certify any stock it did not itself watch
/// empty. This is the form rung 4 landed as the shipped bytes, and
/// the live e2e lane falsified its throughput shape (the census
/// records the numbers): under sustained delivery the stock moves
/// through the re-observation, the belt keeps refusing to stamp and
/// keeps zeroing freshly drawn budget — sound law, unusable rate.
/// The theorem stands as the model-side certificate of what the
/// full close costs to ship; the shipped bytes carry the
/// zeroed-verdict gate instead.
#[kani::proof]
fn every_quiet_belt_segment_preserves_the_full_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let gen_obs: u64 = kani::any();
    kani::assume(gen_obs <= w.g_live);
    let stale_obs: u64 = kani::any();
    let zeroed: bool = kani::any();
    let seg: u8 = kani::any();
    match seg % 2 {
        0 => {
            let _ = belt_zero_seg(&mut w, stale_obs);
        }
        _ => belt_stamp_quiet_seg(&mut w, gen_obs, zeroed),
    }
    assert!(w.laws_ok(), "a quiet belt segment broke the invariant");
}

/// THE mutation and init family's preservation: for EVERY P-state,
/// the forward-only generation bump and the NOEXIST init keep the
/// full invariant — the bump only stales stamps (the belt's own
/// firing condition), and the atomic insert births a zero bucket
/// the ledger already counts. The mutate domain states the MMSPA
/// generation's own width (u32, forward only).
#[kani::proof]
fn every_mutate_and_init_segment_preserves_the_laws_for_all_states() {
    let mut w = any_world();
    kani::assume(w.laws_ok());
    let bump: u64 = kani::any();
    kani::assume(bump >= 1);
    // The mutate domain, the total subtraction form (the saturating
    // shape's u32-ceiling hole closed the same way the stock
    // headroom's was; the bound on bump keeps the subtraction
    // itself total).
    kani::assume(bump <= GENERATION_MAX);
    kani::assume(w.g_live <= GENERATION_MAX - bump);
    let seg: u8 = kani::any();
    if seg % 2 == 0 {
        mutate_seg(&mut w, bump);
    } else {
        init_seg(&mut w);
    }
    assert!(w.laws_ok(), "a mutate or init segment broke the invariant");
}
